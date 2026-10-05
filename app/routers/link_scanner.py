"""
Link Scanner router — multi-tier threat detection.

Verdict pipeline:
  1. Google Safe Browsing (needs GOOGLE_SAFE_BROWSING_API_KEY) and
  2. URLhaus / abuse.ch   (needs URLHAUS_AUTH_KEY)
     are queried CONCURRENTLY: they cover different threats, so "clean" from one must not
     hide a hit in the other. Any malicious verdict wins (Safe Browsing preferred).
  3. Internal heuristic   (always available — phishing keyword / TLD / shortener rules)
     scores everything that no provider flagged, and is the sole source when both
     providers are unavailable.

The `scan_provider` field on the response reports which tier produced the
final verdict, so the UI can show a confidence indicator.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert, AlertSeverity, AlertType
from app.models.link_scan import LinkScan
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.link_scan import LinkScanRequest, LinkScanResponse
from app.services.gsb_service import check_url_gsb, is_configured as gsb_is_configured
from app.services.threat_analyzer import analyze_url
from app.services.urlhaus_service import check_url_urlhaus
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/link-scanner", tags=["link-scanner"])

# Maps any provider's threat-type string to the canonical internal category.
_THREAT_CATEGORY_MAP = {
    "MALWARE":                        "malware",
    "MALWARE_DOWNLOAD":               "malware",
    "SOCIAL_ENGINEERING":             "phishing",
    "PHISHING":                       "phishing",
    "UNWANTED_SOFTWARE":              "unwanted_software",
    "POTENTIALLY_HARMFUL_APPLICATION":"harmful_app",
    "EXPLOIT":                        "exploit",
}

# Statuses indicating the provider couldn't deliver a definitive verdict.
_INCONCLUSIVE = {
    "no_api_key", "rate_limited",
    "network_error", "http_error", "unknown_error",
}


@router.post("/scan", response_model=LinkScanResponse)
async def scan_link(
    request: LinkScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    url = request.url

    # ── Providers (concurrent; each degrades to an inconclusive envelope, never raises) ──
    gsb_result, urlhaus_result = await asyncio.gather(check_url_gsb(url), check_url_urlhaus(url))
    gsb_status = gsb_result.get("status")
    urlhaus_status = urlhaus_result.get("status")

    if gsb_status == "malicious" or urlhaus_status == "malicious":
        hit, provider = (
            (gsb_result, "google_safe_browsing") if gsb_status == "malicious" else (urlhaus_result, "urlhaus")
        )
        threats = hit["threats"]
        threat_types = [t["threat_type"] for t in threats]
        is_phishing = any(t in ("SOCIAL_ENGINEERING", "PHISHING") for t in threat_types)
        is_malicious = True
        risk_score = 95.0 if provider == "google_safe_browsing" else 90.0
        threat_category = (
            _THREAT_CATEGORY_MAP.get(threat_types[0], "malicious_url") if threat_types else "malicious_url"
        )
        scan_provider = provider
        gsb_threats = threats
    elif gsb_status == "safe" or urlhaus_status == "safe":
        # At least one provider answered conclusively "not known-bad". Providers only list KNOWN
        # threats, so the internal engine still scores structure/TLD/keyword risk.
        is_phishing, is_malicious, risk_score, threat_category = analyze_url(url)
        both = gsb_status == "safe" and urlhaus_status == "safe"
        scan_provider = (
            "google_safe_browsing+urlhaus" if both
            else "google_safe_browsing" if gsb_status == "safe"
            else "urlhaus_clean_internal_score"
        )
        gsb_threats = []
    else:
        is_phishing, is_malicious, risk_score, threat_category = analyze_url(url)
        scan_provider = "internal_fallback"
        gsb_threats = None
        logger.info(
            "[LinkScan] All external providers inconclusive — gsb=%s/%s urlhaus=%s/%s",
            gsb_status, gsb_result.get("reason"), urlhaus_status, urlhaus_result.get("reason"),
        )

    scan = LinkScan(
        user_id=current_user.id,
        url=url,
        is_phishing=is_phishing,
        is_malicious=is_malicious,
        risk_score=risk_score,
        threat_category=threat_category,
        scan_provider=scan_provider,
        gsb_threats=gsb_threats,
    )
    db.add(scan)

    if is_phishing or is_malicious or risk_score >= 50:
        alert = Alert(
            user_id=current_user.id,
            alert_type=AlertType.phishing,
            title="Dangerous Link Detected",
            message=(
                f"The URL you scanned is flagged as "
                f"{'malicious' if is_malicious else 'phishing'}. "
                f"Risk score: {risk_score:.0f}/100"
            ),
            severity=AlertSeverity.critical if is_malicious else AlertSeverity.warning,
            extra_data={
                "url": url[:200],
                "risk_score": risk_score,
                "provider": scan_provider,
            },
        )
        db.add(alert)

    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/history", response_model=List[LinkScanResponse])
async def get_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(LinkScan)
        .where(LinkScan.user_id == current_user.id)
        .order_by(LinkScan.scanned_at.desc())
        .limit(50)
    )
    return result.scalars().all()


@router.get("/providers/status")
async def get_provider_status(current_user: User = Depends(get_current_user)):
    """
    Diagnostic endpoint — used by the Settings screen to show which
    threat-intel providers are live.
    """
    return {
        "gsb": {
            "configured": gsb_is_configured(),
            "name": "Google Safe Browsing",
        },
        "urlhaus": {
            "configured": bool((settings.URLHAUS_AUTH_KEY or "").strip()),
            "name": "URLhaus (abuse.ch)",
        },
        "internal": {
            "configured": True,
            "name": "SecureShield Heuristics",
        },
    }
