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

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert, AlertSeverity, AlertType
from app.models.link_scan import LinkScan
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.link_scan import LinkScanRequest, LinkScanResponse
from app.services.link_scan_retention import maybe_purge_expired
from app.services.url_privacy import (
    provider_url,
    redact_url_for_storage,
    sanitize_threats,
)
from app.services.user_rate_limits import user_limit
from app.services.gsb_service import check_url_gsb, is_configured as gsb_is_configured
from app.services.scam_verdict_adapters import (
    from_stored_url_scan,
    from_url_scan,
    safe_verdict,
)
from app.services.threat_analyzer import analyze_url, analyze_url_signals
from app.services.urlhaus_service import check_url_urlhaus
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/link-scanner", tags=["link-scanner"])

# Maps any provider's threat-type string to the canonical internal category.
_THREAT_CATEGORY_MAP = {
    "MALWARE": "malware",
    "MALWARE_DOWNLOAD": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "PHISHING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted_software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful_app",
    "EXPLOIT": "exploit",
}

# Statuses indicating the provider couldn't deliver a definitive verdict.
_INCONCLUSIVE = {
    "no_api_key",
    "rate_limited",
    "network_error",
    "http_error",
    "unknown_error",
}


@router.post(
    "/scan",
    response_model=LinkScanResponse,
    # BH-1: 10/min and 120/hour per user, checked before any provider call
    dependencies=[Depends(user_limit("link_scan"))],
)
async def scan_link(
    request: LinkScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    url = request.url  # the full URL lives in memory only: detection below uses it, storage and logs never do
    stored_url = redact_url_for_storage(url)
    lookup_url = provider_url(
        url
    )  # no user-info, fragment or credential-named parameters leave the server

    # ── Providers (concurrent; each degrades to an inconclusive envelope, never raises) ──
    gsb_result, urlhaus_result = await asyncio.gather(
        check_url_gsb(lookup_url), check_url_urlhaus(lookup_url)
    )
    gsb_status = gsb_result.get("status")
    urlhaus_status = urlhaus_result.get("status")

    if gsb_status == "malicious" or urlhaus_status == "malicious":
        hit, provider = (
            (gsb_result, "google_safe_browsing")
            if gsb_status == "malicious"
            else (urlhaus_result, "urlhaus")
        )
        threats = hit["threats"]
        threat_types = [t["threat_type"] for t in threats]
        is_phishing = any(t in ("SOCIAL_ENGINEERING", "PHISHING") for t in threat_types)
        is_malicious = True
        risk_score = 95.0 if provider == "google_safe_browsing" else 90.0
        threat_category = (
            _THREAT_CATEGORY_MAP.get(threat_types[0], "malicious_url")
            if threat_types
            else "malicious_url"
        )
        scan_provider = provider
        gsb_threats = threats
    elif gsb_status == "safe" or urlhaus_status == "safe":
        # At least one provider answered conclusively "not known-bad". Providers only list KNOWN
        # threats, so the internal engine still scores structure/TLD/keyword risk.
        is_phishing, is_malicious, risk_score, threat_category = analyze_url(url)
        both = gsb_status == "safe" and urlhaus_status == "safe"
        scan_provider = (
            "google_safe_browsing+urlhaus"
            if both
            else "google_safe_browsing"
            if gsb_status == "safe"
            else "urlhaus_clean_internal_score"
        )
        gsb_threats = []
    else:
        is_phishing, is_malicious, risk_score, threat_category = analyze_url(url)
        scan_provider = "internal_fallback"
        gsb_threats = None
        logger.info(
            "[LinkScan] All external providers inconclusive — gsb=%s/%s urlhaus=%s/%s",
            gsb_status,
            gsb_result.get("reason"),
            urlhaus_status,
            urlhaus_result.get("reason"),
        )

    scan = LinkScan(
        user_id=current_user.id,
        url=stored_url,
        is_phishing=is_phishing,
        is_malicious=is_malicious,
        risk_score=risk_score,
        threat_category=threat_category,
        scan_provider=scan_provider,
        gsb_threats=sanitize_threats(gsb_threats),
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
                "url": stored_url[:200],
                "risk_score": risk_score,
                "provider": scan_provider,
            },
        )
        db.add(alert)

    await db.commit()
    await db.refresh(scan)
    background_tasks.add_task(
        maybe_purge_expired
    )  # BH-2 retention: bounded, at most hourly, after the response
    # Additive shared verdict: built from the SAME provider results and score that produced the response above.
    response = LinkScanResponse.model_validate(scan)
    response.verdict = safe_verdict(
        from_url_scan,
        risk_score=risk_score,
        threat_category=threat_category,
        signals=analyze_url_signals(url)[4],
        gsb=gsb_result,
        urlhaus=urlhaus_result,
    )
    return response


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
    out = []
    for row in result.scalars().all():
        item = LinkScanResponse.model_validate(row)
        # rows written before BH-2 may still hold a full URL: never return one
        item.url = redact_url_for_storage(row.url)
        item.gsb_threats = sanitize_threats(row.gsb_threats)
        item.verdict = safe_verdict(
            from_stored_url_scan,
            scan_provider=row.scan_provider,
            is_malicious=bool(row.is_malicious),
            risk_score=row.risk_score,
            threat_category=row.threat_category,
            gsb_threats=row.gsb_threats,
        )
        out.append(item)
    return out


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
