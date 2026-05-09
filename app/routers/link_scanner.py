from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.link_scan import LinkScan
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.link_scan import LinkScanRequest, LinkScanResponse
from app.routers.auth import get_current_user
from app.services.threat_analyzer import analyze_url
from app.services.gsb_service import check_url_gsb

router = APIRouter(prefix="/link-scanner", tags=["link-scanner"])

# Maps GSB threat types to internal threat_category values
_THREAT_CATEGORY_MAP = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted_software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful_app",
}


@router.post("/scan", response_model=LinkScanResponse)
async def scan_link(
    request: LinkScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # 1. Try Google Safe Browsing first
    gsb_result = await check_url_gsb(request.url)

    if gsb_result is not None:
        if not gsb_result["safe"]:
            # GSB confirmed threat — use GSB data directly
            threats = gsb_result["threats"]
            threat_types = [t["threat_type"] for t in threats]
            first_threat = threat_types[0] if threat_types else "MALWARE"

            threat_category = _THREAT_CATEGORY_MAP.get(first_threat, "malicious_url")
            is_malicious = True
            is_phishing = "SOCIAL_ENGINEERING" in threat_types
            risk_score = 95.0
            scan_provider = "google_safe_browsing"
            gsb_threats = threats
        else:
            # GSB says clean — run internal engine for a risk score
            is_phishing, is_malicious, risk_score, threat_category = analyze_url(request.url)
            scan_provider = "google_safe_browsing"
            gsb_threats = []
    else:
        # GSB unavailable — fallback to internal rules only
        is_phishing, is_malicious, risk_score, threat_category = analyze_url(request.url)
        scan_provider = "internal_fallback"
        gsb_threats = None

    scan = LinkScan(
        user_id=current_user.id,
        url=request.url,
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
            message=f"The URL you scanned is flagged as {'malicious' if is_malicious else 'phishing'}. Risk score: {risk_score:.0f}/100",
            severity=AlertSeverity.critical if is_malicious else AlertSeverity.warning,
            extra_data={"url": request.url[:200], "risk_score": risk_score, "provider": scan_provider},
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
