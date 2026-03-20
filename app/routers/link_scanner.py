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

router = APIRouter(prefix="/link-scanner", tags=["link-scanner"])


@router.post("/scan", response_model=LinkScanResponse)
async def scan_link(
    request: LinkScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    is_phishing, is_malicious, risk_score, threat_category = analyze_url(request.url)

    scan = LinkScan(
        user_id=current_user.id,
        url=request.url,
        is_phishing=is_phishing,
        is_malicious=is_malicious,
        risk_score=risk_score,
        threat_category=threat_category,
        scan_provider="internal",
    )
    db.add(scan)

    if is_phishing or is_malicious or risk_score >= 50:
        alert = Alert(
            user_id=current_user.id,
            alert_type=AlertType.phishing,
            title="Dangerous Link Detected",
            message=f"The URL you scanned is flagged as {'malicious' if is_malicious else 'phishing'}. Risk score: {risk_score:.0f}/100",
            severity=AlertSeverity.critical if is_malicious else AlertSeverity.warning,
            extra_data={"url": request.url[:200], "risk_score": risk_score},
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
