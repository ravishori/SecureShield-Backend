from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.user import User
from app.models.wifi_scan import WifiScan
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.wifi_scan import WifiScanRequest, WifiScanResponse
from app.routers.auth import get_current_user
from app.services.threat_analyzer import analyze_wifi

router = APIRouter(prefix="/wifi", tags=["wifi"])


@router.post("/scan", response_model=WifiScanResponse)
async def scan_wifi(
    request: WifiScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    is_open = not request.encryption_type or request.encryption_type.upper() in ["NONE", "OPEN", ""]
    is_suspicious, risk_level, risk_reasons = analyze_wifi(
        request.ssid, request.encryption_type, is_open
    )

    scan = WifiScan(
        device_id=None,           # device_id is optional — not required for wifi scans
        ssid=request.ssid,
        bssid=request.bssid,
        signal_strength=request.signal_strength,
        encryption_type=request.encryption_type,
        is_open=is_open,
        is_suspicious=is_suspicious,
        risk_level=risk_level,
        risk_reasons=risk_reasons,
    )
    db.add(scan)

    if is_suspicious or risk_level in ("high", "medium"):
        alert = Alert(
            user_id=current_user.id,
            device_id=None,       # device_id optional on alerts too
            alert_type=AlertType.wifi_unsafe,
            title=f"Unsafe Wi-Fi: {request.ssid or 'Unknown'}",
            message=f"The Wi-Fi network '{request.ssid}' may be unsafe. Reasons: {', '.join(risk_reasons)}",
            severity=AlertSeverity.warning,
            extra_data={"ssid": request.ssid, "risk_level": risk_level},
        )
        db.add(alert)

    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/history", response_model=List[WifiScanResponse])
async def get_history(
    device_id: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    import uuid
    query = select(WifiScan).order_by(WifiScan.scanned_at.desc()).limit(50)
    if device_id:
        query = query.where(WifiScan.device_id == uuid.UUID(device_id))
    result = await db.execute(query)
    return result.scalars().all()
