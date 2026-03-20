from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import uuid

from app.database import get_db
from app.models.user import User
from app.models.app_scan import AppScan
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.app_scan import AppScanRequest, AppScanResponse, AppScanResult
from app.routers.auth import get_current_user
from app.services.threat_analyzer import analyze_app_risk

router = APIRouter(prefix="/app-scanner", tags=["app-scanner"])


@router.post("/scan", response_model=AppScanResponse)
async def scan_apps(
    request: AppScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    results = []
    high_risk_count = 0

    for app_info in request.apps:
        risk_score, risk_level, is_malicious, threat_tags = analyze_app_risk(
            app_info.package_name,
            app_info.permissions,
            app_info.is_system_app,
        )

        scan = AppScan(
            device_id=request.device_id,
            package_name=app_info.package_name,
            app_name=app_info.app_name,
            version_name=app_info.version_name,
            risk_score=risk_score,
            risk_level=risk_level,
            permissions=app_info.permissions,
            is_system_app=app_info.is_system_app,
            is_malicious=is_malicious,
            threat_tags=threat_tags,
        )
        db.add(scan)

        if risk_level in ("high", "critical") or is_malicious:
            high_risk_count += 1
            alert = Alert(
                user_id=current_user.id,
                device_id=request.device_id,
                alert_type=AlertType.app_risk,
                title=f"Risky App Detected: {app_info.app_name}",
                message=f"{app_info.app_name} has a risk score of {risk_score:.0f}/100. Threat tags: {', '.join(threat_tags)}",
                severity=AlertSeverity.critical if risk_level == "critical" else AlertSeverity.warning,
                extra_data={"package_name": app_info.package_name, "risk_score": risk_score},
            )
            db.add(alert)

        results.append(scan)

    await db.commit()
    for r in results:
        await db.refresh(r)

    return AppScanResponse(
        total_apps=len(results),
        high_risk_count=high_risk_count,
        results=results,
    )


@router.get("/results", response_model=List[AppScanResult])
async def get_scan_results(
    device_id: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(AppScan)
    if device_id:
        query = query.where(AppScan.device_id == uuid.UUID(device_id))
    query = query.order_by(AppScan.scanned_at.desc()).limit(100)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/results/{scan_id}", response_model=AppScanResult)
async def get_scan_result(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(AppScan).where(AppScan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return scan
