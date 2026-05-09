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
from app.services.threat_analyzer import analyze_app_risk, get_removal_reason

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

        removal_reason = get_removal_reason(risk_level, threat_tags, is_malicious)

        scan = AppScan(
            device_id=None,           # device_id optional — not required for app scans
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
            spyware_note = " This may be a spyware app — uninstall immediately." if "known_spyware" in threat_tags else ""
            alert = Alert(
                user_id=current_user.id,
                device_id=None,
                alert_type=AlertType.app_risk,
                title=f"{'Spyware' if 'known_spyware' in threat_tags else 'Risky App'} Detected: {app_info.app_name}",
                message=f"{app_info.app_name} has a risk score of {risk_score:.0f}/100. Threat: {', '.join(threat_tags)}.{spyware_note}",
                severity=AlertSeverity.critical if risk_level == "critical" or is_malicious else AlertSeverity.warning,
                extra_data={
                    "package_name": app_info.package_name,
                    "risk_score": risk_score,
                    "removal_reason": removal_reason,
                },
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


@router.get("/spyware-check")
async def check_for_spyware(
    device_id: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns all apps identified as spyware or critical risk with removal guidance."""
    query = select(AppScan).where(
        AppScan.is_malicious == True,
    )
    if device_id:
        query = query.where(AppScan.device_id == uuid.UUID(device_id))
    query = query.order_by(AppScan.scanned_at.desc()).limit(20)
    result = await db.execute(query)
    spyware_apps = result.scalars().all()

    return {
        "spyware_count": len(spyware_apps),
        "spyware_apps": [
            {
                "app_name": a.app_name,
                "package_name": a.package_name,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "threat_tags": a.threat_tags,
                "removal_reason": get_removal_reason(a.risk_level, a.threat_tags or [], a.is_malicious),
                "removal_steps": [
                    f"Go to Settings → Apps → {a.app_name}",
                    "Tap 'Uninstall' or 'Disable'",
                    "If it has Device Admin rights: Settings → Security → Device Admins → Deactivate first",
                    "Restart your device after removal",
                    "Run another scan to confirm removal",
                ],
            }
            for a in spyware_apps
        ],
        "after_removal_steps": [
            "Change all passwords from a safe device",
            "Enable 2FA on all important accounts",
            "Check for unauthorized transactions in banking apps",
            "Report spyware installation at cybercrime.gov.in",
        ] if spyware_apps else [],
    }
