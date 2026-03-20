from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import uuid

from app.database import get_db
from app.models.user import User
from app.models.network_activity import NetworkActivity
from app.schemas.network_activity import NetworkActivityBatchRequest, NetworkActivityResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/network", tags=["network"])

SUSPICIOUS_DOMAINS = [
    "exfiltrate.com", "dataharvest.net", "spynet.ru",
    "maltrack.cn", "phishkit.tk",
]

SUSPICIOUS_IPS = [
    "185.220.", "5.188.", "77.73.",
]


def is_suspicious_activity(domain: str | None, ip: str | None) -> tuple[bool, str | None]:
    if domain:
        for sus in SUSPICIOUS_DOMAINS:
            if sus in domain.lower():
                return True, f"Suspicious domain: {domain}"
    if ip:
        for sus_ip in SUSPICIOUS_IPS:
            if ip.startswith(sus_ip):
                return True, f"Suspicious IP range: {ip}"
    return False, None


@router.post("/activity")
async def log_activity(
    request: NetworkActivityBatchRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    logged = 0
    for activity in request.activities:
        is_sus, risk_reason = is_suspicious_activity(
            activity.destination_domain, activity.destination_ip
        )
        record = NetworkActivity(
            device_id=request.device_id,
            app_package=activity.app_package,
            app_name=activity.app_name,
            bytes_sent=activity.bytes_sent,
            bytes_received=activity.bytes_received,
            destination_ip=activity.destination_ip,
            destination_domain=activity.destination_domain,
            is_suspicious=is_sus,
            risk_reason=risk_reason,
        )
        db.add(record)
        logged += 1

    await db.commit()
    return {"logged": logged}


@router.get("/suspicious", response_model=List[NetworkActivityResponse])
async def get_suspicious(
    device_id: str = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(NetworkActivity).where(NetworkActivity.is_suspicious == True)
    if device_id:
        query = query.where(NetworkActivity.device_id == uuid.UUID(device_id))
    query = query.order_by(NetworkActivity.logged_at.desc()).limit(50)
    result = await db.execute(query)
    return result.scalars().all()
