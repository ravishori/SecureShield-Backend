from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List
import uuid

from app.database import get_db
from app.models.user import User
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.alert import AlertResponse, AlertListResponse, PanicAlertRequest
from app.routers.auth import get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = 1,
    page_size: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * page_size
    count_result = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.user_id == current_user.id,
            Alert.is_dismissed == False,
        )
    )
    total = count_result.scalar()

    result = await db.execute(
        select(Alert)
        .where(Alert.user_id == current_user.id, Alert.is_dismissed == False)
        .order_by(Alert.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    items = result.scalars().all()

    return AlertListResponse(total=total, page=page, page_size=page_size, items=items)


@router.patch("/{alert_id}/read", response_model=AlertResponse)
async def mark_read(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(Alert.id == uuid.UUID(alert_id), Alert.user_id == current_user.id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    await db.commit()
    await db.refresh(alert)
    return alert


@router.patch("/{alert_id}/dismiss", response_model=AlertResponse)
async def dismiss_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(Alert.id == uuid.UUID(alert_id), Alert.user_id == current_user.id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_dismissed = True
    await db.commit()
    await db.refresh(alert)
    return alert


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(Alert.id == uuid.UUID(alert_id), Alert.user_id == current_user.id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)
    await db.commit()
    return {"message": "Alert deleted"}


@router.post("/panic", response_model=AlertResponse)
async def trigger_panic(
    request: PanicAlertRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    extra_data = {"message": request.message}
    if request.latitude:
        extra_data["latitude"] = request.latitude
    if request.longitude:
        extra_data["longitude"] = request.longitude

    alert = Alert(
        user_id=current_user.id,
        alert_type=AlertType.panic,
        title="PANIC ALERT TRIGGERED",
        message=request.message or "Emergency! I need help!",
        severity=AlertSeverity.critical,
        extra_data=extra_data,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert
