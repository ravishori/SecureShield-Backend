from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import re
import uuid

from app.database import get_db
from app.middleware.rate_limiter import rate_limiter
from app.models.emergency_contact import EmergencyContact
from app.services import notifications
from app.services.logger_service import get_logger
from app.models.user import User
from app.models.alert import Alert, AlertType, AlertSeverity
from app.schemas.alert import AlertResponse, AlertListResponse, PanicAlertRequest
from app.routers.auth import get_current_user

logger = get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


def _alert_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="Alert not found")


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = 1,
    page_size: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * page_size
    count_result = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            Alert.user_id == current_user.id,
            Alert.is_dismissed.is_(False),
        )
    )
    total = count_result.scalar()

    result = await db.execute(
        select(Alert)
        .where(Alert.user_id == current_user.id, Alert.is_dismissed.is_(False))
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
        select(Alert).where(
            Alert.id == _alert_uuid(alert_id), Alert.user_id == current_user.id
        )
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
        select(Alert).where(
            Alert.id == _alert_uuid(alert_id), Alert.user_id == current_user.id
        )
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
        select(Alert).where(
            Alert.id == _alert_uuid(alert_id), Alert.user_id == current_user.id
        )
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
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Record a panic alert and notify the user's emergency contacts (SMS / e-mail)."""
    if not rate_limiter.is_allowed(
        f"panic:{current_user.id}", max_hits=10, window_seconds=600
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many panic alerts. If you are in danger call 112 now.",
            headers={"Retry-After": "60"},
        )
    extra_data = {"message": request.message}
    if request.latitude is not None:
        extra_data["latitude"] = request.latitude
    if request.longitude is not None:
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
    contacts = (
        (
            await db.execute(
                select(EmergencyContact).where(
                    EmergencyContact.user_id == current_user.id
                )
            )
        )
        .scalars()
        .all()
    )
    targets = [(c.phone, c.email) for c in contacts]
    await db.commit()
    await db.refresh(alert)

    background_tasks.add_task(
        _notify_emergency_contacts,
        user_name=current_user.full_name or "A SecureShield user",
        message=alert.message,
        latitude=request.latitude,
        longitude=request.longitude,
        targets=targets,
    )
    return alert


async def _notify_emergency_contacts(
    user_name: str,
    message: str,
    latitude: float | None,
    longitude: float | None,
    targets: list[tuple[str | None, str | None]],
) -> None:
    """Best effort: one failing contact/channel never blocks the others."""
    clean = re.sub(r"[\x00-\x1f\x7f]+", " ", message or "").strip()[:300]
    who = re.sub(r"[\x00-\x1f\x7f]+", " ", user_name).strip()[:100]
    lines = [
        f"EMERGENCY - {who} pressed the SecureShield panic button.",
        f'"{clean}"',
    ]
    if latitude is not None and longitude is not None:
        lines.append(
            f"Location: https://maps.google.com/?q={latitude:.5f},{longitude:.5f}"
        )
    lines.append("Please call them now. If you cannot reach them, call 112.")
    body = "\n".join(lines)
    for phone, email in targets:
        for send, to, args in (
            (notifications.send_sms, phone, (body,)),
            (notifications.send_email, email, ("SecureShield EMERGENCY alert", body)),
        ):
            if not to:
                continue
            try:
                await send(to, *args)
            except Exception as exc:
                logger.error(f"[PANIC] notification failed: {type(exc).__name__}")
