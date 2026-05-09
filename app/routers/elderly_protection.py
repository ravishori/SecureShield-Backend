"""
Elderly Protection router — /api/v1/elderly/

Endpoints:
  GET   /config         — fetch current config
  PUT   /config         — upsert config (create or update)
  POST  /guardian-alert — device reports a risky install; backend notifies guardian
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.elderly_config import ElderlyConfig
from app.schemas.elderly_protection import (
    ElderlyConfigRequest, ElderlyConfigResponse, GuardianAlertRequest,
)
from app.routers.auth import get_current_user
from app.services.logger_service import get_logger

router = APIRouter(prefix="/elderly", tags=["elderly-protection"])
logger = get_logger(__name__)


@router.get("/config", response_model=ElderlyConfigResponse)
async def get_config(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return this user's elderly-protection config (creates defaults if absent)."""
    cfg = await _get_or_create(current_user.id, db)
    await db.commit()
    return cfg


@router.put("/config", response_model=ElderlyConfigResponse)
async def upsert_config(
    request: ElderlyConfigRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create or update the elderly-protection config for this user."""
    cfg = await _get_or_create(current_user.id, db)

    cfg.enabled              = request.enabled
    cfg.guardian_name        = request.guardian_name
    cfg.guardian_phone       = request.guardian_phone
    cfg.guardian_email       = request.guardian_email
    cfg.block_risky_installs = request.block_risky_installs
    cfg.alert_threshold      = request.alert_threshold
    cfg.auto_alert_guardian  = request.auto_alert_guardian
    cfg.require_approval     = request.require_approval
    cfg.simplified_ui        = request.simplified_ui
    cfg.large_text           = request.large_text
    cfg.updated_at           = datetime.utcnow()

    await db.commit()
    await db.refresh(cfg)
    return cfg


@router.post("/guardian-alert", status_code=202)
async def send_guardian_alert(
    request: GuardianAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Device calls this when a risky install is detected in elderly mode.
    Backend delivers the alert to the configured guardian asynchronously.
    """
    cfg = await _get_or_create(current_user.id, db)
    await db.commit()

    if not cfg.enabled or not cfg.auto_alert_guardian:
        return {"status": "skipped", "reason": "elderly mode disabled or auto-alert off"}

    if not (cfg.guardian_phone or cfg.guardian_email):
        return {"status": "skipped", "reason": "no guardian contact configured"}

    background_tasks.add_task(
        _deliver_guardian_alert,
        user_name=current_user.full_name or current_user.phone or "Unknown",
        guardian_name=cfg.guardian_name,
        guardian_phone=cfg.guardian_phone,
        guardian_email=cfg.guardian_email,
        app_name=request.app_name,
        risk_score=request.risk_score,
        risk_level=request.risk_level,
        risk_tags=request.risk_tags,
        clone_verdict=request.clone_verdict,
    )
    return {"status": "queued"}


# ── Internals ─────────────────────────────────────────────────────────────────

async def _get_or_create(user_id, db: AsyncSession) -> ElderlyConfig:
    result = await db.execute(select(ElderlyConfig).where(ElderlyConfig.user_id == user_id))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        cfg = ElderlyConfig(user_id=user_id)
        db.add(cfg)
    return cfg


async def _deliver_guardian_alert(
    user_name: str,
    guardian_name: str | None,
    guardian_phone: str | None,
    guardian_email: str | None,
    app_name: str,
    risk_score: int,
    risk_level: str,
    risk_tags: list,
    clone_verdict: str | None,
):
    """
    Deliver alert to guardian via SMS / email.
    Wire up your SMS provider (Twilio / MSG91) and email (SMTP) here.
    Currently logs to console for development.
    """
    greeting = f"Dear {guardian_name}," if guardian_name else "Guardian Alert:"
    tags_text = "; ".join(risk_tags[:3]) if risk_tags else "multiple risk signals detected"

    message = (
        f"{greeting}\n\n"
        f"⚠️ SecureShield Alert\n\n"
        f"{user_name} just installed a {risk_level.upper()} risk app: '{app_name}'\n"
        f"Risk score: {risk_score}/100\n"
        f"Reason: {tags_text}\n"
        + (f"Verdict: {clone_verdict.replace('_', ' ').title()}\n" if clone_verdict else "")
        + "\nPlease check their device and help them remove it if it looks suspicious.\n"
        f"– SecureShield AI"
    )

    if guardian_phone:
        logger.info(f"[ELDERLY] SMS to {guardian_phone}: {message[:120]}…")
        # TODO: twilio_client.messages.create(to=guardian_phone, body=message, from_=settings.TWILIO_FROM)

    if guardian_email:
        logger.info(f"[ELDERLY] Email to {guardian_email}: {message[:120]}…")
        # TODO: send_email(to=guardian_email, subject="SecureShield Guardian Alert", body=message)
