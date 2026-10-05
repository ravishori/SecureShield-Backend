"""
Elderly Protection router — /api/v1/elderly/

Endpoints:
  GET   /config         — fetch current config
  PUT   /config         — upsert config (create or update)
  POST  /guardian-alert — device reports a risky install; backend notifies guardian
"""

from __future__ import annotations

from datetime import datetime

import re

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.elderly_config import ElderlyConfig
from app.schemas.elderly_protection import (
    ElderlyConfigRequest,
    ElderlyConfigResponse,
    GuardianAlertRequest,
)
from app.middleware.rate_limiter import rate_limiter
from app.routers.auth import get_current_user
from app.services import notifications
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

    cfg.enabled = request.enabled
    cfg.guardian_name = request.guardian_name
    cfg.guardian_phone = request.guardian_phone
    cfg.guardian_email = request.guardian_email
    cfg.block_risky_installs = request.block_risky_installs
    cfg.alert_threshold = request.alert_threshold
    cfg.auto_alert_guardian = request.auto_alert_guardian
    cfg.require_approval = request.require_approval
    cfg.simplified_ui = request.simplified_ui
    cfg.large_text = request.large_text
    cfg.updated_at = datetime.utcnow()

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
        return {
            "status": "skipped",
            "reason": "elderly mode disabled or auto-alert off",
        }

    if not (cfg.guardian_phone or cfg.guardian_email):
        return {"status": "skipped", "reason": "no guardian contact configured"}

    if request.risk_score < cfg.alert_threshold:
        return {"status": "skipped", "reason": "risk below the alert threshold"}

    # SMS/e-mail cost money and can harass the guardian: cap per user.
    if not rate_limiter.is_allowed(
        f"guardian_alert:{current_user.id}", max_hits=10, window_seconds=3600
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many guardian alerts. Please try again later.",
            headers={"Retry-After": "3600"},
        )

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
    result = await db.execute(
        select(ElderlyConfig).where(ElderlyConfig.user_id == user_id)
    )
    cfg = result.scalar_one_or_none()
    if cfg is None:
        cfg = ElderlyConfig(user_id=user_id)
        db.add(cfg)
    return cfg


def _clean(text: str, limit: int) -> str:
    """Single line, no control characters (these values end up in an SMS / e-mail)."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()[:limit]


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
) -> dict:
    """Deliver the alert to the guardian by SMS and/or e-mail. Returns per-channel results."""
    greeting = (
        f"Dear {_clean(guardian_name, 100)}," if guardian_name else "Guardian Alert:"
    )
    tags_text = (
        "; ".join(_clean(t, 100) for t in risk_tags[:3])
        if risk_tags
        else "multiple risk signals detected"
    )
    lines = [
        greeting,
        "",
        "SecureShield Alert",
        "",
        f"{_clean(user_name, 100)} just installed a {risk_level.upper()} risk app: "
        f"'{_clean(app_name, 100)}'",
        f"Risk score: {risk_score}/100",
        f"Reason: {tags_text}",
    ]
    if clone_verdict:
        verdict = _clean(clone_verdict, 50).replace("_", " ").title()
        lines.append(f"Verdict: {verdict}")
    lines += [
        "",
        "Please check their device and help them remove it if it looks suspicious.",
        "- SecureShield AI",
    ]
    message = "\n".join(lines)
    results = {}
    channels = []
    if guardian_phone:
        channels.append(("sms", notifications.send_sms(guardian_phone, message)))
    if guardian_email:
        channels.append(
            (
                "email",
                notifications.send_email(
                    guardian_email, "SecureShield Guardian Alert", message
                ),
            )
        )
    for name, coro in channels:
        # One failing channel must not stop the other (or surface as a server error).
        try:
            results[name] = bool(await coro)
        except Exception as exc:
            logger.error(f"[ELDERLY] {name} delivery raised {type(exc).__name__}")
            results[name] = False
    if not any(results.values()):
        logger.error("[ELDERLY] guardian alert could not be delivered on any channel")
    return results
