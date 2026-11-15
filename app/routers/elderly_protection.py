"""
Elderly Protection router — /api/v1/elderly/

Endpoints:
  GET   /config         — fetch current config
  PUT   /config         — upsert config (create or update)
  POST  /guardian-alert — device reports a risky install; backend notifies guardian
"""

from __future__ import annotations

from datetime import datetime

import hashlib

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.elderly_config import ElderlyConfig
from app.schemas.elderly_protection import (
    GuardianVerifyConfirm,
    GuardianVerifyStart,
    ElderlyConfigRequest,
    ElderlyConfigResponse,
    GuardianAlertRequest,
)
from app.middleware.rate_limiter import rate_limiter
from app.routers.auth import get_current_user
from app.middleware.rate_limiter import check_otp_send_rate, check_otp_verify_rate
from app.models.app_install_event import AppInstallEvent
from app.routers.auth import _check_otp_send_ip, _mask
from app.services import guardian_alerts as rules
from app.services import guardian_outbox
from app.services import identity as idn
from app.services.client_ip import client_ip_for
from app.services.clone_analyzer import analyze_clone
from app.services.risk_engine import compute_risk
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
    old_email, old_phone = cfg.guardian_email, cfg.guardian_phone

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

    # A different contact is a different person: whatever was authorised or verified for the old one is withdrawn.
    email_changed = (old_email or "").lower() != (cfg.guardian_email or "").lower()
    phone_changed = (old_phone or "") != (cfg.guardian_phone or "")
    if email_changed:
        cfg.guardian_email_verified_at = None
        cfg.guardian_email_verified_value = None
    if phone_changed:
        cfg.guardian_phone_verified_at = None
        cfg.guardian_phone_verified_value = None
    if email_changed or phone_changed:
        cfg.guardian_authorised_at = None
        cfg.guardian_notice_version = None

    if request.guardian_authorised is True:
        if request.guardian_notice_version != rules.GUARDIAN_NOTICE_VERSION:
            await db.rollback()
            raise HTTPException(
                status_code=409,
                detail="The guardian disclosure was updated. Review the current version and authorise again.",
                headers={"X-Consent-Error": "stale_guardian_notice"},
            )
        if not (cfg.guardian_email or cfg.guardian_phone):
            await db.rollback()
            raise HTTPException(
                status_code=422,
                detail="Add a guardian contact before authorising a guardian.",
            )
        cfg.guardian_authorised_at = datetime.utcnow()
        cfg.guardian_notice_version = rules.GUARDIAN_NOTICE_VERSION
    elif request.guardian_authorised is False:
        cfg.guardian_authorised_at = None
        cfg.guardian_notice_version = None
        cfg.guardian_email_verified_at = cfg.guardian_email_verified_value = None
        cfg.guardian_phone_verified_at = cfg.guardian_phone_verified_value = None

    await db.commit()
    await db.refresh(cfg)
    return cfg


@router.post("/guardian/verify/start")
async def guardian_verify_start(
    body: GuardianVerifyStart,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Send a code to the GUARDIAN's e-mail so the guardian can confirm they agree to receive alerts about this person.

    Needs the account holder's authorisation first. The code is shared back by the guardian and confirmed with
    ``POST /guardian/verify/confirm``. SMS verification is not available until an SMS provider exists."""
    client_ip = client_ip_for(http_request, None)
    _check_otp_send_ip(client_ip)
    cfg = await _get_or_create(current_user.id, db)
    if not rules.is_authorised(cfg):
        raise HTTPException(
            status_code=409,
            detail="Authorise your guardian first (and acknowledge the guardian disclosure).",
            headers={"X-Guardian-Error": "not_authorised"},
        )
    if body.channel == "phone":
        raise HTTPException(
            status_code=409,
            detail="Phone (SMS) verification is not available yet; verify the guardian's e-mail address.",
            headers={"X-Guardian-Error": "sms_unavailable"},
        )
    if not cfg.guardian_email:
        raise HTTPException(
            status_code=422, detail="Add the guardian's e-mail address first."
        )
    email = cfg.guardian_email.lower()
    check_otp_send_rate(email)
    code = await idn.issue_challenge(
        db,
        kind=idn.EMAIL,
        identifier=email,
        purpose=idn.GUARDIAN_VERIFY,
        user_id=current_user.id,
    )
    await db.commit()
    who = current_user.full_name or "A SecureShield user"
    ok = await notifications.send_email(
        email,
        "SecureShield: confirm you agree to be a guardian",
        f"{rules.clean(who, 100)} named you as their guardian in SecureShield. If you agree, SecureShield may email you "
        "when it detects a risky app on their phone (the app name, a risk summary and when it happened).\n\n"
        f"Your confirmation code: {code}\n\n"
        "Give this code to them to finish setting it up. If you do not agree or do not know them, ignore this message: "
        "nothing will be sent to you.",
    )
    if not ok:
        logger.warning("Guardian verification e-mail could not be sent")
        raise HTTPException(
            status_code=503,
            detail="Could not send the verification code. Please try again later.",
        )
    return {
        "message": "We sent a confirmation code to your guardian.",
        "identifier": _mask(email),
    }


@router.post("/guardian/verify/confirm")
async def guardian_verify_confirm(
    body: GuardianVerifyConfirm,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cfg = await _get_or_create(current_user.id, db)
    if not rules.is_authorised(cfg) or not cfg.guardian_email:
        raise idn.failure()
    email = cfg.guardian_email.lower()
    check_otp_verify_rate(f"guardian:{current_user.id}")
    otp = await idn.consume_challenge(
        db,
        kind=idn.EMAIL,
        identifier=email,
        purpose=idn.GUARDIAN_VERIFY,
        code=body.code,
    )
    if otp is None or otp.user_id != current_user.id:
        raise idn.failure()
    cfg.guardian_email_verified_at = datetime.utcnow()
    cfg.guardian_email_verified_value = email
    await db.commit()
    await db.refresh(cfg)
    return {
        "message": "Your guardian's e-mail address is verified.",
        "guardian_email_verified": True,
    }


async def _server_risk(
    db: AsyncSession, user_id, package_name: str, app_name: str
) -> dict:
    """The risk the SERVER calculated for this app. The device-reported score of the legacy request is never used.

    Prefer the server score already stored for this user's newest synced event of the package; otherwise compute it from
    what the legacy request actually contains (package and app name -> clone analysis; there are no permissions, installer
    or overlay signals to score, so only a clone-like app can reach the threshold through this endpoint)."""
    ev = (
        await db.execute(
            select(AppInstallEvent)
            .where(
                AppInstallEvent.user_id == user_id,
                AppInstallEvent.package_name == package_name,
            )
            .order_by(AppInstallEvent.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if ev is not None:
        return {
            "score": ev.server_risk_score,
            "level": ev.risk_level,
            "tags": list(ev.risk_tags or [])[:10],
            "clone_verdict": "likely_clone" if ev.flagged_as_clone else None,
        }
    clone = analyze_clone(package_name=package_name, app_name=app_name)
    risk = compute_risk(0, False, None, clone.overall_score)
    is_clone = clone.verdict in ("likely_clone", "confirmed_clone")
    return {
        "score": risk.score,
        "level": risk.level,
        "tags": list(risk.tags)[:10],
        "clone_verdict": clone.verdict if is_clone else None,
    }


@router.post("/guardian-alert", status_code=202)
async def send_guardian_alert(
    request: GuardianAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    LEGACY entry point (the supported path is ``POST /app-monitor/sync``, which decides and queues the alert itself).

    Goes through the same durable outbox, the same eligibility rules and the same authorisation / verification gate as sync:
    the alert is stored first, delivered by the worker with retries, and never sent to an unverified guardian. The risk used
    for eligibility is calculated by the server; ``risk_score`` / ``risk_level`` / ``risk_tags`` in the request are accepted
    for compatibility but ignored. One alert per (package, hour) is queued: repeats inside the hour are collapsed.
    """
    cfg = await _get_or_create(current_user.id, db)
    await db.commit()

    risk = await _server_risk(
        db, current_user.id, request.package_name, request.app_name
    )
    reason = rules.check_eligibility(cfg, risk["score"])
    if reason:
        return {"status": "skipped", "reason": reason}

    # SMS/e-mail cost money and can harass the guardian: cap per user.
    if not rate_limiter.is_allowed(
        f"guardian_alert:{current_user.id}", max_hits=10, window_seconds=3600
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many guardian alerts. Please try again later.",
            headers={"Retry-After": "3600"},
        )

    now = datetime.utcnow()
    bucket = now.strftime("%Y%m%d%H")
    key = (
        "legacy:"
        + hashlib.sha1(
            f"{request.package_name}|{request.app_name}|{bucket}".encode()
        ).hexdigest()[:40]
    )
    await guardian_outbox.enqueue(
        db,
        user_id=current_user.id,
        event_id=None,
        dedupe_key=key,
        payload={
            "app_name": request.app_name,
            "package_name": request.package_name,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "risk_tags": risk["tags"],
            "clone_verdict": risk["clone_verdict"],
            "occurred_at": now.isoformat(),
        },
        now=now,
    )
    await db.commit()
    background_tasks.add_task(guardian_outbox.run_once_safe)
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


_clean = rules.clean  # shared with the outbox worker


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
    user_id: str | None = None,
) -> dict:
    """Deliver the alert to the guardian by SMS and/or e-mail. Returns per-channel results.

    Nothing calls this today (the supported path is the outbox); it is gated like the outbox so that reviving it cannot dispatch
    notifications from a development/test process.
    """
    if not guardian_outbox.dispatch_enabled():
        logger.info(
            "[ELDERLY] guardian alert not delivered: guardian dispatch is disabled in this environment"
        )
        return {}
    message = rules.build_message(
        user_name=user_name,
        guardian_name=guardian_name,
        app_name=app_name,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_tags=risk_tags,
        clone_verdict=clone_verdict,
    )
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
            logger.error(
                f"[ELDERLY] user={user_id} {name} delivery raised {type(exc).__name__}"
            )
            results[name] = False
    outcome = ",".join(f"{k}={'ok' if v else 'failed'}" for k, v in results.items())
    if not any(results.values()):
        logger.error(
            f"[ELDERLY] user={user_id} guardian alert could not be delivered on any channel ({outcome})"
        )
    else:
        logger.info(
            f"[ELDERLY] user={user_id} guardian alert delivered: risk={risk_level} score={risk_score} ({outcome})"
        )
    return results
