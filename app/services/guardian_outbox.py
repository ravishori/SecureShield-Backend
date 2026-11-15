"""Durable guardian-alert delivery: enqueue, claim with a lease, send, retry, expire, audit.

Guarantees (and limits)
  * An alert is persisted before any send (``enqueue``). The same logical event is never queued twice (unique dedupe key).
  * ``claim_due`` takes rows atomically with ``FOR UPDATE SKIP LOCKED`` and stamps a lease; two workers never hold the same
    row, and a worker that dies loses its lease after ``LEASE`` so another one picks the row up.
  * Results are written only by the lease holder (compare-and-set on the lease token): a worker that lost its lease cannot
    overwrite the new holder's outcome.
  * Per-channel success is remembered, so a retry never re-sends a channel that already succeeded.
  * Delivery is AT-LEAST-ONCE. A crash after the provider accepted a message but before the database recorded it can send
    that channel once more on retry. Exactly-once against an external provider is not achievable and is not claimed.
  * Retry with exponential backoff and jitter; alerts older than ``TTL`` expire instead of being sent late; a per-user
    hourly cap defers (does not fail) alerts.
  * An alert is sent only to channels that are VERIFIED for the CURRENT guardian and only while the account holder's
    authorisation stands (re-checked from the live config at delivery time).
  * Attempts never exceed ``max_attempts``: a row whose worker died on its last attempt is failed, not retried again.
  * Terminal rows (sent, skipped, expired, failed) and their delivery audit are purged after ``RETENTION`` (90 days).
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.elderly_config import ElderlyConfig
from app.models.guardian_outbox import (
    EXPIRED,
    FAILED,
    LEASED,
    PENDING,
    SENT,
    SKIPPED,
    GuardianAlertDelivery,
    GuardianAlertOutbox,
)
from app.models.user import User
from app.services import guardian_alerts as rules
from app.services import notifications
from app.services.logger_service import get_logger

logger = get_logger(__name__)

TTL = timedelta(days=7)
RETENTION = timedelta(
    days=90
)  # terminal alerts and their delivery audit are deleted this long after their last change
PURGE_EVERY_SECONDS = 3600
TERMINAL = (SENT, SKIPPED, EXPIRED, FAILED)
LEASE = timedelta(minutes=5)
MAX_ATTEMPTS = 5
HOURLY_CAP = 10
BACKOFF_BASE_SECONDS = 60
BACKOFF_MAX_SECONDS = 3600


def backoff_seconds(attempts: int, jitter: float | None = None) -> float:
    """Delay after the ``attempts``-th failed attempt: 60s, 120s, 240s ... capped at 1h, plus up to 10% jitter."""
    base = min(BACKOFF_BASE_SECONDS * (2 ** max(attempts - 1, 0)), BACKOFF_MAX_SECONDS)
    return base * (1 + (random.random() * 0.1 if jitter is None else jitter))


async def enqueue(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    event_id: Optional[uuid.UUID],
    dedupe_key: str,
    payload: dict,
    now: Optional[datetime] = None,
) -> tuple[Optional[uuid.UUID], bool]:
    """Insert once per (user, dedupe_key). Returns (outbox id, created). Does not commit."""
    now = now or datetime.utcnow()
    stmt = (
        pg_insert(GuardianAlertOutbox)
        .values(
            id=uuid.uuid4(),
            user_id=user_id,
            event_id=event_id,
            dedupe_key=dedupe_key,
            payload=payload,
            status=PENDING,
            attempts=0,
            max_attempts=MAX_ATTEMPTS,
            next_attempt_at=now,
            channels_done={},
            expires_at=now + TTL,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_nothing(index_elements=["user_id", "dedupe_key"])
        .returning(GuardianAlertOutbox.id)
    )
    row = (await db.execute(stmt)).first()
    if row is not None:
        return row[0], True
    existing = (
        await db.execute(
            select(GuardianAlertOutbox.id).where(
                GuardianAlertOutbox.user_id == user_id,
                GuardianAlertOutbox.dedupe_key == dedupe_key,
            )
        )
    ).first()
    return (existing[0] if existing else None), False


async def status_for_event(
    db: AsyncSession, user_id: uuid.UUID, event_id: uuid.UUID
) -> Optional[str]:
    return (
        await db.execute(
            select(GuardianAlertOutbox.status).where(
                GuardianAlertOutbox.user_id == user_id,
                GuardianAlertOutbox.event_id == event_id,
            )
        )
    ).scalar_one_or_none()


async def expire_old(db: AsyncSession, now: datetime) -> int:
    res = await db.execute(
        update(GuardianAlertOutbox)
        .where(
            GuardianAlertOutbox.expires_at < now,
            or_(
                GuardianAlertOutbox.status == PENDING,
                and_(
                    GuardianAlertOutbox.status == LEASED,
                    GuardianAlertOutbox.lease_expires_at < now,
                ),
            ),
        )
        .values(
            status=EXPIRED, lease_token=None, updated_at=now, last_error_code="expired"
        )
    )
    return res.rowcount or 0


async def fail_exhausted(db: AsyncSession, now: datetime) -> int:
    """Rows that are due (or whose lease expired) but have already used every attempt are failed, never leased again.
    This is the guard against a worker that died on the last attempt causing a ``max_attempts + 1``-th send."""
    res = await db.execute(
        update(GuardianAlertOutbox)
        .where(
            GuardianAlertOutbox.attempts >= GuardianAlertOutbox.max_attempts,
            or_(
                GuardianAlertOutbox.status == PENDING,
                and_(
                    GuardianAlertOutbox.status == LEASED,
                    GuardianAlertOutbox.lease_expires_at < now,
                ),
            ),
        )
        .values(
            status=FAILED,
            lease_token=None,
            lease_expires_at=None,
            updated_at=now,
            last_error_code="attempts_exhausted",
        )
    )
    return res.rowcount or 0


async def purge_terminal(db: AsyncSession, now: Optional[datetime] = None) -> int:
    """Delete terminal alerts older than ``RETENTION``; their delivery-audit rows go by cascade. Commits. Returns the count."""
    now = now or datetime.utcnow()
    res = await db.execute(
        delete(GuardianAlertOutbox).where(
            GuardianAlertOutbox.status.in_(TERMINAL),
            GuardianAlertOutbox.updated_at < now - RETENTION,
        )
    )
    await db.commit()
    return res.rowcount or 0


async def claim_due(
    db: AsyncSession,
    *,
    now: Optional[datetime] = None,
    limit: int = 10,
    lease: timedelta = LEASE,
) -> list[GuardianAlertOutbox]:
    """Atomically lease up to ``limit`` due rows (pending and due, or leased with an expired lease). Commits."""
    now = now or datetime.utcnow()
    await expire_old(db, now)
    await fail_exhausted(db, now)
    due = (
        select(GuardianAlertOutbox.id)
        .where(
            or_(
                and_(
                    GuardianAlertOutbox.status == PENDING,
                    GuardianAlertOutbox.next_attempt_at <= now,
                ),
                and_(
                    GuardianAlertOutbox.status == LEASED,
                    GuardianAlertOutbox.lease_expires_at < now,
                ),
            )
        )
        .order_by(GuardianAlertOutbox.next_attempt_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    stmt = (
        update(GuardianAlertOutbox)
        .where(GuardianAlertOutbox.id.in_(due.scalar_subquery()))
        .values(
            status=LEASED,
            lease_token=func.gen_random_uuid(),
            lease_expires_at=now + lease,
            attempts=GuardianAlertOutbox.attempts + 1,
            updated_at=now,
        )
        .returning(GuardianAlertOutbox)
        .execution_options(populate_existing=True)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    await db.commit()
    return rows


async def _finalise(
    db: AsyncSession,
    row: GuardianAlertOutbox,
    token: uuid.UUID,
    *,
    status: str,
    now: datetime,
    next_attempt_at: Optional[datetime] = None,
    error_code: Optional[str] = None,
    channels_done: Optional[dict] = None,
    refund_attempt: bool = False,
) -> bool:
    """Compare-and-set on the lease token. False = the lease was lost, nothing was written."""
    values = dict(
        status=status,
        lease_token=None,
        lease_expires_at=None,
        updated_at=now,
        last_error_code=error_code,
    )
    if status == SENT:
        values["sent_at"] = now
    if next_attempt_at is not None:
        values["next_attempt_at"] = next_attempt_at
    if channels_done is not None:
        values["channels_done"] = channels_done
    if refund_attempt:
        values["attempts"] = GuardianAlertOutbox.attempts - 1
    res = await db.execute(
        update(GuardianAlertOutbox)
        .where(
            GuardianAlertOutbox.id == row.id,
            GuardianAlertOutbox.lease_token == token,
            GuardianAlertOutbox.status == LEASED,
        )
        .values(**values)
    )
    await db.commit()
    return (res.rowcount or 0) == 1


async def _sent_in_last_hour(
    db: AsyncSession, user_id: uuid.UUID, now: datetime
) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(GuardianAlertOutbox)
            .where(
                GuardianAlertOutbox.user_id == user_id,
                GuardianAlertOutbox.status == SENT,
                GuardianAlertOutbox.sent_at > now - timedelta(hours=1),
            )
        )
    ).scalar_one()


async def process(
    db: AsyncSession, row: GuardianAlertOutbox, *, now: Optional[datetime] = None
) -> str:
    """Deliver one leased row. Returns the resulting status (or ``lost`` if the lease was lost)."""
    now = now or datetime.utcnow()
    token = row.lease_token
    payload = dict(row.payload or {})
    cfg = (
        await db.execute(
            select(ElderlyConfig).where(ElderlyConfig.user_id == row.user_id)
        )
    ).scalar_one_or_none()

    # Live config: a disabled/changed guardian setting at delivery time wins over the one at enqueue time.
    reason = rules.check_eligibility(cfg, int(payload.get("risk_score", 0)))
    if reason:
        ok = await _finalise(
            db,
            row,
            token,
            status=SKIPPED,
            now=now,
            error_code=rules.REASON_CODES[reason],
        )
        return SKIPPED if ok else "lost"

    # Durable per-user cap (the old in-memory counter reset on every restart): defer, do not fail, do not burn an attempt.
    if await _sent_in_last_hour(db, row.user_id, now) >= HOURLY_CAP:
        ok = await _finalise(
            db,
            row,
            token,
            status=PENDING,
            now=now,
            next_attempt_at=now + timedelta(minutes=10),
            error_code="rate_limited",
            refund_attempt=True,
        )
        return PENDING if ok else "lost"

    user = await db.get(User, row.user_id)
    occurred = payload.get("occurred_at")
    message = rules.build_message(
        user_name=(user.full_name or user.phone or "Unknown") if user else "Unknown",
        guardian_name=cfg.guardian_name,
        app_name=str(payload.get("app_name", "an app")),
        risk_score=int(payload.get("risk_score", 0)),
        risk_level=str(payload.get("risk_level", "warning")),
        risk_tags=payload.get("risk_tags") or [],
        clone_verdict=payload.get("clone_verdict"),
        occurred_at=datetime.fromisoformat(occurred) if occurred else None,
    )

    wanted: list[tuple[str, object]] = []
    allowed = set(
        rules.deliverable_channels(cfg)
    )  # verified channels for the current guardian, nothing else
    if "sms" in allowed:
        wanted.append(
            ("sms", lambda: notifications.send_sms(cfg.guardian_phone, message))
        )
    if "email" in allowed:
        wanted.append(
            (
                "email",
                lambda: notifications.send_email(
                    cfg.guardian_email, "SecureShield Guardian Alert", message
                ),
            )
        )
    done = dict(row.channels_done or {})
    this_attempt: dict[str, bool] = {}
    for name, send in wanted:
        if done.get(name):
            continue  # already delivered on an earlier attempt: never repeated
        try:
            ok = bool(await send())
            result, code = ("ok", None) if ok else ("failed", "provider_failed")
        except Exception as exc:  # noqa: BLE001 - one channel failing must not stop the other
            ok, result, code = False, "error", type(exc).__name__[:40]
            logger.error(
                f"[ELDERLY] user={row.user_id} {name} delivery raised {type(exc).__name__}"
            )
        this_attempt[name] = ok
        db.add(
            GuardianAlertDelivery(
                outbox_id=row.id,
                attempt_no=row.attempts,
                channel=name,
                result=result,
                error_code=code,
            )
        )
        if ok:
            done[name] = True
        await db.commit()

    if this_attempt:
        outcome = ",".join(
            f"{k}={'ok' if v else 'failed'}" for k, v in this_attempt.items()
        )
        if not any(this_attempt.values()):
            logger.error(
                f"[ELDERLY] user={row.user_id} guardian alert could not be delivered on any channel ({outcome})"
            )
        else:
            logger.info(
                f"[ELDERLY] user={row.user_id} guardian alert delivered: "
                f"risk={payload.get('risk_level', 'warning')} score={int(payload.get('risk_score', 0))} ({outcome})"
            )

    if all(done.get(name) for name, _ in wanted):
        ok = await _finalise(db, row, token, status=SENT, now=now, channels_done=done)
        return SENT if ok else "lost"
    if row.attempts >= row.max_attempts:
        ok = await _finalise(
            db,
            row,
            token,
            status=FAILED,
            now=now,
            channels_done=done,
            error_code="attempts_exhausted",
        )
        return FAILED if ok else "lost"
    ok = await _finalise(
        db,
        row,
        token,
        status=PENDING,
        now=now,
        channels_done=done,
        error_code="provider_failed",
        next_attempt_at=now + timedelta(seconds=backoff_seconds(row.attempts)),
    )
    return PENDING if ok else "lost"


async def run_once(
    db: AsyncSession, *, limit: int = 10, now: Optional[datetime] = None
) -> dict:
    """Claim and process due rows. Safe to run from any number of workers at once."""
    rows = await claim_due(db, now=now, limit=limit)
    out: dict[str, int] = {}
    for row in rows:
        try:
            status = await process(db, row, now=now)
        except Exception as exc:  # noqa: BLE001 - leave the lease to expire; another run retries it
            await db.rollback()
            logger.error(f"[GUARDIAN-OUTBOX] processing failed: {type(exc).__name__}")
            status = "error"
        out[status] = out.get(status, 0) + 1
    return out


def dispatch_enabled() -> bool:
    """May this process SEND guardian notifications (SMS / e-mail)? Same switch as the worker: on in production by default,
    off in development/test/staging unless GUARDIAN_WORKER_ENABLED=true. Unreadable settings count as off."""
    from app.config import settings

    try:
        return bool(settings.guardian_worker_enabled())
    except Exception:  # noqa: BLE001
        return False


async def run_once_safe() -> None:
    """Best-effort immediate attempt after a sync (its own session). The periodic worker is the safety net.

    Request-triggered (BackgroundTasks in app_monitor / elderly_protection), so it honours the same switch as the worker:
    when dispatch is disabled nothing is claimed or sent; the alert stays queued in the outbox.
    """
    from app.database import AsyncSessionLocal

    if not dispatch_enabled():
        logger.info(
            "[GUARDIAN-OUTBOX] immediate dispatch skipped: guardian dispatch is disabled in this environment"
        )
        return
    try:
        async with AsyncSessionLocal() as db:
            await run_once(db)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[GUARDIAN-OUTBOX] immediate run failed: {type(exc).__name__}")


async def purge_safe() -> None:
    from app.database import AsyncSessionLocal
    from app.db_identity import retention_gate

    decision = retention_gate()
    if not decision.allowed:
        logger.warning(f"[GUARDIAN-OUTBOX] purge blocked: {decision.reason}")
        return
    try:
        async with AsyncSessionLocal() as db:
            n = await purge_terminal(db)
        if n:
            logger.info(
                f"[GUARDIAN-OUTBOX] purged {n} terminal alert(s) past retention"
            )
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[GUARDIAN-OUTBOX] purge failed: {type(exc).__name__}")


async def worker_loop(poll_seconds: float) -> None:
    """Periodic worker started at application startup (see app.main). Cancelled at shutdown."""
    if (
        not dispatch_enabled()
    ):  # defence in depth: the worker must never run where dispatch is disabled
        logger.info(
            "[GUARDIAN-OUTBOX] worker not started: guardian dispatch is disabled in this environment"
        )
        return
    last_purge = 0.0
    while True:
        await run_once_safe()
        if time.monotonic() - last_purge >= PURGE_EVERY_SECONDS:
            await purge_safe()
            last_purge = time.monotonic()
        await asyncio.sleep(poll_seconds)


def poll_seconds_from_env() -> float:
    """``GUARDIAN_OUTBOX_POLL_SECONDS`` through the shared settings (default 30). 0, negative or unparsable disables the periodic worker."""
    from app.config import load_settings

    try:
        raw = (
            load_settings().GUARDIAN_OUTBOX_POLL_SECONDS
        )  # shared settings: process env > selected env file
    except Exception:  # noqa: BLE001 - an unreadable configuration must not enable the worker by accident
        return 0.0
    if raw is None or not str(raw).strip():
        return 30.0
    try:
        return float(raw)
    except ValueError:
        return 0.0
