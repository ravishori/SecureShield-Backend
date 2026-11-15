"""BH-2 retention for link-scan history (the ``link_scans`` table).

Policy: a scan record is kept for ``LINK_SCAN_RETENTION_DAYS`` (default 30). Records whose ``scanned_at`` is STRICTLY older
than that are eligible for deletion; a record exactly N days old is kept. Account deletion is unchanged
(``account_erasure`` removes a user's scans immediately, regardless of age).

Cleanup is bounded (``LINK_SCAN_PURGE_BATCH`` rows per statement, at most ``LINK_SCAN_PURGE_MAX_BATCHES`` statements per run),
repeatable (running it again deletes nothing more once the backlog is gone) and safe to run concurrently (a DELETE of rows
selected by id; a row already deleted by another run is simply not found). It uses no scheduler and NEVER runs at application startup: it runs from the
``python -m app.cli.purge_link_scans`` command and opportunistically at most once per hour per process after a scan.
Every deletion needs ``RETENTION_CLEANUP_ENABLED=true`` and a valid database identity (``app.db_identity.retention_gate``);
otherwise a run deletes nothing and returns ``error="blocked"``.
Failures are logged by exception CLASS only and recorded in ``last_run`` (no URL, row or parameter is ever logged).
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Dict, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import delete, select

from app.config import _resolve_env_files
from app.services.logger_service import get_logger

logger = get_logger(__name__)

DEFAULT_DAYS = 30
DEFAULT_BATCH = 500
DEFAULT_MAX_BATCHES = 20
_MAX_DAYS = 3650


class RetentionSettings(BaseSettings):
    """Raw strings, so a malformed value is detected rather than coerced. ``None`` = use the default."""

    LINK_SCAN_RETENTION_DAYS: Optional[str] = None
    LINK_SCAN_PURGE_BATCH: Optional[str] = None
    LINK_SCAN_PURGE_MAX_BATCHES: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )


retention_settings = RetentionSettings()


@dataclass(frozen=True)
class RetentionPolicy:
    days: int
    batch: int
    max_batches: int
    problems: (
        tuple  # variable names whose value was invalid and replaced by the default
    )


def _int(
    raw: Optional[str], default: int, low: int, high: int, name: str, problems: list
) -> int:
    if raw is None:
        return default
    if not re.fullmatch(r"[0-9]{1,6}", raw) or not (low <= int(raw) <= high):
        problems.append(
            name
        )  # fail SAFE: an invalid value never disables or lengthens retention
        return default
    return int(raw)


def current_policy() -> RetentionPolicy:
    problems: list = []
    s = retention_settings
    return RetentionPolicy(
        days=_int(
            s.LINK_SCAN_RETENTION_DAYS,
            DEFAULT_DAYS,
            1,
            _MAX_DAYS,
            "LINK_SCAN_RETENTION_DAYS",
            problems,
        ),
        batch=_int(
            s.LINK_SCAN_PURGE_BATCH,
            DEFAULT_BATCH,
            1,
            5000,
            "LINK_SCAN_PURGE_BATCH",
            problems,
        ),
        max_batches=_int(
            s.LINK_SCAN_PURGE_MAX_BATCHES,
            DEFAULT_MAX_BATCHES,
            1,
            1000,
            "LINK_SCAN_PURGE_MAX_BATCHES",
            problems,
        ),
        problems=tuple(problems),
    )


@dataclass(frozen=True)
class PurgeResult:
    deleted: int
    batches: int
    more_remaining: bool  # the per-run bound was reached; the next run continues
    error: Optional[str] = None  # exception class name only
    days: int = DEFAULT_DAYS


last_run: Dict[str, object] = {"at": None, "deleted": 0, "error": None}


def cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=days)


async def purge_expired(
    session_factory: Optional[Callable] = None, now: Optional[datetime] = None
) -> PurgeResult:
    """Delete expired link scans in bounded batches. Never raises."""
    from app.models.link_scan import LinkScan

    policy = current_policy()
    for name in policy.problems:
        logger.warning("link scan retention: %s is invalid; using the default", name)
    from app.db_identity import retention_gate

    decision = retention_gate()
    if not decision.allowed:
        logger.warning("link scan retention blocked: %s", decision.reason)
        return PurgeResult(0, 0, False, "blocked", policy.days)
    limit_time = cutoff(now or datetime.utcnow(), policy.days)
    if session_factory is None:
        from app import database

        session_factory = database.AsyncSessionLocal
    deleted = batches = 0
    more = False
    try:
        async with session_factory() as session:
            for _ in range(policy.max_batches):
                ids = (
                    select(LinkScan.id)
                    .where(LinkScan.scanned_at < limit_time)
                    .order_by(LinkScan.scanned_at)
                    .limit(policy.batch)
                )
                result = await session.execute(
                    delete(LinkScan).where(LinkScan.id.in_(ids))
                )
                await session.commit()
                n = result.rowcount or 0
                batches += 1
                deleted += n
                if n < policy.batch:
                    break
            else:
                more = True  # every allowed batch was full: there may be more
        outcome = PurgeResult(deleted, batches, more, None, policy.days)
    except Exception as exc:  # noqa: BLE001 - cleanup must never break startup or a request
        logger.warning("link scan retention failed: class=%s", type(exc).__name__)
        outcome = PurgeResult(deleted, batches, False, type(exc).__name__, policy.days)
    last_run.update(
        at=datetime.utcnow().isoformat(timespec="seconds"),
        deleted=outcome.deleted,
        error=outcome.error,
    )
    if outcome.deleted or outcome.error is None:
        logger.info(
            "link scan retention: deleted=%d batches=%d days=%d more_remaining=%s",
            outcome.deleted,
            outcome.batches,
            outcome.days,
            outcome.more_remaining,
        )
    return outcome


# ---- opportunistic trigger: at most once per hour per process, run after the response (BackgroundTasks) ---------------
_gate_lock = threading.Lock()
_gate = {"next": 0.0}
_GATE_SECONDS = 3600.0


def _due(clock: Callable[[], float] = time.monotonic) -> bool:
    with _gate_lock:
        now = clock()
        if now < _gate["next"]:
            return False
        _gate["next"] = now + _GATE_SECONDS
        return True


async def maybe_purge_expired() -> None:
    if _due():
        await purge_expired()
