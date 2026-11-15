"""Retention for the ``error_logs`` table (FG-034), moved out of application startup.

Deletion happens only through ``python -m app.cli.purge_error_logs`` (or a direct call), never at startup, and only when
``RETENTION_CLEANUP_ENABLED=true`` with a valid database identity (``app.db_identity.retention_gate``). A non-positive
``LOG_RETENTION_DAYS`` would make the cutoff "now" and delete EVERY row, so it is refused. Failures are reported by exception
class only; no row content is ever logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy import text

from app.services.logger_service import get_logger

logger = get_logger(__name__)

_DELETE_SQL = (
    "DELETE FROM error_logs "
    "WHERE created_at < NOW() - make_interval(days => :days) "
    "RETURNING id"
)
_COUNT_SQL = (
    "SELECT COUNT(*) FROM error_logs "
    "WHERE created_at < NOW() - make_interval(days => :days)"
)


@dataclass(frozen=True)
class ErrorLogPurgeResult:
    deleted: int
    days: int
    error: Optional[str] = None  # "blocked", "invalid_days" or an exception class name


def _days(days: Optional[int]) -> int:
    if days is not None:
        return days
    from app.config import settings

    return settings.LOG_RETENTION_DAYS


def _factory(session_factory: Optional[Callable]):
    if session_factory is not None:
        return session_factory
    from app import database

    return database.AsyncSessionLocal


async def count_old_error_logs(
    session_factory: Optional[Callable] = None, days: Optional[int] = None
) -> int:
    """Rows a purge would delete. Read-only; needs no retention flag. Raises on database errors."""
    retention_days = _days(days)
    if retention_days < 1:
        raise ValueError("LOG_RETENTION_DAYS must be a positive number of days")
    async with _factory(session_factory)() as session:
        return int(
            (
                await session.execute(text(_COUNT_SQL), {"days": retention_days})
            ).scalar_one()
        )


async def purge_old_error_logs(
    session_factory: Optional[Callable] = None, days: Optional[int] = None
) -> ErrorLogPurgeResult:
    """Delete ``error_logs`` rows older than the retention period. Never raises; deletes nothing when blocked."""
    from app.db_identity import retention_gate

    retention_days = _days(days)
    if retention_days < 1:
        logger.warning(
            "error-log retention refused: LOG_RETENTION_DAYS is not a positive number of days"
        )
        return ErrorLogPurgeResult(0, retention_days, "invalid_days")
    decision = retention_gate()
    if not decision.allowed:
        logger.warning("error-log retention blocked: %s", decision.reason)
        return ErrorLogPurgeResult(0, retention_days, "blocked")
    try:
        async with _factory(session_factory)() as session:
            result = await session.execute(text(_DELETE_SQL), {"days": retention_days})
            deleted = len(result.fetchall())
            await session.commit()
        logger.info("error-log retention: deleted=%d days=%d", deleted, retention_days)
        return ErrorLogPurgeResult(deleted, retention_days)
    except Exception as exc:  # noqa: BLE001
        logger.warning("error-log retention failed: class=%s", type(exc).__name__)
        return ErrorLogPurgeResult(0, retention_days, type(exc).__name__)
