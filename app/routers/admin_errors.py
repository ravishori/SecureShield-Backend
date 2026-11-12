"""
Admin / observability router — query and inspect the error_logs table.

NOT exposed to end users. Requires an admin session (``Authorization: Bearer`` from /admin/auth/login, any role) or,
while ADMIN_LEGACY_TOKEN_ENABLED is true, the legacy shared token below.

Legacy call (set ADMIN_TOKEN in .env to a strong secret):
    curl -H "X-Admin-Token: $ADMIN_TOKEN" \
         http://localhost:8000/api/v1/admin/errors?level=CRITICAL&limit=20
"""

from __future__ import annotations

import hmac
import threading
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.config import settings
from app.database import get_db
from app.middleware.rate_limiter import rate_limiter
from app.models.error_log import ErrorLog
from app.services.admin_access import AdminPrincipal, require_role
from app.services.logger_service import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/admin", tags=["admin-errors"])


# FG-166: failed-attempt throttle for the shared admin token.
#
# Why ONE global budget and not a per-IP one: the token is shared, so an attacker's identity does not matter,
# and the client IP the app can see is attacker-controlled (the global limiter trusts the first X-Forwarded-For
# value), so any per-IP key could be bypassed by changing a header. Only wrong, non-empty tokens count; missing
# tokens and correct tokens never consume the budget. When the budget is spent EVERY admin authentication is
# answered with the same 429 (the token is not even compared), so the response never says whether a guess was
# close. The window slides: throttled requests are not recorded, so access returns once the oldest failures
# age out - there is no permanent lockout. Trade-off: while an attacker keeps failing, the admin can be
# locked out for up to one window (denial of the admin surface, not access to it).
#
# Backend: the app-wide limiter (in-memory, per process; the Redis backend is not implemented). With several
# workers/replicas the budget is per process. If the limiter itself fails the request is denied (fail closed).
_ADMIN_FAIL_KEY = "admin_auth_fail"
_admin_lock = (
    threading.Lock()
)  # sync dependencies run in a thread pool: make check + record atomic


def _admin_throttled() -> HTTPException:
    return HTTPException(
        status_code=429,
        detail="Too many failed admin attempts. Try again later.",
        headers={"Retry-After": str(settings.ADMIN_AUTH_FAIL_WINDOW_SECONDS)},
    )


def _check_admin(token: Optional[str]) -> None:
    expected = (settings.ADMIN_TOKEN or "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin endpoint is not configured (ADMIN_TOKEN missing).",
        )
    limit = settings.ADMIN_AUTH_FAIL_LIMIT
    window = settings.ADMIN_AUTH_FAIL_WINDOW_SECONDS
    with _admin_lock:
        try:
            if rate_limiter.current_count(_ADMIN_FAIL_KEY, window) >= limit:
                raise _admin_throttled()
        except HTTPException:
            raise
        except Exception as exc:  # limiter unavailable -> deny, never fail open
            logger.error(f"admin throttle unavailable: {type(exc).__name__}")
            raise HTTPException(
                status_code=503, detail="Admin temporarily unavailable."
            )
        if not token:
            raise HTTPException(status_code=401, detail="Invalid admin token")
        if hmac.compare_digest(token.encode(), expected.encode()):
            return
        try:
            rate_limiter.is_allowed(
                _ADMIN_FAIL_KEY, max_hits=limit, window_seconds=window
            )
        except Exception as exc:
            logger.error(f"admin throttle unavailable: {type(exc).__name__}")
            raise HTTPException(
                status_code=503, detail="Admin temporarily unavailable."
            )
    raise HTTPException(status_code=401, detail="Invalid admin token")


@router.get("/errors")
async def list_errors(
    level: Optional[str] = Query(None, description="DEBUG/INFO/WARNING/ERROR/CRITICAL"),
    endpoint: Optional[str] = Query(None, description="Filter by endpoint substring"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _principal: AdminPrincipal = Depends(require_role("support")),
) -> dict[str, Any]:
    """List recent error_logs rows with optional filters."""
    q = select(ErrorLog)
    if level:
        q = q.where(ErrorLog.level == level.upper())
    if endpoint:
        q = q.where(ErrorLog.endpoint.ilike(f"%{endpoint}%"))
    q = q.order_by(desc(ErrorLog.created_at)).offset(offset).limit(limit)

    rows = (await db.execute(q)).scalars().all()
    return {
        "count": len(rows),
        "offset": offset,
        "errors": [
            {
                "id": r.id,
                "level": r.level,
                "message": r.message,
                "exception_type": r.exception_type,
                "endpoint": r.endpoint,
                "method": r.method,
                "user_id": r.user_id,
                "client_ip": r.client_ip,
                "email_sent": r.email_sent,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "has_traceback": bool(r.traceback),
            }
            for r in rows
        ],
    }


@router.get("/errors/{error_id}")
async def get_error(
    error_id: int,
    db: AsyncSession = Depends(get_db),
    _principal: AdminPrincipal = Depends(require_role("support")),
) -> dict[str, Any]:
    """Fetch one error_log row including full traceback + extra."""
    row = await db.get(ErrorLog, error_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"error_log {error_id} not found")

    return {
        "id": row.id,
        "level": row.level,
        "message": row.message,
        "exception_type": row.exception_type,
        "traceback": row.traceback,
        "endpoint": row.endpoint,
        "method": row.method,
        "user_id": row.user_id,
        "client_ip": row.client_ip,
        "extra": row.extra,
        "email_sent": row.email_sent,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/errors/stats/summary")
async def errors_summary(
    db: AsyncSession = Depends(get_db),
    _principal: AdminPrincipal = Depends(require_role("support")),
) -> dict[str, Any]:
    """Aggregate counts by level + top noisy endpoints (last 24h)."""
    # Per-level counts
    level_rows = (
        await db.execute(select(ErrorLog.level, func.count()).group_by(ErrorLog.level))
    ).all()

    # Top 10 noisiest endpoints
    endpoint_rows = (
        await db.execute(
            select(ErrorLog.endpoint, func.count())
            .where(ErrorLog.endpoint.isnot(None))
            .group_by(ErrorLog.endpoint)
            .order_by(desc(func.count()))
            .limit(10)
        )
    ).all()

    return {
        "by_level": {lvl: cnt for lvl, cnt in level_rows},
        "top_endpoints": [{"endpoint": ep, "count": cnt} for ep, cnt in endpoint_rows],
    }
