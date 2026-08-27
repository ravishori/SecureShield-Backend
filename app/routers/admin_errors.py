"""
Admin / observability router — query and inspect the error_logs table.

NOT exposed to end users. Protected by a static admin-token header check.

Set ADMIN_TOKEN in .env to a strong secret. Then call with:
    curl -H "X-Admin-Token: $ADMIN_TOKEN" \
         http://localhost:8000/api/v1/admin/errors?level=CRITICAL&limit=20
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.config import settings
from app.database import get_db
from app.models.error_log import ErrorLog

router = APIRouter(prefix="/admin", tags=["admin-errors"])


def _check_admin(token: Optional[str]) -> None:
    expected = (settings.ADMIN_TOKEN or "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin endpoint is not configured (ADMIN_TOKEN missing).",
        )
    if not token or token != expected:
        raise HTTPException(status_code=401, detail="Invalid admin token")


@router.get("/errors")
async def list_errors(
    level: Optional[str] = Query(None, description="DEBUG/INFO/WARNING/ERROR/CRITICAL"),
    endpoint: Optional[str] = Query(None, description="Filter by endpoint substring"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None),
) -> dict[str, Any]:
    """List recent error_logs rows with optional filters."""
    _check_admin(x_admin_token)

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
                "id":             r.id,
                "level":          r.level,
                "message":        r.message,
                "exception_type": r.exception_type,
                "endpoint":       r.endpoint,
                "method":         r.method,
                "user_id":        r.user_id,
                "client_ip":      r.client_ip,
                "email_sent":     r.email_sent,
                "created_at":     r.created_at.isoformat() if r.created_at else None,
                "has_traceback":  bool(r.traceback),
            }
            for r in rows
        ],
    }


@router.get("/errors/{error_id}")
async def get_error(
    error_id: int,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None),
) -> dict[str, Any]:
    """Fetch one error_log row including full traceback + extra."""
    _check_admin(x_admin_token)

    row = await db.get(ErrorLog, error_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"error_log {error_id} not found")

    return {
        "id":             row.id,
        "level":          row.level,
        "message":        row.message,
        "exception_type": row.exception_type,
        "traceback":      row.traceback,
        "endpoint":       row.endpoint,
        "method":         row.method,
        "user_id":        row.user_id,
        "client_ip":      row.client_ip,
        "extra":          row.extra,
        "email_sent":     row.email_sent,
        "created_at":     row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/errors/stats/summary")
async def errors_summary(
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None),
) -> dict[str, Any]:
    """Aggregate counts by level + top noisy endpoints (last 24h)."""
    _check_admin(x_admin_token)

    # Per-level counts
    level_rows = (await db.execute(
        select(ErrorLog.level, func.count())
        .group_by(ErrorLog.level)
    )).all()

    # Top 10 noisiest endpoints
    endpoint_rows = (await db.execute(
        select(ErrorLog.endpoint, func.count())
        .where(ErrorLog.endpoint.isnot(None))
        .group_by(ErrorLog.endpoint)
        .order_by(desc(func.count()))
        .limit(10)
    )).all()

    return {
        "by_level": {lvl: cnt for lvl, cnt in level_rows},
        "top_endpoints": [{"endpoint": ep, "count": cnt} for ep, cnt in endpoint_rows],
    }
