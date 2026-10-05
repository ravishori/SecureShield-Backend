"""Admin operations: platform statistics and user account control.

Protected by the same static ``X-Admin-Token`` as the error-log admin API (constant-time compare).
Responses never include credentials, OTPs, tokens or hashed passwords. Every state change is
written to the application log (actor is the token holder, i.e. "admin") with the target id only.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.evidence import Evidence
from app.models.recording import Recording
from app.models.user import User
from app.routers.admin_errors import _check_admin
from app.services.logger_service import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(x_admin_token: Optional[str] = Header(None)) -> None:
    _check_admin(x_admin_token)


class StatusBody(BaseModel):
    is_active: bool


def _view(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "phone": u.phone,
        "full_name": u.full_name,
        "subscription_tier": getattr(
            u.subscription_tier, "value", str(u.subscription_tier)
        ),
        "is_active": u.is_active,
        "senior_mode": u.senior_mode,
        "created_at": u.created_at,
    }


def _like(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\%").replace("_", "\_")


@router.get("/stats", dependencies=[Depends(require_admin)])
async def platform_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(User.id)))).scalar_one()
    active = (
        await db.execute(select(func.count(User.id)).where(User.is_active.is_(True)))
    ).scalar_one()
    senior = (
        await db.execute(select(func.count(User.id)).where(User.senior_mode.is_(True)))
    ).scalar_one()
    evidence = (await db.execute(select(func.count(Evidence.id)))).scalar_one()
    recordings = (await db.execute(select(func.count(Recording.id)))).scalar_one()
    return {
        "users_total": total,
        "users_active": active,
        "users_disabled": total - active,
        "users_senior_mode": senior,
        "evidence_items": evidence,
        "recordings": recordings,
    }


@router.get("/users", dependencies=[Depends(require_admin)])
async def list_users(
    q: Optional[str] = Query(
        None, max_length=100, description="Substring of e-mail, phone or name"
    ),
    is_active: Optional[bool] = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User)
    if q:
        pat = f"%{_like(q.strip())}%"
        stmt = stmt.where(
            User.email.ilike(pat, escape="\\")
            | User.phone.ilike(pat, escape="\\")
            | User.full_name.ilike(pat, escape="\\")
        )
    if is_active is not None:
        stmt = stmt.where(User.is_active.is_(is_active))
    total = (
        await db.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                stmt.order_by(User.created_at.desc(), User.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_view(u) for u in rows],
    }


@router.patch("/users/{user_id}/status", dependencies=[Depends(require_admin)])
async def set_user_status(
    user_id: str, body: StatusBody, db: AsyncSession = Depends(get_db)
):
    """Disable or re-enable an account. A disabled account fails every authenticated request
    (get_current_user rejects inactive users) and cannot refresh tokens."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_active != body.is_active:
        user.is_active = body.is_active
        await db.commit()
        logger.warning(
            f"[ADMIN] user {user.id} {'enabled' if body.is_active else 'disabled'}"
        )
    return _view(user)
