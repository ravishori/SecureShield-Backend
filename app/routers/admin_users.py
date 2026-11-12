"""Admin operations: platform statistics and user account control.

Requires an admin session (``Authorization: Bearer`` from /admin/auth/login) or, while ADMIN_LEGACY_TOKEN_ENABLED is
true, the legacy shared ``X-Admin-Token``. Responses never include credentials, OTPs, tokens or hashed passwords.
Every state change is written to the audit log with the actor (named admin or ``legacy-token``) and the target id.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.admin_audit import AdminAuditLog
from app.models.evidence import Evidence
from app.models.recording import Recording
from app.models.user import User
from app.services.admin_access import AdminPrincipal, add_audit, require_role
from app.services.logger_service import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


# Read-only views need any admin role; changing an end user needs "admin" (the legacy token counts as "admin").
require_admin = require_role("support")
require_operator = require_role("admin")


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


@router.patch("/users/{user_id}/status")
async def set_user_status(
    user_id: str,
    body: StatusBody,
    request: Request,
    principal: AdminPrincipal = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
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
        add_audit(
            db,
            principal,
            "user.enable" if body.is_active else "user.disable",
            request,
            target_user_id=user.id,
            detail={"is_active": body.is_active},
        )
        await db.commit()
        logger.warning(
            f"[ADMIN] user {user.id} {'enabled' if body.is_active else 'disabled'}"
        )
    return _view(user)


@router.get("/audit", dependencies=[Depends(require_admin)])
async def audit_log(
    action: Optional[str] = Query(None, max_length=64),
    target_user_id: Optional[str] = Query(None, max_length=36),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100000),
    db: AsyncSession = Depends(get_db),
):
    """Newest-first list of admin actions. Append-only: no endpoint edits or deletes it."""
    stmt = select(AdminAuditLog)
    if action:
        stmt = stmt.where(AdminAuditLog.action == action)
    if target_user_id:
        try:
            stmt = stmt.where(AdminAuditLog.target_user_id == uuid.UUID(target_user_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="target_user_id must be a UUID")
    total = (
        await db.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                stmt.order_by(AdminAuditLog.created_at.desc(), AdminAuditLog.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "action": r.action,
                "target_user_id": r.target_user_id,
                "actor": r.actor_label,
                "actor_admin_id": r.actor_admin_id,
                "detail": r.detail,
                "client_ip": r.client_ip,
                "created_at": r.created_at,
            }
            for r in rows
        ],
    }
