"""Authentication and authorisation dependencies for the admin API.

Two ways in, evaluated in this order:
  1. ``Authorization: Bearer <admin token>`` - a short-lived token issued by ``POST /admin/auth/login`` after password AND
     MFA. It carries a session id; the session row is checked on every request, so revoking it (or deactivating the
     account) takes effect immediately. Role and account state are always read from the database, never from the token.
  2. ``X-Admin-Token`` - the legacy shared secret, accepted only while ``ADMIN_LEGACY_TOKEN_ENABLED`` is true. It maps to the
     ``admin`` role, can never manage admin accounts, is throttled like before, and is recorded in the audit log as
     ``legacy-token`` (no identity).

A bearer token that is present but invalid is rejected; it never silently falls back to the legacy token.
Admin tokens have ``type=admin`` and are refused by the end-user API (which requires ``type=access``), and end-user tokens
are refused here.
"""

from __future__ import annotations

import calendar
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from jwt import PyJWTError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin_settings import admin_settings
from app.config import settings
from app.database import get_db
from app.models.admin_account import AdminAccount, AdminSession
from app.models.admin_audit import AdminAuditLog
from app.services.client_ip import client_ip_for

ROLE_RANK = {"support": 1, "admin": 2, "superadmin": 3}
LEGACY_LABEL = "legacy-token"
TOKEN_TYPE = "admin"


@dataclass
class AdminPrincipal:
    kind: str  # "account" | "legacy"
    role: str
    account: AdminAccount | None = None
    session: AdminSession | None = None

    @property
    def admin_id(self) -> uuid.UUID | None:
        return self.account.id if self.account else None

    @property
    def label(self) -> str:
        return LEGACY_LABEL if self.kind == "legacy" else f"admin:{self.account.id}"  # type: ignore[union-attr]


def unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def issue_token(session: AdminSession, now: datetime | None = None) -> tuple[str, int]:
    """Sign an access token for ``session``; it never outlives the session. Returns (token, seconds valid)."""
    now = now or datetime.utcnow()
    expires = min(
        now + timedelta(minutes=admin_settings.ADMIN_ACCESS_TOKEN_MINUTES),
        session.expires_at,
    )
    token = jwt.encode(
        {
            "sub": str(session.admin_id),
            "sid": str(session.id),
            "type": TOKEN_TYPE,
            "scope": session.scope,
            # ``now`` is naive UTC (datetime.utcnow); .timestamp() would read it as local time.
            "iat": calendar.timegm(now.utctimetuple()),
            "exp": calendar.timegm(expires.utctimetuple()),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return token, max(0, int((expires - now).total_seconds()))


async def revoke_sessions(
    db: AsyncSession, admin_id: uuid.UUID, *, except_session: uuid.UUID | None = None
) -> None:
    stmt = update(AdminSession).where(
        AdminSession.admin_id == admin_id, AdminSession.revoked_at.is_(None)
    )
    if except_session is not None:
        stmt = stmt.where(AdminSession.id != except_session)
    await db.execute(stmt.values(revoked_at=datetime.utcnow()))


def add_audit(
    db: AsyncSession,
    principal: AdminPrincipal | None,
    action: str,
    request: Request | None,
    *,
    target_user_id: uuid.UUID | None = None,
    actor_admin_id: uuid.UUID | None = None,
    detail: dict | None = None,
) -> None:
    """Queue an audit row (the caller commits). ``detail`` must never hold secrets, codes or free text from clients."""
    actor = actor_admin_id or (principal.admin_id if principal else None)
    label = principal.label if principal else (f"admin:{actor}" if actor else None)
    db.add(
        AdminAuditLog(
            action=action,
            target_user_id=target_user_id,
            detail=detail or {},
            client_ip=client_ip_for(request, None) if request is not None else None,
            actor_admin_id=actor,
            actor_label=label,
        )
    )


async def _from_bearer(token: str, db: AsyncSession) -> AdminPrincipal:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        if payload.get("type") != TOKEN_TYPE:
            raise unauthorized("Invalid token")
        admin_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
    except HTTPException:
        raise
    except (PyJWTError, ValueError, KeyError, TypeError):
        raise unauthorized("Invalid or expired token")

    now = datetime.utcnow()
    session = (
        await db.execute(select(AdminSession).where(AdminSession.id == session_id))
    ).scalar_one_or_none()
    if (
        session is None
        or session.admin_id != admin_id
        or session.revoked_at is not None
        or session.expires_at <= now
        or session.scope != payload.get("scope")
    ):
        raise unauthorized("Invalid or expired token")
    account = (
        await db.execute(select(AdminAccount).where(AdminAccount.id == admin_id))
    ).scalar_one_or_none()
    if account is None or not account.is_active:
        raise unauthorized("Invalid or expired token")
    return AdminPrincipal(
        kind="account", role=account.role, account=account, session=session
    )


def require_role(
    min_role: str = "support",
    *,
    scopes: tuple[str, ...] = ("full",),
    allow_legacy: bool = True,
):
    """FastAPI dependency factory: authenticate and authorise an admin call (401 unauthenticated, 403 insufficient role)."""
    needed = ROLE_RANK[min_role]

    async def dependency(
        request: Request,
        authorization: Optional[str] = Header(None),
        x_admin_token: Optional[str] = Header(None),
        db: AsyncSession = Depends(get_db),
    ) -> AdminPrincipal:
        if authorization:
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                raise unauthorized("Invalid authorization header")
            principal = await _from_bearer(token.strip(), db)
            if principal.session.scope not in scopes:  # type: ignore[union-attr]
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Finish account setup (password change and MFA enrolment) first"
                    if principal.session.scope == "setup"  # type: ignore[union-attr]
                    else "This token cannot be used here",
                )
        elif x_admin_token is not None:
            if not allow_legacy or not admin_settings.ADMIN_LEGACY_TOKEN_ENABLED:
                raise unauthorized("Admin token authentication is not enabled")
            from app.routers.admin_errors import (
                _check_admin,
            )  # local import: avoids a router import cycle

            _check_admin(
                x_admin_token
            )  # constant-time compare + global failed-attempt throttle
            principal = AdminPrincipal(kind="legacy", role="admin")
        else:
            raise unauthorized()
        if ROLE_RANK.get(principal.role, 0) < needed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role"
            )
        request.state.admin_principal = principal
        return principal

    return dependency
