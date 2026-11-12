"""Individually authenticated admin accounts: login with password + TOTP, sessions, MFA enrolment, recovery,
account management and audit.

Flow
  * ``POST /admin/auth/login`` (e-mail, password, ``totp_code`` or a one-time ``recovery_code``) -> access token.
    An account that has not finished setup (temporary password not yet changed, or MFA not yet enrolled) gets a
    ``setup``-scope token that works ONLY for ``/password/change`` and ``/mfa/enroll/*``; completing setup returns a
    ``full`` token. MFA is mandatory for every account: there is no way to switch it off.
  * Every failure is the same ``401 Invalid credentials`` (unknown e-mail, wrong password, wrong code, locked or
    disabled account); unknown e-mails cost the same time as wrong passwords.
  * Wrong password/code attempts lock the account (``ADMIN_LOGIN_MAX_FAILURES`` / ``ADMIN_LOCKOUT_MINUTES``); there is
    also a per-source limit. Lockout is denial, never access: a superadmin (or the CLI) can unlock.
  * Recovery: one-time recovery codes (shown once at enrolment) can replace the TOTP code at login; a superadmin can
    reset another admin's MFA or password (the target must re-enrol / change the password at next login); the CLI
    (``python -m app.cli.admin_accounts``) is the last resort when no superadmin can sign in.
  * Sessions can be listed and revoked; password changes, role changes, MFA resets and deactivation revoke sessions.
  * Every login, failure, lockout, enrolment, reset and account change is written to ``admin_audit_logs`` with the actor.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin_settings import admin_settings
from app.database import get_db
from app.middleware.rate_limiter import rate_limiter
from app.models.admin_account import ADMIN_ROLES, AdminAccount, AdminSession
from app.services.admin_access import (
    AdminPrincipal,
    add_audit,
    issue_token,
    require_role,
    revoke_sessions,
    unauthorized,
)
from app.services.admin_security import (
    DUMMY_HASH,
    consume_recovery_code,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    new_recovery_codes,
    new_totp_secret,
    password_problems,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.services.logger_service import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")

any_admin = require_role("support", scopes=("full",), allow_legacy=False)
setup_or_full = require_role("support", scopes=("setup", "full"), allow_legacy=False)
setup_only = require_role("support", scopes=("setup",), allow_legacy=False)
superadmin_only = require_role("superadmin", scopes=("full",), allow_legacy=False)


# ── schemas ──────────────────────────────────────────────────────────────────────────────────────────────────────
class LoginBody(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=256)
    totp_code: Optional[str] = Field(default=None, max_length=12)
    recovery_code: Optional[str] = Field(default=None, max_length=20)


class CodeBody(BaseModel):
    code: str = Field(max_length=12)


class PasswordChangeBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class CreateAccountBody(BaseModel):
    email: str = Field(max_length=255)
    role: str = Field(max_length=20)
    temporary_password: str = Field(max_length=256)


class RoleBody(BaseModel):
    role: str = Field(max_length=20)


class TempPasswordBody(BaseModel):
    temporary_password: str = Field(max_length=256)


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _bad_credentials() -> HTTPException:
    return unauthorized("Invalid credentials")


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _setup_pending(acct: AdminAccount) -> list[str]:
    pending = []
    if acct.must_change_password:
        pending.append("password")
    if not acct.totp_enabled:
        pending.append("mfa")
    return pending


async def _new_session(
    db: AsyncSession, acct: AdminAccount, request: Request, scope: str
) -> AdminSession:
    now = datetime.utcnow()
    session = AdminSession(
        admin_id=acct.id,
        scope=scope,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=admin_settings.ADMIN_SESSION_MAX_HOURS),
        client_ip=_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:200] or None,
    )
    db.add(session)
    await db.flush()
    return session


def _token_response(session: AdminSession, acct: AdminAccount, **extra) -> dict:
    token, seconds = issue_token(session)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": seconds,
        "scope": session.scope,
        "role": acct.role,
        "setup_required": _setup_pending(acct),
        **extra,
    }


async def _register_failure(
    db: AsyncSession, acct: AdminAccount, request: Request, reason: str
) -> None:
    acct.failed_logins += 1
    add_audit(
        db,
        None,
        "admin.login_failed",
        request,
        actor_admin_id=acct.id,
        detail={"reason": reason},
    )
    if acct.failed_logins >= admin_settings.ADMIN_LOGIN_MAX_FAILURES:
        acct.locked_until = datetime.utcnow() + timedelta(
            minutes=admin_settings.ADMIN_LOCKOUT_MINUTES
        )
        acct.failed_logins = 0
        add_audit(db, None, "admin.account_locked", request, actor_admin_id=acct.id)
        logger.warning(f"[ADMIN] account {acct.id} locked after repeated failures")
    await db.commit()  # the counter must survive the 401


async def _finish_setup_if_done(
    db: AsyncSession, acct: AdminAccount, session: AdminSession, request: Request
) -> dict:
    """After a setup step: when nothing is pending, trade the setup session for a full one."""
    if _setup_pending(acct):
        await db.commit()
        return _token_response(session, acct)
    session.revoked_at = datetime.utcnow()
    full = await _new_session(db, acct, request, "full")
    await db.commit()
    return _token_response(full, acct)


def _limit_or_429(key: str, max_hits: int, window: int, detail: str) -> None:
    if not rate_limiter.is_allowed(key, max_hits=max_hits, window_seconds=window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(window)},
        )


def _view(a: AdminAccount) -> dict:
    now = datetime.utcnow()
    return {
        "id": a.id,
        "email": a.email,
        "role": a.role,
        "is_active": a.is_active,
        "mfa_enabled": a.totp_enabled,
        "must_change_password": a.must_change_password,
        "locked": bool(a.locked_until and a.locked_until > now),
        "last_login_at": a.last_login_at,
        "created_at": a.created_at,
    }


# ── login / logout / refresh ─────────────────────────────────────────────────────────────────────────────────────
@router.post("/login")
async def login(body: LoginBody, request: Request, db: AsyncSession = Depends(get_db)):
    _limit_or_429(
        f"admin_login_ip:{_ip(request)}",
        admin_settings.ADMIN_LOGIN_IP_LIMIT,
        900,
        "Too many sign-in attempts. Try again later.",
    )
    email = body.email.strip().lower()
    acct = (
        await db.execute(
            select(AdminAccount).where(AdminAccount.email == email).with_for_update()
        )
    ).scalar_one_or_none()
    if acct is None:
        verify_password(body.password, DUMMY_HASH)  # same work as a real check
        raise _bad_credentials()

    now = datetime.utcnow()
    password_ok = verify_password(body.password, acct.password_hash)
    if (acct.locked_until and acct.locked_until > now) or not acct.is_active:
        raise _bad_credentials()  # not counted: a locked/disabled account gives nothing away
    if not password_ok:
        await _register_failure(db, acct, request, "password")
        raise _bad_credentials()

    if acct.totp_enabled:
        accepted = False
        secret = decrypt_secret(acct.totp_secret_enc or "")
        if body.totp_code and secret:
            step = verify_totp(secret, body.totp_code, acct.totp_last_step)
            if step is not None:
                acct.totp_last_step = step
                accepted = True
        elif body.recovery_code:
            remaining = consume_recovery_code(acct.recovery_hashes, body.recovery_code)
            if remaining is not None:
                acct.recovery_hashes = remaining
                add_audit(
                    db,
                    None,
                    "admin.recovery_code_used",
                    request,
                    actor_admin_id=acct.id,
                    detail={"codes_left": len(remaining)},
                )
                accepted = True
        if not accepted:
            await _register_failure(db, acct, request, "mfa")
            raise _bad_credentials()

    scope = "full" if not _setup_pending(acct) else "setup"
    acct.failed_logins = 0
    acct.locked_until = None
    acct.last_login_at = now
    session = await _new_session(db, acct, request, scope)
    add_audit(
        db,
        None,
        "admin.login",
        request,
        actor_admin_id=acct.id,
        detail={"scope": scope},
    )
    await db.commit()
    return _token_response(session, acct)


@router.post("/logout")
async def logout(
    request: Request,
    p: AdminPrincipal = Depends(setup_or_full),
    db: AsyncSession = Depends(get_db),
):
    p.session.revoked_at = datetime.utcnow()  # type: ignore[union-attr]
    add_audit(db, p, "admin.logout", request)
    await db.commit()
    return {"ok": True}


@router.post("/refresh")
async def refresh(
    p: AdminPrincipal = Depends(setup_or_full), db: AsyncSession = Depends(get_db)
):
    """New access token for the same session; the session's absolute lifetime is never extended."""
    p.session.last_seen_at = datetime.utcnow()  # type: ignore[union-attr]
    await db.commit()
    return _token_response(p.session, p.account)  # type: ignore[arg-type]


@router.get("/me")
async def me(
    p: AdminPrincipal = Depends(require_role("support", scopes=("setup", "full"))),
):
    if p.kind == "legacy":
        return {"kind": "legacy", "role": p.role, "email": None}
    a = p.account
    return {
        "kind": "account",
        "id": a.id,  # type: ignore[union-attr]
        "email": a.email,  # type: ignore[union-attr]
        "role": a.role,  # type: ignore[union-attr]
        "scope": p.session.scope,  # type: ignore[union-attr]
        "mfa_enabled": a.totp_enabled,  # type: ignore[union-attr]
        "setup_required": _setup_pending(a),  # type: ignore[arg-type]
    }


# ── MFA enrolment and password change (setup or full scope) ──────────────────────────────────────────────────────
@router.post("/mfa/enroll/start")
async def mfa_enroll_start(
    p: AdminPrincipal = Depends(setup_only), db: AsyncSession = Depends(get_db)
):
    a = p.account
    if a.totp_enabled:  # type: ignore[union-attr]
        raise HTTPException(
            status_code=409,
            detail="MFA is already enrolled; ask a superadmin to reset it",
        )
    secret = new_totp_secret()
    a.totp_secret_enc = encrypt_secret(secret)  # type: ignore[union-attr]
    await db.commit()
    return {
        "secret": secret,
        "otpauth_uri": totp_uri(secret, a.email, admin_settings.ADMIN_TOTP_ISSUER),  # type: ignore[union-attr]
        "issuer": admin_settings.ADMIN_TOTP_ISSUER,
    }


@router.post("/mfa/enroll/confirm")
async def mfa_enroll_confirm(
    body: CodeBody,
    request: Request,
    p: AdminPrincipal = Depends(setup_only),
    db: AsyncSession = Depends(get_db),
):
    a = p.account
    _limit_or_429(
        f"admin_mfa_confirm:{a.id}", 10, 900, "Too many attempts. Try again later."
    )  # type: ignore[union-attr]
    if a.totp_enabled or not a.totp_secret_enc:  # type: ignore[union-attr]
        raise HTTPException(status_code=409, detail="Start MFA enrolment first")
    secret = decrypt_secret(a.totp_secret_enc)  # type: ignore[union-attr]
    step = verify_totp(secret, body.code, 0) if secret else None
    if step is None:
        raise HTTPException(status_code=400, detail="Invalid code")
    shown, stored = new_recovery_codes()
    a.totp_enabled = True  # type: ignore[union-attr]
    a.totp_last_step = step  # type: ignore[union-attr]
    a.recovery_hashes = stored  # type: ignore[union-attr]
    add_audit(db, p, "admin.mfa_enrolled", request)
    result = await _finish_setup_if_done(db, a, p.session, request)  # type: ignore[arg-type]
    result["recovery_codes"] = shown  # shown exactly once; only hashes are stored
    return result


@router.post("/password/change")
async def password_change(
    body: PasswordChangeBody,
    request: Request,
    p: AdminPrincipal = Depends(setup_or_full),
    db: AsyncSession = Depends(get_db),
):
    a = p.account
    _limit_or_429(
        f"admin_pw_change:{a.id}", 10, 900, "Too many attempts. Try again later."
    )  # type: ignore[union-attr]
    if not verify_password(body.current_password, a.password_hash):  # type: ignore[union-attr]
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(
            status_code=422, detail="The new password must differ from the current one"
        )
    problems = password_problems(body.new_password, a.email)  # type: ignore[union-attr]
    if problems:
        raise HTTPException(status_code=422, detail="Password " + "; ".join(problems))
    a.password_hash = hash_password(body.new_password)  # type: ignore[union-attr]
    a.must_change_password = False  # type: ignore[union-attr]
    a.password_changed_at = datetime.utcnow()  # type: ignore[union-attr]
    await revoke_sessions(db, a.id, except_session=p.session.id)  # type: ignore[union-attr]
    add_audit(db, p, "admin.password_changed", request)
    if p.session.scope == "setup":  # type: ignore[union-attr]
        return await _finish_setup_if_done(db, a, p.session, request)  # type: ignore[arg-type]
    await db.commit()
    return {"ok": True, "setup_required": []}


# ── own sessions ─────────────────────────────────────────────────────────────────────────────────────────────────
@router.get("/sessions")
async def list_sessions(
    p: AdminPrincipal = Depends(any_admin), db: AsyncSession = Depends(get_db)
):
    now = datetime.utcnow()
    rows = (
        (
            await db.execute(
                select(AdminSession)
                .where(
                    AdminSession.admin_id == p.account.id,  # type: ignore[union-attr]
                    AdminSession.revoked_at.is_(None),
                    AdminSession.expires_at > now,
                )
                .order_by(AdminSession.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": s.id,
                "scope": s.scope,
                "created_at": s.created_at,
                "last_seen_at": s.last_seen_at,
                "expires_at": s.expires_at,
                "client_ip": s.client_ip,
                "user_agent": s.user_agent,
                "current": s.id == p.session.id,  # type: ignore[union-attr]
            }
            for s in rows
        ]
    }


@router.post("/sessions/revoke-others")
async def revoke_other_sessions(
    request: Request,
    p: AdminPrincipal = Depends(any_admin),
    db: AsyncSession = Depends(get_db),
):
    await revoke_sessions(db, p.account.id, except_session=p.session.id)  # type: ignore[union-attr]
    add_audit(db, p, "admin.sessions_revoked", request, detail={"scope": "others"})
    await db.commit()
    return {"ok": True}


@router.post("/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: str,
    request: Request,
    p: AdminPrincipal = Depends(any_admin),
    db: AsyncSession = Depends(get_db),
):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    s = (
        await db.execute(
            select(AdminSession).where(
                AdminSession.id == sid, AdminSession.admin_id == p.account.id
            )  # type: ignore[union-attr]
        )
    ).scalar_one_or_none()
    if s is None:  # someone else's session id is indistinguishable from a missing one
        raise HTTPException(status_code=404, detail="Session not found")
    s.revoked_at = s.revoked_at or datetime.utcnow()
    add_audit(db, p, "admin.session_revoked", request, detail={"session": str(sid)})
    await db.commit()
    return {"ok": True}


# ── account management (superadmin) ──────────────────────────────────────────────────────────────────────────────
# Account-management changes are serialised (one at a time, transaction-scoped advisory lock). Without it two
# superadmins could disable or demote each other concurrently: each check would still see the other as active and both
# would commit, leaving no active superadmin.
_ACCOUNT_ADMIN_LOCK = 7203410001


async def _target(db: AsyncSession, account_id: str) -> AdminAccount:
    try:
        aid = uuid.UUID(account_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Admin account not found")
    await db.execute(
        text("select pg_advisory_xact_lock(:k)"), {"k": _ACCOUNT_ADMIN_LOCK}
    )
    a = (
        await db.execute(
            select(AdminAccount).where(AdminAccount.id == aid).with_for_update()
        )
    ).scalar_one_or_none()
    if a is None:
        raise HTTPException(status_code=404, detail="Admin account not found")
    return a


async def _other_active_superadmins(db: AsyncSession, excluding: uuid.UUID) -> int:
    return (
        await db.execute(
            select(func.count(AdminAccount.id)).where(
                AdminAccount.role == "superadmin",
                AdminAccount.is_active.is_(True),
                AdminAccount.id != excluding,
            )
        )
    ).scalar_one()


@router.get("/accounts")
async def list_accounts(
    p: AdminPrincipal = Depends(superadmin_only), db: AsyncSession = Depends(get_db)
):
    rows = (
        (await db.execute(select(AdminAccount).order_by(AdminAccount.created_at)))
        .scalars()
        .all()
    )
    return {"items": [_view(a) for a in rows]}


@router.post("/accounts", status_code=201)
async def create_account(
    body: CreateAccountBody,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    email = body.email.strip().lower()
    if not _EMAIL.match(email):
        raise HTTPException(status_code=422, detail="Invalid e-mail address")
    if body.role not in ADMIN_ROLES:
        raise HTTPException(
            status_code=422, detail="role must be one of: " + ", ".join(ADMIN_ROLES)
        )
    problems = password_problems(body.temporary_password, email)
    if problems:
        raise HTTPException(status_code=422, detail="Password " + "; ".join(problems))
    exists = (
        await db.execute(select(AdminAccount.id).where(AdminAccount.email == email))
    ).scalar_one_or_none()
    if exists:
        raise HTTPException(
            status_code=409, detail="An admin account with this e-mail already exists"
        )
    a = AdminAccount(
        email=email,
        role=body.role,
        password_hash=hash_password(body.temporary_password),
        must_change_password=True,
        recovery_hashes=[],
    )
    db.add(a)
    await db.flush()
    add_audit(
        db,
        p,
        "admin.account_created",
        request,
        detail={"account": str(a.id), "role": a.role},
    )
    await db.commit()
    return _view(a)


async def _set_active(
    account_id: str, active: bool, request: Request, p: AdminPrincipal, db: AsyncSession
) -> dict:
    a = await _target(db, account_id)
    if not active:
        if a.id == p.account.id:  # type: ignore[union-attr]
            raise HTTPException(
                status_code=409, detail="You cannot deactivate your own account"
            )
        if (
            a.role == "superadmin"
            and a.is_active
            and await _other_active_superadmins(db, a.id) == 0
        ):
            raise HTTPException(
                status_code=409, detail="At least one active superadmin must remain"
            )
    if a.is_active != active:
        a.is_active = active
        if not active:
            await revoke_sessions(db, a.id)
        add_audit(
            db,
            p,
            "admin.account_enabled" if active else "admin.account_disabled",
            request,
            detail={"account": str(a.id)},
        )
        await db.commit()
    return _view(a)


@router.post("/accounts/{account_id}/disable")
async def disable_account(
    account_id: str,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    return await _set_active(account_id, False, request, p, db)


@router.post("/accounts/{account_id}/enable")
async def enable_account(
    account_id: str,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    return await _set_active(account_id, True, request, p, db)


@router.post("/accounts/{account_id}/role")
async def change_role(
    account_id: str,
    body: RoleBody,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    if body.role not in ADMIN_ROLES:
        raise HTTPException(
            status_code=422, detail="role must be one of: " + ", ".join(ADMIN_ROLES)
        )
    a = await _target(db, account_id)
    if a.role == "superadmin" and body.role != "superadmin":
        if a.id == p.account.id:  # type: ignore[union-attr]
            raise HTTPException(status_code=409, detail="You cannot demote yourself")
        if a.is_active and await _other_active_superadmins(db, a.id) == 0:
            raise HTTPException(
                status_code=409, detail="At least one active superadmin must remain"
            )
    if a.role != body.role:
        add_audit(
            db,
            p,
            "admin.role_changed",
            request,
            detail={"account": str(a.id), "from": a.role, "to": body.role},
        )
        a.role = body.role
        await revoke_sessions(
            db, a.id
        )  # a changed role takes effect at the next sign-in
        await db.commit()
    return _view(a)


@router.post("/accounts/{account_id}/reset-mfa")
async def reset_mfa(
    account_id: str,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    a = await _target(db, account_id)
    if a.id == p.account.id:  # type: ignore[union-attr]
        raise HTTPException(
            status_code=409,
            detail="Use another superadmin (or the CLI) to reset your own MFA",
        )
    a.totp_secret_enc = None
    a.totp_enabled = False
    a.totp_last_step = 0
    a.recovery_hashes = []
    await revoke_sessions(db, a.id)
    add_audit(db, p, "admin.mfa_reset", request, detail={"account": str(a.id)})
    await db.commit()
    return _view(a)


@router.post("/accounts/{account_id}/reset-password")
async def reset_password(
    account_id: str,
    body: TempPasswordBody,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    a = await _target(db, account_id)
    if a.id == p.account.id:  # type: ignore[union-attr]
        raise HTTPException(
            status_code=409, detail="Change your own password with /password/change"
        )
    problems = password_problems(body.temporary_password, a.email)
    if problems:
        raise HTTPException(status_code=422, detail="Password " + "; ".join(problems))
    a.password_hash = hash_password(body.temporary_password)
    a.must_change_password = True
    a.failed_logins = 0
    a.locked_until = None
    await revoke_sessions(db, a.id)
    add_audit(db, p, "admin.password_reset", request, detail={"account": str(a.id)})
    await db.commit()
    return _view(a)


@router.post("/accounts/{account_id}/unlock")
async def unlock_account(
    account_id: str,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    a = await _target(db, account_id)
    a.failed_logins = 0
    a.locked_until = None
    add_audit(db, p, "admin.account_unlocked", request, detail={"account": str(a.id)})
    await db.commit()
    return _view(a)


@router.post("/accounts/{account_id}/revoke-sessions")
async def revoke_account_sessions(
    account_id: str,
    request: Request,
    p: AdminPrincipal = Depends(superadmin_only),
    db: AsyncSession = Depends(get_db),
):
    a = await _target(db, account_id)
    await revoke_sessions(db, a.id)
    add_audit(
        db,
        p,
        "admin.sessions_revoked",
        request,
        detail={"account": str(a.id), "scope": "all"},
    )
    await db.commit()
    return {"ok": True}
