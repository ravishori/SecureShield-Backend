"""Identity binding: an e-mail address or phone number may authenticate an account ONLY after its owner proved it.

Rules enforced here (and by the routers that call it)

* **One challenge = one identifier = one channel = one purpose.** A code issued to ``a@x.com`` for ``login`` can verify nothing
  else: not a phone number, not another purpose, not another address. The lookup is by (kind, identifier, purpose) and the
  stored HMAC also covers all three (``hash_challenge``).
* **Verified-only resolution.** ``users.email_verified_at`` / ``phone_verified_at`` say whether an identifier was proven. New
  sign-ups never put an unverified identifier on ``users`` at all (they wait in ``pending_registrations``).
* **Legacy rows** (created before verification state existed) keep NULL timestamps - nothing is marked verified automatically:
    - ``legacy_sole``: the row has NO verified identifier. A correct code sent to that one identifier verifies it and signs in.
    - ``legacy_with_other``: the row already has a verified identifier. Proving the *other* identifier does NOT sign in (no
      merge, no data transfer); its owner may *release* the unverified claim (it is removed from that row) and register.
* **No silent merge or split**: eviction only ever clears an unverified identifier from a row; it never moves data.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pending_registration import PendingRegistration
from app.models.user import OTP, User
from app.services.otp_codes import (
    OTP_MAX_ATTEMPTS,
    OTP_TTL_MINUTES,
    challenge_matches,
    generate_code,
    hash_challenge,
)

EMAIL = "email"
PHONE = "phone"

LOGIN = "login"
REGISTER = "register"
ADD_PHONE = "add_phone"
CHANGE_EMAIL = "change_email"
RECLAIM = "reclaim"
DELETE_ACCOUNT = "delete_account"
GUARDIAN_VERIFY = "guardian_verify"

OTP_FAILURE_DETAIL = "Invalid or expired OTP. Please request a new one."
PENDING_TTL = timedelta(hours=24)

VERIFIED = "verified"
LEGACY_SOLE = "legacy_sole"
LEGACY_WITH_OTHER = "legacy_with_other"
NONE = "none"


def kind_of(identifier: str) -> str:
    return EMAIL if "@" in identifier else PHONE


def normalise(kind: str, value: str) -> str:
    if kind == EMAIL:
        return value.strip().lower()
    from app.services.otp_service import _normalize_phone

    return _normalize_phone(value.strip())


def _col(kind: str):
    return User.email if kind == EMAIL else User.phone


def _verified_col(kind: str):
    return User.email_verified_at if kind == EMAIL else User.phone_verified_at


def is_verified(user: User, kind: str) -> bool:
    return user.email_verified if kind == EMAIL else user.phone_verified


def other_verified(user: User, kind: str) -> bool:
    return user.phone_verified if kind == EMAIL else user.email_verified


async def owner_of(db: AsyncSession, kind: str, value: str) -> User | None:
    return (
        await db.execute(select(User).where(_col(kind) == value))
    ).scalar_one_or_none()


async def resolve_for_login(
    db: AsyncSession, kind: str, value: str
) -> tuple[User | None, str]:
    """Which account (if any) holds this identifier, and in which state."""
    user = await owner_of(db, kind, value)
    if user is None:
        return None, NONE
    if is_verified(user, kind):
        return user, VERIFIED
    return user, LEGACY_WITH_OTHER if other_verified(user, kind) else LEGACY_SOLE


def reauth_channel(user: User) -> tuple[str, str] | None:
    """Where to send a re-authentication code for a sensitive action: the VERIFIED e-mail, else the VERIFIED phone, else
    nothing (the caller refuses; an unverified identifier proves nothing about who holds the session)."""
    if user.email_verified and user.email:
        return EMAIL, user.email
    if user.phone_verified and user.phone:
        return PHONE, user.phone
    return None


def verified_login_identifier(user: User, proven: str) -> str:
    """The identifier that goes into token claims: ALWAYS a verified one (the e-mail when verified, else the one just proven)."""
    return user.email if user.email_verified else proven


# ---------------------------------------------------------------------------
# Challenges
# ---------------------------------------------------------------------------
async def issue_challenge(
    db: AsyncSession,
    *,
    kind: str,
    identifier: str,
    purpose: str,
    user_id: uuid.UUID | None = None,
    pending_id: uuid.UUID | None = None,
) -> str:
    """Create a code for exactly one identifier+purpose, replacing any still-open one. Returns the plaintext code (the caller
    commits, then delivers it to THAT identifier only). Only an HMAC is stored."""
    code = generate_code()
    await db.execute(
        update(OTP)
        .where(
            OTP.identifier_type == kind,
            OTP.identifier == identifier,
            OTP.purpose == purpose,
            OTP.is_used.is_(False),
        )
        .values(is_used=True)
    )
    db.add(
        OTP(
            email=identifier if kind == EMAIL else None,
            phone=identifier if kind == PHONE else None,
            identifier=identifier,
            identifier_type=kind,
            purpose=purpose,
            user_id=user_id,
            pending_registration_id=pending_id,
            code=hash_challenge(code, kind, identifier, purpose),
            expires_at=datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES),
        )
    )
    return code


async def consume_challenge(
    db: AsyncSession, *, kind: str, identifier: str, purpose: str, code: str
) -> OTP | None:
    """Atomically use the newest open challenge for (kind, identifier, purpose).

    * No open challenge, wrong code or burned code -> ``None`` (wrong guesses are counted on the row and COMMITTED here; after
      ``OTP_MAX_ATTEMPTS`` the code is burned).
    * Correct code -> the row, marked used. The CALLER commits, together with the business change, so a failed business step
      rolls the consumption back."""
    otp = (
        await db.execute(
            select(OTP)
            .where(
                OTP.identifier_type == kind,
                OTP.identifier == identifier,
                OTP.purpose == purpose,
                OTP.is_used.is_(False),
                OTP.expires_at > datetime.utcnow(),
            )
            .order_by(OTP.created_at.desc())
            .limit(1)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if otp is None:
        return None
    if otp.attempts >= OTP_MAX_ATTEMPTS or not challenge_matches(
        otp.code, code, kind, identifier, purpose
    ):
        otp.attempts += 1
        if otp.attempts >= OTP_MAX_ATTEMPTS:
            otp.is_used = True
        await db.commit()
        return None
    otp.is_used = True
    return otp


def failure() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail=OTP_FAILURE_DETAIL
    )


# ---------------------------------------------------------------------------
# Claims, eviction, conflicts
# ---------------------------------------------------------------------------
async def evict_unverified_claims(
    db: AsyncSession, kind: str, value: str, keep_user_id: uuid.UUID
) -> list[str]:
    """Clear ``value`` from every OTHER row that holds it as an UNVERIFIED claim (legacy data). Only the identifier is cleared:
    nothing is merged or transferred. Verified holders are never touched (the caller has already rejected that case).

    Returns the VERIFIED e-mail addresses of the accounts that lost a claim, so the caller can notify them after committing."""
    values = (
        {"email": None, "email_verified_at": None}
        if kind == EMAIL
        else {"phone": None, "phone_verified_at": None}
    )
    cond = (_col(kind) == value, User.id != keep_user_id, _verified_col(kind).is_(None))
    holders = (await db.execute(select(User).where(*cond))).scalars().all()
    notify = [h.email for h in holders if h.email and h.email_verified]
    if holders:
        await db.execute(update(User).where(*cond).values(**values))
    return notify


async def notify_claim_released(emails: list[str], kind: str, value: str) -> None:
    """Best effort, after the commit: tell each affected account (through its VERIFIED e-mail) that an unverified identifier
    was removed because its real owner proved it. Never raises and never includes the full identifier."""
    if not emails:
        return
    from app.services import notifications

    masked = value[:2] + "***" + value[-2:] if len(value) > 4 else "***"
    for email in set(emails):
        try:
            await notifications.send_email(
                email,
                "A contact detail was removed from your SecureShield account",
                f"The unverified {kind} {masked} was removed from your account because someone proved they own it. "
                "Your verified details and data are unchanged. If this looks wrong, contact support.",
            )
        except Exception:  # noqa: BLE001 - a notice must never break the change
            pass


async def commit_or_conflict(db: AsyncSession, detail: str) -> None:
    """Commit; on a unique-constraint race roll back (the session stays usable) and answer 409."""
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


async def purge_expired_pending(db: AsyncSession) -> None:
    await db.execute(
        delete(PendingRegistration).where(
            PendingRegistration.expires_at < datetime.utcnow()
        )
    )
