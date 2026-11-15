"""Identity binding endpoints: verify a phone number, change the e-mail address, release an unverified claim.

Every flow proves the identifier with a code sent to THAT identifier only (``app.services.identity``): a code for one identifier
or purpose can never verify another. Changes are applied in a single transaction; a unique-constraint race rolls back (the
session stays usable) and answers 409. The old verified e-mail stays active until the new one is verified.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.rate_limiter import (
    check_otp_send_rate,
    check_otp_verify_rate,
    rate_limiter,
)
from app.models.user import User
from app.routers.auth import _check_otp_send_ip, _mask, _mask_for_log, get_current_user
from app.schemas.auth import (
    EmailChangeConfirmRequest,
    EmailChangeStartRequest,
    IdentityStepResponse,
    PhoneConfirmRequest,
    PhoneStartRequest,
    ReleaseConfirmRequest,
    ReleaseStartRequest,
)
from app.services import identity as idn
from app.services.client_ip import client_ip_for
from app.services.logger_service import get_logger, log_error
from app.services.otp_service import deliver_otp

router = APIRouter(prefix="/auth", tags=["auth-identity"])
logger = get_logger(__name__)

NOT_SENT = "Could not send the verification code. Please try again later."


def _valid_phone(phone: str) -> str:
    phone = idn.normalise(idn.PHONE, phone)
    if not (phone.startswith("+") and phone[1:].isdigit() and 7 <= len(phone) <= 20):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enter a valid phone number including the country code.",
        )
    return phone


def _state(
    user: User, message: str, identifier: str | None = None
) -> IdentityStepResponse:
    return IdentityStepResponse(
        message=message,
        identifier=_mask(identifier) if identifier else None,
        email_verified=user.email_verified,
        phone_verified=user.phone_verified,
    )


async def _send(db: AsyncSession, kind: str, identifier: str, code: str) -> None:
    result = await deliver_otp(identifier, code)
    if not result.success:
        logger.warning(
            f"Verification code delivery failed to {_mask_for_log(identifier)}: {result.error}"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=NOT_SENT
        )


# ---------------------------------------------------------------------------
# Phone verification (separate from e-mail verification)
# ---------------------------------------------------------------------------
@router.post("/phone/add/start", response_model=IdentityStepResponse)
async def phone_add_start(
    body: PhoneStartRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Send a code to the phone number ONLY. The number is attached to the account when that code is confirmed."""
    client_ip = client_ip_for(http_request, None)
    _check_otp_send_ip(client_ip)
    phone = _valid_phone(body.phone)
    check_otp_send_rate(phone)
    try:
        if current_user.phone_verified and current_user.phone == phone:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This phone number is already verified on your account.",
            )
        holder = await idn.owner_of(db, idn.PHONE, phone)
        if (
            holder is not None
            and holder.id != current_user.id
            and holder.phone_verified
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This phone number belongs to another account.",
            )
        code = await idn.issue_challenge(
            db,
            kind=idn.PHONE,
            identifier=phone,
            purpose=idn.ADD_PHONE,
            user_id=current_user.id,
        )
        await db.commit()
        await _send(db, idn.PHONE, phone, code)
        return _state(current_user, "Verification code sent.", phone)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Phone verification start failed",
            exc=exc,
            endpoint="/auth/phone/add/start",
            method="POST",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Could not start verification.")


@router.post("/phone/add/confirm", response_model=IdentityStepResponse)
async def phone_add_confirm(
    body: PhoneConfirmRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    client_ip = client_ip_for(http_request, None)
    phone = _valid_phone(body.phone)
    check_otp_verify_rate(phone)
    try:
        otp = await idn.consume_challenge(
            db,
            kind=idn.PHONE,
            identifier=phone,
            purpose=idn.ADD_PHONE,
            code=body.code,
        )
        if otp is None or otp.user_id != current_user.id:
            raise idn.failure()
        holder = await idn.owner_of(db, idn.PHONE, phone)
        if (
            holder is not None
            and holder.id != current_user.id
            and holder.phone_verified
        ):
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This phone number belongs to another account.",
            )
        # Proof of the number outranks an UNVERIFIED claim on another row: that row only loses the identifier (no data moves).
        notify = await idn.evict_unverified_claims(
            db, idn.PHONE, phone, current_user.id
        )
        current_user.phone = phone
        current_user.phone_verified_at = datetime.utcnow()
        await idn.commit_or_conflict(
            db, "This phone number belongs to another account."
        )
        await db.refresh(current_user)
        await idn.notify_claim_released(notify, idn.PHONE, phone)
        return _state(current_user, "Phone number verified.", phone)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Phone verification failed",
            exc=exc,
            endpoint="/auth/phone/add/confirm",
            method="POST",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Verification failed.")


# ---------------------------------------------------------------------------
# E-mail change (the new address must prove itself; the old one stays active meanwhile)
# ---------------------------------------------------------------------------
@router.post("/email/change/start", response_model=IdentityStepResponse)
async def email_change_start(
    body: EmailChangeStartRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    client_ip = client_ip_for(http_request, None)
    _check_otp_send_ip(client_ip)
    new_email = idn.normalise(idn.EMAIL, body.new_email)
    check_otp_send_rate(new_email)
    try:
        if current_user.email_verified and current_user.email == new_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This is already your verified email address.",
            )
        holder = await idn.owner_of(db, idn.EMAIL, new_email)
        if (
            holder is not None
            and holder.id != current_user.id
            and holder.email_verified
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email address belongs to another account.",
            )
        code = await idn.issue_challenge(
            db,
            kind=idn.EMAIL,
            identifier=new_email,
            purpose=idn.CHANGE_EMAIL,
            user_id=current_user.id,
        )
        await db.commit()
        await _send(db, idn.EMAIL, new_email, code)
        return _state(
            current_user, "Verification code sent to the new address.", new_email
        )
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Email change start failed",
            exc=exc,
            endpoint="/auth/email/change/start",
            method="POST",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Could not start the email change.")


@router.post("/email/change/confirm", response_model=IdentityStepResponse)
async def email_change_confirm(
    body: EmailChangeConfirmRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    client_ip = client_ip_for(http_request, None)
    new_email = idn.normalise(idn.EMAIL, body.new_email)
    check_otp_verify_rate(new_email)
    old_email = current_user.email if current_user.email_verified else None
    try:
        otp = await idn.consume_challenge(
            db,
            kind=idn.EMAIL,
            identifier=new_email,
            purpose=idn.CHANGE_EMAIL,
            code=body.code,
        )
        if otp is None or otp.user_id != current_user.id:
            raise idn.failure()
        holder = await idn.owner_of(db, idn.EMAIL, new_email)
        if (
            holder is not None
            and holder.id != current_user.id
            and holder.email_verified
        ):
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email address belongs to another account.",
            )
        notify_holders = await idn.evict_unverified_claims(
            db, idn.EMAIL, new_email, current_user.id
        )
        current_user.email = new_email
        current_user.email_verified_at = datetime.utcnow()
        current_user.updated_at = datetime.utcnow()
        # google_sub is deliberately untouched: an e-mail change never moves the Google binding.
        await idn.commit_or_conflict(
            db, "This email address belongs to another account."
        )
        await db.refresh(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Email change failed",
            exc=exc,
            endpoint="/auth/email/change/confirm",
            method="POST",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Could not change the email.")

    await idn.notify_claim_released(notify_holders, idn.EMAIL, new_email)
    if (
        old_email and old_email != new_email
    ):  # best effort: tell the OLD address that it changed
        try:
            from app.services import notifications

            await notifications.send_email(
                old_email,
                "Your SecureShield email address was changed",
                f"The email address on your SecureShield account was changed to {_mask(new_email)}. "
                "If this was not you, contact support immediately.",
            )
        except Exception as exc:
            logger.warning(f"Old-address change notice failed: {type(exc).__name__}")
    return _state(current_user, "Email address changed.", new_email)


# ---------------------------------------------------------------------------
# Release an UNVERIFIED claim (legacy rows): lets the real owner of an identifier use it for a new account.
# ---------------------------------------------------------------------------
@router.post("/identifier/release/start", response_model=IdentityStepResponse)
async def release_start(
    body: ReleaseStartRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Answers the same whether or not anything applies. A code is sent (to that identifier only) only when the identifier
    sits UNVERIFIED on an account that has another VERIFIED identifier."""
    client_ip = client_ip_for(http_request, None)
    _check_otp_send_ip(client_ip)
    kind = idn.kind_of(body.identifier)
    identifier = idn.normalise(kind, body.identifier)
    check_otp_send_rate(identifier)
    reply = IdentityStepResponse(
        message="If this identifier can be released, a verification code was sent.",
        identifier=_mask(identifier),
    )
    try:
        holder, state = await idn.resolve_for_login(db, kind, identifier)
        if holder is None or state != idn.LEGACY_WITH_OTHER:
            return reply
        code = await idn.issue_challenge(
            db,
            kind=kind,
            identifier=identifier,
            purpose=idn.RECLAIM,
            user_id=holder.id,
        )
        await db.commit()
        await _send(db, kind, identifier, code)
        return reply
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Identifier release start failed",
            exc=exc,
            endpoint="/auth/identifier/release/start",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Could not start the release.")


@router.post("/identifier/release/confirm", response_model=IdentityStepResponse)
async def release_confirm(
    body: ReleaseConfirmRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = client_ip_for(http_request, None)
    if not rate_limiter.is_allowed(
        f"release_confirm_ip:{client_ip}", max_hits=20, window_seconds=3600
    ):
        raise HTTPException(
            status_code=429, detail="Too many attempts. Try again later."
        )
    kind = idn.kind_of(body.identifier)
    identifier = idn.normalise(kind, body.identifier)
    check_otp_verify_rate(identifier)
    try:
        otp = await idn.consume_challenge(
            db, kind=kind, identifier=identifier, purpose=idn.RECLAIM, code=body.code
        )
        if otp is None or otp.user_id is None:
            raise idn.failure()
        holder = await db.get(User, otp.user_id)
        still = (
            holder is not None
            and (holder.email if kind == idn.EMAIL else holder.phone) == identifier
            and not idn.is_verified(holder, kind)
            and idn.other_verified(holder, kind)
        )
        if not still:
            await db.commit()
            raise idn.failure()
        # Only the unverified identifier is removed from that account. No data moves anywhere.
        notify = [holder.email] if holder.email and holder.email_verified else []
        if kind == idn.EMAIL:
            holder.email, holder.email_verified_at = None, None
        else:
            holder.phone, holder.phone_verified_at = None, None
        await db.commit()
        await idn.notify_claim_released(notify, kind, identifier)
        logger.warning(
            f"Unverified {kind} claim released from account {holder.id}: {_mask_for_log(identifier)}"
        )
        return IdentityStepResponse(
            message="Released. You can now register with this identifier.",
            identifier=_mask(identifier),
        )
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Identifier release failed",
            exc=exc,
            endpoint="/auth/identifier/release/confirm",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Could not release the identifier.")
