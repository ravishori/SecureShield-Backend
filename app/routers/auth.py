"""
Auth Router — Register / OTP send / verify / refresh / profile
==============================================================
Identity binding (see app.services.identity): every code is bound to ONE identifier, ONE channel and ONE purpose.
  Registration  → pending registration + code to the E-MAIL only; the account is created when that code is verified.
                  The phone is attached later, after its own separate code (routers/identity.py).
  Login         → code to the identifier used, only if that identifier is VERIFIED on an account.

All exceptions are caught, logged (file + DB + email alert), and
re-raised as clean HTTP errors.
"""

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import PyJWTError as JWTError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.rate_limiter import (
    check_otp_send_rate,
    check_otp_verify_rate,
    rate_limiter,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.pending_registration import PendingRegistration
from app.models.refresh_token import RefreshTokenUse, RevokedTokenFamily
from app.models.user import User
from app.schemas.auth import (
    GoogleLoginRequest,
    DeleteAccountRequest,
    DeleteAccountResponse,
    RefreshTokenRequest,
    RegisterRequest,
    RegisterResponse,
    SendOtpRequest,
    SendOtpResponse,
    TokenResponse,
    UpdateProfileRequest,
    UserResponse,
    VerifyOtpRequest,
)
from app.services.account_erasure import RETAINED, erase_user_data, remove_files
from app.services import consent as cns
from app.services import identity as idn
from app.services.client_ip import client_ip_for
from app.services.device_service import register_and_check_device, send_new_device_alert
from app.services.logger_service import get_logger, log_error
from app.services.google_auth import (
    GoogleAuthError,
    GoogleNotConfigured,
    verify_google_id_token,
)
from app.services.log_scrubber import mask_email_for_log, mask_phone_for_log
from app.services.otp_service import deliver_otp, _normalize_phone

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------
def _mask_phone(phone: str) -> str:
    """+919987671916 → +91*****1916"""
    if len(phone) <= 6:
        return phone
    return phone[:3] + "*" * (len(phone) - 6) + phone[-3:]


def _mask_email(email: str) -> str:
    """ravishori@gmail.com → r*******i@gmail.com"""
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}*@{domain}"
    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"


def _mask(identifier: str) -> str:
    return _mask_email(identifier) if "@" in identifier else _mask_phone(identifier)


def _mask_for_log(identifier: str) -> str:
    """Log-safe mask (never raises, reveals at most the last two phone digits / first e-mail character)."""
    if "@" in str(identifier):
        return mask_email_for_log(identifier)
    return mask_phone_for_log(identifier)


# ---------------------------------------------------------------------------
# OTP helpers
# ---------------------------------------------------------------------------
OTP_SEND_IP_LIMIT = (
    20  # OTP sends per source address per hour (SMS-pumping / mail-bombing guard)
)
OTP_FAILURE_DETAIL = "Invalid or expired OTP. Please request a new one."


def _check_otp_send_ip(client_ip: str | None) -> None:
    """Cap how many codes one source can trigger per hour, independent of the target identifier: the per-identifier
    limit alone lets one client send a code to every phone number it can enumerate."""
    if not rate_limiter.is_allowed(
        f"otp_send_ip:{client_ip or 'unknown'}",
        max_hits=OTP_SEND_IP_LIMIT,
        window_seconds=3600,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification codes requested from this network. Please try again later.",
            headers={"Retry-After": "3600"},
        )


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_tokens(user_id: str, identifier: str, family_id: str | None = None) -> dict:
    payload = {"sub": user_id, "identifier": identifier}
    if "@" not in identifier:
        payload["phone"] = identifier
    else:
        payload["email"] = identifier

    # Access and refresh tokens are signed with the same key, so the ``type`` claim
    # is what keeps them from being interchangeable (see get_current_user / refresh).
    access_token = create_token(
        {**payload, "type": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    # Each refresh token has a unique jti and belongs to a family (one login). /refresh consumes the
    # jti; presenting a consumed one again revokes the whole family (stolen-token replay).
    refresh_token = create_token(
        {
            **payload,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
            "fam": family_id or str(uuid.uuid4()),
        },
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        # Only ACCESS tokens authenticate API calls. A refresh token (30-day lifetime) must
        # never work as a bearer token, and tokens without a type claim are rejected.
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
            )
        user_uuid = uuid.UUID(user_id)
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _token_response(user: User, proven: str, *, next_step: str | None = None) -> dict:
    """Tokens whose claims carry a VERIFIED identifier only, plus the backend-authoritative verification state."""
    tokens = create_tokens(str(user.id), idn.verified_login_identifier(user, proven))
    tokens.update(
        email_verified=user.email_verified,
        phone_verified=user.phone_verified,
        next_step=next_step,
    )
    return tokens


async def _register_device(db, user: User, request, client_ip: str | None) -> None:
    if not getattr(request, "device_token", None):
        return
    try:
        _device, is_new_device = await register_and_check_device(
            db=db,
            user=user,
            device_token=request.device_token,
            device_name=request.device_name,
            platform=request.platform,
            os_version=request.os_version,
            app_version=request.app_version,
            client_ip=client_ip,
        )
        if is_new_device:
            await send_new_device_alert(
                user=user,
                device_name=request.device_name,
                platform=request.platform,
                client_ip=client_ip,
            )
    except Exception as dev_exc:
        logger.error(f"Device registration failed for user {user.id}: {dev_exc}")


def _unverified_on_existing_account() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            "This identifier is on an existing account but has not been verified. Sign in with that account's verified "
            "identifier, or release it to use it for a new account."
        ),
        headers={"X-Identity-Error": "identifier_unverified_on_existing_account"},
    )


@router.get("/check-user")
async def check_user(
    identifier: str,
    http_request: Request,
):
    """DEPRECATED, kept only so already-installed app versions keep working.

    It used to say whether an e-mail address or phone number had an account, which let anyone enumerate users. It now answers
    the SAME thing for every identifier (and does no database lookup, so there is no timing difference either). Sign-in does not
    need it: ``POST /auth/send-otp`` already answers identically whether or not an account exists, and a code is only ever sent
    to an identifier that belongs to an account. Remains rate-limited per source IP.
    """
    client_ip = client_ip_for(http_request)
    if not rate_limiter.is_allowed(
        f"check_user_ip:{client_ip}", max_hits=30, window_seconds=60
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many account-lookup requests. Please wait a minute.",
            headers={"Retry-After": "60"},
        )
    return {"exists": True, "has_profile": True}


@router.post("/register", response_model=RegisterResponse)
async def register_user(
    body: RegisterRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Start a registration. NO account is created and NO identifier is bound yet:
      1. validate the identifiers are not already taken
      2. park the profile in ``pending_registrations`` (expires after 24 h)
      3. send a one-time code to the E-MAIL address only
    The account is created by ``POST /auth/register/verify``; the phone is verified later, separately
    (``/auth/phone/add/*``), and only then can it be used to sign in.
    """
    client_ip = client_ip_for(http_request, None)

    # Both per-IP (abuse) and per-identifier (quota burn) limits.
    ip_key = client_ip or "unknown"
    if not rate_limiter.is_allowed(
        f"register_ip:{ip_key}", max_hits=10, window_seconds=3600
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts from this network. Please wait an hour.",
            headers={"Retry-After": "3600"},
        )
    check_otp_send_rate(body.email.lower())

    # Mandatory, separate acknowledgements (terms + privacy notice) at the stated versions; optional choices never gate sign-up.
    if body.consent is None:
        raise cns.consent_required_error()
    cns.check_required_versions(
        body.consent.terms_version, body.consent.privacy_version
    )

    try:
        email_lower = body.email.lower()
        await idn.purge_expired_pending(db)

        if await idn.owner_of(db, idn.EMAIL, email_lower):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists. Please login instead.",
            )

        normalized_phone: str | None = None
        if body.phone:
            try:
                normalized_phone = _normalize_phone(body.phone)
            except Exception:
                normalized_phone = body.phone
            if await idn.owner_of(db, idn.PHONE, normalized_phone):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this phone number already exists. Please login instead.",
                )

        now = datetime.utcnow()
        fields = dict(
            phone=normalized_phone,
            first_name=body.first_name.strip(),
            last_name=body.last_name.strip() if body.last_name else None,
            full_name=f"{body.first_name} {body.last_name or ''}".strip(),
            flat_no=body.flat_no,
            building=body.building,
            street=body.street,
            city=body.city,
            state=body.state,
            country=body.country or "India",
            pin_code=body.pin_code,
            terms_version=body.consent.terms_version,
            privacy_version=body.consent.privacy_version,
            consented_at=now,
            ai_processing_consent=body.consent.ai_processing,
        )
        # Upsert on the unique e-mail: a repeated registration refreshes the same pending row (and issues a new code).
        stmt = (
            pg_insert(PendingRegistration)
            .values(
                id=uuid.uuid4(),
                email=email_lower,
                created_at=now,
                expires_at=now + idn.PENDING_TTL,
                **fields,
            )
            .on_conflict_do_update(
                index_elements=[PendingRegistration.email],
                set_={**fields, "expires_at": now + idn.PENDING_TTL},
            )
            .returning(PendingRegistration.id)
        )
        pending_id = (await db.execute(stmt)).scalar_one()
        code = await idn.issue_challenge(
            db,
            kind=idn.EMAIL,
            identifier=email_lower,
            purpose=idn.REGISTER,
            pending_id=pending_id,
        )
        await db.commit()

        email_result = await deliver_otp(email_lower, code)
        if not email_result.success:
            logger.warning(
                f"Registration code delivery failed for {mask_email_for_log(email_lower)}: {email_result.error}"
            )

        masked_email = _mask_email(email_lower)
        logger.info(
            f"Registration started, e-mail verification pending: {masked_email}"
        )
        return RegisterResponse(
            message="We sent a verification code to your email.",
            identifier=masked_email,
            masked_email=masked_email,
            masked_phone=_mask_phone(normalized_phone) if normalized_phone else None,
            next_step="verify_email",
        )

    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Registration failed",
            exc=exc,
            endpoint="/auth/register",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again.",
        )


@router.post("/register/verify", response_model=TokenResponse)
async def register_verify(
    request: VerifyOtpRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Verify the e-mail code of a pending registration: ONLY now is the account created, with the e-mail marked verified."""
    client_ip = client_ip_for(http_request, None)
    if not request.is_email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Registration is verified with the e-mail address.",
        )
    check_otp_verify_rate(request.identifier)
    try:
        email = idn.normalise(idn.EMAIL, request.identifier)
        otp = await idn.consume_challenge(
            db,
            kind=idn.EMAIL,
            identifier=email,
            purpose=idn.REGISTER,
            code=request.code,
        )
        if otp is None or otp.pending_registration_id is None:
            raise idn.failure()
        pending = await db.get(PendingRegistration, otp.pending_registration_id)
        if (
            pending is None
            or pending.email != email
            or pending.expires_at < datetime.utcnow()
        ):
            await db.commit()  # the code is spent either way
            raise idn.failure()

        if (
            pending.terms_version != cns.VERSIONS[cns.TERMS]
            or pending.privacy_version != cns.VERSIONS[cns.PRIVACY]
            or pending.consented_at is None
        ):
            # No consent on record for this registration (it predates consent capture, or the notice changed meanwhile):
            # no account is created. The code is spent; the person registers again and sees the current notice.
            await db.delete(pending)
            await db.commit()
            raise idn.failure()

        now = datetime.utcnow()
        user = User(
            id=uuid.uuid4(),
            email=email,
            email_verified_at=now,
            first_name=pending.first_name,
            last_name=pending.last_name,
            full_name=pending.full_name,
            flat_no=pending.flat_no,
            building=pending.building,
            street=pending.street,
            city=pending.city,
            state=pending.state,
            country=pending.country,
            pin_code=pending.pin_code,
        )
        had_phone = bool(pending.phone)
        db.add(user)
        cns.add_required(db, user.id, cns.REGISTER, pending.consented_at)
        if pending.ai_processing_consent is not None:
            cns.add_decision(
                db,
                user.id,
                cns.AI_PROCESSING,
                pending.ai_processing_consent,
                cns.REGISTER,
                pending.consented_at,
            )
        await db.delete(pending)
        await idn.commit_or_conflict(
            db, "An account with this email already exists. Please login instead."
        )
        await db.refresh(user)
        logger.info(f"Account created after e-mail verification: {user.id}")

        await _register_device(db, user, request, client_ip)
        return _token_response(
            user, email, next_step="verify_phone" if had_phone else None
        )
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message=f"Registration verification failed for {_mask(request.identifier)}",
            exc=exc,
            endpoint="/auth/register/verify",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Verification failed. Please try again.",
        )


@router.post("/send-otp", response_model=SendOtpResponse)
async def send_otp(
    request: SendOtpRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Login code: sent to the identifier used, and ONLY to it, when that identifier belongs to an account.
    The answer is identical whether or not an account exists (nothing is sent, and nothing is created, for an unknown identifier).
    """
    client_ip = client_ip_for(http_request, None)
    _check_otp_send_ip(client_ip)
    check_otp_send_rate(request.identifier)

    try:
        kind = idn.EMAIL if request.is_email else idn.PHONE
        identifier = idn.normalise(kind, request.identifier)
        response = SendOtpResponse(
            message="OTP sent successfully",
            identifier=_mask(request.identifier),
            method=request.method,
        )

        user, _state = await idn.resolve_for_login(db, kind, identifier)
        if user is None:
            # Resend for a registration still waiting on its e-mail code: reissue the REGISTER challenge (e-mail only). The
            # reply is the same as for an unknown identifier, so this does not reveal that a pending registration exists.
            pending = None
            if kind == idn.EMAIL:
                pending = (
                    await db.execute(
                        select(PendingRegistration).where(
                            PendingRegistration.email == identifier,
                            PendingRegistration.expires_at > datetime.utcnow(),
                        )
                    )
                ).scalar_one_or_none()
            if pending is None:
                logger.info(
                    f"Login code not sent (no account) for {_mask_for_log(request.identifier)}"
                )
                return response
            code = await idn.issue_challenge(
                db,
                kind=idn.EMAIL,
                identifier=identifier,
                purpose=idn.REGISTER,
                pending_id=pending.id,
            )
            await db.commit()
            resent = await deliver_otp(identifier, code)
            if not resent.success:
                logger.warning(
                    f"Registration code resend failed for {_mask_for_log(request.identifier)}: {resent.error}"
                )
            return response

        code = await idn.issue_challenge(
            db, kind=kind, identifier=identifier, purpose=idn.LOGIN, user_id=user.id
        )
        await db.commit()

        result = await deliver_otp(identifier, code)
        if result.success:
            logger.info(
                f"OTP delivered via {result.method} to {_mask_for_log(request.identifier)}"
            )
            return response
        logger.warning(
            f"OTP delivery failed to {_mask_for_log(request.identifier)}: {result.error}"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not send the verification code. Please try again later.",
        )

    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message=f"Failed to send OTP to {_mask(request.identifier)}",
            exc=exc,
            endpoint="/auth/send-otp",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP. Please try again.",
        )


@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(
    request: VerifyOtpRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Sign in with a login code. The code verifies exactly the identifier it was sent to, for the ``login`` purpose only."""
    client_ip = client_ip_for(http_request, None)
    check_otp_verify_rate(request.identifier)

    try:
        kind = idn.EMAIL if request.is_email else idn.PHONE
        identifier = idn.normalise(kind, request.identifier)

        # Only the newest open code for this identifier+purpose can be used. The row is locked (FOR UPDATE) so two concurrent
        # requests cannot both consume it, and wrong guesses are counted on the row itself, so the limit survives restarts and
        # holds across workers. Every failure returns the same response.
        otp = await idn.consume_challenge(
            db, kind=kind, identifier=identifier, purpose=idn.LOGIN, code=request.code
        )
        if otp is None or otp.user_id is None:
            raise idn.failure()

        user = await db.get(User, otp.user_id)
        held = (
            None if user is None else (user.email if kind == idn.EMAIL else user.phone)
        )
        if user is None or held != identifier:
            await (
                db.commit()
            )  # the code is spent; the account no longer holds this identifier
            raise idn.failure()

        if idn.is_verified(user, kind):
            pass
        elif idn.other_verified(user, kind):
            # Legacy row whose OTHER identifier is verified: proving this one signs nobody in and merges nothing.
            await db.commit()
            raise _unverified_on_existing_account()
        else:
            # Legacy row with NO verified identifier: this code, sent to this identifier alone, proves it.
            if kind == idn.EMAIL:
                user.email_verified_at = datetime.utcnow()
            else:
                user.phone_verified_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)

        logger.info(f"User authenticated: {user.id} via {_mask(request.identifier)}")
        await _register_device(db, user, request, client_ip)
        return _token_response(user, identifier)

    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message=f"OTP verification failed for {_mask(request.identifier)}",
            exc=exc,
            endpoint="/auth/verify-otp",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Verification failed. Please try again.",
        )


@router.post("/google", response_model=TokenResponse)
async def google_login(
    request: GoogleLoginRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Sign in (or sign up) with a Google ID token verified server-side."""
    client_ip = client_ip_for(http_request, None)
    if not rate_limiter.is_allowed(
        f"google_login_ip:{client_ip}", max_hits=20, window_seconds=60
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many sign-in attempts. Please wait a minute.",
            headers={"Retry-After": "60"},
        )
    try:
        identity = await verify_google_id_token(request.id_token)
    except GoogleNotConfigured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Sign-In is not available right now.",
        )
    except GoogleAuthError as exc:
        logger.warning(f"Google sign-in rejected: {exc.reason}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google sign-in could not be verified.",
        )

    email = identity.email.strip().lower()
    now = datetime.utcnow()
    try:
        # 1. A stable Google subject already bound to an account always wins (an e-mail change never moves the link).
        user = (
            await db.execute(select(User).where(User.google_sub == identity.subject))
        ).scalar_one_or_none()
        if user is None:
            holder = await idn.owner_of(db, idn.EMAIL, email)
            if holder is None:
                # 2. Nobody holds this address: new account, e-mail proven by Google. Creating an account needs the same
                #    consent as e-mail registration; without it nothing is created (the client shows the consent screen
                #    and retries).
                if request.consent is None:
                    raise cns.consent_required_error()
                cns.check_required_versions(
                    request.consent.terms_version, request.consent.privacy_version
                )
                user = User(
                    id=uuid.uuid4(),
                    email=email,
                    email_verified_at=now,
                    full_name=identity.name,
                    google_sub=identity.subject,
                    is_active=True,  # the column default only applies on flush; the check below runs before it
                )
                db.add(user)
                cns.add_required(db, user.id, cns.GOOGLE, now)
                if request.consent.ai_processing is not None:
                    cns.add_decision(
                        db,
                        user.id,
                        cns.AI_PROCESSING,
                        request.consent.ai_processing,
                        cns.GOOGLE,
                        now,
                    )
            else:
                # 3. Somebody holds it. Link ONLY when this is the same mailbox the account already PROVED (two independent
                #    proofs), never over an existing different Google binding, never onto an unverified claim.
                if holder.google_sub and holder.google_sub != identity.subject:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="This account is already linked to a different Google account.",
                    )
                if holder.email_verified:
                    holder.google_sub = identity.subject
                elif not idn.other_verified(holder, idn.EMAIL):
                    # legacy row with nothing verified: Google proves its only identifier
                    holder.email_verified_at = now
                    holder.google_sub = identity.subject
                else:
                    raise _unverified_on_existing_account()
                user = holder
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled."
            )
        if not user.full_name and identity.name:
            user.full_name = identity.name
        await idn.commit_or_conflict(
            db, "This Google account or email is already linked to another account."
        )
        await db.refresh(user)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        await log_error(
            message="Google sign-in failed",
            exc=exc,
            endpoint="/auth/google",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Sign-in failed. Please try again.",
        )
    logger.info(f"User authenticated: {user.id} via google ({_mask(email)})")

    await _register_device(db, user, request, client_ip)
    return _token_response(user, email)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = client_ip_for(http_request, None)
    try:
        payload = jwt.decode(
            request.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        user_id = payload.get("sub")
        try:
            user_uuid = uuid.UUID(str(user_id))
        except ValueError:
            raise HTTPException(
                status_code=401, detail="Invalid or expired refresh token"
            )
        # A deleted/deactivated account must not be able to keep minting tokens.
        user = (
            await db.execute(select(User).where(User.id == user_uuid))
        ).scalar_one_or_none()
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        identifier = (
            payload.get("identifier")
            or payload.get("email")
            or payload.get("phone")
            or ""
        )

        # -- Rotation with replay detection ------------------------------------
        try:
            jti = uuid.UUID(str(payload.get("jti")))
            family = uuid.UUID(str(payload.get("fam")))
        except ValueError:
            # Issued before rotation existed: it cannot be tracked, so it cannot be honoured.
            raise HTTPException(status_code=401, detail="Please sign in again.")
        now = datetime.utcnow()
        expires = datetime.utcfromtimestamp(payload["exp"])
        await db.execute(
            delete(RefreshTokenUse).where(RefreshTokenUse.expires_at < now)
        )
        await db.execute(
            delete(RevokedTokenFamily).where(RevokedTokenFamily.expires_at < now)
        )
        revoked = (
            await db.execute(
                select(RevokedTokenFamily.family_id).where(
                    RevokedTokenFamily.family_id == family
                )
            )
        ).first()
        if revoked:
            await db.commit()
            raise HTTPException(status_code=401, detail="Please sign in again.")
        inserted = await db.execute(
            pg_insert(RefreshTokenUse)
            .values(
                jti=jti,
                family_id=family,
                user_id=user_uuid,
                expires_at=expires,
                used_at=now,
            )
            .on_conflict_do_nothing(index_elements=["jti"])
            .returning(RefreshTokenUse.jti)
        )
        if inserted.first() is None:
            # Already exchanged once: someone is replaying it. Kill the whole login lineage.
            await db.execute(
                pg_insert(RevokedTokenFamily)
                .values(
                    family_id=family,
                    user_id=user_uuid,
                    expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
                    revoked_at=now,
                )
                .on_conflict_do_nothing(index_elements=["family_id"])
            )
            await db.commit()
            logger.warning(
                f"Refresh-token replay detected for user {user_uuid}; family revoked"
            )
            raise HTTPException(status_code=401, detail="Please sign in again.")
        await db.commit()
        return create_tokens(user_id, identifier, family_id=str(family))

    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    except Exception as exc:
        await log_error(
            message="Token refresh failed",
            exc=exc,
            endpoint="/auth/refresh",
            method="POST",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=500, detail="Token refresh failed. Please log in again."
        )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    request: UpdateProfileRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    client_ip = client_ip_for(http_request, None)
    # An e-mail address is an identity: it can only change after the NEW address proves itself (POST /auth/email/change/*).
    if request.email is not None and request.email.strip().lower() != (
        current_user.email or ""
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The email address cannot be changed here. Verify the new address with /auth/email/change/start.",
            headers={"X-Identity-Error": "email_change_requires_verification"},
        )
    try:
        if request.full_name is not None:
            current_user.full_name = request.full_name
        if request.first_name is not None:
            current_user.first_name = request.first_name
        if request.last_name is not None:
            current_user.last_name = request.last_name
        if (
            request.first_name is not None or request.last_name is not None
        ) and request.full_name is None:
            fn = request.first_name or current_user.first_name or ""
            ln = request.last_name or current_user.last_name or ""
            current_user.full_name = f"{fn} {ln}".strip() or current_user.full_name
        if request.alt_phone is not None:
            current_user.alt_phone = request.alt_phone
        if request.senior_mode is not None:
            current_user.senior_mode = request.senior_mode
        if request.flat_no is not None:
            current_user.flat_no = request.flat_no
        if request.building is not None:
            current_user.building = request.building
        if request.street is not None:
            current_user.street = request.street
        if request.city is not None:
            current_user.city = request.city
        if request.state is not None:
            current_user.state = request.state
        if request.country is not None:
            current_user.country = request.country
        if request.pin_code is not None:
            current_user.pin_code = request.pin_code
        current_user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(current_user)
        return current_user
    except Exception as exc:
        await (
            db.rollback()
        )  # a failed commit must not leave the session unusable for the error log below
        await log_error(
            message=f"Profile update failed for user {current_user.id}",
            exc=exc,
            endpoint="/auth/me",
            method="PATCH",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=500, detail="Profile update failed. Please try again."
        )


# ---------------------------------------------------------------------------
# Account deletion — mandatory for Google Play (User Data policy)
# ---------------------------------------------------------------------------
#
# Approach: erase everything the user created, keep an inert tombstone.
#   • DELETE every user-linked row (evidence, recordings, devices, family, emergency
#     contacts, OTPs, scans, warrior data, ...) and the uploaded files; anonymise
#     error_logs. Full policy: app/services/account_erasure.py.
#   • Keep User.id + created_at as a tombstone (all PII columns NULLed, is_active=False)
#     so the append-only warrior audit trail keeps referential integrity.
#   • Email and phone are UNIQUE indexes with NULL allowed, so the user
#     can re-register with the same credentials later and get a brand
#     new User row — exactly what Play requires.
#
# Not implemented here (follow-up slice): cascade cleanup of recordings,
# evidence, alerts, reports — those tables have their own retention policy
# and need per-table decisions. Phase 2 will add a background task.
@router.delete("/me", response_model=DeleteAccountResponse)
async def delete_account(
    request: DeleteAccountRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the authenticated user's data and neutralise the account.

    Deletes everything the user created (rows + uploaded files), anonymises error
    logs and keeps only an inert tombstone plus the append-only moderation audit trail
    (see app/services/account_erasure.py for the exact policy).

    Requires `{"confirm": "DELETE", "code": "<code>"}`: the literal confirmation (any other value is a 422) and the
    re-authentication code from `POST /auth/me/delete/start`. A wrong, expired, replayed or other-account code is the
    same 400 as any failed code. On
    success, returns `{message, user_id, scrubbed_at}` and the client
    must discard its JWT (the account's is_active=False will block any
    subsequent refresh).
    """
    client_ip = client_ip_for(http_request, None)
    user_id = str(current_user.id)

    # Re-authentication: a code sent a moment ago (POST /auth/me/delete/start) to the VERIFIED e-mail/phone, bound to this
    # account and to this purpose. A stolen access token alone cannot erase an account. The code is consumed in the same
    # transaction as the erasure, so a failed erasure can be retried with the same code.
    channel = idn.reauth_channel(current_user)
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Verify your email address or phone number before deleting your account (sign in again with a code).",
            headers={"X-Identity-Error": "no_verified_identifier"},
        )
    kind, identifier = channel
    check_otp_verify_rate(f"delete:{user_id}")
    otp = await idn.consume_challenge(
        db,
        kind=kind,
        identifier=identifier,
        purpose=idn.DELETE_ACCOUNT,
        code=request.code,
    )
    if otp is None or otp.user_id != current_user.id:
        raise idn.failure()

    try:
        logger.info(f"Account deletion requested by user {user_id}")
        # Identifiers the OTP rows are keyed by — capture BEFORE the scrub.
        email, phone, alt_phone = (
            current_user.email,
            current_user.phone,
            current_user.alt_phone,
        )

        # ── Delete user-linked data (rows) inside this transaction ─────────
        erased = await erase_user_data(
            db, current_user, email=email, phone=phone, alt_phone=alt_phone
        )

        # ── Scrub the user row into an inert tombstone ──────────────────────
        current_user.email = None
        current_user.phone = None
        current_user.email_verified_at = None
        current_user.phone_verified_at = None
        current_user.google_sub = None
        current_user.alt_phone = None
        current_user.first_name = None
        current_user.last_name = None
        current_user.full_name = None
        current_user.hashed_password = None
        current_user.flat_no = None
        current_user.building = None
        current_user.street = None
        current_user.city = None
        current_user.state = None
        current_user.pin_code = None
        current_user.country = None
        # Deactivate: blocks API access and /auth/refresh for any token already issued
        current_user.is_active = False
        current_user.updated_at = datetime.utcnow()

        await db.commit()

        # Files are removed only after the DB commit succeeded (a failed commit must not
        # leave rows pointing at deleted files). Missing files are fine (idempotent).
        removed, failed = remove_files(erased.files)
        logger.info(
            f"Account {user_id} erased: rows={sum(erased.counts.values())} "
            f"files_removed={removed} files_failed={failed}"
        )
        if failed:
            await log_error(
                message=f"Account erasure left {failed} file(s) on disk for user {user_id}",
                level="ERROR",
                endpoint="/auth/me",
                method="DELETE",
                client_ip=client_ip,
                send_email=False,
            )
        return DeleteAccountResponse(
            message=(
                "Your account and the data you created have been deleted. We keep only an "
                "inert account record and moderation audit entries (identifiers, actions "
                "and reviewer notes)."
            ),
            retained=RETAINED,
            user_id=user_id,
            scrubbed_at=current_user.updated_at,
        )
    except Exception as exc:
        await db.rollback()
        await log_error(
            message=f"Account deletion failed for user {user_id}",
            exc=exc,
            endpoint="/auth/me",
            method="DELETE",
            user_id=user_id,
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=500,
            detail="Account deletion failed. Please try again or contact support.",
        )
