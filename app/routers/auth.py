"""
Auth Router — Register / OTP send / verify / refresh / profile
==============================================================
Dual-channel OTP:
  Registration  → OTP sent to email (required) + phone (if provided)
  Login         → OTP sent to both email AND phone when user has both

All exceptions are caught, logged (file + DB + email alert), and
re-raised as clean HTTP errors.
"""

import random
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.rate_limiter import check_otp_send_rate, check_otp_verify_rate
from app.models.user import OTP, User
from app.schemas.auth import (
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
from app.services.device_service import register_and_check_device, send_new_device_alert
from app.services.logger_service import get_logger, log_error
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


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_tokens(user_id: str, identifier: str) -> dict:
    payload = {"sub": user_id, "identifier": identifier}
    if "@" not in identifier:
        payload["phone"] = identifier
    else:
        payload["email"] = identifier

    access_token = create_token(
        payload, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_token(
        {**payload, "type": "refresh"},
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
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/check-user")
async def check_user(
    identifier: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Check if a phone number or email is already registered.
    Returns {exists, has_profile} — used by the Flutter app for smart auth routing.
    """
    identifier = identifier.strip()
    if "@" in identifier:
        result = await db.execute(select(User).where(User.email == identifier.lower()))
    else:
        try:
            normalised = _normalize_phone(identifier)
        except Exception:
            normalised = identifier
        result = await db.execute(select(User).where(User.phone == normalised))

    user = result.scalar_one_or_none()
    if not user:
        return {"exists": False, "has_profile": False}

    has_profile = bool(user.full_name and user.full_name.strip())
    return {"exists": True, "has_profile": has_profile}


@router.post("/register", response_model=RegisterResponse)
async def register_user(
    body: RegisterRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    One-step registration:
      1. Validate uniqueness of email (and phone if provided)
      2. Create user with full profile data
      3. Generate OTP
      4. Send OTP to email (required) + phone (if provided)
      5. Return masked identifiers so Flutter can display them on OTP screen
    """
    client_ip = http_request.client.host if http_request.client else None

    try:
        # ── Uniqueness checks ──────────────────────────────────────────────
        email_lower = body.email.lower()
        existing_email = await db.execute(select(User).where(User.email == email_lower))
        if existing_email.scalar_one_or_none():
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

            existing_phone = await db.execute(select(User).where(User.phone == normalized_phone))
            if existing_phone.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this phone number already exists. Please login instead.",
                )

        # ── Create user ────────────────────────────────────────────────────
        full_name = f"{body.first_name} {body.last_name or ''}".strip()
        user = User(
            email=email_lower,
            phone=normalized_phone,
            first_name=body.first_name.strip(),
            last_name=body.last_name.strip() if body.last_name else None,
            full_name=full_name,
            flat_no=body.flat_no,
            building=body.building,
            street=body.street,
            city=body.city,
            state=body.state,
            country=body.country or "India",
            pin_code=body.pin_code,
        )
        db.add(user)
        await db.flush()   # get user.id without committing yet

        # ── Generate OTP (single code, dual delivery) ──────────────────────
        code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        # One OTP record with both channels populated (whichever apply)
        otp = OTP(
            email=email_lower,
            phone=normalized_phone,
            code=code,
            expires_at=expires_at,
        )
        db.add(otp)
        await db.commit()
        await db.refresh(user)

        # ── Deliver OTP ────────────────────────────────────────────────────
        email_result = await deliver_otp(email_lower, code)
        if not email_result.success:
            logger.warning(f"OTP email delivery failed for {_mask_email(email_lower)}: {email_result.error}")

        if normalized_phone:
            phone_result = await deliver_otp(normalized_phone, code)
            if not phone_result.success:
                logger.warning(f"OTP SMS delivery failed for {_mask_phone(normalized_phone)}: {phone_result.error}")

        masked_email = _mask_email(email_lower)
        masked_phone = _mask_phone(normalized_phone) if normalized_phone else None
        channel_msg = "email" + (" and phone" if normalized_phone else "")

        logger.info(f"New user registered: {user.id}, email: {masked_email}")

        return RegisterResponse(
            message=f"Account created! OTP sent to your {channel_msg}.",
            identifier=masked_email,
            masked_email=masked_email,
            masked_phone=masked_phone,
        )

    except HTTPException:
        raise
    except Exception as exc:
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


@router.post("/send-otp", response_model=SendOtpResponse)
async def send_otp(
    request: SendOtpRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Login OTP: sends to the provided identifier.
    If the user has BOTH email and phone on file, sends to both channels.
    """
    client_ip = http_request.client.host if http_request.client else None
    check_otp_send_rate(request.identifier)

    try:
        code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        identifier = request.identifier
        if not request.is_email:
            identifier = _normalize_phone(identifier)

        # ── Look up user to check if they have both channels ───────────────
        if request.is_email:
            user_result = await db.execute(select(User).where(User.email == identifier.lower()))
        else:
            user_result = await db.execute(select(User).where(User.phone == identifier))
        user = user_result.scalar_one_or_none()

        # Determine the other channel
        other_email: str | None = None
        other_phone: str | None = None

        if user:
            if request.is_email and user.phone:
                other_phone = user.phone
            elif not request.is_email and user.email:
                other_email = user.email

        # ── Create OTP record with all applicable channels ─────────────────
        if request.is_email:
            otp = OTP(
                email=identifier.lower(),
                phone=other_phone,
                code=code,
                expires_at=expires_at,
            )
        else:
            otp = OTP(
                phone=identifier,
                email=other_email,
                code=code,
                expires_at=expires_at,
            )

        db.add(otp)
        await db.commit()

        # ── Deliver OTP (primary channel + secondary if available) ─────────
        primary_result = await deliver_otp(identifier, code)
        if primary_result.success:
            logger.info(f"OTP delivered via {primary_result.method} to {_mask(request.identifier)}")
        else:
            logger.warning(f"Primary OTP delivery failed to {_mask(request.identifier)}: {primary_result.error}")

        # Secondary channel delivery (fire-and-forget on failure)
        if other_phone:
            secondary = await deliver_otp(other_phone, code)
            if secondary.success:
                logger.info(f"OTP also delivered via SMS to secondary channel {_mask_phone(other_phone)}")
        elif other_email:
            secondary = await deliver_otp(other_email, code)
            if secondary.success:
                logger.info(f"OTP also delivered via email to secondary channel {_mask_email(other_email)}")

        return SendOtpResponse(
            message="OTP sent successfully",
            identifier=_mask(request.identifier),
            method=request.method,
        )

    except HTTPException:
        raise
    except Exception as exc:
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
    client_ip = http_request.client.host if http_request.client else None
    check_otp_verify_rate(request.identifier)

    try:
        identifier = request.identifier
        if not request.is_email:
            identifier = _normalize_phone(identifier)

        if request.is_email:
            otp_filter = OTP.email == identifier.lower()
            user_filter = User.email == identifier.lower()
        else:
            otp_filter = OTP.phone == identifier
            user_filter = User.phone == identifier

        otp_result = await db.execute(
            select(OTP)
            .where(
                otp_filter,
                OTP.code == request.code,
                OTP.is_used == False,  # noqa: E712
                OTP.expires_at > datetime.utcnow(),
            )
            .order_by(OTP.created_at.desc())
        )
        otp = otp_result.scalar_one_or_none()
        if not otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP. Please request a new one.",
            )

        otp.is_used = True

        user_result = await db.execute(select(User).where(user_filter))
        user = user_result.scalar_one_or_none()
        if not user:
            # Fallback: create minimal user (legacy login flow)
            if request.is_email:
                user = User(email=identifier.lower())
            else:
                user = User(phone=identifier)
            db.add(user)

        await db.commit()
        await db.refresh(user)

        logger.info(f"User authenticated: {user.id} via {_mask(request.identifier)}")

        # ── Device registration ───────────────────────────────────────────
        if request.device_token:
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

        # Use email as primary identifier for JWT if available (for registered users)
        login_identifier = user.email or identifier
        return create_tokens(str(user.id), login_identifier)

    except HTTPException:
        raise
    except Exception as exc:
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


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = http_request.client.host if http_request.client else None
    try:
        payload = jwt.decode(
            request.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        user_id = payload.get("sub")
        identifier = payload.get("identifier") or payload.get("email") or payload.get("phone") or ""
        return create_tokens(user_id, identifier)

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
        raise HTTPException(status_code=500, detail="Token refresh failed. Please log in again.")


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
    client_ip = http_request.client.host if http_request.client else None
    try:
        if request.email is not None:
            current_user.email = request.email.lower()
        if request.full_name is not None:
            current_user.full_name = request.full_name
        if request.first_name is not None:
            current_user.first_name = request.first_name
        if request.last_name is not None:
            current_user.last_name = request.last_name
        if (request.first_name is not None or request.last_name is not None) \
                and request.full_name is None:
            fn = request.first_name or current_user.first_name or ''
            ln = request.last_name  or current_user.last_name  or ''
            current_user.full_name = f"{fn} {ln}".strip() or current_user.full_name
        if request.alt_phone is not None:
            current_user.alt_phone = request.alt_phone
        if request.senior_mode is not None:
            current_user.senior_mode = request.senior_mode
        if request.flat_no  is not None: current_user.flat_no  = request.flat_no
        if request.building is not None: current_user.building = request.building
        if request.street   is not None: current_user.street   = request.street
        if request.city     is not None: current_user.city     = request.city
        if request.state    is not None: current_user.state    = request.state
        if request.country  is not None: current_user.country  = request.country
        if request.pin_code is not None: current_user.pin_code = request.pin_code
        current_user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(current_user)
        return current_user
    except Exception as exc:
        await log_error(
            message=f"Profile update failed for user {current_user.id}",
            exc=exc,
            endpoint="/auth/me",
            method="PATCH",
            user_id=str(current_user.id),
            client_ip=client_ip,
        )
        raise HTTPException(status_code=500, detail="Profile update failed. Please try again.")
