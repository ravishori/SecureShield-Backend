"""
Auth Router — OTP send / verify / refresh / profile
=====================================================
Supports BOTH phone number and email address for OTP login:

  Phone  → OTP sent via Twilio SMS (falls back to WhatsApp, then console)
  Email  → OTP sent via SMTP (Gmail / any SMTP provider)

Auto-detection: if 'identifier' contains '@' it's treated as email,
otherwise as a phone number.

All exceptions are caught, logged (file + DB + email alert), and
re-raised as clean HTTP errors — the user never sees a raw traceback.

New in this version:
  - Rate limiting on send_otp and verify_otp
  - Device registration on successful verify_otp
  - New-device email alert when a previously unseen device logs in
  - OTP delivery delegated to otp_service.deliver_otp()
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
# Masking helpers (so we don't expose full phone/email in API response)
# ---------------------------------------------------------------------------
def _mask_phone(phone: str) -> str:
    """+919987671916 → +91*****1916"""
    if len(phone) <= 4:
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
    """identifier is the phone or email the user logged in with."""
    payload = {"sub": user_id, "identifier": identifier}
    # Keep 'phone' key for backwards-compat with JwtDecoder on Flutter side
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
@router.post("/send-otp", response_model=SendOtpResponse)
async def send_otp(
    request: SendOtpRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = http_request.client.host if http_request.client else None

    # Rate limit — 5 sends per identifier per hour
    check_otp_send_rate(request.identifier)

    try:
        code = str(random.randint(100000, 999999))
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        # Normalise phone to E.164 before storing and delivering
        identifier = request.identifier
        if not request.is_email:
            identifier = _normalize_phone(identifier)

        # Create OTP record — set phone or email field based on identifier type
        if request.is_email:
            otp = OTP(email=identifier, code=code, expires_at=expires_at)
        else:
            otp = OTP(phone=identifier, code=code, expires_at=expires_at)

        db.add(otp)
        await db.commit()

        # Deliver OTP via otp_service (SMS → WhatsApp → email → console)
        result = await deliver_otp(identifier, code)

        if result.success:
            logger.info(
                f"OTP delivered via {result.method} to {_mask(request.identifier)}"
            )
        else:
            logger.warning(
                f"OTP delivery failed (method={result.method}) for {_mask(request.identifier)}: "
                f"{result.error} — fell back to console"
            )

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

    # Rate limit — 10 attempts per identifier per 15 minutes
    check_otp_verify_rate(request.identifier)

    try:
        # Normalise phone to E.164 so the lookup matches what was stored at send-otp time
        identifier = request.identifier
        if not request.is_email:
            identifier = _normalize_phone(identifier)

        # Build query based on identifier type
        if request.is_email:
            otp_filter = OTP.email == identifier
            user_filter = User.email == identifier
        else:
            otp_filter = OTP.phone == identifier
            user_filter = User.phone == identifier

        # Validate OTP
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

        # Get or create user
        user_result = await db.execute(select(User).where(user_filter))
        user = user_result.scalar_one_or_none()
        if not user:
            if request.is_email:
                user = User(email=identifier)
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
                    logger.info(
                        f"New device detected for user {user.id}: "
                        f"'{request.device_name}' ({request.platform}) — sending alert"
                    )
                    # Fire-and-forget: send alert email (errors are swallowed inside)
                    await send_new_device_alert(
                        user=user,
                        device_name=request.device_name,
                        platform=request.platform,
                        client_ip=client_ip,
                    )
            except Exception as dev_exc:
                # Device registration failure must never block login
                logger.error(f"Device registration failed for user {user.id}: {dev_exc}")

        return create_tokens(str(user.id), identifier)

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
        identifier = payload.get("identifier") or payload.get("phone") or ""
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
            current_user.email = request.email
        if request.full_name is not None:
            current_user.full_name = request.full_name
        if request.senior_mode is not None:
            current_user.senior_mode = request.senior_mode
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
