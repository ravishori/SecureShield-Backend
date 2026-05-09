from pydantic import BaseModel, field_validator
from typing import Optional
import uuid
from datetime import datetime
from app.models.user import SubscriptionTier


def _detect_method(identifier: str) -> str:
    """Return 'email' if identifier contains '@', else 'sms'."""
    return "email" if "@" in identifier else "sms"


class SendOtpRequest(BaseModel):
    identifier: str  # phone number OR email address

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Phone number or email address is required.")
        if "@" in v:
            parts = v.split("@")
            if len(parts) != 2 or not parts[0] or "." not in parts[1]:
                raise ValueError("Invalid email address format.")
        else:
            digits = v.lstrip("+").replace(" ", "").replace("-", "")
            if not digits.isdigit() or len(digits) < 7:
                raise ValueError("Invalid phone number format.")
        return v

    @property
    def is_email(self) -> bool:
        return "@" in self.identifier

    @property
    def method(self) -> str:
        return _detect_method(self.identifier)


class SendOtpResponse(BaseModel):
    message: str
    identifier: str   # masked, e.g. +91*****1916 or r****@gmail.com
    method: str       # 'sms' or 'email'


class VerifyOtpRequest(BaseModel):
    identifier: str   # same phone or email used in send-otp
    code: str

    # Optional device registration fields
    device_token: Optional[str] = None
    device_name: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    app_version: Optional[str] = None

    @property
    def is_email(self) -> bool:
        return "@" in self.identifier


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    phone: Optional[str]
    email: Optional[str]
    full_name: Optional[str]
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    alt_phone: Optional[str] = None
    subscription_tier: SubscriptionTier
    is_active: bool
    senior_mode: bool
    # Address fields
    flat_no: Optional[str] = None
    building: Optional[str] = None
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    pin_code: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateProfileRequest(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    alt_phone: Optional[str] = None
    senior_mode: Optional[bool] = None
    # Address fields
    flat_no: Optional[str] = None
    building: Optional[str] = None
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    pin_code: Optional[str] = None


# ── Registration ─────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    """Full profile registration — creates user + sends OTP in one step."""
    first_name: str
    last_name: Optional[str] = None
    email: str
    phone: Optional[str] = None     # optional; with country code e.g. +919987671916
    # Address (all optional at registration time)
    flat_no: Optional[str] = None
    building: Optional[str] = None
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pin_code: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        parts = v.split("@")
        if len(parts) != 2 or not parts[0] or "." not in parts[1]:
            raise ValueError("Invalid email address format.")
        return v

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("First name is required.")
        if len(v) < 2:
            raise ValueError("First name must be at least 2 characters.")
        return v

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        digits = v.lstrip("+").replace(" ", "").replace("-", "")
        if not digits.isdigit() or len(digits) < 7:
            raise ValueError("Invalid phone number format.")
        return v

    @field_validator("pin_code")
    @classmethod
    def validate_pin_code(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not v.isdigit() or len(v) != 6:
            raise ValueError("PIN code must be exactly 6 digits.")
        return v


class RegisterResponse(BaseModel):
    message: str
    identifier: str          # masked primary identifier (email)
    masked_email: str        # r****@gmail.com
    masked_phone: Optional[str] = None  # +91*****1916 or None
