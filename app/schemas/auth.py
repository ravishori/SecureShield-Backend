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
            # Basic email format check
            parts = v.split("@")
            if len(parts) != 2 or not parts[0] or "." not in parts[1]:
                raise ValueError("Invalid email address format.")
        else:
            # Basic phone check — digits, optional leading +
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
    subscription_tier: SubscriptionTier
    is_active: bool
    senior_mode: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateProfileRequest(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    senior_mode: Optional[bool] = None
