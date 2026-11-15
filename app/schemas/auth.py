from pydantic import BaseModel, Field, field_validator
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
    identifier: str  # masked, e.g. +91*****1916 or r****@gmail.com
    method: str  # 'sms' or 'email'


class VerifyOtpRequest(BaseModel):
    identifier: str  # same phone or email used in send-otp
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


class GoogleLoginRequest(BaseModel):
    id_token: str = Field(..., min_length=20, max_length=4096)
    # Required only when this sign-in would CREATE an account (422 consent_required otherwise).
    consent: Optional["ConsentSubmission"] = None

    # Optional device registration fields (same as verify-otp)
    device_token: Optional[str] = None
    device_name: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    app_version: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    # Backend-authoritative verification state (additive; clients must not assume an identifier is verified otherwise).
    email_verified: Optional[bool] = None
    phone_verified: Optional[bool] = None
    next_step: Optional[str] = (
        None  # e.g. "verify_phone" right after e-mail verification
    )


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
    email_verified: bool = False
    phone_verified: bool = False
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


class ConsentSubmission(BaseModel):
    """What the person accepted on the consent screen. The two acknowledgements are mandatory and separate from the optional
    choices; versions must match the notice the server currently publishes."""

    terms_version: str = Field(..., max_length=20)
    privacy_version: str = Field(..., max_length=20)
    ai_processing: Optional[bool] = None  # optional, default off; None = not asked


class RegisterRequest(BaseModel):
    """Full profile registration — creates user + sends OTP in one step."""

    consent: Optional[ConsentSubmission] = (
        None  # required by the endpoint (422 without it)
    )
    first_name: str
    last_name: Optional[str] = None
    email: str
    phone: Optional[str] = None  # optional; with country code e.g. +919987671916
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
    identifier: str  # masked primary identifier (email)
    masked_email: str  # r****@gmail.com
    masked_phone: Optional[str] = (
        None  # +91*****1916 or None (pending: verified in a second step)
    )
    next_step: str = "verify_email"


# ---------------------------------------------------------------------------
# Account deletion (Play Store User Data policy requirement)
# ---------------------------------------------------------------------------
class DeleteAccountRequest(BaseModel):
    """Explicit confirmation body for account deletion.

    Requiring the user to echo back a literal string prevents accidental
    deletion via click-jacking or test tooling, and satisfies Play's
    "clear and conspicuous" confirmation guidance.
    """

    confirm: str  # must be exactly "DELETE"
    # Re-authentication: the code sent by POST /auth/me/delete/start to the account's verified e-mail (or phone).
    code: str = Field(..., min_length=4, max_length=12)

    @field_validator("confirm")
    @classmethod
    def validate_confirm(cls, v: str) -> str:
        if v != "DELETE":
            raise ValueError('Confirmation must be the literal string "DELETE".')
        return v


class ConsentItem(BaseModel):
    purpose: str
    required: bool
    version: str  # the version currently published
    granted: Optional[bool] = None  # newest decision, None = never decided
    accepted_version: Optional[str] = None
    decided_at: Optional[datetime] = None
    up_to_date: bool = False


class ConsentState(BaseModel):
    items: list[ConsentItem]
    required_up_to_date: bool


class ConsentUpdateRequest(BaseModel):
    purpose: str = Field(..., max_length=40)
    granted: bool
    version: str = Field(..., max_length=20)


class DeleteStartResponse(BaseModel):
    message: str
    identifier: Optional[str] = None  # masked


class DeleteAccountResponse(BaseModel):
    message: str
    user_id: str
    scrubbed_at: datetime
    retained: list[str] = []  # what is deliberately kept (see account_erasure.py)


# ---------------------------------------------------------------------------
# Identity binding (phone verification, e-mail change, release of an unverified claim)
# ---------------------------------------------------------------------------
def _clean_phone(v: str) -> str:
    v = v.strip()
    digits = v.lstrip("+").replace(" ", "").replace("-", "")
    if not digits.isdigit() or len(digits) < 7:
        raise ValueError("Invalid phone number format.")
    return v


def _clean_email(v: str) -> str:
    v = v.strip().lower()
    parts = v.split("@")
    if len(parts) != 2 or not parts[0] or "." not in parts[1]:
        raise ValueError("Invalid email address format.")
    return v


class PhoneStartRequest(BaseModel):
    phone: str

    @field_validator("phone")
    @classmethod
    def _v(cls, v: str) -> str:
        return _clean_phone(v)


class PhoneConfirmRequest(BaseModel):
    phone: str
    code: str = Field(..., min_length=4, max_length=12)

    @field_validator("phone")
    @classmethod
    def _v(cls, v: str) -> str:
        return _clean_phone(v)


class EmailChangeStartRequest(BaseModel):
    new_email: str

    @field_validator("new_email")
    @classmethod
    def _v(cls, v: str) -> str:
        return _clean_email(v)


class EmailChangeConfirmRequest(BaseModel):
    new_email: str
    code: str = Field(..., min_length=4, max_length=12)

    @field_validator("new_email")
    @classmethod
    def _v(cls, v: str) -> str:
        return _clean_email(v)


class ReleaseStartRequest(BaseModel):
    identifier: str

    @field_validator("identifier")
    @classmethod
    def _v(cls, v: str) -> str:
        return _clean_email(v) if "@" in v else _clean_phone(v)


class ReleaseConfirmRequest(BaseModel):
    identifier: str
    code: str = Field(..., min_length=4, max_length=12)

    @field_validator("identifier")
    @classmethod
    def _v(cls, v: str) -> str:
        return _clean_email(v) if "@" in v else _clean_phone(v)


class IdentityStepResponse(BaseModel):
    message: str
    identifier: Optional[str] = None  # masked
    email_verified: Optional[bool] = None
    phone_verified: Optional[bool] = None
