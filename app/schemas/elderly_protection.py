from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
import re

from pydantic import BaseModel, Field, field_validator


_PHONE = re.compile(r"^\+?[0-9][0-9\s\-()]{5,18}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")


class ElderlyConfigRequest(BaseModel):
    enabled: bool = False
    guardian_name: Optional[str] = Field(None, max_length=100)
    guardian_phone: Optional[str] = Field(None, max_length=20)
    guardian_email: Optional[str] = Field(None, max_length=255)
    block_risky_installs: bool = True
    alert_threshold: int = Field(40, ge=0, le=100)
    auto_alert_guardian: bool = True
    require_approval: bool = False
    simplified_ui: bool = True
    large_text: bool = True
    # Authorising a guardian: true = "this guardian agreed to be alerted and I saw the disclosure" (needs the current notice
    # version); false = withdraw. Omitted = unchanged. Changing a guardian contact always withdraws authorisation and
    # verification for the old contact.
    guardian_authorised: Optional[bool] = None
    guardian_notice_version: Optional[str] = Field(None, max_length=20)

    @field_validator("guardian_name", "guardian_phone", "guardian_email", mode="before")
    @classmethod
    def _blank_to_none(cls, v):
        if isinstance(v, str):
            v = v.strip()
            return v or None
        return v

    @field_validator("guardian_phone")
    @classmethod
    def _phone(cls, v):
        if v is not None and not _PHONE.match(v):
            raise ValueError("guardian_phone is not a valid phone number")
        return v

    @field_validator("guardian_email")
    @classmethod
    def _email(cls, v):
        if v is not None and not _EMAIL.match(v):
            raise ValueError("guardian_email is not a valid e-mail address")
        return v.lower() if v else v


class ElderlyConfigResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    enabled: bool
    guardian_name: Optional[str]
    guardian_phone: Optional[str]
    guardian_email: Optional[str]
    block_risky_installs: bool
    alert_threshold: int
    auto_alert_guardian: bool
    require_approval: bool
    simplified_ui: bool
    large_text: bool
    updated_at: datetime
    guardian_authorised: bool = False
    guardian_email_verified: bool = False
    guardian_phone_verified: bool = False

    model_config = {"from_attributes": True}


class GuardianVerifyStart(BaseModel):
    channel: str = Field("email", pattern=r"^(email|phone)$")


class GuardianVerifyConfirm(BaseModel):
    code: str = Field(..., min_length=4, max_length=12)


class GuardianAlertRequest(BaseModel):
    """
    Sent by the device when a risky install is detected in elderly mode
    and auto_alert_guardian is true.  Backend delivers SMS / email.
    """

    package_name: str = Field(..., min_length=1, max_length=255)
    app_name: str = Field(..., min_length=1, max_length=100)
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str = Field(..., pattern=r"^[A-Za-z_]{1,20}$")
    risk_tags: list[str] = Field(default_factory=list, max_length=10)
    clone_verdict: Optional[str] = Field(None, max_length=50)

    @field_validator("risk_tags")
    @classmethod
    def _tags(cls, v):
        return [t[:100] for t in v]
