import re
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

# Limits mirror the column sizes (name 150, relationship 100, phone 30, email 255): an over-long
# value used to reach the database and come back as a 500.
_PHONE = re.compile(r"^\+?[0-9][0-9\s\-()]{5,28}$")


def _clean_phone(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    v = v.strip()
    if v == "":
        return ""  # PATCH: empty string means "clear this field"
    if not _PHONE.match(v):
        raise ValueError(
            "phone must be 6-30 digits (optional +, spaces, dashes, brackets)"
        )
    return v


class EmergencyContactCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    relationship: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = Field(None, max_length=30)
    email: Optional[EmailStr] = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        v = _clean_phone(v)
        return v or None

    @field_validator("email", mode="before")
    @classmethod
    def _blank_email(cls, v):
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("relationship")
    @classmethod
    def _rel(cls, v):
        return (v.strip() or None) if isinstance(v, str) else v

    @model_validator(mode="after")
    def _needs_a_channel(self):
        if not (self.phone or self.email):
            raise ValueError("at least one of phone or email is required")
        return self


class EmergencyContactUpdate(BaseModel):
    """Partial update - only fields the user supplies are changed ("" clears phone/email/relationship)."""

    name: Optional[str] = Field(None, max_length=150)
    relationship: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = Field(None, max_length=30)
    email: Optional[str] = Field(None, max_length=255)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        return _clean_phone(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        if v is None or v.strip() == "":
            return "" if v is not None else None
        from pydantic import TypeAdapter

        return str(TypeAdapter(EmailStr).validate_python(v.strip()))


class EmergencyContactResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    relationship: Optional[str]
    phone: Optional[str]
    email: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
