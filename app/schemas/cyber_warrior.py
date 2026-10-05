"""Pydantic schemas for the Cyber Warriors Network.

Validation guard rails live here, not in the router:
  • Applicants must be ≥ 18 years old on the day they apply. The schema
    rejects any date_of_birth that would make the applicant underage.
  • Explicit affirmative consent on three distinct checkboxes. "True"
    is the only accepted value; the checkbox stays unchecked otherwise.
  • Motivation must be ≥ 40 characters so the admin reviewer gets
    enough signal to make a decision.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.cyber_warrior import (
    ApplicationStatus,
    WarriorRole,
)


# ─── Age gate ────────────────────────────────────────────────────────────

MIN_WARRIOR_AGE_YEARS = 18


def _age_in_years(dob: date, today: date | None = None) -> int:
    """Precise whole-years-old count honouring birth day/month."""
    today = today or date.today()
    years = today.year - dob.year
    if (today.month, today.day) < (dob.month, dob.day):
        years -= 1
    return years


# ─── Application in ──────────────────────────────────────────────────────


class WarriorApplicationCreate(BaseModel):
    """Payload for POST /warriors/apply.

    All consent flags must be `true` — the schema rejects false/missing.
    date_of_birth must correspond to someone ≥ 18 years old today.
    """

    full_name: str = Field(..., min_length=2, max_length=255)
    date_of_birth: date
    phone: str = Field(..., min_length=7, max_length=20)
    email: EmailStr
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)

    preferred_role: WarriorRole = WarriorRole.trainee
    motivation: str = Field(..., min_length=40, max_length=5000)
    skills: Optional[str] = Field(None, max_length=5000)
    languages: Optional[str] = Field(None, max_length=200)
    availability_hours_per_week: Optional[int] = Field(None, ge=1, le=168)

    consent_bgcheck: bool
    consent_pii: bool
    consent_safeguarding: bool

    @field_validator("date_of_birth")
    @classmethod
    def must_be_adult(cls, v: date) -> date:
        """Reject minors with a precise error message."""
        if _age_in_years(v) < MIN_WARRIOR_AGE_YEARS:
            raise ValueError(
                f"Cyber Warriors must be at least {MIN_WARRIOR_AGE_YEARS} "
                "years old. Minors can still participate in supervised "
                "awareness activities inside the app."
            )
        # Sanity: can't be born in the future, can't be absurdly old
        if v > date.today():
            raise ValueError("date_of_birth cannot be in the future.")
        if _age_in_years(v) > 120:
            raise ValueError("date_of_birth is implausible (>120 years ago).")
        return v

    @field_validator("preferred_role")
    @classmethod
    def cannot_self_promote(cls, v: WarriorRole) -> WarriorRole:
        """Applicants can only request trainee or verified_warrior.

        Mentor / moderator / admin are promotion-only roles — admin assigns
        them explicitly to vetted individuals. Letting a brand-new applicant
        tick "admin" is a trivial escalation path, so it's blocked here.
        """
        allowed = {WarriorRole.trainee, WarriorRole.verified_warrior}
        if v not in allowed:
            raise ValueError(
                "preferred_role must be 'trainee' or 'verified_warrior'. "
                "Higher roles are assigned by admin after review."
            )
        return v

    @field_validator("consent_bgcheck", "consent_pii", "consent_safeguarding")
    @classmethod
    def consent_must_be_true(cls, v: bool, info) -> bool:
        if v is not True:
            raise ValueError(
                f"Consent field '{info.field_name}' must be explicitly True."
            )
        return v


# ─── Application out ─────────────────────────────────────────────────────


class WarriorApplicationResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    full_name: str
    status: ApplicationStatus
    preferred_role: WarriorRole
    created_at: datetime
    reviewed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ─── Profile out (for /me/warrior endpoint, future slice) ────────────────


class WarriorProfileResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    role: WarriorRole
    is_active: bool
    display_name: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ─── Admin review payloads ───────────────────────────────────────────────


class ApplicationApprove(BaseModel):
    reviewer_notes: Optional[str] = Field(None, max_length=5000)
    assigned_role: WarriorRole = WarriorRole.trainee

    @field_validator("assigned_role")
    @classmethod
    def no_admin_fast_track(cls, v: WarriorRole) -> WarriorRole:
        # Approvals can only create trainee or verified_warrior profiles.
        # Mentor+ roles require a subsequent explicit promote action with
        # its own audit log entry.
        if v not in {WarriorRole.trainee, WarriorRole.verified_warrior}:
            raise ValueError(
                "Approvals must assign 'trainee' or 'verified_warrior'. "
                "Promote to mentor/moderator/admin via a separate action."
            )
        return v


class ApplicationReject(BaseModel):
    reviewer_notes: str = Field(
        ..., min_length=5, max_length=5000, description="Reason shown to the applicant."
    )
