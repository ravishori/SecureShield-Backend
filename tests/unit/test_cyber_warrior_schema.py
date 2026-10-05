"""Schema-level tests for the Cyber Warriors application form.

These enforce the three safeguarding guardrails:
  1. Age ≥ 18 (minors cannot apply)
  2. All three consent flags must be True
  3. Self-promotion to admin/mentor/moderator is impossible via the form
"""

from datetime import date, timedelta

import pytest
from pydantic import ValidationError

from app.models.cyber_warrior import WarriorRole
from app.schemas.cyber_warrior import (
    ApplicationApprove,
    ApplicationReject,
    MIN_WARRIOR_AGE_YEARS,
    WarriorApplicationCreate,
    _age_in_years,
)


# ─── Age helper ──────────────────────────────────────────────────────────

class TestAgeInYears:
    @pytest.mark.unit
    def test_exact_18_today(self):
        today = date(2026, 10, 4)
        dob = date(2008, 10, 4)
        assert _age_in_years(dob, today) == 18

    @pytest.mark.unit
    def test_18th_birthday_tomorrow_is_17(self):
        today = date(2026, 10, 4)
        dob = date(2008, 10, 5)
        assert _age_in_years(dob, today) == 17

    @pytest.mark.unit
    def test_adult_many_years(self):
        today = date(2026, 10, 4)
        dob = date(1980, 1, 1)
        assert _age_in_years(dob, today) == 46


# ─── Baseline payload ────────────────────────────────────────────────────

def _adult_dob() -> date:
    """A birth date comfortably over 18."""
    return date.today() - timedelta(days=365 * 25)


def _minor_dob() -> date:
    """A birth date for a 10-year-old today."""
    return date.today() - timedelta(days=365 * 10)


def _valid_payload(**overrides):
    base = dict(
        full_name="Priya Sharma",
        date_of_birth=_adult_dob(),
        phone="+919876543210",
        email="priya@example.com",
        city="Mumbai",
        state="MH",
        preferred_role=WarriorRole.trainee,
        motivation=(
            "I want to help victims of financial cyber-fraud. I have "
            "handled such cases pro bono for three years already."
        ),
        skills="Legal, Hindi, Marathi",
        languages="Hindi,English,Marathi",
        availability_hours_per_week=8,
        consent_bgcheck=True,
        consent_pii=True,
        consent_safeguarding=True,
    )
    base.update(overrides)
    return base


# ─── WarriorApplicationCreate ────────────────────────────────────────────

class TestWarriorApplicationCreate:
    @pytest.mark.unit
    def test_valid_adult_payload_passes(self):
        app = WarriorApplicationCreate(**_valid_payload())
        assert app.full_name == "Priya Sharma"
        assert app.consent_bgcheck is True

    # ── Age gate ─────────────────────────────────────────────────────────
    @pytest.mark.unit
    @pytest.mark.security
    def test_minor_dob_is_rejected(self):
        with pytest.raises(ValidationError, match="at least"):
            WarriorApplicationCreate(**_valid_payload(date_of_birth=_minor_dob()))

    @pytest.mark.unit
    @pytest.mark.security
    def test_17_year_old_is_rejected(self):
        today = date.today()
        dob = date(today.year - 17, today.month, today.day)
        with pytest.raises(ValidationError, match="at least"):
            WarriorApplicationCreate(**_valid_payload(date_of_birth=dob))

    @pytest.mark.unit
    def test_exact_18_year_old_is_accepted(self):
        today = date.today()
        dob = date(today.year - MIN_WARRIOR_AGE_YEARS, today.month, today.day)
        WarriorApplicationCreate(**_valid_payload(date_of_birth=dob))

    @pytest.mark.unit
    def test_future_dob_rejected(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(
                **_valid_payload(date_of_birth=date.today() + timedelta(days=1))
            )

    @pytest.mark.unit
    def test_absurdly_old_dob_rejected(self):
        with pytest.raises(ValidationError, match="implausible"):
            WarriorApplicationCreate(
                **_valid_payload(date_of_birth=date(1800, 1, 1))
            )

    # ── Consent ─────────────────────────────────────────────────────────
    @pytest.mark.unit
    @pytest.mark.security
    def test_missing_bgcheck_consent_rejected(self):
        with pytest.raises(ValidationError, match="consent_bgcheck"):
            WarriorApplicationCreate(**_valid_payload(consent_bgcheck=False))

    @pytest.mark.unit
    @pytest.mark.security
    def test_missing_pii_consent_rejected(self):
        with pytest.raises(ValidationError, match="consent_pii"):
            WarriorApplicationCreate(**_valid_payload(consent_pii=False))

    @pytest.mark.unit
    @pytest.mark.security
    def test_missing_safeguarding_consent_rejected(self):
        with pytest.raises(ValidationError, match="consent_safeguarding"):
            WarriorApplicationCreate(**_valid_payload(consent_safeguarding=False))

    # ── Role self-escalation ─────────────────────────────────────────────
    @pytest.mark.unit
    @pytest.mark.security
    def test_cannot_request_admin_role(self):
        with pytest.raises(ValidationError, match="preferred_role"):
            WarriorApplicationCreate(
                **_valid_payload(preferred_role=WarriorRole.admin)
            )

    @pytest.mark.unit
    @pytest.mark.security
    def test_cannot_request_mentor_role(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(
                **_valid_payload(preferred_role=WarriorRole.mentor)
            )

    @pytest.mark.unit
    @pytest.mark.security
    def test_cannot_request_moderator_role(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(
                **_valid_payload(preferred_role=WarriorRole.moderator)
            )

    # ── Content constraints ─────────────────────────────────────────────
    @pytest.mark.unit
    def test_motivation_too_short_rejected(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(**_valid_payload(motivation="short"))

    @pytest.mark.unit
    def test_name_too_short_rejected(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(**_valid_payload(full_name="A"))

    @pytest.mark.unit
    def test_invalid_email_rejected(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(**_valid_payload(email="not-an-email"))

    @pytest.mark.unit
    def test_availability_bounds(self):
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(
                **_valid_payload(availability_hours_per_week=200)
            )
        with pytest.raises(ValidationError):
            WarriorApplicationCreate(
                **_valid_payload(availability_hours_per_week=0)
            )


# ─── Approval schema ────────────────────────────────────────────────────

class TestApplicationApprove:
    @pytest.mark.unit
    def test_trainee_assignment_ok(self):
        ApplicationApprove(assigned_role=WarriorRole.trainee)

    @pytest.mark.unit
    def test_verified_warrior_assignment_ok(self):
        ApplicationApprove(assigned_role=WarriorRole.verified_warrior)

    @pytest.mark.unit
    @pytest.mark.security
    def test_cannot_approve_direct_to_admin(self):
        with pytest.raises(ValidationError):
            ApplicationApprove(assigned_role=WarriorRole.admin)

    @pytest.mark.unit
    @pytest.mark.security
    def test_cannot_approve_direct_to_mentor(self):
        with pytest.raises(ValidationError):
            ApplicationApprove(assigned_role=WarriorRole.mentor)


# ─── Rejection schema ───────────────────────────────────────────────────

class TestApplicationReject:
    @pytest.mark.unit
    def test_reason_required(self):
        with pytest.raises(ValidationError):
            ApplicationReject()

    @pytest.mark.unit
    def test_short_reason_rejected(self):
        with pytest.raises(ValidationError):
            ApplicationReject(reviewer_notes="no")

    @pytest.mark.unit
    def test_valid_reason_ok(self):
        r = ApplicationReject(reviewer_notes="Insufficient volunteer experience")
        assert r.reviewer_notes.startswith("Insufficient")
