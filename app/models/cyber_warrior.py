"""Cyber Warriors Network — data model.

The Warriors Network supports adult volunteers who assist victims of
cyber-crime through SecureShield. Minors can participate in supervised
awareness activities only (handled at the RBAC layer, not here).

Scope of this file (Phase 1B foundation slice):
  • WarriorApplication  — pending adult volunteer applications
  • WarriorProfile      — approved warriors with role + status
  • WarriorAuditLog     — append-only trail of every state change

Deliberately NOT in this file (follow-up slices):
  • AssistanceCase, CaseAssignment, CaseMessage — victim-interaction
    tables that require safeguarding, consent capture, and moderation
    controls to be built FIRST (see spec section 3).
  • WarriorCredential, TrainingCompletion — gated on admin approval
    workflow landing (CW-5).

Reuses:
  • User.id as the identity backbone — one User ⇄ at most one
    WarriorApplication (open) ⇄ at most one WarriorProfile.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, date

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


# ─── Enums ────────────────────────────────────────────────────────────────

class WarriorRole(str, enum.Enum):
    """Role tiers, ordered least → most privileged.

    `trainee` is assigned automatically on admin approval. Promotion to
    higher tiers is an explicit admin action with an audit trail entry.
    """
    trainee          = "trainee"
    verified_warrior = "verified_warrior"
    mentor           = "mentor"
    moderator        = "moderator"
    admin            = "admin"


# Explicit ordering used by the require_warrior_role dependency.
_ROLE_ORDER = {
    WarriorRole.trainee:          0,
    WarriorRole.verified_warrior: 1,
    WarriorRole.mentor:           2,
    WarriorRole.moderator:        3,
    WarriorRole.admin:            4,
}


def role_meets(current: WarriorRole, required: WarriorRole) -> bool:
    """Return True if `current` role satisfies `required` tier.

    Admins meet every requirement, moderators meet moderator+below, etc.
    Used by the RBAC guard — kept here next to the enum so there's exactly
    one source of truth for role ordering.
    """
    return _ROLE_ORDER[current] >= _ROLE_ORDER[required]


class ApplicationStatus(str, enum.Enum):
    pending  = "pending"
    approved = "approved"
    rejected = "rejected"
    withdrawn = "withdrawn"


class AuditAction(str, enum.Enum):
    application_submitted = "application_submitted"
    application_approved  = "application_approved"
    application_rejected  = "application_rejected"
    application_withdrawn = "application_withdrawn"
    role_promoted         = "role_promoted"
    role_demoted          = "role_demoted"
    profile_suspended     = "profile_suspended"
    profile_reactivated   = "profile_reactivated"


# ─── Tables ───────────────────────────────────────────────────────────────

class WarriorApplication(Base):
    """Adult volunteer application awaiting admin review.

    Safeguarding guard rails:
      • `date_of_birth` is required and validated at the schema layer to
        be ≥ 18 years. Minors cannot submit applications — the Flutter
        signup path refuses, the schema validator refuses, and this
        column is NOT NULL so a bypass of both is still rejected by the
        database.
      • One **open** application per user — enforced via a partial unique
        index on (`user_id`, `status`='pending') in the Alembic migration.
    """
    __tablename__ = "warrior_applications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Required personal data captured at application time (does not reuse
    # User fields, because User fields are user-editable and we need the
    # frozen snapshot the applicant actually submitted).
    full_name:    Mapped[str]  = mapped_column(String(255), nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date,         nullable=False)
    phone:        Mapped[str]  = mapped_column(String(20),   nullable=False)
    email:        Mapped[str]  = mapped_column(String(255),  nullable=False)
    city:         Mapped[str | None] = mapped_column(String(100), nullable=True)
    state:        Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Volunteer-specific intake
    preferred_role: Mapped[WarriorRole] = mapped_column(
        SAEnum(WarriorRole, name="warriorrole"),
        default=WarriorRole.trainee, nullable=False,
    )
    motivation:   Mapped[str]  = mapped_column(Text, nullable=False)
    skills:       Mapped[str | None] = mapped_column(Text, nullable=True)
    languages:    Mapped[str | None] = mapped_column(
        String(200), nullable=True
    )
    availability_hours_per_week: Mapped[int | None] = mapped_column(
        nullable=True
    )

    # Explicit consent — Play Store + privacy law requires affirmative opt-in
    consent_bgcheck: Mapped[bool] = mapped_column(
        Boolean, nullable=False
    )  # user permits background verification
    consent_pii:     Mapped[bool] = mapped_column(
        Boolean, nullable=False
    )  # user acknowledges PII will be processed
    consent_safeguarding: Mapped[bool] = mapped_column(
        Boolean, nullable=False
    )  # user accepts safeguarding + minor-protection code of conduct

    status: Mapped[ApplicationStatus] = mapped_column(
        SAEnum(ApplicationStatus, name="warriorapplicationstatus"),
        default=ApplicationStatus.pending, nullable=False, index=True,
    )
    reviewer_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True,
    )
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True,
    )


class WarriorProfile(Base):
    """Approved warrior — active record with role and status.

    Created automatically when an admin approves a WarriorApplication.
    Deactivating here (is_active=False) retires a warrior without
    deleting their audit history.
    """
    __tablename__ = "warrior_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("warrior_applications.id", ondelete="SET NULL"),
        nullable=True,
    )

    role: Mapped[WarriorRole] = mapped_column(
        SAEnum(WarriorRole, name="warriorrole"),
        default=WarriorRole.trainee, nullable=False, index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Snapshot carried from the approved application so profile stays
    # usable even if the admin later deletes the application row.
    display_name:  Mapped[str] = mapped_column(String(255), nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date,       nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow,
        onupdate=datetime.utcnow, nullable=False,
    )


class WarriorAuditLog(Base):
    """Append-only audit trail for every warrior state change.

    No UPDATE/DELETE should ever happen on this table — enforced at the
    DB level in a future migration (REVOKE UPDATE/DELETE from the app
    role). For now the discipline is in the application layer.
    """
    __tablename__ = "warrior_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True,
    )
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True,
    )
    action: Mapped[AuditAction] = mapped_column(
        SAEnum(AuditAction, name="warriorauditaction"),
        nullable=False, index=True,
    )

    # Structured extra context, e.g. {"from_role":"trainee","to_role":"mentor"}
    extra: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False,
    )

    __table_args__ = (
        # Fast lookup "all events for user X newest first"
        {"comment": "Append-only. Do not UPDATE or DELETE rows here."},
    )
