import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class ElderlyConfig(Base):
    """
    Per-user elderly / guardian protection settings.
    One row per user — upsert on every update.
    The device syncs this config at startup and after any change.
    """

    __tablename__ = "elderly_configs"
    __table_args__ = (
        # The database has BOTH a UNIQUE constraint on user_id (elderly_configs_user_id_key) and this plain index (revision
        # k6l7m8n9o0p1). The index is redundant but harmless; it is declared so the models match the database. Dropping it
        # would be a separate, optional migration (and this line would go with it).
        Index("ix_elderly_configs_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=False
    )

    # ── Master toggle ────────────────────────────────────────────────────────
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Guardian contact ─────────────────────────────────────────────────────
    guardian_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    guardian_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    guardian_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ── Guardian authorisation and verification (a guardian is a THIRD PARTY who receives alerts about the user) ─────────
    # The user attests that the guardian agrees to be alerted and has seen the disclosure (versioned); the guardian then proves
    # control of each channel with a code. Alerts go only to VERIFIED channels whose value still equals the verified value, so
    # changing a contact silently withdraws its verification.
    guardian_authorised_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    guardian_notice_version: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    guardian_email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    guardian_email_verified_value: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    guardian_phone_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    guardian_phone_verified_value: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )

    @property
    def guardian_authorised(self) -> bool:
        from app.services.guardian_alerts import is_authorised

        return is_authorised(self)

    @property
    def guardian_email_verified(self) -> bool:
        from app.services.guardian_alerts import email_verified

        return email_verified(self)

    @property
    def guardian_phone_verified(self) -> bool:
        from app.services.guardian_alerts import phone_verified

        return phone_verified(self)

    # ── Protection policies ──────────────────────────────────────────────────
    block_risky_installs: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    alert_threshold: Mapped[int] = mapped_column(
        Integer, default=40, nullable=False
    )  # min risk_score to alert
    auto_alert_guardian: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    require_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # show approval dialog

    # ── UI preferences ───────────────────────────────────────────────────────
    simplified_ui: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    large_text: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── Timestamps ───────────────────────────────────────────────────────────
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
