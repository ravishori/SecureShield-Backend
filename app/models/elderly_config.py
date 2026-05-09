import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer
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

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, nullable=False, index=True)

    # ── Master toggle ────────────────────────────────────────────────────────
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Guardian contact ─────────────────────────────────────────────────────
    guardian_name:  Mapped[str | None] = mapped_column(String(100),  nullable=True)
    guardian_phone: Mapped[str | None] = mapped_column(String(20),   nullable=True)
    guardian_email: Mapped[str | None] = mapped_column(String(255),  nullable=True)

    # ── Protection policies ──────────────────────────────────────────────────
    block_risky_installs:  Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)
    alert_threshold:       Mapped[int]  = mapped_column(Integer, default=40,    nullable=False)  # min risk_score to alert
    auto_alert_guardian:   Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)
    require_approval:      Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # show approval dialog

    # ── UI preferences ───────────────────────────────────────────────────────
    simplified_ui: Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)
    large_text:    Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)

    # ── Timestamps ───────────────────────────────────────────────────────────
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
