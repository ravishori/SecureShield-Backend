import uuid
import enum
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer, BigInteger
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class EventType(str, enum.Enum):
    installed = "installed"
    updated   = "updated"
    removed   = "removed"


class InstallRiskLevel(str, enum.Enum):
    safe    = "safe"
    warning = "warning"
    danger  = "danger"


class AppInstallEvent(Base):
    """
    Every app install / update / removal observed on a user's device.
    Written offline-first by the Flutter layer and synced to the backend.
    Risk scores are computed locally (Kotlin) and refined server-side.
    """
    __tablename__ = "app_install_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # ── App identity ────────────────────────────────────────────────────────
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    app_name:     Mapped[str] = mapped_column(String(255), nullable=False)
    version_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_type:   Mapped[str] = mapped_column(String(20), nullable=False, default="installed")  # EventType value

    # ── Install provenance ──────────────────────────────────────────────────
    installer_package:  Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_unknown_source:  Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_system_app:      Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Permissions ─────────────────────────────────────────────────────────
    dangerous_perms: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    perm_count:      Mapped[int]  = mapped_column(Integer, default=0, nullable=False)

    # ── Risk scores (local Kotlin preliminary + server refined) ─────────────
    local_risk_score:  Mapped[int] = mapped_column(Integer, default=0, nullable=False)   # Kotlin preliminary
    server_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)   # server refined
    risk_level:        Mapped[str] = mapped_column(String(10), default="safe", nullable=False)
    risk_tags:         Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # ── Clone detection ─────────────────────────────────────────────────────
    clone_probability: Mapped[int]  = mapped_column(Integer, default=0, nullable=False)  # 0-100
    flagged_as_clone:  Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    clone_target_pkg:  Mapped[str | None] = mapped_column(String(255), nullable=True)   # which legit app it fakes

    # ── Behaviour signals ───────────────────────────────────────────────────
    has_overlay:         Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    has_accessibility:   Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Timestamps ──────────────────────────────────────────────────────────
    first_install_time: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    synced_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    created_at:  Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
