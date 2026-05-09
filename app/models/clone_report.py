import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class CloneReport(Base):
    """
    Result of running the clone-detection engine on a specific installed app.
    One-to-one with AppInstallEvent for suspicious apps; standalone for on-demand scans.
    """
    __tablename__ = "clone_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # ── Analysed app ─────────────────────────────────────────────────────────
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    app_name:     Mapped[str] = mapped_column(String(255), nullable=False)

    # ── Best matching legitimate app ─────────────────────────────────────────
    target_package: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_name:    Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ── Individual signal scores (0-100) ─────────────────────────────────────
    name_similarity:    Mapped[int]  = mapped_column(Integer, default=0, nullable=False)
    package_similarity: Mapped[int]  = mapped_column(Integer, default=0, nullable=False)
    icon_hash_match:    Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cert_hash_match:    Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    overall_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # safe / suspicious / likely_clone / confirmed_clone
    verdict:       Mapped[str] = mapped_column(String(20), default="safe", nullable=False)

    # ── Human-readable findings ───────────────────────────────────────────────
    signals: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # ── Response tracking ─────────────────────────────────────────────────────
    # none / warned / blocked / uninstall_prompted / reported
    action_taken:    Mapped[str | None] = mapped_column(String(50), nullable=True)
    user_confirmed:  Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # did user agree it's fake?

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
