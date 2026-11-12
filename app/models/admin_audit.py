import uuid
from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AdminAuditLog(Base):
    """Append-only record of state-changing admin actions.

    Admin calls authenticate as a named admin account (``actor_admin_id``) or, during the migration period, with
    the shared ``X-Admin-Token`` (``actor_label = "legacy-token"``, no identity). The record holds who did what, to
    whom (no foreign keys: rows must outlive erased accounts), and from which address. Never store tokens, credentials or message bodies here.
    """

    __tablename__ = "admin_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Who did it: the named admin account, or ``legacy-token`` for the shared break-glass token (no identity).
    actor_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    actor_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )
