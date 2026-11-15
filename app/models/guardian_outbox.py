"""Durable guardian-alert outbox and its delivery audit.

An alert is a row here BEFORE anything is sent, so a crash, a restart or a provider outage never loses it (the previous design
only used FastAPI background tasks). Delivery is AT-LEAST-ONCE with per-channel bookkeeping; it is not, and cannot be,
exactly-once against an external SMS/e-mail provider: a crash between the provider accepting a message and the database
recording it can send that channel once more on retry.

Independent of the history record: deleting or failing to sync an install event does not change an alert's state and the other
way round (``event_id`` is a nullable link that is cleared, not cascaded, when an event is deleted).

Statuses: pending -> leased -> sent | skipped | expired | failed, or back to pending for a retry.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

PENDING = "pending"
LEASED = "leased"
SENT = "sent"
SKIPPED = "skipped"
EXPIRED = "expired"
FAILED = "failed"


class GuardianAlertOutbox(Base):
    __tablename__ = "guardian_alert_outbox"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "dedupe_key", name="uq_guardian_outbox_user_dedupe"
        ),
        Index("ix_guardian_outbox_due", "status", "next_attempt_at"),
        # ON DELETE SET NULL on event_id and the per-event status lookup both search by event_id
        Index("ix_guardian_outbox_event_id", "event_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_install_events.id", ondelete="SET NULL"),
        nullable=True,
    )
    # One alert per logical event: "evt:<server event id>" for synced events, "legacy:<hash>" (package + app + hour) for
    # the legacy /elderly/guardian-alert endpoint. The recipient is NOT part of the key: it is the user's current verified
    # guardian at delivery time.
    dedupe_key: Mapped[str] = mapped_column(String(80), nullable=False)
    # What the message needs (app name, risk, tags, clone verdict, when it happened). No guardian contact data: the contact is
    # read from the user's CURRENT elderly config at delivery time, so a disabled or changed config is respected.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default=PENDING)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    lease_token: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # {"sms": true, "email": false}: a retry only re-sends channels that have not succeeded yet.
    channels_done: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )


class GuardianAlertDelivery(Base):
    """Audit of every send attempt per channel. Holds no contact details and no message text."""

    __tablename__ = "guardian_alert_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    outbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_alert_outbox.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    channel: Mapped[str] = mapped_column(String(8), nullable=False)  # sms | email
    result: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # ok | failed | error
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
