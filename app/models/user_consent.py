"""Append-only record of what a user agreed to, for which purpose, under which notice version and when.

One row per decision. The CURRENT state of a purpose is its newest row; withdrawing an optional consent adds a new row with
``granted = false`` (the history is kept, nothing is edited). Rows are erased with the account (see account_erasure.py).
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UserConsent(Base):
    __tablename__ = "user_consents"
    __table_args__ = (Index("ix_user_consents_user_purpose", "user_id", "purpose"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # where the decision was taken: register | google | settings | update
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
