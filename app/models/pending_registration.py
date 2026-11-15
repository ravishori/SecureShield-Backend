"""A registration that has NOT been verified yet.

Unverified identifiers never live on ``users``: registration parks the profile here, the e-mail code is sent to the e-mail
address only, and the ``users`` row is created when that code is verified. ``phone`` is only a hint for the next step (the
phone is attached to the account after its own, separate verification). Rows expire and are purged opportunistically.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PendingRegistration(Base):
    __tablename__ = "pending_registrations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    flat_no: Mapped[str | None] = mapped_column(String(50), nullable=True)
    building: Mapped[str | None] = mapped_column(String(255), nullable=True)
    street: Mapped[str | None] = mapped_column(String(255), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    pin_code: Mapped[str | None] = mapped_column(String(10), nullable=True)
    # Consent captured on the registration screen (NULL only on rows that predate the consent migration; such a row cannot
    # be verified and the user simply registers again). Copied to ``user_consents`` when the e-mail is verified.
    terms_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    privacy_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    consented_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ai_processing_consent: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
