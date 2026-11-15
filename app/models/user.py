import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum


class SubscriptionTier(str, enum.Enum):
    free = "free"
    premium = "premium"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Both phone and email are nullable — user must have at least one (enforced in app layer)
    phone: Mapped[str | None] = mapped_column(
        String(20), unique=True, nullable=True, index=True
    )
    email: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    # An identifier may authenticate this account ONLY while its *_verified_at is set. Historical rows keep NULL here (they were
    # never proven); they are verified by a successful code to that single identifier (see app.services.identity).
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Google's stable account id (``sub`` claim). Binding by subject, never by e-mail, so an e-mail change cannot move the link.
    google_sub: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True, index=True
    )
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    subscription_tier: Mapped[SubscriptionTier] = mapped_column(
        SAEnum(SubscriptionTier), default=SubscriptionTier.free, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    senior_mode: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Extended profile fields (added for profile completeness feature)
    first_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    alt_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Address fields
    flat_no: Mapped[str | None] = mapped_column(String(50), nullable=True)
    building: Mapped[str | None] = mapped_column(String(255), nullable=True)
    street: Mapped[str | None] = mapped_column(String(255), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country: Mapped[str | None] = mapped_column(
        String(100), nullable=True, default="India"
    )
    pin_code: Mapped[str | None] = mapped_column(String(10), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @property
    def email_verified(self) -> bool:
        return bool(self.email and self.email_verified_at)

    @property
    def phone_verified(self) -> bool:
        return bool(self.phone and self.phone_verified_at)

    @property
    def identifier(self) -> str:
        """Primary identifier used for login — phone takes priority over email."""
        return self.phone or self.email or ""


class OTP(Base):
    __tablename__ = "otps"
    __table_args__ = (
        # New-style challenges are bound to exactly ONE identifier; legacy rows (identifier IS NULL) are left alone and ignored.
        CheckConstraint(
            "identifier IS NULL OR (purpose IS NOT NULL AND ("
            "(identifier_type = 'email' AND email = identifier AND phone IS NULL) OR "
            "(identifier_type = 'phone' AND phone = identifier AND email IS NULL)))",
            name="ck_otps_single_identifier",
        ),
        Index("ix_otps_challenge", "identifier_type", "identifier", "purpose"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # One of phone/email must be set — enforced in application layer
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    code: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # HMAC of the code, never plaintext
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Wrong guesses against THIS code; the code is burned after OTP_MAX_ATTEMPTS (app.services.otp_codes).
    attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )
    # Challenge binding (NULL on legacy rows, which the new code never accepts): ONE identifier, ONE channel, ONE purpose.
    identifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    identifier_type: Mapped[str | None] = mapped_column(String(8), nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(32), nullable=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    pending_registration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pending_registrations.id", ondelete="CASCADE"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
