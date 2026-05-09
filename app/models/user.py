import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum


class SubscriptionTier(str, enum.Enum):
    free = "free"
    premium = "premium"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Both phone and email are nullable — user must have at least one (enforced in app layer)
    phone: Mapped[str | None] = mapped_column(String(20), unique=True, nullable=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    subscription_tier: Mapped[SubscriptionTier] = mapped_column(
        SAEnum(SubscriptionTier), default=SubscriptionTier.free, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    senior_mode: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Extended profile fields (added for profile completeness feature)
    first_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_name:  Mapped[str | None] = mapped_column(String(100), nullable=True)
    alt_phone:  Mapped[str | None] = mapped_column(String(20),  nullable=True)

    # Address fields
    flat_no:   Mapped[str | None] = mapped_column(String(50),  nullable=True)
    building:  Mapped[str | None] = mapped_column(String(255), nullable=True)
    street:    Mapped[str | None] = mapped_column(String(255), nullable=True)
    city:      Mapped[str | None] = mapped_column(String(100), nullable=True)
    state:     Mapped[str | None] = mapped_column(String(100), nullable=True)
    country:   Mapped[str | None] = mapped_column(String(100), nullable=True, default="India")
    pin_code:  Mapped[str | None] = mapped_column(String(10),  nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def identifier(self) -> str:
        """Primary identifier used for login — phone takes priority over email."""
        return self.phone or self.email or ""


class OTP(Base):
    __tablename__ = "otps"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # One of phone/email must be set — enforced in application layer
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    code: Mapped[str] = mapped_column(String(10), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
