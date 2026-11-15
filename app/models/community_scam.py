import uuid
import enum
from datetime import datetime
from sqlalchemy import (
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    text,
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class ScamType(str, enum.Enum):
    phishing_link = "phishing_link"
    fake_job = "fake_job"
    lottery_fraud = "lottery_fraud"
    investment_scam = "investment_scam"
    bank_fraud = "bank_fraud"
    otp_fraud = "otp_fraud"
    romance_scam = "romance_scam"
    tech_support_scam = "tech_support_scam"
    parcel_scam = "parcel_scam"
    other = "other"


class CommunityScamReport(Base):
    __tablename__ = "community_scam_reports"
    __table_args__ = (
        # Names and ordering exactly as created by revision f1a2b3c4d5e6 (raw SQL).
        Index("ix_community_scam_user_id", "user_id"),
        Index("ix_community_scam_city", "city"),
        Index("ix_community_scam_pincode", "pincode"),
        Index("ix_community_scam_created_at", text("created_at DESC")),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    scam_type: Mapped[ScamType] = mapped_column(SAEnum(ScamType), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    pincode: Mapped[str | None] = mapped_column(String(10), nullable=True)
    upvotes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra_data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
