import uuid
import enum
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Float, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class BehaviorEventType(str, enum.Enum):
    clicked_unknown_link = "clicked_unknown_link"
    installed_suspicious_app = "installed_suspicious_app"
    shared_otp = "shared_otp"
    connected_open_wifi = "connected_open_wifi"
    received_scam_call = "received_scam_call"
    submitted_form_on_suspicious_site = "submitted_form_on_suspicious_site"
    opened_scam_message = "opened_scam_message"
    granted_excessive_permissions = "granted_excessive_permissions"
    disabled_security_feature = "disabled_security_feature"


class BehaviorEvent(Base):
    __tablename__ = "behavior_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    event_type: Mapped[BehaviorEventType] = mapped_column(SAEnum(BehaviorEventType), nullable=False)
    risk_contribution: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra_data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
