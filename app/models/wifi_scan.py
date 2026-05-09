import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class WifiScan(Base):
    __tablename__ = "wifi_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    ssid: Mapped[str | None] = mapped_column(String(255), nullable=True)
    bssid: Mapped[str | None] = mapped_column(String(50), nullable=True)
    signal_strength: Mapped[int | None] = mapped_column(Integer, nullable=True)
    encryption_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_open: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    risk_reasons: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
