import uuid
from datetime import datetime, date
from sqlalchemy import String, DateTime, ForeignKey, Float, Integer, Date
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    report_date: Mapped[date] = mapped_column(Date, nullable=False)
    threats_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    apps_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    links_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    calls_analyzed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    top_threats: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
