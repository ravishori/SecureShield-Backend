from sqlalchemy import String, Integer, Text, Index, text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class TspCode(Base):
    """TSP (Telecom Service Provider) code — the 'X' character in XY-HEADER SMS sender format."""

    __tablename__ = "tsp_codes"

    code: Mapped[str] = mapped_column(String(1), primary_key=True)
    provider_name: Mapped[str] = mapped_column(Text, nullable=False)


class LsaCode(Base):
    """LSA (License Service Area) code — the 'Y' character in XY-HEADER SMS sender format."""

    __tablename__ = "lsa_codes"

    code: Mapped[str] = mapped_column(String(1), primary_key=True)
    service_area: Mapped[str] = mapped_column(Text, nullable=False)


class SmsSenderRegistry(Base):
    """
    TRAI-registered SMS headers (Sender IDs) and their Principal Entity names.
    Source: TCCCPR 2018 — Access Provider submissions to TRAI.
    Data loaded from List_SMS_Headers_16062020_0.xlsx (23,192 rows).
    """

    __tablename__ = "sms_sender_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Header part only — e.g. 'SBIBNK' from 'VK-SBIBNK', or numeric like '8'
    header: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    principal_entity_name: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        # The only lookup (app/services/sms_header_validator.py) is `WHERE upper(header) = :x`. A plain index on `header` cannot
        # serve that expression, so this is an EXPRESSION index on upper(header). Created by revision y0z1a2b3c4d5, which issues
        # `upper(header)`. PostgreSQL stores it as `upper((header)::text)`; SQLAlchemy reflects it as `upper(header::text)`, and
        # Alembic's PostgreSQL comparison treats that as equal to `upper(header)` (verified by `alembic check`, Stage 1.5F).
        Index("ix_sms_sender_header_upper", text("upper(header)")),
    )
