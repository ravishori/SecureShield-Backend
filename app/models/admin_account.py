import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

ADMIN_ROLES = ("support", "admin", "superadmin")


class AdminAccount(Base):
    """An individually identified operator of the admin API (distinct from end-user ``users``).

    Roles: ``support`` (read-only), ``admin`` (+ disable/enable end users), ``superadmin`` (+ manage admin accounts).
    The password is a salted scrypt hash; the TOTP secret is stored encrypted; recovery codes are stored only as
    keyed hashes and each works once. Nothing here is ever returned by an API.
    """

    __tablename__ = "admin_accounts"
    __table_args__ = (
        CheckConstraint(
            "role in ('support','admin','superadmin')", name="ck_admin_accounts_role"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="support")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    recovery_hashes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AdminSession(Base):
    """One login of an admin account. The access token carries the session id; revoking the row (or deactivating
    the account) invalidates the token immediately, long before it would expire."""

    __tablename__ = "admin_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    admin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # "full" = MFA-verified and usable everywhere; "setup" = may only change the password / enrol MFA.
    scope: Mapped[str] = mapped_column(String(10), nullable=False, default="full")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(200), nullable=True)
