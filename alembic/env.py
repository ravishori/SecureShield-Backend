import asyncio
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

# this is the Alembic Config object
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all models so Alembic can detect them
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base

# Import every model so Alembic's autogenerate can see them. Models without
# a corresponding file are guarded by try/except so a missing module never
# breaks the migration runner.
from app.models.user import User, OTP  # noqa: F401
from app.models.device import Device  # noqa: F401
from app.models.app_scan import AppScan  # noqa: F401
from app.models.link_scan import LinkScan  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.scam_call import ScamCall  # noqa: F401
from app.models.evidence import Evidence  # noqa: F401
from app.models.family import FamilyMember  # noqa: F401
from app.models.security_report import SecurityReport  # noqa: F401
from app.models.wifi_scan import WifiScan  # noqa: F401
from app.models.ai_conversation import AiConversation  # noqa: F401
from app.models.network_activity import NetworkActivity  # noqa: F401
from app.models.error_log import ErrorLog  # noqa: F401
from app.models.recording import Recording  # noqa: F401
from app.models.sms_sender_registry import TspCode, LsaCode, SmsSenderRegistry  # noqa: F401
from app.models.app_install_event import AppInstallEvent  # noqa: F401
from app.models.clone_report import CloneReport  # noqa: F401
from app.models.elderly_config import ElderlyConfig  # noqa: F401
from app.models.emergency_contact import EmergencyContact  # noqa: F401

# Optional models — present only on some branches. Don't fail migrations if missing.
try:
    from app.models.otp_vault import OtpVaultEntry  # noqa: F401
except ModuleNotFoundError:
    pass
try:
    from app.models.community_scam import CommunityScamReport  # noqa: F401
except ModuleNotFoundError:
    pass
try:
    from app.models.behavior_event import BehaviorEvent  # noqa: F401
except ModuleNotFoundError:
    pass

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    # Prefer migrator URL from Settings; never rely on credentials in alembic.ini.
    from app.config import settings

    url = settings.MIGRATOR_DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    # Alembic must use secureshield_migrator (MIGRATOR_DATABASE_URL), never the app role.
    from app.config import settings
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = settings.MIGRATOR_DATABASE_URL

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
