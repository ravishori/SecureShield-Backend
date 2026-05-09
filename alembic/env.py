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
from app.models.user import User, OTP
from app.models.device import Device
from app.models.app_scan import AppScan
from app.models.otp_vault import OtpVaultEntry
from app.models.link_scan import LinkScan
from app.models.alert import Alert
from app.models.scam_call import ScamCall
from app.models.evidence import Evidence
from app.models.family import FamilyMember
from app.models.security_report import SecurityReport
from app.models.wifi_scan import WifiScan
from app.models.ai_conversation import AiConversation
from app.models.network_activity import NetworkActivity
from app.models.error_log import ErrorLog  # noqa: F401  — keeps Alembic aware
from app.models.recording import Recording  # noqa: F401
from app.models.sms_sender_registry import TspCode, LsaCode, SmsSenderRegistry  # noqa: F401

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
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
    # Use async URL from environment for the engine
    from app.config import settings
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = settings.DATABASE_URL

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
