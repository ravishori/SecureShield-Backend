from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase
from app.config import settings, split_asyncpg_options
from app.db_identity import validate_identity


def build_async_engine(url: str, **kwargs) -> AsyncEngine:
    """Create the async engine for ``url``.

    asyncpg integer options carried in the URL query (for example ``?statement_cache_size=0``, used with a
    PgBouncer-style pooler such as Neon's ``-pooler`` host) are passed to asyncpg as ints through ``connect_args``:
    a URL query value is a string and asyncpg would raise ``TypeError`` on it.

    hide_parameters: SQLAlchemy otherwise appends "[parameters: (...)]" to DB errors, which would put bound values
    (submitted OTP codes, emails, phone numbers) into exception text, tracebacks, error_logs rows and alert e-mails.
    """
    clean_url, connect_args = split_asyncpg_options(url)
    if connect_args:
        kwargs["connect_args"] = {**kwargs.get("connect_args", {}), **connect_args}
    if make_url(clean_url).port is None:
        # asyncpg takes a MISSING port from PGPORT in the process environment, which would silently redirect an already
        # validated target to another server on the same host. An explicit connect argument always wins over PGPORT.
        kwargs["connect_args"] = {"port": 5432, **kwargs.get("connect_args", {})}
    return create_async_engine(clean_url, hide_parameters=True, **kwargs)


# Refuse to build any engine for an endpoint that does not match the declared environment (no connection is made).
validate_identity(settings)
engine = build_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
