"""PostgreSQL-backed integration-test harness.

Safety model (fail-closed):
  1. Integration tests run ONLY when ``TEST_DATABASE_URL`` is set. Otherwise
     they are skipped (never silently pointed at a default database).
  2. The URL must pass ``assert_safe_test_database``: loopback host (or the
     explicit CI allow-list) AND a database name ending in ``_test``.
     Anything else raises immediately — no connection is attempted.
  3. The app's own ``settings.DATABASE_URL`` must equal that URL, proving the
     process is not bound to some other database.
  4. ``app.database.AsyncSessionLocal`` is repointed at the test engine so
     code paths that open their own sessions (error logger, middleware) can
     not reach any other database either.

Isolation: tables are TRUNCATEd before every test (the guard above is what
makes that safe). Each test gets a NullPool engine created inside its own
event loop, avoiding asyncpg "attached to a different loop" errors.
"""

from __future__ import annotations

import os
import uuid
from datetime import date, datetime, timedelta
from typing import AsyncIterator, Callable

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
_EXTRA_HOSTS_ENV = "TEST_DATABASE_ALLOWED_HOSTS"  # comma list, e.g. CI service name


class UnsafeTestDatabaseError(RuntimeError):
    """Raised when TEST_DATABASE_URL is not clearly a disposable test DB."""


def assert_safe_test_database(url: str) -> None:
    """Fail closed unless ``url`` is explicitly a local, `_test`-suffixed DB."""
    try:
        parsed = make_url(url)
    except Exception as exc:  # noqa: BLE001
        raise UnsafeTestDatabaseError("TEST_DATABASE_URL is not a valid URL") from exc

    host = (parsed.host or "").lower()
    allowed = set(_ALLOWED_HOSTS)
    extra = os.environ.get(_EXTRA_HOSTS_ENV, "")
    allowed |= {h.strip().lower() for h in extra.split(",") if h.strip()}

    if host not in allowed:
        raise UnsafeTestDatabaseError(
            f"Refusing to run integration tests: DB host '{host}' is not in "
            f"the allow-list {sorted(allowed)}."
        )
    if "azure" in host or "windows.net" in host or "rds.amazonaws" in host:
        raise UnsafeTestDatabaseError("Refusing: host looks like a managed cloud DB.")

    dbname = parsed.database or ""
    if not dbname.endswith("_test"):
        raise UnsafeTestDatabaseError(
            f"Refusing to run integration tests: database '{dbname}' must end "
            "with '_test'."
        )


def _test_url() -> str | None:
    value = os.environ.get("TEST_DATABASE_URL", "").strip()
    return value or None


# ---------------------------------------------------------------------------
# Collection-time gating
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(config, items):
    if _test_url():
        return
    skip = pytest.mark.skip(
        reason="TEST_DATABASE_URL not set — PostgreSQL integration tests skipped"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# Session-scoped: validate URL, migrate schema once
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_database_url() -> str:
    url = _test_url()
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    assert_safe_test_database(url)

    from app.config import settings

    # The app process itself must be bound to this exact database.
    assert settings.DATABASE_URL == url, (
        "settings.DATABASE_URL differs from TEST_DATABASE_URL — refusing to run"
    )
    assert settings.MIGRATOR_DATABASE_URL == url
    return url


@pytest.fixture(scope="session")
def migrated_database(test_database_url: str) -> str:
    """Run ``alembic upgrade head`` against the validated test DB (sync, once)."""
    from alembic import command
    from alembic.config import Config

    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    command.upgrade(cfg, "head")
    return test_database_url


# ---------------------------------------------------------------------------
# Function-scoped: engine, session factory, cleanup, client
# ---------------------------------------------------------------------------

_TRUNCATE_SQL = (
    "TRUNCATE TABLE warrior_audit_logs, warrior_profiles, warrior_applications, "
    "otps, error_logs, users RESTART IDENTITY CASCADE"
)


@pytest_asyncio.fixture
async def db_engine(migrated_database: str, monkeypatch) -> AsyncIterator:
    engine = create_async_engine(migrated_database, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Repoint every code path that opens its own session (error logger, etc.)
    import app.database as app_db

    monkeypatch.setattr(app_db, "engine", engine)
    monkeypatch.setattr(app_db, "AsyncSessionLocal", factory)

    async with engine.begin() as conn:
        await conn.execute(text(_TRUNCATE_SQL))
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(db_engine) -> async_sessionmaker:
    return async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def db(session_factory) -> AsyncIterator[AsyncSession]:
    """A session for arranging / asserting state directly."""
    async with session_factory() as session:
        yield session


@pytest.fixture(autouse=True)
def _no_alert_emails(monkeypatch):
    """The error logger emails alerts; never attempt SMTP from tests."""
    import app.services.logger_service as ls

    monkeypatch.setattr(ls, "_send_email_sync", lambda *a, **k: None)
    yield


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    from app.middleware.rate_limiter import rate_limiter

    hits = getattr(rate_limiter, "_hits", None)
    if hits is not None:
        hits.clear()
    yield


@pytest_asyncio.fixture
async def client(session_factory) -> AsyncIterator[httpx.AsyncClient]:
    """ASGI client. ``ASGITransport`` does not run lifespan/startup events, so
    nothing contacts Twilio, Google Safe Browsing or any external service."""
    from app.database import get_db
    from app.main import app

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture
async def lenient_client(session_factory) -> AsyncIterator[httpx.AsyncClient]:
    """Like ``client`` but unhandled server errors surface as HTTP 500
    responses instead of re-raising — for failure/rollback tests."""
    from app.database import get_db
    from app.main import app

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Data + auth helpers
# ---------------------------------------------------------------------------

def adult_dob(years: int = 30) -> date:
    return date.today() - timedelta(days=365 * years + years // 4 + 2)


def minor_dob(years: int = 12) -> date:
    return date.today() - timedelta(days=365 * years)


def application_payload(**overrides) -> dict:
    payload = {
        "full_name": "Priya Sharma",
        "date_of_birth": adult_dob().isoformat(),
        "phone": "+919876543210",
        "email": "priya.volunteer@example.com",
        "city": "Mumbai",
        "state": "Maharashtra",
        "preferred_role": "trainee",
        "motivation": (
            "I have supported victims of UPI and KYC fraud for three years "
            "and want to help more people recover safely."
        ),
        "skills": "Legal basics, Hindi, Marathi",
        "languages": "Hindi,English,Marathi",
        "availability_hours_per_week": 8,
        "consent_bgcheck": True,
        "consent_pii": True,
        "consent_safeguarding": True,
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def make_user(session_factory) -> Callable:
    """Create a persisted ``User`` (unique email/phone per call)."""

    async def _make(label: str = "user", **fields):
        from app.models.user import User

        n = uuid.uuid4().hex[:8]
        user = User(
            email=fields.pop("email", f"{label}.{n}@example.com"),
            phone=fields.pop("phone", f"+9199{int(n, 16) % 10**8:08d}"),
            full_name=fields.pop("full_name", f"{label.title()} {n}"),
            is_active=fields.pop("is_active", True),
            **fields,
        )
        async with session_factory() as s:
            s.add(user)
            await s.commit()
            await s.refresh(user)
        return user

    return _make


@pytest.fixture
def auth_headers() -> Callable:
    """Bearer headers for ``user`` using the app's own token factory."""

    def _headers(user) -> dict:
        from app.routers.auth import create_token

        token = create_token(
            {"sub": str(user.id), "type": "access"}, timedelta(minutes=15)
        )
        return {"Authorization": f"Bearer {token}"}

    return _headers


@pytest.fixture
def make_warrior(session_factory) -> Callable:
    """Give ``user`` an (optionally inactive) WarriorProfile with ``role``."""

    async def _make(user, role="trainee", is_active: bool = True):
        from app.models.cyber_warrior import WarriorProfile, WarriorRole

        profile = WarriorProfile(
            user_id=user.id,
            role=WarriorRole(role),
            is_active=is_active,
            display_name=user.full_name or "Warrior",
            date_of_birth=adult_dob(),
        )
        async with session_factory() as s:
            s.add(profile)
            await s.commit()
            await s.refresh(profile)
        return profile

    return _make
