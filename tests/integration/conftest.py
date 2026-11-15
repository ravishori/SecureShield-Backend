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

    # Effective identity, not just the host text: connection-routing query parameters (?host=, ?port=, ?database= ...), lookalike
    # or non-ASCII hosts, an empty database and the driver's real connect arguments are all checked (app.db_identity).
    from app.db_identity import (
        DatabaseIdentityError,
        load_production_database_names,
        load_registry,
        parse_endpoint,
    )

    try:
        endpoint = parse_endpoint(url)
        registry = load_registry(os.environ.get("PRODUCTION_DATABASE_ENDPOINTS", ""))
        production_names = load_production_database_names(
            os.environ.get("PRODUCTION_DATABASE_NAMES", "")
        )
    except DatabaseIdentityError as exc:
        raise UnsafeTestDatabaseError(
            f"Refusing: TEST_DATABASE_URL identity check failed: {exc}"
        ) from None
    if (
        endpoint.endpoint_id in registry
        or endpoint.database.lower() in production_names
    ):
        raise UnsafeTestDatabaseError(
            "Refusing: TEST_DATABASE_URL names a production endpoint or production database name."
        )

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

    from app.db_identity import validate_identity

    validate_identity(
        settings
    )  # ENVIRONMENT=test / DATABASE_ENVIRONMENT=test, loopback, same endpoint for both roles
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

# Every application table is emptied between tests (a fixed list missed tables without an
# FK to users, e.g. app_scans/wifi_scans, which leaked rows across tests). Alembic's version
# table and the static reference tables are kept.
_KEEP_TABLES = ("alembic_version", "tsp_codes", "lsa_codes", "sms_sender_registry")


async def _truncate_all(conn) -> None:
    rows = await conn.execute(
        text("select tablename from pg_tables where schemaname = 'public'")
    )
    tables = [r[0] for r in rows if r[0] not in _KEEP_TABLES]
    if tables:
        quoted = ", ".join(f'"{t}"' for t in tables)
        await conn.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def db_engine(migrated_database: str, monkeypatch) -> AsyncIterator:
    # A URL without a port must not be redirected by PGPORT in the environment: pin the port like app.database does.
    connect_args = {} if make_url(migrated_database).port else {"port": 5432}
    engine = create_async_engine(
        migrated_database, poolclass=NullPool, connect_args=connect_args
    )
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Repoint every code path that opens its own session (error logger, etc.)
    import app.database as app_db

    monkeypatch.setattr(app_db, "engine", engine)
    monkeypatch.setattr(app_db, "AsyncSessionLocal", factory)

    # Read-only: the server we reached must be the configured *_test database (never a tunnel to something else).
    from app.config import settings as app_settings
    from app.db_identity import verify_connected_database

    await verify_connected_database(app_settings, engine)

    async with engine.begin() as conn:
        await _truncate_all(conn)
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

        from datetime import datetime

        n = uuid.uuid4().hex[:8]
        now = datetime.utcnow()
        # Default: both identifiers VERIFIED (a normal, fully onboarded account). Pass ``email_verified_at=None`` /
        # ``phone_verified_at=None`` to build legacy or unverified-claim rows.
        user = User(
            email=fields.pop("email", f"{label}.{n}@example.com"),
            phone=fields.pop("phone", f"+9199{int(n, 16) % 10**8:08d}"),
            full_name=fields.pop("full_name", f"{label.title()} {n}"),
            is_active=fields.pop("is_active", True),
            email_verified_at=fields.pop("email_verified_at", now),
            phone_verified_at=fields.pop("phone_verified_at", now),
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


CONSENT_BODY = {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"}


async def delete_body(headers: dict, confirm: str = "DELETE") -> dict:
    """Request body for ``DELETE /auth/me``: the literal confirmation plus a fresh re-authentication code for the caller
    (issued straight into the test database; no delivery is involved)."""
    import jwt

    from app.database import AsyncSessionLocal
    from app.models.user import User
    from app.services import identity as idn

    token = headers["Authorization"].split()[1]
    uid = uuid.UUID(jwt.decode(token, options={"verify_signature": False})["sub"])
    async with AsyncSessionLocal() as s:
        user = await s.get(User, uid)
        channel = idn.reauth_channel(user) if user is not None else None
        if (
            channel is None
        ):  # an already-erased account: the request is meant to be refused anyway
            return {"confirm": confirm, "code": "000000"}
        kind, identifier = channel
        code = await idn.issue_challenge(
            s,
            kind=kind,
            identifier=identifier,
            purpose=idn.DELETE_ACCOUNT,
            user_id=user.id,
        )
        await s.commit()
    return {"confirm": confirm, "code": code}


def verified_guardian_fields(email=None, phone=None) -> dict:
    """ElderlyConfig columns for a guardian who was authorised by the account holder and verified on each given channel."""
    now = datetime.utcnow()
    out = {"guardian_authorised_at": now, "guardian_notice_version": "2026-11-14"}
    if email:
        out.update(
            guardian_email_verified_at=now, guardian_email_verified_value=email.lower()
        )
    if phone:
        out.update(guardian_phone_verified_at=now, guardian_phone_verified_value=phone)
    return out


async def ready_guardian(client, headers: dict, **cfg) -> dict:
    """Configure elderly protection the way the app does AND complete the guardian authorisation + verification
    (the verification code exchange itself is tested in test_guardian_authorisation_api.py)."""
    import jwt
    from sqlalchemy import update

    from app.database import AsyncSessionLocal
    from app.models.elderly_config import ElderlyConfig

    body = {"enabled": True, "alert_threshold": 30, **cfg}
    has_contact = bool(body.get("guardian_email") or body.get("guardian_phone"))
    if has_contact:
        body.update(guardian_authorised=True, guardian_notice_version="2026-11-14")
    r = await client.put("/api/v1/elderly/config", headers=headers, json=body)
    assert r.status_code == 200, r.text
    if has_contact:
        uid = uuid.UUID(
            jwt.decode(
                headers["Authorization"].split()[1], options={"verify_signature": False}
            )["sub"]
        )
        saved = r.json()
        async with AsyncSessionLocal() as s:
            await s.execute(
                update(ElderlyConfig)
                .where(ElderlyConfig.user_id == uid)
                .values(
                    **verified_guardian_fields(
                        saved["guardian_email"], saved["guardian_phone"]
                    )
                )
            )
            await s.commit()
    return r.json()


# ---------------------------------------------------------------------------
# Guardian alert outbox: enqueueing (HTTP 202) is tested separately from delivery (the worker)
# ---------------------------------------------------------------------------


@pytest.fixture
def quiet_worker(monkeypatch):
    """The request path must only ENQUEUE. ``run_once_safe`` is the best-effort immediate attempt scheduled after a request; it is
    disabled here (it also does nothing outside production unless GUARDIAN_WORKER_ENABLED is set), so a test never depends on it.
    Delivery is exercised explicitly with ``drain_guardian_outbox`` and mocked SMS/e-mail providers: no real message is sent."""
    from app.services import guardian_outbox

    async def _noop():
        return None

    monkeypatch.setattr(guardian_outbox, "run_once_safe", _noop)


async def drain_guardian_outbox(limit: int = 10) -> dict:
    """Run the delivery worker once, in its own session, against the (harness-repointed) test database."""
    import app.database as app_db
    from app.services import guardian_outbox

    async with app_db.AsyncSessionLocal() as session:
        return await guardian_outbox.run_once(session, limit=limit)


async def outbox_rows() -> list:
    """Every guardian outbox row (status, user id), for asserting what the request path queued."""
    import app.database as app_db
    from sqlalchemy import select

    from app.models.guardian_outbox import GuardianAlertOutbox

    async with app_db.AsyncSessionLocal() as session:
        rows = (await session.execute(select(GuardianAlertOutbox))).scalars().all()
        return [(r.status, r.user_id) for r in rows]
