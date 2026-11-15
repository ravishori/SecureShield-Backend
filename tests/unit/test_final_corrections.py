"""Final Stage 1.1 corrections: the unit-test connection guard itself, migration-rehearsal environment propagation, CLI identity
checks and the integration-harness identity check. Nothing here can reach a database."""

import asyncio
import importlib.util
import socket
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import config
from app.db_identity import DatabaseIdentityError, validate_identity

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]
PROD_URL = "postgresql+asyncpg://u:SENTINEL-PW@ep-cool-silence-aohbh87f-pooler.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB"


# ---- the unit-test connection guard ----------------------------------------------------------------------------------------------------
class TestUnitConnectionGuard:
    def test_asyncpg_entry_points_fail_immediately_and_are_counted(
        self, _no_database_connections
    ):
        import asyncpg

        for call in (
            lambda: asyncpg.connect("postgresql://u:p@localhost/x"),
            lambda: asyncpg.create_pool("postgresql://u:p@localhost/x"),
        ):
            with pytest.raises(AssertionError, match="unit tests must not connect"):
                asyncio.run(call())
        assert len(_no_database_connections) == 2
        _no_database_connections.clear()  # (an uncleared attempt would fail this very test at teardown, which is the point)

    def test_the_production_verification_helper_is_blocked(
        self, _no_database_connections
    ):
        from app.db_identity import verify_connected_database

        with pytest.raises(AssertionError):
            asyncio.run(verify_connected_database(SimpleNamespace(), object()))
        assert len(_no_database_connections) == 1
        _no_database_connections.clear()

    def test_sockets_and_event_loops_to_postgres_ports_are_blocked(
        self, _no_database_connections
    ):
        for port in (5432, 5433, 6543):
            with pytest.raises(AssertionError):
                socket.socket().connect(("127.0.0.1", port))
            with pytest.raises(AssertionError):
                socket.socket().connect_ex(("127.0.0.1", port))

        async def via_loop():
            loop = asyncio.get_running_loop()
            await loop.create_connection(asyncio.Protocol, "127.0.0.1", 5432)

        with pytest.raises(AssertionError):
            asyncio.run(via_loop())
        assert len(_no_database_connections) == 7
        _no_database_connections.clear()

    def test_sqlalchemy_engines_cannot_connect_either(self, _no_database_connections):
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(
            "postgresql+asyncpg://u:p@localhost:5432/secureshield_test"
        )

        async def go():
            async with engine.connect():
                pass

        with pytest.raises(Exception):  # noqa: B017 - SQLAlchemy may wrap the error; the attempt count is what matters
            asyncio.run(go())
        assert _no_database_connections
        _no_database_connections.clear()

    def test_a_test_that_swallows_the_error_still_fails_at_teardown(
        self, _no_database_connections
    ):
        """The fixture's teardown assertion is what catches code that catches ``Exception`` (error logger, routers)."""
        import asyncpg

        try:
            asyncio.run(asyncpg.connect("postgresql://u:p@localhost/x"))
        except Exception:  # noqa: BLE001 - swallowed, as production code does
            pass
        assert (
            _no_database_connections
        )  # teardown would now fail the test; clear it so THIS test passes
        _no_database_connections.clear()

    def test_other_loopback_ports_are_unaffected(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client = socket.socket()
        client.connect(server.getsockname())
        client.close()
        server.close()

    def test_no_database_fixture_serves_requests_without_any_connection(
        self, no_database
    ):
        import httpx

        from app.main import app

        async def go():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://t"
            ) as c:
                return (await c.get("/health")).status_code, (
                    await c.get(
                        "/api/v1/recordings/share/Zx9Qm4Rt7Lp2Vb6Nc8Wd3Hs5Jf1Gk0Ya"
                    )
                ).status_code

        health, share = asyncio.run(go())
        assert health == 200 and share in (404, 410, 422)


# ---- migration rehearsal: explicit environment + visible errors ------------------------------------------------------------------------------
def _rehearsal():
    sys.path.insert(0, str(BACKEND / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "migration_rehearsal_under_test", BACKEND / "scripts" / "migration_rehearsal.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCRATCH = "postgresql+asyncpg://postgres:SENTINEL-PW@localhost:5432/secureshield_migration_review_ab12cd"


def test_rehearsal_alembic_environment_is_explicit_and_sufficient(monkeypatch):
    monkeypatch.setenv("SECURESHIELD_ENV_FILE", "C:/somewhere/prod.env")
    monkeypatch.setenv("RETENTION_CLEANUP_ENABLED", "true")
    monkeypatch.setenv(
        "ENVIRONMENT", "production"
    )  # a hostile caller environment must not leak through
    monkeypatch.setenv("DATABASE_ENVIRONMENT", "production")
    env = _rehearsal().alembic_env(SCRATCH)
    assert (
        env["ENVIRONMENT"] == "development" and env["DATABASE_ENVIRONMENT"] == "local"
    )
    assert env["DATABASE_URL"] == env["MIGRATOR_DATABASE_URL"] == SCRATCH
    assert "SECURESHIELD_ENV_FILE" not in env and "RETENTION_CLEANUP_ENABLED" not in env
    # the identity check the application runs in the child accepts exactly this environment ...
    ok = SimpleNamespace(
        **{
            k: env.get(k, "")
            for k in (
                "ENVIRONMENT",
                "DATABASE_ENVIRONMENT",
                "DATABASE_URL",
                "MIGRATOR_DATABASE_URL",
                "DEV_DATABASE_ALLOWED_HOSTS",
            )
        }
    )
    assert "class=loopback" in validate_identity(ok)
    # ... and refuses it if the declarations were missing (the earlier silent failure)
    missing = SimpleNamespace(
        ENVIRONMENT="",
        DATABASE_ENVIRONMENT="",
        DATABASE_URL=SCRATCH,
        MIGRATOR_DATABASE_URL=SCRATCH,
        DEV_DATABASE_ALLOWED_HOSTS="",
    )
    with pytest.raises(DatabaseIdentityError):
        validate_identity(missing)


def test_rehearsal_alembic_failure_is_reported_with_a_scrubbed_stderr_tail(monkeypatch):
    mod = _rehearsal()
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            cmd,
            3,
            stdout="",
            stderr=f"RuntimeError: Database identity refused: boom while using {SCRATCH}",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as info:
        mod.alembic(SCRATCH, "upgrade", "head")
    message = str(info.value)
    assert (
        "alembic upgrade head failed (exit 3)" in message
        and "Database identity refused" in message
    )
    assert "SENTINEL-PW" not in message and SCRATCH not in message
    assert (
        captured["capture_output"] is True
        and captured["env"]["DATABASE_ENVIRONMENT"] == "local"
    )
    assert (
        captured.get("stderr") is None and captured.get("stdout") is None
    )  # nothing is sent to DEVNULL any more


def test_rehearsal_alembic_success_does_not_raise(monkeypatch):
    mod = _rehearsal()
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr=""),
    )
    mod.alembic(SCRATCH, "upgrade", "head")


# ---- CLIs: identity before any database use ---------------------------------------------------------------------------------------------------
class ReachedDatabase(Exception):
    pass


def _reaches_database(*a, **k):
    raise ReachedDatabase()


@pytest.fixture
def verify_calls(monkeypatch):
    calls = []

    async def ok(settings, *a, **k):
        calls.append(1)

    monkeypatch.setattr("app.db_identity.verify_connected_database", ok)
    return calls


def test_admin_accounts_refuses_a_bad_declared_identity_before_the_database(
    monkeypatch, capsys, verify_calls
):
    from app.cli import admin_accounts

    monkeypatch.setattr(admin_accounts, "AsyncSessionLocal", _reaches_database)
    monkeypatch.setattr(
        config.settings, "DATABASE_ENVIRONMENT", "production"
    )  # disagrees with ENVIRONMENT=test
    assert asyncio.run(admin_accounts.run(Namespace(command="list"))) == 2
    assert "refused" in capsys.readouterr().err and verify_calls == []


def test_admin_accounts_refuses_a_mismatched_connected_database(monkeypatch, capsys):
    from app.cli import admin_accounts

    async def mismatch(settings, *a, **k):
        raise DatabaseIdentityError(
            "connected database name differs from the configured database name"
        )

    monkeypatch.setattr("app.db_identity.verify_connected_database", mismatch)
    monkeypatch.setattr(admin_accounts, "AsyncSessionLocal", _reaches_database)
    assert asyncio.run(admin_accounts.run(Namespace(command="list"))) == 2
    assert "refused" in capsys.readouterr().err


def test_admin_accounts_verifies_before_it_touches_the_database(
    monkeypatch, verify_calls
):
    from app.cli import admin_accounts

    monkeypatch.setattr(admin_accounts, "AsyncSessionLocal", _reaches_database)
    with pytest.raises(ReachedDatabase):
        asyncio.run(admin_accounts.run(Namespace(command="list")))
    assert verify_calls == [1]


def test_bootstrap_admin_checks_identity_for_the_dry_run_too(
    monkeypatch, capsys, verify_calls
):
    from app.cli import bootstrap_admin

    monkeypatch.setattr("app.database.AsyncSessionLocal", _reaches_database)
    args = Namespace(email="a@example.com", date_of_birth="2000-01-01", confirm=None)
    monkeypatch.setattr(config.settings, "DATABASE_ENVIRONMENT", "production")
    assert asyncio.run(bootstrap_admin._run(args)) == 2
    assert "refused" in capsys.readouterr().err and verify_calls == []
    monkeypatch.setattr(config.settings, "DATABASE_ENVIRONMENT", "test")
    with pytest.raises(ReachedDatabase):
        asyncio.run(bootstrap_admin._run(args))
    assert verify_calls == [1]


def test_rate_limit_preflight_checks_database_identity_when_urls_are_present(capsys):
    from app.cli import check_rate_limit_config as cli

    local = "postgresql+asyncpg://u:p@localhost/secureshield_dev"
    base = {
        "ENVIRONMENT": "development",
        "DATABASE_ENVIRONMENT": "local",
        "DATABASE_URL": local,
        "MIGRATOR_DATABASE_URL": local,
    }
    import io

    out = io.StringIO()
    assert (
        cli.run(["--environment", "development"], env=base, out=out) == 0
        and "OK" in out.getvalue()
    )
    out = io.StringIO()
    bad = {**base, "DATABASE_URL": PROD_URL, "MIGRATOR_DATABASE_URL": PROD_URL}
    assert cli.run(["--environment", "development"], env=bad, out=out) == 1
    text = out.getvalue()
    assert (
        "REFUSED" in text
        and "SENTINEL-PW" not in text
        and "neon" not in text
        and "://" not in text
    )
    out = io.StringIO()
    assert (
        cli.run(
            ["--environment", "development"],
            env={"ENVIRONMENT": "development"},
            out=out,
        )
        == 0
    )  # no URLs: identity not checked


# ---- integration harness: effective identity (finding 7) -----------------------------------------------------------------------------------------
class TestIntegrationHarnessIdentity:
    def _guard(self):
        from tests.integration.conftest import (
            UnsafeTestDatabaseError,
            assert_safe_test_database,
        )

        return assert_safe_test_database, UnsafeTestDatabaseError

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql+asyncpg://u:p@localhost:5432/app_test?host=ep-cool-silence-aohbh87f.c-2.aws.neon.tech",  # hostname check alone passes this
            "postgresql+asyncpg://u:p@localhost/app_test?port=6543",
            "postgresql+asyncpg://u:p@localhost/app_test?database=SecureShieldDB",
            "postgresql+asyncpg://u:p@localhost/app_test?dsn=postgresql://x@h/d",
            "postgresql+asyncpg://u:p@localhost",
            "postgresql+asyncpg://u:p@\uff4cocalhost/app_test",
            "postgresql+asyncpg://u:p@127.0.0.1.evil.example/app_test",
            "postgresql+asyncpg://u:p@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/app_test",
        ],
    )
    def test_routing_tricks_and_production_endpoints_are_refused(self, url):
        guard, error = self._guard()
        with pytest.raises(error):
            guard(url)

    def test_a_registered_production_database_name_is_refused_even_with_the_test_suffix(
        self, monkeypatch
    ):
        guard, error = self._guard()
        guard("postgresql+asyncpg://u:p@localhost:5432/secureshield_ci_test")
        monkeypatch.setenv("PRODUCTION_DATABASE_NAMES", "secureshield_ci_test")
        with pytest.raises(error, match="production"):
            guard("postgresql+asyncpg://u:p@localhost:5432/secureshield_ci_test")

    def test_error_messages_carry_no_credentials(self):
        guard, error = self._guard()
        with pytest.raises(error) as info:
            guard(
                "postgresql+asyncpg://u:SENTINEL-PW@localhost/app_test?host=h.example"
            )
        assert "SENTINEL-PW" not in str(info.value)

    def test_a_clean_local_test_database_is_still_accepted(self):
        guard, _ = self._guard()
        for host in ("localhost", "127.0.0.1", "[::1]"):
            guard(f"postgresql+asyncpg://u:p@{host}:5432/secureshield_cw_test")
        guard("postgresql+asyncpg://u:p@localhost/secureshield_cw_test?ssl=disable")
