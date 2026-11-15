"""Retention gate, startup safety, maintenance CLIs and guardian worker (Stage 1.1).

Every test here is database-free: sessions are fakes that fail the test if a statement is executed when it must not be.
"""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import config, main
from app.db_identity import retention_gate
from app.services import error_log_retention, guardian_outbox, link_scan_retention
from app.startup_checks import StartupCheckError, check_retention_configuration

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]


class ExplodingFactory:
    """A session factory that must never be used."""

    def __call__(self, *a, **k):
        raise AssertionError(
            "the database was touched although retention must be blocked"
        )


class RecordingSession:
    def __init__(self, log):
        self.log = log

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, statement, params=None):
        self.log.append(str(statement))
        return SimpleNamespace(
            rowcount=0, fetchall=lambda: [(1,), (2,)], scalar_one=lambda: 3
        )

    async def commit(self):
        self.log.append("COMMIT")


@pytest.fixture
def verified(monkeypatch):
    """Mock the read-only current_database() check; records the calls."""
    calls = []

    async def ok(settings, *a, **k):
        calls.append(1)

    monkeypatch.setattr("app.db_identity.verify_connected_database", ok)
    return calls


def _factory(log):
    return lambda: RecordingSession(log)


@pytest.fixture
def flag(monkeypatch):
    def set_flag(value):
        monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", value)

    return set_flag


# ---- T1: flag unset => nothing is deleted, on every path --------------------------------------------------------------
async def test_t1_unset_flag_blocks_link_scan_purge():
    res = await link_scan_retention.purge_expired(ExplodingFactory())
    assert (res.deleted, res.error) == (0, "blocked")


async def test_t1_unset_flag_blocks_error_log_purge():
    res = await error_log_retention.purge_old_error_logs(ExplodingFactory(), days=90)
    assert (res.deleted, res.error) == (0, "blocked")


async def test_t1_unset_flag_blocks_guardian_purge(monkeypatch):
    called = []

    async def terminal(db):
        called.append(1)
        return 0

    monkeypatch.setattr(guardian_outbox, "purge_terminal", terminal)
    monkeypatch.setattr("app.database.AsyncSessionLocal", ExplodingFactory())
    await guardian_outbox.purge_safe()
    assert called == []


async def test_t1_opportunistic_trigger_is_gated_too():
    link_scan_retention._gate["next"] = 0.0
    await (
        link_scan_retention.maybe_purge_expired()
    )  # would use the real database if it were not blocked


# ---- T2: flag true but identity invalid => nothing is deleted ---------------------------------------------------------
async def test_t2_flag_true_with_bad_identity_deletes_nothing(flag, monkeypatch):
    flag("true")
    monkeypatch.setattr(
        config.settings, "DATABASE_ENVIRONMENT", "production"
    )  # disagrees with ENVIRONMENT=test
    assert retention_gate().allowed is False
    assert (
        await link_scan_retention.purge_expired(ExplodingFactory())
    ).error == "blocked"
    assert (
        await error_log_retention.purge_old_error_logs(ExplodingFactory(), days=90)
    ).error == "blocked"


# ---- T3: flag true and identity valid => deletes as before -------------------------------------------------------------
async def test_t3_enabled_error_log_purge_runs_the_same_delete(flag):
    flag("true")
    log = []
    res = await error_log_retention.purge_old_error_logs(_factory(log), days=90)
    assert (res.deleted, res.error) == (2, None)
    assert (
        any("DELETE FROM error_logs" in s and "make_interval" in s for s in log)
        and "COMMIT" in log
    )


async def test_t3_enabled_link_scan_purge_issues_a_delete(flag):
    flag("true")
    log = []
    res = await link_scan_retention.purge_expired(_factory(log))
    assert res.error is None and any("DELETE" in s.upper() for s in log)


async def test_t3_enabled_guardian_purge_runs(flag, monkeypatch):
    flag("true")
    called = []

    async def terminal(db):
        called.append(1)
        return 0

    monkeypatch.setattr(guardian_outbox, "purge_terminal", terminal)
    monkeypatch.setattr("app.database.AsyncSessionLocal", _factory([]))
    await guardian_outbox.purge_safe()
    assert called == [1]


# ---- T4: only the exact value "true" enables ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("TRUE ", True),
        (" True", True),
        ("1", False),
        ("yes", False),
        ("on", False),
        ("garbage", False),
        ("false", False),
        ("", False),
        (None, False),
    ],
)
def test_t4_only_true_enables(flag, value, expected):
    flag(value)
    assert retention_gate().allowed is expected


# ---- T5/T6: production must state the flag explicitly -------------------------------------------------------------------
def _prod(flag_value):
    return SimpleNamespace(
        RETENTION_CLEANUP_ENABLED=flag_value, is_production=lambda: True
    )


@pytest.mark.parametrize("value", [None, "", "  ", "maybe", "1"])
def test_t5_production_boot_refuses_without_an_explicit_value(value):
    with pytest.raises(StartupCheckError, match="RETENTION_CLEANUP_ENABLED"):
        check_retention_configuration(_prod(value))


def test_t6_production_false_boots_with_a_loud_warning(caplog):
    with caplog.at_level("WARNING"):
        check_retention_configuration(_prod("false"))
    assert "will NOT delete" in caplog.text
    check_retention_configuration(_prod("true"))


def test_non_production_may_leave_the_flag_unset():
    check_retention_configuration(
        SimpleNamespace(RETENTION_CLEANUP_ENABLED=None, is_production=lambda: False)
    )


# ---- T7: application startup deletes nothing ---------------------------------------------------------------------------
async def test_t7_startup_touches_no_database(monkeypatch, verified):
    monkeypatch.setattr(main, "run_startup_checks", lambda s: None)
    monkeypatch.setattr(main, "_start_guardian_worker", lambda: None)
    monkeypatch.setattr("app.database.AsyncSessionLocal", ExplodingFactory())
    monkeypatch.setattr(
        config.settings, "RETENTION_CLEANUP_ENABLED", "true"
    )  # even when enabled
    await main.on_startup()


def test_t7_main_has_no_delete_or_purge_code():
    source = (BACKEND / "app" / "main.py").read_text(encoding="utf-8")
    for forbidden in (
        "DELETE FROM",
        "_cleanup_old_error_logs",
        "_purge_expired_link_scans",
        "purge_expired",
        "purge_old_error_logs",
    ):
        assert forbidden not in source, forbidden


def test_startup_runs_identity_check_before_the_retention_check():
    from app.startup_checks import _CHECKS, check_database_identity

    assert _CHECKS[0] is check_database_identity


# ---- T8-T11: maintenance CLIs --------------------------------------------------------------------------------------------
def test_t8_error_log_cli_dry_run_counts_and_deletes_nothing(
    monkeypatch, capsys, verified
):
    from app.cli import purge_error_logs

    async def count(*a, **k):
        return 7

    async def purge(*a, **k):
        raise AssertionError("dry-run must not delete")

    monkeypatch.setattr(error_log_retention, "count_old_error_logs", count)
    monkeypatch.setattr(error_log_retention, "purge_old_error_logs", purge)
    assert purge_error_logs.run(["--dry-run"]) == 0
    assert "7" in capsys.readouterr().out


def test_t9_error_log_cli_refuses_a_bad_identity(monkeypatch, capsys):
    from app.cli import purge_error_logs

    monkeypatch.setattr(config.settings, "DATABASE_ENVIRONMENT", "production")

    async def boom(*a, **k):
        raise AssertionError("must not touch the database")

    monkeypatch.setattr(error_log_retention, "count_old_error_logs", boom)
    monkeypatch.setattr(error_log_retention, "purge_old_error_logs", boom)
    assert purge_error_logs.run([]) == 2
    assert purge_error_logs.run(["--dry-run"]) == 2
    assert "refused" in capsys.readouterr().out


@pytest.mark.parametrize("days", [0, -1, -90])
def test_t10_error_log_cli_refuses_non_positive_days(monkeypatch, days):
    from app.cli import purge_error_logs

    monkeypatch.setattr(config.settings, "LOG_RETENTION_DAYS", days)
    monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", "true")

    async def boom(*a, **k):
        raise AssertionError("must not touch the database")

    monkeypatch.setattr(error_log_retention, "purge_old_error_logs", boom)
    assert purge_error_logs.run([]) == 2


def test_error_log_cli_without_the_flag_is_blocked_with_exit_3(capsys, monkeypatch):
    from app.cli import purge_error_logs

    async def boom(*a, **k):
        raise AssertionError("must not delete")

    monkeypatch.setattr(error_log_retention, "purge_old_error_logs", boom)
    assert purge_error_logs.run([]) == 3
    assert "nothing was deleted" in capsys.readouterr().out


def test_error_log_cli_with_the_flag_deletes(monkeypatch, capsys, flag, verified):
    from app.cli import purge_error_logs

    flag("true")

    async def purge(*a, **k):
        return error_log_retention.ErrorLogPurgeResult(5, 90)

    monkeypatch.setattr(error_log_retention, "purge_old_error_logs", purge)
    assert purge_error_logs.run([]) == 0
    assert "deleted=5" in capsys.readouterr().out


@pytest.mark.parametrize("args", [[], ["--dry-run"], ["--redact-existing"]])
def test_t11_link_scan_cli_refuses_a_bad_identity_in_every_mode(
    monkeypatch, capsys, args
):
    from app.cli import purge_link_scans

    monkeypatch.setattr(config.settings, "DATABASE_ENVIRONMENT", "production")
    monkeypatch.setattr("app.database.AsyncSessionLocal", ExplodingFactory())
    assert purge_link_scans.run(args) == 2
    assert "refused" in capsys.readouterr().out


# ---- T12: the new modules stay away from AI --------------------------------------------------------------------------
def test_t12_new_modules_do_not_touch_ai():
    for rel in (
        "app/db_identity.py",
        "app/services/error_log_retention.py",
        "app/cli/purge_error_logs.py",
    ):
        source = (BACKEND / rel).read_text(encoding="utf-8")
        for word in ("ai_gate", "ai_service", "AI_PROCESSING_ENABLED", "ANTHROPIC"):
            assert word not in source, (rel, word)


# ---- Guardian worker and Twilio --------------------------------------------------------------------------------------------
async def test_guardian_worker_starts_without_any_twilio_configuration(monkeypatch):
    for name in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"):
        monkeypatch.setattr(config.settings, name, "")
    started = []

    async def fake_loop(poll):
        started.append(poll)

    monkeypatch.setattr(guardian_outbox, "worker_loop", fake_loop)
    monkeypatch.setattr(guardian_outbox, "poll_seconds_from_env", lambda: 12.0)
    monkeypatch.setattr(config.settings, "GUARDIAN_WORKER_ENABLED", True)
    main._start_guardian_worker()
    await main.app.state.guardian_worker
    assert started == [12.0]


@pytest.mark.parametrize("enabled,poll", [(False, 30.0), (True, 0.0), (True, -1.0)])
def test_guardian_worker_can_be_disabled(monkeypatch, enabled, poll):
    monkeypatch.setattr(config.settings, "GUARDIAN_WORKER_ENABLED", enabled)
    monkeypatch.setattr(guardian_outbox, "poll_seconds_from_env", lambda: poll)
    monkeypatch.setattr(main.app.state, "guardian_worker", None, raising=False)
    main._start_guardian_worker()
    assert main.app.state.guardian_worker is None


def test_startup_makes_no_outbound_twilio_call():
    tree = ast.parse((BACKEND / "app" / "main.py").read_text(encoding="utf-8"))
    imported = {
        n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module
    } | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m.startswith("twilio") for m in imported)
    assert "_verify_twilio" not in (BACKEND / "app" / "main.py").read_text(
        encoding="utf-8"
    )


def test_missing_twilio_configuration_does_not_crash_startup_logging(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "")
    main._log_twilio_configuration()
