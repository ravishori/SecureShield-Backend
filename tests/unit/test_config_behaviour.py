"""Behavioural configuration tests (review findings L5, M1, M2): real precedence of all six settings classes, guardian worker
defaults, and the startup wiring order. Subprocess tests run a fresh interpreter, so the env-file selection is exercised
exactly as in production; they import settings classes only (no database engine is created, nothing connects)."""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from app import config, main
from app.config import Settings
from app.db_identity import DatabaseIdentityError
from app.services import guardian_outbox
from app.startup_checks import StartupCheckError

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]

# (variable, value in the selected file, value in the process environment, default) for each of the six settings classes.
PROBE = {
    "Settings": ("ACCESS_TOKEN_EXPIRE_MINUTES", "9", "5", 60),
    "AdminAuthSettings": ("ADMIN_ACCESS_TOKEN_MINUTES", "40", "50", 30),
    "DeliverySettings": ("SMTP_FALLBACK_ENABLED", "false", "true", True),
    "_Switch": (
        "AI_PROCESSING_ENABLED",
        "false",
        "false",
        "false",
    ),  # AI stays off in every scenario
    "RetentionSettings": ("LINK_SCAN_RETENTION_DAYS", "11", "22", None),
    "RateLimitSettings": ("MESSAGE_ANALYZE_PER_MINUTE", "7", "8", None),
}

SCRIPT = textwrap.dedent(
    """
    import json
    from app.config import Settings
    from app.admin_settings import AdminAuthSettings
    from app.delivery_settings import DeliverySettings
    from app.services.ai_gate import _Switch
    from app.services.link_scan_retention import RetentionSettings
    from app.services.user_rate_limits import RateLimitSettings
    probes = {"Settings": ("ACCESS_TOKEN_EXPIRE_MINUTES", Settings), "AdminAuthSettings": ("ADMIN_ACCESS_TOKEN_MINUTES", AdminAuthSettings),
              "DeliverySettings": ("SMTP_FALLBACK_ENABLED", DeliverySettings), "_Switch": ("AI_PROCESSING_ENABLED", _Switch),
              "RetentionSettings": ("LINK_SCAN_RETENTION_DAYS", RetentionSettings), "RateLimitSettings": ("MESSAGE_ANALYZE_PER_MINUTE", RateLimitSettings)}
    print(json.dumps({k: getattr(cls(), var) for k, (var, cls) in probes.items()}))
    """
)


def _run(file_text=None, env_extra=None, tmp_path=None, select=True):
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {v[0] for v in PROBE.values()} | {"SECURESHIELD_ENV_FILE"}
    }
    if file_text is not None:
        f = tmp_path / "selected.env"
        f.write_text(file_text, encoding="utf-8")
        if select:
            env["SECURESHIELD_ENV_FILE"] = str(
                f
            )  # otherwise the file simply sits unselected
    env.update(env_extra or {})
    out = subprocess.run(
        [sys.executable, "-c", SCRIPT],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr[-400:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def _file(which):
    return (
        "\n".join(f"{var}={file_value}" for var, file_value, _, _ in PROBE.values())
        + "\n"
    )


def test_l5_selected_file_supplies_values_for_all_six_classes(tmp_path):
    got = _run(_file(None), tmp_path=tmp_path)
    for name, (var, file_value, _, _) in PROBE.items():
        assert str(got[name]).lower() == file_value.lower(), name


def test_l5_process_environment_beats_the_selected_file_for_all_six_classes(tmp_path):
    env = {var: env_value for var, _, env_value, _ in PROBE.values()}
    got = _run(_file(None), env_extra=env, tmp_path=tmp_path)
    for name, (var, _, env_value, _) in PROBE.items():
        assert str(got[name]).lower() == env_value.lower(), name


def test_l5_defaults_apply_with_no_file_and_no_variable_for_all_six_classes():
    got = _run()
    for name, (_, _, _, default) in PROBE.items():
        assert got[name] == default, name


def test_l5_an_unselected_file_is_ignored_by_all_six_classes(tmp_path):
    got = _run(_file(None), tmp_path=tmp_path, select=False)
    for name, (_, _, _, default) in PROBE.items():
        assert got[name] == default, name


def test_l5_a_missing_selected_file_stops_every_class(tmp_path):
    env = {k: v for k, v in os.environ.items()}
    env["SECURESHIELD_ENV_FILE"] = str(tmp_path / "absent.env")
    for module in (
        "app.config",
        "app.admin_settings",
        "app.delivery_settings",
        "app.services.ai_gate",
        "app.services.link_scan_retention",
        "app.services.user_rate_limits",
    ):
        out = subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            cwd=BACKEND,
            env=env,
            capture_output=True,
            text=True,
        )
        assert out.returncode != 0 and "SECURESHIELD_ENV_FILE" in out.stderr, module


# ---- M1: guardian worker defaults -------------------------------------------------------------------------------------------------
def _settings(**kw):
    base = dict(
        DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
        MIGRATOR_DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
        SECRET_KEY="k",
        SMTP_HOST="h",
        SMTP_PORT="1",
        SMTP_USER="u",
        SMTP_PASSWORD="p",
        SMTP_FROM_EMAIL="e@e.c",
        ERROR_NOTIFY_EMAIL="e@e.c",
        TWILIO_ACCOUNT_SID="AC",
        TWILIO_AUTH_TOKEN="t",
        TWILIO_SMS_NUMBER="1",
        TWILIO_WHATSAPP_NUMBER="1",
    )
    base.update(kw)
    return Settings(_env_file=None, **base)


@pytest.mark.parametrize(
    "environment,explicit,expected",
    [
        ("development", None, False),
        ("test", None, False),
        ("staging", None, False),
        ("production", None, True),
        ("development", True, True),
        ("test", True, True),
        ("staging", True, True),
        ("production", True, True),
        ("development", False, False),
        ("production", False, False),
    ],
)
def test_m1_worker_default_is_off_outside_production(environment, explicit, expected):
    kwargs = {"ENVIRONMENT": environment}
    if explicit is not None:
        kwargs["GUARDIAN_WORKER_ENABLED"] = explicit
    assert _settings(**kwargs).guardian_worker_enabled() is expected


def test_m1_unset_variable_means_none_not_true():
    assert _settings().GUARDIAN_WORKER_ENABLED is None


@pytest.mark.parametrize("environment", ["development", "test", "staging"])
async def test_m1_startup_does_not_start_the_worker_by_default_outside_production(
    monkeypatch, environment
):
    monkeypatch.setattr(config.settings, "ENVIRONMENT", environment)
    monkeypatch.setattr(config.settings, "GUARDIAN_WORKER_ENABLED", None)
    monkeypatch.setattr(guardian_outbox, "poll_seconds_from_env", lambda: 30.0)
    monkeypatch.setattr(main.app.state, "guardian_worker", None, raising=False)
    main._start_guardian_worker()
    assert main.app.state.guardian_worker is None


async def test_m1_production_default_starts_the_worker_and_explicit_opt_in_works_elsewhere(
    monkeypatch,
):
    started = []

    async def fake_loop(poll):
        started.append(poll)

    monkeypatch.setattr(guardian_outbox, "worker_loop", fake_loop)
    monkeypatch.setattr(guardian_outbox, "poll_seconds_from_env", lambda: 5.0)
    for environment, explicit in (("production", None), ("development", True)):
        monkeypatch.setattr(config.settings, "ENVIRONMENT", environment)
        monkeypatch.setattr(config.settings, "GUARDIAN_WORKER_ENABLED", explicit)
        main._start_guardian_worker()
        await main.app.state.guardian_worker
    assert started == [5.0, 5.0]


# ---- M2: poll interval through the shared settings -----------------------------------------------------------------------------------
def test_m2_poll_seconds_from_process_environment(monkeypatch):
    monkeypatch.delenv("GUARDIAN_OUTBOX_POLL_SECONDS", raising=False)
    assert guardian_outbox.poll_seconds_from_env() == 30
    for raw, expected in (
        ("0", 0),
        ("-5", -5),
        ("12.5", 12.5),
        ("garbage", 0),
        ("1e999x", 0),
    ):
        monkeypatch.setenv("GUARDIAN_OUTBOX_POLL_SECONDS", raw)
        assert guardian_outbox.poll_seconds_from_env() == expected


def _poll_in_subprocess(tmp_path, file_text, env_extra=None):
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"GUARDIAN_OUTBOX_POLL_SECONDS", "SECURESHIELD_ENV_FILE"}
    }
    if file_text is not None:
        f = tmp_path / "selected.env"
        f.write_text(file_text, encoding="utf-8")
        env["SECURESHIELD_ENV_FILE"] = str(f)
    env.update(env_extra or {})
    code = "from app.services import guardian_outbox as g; print(g.poll_seconds_from_env())"
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr[-400:]
    return float(out.stdout.strip().splitlines()[-1])


def test_m2_poll_seconds_come_from_the_selected_env_file(tmp_path):
    assert _poll_in_subprocess(tmp_path, "GUARDIAN_OUTBOX_POLL_SECONDS=0\n") == 0.0
    assert _poll_in_subprocess(tmp_path, "GUARDIAN_OUTBOX_POLL_SECONDS=17\n") == 17.0
    assert _poll_in_subprocess(tmp_path, "# nothing\n") == 30.0


def test_m2_process_environment_beats_the_selected_file_for_the_poll_interval(tmp_path):
    assert (
        _poll_in_subprocess(
            tmp_path,
            "GUARDIAN_OUTBOX_POLL_SECONDS=0\n",
            {"GUARDIAN_OUTBOX_POLL_SECONDS": "9"},
        )
        == 9.0
    )


# ---- startup wiring (M3) ----------------------------------------------------------------------------------------------------------------
async def test_m3_startup_verifies_the_database_after_the_checks_and_before_anything_else(
    monkeypatch,
):
    order = []
    monkeypatch.setattr(main, "run_startup_checks", lambda s: order.append("checks"))

    async def verify():
        order.append("verify")

    monkeypatch.setattr(main, "_verify_database_identity", verify)
    monkeypatch.setattr(
        main, "_warn_if_legacy_admin_token", lambda: order.append("admin")
    )
    monkeypatch.setattr(
        main, "_log_twilio_configuration", lambda: order.append("twilio")
    )
    monkeypatch.setattr(main, "_start_guardian_worker", lambda: order.append("worker"))
    await main.on_startup()
    assert order == ["checks", "verify", "admin", "twilio", "worker"]


async def test_m3_a_mismatched_database_stops_startup_without_leaking(monkeypatch):
    async def mismatch(settings, *a, **k):
        raise DatabaseIdentityError(
            "connected database name differs from the configured database name"
        )

    monkeypatch.setattr("app.db_identity.verify_connected_database", mismatch)
    with pytest.raises(StartupCheckError, match="Database identity refused"):
        await main._verify_database_identity()


async def test_m3_a_connection_failure_fails_closed_and_logs_only_the_class(
    monkeypatch,
):
    async def down(settings, *a, **k):
        raise ConnectionRefusedError("postgresql://user:SENTINEL-PW@host/db")

    monkeypatch.setattr("app.db_identity.verify_connected_database", down)
    with pytest.raises(StartupCheckError) as info:
        await main._verify_database_identity()
    assert (
        "ConnectionRefusedError" in str(info.value)
        and "SENTINEL-PW" not in str(info.value)
        and "postgresql://" not in str(info.value)
    )


def test_m3_alembic_and_cli_paths_use_the_same_check():
    for rel in ("app/cli/purge_error_logs.py", "app/cli/purge_link_scans.py"):
        source = (BACKEND / rel).read_text(encoding="utf-8")
        assert (
            source.index("validate_identity(settings)")
            < source.index("verify_connected_database(settings)")
            < source.index("asyncio.run(")
        )
