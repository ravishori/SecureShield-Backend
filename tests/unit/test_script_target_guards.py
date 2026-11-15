"""Operator scripts must refuse a wrong or production-class target BEFORE opening any connection (review finding M4).

Every script is imported in-process with the real network/database entry points replaced by functions that fail the test, so a
missing guard would fail the test instead of connecting anywhere.
"""

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

from app.db_identity import DatabaseIdentityError, assert_script_target

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]
PROD = "postgresql://u:SENTINEL-PW@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB"
RECOVERY = "postgresql://u:SENTINEL-PW@ep-small-tooth-aolra8tc-pooler.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB"
LOCAL = "postgresql://postgres:SENTINEL-PW@localhost:5432/postgres"
OTHER = "postgresql://u:SENTINEL-PW@db.example.com:5432/appdb"


# ---- the shared guard ------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["scratch", "migrator"])
def test_scratch_roles_accept_only_loopback_non_registry_servers(role):
    assert assert_script_target(LOCAL, role, environ={}).host == "localhost"
    for url in (PROD, RECOVERY, OTHER):
        with pytest.raises(DatabaseIdentityError) as info:
            assert_script_target(url, role, environ={})
        assert "SENTINEL-PW" not in str(info.value)


@pytest.mark.parametrize("url", [PROD, RECOVERY])
def test_read_only_production_target_needs_the_exact_endpoint_id_as_confirmation(url):
    eid = (
        "ep-cool-silence-aohbh87f"
        if "cool-silence" in url
        else "ep-small-tooth-aolra8tc"
    )
    with pytest.raises(
        DatabaseIdentityError, match="SECURESHIELD_CONFIRM_PRODUCTION_READ"
    ):
        assert_script_target(url, "read_only", environ={})
    for wrong in ("yes", "true", "1", "ep-other", "ep-cool-silence-aohbh87f-x", ""):
        with pytest.raises(DatabaseIdentityError):
            assert_script_target(
                url,
                "read_only",
                environ={
                    "SECURESHIELD_CONFIRM_PRODUCTION_READ": wrong
                    if wrong != "ep-cool-silence-aohbh87f-x"
                    else eid + "x"
                },
            )
    assert (
        assert_script_target(
            url,
            "read_only",
            environ={"SECURESHIELD_CONFIRM_PRODUCTION_READ": eid.upper()},
        ).endpoint_id
        == eid
    )


def test_read_only_other_hosts_need_no_confirmation():
    assert assert_script_target(OTHER, "read_only", environ={}).host == "db.example.com"
    assert assert_script_target(LOCAL, "read_only", environ={}).host == "localhost"


def test_guard_rejects_routing_parameters_lookalikes_and_unknown_roles():
    for url in (
        f"{LOCAL}?host=ep-cool-silence-aohbh87f.c-2.aws.neon.tech",
        "postgresql://u:p@ep-cool-silence-aohbh87f.neon.tech.evil.example/db&x",
    ):
        with pytest.raises(DatabaseIdentityError):
            assert_script_target(url, "scratch", environ={})
    lookalike = "postgresql://u:p@ep-cool-silence-aohbh87f.evil.example/db"
    with pytest.raises(DatabaseIdentityError, match="loopback"):
        assert_script_target(lookalike, "scratch", environ={})
    with pytest.raises(ValueError):
        assert_script_target(LOCAL, "root", environ={})


def test_environment_registry_additions_are_honoured_by_the_guard():
    extra = "postgresql://u:p@ep-new-prod-000001.c-2.aws.neon.tech/db"
    with pytest.raises(DatabaseIdentityError):
        assert_script_target(
            extra,
            "read_only",
            environ={"PRODUCTION_DATABASE_ENDPOINTS": "ep-new-prod-000001"},
        )


# ---- the scripts themselves ------------------------------------------------------------------------------------------------------
def _load(name):
    sys.path.insert(0, str(BACKEND / "scripts"))
    spec = importlib.util.spec_from_file_location(
        f"script_under_test_{name}", BACKEND / "scripts" / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def no_network(monkeypatch):
    import asyncpg
    import subprocess

    def boom(*a, **k):
        raise AssertionError(
            "a script opened a connection / ran a tool although its target must be refused"
        )

    monkeypatch.setattr(asyncpg, "connect", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    for var in (
        "SECURESHIELD_CONFIRM_PRODUCTION_READ",
        "PRODUCTION_DATABASE_ENDPOINTS",
    ):
        monkeypatch.delenv(var, raising=False)


def test_premigration_report_refuses_a_production_target(
    monkeypatch, capsys, no_network
):
    mod = _load("premigration_report")
    monkeypatch.setenv("PREMIGRATION_DATABASE_URL", PROD)
    assert asyncio.run(mod.main()) == 1
    assert "Refusing" in capsys.readouterr().err


def test_premigration_report_allows_a_confirmed_target_to_proceed_to_the_connection(
    monkeypatch, no_network
):
    mod = _load("premigration_report")
    monkeypatch.setenv("PREMIGRATION_DATABASE_URL", PROD)
    monkeypatch.setenv(
        "SECURESHIELD_CONFIRM_PRODUCTION_READ", "ep-cool-silence-aohbh87f"
    )
    with pytest.raises(
        AssertionError, match="opened a connection"
    ):  # got past the guard to the (mocked) connect
        asyncio.run(mod.main())


def test_db_backup_refuses_a_production_target(monkeypatch, no_network):
    mod = _load("db_backup")
    monkeypatch.setattr(sys, "argv", ["db_backup.py"])
    monkeypatch.setenv("BACKUP_DATABASE_URL", RECOVERY)
    with pytest.raises(SystemExit) as info:
        mod.main()
    assert "Refusing" in str(info.value)


@pytest.mark.parametrize(
    "admin",
    [PROD, RECOVERY, OTHER, LOCAL + "?host=ep-cool-silence-aohbh87f.c-2.aws.neon.tech"],
)
def test_restore_check_refuses_non_loopback_production_and_routed_admin_urls(
    monkeypatch, tmp_path, no_network, admin
):
    mod = _load("db_restore_check")
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    monkeypatch.setattr(sys, "argv", ["db_restore_check.py", str(dump)])
    monkeypatch.setenv("RESTORE_ADMIN_URL", admin)
    monkeypatch.delenv("BACKUP_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as info:
        mod.main()
    assert "Refusing" in str(info.value)


def test_restore_check_refuses_a_production_comparison_source(
    monkeypatch, tmp_path, no_network
):
    mod = _load("db_restore_check")
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    monkeypatch.setattr(sys, "argv", ["db_restore_check.py", str(dump)])
    monkeypatch.setenv("RESTORE_ADMIN_URL", LOCAL)
    monkeypatch.setenv("BACKUP_DATABASE_URL", PROD)
    with pytest.raises(SystemExit) as info:
        mod.main()
    assert "Refusing" in str(info.value)


@pytest.mark.parametrize(
    "admin",
    [PROD, OTHER, LOCAL + "?port=6543&host=ep-small-tooth-aolra8tc.c-2.aws.neon.tech"],
)
def test_migration_rehearsal_refuses_a_non_scratch_server(
    monkeypatch, no_network, admin
):
    mod = _load("migration_rehearsal")
    monkeypatch.setenv("RESTORE_ADMIN_URL", admin)
    with pytest.raises(SystemExit) as info:
        mod.main()
    assert "Refusing" in str(info.value)


def test_seed_script_validates_identity_before_building_its_dsn():
    source = (BACKEND / "scripts" / "seed_sms_registry.py").read_text(encoding="utf-8")
    assert source.index("validate_identity(settings)") < source.index(
        "DSN = _libpq_dsn("
    )


@pytest.mark.parametrize(
    "name,guard,first_connection",
    [
        ("premigration_report", "assert_script_target(url", "asyncpg.connect("),
        ("db_backup", "assert_script_target(url", "path = backup("),
        ("db_restore_check", "assert_script_target(admin_url", "asyncio.run(_admin("),
        ("migration_rehearsal", "assert_script_target(admin_url", "asyncio.run(admin("),
    ],
)
def test_guard_precedes_the_first_connection_in_each_script(
    name, guard, first_connection
):
    # Whitespace-insensitive, so reformatting (for example line wrapping) cannot change what this asserts.
    def squash(text: str) -> str:
        return "".join(text.split())

    source = squash((BACKEND / "scripts" / f"{name}.py").read_text(encoding="utf-8"))
    assert source.index(squash(guard)) < source.index(squash(first_connection))
