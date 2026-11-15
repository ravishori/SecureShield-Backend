"""Stage 1.6B-3: the SMS registry seed must verify ``current_database()`` is the local dev database before its first write."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.db_identity as db_identity

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]
LOCAL_DEV = "postgresql+asyncpg://secureshield_dev_owner:SENTINEL-PW@localhost:5432/secureshield_dev"


@pytest.fixture(scope="module")
def seed():
    mp = pytest.MonkeyPatch()
    mp.setattr(
        db_identity, "validate_identity", lambda *a, **k: "ok"
    )  # module-level guard; its own tests live elsewhere
    spec = importlib.util.spec_from_file_location(
        "seed_sms_registry_under_test", BACKEND / "scripts" / "seed_sms_registry.py"
    )
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        mp.undo()
    return mod


def cfg(url=LOCAL_DEV, env="development"):
    return SimpleNamespace(
        MIGRATOR_DATABASE_URL=url,
        DATABASE_URL=url.replace("secureshield_dev_owner", "secureshield_dev_app"),
        ENVIRONMENT=env,
        PRODUCTION_DATABASE_NAMES="",
    )


def test_accepts_the_local_development_database(seed):
    seed.assert_seed_target("secureshield_dev", cfg())


@pytest.mark.parametrize(
    "actual",
    ["postgres", "SecureShieldDB", "secureshield_test", "", "secureshield_dev2"],
)
def test_refuses_any_other_connected_database(seed, actual):
    with pytest.raises(SystemExit) as info:
        seed.assert_seed_target(actual, cfg())
    assert "Refusing to seed" in str(info.value)


@pytest.mark.parametrize("env", ["production", "staging", "test", ""])
def test_refuses_a_non_development_environment(seed, env):
    with pytest.raises(SystemExit):
        seed.assert_seed_target("secureshield_dev", cfg(env=env))


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:SENTINEL-PW@db.example.com:5432/secureshield_dev",
        "postgresql+asyncpg://u:SENTINEL-PW@localhost:5433/secureshield_dev",
    ],
)
def test_refuses_a_non_local_host_or_port_without_leaking_credentials(seed, url):
    with pytest.raises(SystemExit) as info:
        seed.assert_seed_target("secureshield_dev", cfg(url))
    assert "SENTINEL-PW" not in str(info.value)


def test_a_connected_name_that_differs_from_the_configured_one_is_refused(seed):
    other = cfg(LOCAL_DEV.replace("/secureshield_dev", "/other_db"))
    with pytest.raises(SystemExit):
        seed.assert_seed_target("secureshield_dev", other)


def test_identity_check_precedes_every_write_in_the_script():
    src = (BACKEND / "scripts" / "seed_sms_registry.py").read_text(encoding="utf-8")
    check = src.index("assert_seed_target(cur.fetchone()[0])")
    for write in ("TRUNCATE", "INSERT INTO", "conn.commit()"):
        assert check < src.index(write, src.index("def seed(")), write
    assert "--replace" in src and src.index("current_database()") < src.index(
        "SELECT (SELECT count(*)"
    )


def test_console_output_is_ascii_safe_for_windows_cp1252():
    """Stage 1.6B-4: the final success message crashed on a cp1252 console (after the commit)."""
    import ast

    src = (BACKEND / "scripts" / "seed_sms_registry.py").read_text(encoding="utf-8")
    printed = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    printed.append(sub.value)
    assert printed
    for text_ in printed:
        text_.encode(
            "cp1252"
        )  # raises UnicodeEncodeError if any printed literal is not cp1252-encodable
        assert text_.isascii(), text_
    assert any(t.startswith("\nDone!") for t in printed)
