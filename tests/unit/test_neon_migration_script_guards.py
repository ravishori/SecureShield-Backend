"""Target-identity guards for the 23 database-touching scripts in docs/neon-migration/scripts (final review finding M-4).

Nothing is executed: the scripts are only parsed (AST), and the guard module is exercised with fake ``asyncpg.connect`` functions
and fake environments. No connection can be opened (see tests/unit/conftest.py).
"""

import ast
import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.security]

SCRIPTS_DIR = (
    Path(__file__).resolve().parents[3] / "docs" / "neon-migration" / "scripts"
)
ALL = sorted(p.name for p in SCRIPTS_DIR.glob("*.py"))
NO_CONNECTION = {
    "classify.py",
    "compare_inventories.py",
    "test_migration_guards.py",
    "connection_guard.py",
}
GUARDED = sorted(set(ALL) - NO_CONNECTION)

PROD = "postgresql://u:SENTINEL-PW@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB?sslmode=require"
POOLED = "postgresql://u:SENTINEL-PW@ep-cool-silence-aohbh87f-pooler.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB"
RECOVERY = "postgresql://u:SENTINEL-PW@ep-small-tooth-aolra8tc.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB"
LOCAL_SOURCE = "postgresql://postgres:SENTINEL-PW@localhost:5432/SecureShieldDB"
REHEARSAL = "postgresql://rehearsal:SENTINEL-PW@localhost:5432/secureshield_neon_rehearsal_s3_20261018"
ADMIN = "postgresql://postgres:SENTINEL-PW@localhost:5432/postgres"
NOT_OURS = "postgresql://u:SENTINEL-PW@db.example.com:5432/appdb"
READ = "SECURESHIELD_CONFIRM_PRODUCTION_READ"
WRITE = "SECURESHIELD_CONFIRM_PRODUCTION_WRITE"


@pytest.fixture(scope="module")
def guard():
    """The guard module, loaded with asyncpg's connect functions restored afterwards (the module installs a wrapper on import)."""
    import asyncpg
    import asyncpg.connection

    saved = (asyncpg.connect, asyncpg.connection.connect)
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        spec = importlib.util.spec_from_file_location(
            "connection_guard_under_test", SCRIPTS_DIR / "connection_guard.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        asyncpg.connect, asyncpg.connection.connect = saved
        sys.path.remove(str(SCRIPTS_DIR))


# ---- inventory: 26 files, 23 guarded --------------------------------------------------------------------------------------------------
def test_inventory_is_the_expected_set():
    assert len(ALL) == 27  # 26 original scripts + connection_guard.py
    assert len(GUARDED) == 23, GUARDED
    for name in NO_CONNECTION - {"connection_guard.py"}:
        src = (SCRIPTS_DIR / name).read_text(encoding="utf-8")
        assert (
            "asyncpg.connect" not in src
            and "subprocess.run" not in src
            and "create_async_engine" not in src
        ), name


@pytest.mark.parametrize("name", GUARDED)
def test_every_database_touching_script_installs_the_guard_before_anything_else(name):
    source = (SCRIPTS_DIR / name).read_text(encoding="utf-8")
    assert "import connection_guard" in source, name
    guard_at = source.index("import connection_guard")
    for needle in (
        "asyncpg.connect",
        "create_async_engine(",
        "subprocess.run(",
        "L.connect(",
        "import asyncpg",
    ):
        if needle in source and needle != "import asyncpg":
            assert guard_at < source.index(needle), (name, needle)
    assert "from __future__" not in source[guard_at:], (
        name
    )  # the guard comes after the future import, before every other import
    tree = ast.parse(source)
    first_real = next(
        n
        for n in tree.body
        if not (
            isinstance(n, ast.Expr)
            and isinstance(getattr(n, "value", None), ast.Constant)
        )
        and not (isinstance(n, ast.ImportFrom) and n.module == "__future__")
    )
    assert "guard" in ast.unparse(first_real).lower(), (
        name,
        ast.unparse(first_real)[:60],
    )


@pytest.mark.parametrize("name", GUARDED)
def test_every_function_that_starts_a_process_checks_its_target_first(name):
    tree = ast.parse((SCRIPTS_DIR / name).read_text(encoding="utf-8"))
    for fn in [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]:
        text = ast.unparse(fn)
        starts = [m for m in ("subprocess.run(", "subprocess.Popen(") if m in text]
        if not starts:
            continue
        if (
            fn.name == "version_of"
        ):  # pg_dump/pg_restore --version: no database involved
            continue
        # a run without env= cannot carry a database target (e.g. "pg_restore --list FILE"); every run that does must be preceded by a check
        import re

        runs = [m.start() for m in re.finditer(r"subprocess\.(run|Popen)\(", text)]
        with_env = [i for i in runs if "env=" in text[i : i + 700]]
        if with_env:
            assert "check_subprocess(" in text, (name, fn.name)
            assert text.index("check_subprocess(") < with_env[0], (name, fn.name)


def test_the_shared_runner_in_the_library_checks_before_it_runs():
    text = ast.unparse(
        next(
            n
            for n in ast.walk(
                ast.parse(
                    (SCRIPTS_DIR / "neon_migration_lib.py").read_text(encoding="utf-8")
                )
            )
            if isinstance(n, ast.FunctionDef) and n.name == "run"
        )
    )
    assert (
        text.index("check_subprocess(") < text.index("subprocess.run(")
        and "GuardRefusal" in text
    )


# ---- asyncpg guard behaviour (fake connect, no network) ----------------------------------------------------------------------------------
def _connect(guard, env, **kw):
    seen = {}

    async def fake(dsn=None, *a, **k):
        seen.update(dsn=dsn, **k)
        return "connection"

    wrapped = guard.make_guarded_connect(fake, environ=env)
    return asyncio.run(wrapped(**kw)) if "dsn" in kw else asyncio.run(
        wrapped(kw.pop("_dsn", None), **kw)
    ), seen


def test_loopback_scratch_and_other_local_databases_connect_without_confirmation(guard):
    for url in (REHEARSAL, ADMIN):
        assert _connect(guard, {}, _dsn=url)[0] == "connection"


@pytest.mark.parametrize(
    "url,token",
    [
        (PROD, "ep-cool-silence-aohbh87f"),
        (POOLED, "ep-cool-silence-aohbh87f"),
        (RECOVERY, "ep-small-tooth-aolra8tc"),
        (LOCAL_SOURCE, "database:secureshielddb"),
    ],
)
def test_production_class_targets_need_the_exact_confirmation_token(guard, url, token):
    with pytest.raises(guard.GuardRefusal) as info:
        _connect(guard, {}, _dsn=url)
    assert "SENTINEL-PW" not in str(info.value)
    for wrong in ("true", "1", "ep-other", "database:other", ""):
        with pytest.raises(guard.GuardRefusal):
            _connect(guard, {READ: wrong}, _dsn=url)
    assert (
        _connect(guard, {READ: f"unrelated, {token.upper()}"}, _dsn=url)[0]
        == "connection"
    )


def test_a_tunnel_or_port_forward_to_the_production_database_name_is_treated_as_production(
    guard,
):
    for port in (5432, 15432, 6543, 5433):
        url = f"postgresql://u:p@127.0.0.1:{port}/SecureShieldDB"
        with pytest.raises(
            guard.GuardRefusal, match="database:securesheilddb|database:secureshielddb"
        ):
            _connect(guard, {}, _dsn=url)


def test_unexpected_hosts_routing_parameters_and_lookalikes_are_refused(guard):
    bad = [
        NOT_OURS,
        ADMIN + "?host=ep-cool-silence-aohbh87f.c-2.aws.neon.tech",
        ADMIN + "?port=6543",
        "postgresql://u:p@ep-cool-silence-aohbh87f.neon.tech.evil.example/SecureShieldDB",
        "postgresql://u:p@ep-cool-silence-aohbh87f.evil.example/SecureShieldDB",
        "postgresql://u:p@localhost",  # no database
        "postgresql://u:p@/db",  # no host
    ]
    for url in bad:
        with pytest.raises(guard.GuardRefusal):
            _connect(
                guard,
                {
                    READ: "ep-cool-silence-aohbh87f,ep-small-tooth-aolra8tc,database:secureshielddb"
                },
                _dsn=url,
            )


def test_keyword_connections_are_checked_and_the_port_is_always_explicit(guard):
    env = {}
    conn, seen = _connect(
        guard,
        env,
        host="localhost",
        database="secureshield_neon_rehearsal_s3_20261018",
        user="u",
        password="SENTINEL-PW",
    )
    assert conn == "connection" and seen["port"] == 5432  # PGPORT can never redirect it
    with pytest.raises(guard.GuardRefusal):
        _connect(
            guard, env, host="localhost", user="u"
        )  # no database: would come from PGDATABASE
    with pytest.raises(guard.GuardRefusal):
        _connect(guard, env, database="d", user="u")  # no host: would come from PGHOST
    with pytest.raises(guard.GuardRefusal):
        _connect(
            guard,
            env,
            host="ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech",
            port=5432,
            database="SecureShieldDB",
            user="u",
        )
    ok, _ = _connect(
        guard,
        {READ: "ep-cool-silence-aohbh87f"},
        host="ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech",
        port=5432,
        database="SecureShieldDB",
        user="u",
        ssl="require",
    )
    assert ok == "connection"


def test_install_wraps_asyncpg_connect_once_and_delegates(guard, monkeypatch):
    import asyncpg
    import asyncpg.connection

    calls = []

    async def fake(dsn=None, **kw):
        calls.append((dsn, kw))
        return "connection"

    monkeypatch.setattr(asyncpg, "connect", fake)
    monkeypatch.setattr(asyncpg.connection, "connect", fake)
    guard.install()
    wrapped = asyncpg.connect
    assert (
        getattr(wrapped, "__guarded__", False) and asyncpg.connection.connect is wrapped
    )
    guard.install()  # idempotent
    assert asyncpg.connect is wrapped
    assert (
        asyncio.run(wrapped(REHEARSAL)) == "connection" and calls
    )  # SQLAlchemy's dialect reaches the same attribute
    with pytest.raises(guard.GuardRefusal):
        asyncio.run(wrapped(PROD))
    assert len(calls) == 1  # the refused target never reached the real connect


# ---- subprocess guard: pg_dump / pg_restore / alembic / python helper scripts ---------------------------------------------------------------
def pg_env(url_host, database, port="5432"):
    return {
        "PGHOST": url_host,
        "PGPORT": port,
        "PGDATABASE": database,
        "PGPASSWORD": "SENTINEL-PW",
        "PGUSER": "u",
    }


NEON = "ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech"


def test_dumping_the_local_source_needs_the_database_name_token(guard):
    env = pg_env("localhost", "SecureShieldDB")
    with pytest.raises(guard.GuardRefusal):
        guard.check_subprocess(["pg_dump", "--format=custom"], env)
    guard.check_subprocess(
        ["pg_dump", "--format=custom"], {**env, READ: "database:secureshielddb"}
    )


def test_restoring_into_a_rehearsal_database_needs_nothing_but_must_be_loopback_and_non_production(
    guard,
):
    guard.check_subprocess(
        ["pg_restore", "--data-only"],
        pg_env("localhost", "secureshield_neon_rehearsal_s3_20261018"),
    )
    for host, db in (
        ("localhost", "SecureShieldDB"),
        ("db.example.com", "appdb"),
        ("127.0.0.1", "secureshielddb"),
    ):
        with pytest.raises(guard.GuardRefusal):
            guard.check_subprocess(
                ["pg_restore", "--data-only"],
                {**pg_env(host, db), READ: "database:secureshielddb"},
            )


def test_writing_to_neon_needs_the_write_token_and_the_read_token_is_not_enough(guard):
    env = pg_env(NEON, "SecureShieldDB")
    for cmd in (
        ["pg_restore", "--data-only", "--single-transaction"],
        ["python", "-m", "alembic", "upgrade", "head"],
    ):
        with pytest.raises(guard.GuardRefusal):
            guard.check_subprocess(cmd, env)
        with pytest.raises(guard.GuardRefusal):
            guard.check_subprocess(cmd, {**env, READ: "ep-cool-silence-aohbh87f"})
        guard.check_subprocess(cmd, {**env, WRITE: "ep-cool-silence-aohbh87f"})
    with pytest.raises(guard.GuardRefusal):
        guard.check_subprocess(
            ["pg_restore", "--data-only"],
            {
                **pg_env("ep-unregistered-123456.c-2.aws.neon.tech", "SecureShieldDB"),
                WRITE: "ep-unregistered-123456",
            },
        )


def test_reading_neon_with_pg_dump_or_a_toc_listing_needs_only_the_read_token(guard):
    env = pg_env(NEON, "SecureShieldDB")
    with pytest.raises(guard.GuardRefusal):
        guard.check_subprocess(["pg_dump", "--schema-only"], env)
    guard.check_subprocess(
        ["pg_dump", "--schema-only"], {**env, READ: "ep-cool-silence-aohbh87f"}
    )
    guard.check_subprocess(
        ["pg_restore", "--list", "x.dump"], {**env, READ: "ep-cool-silence-aohbh87f"}
    )


def test_child_python_scripts_are_checked_through_their_url_variables(guard):
    env = {"BACKUP_DATABASE_URL": LOCAL_SOURCE, "RESTORE_ADMIN_URL": ADMIN}
    with pytest.raises(guard.GuardRefusal):
        guard.check_subprocess(["python", "db_restore_check.py"], env)
    guard.check_subprocess(
        ["python", "db_restore_check.py"], {**env, READ: "database:secureshielddb"}
    )
    with pytest.raises(guard.GuardRefusal):
        guard.check_subprocess(
            ["python", "db_restore_check.py"],
            {**env, READ: "database:secureshielddb", "RESTORE_ADMIN_URL": PROD},
        )
    for variable in ("DATABASE_URL", "MIGRATOR_DATABASE_URL"):
        guard.check_subprocess(
            ["python", "-m", "alembic", "current"], {variable: REHEARSAL}
        )
        with pytest.raises(guard.GuardRefusal):
            guard.check_subprocess(
                ["python", "-m", "alembic", "upgrade", "head"],
                {variable: PROD, READ: "ep-cool-silence-aohbh87f"},
            )
    with pytest.raises(guard.GuardRefusal):
        guard.check_subprocess(["pytest"], {"TEST_DATABASE_URL": LOCAL_SOURCE})
    guard.check_subprocess(
        ["pytest"],
        {"TEST_DATABASE_URL": "postgresql+asyncpg://u:p@localhost/secureshield_test"},
    )


def test_commands_with_no_database_target_are_not_blocked(guard):
    guard.check_subprocess(["pg_restore", "--list", "x.dump"], {})
    guard.check_subprocess(["python", "--version"], {"PATH": "x"})


def test_error_messages_never_contain_credentials_or_urls(guard):
    for url in (PROD, LOCAL_SOURCE, NOT_OURS):
        with pytest.raises(guard.GuardRefusal) as info:
            _connect(guard, {}, _dsn=url)
        text = str(info.value)
        assert (
            "SENTINEL-PW" not in text and "://" not in text and "neon.tech" not in text
        )


# ---- regressions fixed in the scripts themselves ---------------------------------------------------------------------------------------------
def test_scripts_no_longer_select_a_missing_env_file_and_declare_the_database_environment():
    for name in ("50_alembic_rehearsal.py", "80_final_checks_s2.py"):
        source = (SCRIPTS_DIR / name).read_text(encoding="utf-8")
        assert "SECURESHIELD_ENV_FILE=str(" not in source, (
            name
        )  # a selected-but-missing file is an error since Stage 1.1
        assert 'DATABASE_ENVIRONMENT="test"' in source, name
