"""Stage 1.2: isolated local development and test databases.

Everything here is static or in-memory: the SQL file, the documentation and the example configuration are READ AS TEXT, never
executed, and no database is contacted (tests/unit/conftest.py blocks and counts every attempt).
"""

import io
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.cli import show_database_target as cli
from app.db_identity import DatabaseIdentityError, validate_identity

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]
SQL_PATH = BACKEND / "docs" / "database" / "STAGE_1_2_LOCAL_DATABASE_SETUP.sql"
DOC_PATH = BACKEND / "docs" / "LOCAL_DEVELOPMENT.md"
ENV_EXAMPLE = BACKEND / ".env.example"

DEV_DB, TEST_DB = "secureshield_dev", "secureshield_test"
DEV_OWNER, DEV_APP, TEST_OWNER = (
    "secureshield_dev_owner",
    "secureshield_dev_app",
    "secureshield_test_owner",
)
ROLES = (DEV_OWNER, DEV_APP, TEST_OWNER)
PROD_DB = "SecureShieldDB"


def _sql() -> str:
    return SQL_PATH.read_text(encoding="utf-8")


def _executable_sql() -> str:
    """The SQL with comments removed (line comments and the text of dollar-quoted blocks stay: they are code)."""
    return "\n".join(line.split("--", 1)[0] for line in _sql().splitlines())


def _local_block() -> dict[str, str]:
    """The ACTIVE (uncommented) assignments of .env.example."""
    values = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def _commented_test_url() -> str:
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.lstrip("# ").startswith("TEST_DATABASE_URL="):
            return line.lstrip("# ").split("=", 1)[1].strip()
    raise AssertionError("no TEST_DATABASE_URL example in .env.example")


def _settings(**kw):
    base = dict(
        ENVIRONMENT="development",
        DATABASE_ENVIRONMENT="local",
        PRODUCTION_DATABASE_ENDPOINTS="",
        DEV_DATABASE_ALLOWED_HOSTS="",
        PRODUCTION_DATABASE_NAMES="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


# ---- database and role design --------------------------------------------------------------------------------------------------------------
def test_development_and_test_names_are_distinct_and_follow_the_harness_convention():
    assert DEV_DB != TEST_DB and DEV_OWNER != TEST_OWNER and len({*ROLES}) == 3
    assert TEST_DB.endswith("_test") and not DEV_DB.endswith(
        "_test"
    )  # the harness accepts only *_test databases
    assert DEV_DB.lower() != PROD_DB.lower() and TEST_DB.lower() != PROD_DB.lower()


def test_sql_creates_exactly_the_planned_roles_and_databases():
    sql = _executable_sql()
    created_roles = set(re.findall(r"secureshield_[a-z_]+", sql)) & {
        r
        for r in re.findall(r"secureshield_[a-z_]+", sql)
        if r.endswith(("_owner", "_app"))
    }
    assert created_roles == set(ROLES)
    assert set(re.findall(r"'(secureshield_(?:dev|test))'", sql)) == {DEV_DB, TEST_DB}
    assert (
        sql.count("CREATE DATABASE") == 2 and sql.count("CREATE ROLE") == 1
    )  # the role is created once, in a loop over the three names
    assert (
        "secureshield_app" not in sql and "secureshield_migrator" not in sql
    )  # the hosted deployment's role names are not reused


def test_sql_never_names_or_creates_the_production_database_or_a_hosted_endpoint():
    executable = _executable_sql()
    # The one place hosted services are named is the precheck that REFUSES to run on them (their fingerprint settings/roles).
    fingerprint = re.search(
        r"IF EXISTS \(SELECT 1 FROM pg_settings.*?hosted PostgreSQL service[^;]*;",
        executable,
        flags=re.S,
    )
    assert fingerprint and "RAISE EXCEPTION" in fingerprint.group(0)
    scrubbed = executable.replace(fingerprint.group(0), "")
    for forbidden in ("neon", "railway", "ep-cool", "ep-small", "aws", "rds_", "azure"):
        assert forbidden not in scrubbed.lower(), forbidden
    # the only mention of the legacy name is the information-only check in Part 5 (a SELECT)
    mentions = [
        line for line in executable.splitlines() if "secureshielddb" in line.lower()
    ]
    assert len(mentions) == 1 and mentions[0].lower().lstrip().startswith("select")


def test_sql_contains_no_destructive_or_privileged_statement():
    sql = _executable_sql()
    # data/DDL-destroying statements are recognised by their LEADING keyword (the words INSERT/UPDATE/DELETE legitimately appear
    # inside the one GRANT of row privileges to the application role)
    for statement in [
        part.strip() for part in re.split(r";|\\gexec", sql) if part.strip()
    ]:
        first = statement.split()[0].upper().lstrip("\\")
        assert first not in {
            "DROP",
            "TRUNCATE",
            "DELETE",
            "UPDATE",
            "INSERT",
            "COPY",
            "VACUUM",
            "REINDEX",
            "CLUSTER",
            "LOCK",
            "REASSIGN",
        }, statement[:60]
    forbidden = [
        r"\bDROP\b",
        r"\bTRUNCATE\b",
        r"\bCOPY\b",
        r"\bALTER\s+SYSTEM\b",
        r"\bCREATE\s+EXTENSION\b",
        r"\bpg_terminate_backend\b",
        r"\bpg_hba\b",
        r"\bRESET\b",
        r"\bGRANT\s+ALL\b",
        r"\bWITH\s+GRANT\s+OPTION\b",
        r"\bPASSWORD\b",
        r"\bENCRYPTED\b",
        r"(?<![A-Za-z_])SUPERUSER",
        r"(?<![A-Za-z_])CREATEDB",
        r"(?<![A-Za-z_])CREATEROLE",
        r"(?<![A-Za-z_])REPLICATION",
        r"(?<![A-Za-z_])BYPASSRLS",
        r"\bGRANT\s+pg_",
        r"\bGRANT\s+secureshield",
        r"\bALTER\s+DATABASE\b.*\bOWNER\b",
        r"\bREASSIGN\b",
        r"\\!",
        r"\\copy",
        r"\\i\b",
        r"\\ir\b",
    ]
    unquoted = re.sub(
        r"'[^']*'", "''", sql
    )  # words inside messages ("connect as the superuser role") are not statements
    unquoted = unquoted[
        : unquoted.index("SELECT r.rolname")
    ]  # Parts 0-4 only: the Part 5 queries (SELECT-only, checked elsewhere) have column aliases such as "superuser"
    for pattern in forbidden:
        assert not re.search(pattern, unquoted, flags=re.IGNORECASE), pattern
    # "GRANT ALL" is also absent from the comments' instructions about privileges that would exceed least privilege
    assert (
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secureshield_dev_app"
        in re.sub(r"\s+", " ", sql)
    )


def test_sql_sets_no_password_and_no_secret_looking_value():
    text = _sql()
    assert not re.search(r"PASSWORD\s+'", text, flags=re.IGNORECASE)
    assert not re.search(r"://[^:/\s]+:[^@\s]+@", text)
    assert (
        "\\password" in text
    )  # the interactive, client-side-hashed way is what the file documents
    for line in text.splitlines():
        assert not re.search(r"(secret|token|apikey)\s*=", line, flags=re.IGNORECASE), (
            line
        )


def test_every_role_is_least_privilege_login_only():
    sql = _executable_sql()
    attributes = (
        "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
    )
    assert attributes in sql
    # existing roles are NEVER altered (review 1.2A): no ALTER ROLE at all, only a check that aborts on excess privilege
    assert not re.search(r"ALTER\s+ROLE", sql, flags=re.IGNORECASE)
    check = sql[sql.index("offending text") :]
    check = check[: check.index("COMMIT;")]
    for column in (
        "rolsuper",
        "rolcreatedb",
        "rolcreaterole",
        "rolreplication",
        "rolbypassrls",
        "pg_auth_members",
    ):
        assert column in check, column
    assert (
        "RAISE EXCEPTION" in check
        and "this script does not modify existing roles" in check
    )
    assert (
        "CONNECTION LIMIT %s" in sql
        and "('secureshield_dev_app', 50)" in sql
        and "('secureshield_dev_owner', 20)" in sql
        and "('secureshield_test_owner', 20)" in sql
    )
    assert "GRANT USAGE ON SCHEMA public TO secureshield_dev_app" in sql
    assert not re.search(
        r"GRANT\s+(CREATE|ALL)[^;]*\bTO\s+secureshield_dev_app",
        sql,
        flags=re.IGNORECASE,
    )
    assert not re.search(r"TRUNCATE|REFERENCES|TRIGGER", sql, flags=re.IGNORECASE)


def test_connect_privileges_isolate_the_two_databases():
    sql = re.sub(r"\s+", " ", _executable_sql())
    assert (
        f"REVOKE ALL ON DATABASE {DEV_DB} FROM PUBLIC;" in sql
        and f"REVOKE ALL ON DATABASE {TEST_DB} FROM PUBLIC;" in sql
    )
    assert f"GRANT CONNECT ON DATABASE {DEV_DB} TO {DEV_OWNER}, {DEV_APP};" in sql
    assert f"GRANT CONNECT ON DATABASE {TEST_DB} TO {TEST_OWNER};" in sql
    assert f"REVOKE ALL ON DATABASE {DEV_DB} FROM {TEST_OWNER};" in sql
    assert f"REVOKE ALL ON DATABASE {TEST_DB} FROM {DEV_OWNER}, {DEV_APP};" in sql
    assert sql.count("REVOKE ALL ON SCHEMA public FROM PUBLIC;") == 2
    for kind in ("TABLES", "SEQUENCES"):
        assert "IN SCHEMA public GRANT" in sql and f"ON {kind} TO {DEV_APP}" in sql


def test_create_database_is_never_inside_a_transaction_block():
    lines = [line.split("--", 1)[0].strip() for line in _sql().splitlines()]
    depth = 0
    for line in lines:
        if re.fullmatch(r"BEGIN;", line, flags=re.IGNORECASE):
            assert depth == 0, "nested BEGIN"
            depth = 1
        elif re.fullmatch(r"(COMMIT|ROLLBACK);", line, flags=re.IGNORECASE):
            assert depth == 1, "COMMIT without BEGIN"
            depth = 0
        elif "CREATE DATABASE" in line.upper():
            assert depth == 0, "CREATE DATABASE inside a transaction block"
        elif line.startswith("\\connect"):
            assert depth == 0, "\\connect inside a transaction block"
    assert depth == 0, "a transaction is left open"
    text = _executable_sql()
    assert (
        text.count("\\gexec") == 2
    )  # exactly the two CREATE DATABASE statements are run in autocommit, if the database is missing
    assert (
        "--single-transaction" in _sql() and "DO NOT use --single-transaction" in _sql()
    )


def test_script_is_guarded_idempotent_and_ends_with_read_only_verification():
    sql = _sql()
    assert "\\set ON_ERROR_STOP on" in sql
    assert (
        "inet_server_addr()" in sql and "refusing to run" in sql
    )  # loopback-only precheck
    assert "current_database() <> 'postgres'" in sql
    assert sql.count("WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname =") == 2
    assert "NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = spec.role_name)" in sql
    assert "\set AUTOCOMMIT on" in sql
    assert (
        "neon" in sql and "rds_superuser" in sql
    )  # hosted-service fingerprint refusal
    part5 = sql[sql.index("Part 5 - verification") :]
    part5 = part5[part5.index("\n") :]  # skip the rest of the heading comment line
    statements = [
        s.strip() for s in re.sub(r"--[^\n]*", "", part5).split(";") if s.strip()
    ]
    assert len(statements) >= 7 and all(
        s.upper().startswith("SELECT") or s.startswith("\\connect") for s in statements
    ), statements
    assert sql.rstrip().endswith(
        "\\connect postgres"
    )  # the session ends back on the maintenance database


def test_sql_documents_execution_transactions_passwords_and_rollback():
    header = _sql()[: _sql().index("\\set ON_ERROR_STOP")]
    for needle in (
        "NOT executed",
        "TRANSACTIONS",
        "PASSWORDS",
        "ROLLBACK",
        "-X",
        "ON_ERROR_STOP=1",
        "BY HAND",
        "CREATE DATABASE cannot run inside a transaction block".split()[0],
    ):
        assert needle in header, needle
    assert "cannot create a database inside a transaction block" in header


# ---- example configuration and documentation ------------------------------------------------------------------------------------------------
def test_env_example_local_block_is_a_safe_development_target():
    values = _local_block()
    assert (
        values["ENVIRONMENT"] == "development"
        and values["DATABASE_ENVIRONMENT"] == "local"
    )
    assert values["AI_PROCESSING_ENABLED"] == "false"
    settings = _settings(
        DATABASE_URL=values["DATABASE_URL"],
        MIGRATOR_DATABASE_URL=values["MIGRATOR_DATABASE_URL"],
    )
    assert "class=loopback" in validate_identity(
        settings
    ) and f"database={DEV_DB}" in validate_identity(settings)
    assert (
        f"//{DEV_APP}:" in values["DATABASE_URL"]
        and f"//{DEV_OWNER}:" in values["MIGRATOR_DATABASE_URL"]
    )
    assert "@localhost:5432/" in values["DATABASE_URL"]


def test_env_example_contains_no_credential_and_no_hosted_target_in_active_lines():
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            assert not re.search(
                r"neon\.tech|railway|rlwy", line, flags=re.IGNORECASE
            ), line
            match = re.search(r"://[^:/\s]+:([^@\s]+)@", line)
            if match:
                assert match.group(1).startswith("YOUR_"), (
                    line
                )  # a placeholder, never a value
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert not re.search(
        r"(sk-ant-|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20}|-----BEGIN)", text
    )


def test_env_example_never_puts_the_test_database_in_the_env_file():
    assert "TEST_DATABASE_URL" not in _local_block()
    url = _commented_test_url()
    assert f"//{TEST_OWNER}:YOUR_" in url and url.endswith(f"/{TEST_DB}")
    from tests.integration.conftest import assert_safe_test_database

    assert_safe_test_database(url)


def test_the_development_database_is_never_acceptable_as_a_test_database():
    from tests.integration.conftest import (
        UnsafeTestDatabaseError,
        assert_safe_test_database,
    )

    dev_url = _local_block()["MIGRATOR_DATABASE_URL"]
    for url in (
        dev_url,
        _local_block()["DATABASE_URL"],
        f"postgresql+asyncpg://u:p@localhost:5432/{DEV_DB}",
        f"postgresql+asyncpg://u:p@localhost:5432/{PROD_DB}",
    ):
        with pytest.raises(UnsafeTestDatabaseError):
            assert_safe_test_database(url)


def test_the_test_database_is_acceptable_for_tests_and_refused_as_a_development_target_only_by_name_rule():
    settings = _settings(
        ENVIRONMENT="test",
        DATABASE_ENVIRONMENT="test",
        DATABASE_URL=_commented_test_url(),
        MIGRATOR_DATABASE_URL=_commented_test_url(),
    )
    assert f"database={TEST_DB}" in validate_identity(settings)


@pytest.mark.parametrize("name", [PROD_DB, PROD_DB.lower(), PROD_DB.upper()])
@pytest.mark.parametrize(
    "environment,denv", [("development", "local"), ("test", "test")]
)
def test_production_name_and_endpoints_stay_blocked_outside_production(
    name, environment, denv
):
    url = f"postgresql+asyncpg://{DEV_APP}:YOUR_PASSWORD@localhost:5432/{name}"
    with pytest.raises(DatabaseIdentityError, match="production database name"):
        validate_identity(
            _settings(
                ENVIRONMENT=environment,
                DATABASE_ENVIRONMENT=denv,
                DATABASE_URL=url,
                MIGRATOR_DATABASE_URL=url,
            )
        )
    for endpoint in (
        "ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech",
        "ep-small-tooth-aolra8tc-pooler.c-2.ap-southeast-1.aws.neon.tech",
    ):
        remote = f"postgresql+asyncpg://{DEV_APP}:YOUR_PASSWORD@{endpoint}/{DEV_DB}"
        with pytest.raises(DatabaseIdentityError, match="production-registry"):
            validate_identity(
                _settings(
                    ENVIRONMENT=environment,
                    DATABASE_ENVIRONMENT=denv,
                    DATABASE_URL=remote,
                    MIGRATOR_DATABASE_URL=remote,
                )
            )


def test_registry_is_unchanged_by_stage_1_2():
    text = (BACKEND / "config" / "production_endpoints.txt").read_text(encoding="utf-8")
    entries = [
        line.split("#")[0].strip()
        for line in text.splitlines()
        if line.split("#")[0].strip()
    ]
    assert entries == [
        "ep-cool-silence-aohbh87f",
        "ep-small-tooth-aolra8tc",
        "database:SecureShieldDB",
    ]


def test_documentation_covers_the_required_topics_and_contains_no_secret():
    doc = DOC_PATH.read_text(encoding="utf-8").replace("*", "")
    for needle in (
        "Stage 1.2",
        DEV_DB,
        TEST_DB,
        DEV_OWNER,
        DEV_APP,
        TEST_OWNER,
        "SECURESHIELD_ENV_FILE",
        "TEST_DATABASE_URL",
        "show_database_target",
        "pytest tests/unit",
        "pytest tests/integration",
        "\\password",
        "--single-transaction",
        "Manual removal",
        "not activated",
        "Process environment",
        "never reads",
    ):
        assert needle.lower() in doc.lower(), needle
    assert not re.search(r"://[^:/\s<]+:(?!YOUR_|<password>)[^@\s<]+@", doc)
    assert (
        "on its own" in doc and "backend/.env" in doc
    )  # the backend does not load backend/.env implicitly


# ---- no automatic creation / migration / cleanup, no implicit .env ---------------------------------------------------------------------------
def test_startup_never_creates_databases_migrates_or_deletes():
    main_source = (BACKEND / "app" / "main.py").read_text(encoding="utf-8")
    for forbidden in (
        "create_all(",
        "CREATE DATABASE",
        "alembic",
        "command.upgrade",
        "DELETE FROM",
        "purge_expired",
        "purge_old_error_logs",
    ):
        if forbidden == "alembic":
            continue  # /version only READS the head revision from the script directory
        assert forbidden not in main_source, forbidden
    assert "upgrade" not in main_source.lower().replace("upgrade-insecure", "")
    database_source = (BACKEND / "app" / "database.py").read_text(encoding="utf-8")
    assert "create_all" not in database_source


def test_no_implicit_env_file_loading_has_returned():
    from app.config import Settings, _resolve_env_files

    assert Settings.model_config.get("env_file") is None
    assert os.environ.get("SECURESHIELD_ENV_FILE") is None
    assert _resolve_env_files() == ()
    for rel in (
        "app/config.py",
        "alembic/env.py",
        "app/database.py",
        "app/db_identity.py",
    ):
        source = (BACKEND / rel).read_text(encoding="utf-8")
        assert "load_dotenv" not in source and "dotenv_values" not in source, rel
    assert 'str(_BACKEND_DIR / ".env")' not in (
        BACKEND / "app" / "config.py"
    ).read_text(encoding="utf-8").replace('_BACKEND_DIR / ".env").exists()', "")


def test_alembic_uses_only_the_selected_configuration():
    env_py = (BACKEND / "alembic" / "env.py").read_text(encoding="utf-8")
    assert (
        "settings.MIGRATOR_DATABASE_URL" in env_py
        and "validate_identity(settings)" in env_py
    )
    ini = (BACKEND / "alembic.ini").read_text(encoding="utf-8")
    assert re.search(
        r"sqlalchemy\.url\s*=\s*driver://user:pass@localhost/dbname", ini
    )  # an inert placeholder; env.py overrides it


@pytest.mark.parametrize(
    "drop,expected",
    [
        (("DATABASE_URL", "MIGRATOR_DATABASE_URL"), "DATABASE_URL"),
        (("DATABASE_ENVIRONMENT",), "DATABASE_ENVIRONMENT"),
    ],
)
def test_missing_database_configuration_fails_safely_in_a_fresh_process(drop, expected):
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in drop and k != "SECURESHIELD_ENV_FILE"
    }
    code = (
        "import app.database"
        if drop == ("DATABASE_ENVIRONMENT",)
        else "import app.config"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
    )
    assert out.returncode != 0 and expected in out.stderr
    assert "SENTINEL" not in out.stderr


def test_a_missing_test_url_skips_integration_tests_and_never_falls_back():
    from tests.integration import conftest as harness

    assert harness._test_url() is None  # the unit run has no TEST_DATABASE_URL
    markers = []

    class Item:
        keywords = {"integration": True}

        def add_marker(self, marker):
            markers.append(marker)

    harness.pytest_collection_modifyitems(None, [Item()])
    assert (
        len(markers) == 1 and "TEST_DATABASE_URL not set" in markers[0].kwargs["reason"]
    )
    root = (BACKEND / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert (
        '_test_db_url = os.environ.get("TEST_DATABASE_URL", "").strip() or _DUMMY_DB'
        in root
    )
    assert "localhost/test" in root  # the dummy never names a real database
    for rel in ("tests/conftest.py", "tests/integration/conftest.py"):
        source = (BACKEND / rel).read_text(encoding="utf-8")
        assert not re.search(
            r"TEST_DATABASE_URL\s*[\"']?\]?\s*=\s*.*DATABASE_URL",
            source.replace('TEST_DATABASE_URL", "")', ""),
        ), rel


# ---- the verification command ----------------------------------------------------------------------------------------------------------------
def _run(settings, *args):
    out = io.StringIO()
    code = cli.run(list(args), settings=settings, out=out)
    return code, out.getvalue()


def _dev_settings(**kw):
    values = _local_block()
    return _settings(
        DATABASE_URL=values["DATABASE_URL"],
        MIGRATOR_DATABASE_URL=values["MIGRATOR_DATABASE_URL"],
        **kw,
    )


def test_target_report_for_development_makes_no_connection_and_shows_no_secret():
    code, text = _run(_dev_settings(), "--expect", "development")
    assert code == 0
    for needle in (
        f"database             : {DEV_DB}",
        DEV_APP,
        DEV_OWNER,
        "class=loopback",
        "none made by this command",
    ):
        assert needle in text
    assert (
        "YOUR_" not in text
        and "://" not in text
        and "password" not in text.lower().replace("password)", "")
    )


def test_target_report_for_test_environment_and_cross_expectations():
    url = _commented_test_url()
    test = _settings(
        ENVIRONMENT="test",
        DATABASE_ENVIRONMENT="test",
        DATABASE_URL=url,
        MIGRATOR_DATABASE_URL=url,
    )
    assert _run(test, "--expect", "test")[0] == 0
    code, text = _run(test, "--expect", "development")
    assert code == 1 and "PROBLEM" in text
    code, text = _run(_dev_settings(), "--expect", "test")
    assert code == 1 and "PROBLEM" in text


def test_target_report_flags_a_shared_role_and_a_wrong_database_name():
    values = _local_block()
    same_role = _settings(
        DATABASE_URL=values["MIGRATOR_DATABASE_URL"],
        MIGRATOR_DATABASE_URL=values["MIGRATOR_DATABASE_URL"],
    )
    code, text = _run(same_role)
    assert code == 1 and "SAME role" in text
    other = values["DATABASE_URL"].replace(DEV_DB, "scratch")
    code, text = _run(
        _settings(
            DATABASE_URL=other,
            MIGRATOR_DATABASE_URL=values["MIGRATOR_DATABASE_URL"].replace(
                DEV_DB, "scratch"
            ),
        ),
        "--expect",
        "development",
    )
    assert code == 1 and "ending in '_dev'" in text


@pytest.mark.parametrize(
    "overrides",
    [
        dict(
            DATABASE_URL="postgresql+asyncpg://u:p@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/x_dev",
            MIGRATOR_DATABASE_URL="postgresql+asyncpg://u:p@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/x_dev",
        ),
        dict(
            DATABASE_URL=f"postgresql+asyncpg://u:p@localhost/{PROD_DB}",
            MIGRATOR_DATABASE_URL=f"postgresql+asyncpg://u:p@localhost/{PROD_DB}",
        ),
        dict(
            DATABASE_URL="postgresql+asyncpg://u:p@db.example.com/x_dev",
            MIGRATOR_DATABASE_URL="postgresql+asyncpg://u:p@db.example.com/x_dev",
        ),
        dict(DATABASE_ENVIRONMENT="production"),
    ],
)
def test_target_report_refuses_unsafe_targets_with_exit_2(overrides):
    base = dict(
        DATABASE_URL=_local_block()["DATABASE_URL"],
        MIGRATOR_DATABASE_URL=_local_block()["MIGRATOR_DATABASE_URL"],
    )
    base.update(overrides)
    code, text = _run(_settings(**base))
    assert (
        code == 2
        and text.startswith("REFUSED")
        and "://" not in text
        and "neon" not in text
    )


def test_target_report_rejects_bad_arguments():
    out = io.StringIO()
    assert cli.run(["--expect", "production"], settings=_dev_settings(), out=out) == 2


# ---- Stage 1.2A review corrections --------------------------------------------------------------------------------------------------------------
def test_sql_file_is_pure_ascii_with_unix_line_endings():
    raw = SQL_PATH.read_bytes()
    assert all(b < 128 for b in raw), (
        "non-ASCII byte: a Windows console client_encoding could corrupt it"
    )
    assert b"\r" not in raw


def test_password_presence_is_read_from_pg_authid_not_the_masked_pg_roles_view():
    sql = _executable_sql()
    verification = sql[sql.index("SELECT r.rolname") :]
    assert (
        "FROM pg_authid r" in verification and "rolpassword IS NOT NULL" in verification
    )
    assert (
        "rolpassword AS" not in verification and "r.rolpassword," not in verification
    )  # the hash itself is never selected
    assert "FROM pg_hba_file_rules" in sql and "auth_method = 'trust'" in sql


def test_psql_script_has_no_unbalanced_dollar_quotes_or_stray_transaction_commands():
    text = _executable_sql()
    assert (
        text.count("$$") % 2 == 0 and text.count("$$") == 8
    )  # four DO blocks (precheck, create roles, check roles, ownership), each opened and closed
    assert not re.search(
        r"\bSAVEPOINT\b|\bPREPARE\s+TRANSACTION\b|\bSET\s+SESSION\b|\bSET\s+ROLE\b",
        text,
        flags=re.IGNORECASE,
    )
    assert (
        len(re.findall(r"^BEGIN;$", text, flags=re.MULTILINE)) == 4
        and len(re.findall(r"^COMMIT;$", text, flags=re.MULTILINE)) == 4
    )


# ---- Stage 1.2B: the activation runbook must stay in step with the SQL it describes ------------------------------------------------------------------
RUNBOOK = (
    BACKEND / "docs" / "audits" / "STAGE_1_2B_LOCAL_DATABASE_ACTIVATION_RUNBOOK.md"
)


def test_runbook_pins_the_exact_reviewed_sql_file():
    import hashlib

    digest = hashlib.sha256(SQL_PATH.read_bytes()).hexdigest().upper()
    text = RUNBOOK.read_text(encoding="utf-8")
    assert text.count(digest) == 2, (
        "the runbook must state the SHA-256 of the current SQL file (edit the SQL => re-review and update the runbook)"
    )
    assert f"{len(SQL_PATH.read_text(encoding='utf-8').splitlines())} lines" in text
    lines = SQL_PATH.read_text(encoding="utf-8").splitlines()
    assert [
        i + 1
        for i, line in enumerate(lines)
        if re.search(r"DROP|TRUNCATE|PASSWORD '", line)
    ] == [10, 192]
    assert "must print exactly 10 and 192" in text


def test_runbook_part_ranges_match_the_part_boundaries_of_the_sql():
    lines = SQL_PATH.read_text(encoding="utf-8").splitlines()
    text = RUNBOOK.read_text(encoding="utf-8")
    ranges = {
        "part0": (71, 98),
        "part1": (100, 143),
        "part2": (145, 169),
        "part3": (171, 186),
        "part4": (188, 218),
        "part5": (220, 293),
    }
    for name, (a, b) in ranges.items():
        assert f"{name}=@({a},{b})" in text, name
    assert lines[66].startswith("\set ON_ERROR_STOP") and lines[68].startswith(
        "\set AUTOCOMMIT"
    )  # the shared preamble (lines 67-69)
    headings = {
        0: "Part 0 -",
        1: "Part 1 -",
        2: "Part 2 -",
        3: "Part 3 -",
        4: "Part 4 -",
        5: "Part 5 -",
    }
    for part, (a, b) in enumerate(ranges.values()):
        assert set(lines[a - 1]) == {"-", " "} or lines[a - 1].startswith("-- ---"), (
            part
        )  # starts at the dashed rule above the heading
        assert headings[part] in lines[a], part  # followed by its heading
        assert lines[a - 2].strip() == "" or part == 0, (
            part
        )  # preceded by a blank separator
    assert (
        lines[97] == "$$;"
        and lines[142] == "COMMIT;"
        and lines[168] == "$$;"
        and lines[185] == "COMMIT;"
        and lines[217] == "\connect postgres"
    )
    for gap in (98, 143, 169, 186, 218):
        assert lines[gap].strip() == "", (
            gap
        )  # the single line between two parts is blank, so nothing is lost by the cut


def test_runbook_commands_are_local_only_and_never_destructive():
    text = RUNBOOK.read_text(encoding="utf-8")
    commands = "\n".join(
        block for block in re.findall(r"```(?:powershell)?\n(.*?)```", text, flags=re.S)
    )
    commands = "\n".join(
        line for line in commands.splitlines() if "Select-String" not in line
    )  # the 1.7 check LOOKS FOR these words
    assert not re.search(
        r"\bDROP\b|\bTRUNCATE\b|\bDELETE\s+FROM\b|ALTER\s+SYSTEM|--single-transaction|\s-1\s",
        commands,
        flags=re.IGNORECASE,
    )
    assert "neon.tech" not in commands.lower() and "railway" not in commands.lower()
    assert "rolpassword IS NOT NULL" in commands and not re.search(
        r"SELECT[^;\"]*\brolpassword\b(?!\s+IS)", commands
    )  # never selects a hash
    for host in set(re.findall(r"-h\s+(\S+)", commands)):
        assert host.strip("'\",") == "localhost", host
    assert "pending your execution and approval" in text
