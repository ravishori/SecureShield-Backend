"""Database identity validation (Stage 1.1). No database connection is ever opened by these tests."""

import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.db_identity import (
    REGISTRY_PATH,
    DatabaseIdentityError,
    check_connected_database_name,
    endpoint_id,
    parse_endpoint,
    validate_identity,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]

PROD_POOLED = "postgresql+asyncpg://app_role:SENTINEL-PW@ep-cool-silence-aohbh87f-pooler.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB?ssl=require"
PROD_DIRECT = "postgresql+asyncpg://mig_role:SENTINEL-PW@ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB?ssl=require"
RECOVERY = "postgresql+asyncpg://u:SENTINEL-PW@ep-small-tooth-aolra8tc-pooler.c-2.ap-southeast-1.aws.neon.tech/SecureShieldDB"
LOCAL = "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/secureshield_dev"
OTHER_NEON = (
    "postgresql+asyncpg://u:SENTINEL-PW@ep-some-other-123456.c-2.aws.neon.tech/otherdb"
)


def S(**kw):
    base = dict(
        ENVIRONMENT="development",
        DATABASE_ENVIRONMENT="local",
        DATABASE_URL=LOCAL,
        MIGRATOR_DATABASE_URL=LOCAL,
        PRODUCTION_DATABASE_ENDPOINTS="",
        DEV_DATABASE_ALLOWED_HOSTS="",
        RETENTION_CLEANUP_ENABLED=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_i1_development_loopback_passes():
    assert "class=loopback" in validate_identity(S())


def test_i2_development_remote_neon_not_in_registry_refused():
    with pytest.raises(DatabaseIdentityError, match="loopback"):
        validate_identity(S(DATABASE_URL=OTHER_NEON, MIGRATOR_DATABASE_URL=OTHER_NEON))


@pytest.mark.parametrize("url", [PROD_POOLED, PROD_DIRECT, RECOVERY])
def test_i3_development_registry_host_refused_in_either_form(url):
    with pytest.raises(DatabaseIdentityError, match="production-registry"):
        validate_identity(S(DATABASE_URL=url, MIGRATOR_DATABASE_URL=url))


@pytest.mark.parametrize(
    "env,denv", [("development", "local"), ("test", "test"), ("staging", "staging")]
)
def test_i4_registry_wins_over_dev_allow_list_and_every_non_prod_env(env, denv):
    with pytest.raises(DatabaseIdentityError, match="production-registry"):
        validate_identity(
            S(
                ENVIRONMENT=env,
                DATABASE_ENVIRONMENT=denv,
                DATABASE_URL=RECOVERY,
                MIGRATOR_DATABASE_URL=RECOVERY,
                DEV_DATABASE_ALLOWED_HOSTS="ep-small-tooth-aolra8tc",
            )
        )


def test_i5_production_registry_host_passes():
    line = validate_identity(
        S(
            ENVIRONMENT="production",
            DATABASE_ENVIRONMENT="production",
            DATABASE_URL=PROD_POOLED,
            MIGRATOR_DATABASE_URL=PROD_DIRECT,
        )
    )
    assert "class=production-registry" in line


@pytest.mark.parametrize("url", [LOCAL, OTHER_NEON])
def test_i6_production_unlisted_or_loopback_refused(url):
    with pytest.raises(DatabaseIdentityError, match="production must use"):
        validate_identity(
            S(
                ENVIRONMENT="production",
                DATABASE_ENVIRONMENT="production",
                DATABASE_URL=url,
                MIGRATOR_DATABASE_URL=url,
            )
        )


def test_i7_staging_registry_host_refused_but_own_host_passes():
    with pytest.raises(DatabaseIdentityError):
        validate_identity(
            S(
                ENVIRONMENT="staging",
                DATABASE_ENVIRONMENT="staging",
                DATABASE_URL=PROD_POOLED,
                MIGRATOR_DATABASE_URL=PROD_DIRECT,
            )
        )
    assert "class=staging" in validate_identity(
        S(
            ENVIRONMENT="staging",
            DATABASE_ENVIRONMENT="staging",
            DATABASE_URL=OTHER_NEON,
            MIGRATOR_DATABASE_URL=OTHER_NEON,
        )
    )


@pytest.mark.parametrize(
    "env,denv",
    [
        ("development", "production"),
        ("production", "local"),
        ("test", "local"),
        ("development", "test"),
    ],
)
def test_i8_environment_disagreement_refused(env, denv):
    with pytest.raises(DatabaseIdentityError, match="does not match"):
        validate_identity(S(ENVIRONMENT=env, DATABASE_ENVIRONMENT=denv))


def test_i9_runtime_and_migrator_must_share_endpoint_and_database():
    with pytest.raises(DatabaseIdentityError, match="same endpoint"):
        validate_identity(S(DATABASE_URL=LOCAL, MIGRATOR_DATABASE_URL=OTHER_NEON))
    other_db = LOCAL.replace("secureshield_dev", "another_db")
    with pytest.raises(DatabaseIdentityError, match="same endpoint"):
        validate_identity(S(DATABASE_URL=LOCAL, MIGRATOR_DATABASE_URL=other_db))


@pytest.mark.parametrize("value", ["", None, "  "])
def test_i10_database_environment_required(value):
    with pytest.raises(DatabaseIdentityError, match="DATABASE_ENVIRONMENT must be set"):
        validate_identity(S(DATABASE_ENVIRONMENT=value))


@pytest.mark.parametrize("value", ["prod", "nope", "", "Prod-uction"])
def test_i11_unknown_environment_refused(value):
    with pytest.raises(DatabaseIdentityError, match="ENVIRONMENT must be one of"):
        validate_identity(S(ENVIRONMENT=value))


def test_i12_no_message_log_or_exception_leaks_url_or_password(caplog):
    caplog.set_level(logging.DEBUG)
    cases = [
        S(DATABASE_URL=PROD_POOLED, MIGRATOR_DATABASE_URL=PROD_DIRECT),
        S(DATABASE_URL=OTHER_NEON, MIGRATOR_DATABASE_URL=OTHER_NEON),
        S(
            DATABASE_URL="postgresql://u:SENTINEL-PW@:::bad",
            MIGRATOR_DATABASE_URL=LOCAL,
        ),
        S(DATABASE_URL="not a url SENTINEL-PW", MIGRATOR_DATABASE_URL=LOCAL),
        S(ENVIRONMENT="production", DATABASE_ENVIRONMENT="production"),
    ]
    for settings in cases:
        with pytest.raises(DatabaseIdentityError) as info:
            validate_identity(settings)
        text = str(info.value) + repr(info.value) + "".join(map(str, info.value.args))
        assert "SENTINEL-PW" not in text
        assert "neon.tech" not in text and "localhost" not in text and "://" not in text
        assert info.value.__cause__ is None
        assert (
            info.value.__context__ is None or info.value.__suppress_context__
        )  # no parser error chained
    ok = validate_identity(S())
    assert "SENTINEL-PW" not in ok and "localhost" not in ok
    assert "SENTINEL-PW" not in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "postgres://u:p@ep-x-1.c-2.aws.neon.tech/db",
        "postgresql://u:p@ep-x-1.c-2.aws.neon.tech:5432/db?sslmode=require",
        "postgresql+asyncpg://u:p@ep-x-1.c-2.aws.neon.tech/db?ssl=require&statement_cache_size=0",
        "postgres://u:p@EP-X-1-pooler.c-2.aws.neon.tech/db?sslmode=require&channel_binding=require",
    ],
)
def test_i13_url_forms_parse_to_the_same_endpoint(url):
    ep = parse_endpoint(url)
    assert ep.endpoint_id == "ep-x-1" and ep.database == "db"


def test_i14_connected_database_name_mismatch_refused():
    settings = S()
    check_connected_database_name("secureshield_dev", settings)
    with pytest.raises(DatabaseIdentityError, match="connected database"):
        check_connected_database_name("SecureShieldDB", settings)


def _function_body(source: str, name: str) -> str:
    start = source.index(f"def {name}(")
    match = re.search(r"\n(?:async )?def ", source[start + 1 :])
    return source[start : start + 1 + match.start()] if match else source[start:]


def test_i15_alembic_validates_identity_before_any_engine_or_migration():
    source = (Path(__file__).resolve().parents[2] / "alembic" / "env.py").read_text(
        encoding="utf-8"
    )
    offline = _function_body(source, "run_migrations_offline")
    assert offline.index("validate_identity(settings)") < offline.index(
        "context.configure("
    )
    online = _function_body(source, "run_async_migrations")
    assert online.index("validate_identity(settings)") < online.index(
        "async_engine_from_config("
    )
    # M3: the connected database name is read-only checked before the first migration statement
    assert online.index(
        "check_connected_database_name(actual, settings)"
    ) < online.index("run_sync(do_run_migrations)")
    assert "SELECT current_database()" in online


def test_database_module_validates_before_building_the_engine():
    source = (Path(__file__).resolve().parents[2] / "app" / "database.py").read_text(
        encoding="utf-8"
    )
    assert source.index("validate_identity(settings)") < source.index(
        "engine = build_async_engine("
    )


def test_committed_registry_protects_active_production_and_recovery_endpoints():
    ids = {
        endpoint_id(line.split("#")[0].strip(), from_entry=True)
        for line in REGISTRY_PATH.read_text(encoding="utf-8").splitlines()
        if line.split("#")[0].strip()
    }
    assert {"ep-cool-silence-aohbh87f", "ep-small-tooth-aolra8tc"} <= ids
    text = REGISTRY_PATH.read_text(encoding="utf-8")
    assert "://" not in text and "@" not in text  # identifiers only
