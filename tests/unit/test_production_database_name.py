"""The production database NAME is refused outside production on any host (final review finding M-3), plus PGPORT/PGDATABASE
regressions (item 8). Loopback, SSH tunnels and port forwards all look like ``localhost``; only the database name tells."""

import os
from types import SimpleNamespace

import pytest

from app.db_identity import (
    DatabaseIdentityError,
    check_connected_database_name,
    load_production_database_names,
    parse_endpoint,
    validate_identity,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]

PROD_HOST = "ep-cool-silence-aohbh87f-pooler.c-2.ap-southeast-1.aws.neon.tech"


def S(url, environment="development", denv="local", **kw):
    base = dict(
        ENVIRONMENT=environment,
        DATABASE_ENVIRONMENT=denv,
        DATABASE_URL=url,
        MIGRATOR_DATABASE_URL=url,
        PRODUCTION_DATABASE_ENDPOINTS="",
        DEV_DATABASE_ALLOWED_HOSTS="",
        PRODUCTION_DATABASE_NAMES="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


SCENARIOS = {
    "plain loopback": "postgresql+asyncpg://u:p@localhost:5432/SecureShieldDB",
    "ipv4 loopback": "postgresql+asyncpg://u:p@127.0.0.1:5432/SecureShieldDB",
    "ipv6 loopback": "postgresql+asyncpg://u:p@[::1]:5432/SecureShieldDB",
    "ssh tunnel on a high port": "postgresql+asyncpg://u:p@localhost:15432/SecureShieldDB",
    "ssh tunnel reusing 5433": "postgresql+asyncpg://u:p@127.0.0.1:5433/SecureShieldDB",
    "port forward to the pooler port": "postgresql+asyncpg://u:p@localhost:6543/SecureShieldDB",
    "no port at all": "postgresql+asyncpg://u:p@localhost/SecureShieldDB",
    "lower case": "postgresql+asyncpg://u:p@localhost:5432/secureshielddb",
    "upper case": "postgresql+asyncpg://u:p@localhost:5432/SECURESHIELDDB",
    "with ssl options": "postgresql+asyncpg://u:p@localhost:5432/SecureShieldDB?ssl=require&statement_cache_size=0",
    "libpq url form": "postgres://u:p@localhost:5432/SecureShieldDB?sslmode=require",
    "unlisted remote host (allow-listed)": "postgresql+asyncpg://u:p@ep-dev-branch-123456.c-2.aws.neon.tech/SecureShieldDB",
}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
@pytest.mark.parametrize(
    "environment,denv",
    [("development", "local"), ("test", "test"), ("staging", "staging")],
)
def test_production_database_name_is_refused_outside_production(
    scenario, environment, denv
):
    url = SCENARIOS[scenario]
    with pytest.raises(DatabaseIdentityError, match="production database name") as info:
        validate_identity(
            S(url, environment, denv, DEV_DATABASE_ALLOWED_HOSTS="ep-dev-branch-123456")
        )
    assert "SecureShieldDB".lower() not in str(
        info.value
    ).lower() or "database name" in str(info.value)
    assert "localhost" not in str(info.value) and "://" not in str(info.value)


def test_registry_host_with_the_production_name_keeps_the_more_specific_registry_message():
    url = f"postgresql+asyncpg://u:p@{PROD_HOST}/SecureShieldDB"
    with pytest.raises(DatabaseIdentityError, match="production-registry"):
        validate_identity(S(url))


def test_production_with_the_registry_endpoint_and_name_still_passes():
    url = f"postgresql+asyncpg://u:p@{PROD_HOST}/SecureShieldDB"
    assert "class=production-registry" in validate_identity(
        S(url, "production", "production")
    )


@pytest.mark.parametrize(
    "name",
    [
        "secureshield_dev",
        "secureshield_test",
        "SecureShieldDB_test",
        "SecureShieldDBx",
        "xSecureShieldDB",
        "secure_shield",
    ],
)
def test_other_local_names_are_not_affected(name):
    assert "class=loopback" in validate_identity(
        S(f"postgresql+asyncpg://u:p@localhost:5432/{name}")
    )


def test_additional_production_names_from_settings_and_environment():
    url = "postgresql+asyncpg://u:p@localhost/AuditDB"
    assert "class=loopback" in validate_identity(S(url))
    with pytest.raises(DatabaseIdentityError, match="production database name"):
        validate_identity(S(url, PRODUCTION_DATABASE_NAMES="auditdb , other"))
    assert load_production_database_names("auditdb") >= {"auditdb", "secureshielddb"}


@pytest.mark.parametrize("bad", ["a b", "x;drop", "a/b", "", "n" * 80])
def test_malformed_production_name_settings_are_refused(bad):
    if bad == "":
        assert "secureshielddb" in load_production_database_names(bad)
    else:
        with pytest.raises(DatabaseIdentityError):
            load_production_database_names(bad)


def test_runtime_check_refuses_a_production_named_database_outside_production():
    settings = S("postgresql+asyncpg://u:p@localhost/secureshield_dev")
    check_connected_database_name("secureshield_dev", settings)
    # the URL says "secureshield_dev" but the server answers with the production name: a tunnel/port-forward mix-up
    with pytest.raises(DatabaseIdentityError):
        check_connected_database_name("SecureShieldDB", settings)
    pointing_at_prod = S(
        "postgresql+asyncpg://u:p@localhost/SecureShieldDB"
    )  # (cannot pass validate_identity; defence in depth)
    with pytest.raises(DatabaseIdentityError, match="production database name"):
        check_connected_database_name("SecureShieldDB", pointing_at_prod)
    prod = S(
        "postgresql+asyncpg://u:p@localhost/SecureShieldDB", "production", "production"
    )
    check_connected_database_name("SecureShieldDB", prod)


# ---- PGPORT / PGDATABASE / PGHOST must not change a validated destination ------------------------------------------------------
@pytest.fixture
def hostile_pg_environment(monkeypatch):
    monkeypatch.setenv("PGPORT", "6543")
    monkeypatch.setenv("PGHOST", "attacker.example")
    monkeypatch.setenv("PGDATABASE", "SecureShieldDB")
    monkeypatch.setenv("PGUSER", "someone")


def _asyncpg_destination(kwargs):
    """What asyncpg would really connect to (its own pure parser; no socket is opened)."""
    from asyncpg import connect_utils

    base = dict(
        dsn=None,
        host=None,
        port=None,
        user=None,
        password=None,
        passfile=None,
        database=None,
        ssl=None,
        direct_tls=None,
        server_settings=None,
        target_session_attrs=None,
    )
    base.update({k: v for k, v in kwargs.items() if k in base})
    addrs, params = connect_utils._parse_connect_dsn_and_args(**base)
    return addrs, params.database


def test_documented_hazard_a_missing_port_or_database_is_filled_from_the_environment(
    hostile_pg_environment,
):
    """Evidence for the fix below: with a missing port/database asyncpg trusts PGPORT / PGDATABASE."""
    addrs, database = _asyncpg_destination(
        dict(host="localhost", user="u", password="p", database="dev")
    )
    assert addrs == [("localhost", 6543)]
    assert (
        _asyncpg_destination(dict(host="localhost", port=5432, user="u", password="p"))[
            1
        ]
        == "SecureShieldDB"
    )


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:p@localhost/secureshield_dev",
        "postgres://u:p@localhost/secureshield_dev?sslmode=require",
        "postgresql+asyncpg://u:p@localhost/secureshield_dev?ssl=require&statement_cache_size=0",
    ],
)
def test_build_async_engine_pins_the_port_so_pgport_cannot_redirect(
    hostile_pg_environment, monkeypatch, url
):
    import app.database as database

    captured = {}

    def fake_create(clean_url, **kwargs):
        captured.update(url=clean_url, **kwargs)
        return object()

    monkeypatch.setattr(database, "create_async_engine", fake_create)
    from app.config import normalize_async_db_url

    database.build_async_engine(normalize_async_db_url(url))
    args = captured["connect_args"]
    assert args["port"] == 5432
    addrs, database_name = _asyncpg_destination(
        dict(
            host="localhost",
            user="u",
            password="p",
            database="secureshield_dev",
            port=args["port"],
        )
    )
    assert addrs == [("localhost", 5432)] and database_name == "secureshield_dev"


def test_an_explicit_port_in_the_url_is_left_alone(monkeypatch):
    import app.database as database

    captured = {}
    monkeypatch.setattr(
        database,
        "create_async_engine",
        lambda clean_url, **kw: captured.update(kw) or object(),
    )
    database.build_async_engine(
        "postgresql+asyncpg://u:p@localhost:5433/secureshield_dev"
    )
    assert "port" not in captured.get("connect_args", {})


def test_an_url_without_a_database_is_refused_so_pgdatabase_is_never_used(
    hostile_pg_environment,
):
    for url in (
        "postgresql+asyncpg://u:p@localhost",
        "postgresql+asyncpg://u:p@localhost/",
        "postgresql+asyncpg://u:p@localhost:5432",
    ):
        with pytest.raises(DatabaseIdentityError, match="names no database"):
            parse_endpoint(url)


def test_validated_host_is_always_explicit_so_pghost_is_never_used(
    hostile_pg_environment,
):
    with pytest.raises(DatabaseIdentityError, match="no host"):
        parse_endpoint("postgresql+asyncpg://u:p@/secureshield_dev")
    assert (
        parse_endpoint("postgresql+asyncpg://u:p@localhost/secureshield_dev").host
        == "localhost"
    )
    assert (
        os.environ["PGHOST"] == "attacker.example"
    )  # the hostile variables stay in place for the whole test
