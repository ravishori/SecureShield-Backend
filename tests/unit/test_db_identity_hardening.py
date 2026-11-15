"""Adversarial database-URL tests for the identity check (review findings H1, L1, L2, M3). No connection is ever opened."""

import asyncio
from types import SimpleNamespace

import pytest

from app import db_identity
from app.db_identity import (
    PROHIBITED_QUERY_KEYS,
    DatabaseIdentityError,
    endpoint_id,
    parse_endpoint,
    validate_identity,
    verify_connected_database,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]

PROD_HOST = "ep-cool-silence-aohbh87f.c-2.ap-southeast-1.aws.neon.tech"
PROD_POOLED = "ep-cool-silence-aohbh87f-pooler.c-2.ap-southeast-1.aws.neon.tech"
LOCAL = "postgresql+asyncpg://u:SENTINEL-PW@localhost:5432/secureshield_dev"


def S(url=LOCAL, **kw):
    base = dict(
        ENVIRONMENT="development",
        DATABASE_ENVIRONMENT="local",
        DATABASE_URL=url,
        MIGRATOR_DATABASE_URL=url,
        PRODUCTION_DATABASE_ENDPOINTS="",
        DEV_DATABASE_ALLOWED_HOSTS="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _refused(url, **kw):
    with pytest.raises(DatabaseIdentityError) as info:
        validate_identity(S(url, **kw))
    text = str(info.value) + repr(info.value.args)
    assert "SENTINEL-PW" not in text and "neon.tech" not in text and "://" not in text
    return info.value


# ---- H1: connection-routing query parameters ---------------------------------------------------------------------------
@pytest.mark.parametrize("key", sorted(PROHIBITED_QUERY_KEYS))
@pytest.mark.parametrize("spelling", ["{k}", "{K}", "{pct}"])
def test_h1_every_routing_parameter_is_refused_in_any_spelling(key, spelling):
    spelled = spelling.format(
        k=key, K=key.upper(), pct="%" + format(ord(key[0]), "02x") + key[1:]
    )
    err = _refused(f"{LOCAL}?{spelled}={PROD_HOST}")
    assert "routing query parameter" in str(err)


def test_h1_the_original_bypass_is_closed_for_every_environment():
    url = f"postgresql+asyncpg://u:SENTINEL-PW@localhost/secureshield_dev?host={PROD_HOST}"
    for env, denv in [
        ("development", "local"),
        ("test", "test"),
        ("staging", "staging"),
        ("production", "production"),
    ]:
        with pytest.raises(DatabaseIdentityError, match="routing query parameter"):
            validate_identity(S(url, ENVIRONMENT=env, DATABASE_ENVIRONMENT=denv))


def test_h1_port_and_database_overrides_are_refused():
    _refused(f"{LOCAL}?port=6543")
    _refused(f"{LOCAL}?database=SecureShieldDB")
    _refused(f"{LOCAL}?dbname=SecureShieldDB")


def test_h1_repeated_keys_and_mixed_with_benign_options_are_refused():
    _refused(f"{LOCAL}?ssl=require&host=h1&host=h2")
    _refused(f"{LOCAL}?statement_cache_size=0&HOST={PROD_HOST}")


def test_h1_benign_driver_options_are_still_accepted():
    for q in (
        "ssl=require",
        "sslmode=require&channel_binding=require",
        "statement_cache_size=0",
        "ssl=require&command_timeout=30",
    ):
        assert "class=loopback" in validate_identity(S(f"{LOCAL}?{q}"))


def test_h1_effective_driver_arguments_must_match_the_parsed_url(monkeypatch):
    """Defence in depth: even without a prohibited key, a driver that would connect elsewhere is refused."""
    import sqlalchemy.dialects.postgresql.asyncpg as pg

    class Liar(pg.PGDialect_asyncpg):
        def create_connect_args(self, url):
            args, kw = super().create_connect_args(url)
            return args, {**kw, "host": PROD_HOST}

    monkeypatch.setattr(pg, "dialect", Liar)
    with pytest.raises(DatabaseIdentityError, match="does not resolve"):
        parse_endpoint(LOCAL)


# ---- alternate encodings and authority tricks ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        f"postgresql+asyncpg://u:p@localhost:5432@{PROD_HOST}/db",  # second @ in the authority
        f"postgresql+asyncpg://localhost@{PROD_HOST}/db",  # "localhost" is only the user name
        f"postgresql+asyncpg://u:p@{PROD_HOST}%2Flocalhost/db",
        "postgresql+asyncpg://u:p@%6Cocalhost/db",  # percent-encoded host
        "postgresql+asyncpg://u:p@localhost./db",  # trailing dot
        "postgresql+asyncpg://u:p@LOCALHOST.EVIL.EXAMPLE/db",
        "postgresql+asyncpg://u:p@127.1/db",  # short IPv4 forms are not on the loopback list
        "postgresql+asyncpg://u:p@0x7f.0.0.1/db",
        "postgresql+asyncpg://u:p@2130706433/db",
        "postgresql+asyncpg://u:p@[::ffff:127.0.0.1]/db",
        "postgresql+asyncpg://u:p@ｌocalhost/db",  # full-width letter
        "postgresql+asyncpg://u:p@lоcalhost/db",  # Cyrillic o
        "postgresql+asyncpg://u:p@/db",  # no host (unix socket / query-supplied)
        "postgresql+asyncpg://u:p@local host/db",
        "mysql://u:p@localhost/db",
        "",
        "   ",
    ],
)
def test_alternate_encodings_never_pass_as_loopback(url):
    _refused(url)


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST", "127.0.0.1", "[::1]"])
def test_genuine_loopback_spellings_pass(host):
    assert "class=loopback" in validate_identity(
        S(f"postgresql+asyncpg://u:p@{host}:5432/db")
    )


# ---- L1: exact Neon domain, no lookalikes ------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "host",
    [
        "ep-cool-silence-aohbh87f.neon.tech.evil.example",
        "ep-cool-silence-aohbh87f.evil.example",
        "ep-cool-silence-aohbh87f-pooler.evil-neon.tech",
        "ep-cool-silence-aohbh87f.c-2.aws.xneon.tech",
        "ep-cool-silence-aohbh87f",  # bare token as a URL host
        "ep-cool-silence-aohbh87f.neon.tech.",  # trailing dot
        "xep-cool-silence-aohbh87f.c-2.aws.neon.tech",
        "ep-cool-silence-aohbh87f-extra.c-2.aws.neon.tech",
        "EP-COOL-SILENCE-AOHBH87F.EVIL.EXAMPLE",
    ],
)
def test_l1_lookalike_hosts_are_not_the_production_endpoint(host):
    url = f"postgresql+asyncpg://u:SENTINEL-PW@{host}/SecureShieldDB"
    err = _refused(url, ENVIRONMENT="production", DATABASE_ENVIRONMENT="production")
    assert "production must use" in str(err) or "host" in str(err)
    _refused(url)  # and never loopback/allowed in development either


@pytest.mark.parametrize(
    "host",
    [PROD_HOST, PROD_POOLED, PROD_HOST.upper(), PROD_POOLED.replace("c-2", "c-9")],
)
def test_l1_real_endpoint_forms_still_match_and_are_refused_in_development(host):
    url = f"postgresql+asyncpg://u:SENTINEL-PW@{host}/SecureShieldDB"
    with pytest.raises(DatabaseIdentityError, match="production-registry"):
        validate_identity(S(url))
    assert "class=production-registry" in validate_identity(
        S(url, ENVIRONMENT="production", DATABASE_ENVIRONMENT="production")
    )


def test_l1_endpoint_id_rules():
    assert (
        endpoint_id(PROD_POOLED) == endpoint_id(PROD_HOST) == "ep-cool-silence-aohbh87f"
    )
    assert endpoint_id("ep-x.evil.example") == "ep-x.evil.example"
    assert endpoint_id("ep-x", from_entry=True) == "ep-x"
    assert endpoint_id("ep-x-pooler", from_entry=True) == "ep-x"
    assert endpoint_id("ep-x") == "host:ep-x"  # a bare URL host is not a registry id
    assert endpoint_id("ep-x-pooler") == "host:ep-x-pooler"
    assert endpoint_id("DB.Example.COM") == "db.example.com"


# ---- L2: only explicitly approved remote hosts for development/test ------------------------------------------------------------
REMOTE = "ep-dev-branch-123456.c-2.ap-southeast-1.aws.neon.tech"


def test_l2_remote_host_needs_an_exact_allow_list_entry():
    url = f"postgresql+asyncpg://u:p@{REMOTE}/devdb"
    with pytest.raises(DatabaseIdentityError, match="DEV_DATABASE_ALLOWED_HOSTS"):
        validate_identity(S(url))
    assert "class=dev-allowed" in validate_identity(
        S(url, DEV_DATABASE_ALLOWED_HOSTS="ep-dev-branch-123456")
    )
    assert "class=dev-allowed" in validate_identity(
        S(url, DEV_DATABASE_ALLOWED_HOSTS=REMOTE.upper())
    )
    with pytest.raises(DatabaseIdentityError):
        validate_identity(
            S(url, DEV_DATABASE_ALLOWED_HOSTS="ep-dev-branch-1234567")
        )  # near miss
    with pytest.raises(DatabaseIdentityError):
        validate_identity(
            S(
                "postgresql+asyncpg://u:p@ep-dev-branch-123456.evil.example/devdb",
                DEV_DATABASE_ALLOWED_HOSTS="ep-dev-branch-123456",
            )
        )


@pytest.mark.parametrize(
    "entry",
    ["*", "*.neon.tech", "https://x.example", "u@x.example", "two words", "ep-ok,*"],
)
def test_l2_malformed_allow_list_entries_are_refused_not_ignored(entry):
    with pytest.raises(DatabaseIdentityError, match="DEV_DATABASE_ALLOWED_HOSTS"):
        validate_identity(S(DEV_DATABASE_ALLOWED_HOSTS=entry))


@pytest.mark.parametrize("env,denv", [("development", "local"), ("test", "test")])
def test_l2_allow_list_can_never_contain_a_registry_endpoint(env, denv):
    for entry in ("ep-cool-silence-aohbh87f", PROD_POOLED, "ep-small-tooth-aolra8tc"):
        with pytest.raises(DatabaseIdentityError, match="production-registry"):
            validate_identity(
                S(
                    ENVIRONMENT=env,
                    DATABASE_ENVIRONMENT=denv,
                    DEV_DATABASE_ALLOWED_HOSTS=entry,
                )
            )


# ---- M3: read-only current_database() verification with mocked connections ----------------------------------------------------
class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value


class FakeConn:
    def __init__(self, name, log, fail=None):
        self.name, self.log, self.fail = name, log, fail

    async def __aenter__(self):
        if self.fail:
            raise self.fail
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, statement, params=None):
        self.log.append(str(statement))
        return FakeResult(self.name)


class FakeEngine:
    def __init__(self, name="secureshield_dev", fail=None):
        self.log = []
        self._name, self._fail = name, fail

    def connect(self):
        return FakeConn(self._name, self.log, self._fail)


def test_m3_matching_database_passes_and_only_reads_current_database():
    engine = FakeEngine("secureshield_dev")
    asyncio.run(verify_connected_database(S(), engine))
    assert engine.log == ["SELECT current_database()"]


@pytest.mark.parametrize(
    "actual",
    ["SecureShieldDB", "postgres", "", "SECURESHIELD_DEV", "secureshield_dev "],
)
def test_m3_mismatched_database_name_is_refused(actual):
    with pytest.raises(DatabaseIdentityError, match="connected database name"):
        asyncio.run(verify_connected_database(S(), FakeEngine(actual)))


def test_m3_connection_failures_propagate_so_startup_fails_closed():
    with pytest.raises(ConnectionRefusedError):
        asyncio.run(
            verify_connected_database(
                S(), FakeEngine(fail=ConnectionRefusedError("boom"))
            )
        )


def test_m3_a_hung_connection_times_out():
    class Hang(FakeEngine):
        def connect(self):
            class C:
                async def __aenter__(self_):
                    await asyncio.sleep(5)

                async def __aexit__(self_, *a):
                    return False

            return C()

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(verify_connected_database(S(), Hang(), timeout=0.05))


def test_m3_the_check_uses_the_application_engine_by_default(monkeypatch):
    engine = FakeEngine("secureshield_dev")
    monkeypatch.setattr("app.database.engine", engine)
    asyncio.run(verify_connected_database(S()))
    assert engine.log


def test_m3_module_is_settings_free_at_import():
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(db_identity.__file__).read_text(encoding="utf-8"))
    top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = {getattr(n, "module", None) or a.name for n in top for a in n.names} | {
        getattr(n, "module", "") for n in top
    }
    assert (
        "app.config" not in names
    )  # scripts import this module without a full environment
