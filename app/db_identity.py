"""Database identity validation and the retention gate (Stage 1.1, hardened).

Purpose: make it impossible for a development, test or staging process to talk to a production-class database, and for
retention to DELETE rows unless an operator has said so explicitly.

* The registry of production-class endpoints (``config/production_endpoints.txt`` plus the optional
  ``PRODUCTION_DATABASE_ENDPOINTS`` variable, which can only ADD entries) is required in every environment.
* ``validate_identity`` is called before any application or Alembic engine is built. It reads only the registry file and never
  opens a database connection. ``verify_connected_database`` is the separate, read-only ``current_database()`` check that
  runs after the engine exists.
* A URL is accepted only if the host it NAMES is the host the driver would CONNECT to: connection-routing query parameters
  (``host``, ``port``, ``database`` ...) are refused and the effective driver arguments are compared with the parsed URL.
* A Neon endpoint is recognised only on the exact ``.neon.tech`` domain; lookalike domains never match a registry entry.
* The production DATABASE NAME (``database:SecureShieldDB`` in the registry file, plus ``PRODUCTION_DATABASE_NAMES``) is refused
  outside production whatever the host is: loopback, an SSH tunnel and a port forward all look like ``localhost``, so the host
  alone cannot protect production.
* A URL must name its target completely: an empty database is refused, and ``build_async_engine`` pins the port, because asyncpg
  otherwise fills a missing port/database from ``PGPORT``/``PGDATABASE`` in the process environment.
* Messages name variables and rules only. They never contain a URL, user name, password or host.

This module is deliberately free of ``Settings`` imports (the retention gate imports it lazily) so operator scripts can use it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.db_url import normalize_async_db_url

logger = logging.getLogger(__name__)

REGISTRY_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "production_endpoints.txt"
)

ENVIRONMENTS = ("development", "test", "staging", "production")
DATABASE_ENVIRONMENTS = ("local", "test", "staging", "production")
_EXPECTED_DATABASE_ENVIRONMENT = {
    "development": "local",
    "test": "test",
    "staging": "staging",
    "production": "production",
}
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_NEON_SUFFIX = ".neon.tech"
_FORBIDDEN_ENTRY = re.compile(r"(://|@|\s|\*)")
_HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
_IPV6 = re.compile(r"^[0-9a-f:]+$")
_BARE_NEON_ID = re.compile(r"^ep-[a-z0-9-]+$")
# Query parameters that would make the driver connect somewhere other than the host/port/database the URL names (SQLAlchemy
# passes every query key to asyncpg.connect). Refused in any spelling/case/percent-encoding (the query is decoded first).
PROHIBITED_QUERY_KEYS = frozenset(
    {
        "host",
        "hostaddr",
        "port",
        "database",
        "dbname",
        "user",
        "username",
        "password",
        "passfile",
        "service",
        "servers",
        "dsn",
        "target_session_attrs",
    }
)
SCRIPT_CONFIRM_VARIABLE = (
    "SECURESHIELD_CONFIRM_PRODUCTION_READ"  # comma-separated tokens
)
SCRIPT_WRITE_VARIABLE = (
    "SECURESHIELD_CONFIRM_PRODUCTION_WRITE"  # comma-separated tokens
)
_NAME_ENTRY = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")
DATABASE_NAME_PREFIX = "database:"


class DatabaseIdentityError(RuntimeError):
    """The database target is not acceptable for the declared environment. The message never carries credentials."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    endpoint_id: str
    database: str
    port: Optional[int] = None


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str


def endpoint_id(host: str, *, from_entry: bool = False) -> str:
    """Canonical endpoint id.

    Only a host on the exact ``.neon.tech`` domain is reduced to its ``ep-...`` label (any ``-pooler`` suffix removed); every
    other host (including ``ep-x.evil.example`` and ``ep-x.neon.tech.evil.example``) keeps its full name, so it can never equal
    a registry endpoint. A bare ``ep-...`` token is an id only when it is a registry/allow-list ENTRY (``from_entry=True``), not
    when it is the host of a connection URL.
    """
    host = (host or "").strip().lower().rstrip(".")
    if host.endswith(_NEON_SUFFIX):
        first = host.split(".")[0]
        if first.startswith("ep-"):
            return first[: -len("-pooler")] if first.endswith("-pooler") else first
        return host
    if _BARE_NEON_ID.match(host):
        if from_entry:
            return host[: -len("-pooler")] if host.endswith("-pooler") else host
        return (
            "host:" + host
        )  # a bare token as a URL host is just a hostname: never equal to a registry id
    return host


def _check_host(host: str) -> str:
    host = (host or "").lower()
    if not host:
        raise DatabaseIdentityError("database URL has no host")
    ok = _IPV6.match(host) if ":" in host else _HOSTNAME.match(host)
    if not ok or ".." in host:
        raise DatabaseIdentityError("database URL host is not a plain ASCII hostname")
    return host


def parse_endpoint(url: str) -> Endpoint:
    """Parse any supported URL form and prove the driver would connect to exactly the host/port/database it names."""
    try:
        normalized = normalize_async_db_url(url)
        if not normalized.startswith("postgresql+asyncpg://"):
            raise ValueError
        parsed = make_url(normalized)
        query_keys = {str(k).strip().lower() for k in parsed.query}
    except Exception:  # noqa: BLE001 - library messages can echo the URL; never propagate them
        raise DatabaseIdentityError("database URL cannot be parsed") from None
    if query_keys & PROHIBITED_QUERY_KEYS:
        raise DatabaseIdentityError(
            "database URL carries a connection-routing query parameter (host, port, database, user ...); put it in the URL itself"
        )
    host = _check_host(parsed.host or "")
    if not (parsed.database or "").strip():
        raise DatabaseIdentityError(
            "database URL names no database (a missing name would be taken from PGDATABASE)"
        )
    try:
        from sqlalchemy.dialects.postgresql.asyncpg import dialect

        _, effective = dialect().create_connect_args(parsed)
    except Exception:  # noqa: BLE001
        raise DatabaseIdentityError(
            "database URL cannot be resolved to connection arguments"
        ) from None
    if (
        str(effective.get("host", "")).lower() != host
        or (effective.get("port") not in (None, parsed.port))
        or (effective.get("database") or "") != (parsed.database or "")
    ):
        raise DatabaseIdentityError(
            "database URL does not resolve to the endpoint it names"
        )
    return Endpoint(
        host=host,
        endpoint_id=endpoint_id(host),
        database=parsed.database or "",
        port=parsed.port,
    )


def _collect(
    lines: Iterable[str], source: str, allow_names: bool = True
) -> tuple[set[str], set[str]]:
    """(endpoint ids, lower-cased production database names) from registry-style lines."""
    found: set[str] = set()
    names: set[str] = set()
    for number, raw in enumerate(lines, 1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        if entry.lower().startswith(DATABASE_NAME_PREFIX):
            name = entry[len(DATABASE_NAME_PREFIX) :].strip()
            if not allow_names or not _NAME_ENTRY.match(name):
                raise DatabaseIdentityError(
                    f"{source} entry {number} is not a valid database name entry"
                )
            names.add(name.lower())
            continue
        if _FORBIDDEN_ENTRY.search(entry) or not (
            _HOSTNAME.match(entry.lower()) or _IPV6.match(entry.lower())
        ):
            raise DatabaseIdentityError(
                f"{source} entry {number} is not an endpoint id or hostname"
            )
        found.add(endpoint_id(entry, from_entry=True))
    return found, names


def _entries(lines: Iterable[str], source: str) -> set[str]:
    return _collect(lines, source, allow_names=False)[0]


def _read_registry(path: Optional[Path]) -> list[str]:
    registry_file = Path(path) if path is not None else REGISTRY_PATH
    try:
        return registry_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        raise DatabaseIdentityError(
            "production endpoint registry file is missing or unreadable"
        ) from None


def load_registry(extra: str = "", path: Optional[Path] = None) -> frozenset[str]:
    """File entries plus the optional comma-separated variable. The file must exist and the union must not be empty."""
    found, _ = _collect(_read_registry(path), "production endpoint registry file")
    found |= _entries(
        (extra or "").replace(",", "\n").splitlines(), "PRODUCTION_DATABASE_ENDPOINTS"
    )
    if not found:
        raise DatabaseIdentityError(
            "production endpoint registry is empty; it is required in every environment"
        )
    return frozenset(found)


def load_production_database_names(
    extra: str = "", path: Optional[Path] = None
) -> frozenset[str]:
    """Production database names (lower-case): ``database:`` lines of the registry file plus ``PRODUCTION_DATABASE_NAMES``."""
    _, names = _collect(_read_registry(path), "production endpoint registry file")
    for raw in (extra or "").replace(",", "\n").splitlines():
        name = raw.split("#", 1)[0].strip()
        if not name:
            continue
        if not _NAME_ENTRY.match(name):
            raise DatabaseIdentityError(
                "PRODUCTION_DATABASE_NAMES has an entry that is not a valid database name"
            )
        names.add(name.lower())
    return frozenset(names)


def _allowed_dev_hosts(value: str, registry: frozenset[str]) -> frozenset[str]:
    """Explicitly approved non-loopback hosts for development/test. Malformed entries and registry endpoints are errors."""
    entries = _entries(
        (value or "").replace(",", "\n").splitlines(), "DEV_DATABASE_ALLOWED_HOSTS"
    )
    if entries & registry:
        raise DatabaseIdentityError(
            "DEV_DATABASE_ALLOWED_HOSTS must not list a production-registry endpoint"
        )
    return frozenset(entries)


def validate_identity(settings, registry_path: Optional[Path] = None) -> str:
    """Raise ``DatabaseIdentityError`` unless both database URLs are acceptable for the declared environment.

    Returns a one-line, credential-free description for logging.
    """
    environment = (getattr(settings, "ENVIRONMENT", "") or "").strip().lower()
    if environment not in ENVIRONMENTS:
        raise DatabaseIdentityError(
            f"ENVIRONMENT must be one of {', '.join(ENVIRONMENTS)}"
        )
    declared = (getattr(settings, "DATABASE_ENVIRONMENT", "") or "").strip().lower()
    if declared not in DATABASE_ENVIRONMENTS:
        raise DatabaseIdentityError(
            f"DATABASE_ENVIRONMENT must be set to one of {', '.join(DATABASE_ENVIRONMENTS)}"
        )
    if declared != _EXPECTED_DATABASE_ENVIRONMENT[environment]:
        raise DatabaseIdentityError("DATABASE_ENVIRONMENT does not match ENVIRONMENT")

    registry = load_registry(
        getattr(settings, "PRODUCTION_DATABASE_ENDPOINTS", "") or "", registry_path
    )
    allowed = _allowed_dev_hosts(
        getattr(settings, "DEV_DATABASE_ALLOWED_HOSTS", "") or "", registry
    )
    production_names = load_production_database_names(
        getattr(settings, "PRODUCTION_DATABASE_NAMES", "") or "", registry_path
    )
    runtime = parse_endpoint(settings.DATABASE_URL)
    migrator = parse_endpoint(settings.MIGRATOR_DATABASE_URL)
    if (
        runtime.endpoint_id != migrator.endpoint_id
        or runtime.database != migrator.database
    ):
        raise DatabaseIdentityError(
            "DATABASE_URL and MIGRATOR_DATABASE_URL must target the same endpoint and database"
        )

    production_class = runtime.endpoint_id in registry
    if environment == "production":
        if not production_class:
            raise DatabaseIdentityError(
                "production must use a database endpoint listed in the production registry"
            )
        kind = "production-registry"
    elif production_class:
        raise DatabaseIdentityError(
            f"a {environment} environment must never use a production-registry database endpoint"
        )
    elif runtime.database.lower() in production_names:
        # loopback, an SSH tunnel and a port forward all look like "localhost": the database NAME is the only tell
        raise DatabaseIdentityError(
            f"a {environment} environment must never use a production database name"
        )
    elif environment == "staging":
        kind = "staging"
    elif runtime.host in _LOOPBACK_HOSTS:
        kind = "loopback"
    elif runtime.endpoint_id in allowed:
        kind = "dev-allowed"
    else:
        raise DatabaseIdentityError(
            f"a {environment} environment may only use a loopback database or one listed in DEV_DATABASE_ALLOWED_HOSTS"
        )
    return f"database identity OK: environment={environment} class={kind} database={runtime.database}"


def check_connected_database_name(actual: str, settings) -> None:
    """Compare ``SELECT current_database()`` (read by the caller) with the configured name. No connection is made here."""
    if (actual or "") != parse_endpoint(settings.DATABASE_URL).database:
        raise DatabaseIdentityError(
            "connected database name differs from the configured database name"
        )
    environment = (getattr(settings, "ENVIRONMENT", "") or "").strip().lower()
    if environment != "production" and (
        actual or ""
    ).lower() in load_production_database_names(
        getattr(settings, "PRODUCTION_DATABASE_NAMES", "") or ""
    ):
        raise DatabaseIdentityError(
            f"a {environment} environment is connected to a production database name"
        )


async def verify_connected_database(
    settings, engine=None, timeout: float = 15.0
) -> None:
    """Read-only check that the database we are connected to is the configured one (``SELECT current_database()``).

    Run once at startup and in the maintenance CLIs, in the same event loop that will use the engine, before any other
    database use. Raises ``DatabaseIdentityError`` on a mismatch; connection failures propagate as the driver's exception.
    """
    if engine is None:
        from app import database

        engine = database.engine

    async def _read() -> str:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT current_database()"))
            return result.scalar_one()

    check_connected_database_name(await asyncio.wait_for(_read(), timeout), settings)


def _tokens(value: str) -> frozenset[str]:
    return frozenset(t.strip().lower() for t in (value or "").split(",") if t.strip())


def assert_script_target(
    url: str,
    role: str,
    registry_path: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Endpoint:
    """Guard for operator scripts that open their own connection. Returns the parsed endpoint or raises.

    * ``scratch`` / ``migrator``: the script creates, drops or writes databases on the server. Loopback only, never a
      production-registry endpoint and never a production database name.
    * ``read_only``: the script only reads. A production-class target (a registry endpoint, or a production database name on
      any host, which includes a local copy or an SSH tunnel) is refused unless ``SECURESHIELD_CONFIRM_PRODUCTION_READ`` lists
      its token: the endpoint id for a registry endpoint, ``database:<name>`` for a production database name elsewhere.
    * ``production_write``: the script WRITES to a production-class target. It must BE a registry endpoint (a wrong endpoint is
      refused) and ``SECURESHIELD_CONFIRM_PRODUCTION_WRITE`` must list that endpoint id.
    Tokens are comma-separated and case-insensitive.
    """
    env = os.environ if environ is None else environ
    endpoint = parse_endpoint(url)
    registry = load_registry(
        env.get("PRODUCTION_DATABASE_ENDPOINTS", ""), registry_path
    )
    names = load_production_database_names(
        env.get("PRODUCTION_DATABASE_NAMES", ""), registry_path
    )
    in_registry = endpoint.endpoint_id in registry
    production_name = endpoint.database.lower() in names
    if role in ("scratch", "migrator"):
        if in_registry or production_name:
            raise DatabaseIdentityError(
                "this script must never target a production endpoint or database name"
            )
        if endpoint.host not in _LOOPBACK_HOSTS:
            raise DatabaseIdentityError(
                "this script requires a loopback database server"
            )
    elif role == "read_only":
        if in_registry:
            needed = endpoint.endpoint_id
        elif production_name:
            needed = DATABASE_NAME_PREFIX + endpoint.database.lower()
        else:
            needed = ""
        if needed and needed not in _tokens(env.get(SCRIPT_CONFIRM_VARIABLE, "")):
            raise DatabaseIdentityError(
                f"target is production-class; read-only access needs {SCRIPT_CONFIRM_VARIABLE} to list '{needed}'"
            )
    elif role == "production_write":
        if not in_registry:
            raise DatabaseIdentityError(
                "the write target is not a production-registry endpoint; refusing"
            )
        if endpoint.endpoint_id not in _tokens(env.get(SCRIPT_WRITE_VARIABLE, "")):
            raise DatabaseIdentityError(
                f"a production write needs {SCRIPT_WRITE_VARIABLE} to list '{endpoint.endpoint_id}'"
            )
    else:
        raise ValueError("unknown script role")
    return endpoint


def _flag_is_true(value: Optional[str]) -> bool:
    return (value or "").strip().lower() == "true"


def retention_gate(settings=None, registry_path: Optional[Path] = None) -> GateDecision:
    """May retention DELETE rows now? Needs the explicit flag AND a valid database identity. Never raises."""
    if settings is None:
        from app.config import settings as default_settings

        settings = default_settings
    if not _flag_is_true(getattr(settings, "RETENTION_CLEANUP_ENABLED", None)):
        return GateDecision(False, "RETENTION_CLEANUP_ENABLED is not set to true")
    try:
        validate_identity(settings, registry_path)
    except DatabaseIdentityError:
        return GateDecision(False, "database identity validation failed")
    return GateDecision(True, "allowed")
