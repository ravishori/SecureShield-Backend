"""Show which database the selected configuration points at, WITHOUT connecting to it.

    python -m app.cli.show_database_target                       # describe the target
    python -m app.cli.show_database_target --expect development  # also fail unless it is the local development database
    python -m app.cli.show_database_target --expect test         # ... or the local test database

Select the environment file explicitly first (``SECURESHIELD_ENV_FILE``); backend/.env is never read. The report names the
environment, the identity class (loopback / dev-allowed / staging / production-registry), host, port, database and the two role
NAMES. It never prints a password, a URL or a token, and it opens no connection: the read-only ``SELECT current_database()``
check is made by the application itself at startup, by Alembic, and by the maintenance CLIs.

Exit codes: 0 the target is acceptable (and matches --expect), 1 it does not match --expect or looks unsafe, 2 the identity
checks refused it or the arguments were wrong.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from sqlalchemy.engine import make_url

from app.db_identity import DatabaseIdentityError, parse_endpoint, validate_identity

DEV_SUFFIX = "_dev"
TEST_SUFFIX = "_test"
EXPECTATIONS = {
    # expectation: (ENVIRONMENT, DATABASE_ENVIRONMENT, required database-name suffix, forbidden suffix)
    "development": ("development", "local", DEV_SUFFIX, TEST_SUFFIX),
    "test": ("test", "test", TEST_SUFFIX, DEV_SUFFIX),
}


def describe(settings, expect: Optional[str] = None) -> tuple[list[str], list[str]]:
    """(report lines, problems). Raises ``DatabaseIdentityError`` when the identity checks refuse the target."""
    summary = validate_identity(settings)  # raises on any unsafe or inconsistent target
    runtime = parse_endpoint(settings.DATABASE_URL)
    runtime_role = make_url(settings.DATABASE_URL).username or "?"
    migrator_role = make_url(settings.MIGRATOR_DATABASE_URL).username or "?"
    lines = [
        summary,
        f"environment          : {settings.ENVIRONMENT} / {settings.DATABASE_ENVIRONMENT}",
        f"server               : {runtime.host}:{runtime.port or 5432}",
        f"database             : {runtime.database}",
        f"runtime role         : {runtime_role}  (DATABASE_URL)",
        f"migrator role        : {migrator_role}  (MIGRATOR_DATABASE_URL)",
        "connection           : none made by this command",
    ]
    problems: list[str] = []
    if runtime_role == migrator_role and (settings.ENVIRONMENT or "").lower() != "test":
        problems.append(
            "the runtime and migrator URLs use the SAME role; use the least-privilege application role for DATABASE_URL"
        )
    name = runtime.database.lower()
    if expect:
        environment, database_environment, required, forbidden = EXPECTATIONS[expect]
        if (settings.ENVIRONMENT or "").lower() != environment or (
            settings.DATABASE_ENVIRONMENT or ""
        ).lower() != database_environment:
            problems.append(
                f"expected ENVIRONMENT={environment} and DATABASE_ENVIRONMENT={database_environment}"
            )
        if not name.endswith(required):
            problems.append(f"expected a database name ending in '{required}'")
        if name.endswith(forbidden):
            problems.append(
                f"the database name ends in '{forbidden}', which belongs to the other environment"
            )
    return lines, problems


def run(argv: Optional[Sequence[str]] = None, settings=None, out=None) -> int:
    out = out or sys.stdout
    try:
        parser = argparse.ArgumentParser(
            prog="show_database_target", description=__doc__.splitlines()[0]
        )
        parser.add_argument("--expect", choices=sorted(EXPECTATIONS), default=None)
        args = parser.parse_args(list(argv) if argv is not None else None)
        if settings is None:
            from app.config import settings as app_settings

            settings = app_settings
        try:
            lines, problems = describe(settings, args.expect)
        except DatabaseIdentityError as exc:
            print(f"REFUSED: {exc}", file=out)
            return 2
        for line in lines:
            print(line, file=out)
        for problem in problems:
            print(f"PROBLEM: {problem}", file=out)
        return 1 if problems else 0
    except SystemExit as exc:  # argparse usage error
        return 2 if exc.code not in (0, None) else 0
    except Exception as exc:  # noqa: BLE001
        print(f"failed unexpectedly: {type(exc).__name__}", file=out)
        return 2


if __name__ == "__main__":
    sys.exit(run())
