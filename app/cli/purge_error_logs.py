"""Explicit maintenance command for ``error_logs`` retention (never run at application startup).

    python -m app.cli.purge_error_logs --dry-run   # count rows older than LOG_RETENTION_DAYS; deletes nothing
    python -m app.cli.purge_error_logs             # delete them; needs RETENTION_CLEANUP_ENABLED=true

It uses the application's own database settings and refuses a database that fails identity validation (production-class
endpoints in development/test, and so on). Select the environment file explicitly with SECURESHIELD_ENV_FILE. Prints counts
only: no row content, URL or credential.
Exit codes: 0 success, 1 the run failed, 2 usage error / invalid retention days / identity refused / unexpected failure,
3 blocked because RETENTION_CLEANUP_ENABLED is not true (nothing was deleted).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Optional, Sequence


def run(argv: Optional[Sequence[str]] = None) -> int:
    try:
        parser = argparse.ArgumentParser(
            prog="purge_error_logs", description=__doc__.splitlines()[0]
        )
        parser.add_argument("--dry-run", action="store_true")
        args = parser.parse_args(list(argv) if argv is not None else None)

        from app.config import settings
        from app.db_identity import (
            DatabaseIdentityError,
            retention_gate,
            validate_identity,
            verify_connected_database,
        )

        try:
            validate_identity(settings)
        except DatabaseIdentityError as exc:
            print(f"refused: {exc}")
            return 2
        if settings.LOG_RETENTION_DAYS < 1:
            print("refused: LOG_RETENTION_DAYS must be a positive number of days")
            return 2

        from app.services.error_log_retention import (
            count_old_error_logs,
            purge_old_error_logs,
        )

        # One event loop for the whole command: the read-only current_database() check and the work share the engine.
        async def verified(work):
            await verify_connected_database(settings)
            return await work()

        try:
            if args.dry_run:
                n = asyncio.run(verified(count_old_error_logs))
                print(
                    f"eligible for deletion (older than {settings.LOG_RETENTION_DAYS} days): {n}"
                )
                return 0
            if not retention_gate(settings).allowed:
                print(
                    "blocked: RETENTION_CLEANUP_ENABLED is not true; nothing was deleted"
                )
                return 3
            result = asyncio.run(verified(purge_old_error_logs))
        except DatabaseIdentityError as exc:
            print(f"refused: {exc}")
            return 2
        print(f"deleted={result.deleted} retention_days={result.days}")
        if result.error:
            print(f"error class: {result.error}")
            return 1
        return 0
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    except Exception as exc:  # noqa: BLE001
        print(f"failed unexpectedly: {type(exc).__name__}")
        return 2


if __name__ == "__main__":
    sys.exit(run())
