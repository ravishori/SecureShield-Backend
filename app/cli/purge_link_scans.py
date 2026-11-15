"""Link-scan retention and redaction (BH-2). Safe to run repeatedly; bounded per run; prints counts only.

    python -m app.cli.purge_link_scans              # delete scans older than LINK_SCAN_RETENTION_DAYS (bounded batches);
                                                    # needs RETENTION_CLEANUP_ENABLED=true, otherwise nothing is deleted
    python -m app.cli.purge_link_scans --dry-run    # count what a purge would delete; changes nothing
    python -m app.cli.purge_link_scans --redact-existing
                                                    # rewrite stored URLs written before BH-2 to the redacted form (bounded;
                                                    # privacy-improving and idempotent; nothing is deleted)

It uses the application's own database settings. No URL, row or parameter is ever printed.
Exit codes: 0 success, 1 the run reported an error, 2 usage or unexpected failure.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import func, select

from app.services.link_scan_retention import (
    cutoff,
    current_policy,
    purge_expired,
)
from app.services.url_privacy import redact_url_for_storage, sanitize_threats


async def _dry_run() -> int:
    from app import database
    from app.models.link_scan import LinkScan

    policy = current_policy()
    async with database.AsyncSessionLocal() as s:
        n = (
            await s.execute(
                select(func.count())
                .select_from(LinkScan)
                .where(LinkScan.scanned_at < cutoff(datetime.utcnow(), policy.days))
            )
        ).scalar_one()
    print(f"eligible for deletion (older than {policy.days} days): {n}")
    return 0


async def _redact_existing(batch: int = 500, max_batches: int = 20) -> int:
    from app import database
    from app.models.link_scan import LinkScan

    changed = 0
    last_id = None
    async with database.AsyncSessionLocal() as s:
        for _ in range(max_batches):
            q = select(LinkScan).order_by(LinkScan.id).limit(batch)
            if last_id is not None:
                q = q.where(LinkScan.id > last_id)
            rows = (await s.execute(q)).scalars().all()
            if not rows:
                break
            for row in rows:
                new_url = redact_url_for_storage(row.url)
                new_threats = sanitize_threats(row.gsb_threats)
                if new_url != row.url or new_threats != row.gsb_threats:
                    row.url, row.gsb_threats = new_url, new_threats
                    changed += 1
            await s.commit()
            last_id = rows[-1].id
    print(f"rows rewritten to the redacted form: {changed}")
    return 0


def run(argv: Optional[Sequence[str]] = None) -> int:
    try:
        parser = argparse.ArgumentParser(
            prog="purge_link_scans", description=__doc__.splitlines()[0]
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--dry-run", action="store_true")
        group.add_argument("--redact-existing", action="store_true")
        args = parser.parse_args(list(argv) if argv is not None else None)
        # Identity guard first: applies to --dry-run and --redact-existing too (they read or rewrite production data).
        from app.config import settings
        from app.db_identity import (
            DatabaseIdentityError,
            validate_identity,
            verify_connected_database,
        )

        try:
            validate_identity(settings)
        except DatabaseIdentityError as exc:
            print(f"refused: {exc}")
            return 2

        # One event loop per command: the read-only current_database() check and the work share the engine.
        async def verified(work):
            await verify_connected_database(settings)
            return await work()

        try:
            if args.dry_run:
                return asyncio.run(verified(_dry_run))
            if args.redact_existing:
                return asyncio.run(verified(_redact_existing))
            result = asyncio.run(verified(purge_expired))
        except DatabaseIdentityError as exc:
            print(f"refused: {exc}")
            return 2
        print(
            f"deleted={result.deleted} batches={result.batches} more_remaining={result.more_remaining} retention_days={result.days}"
        )
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
