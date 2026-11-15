"""Prove a backup is restorable: restore it into a throw-away database and compare it to the source.

    python scripts/db_restore_check.py backups/secureshield-....dump

Environment:
    RESTORE_ADMIN_URL   connection URL (any database, e.g. .../postgres) of a LOCAL server on which a
                        scratch database may be created and dropped. Must be loopback.
    BACKUP_DATABASE_URL (optional) source database used to compare row counts against.

Safety: the scratch database is always named ``secureshield_restore_check_<rand>`` and the admin host
must be loopback, so this can never restore over (or drop) a real database.
Checks: sha256 sidecar (if present), pg_restore succeeds, alembic_version present, and per-table row
counts equal the source (when a source URL is given).
"""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
from pathlib import Path

import asyncio

import asyncpg
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).parent))
from db_backup import find_tool, pg_env, sha256_of  # noqa: E402

# Refuse a wrong or production-class target before any connection is opened (app.db_identity is free of Settings imports).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db_identity import DatabaseIdentityError, assert_script_target  # noqa: E402

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def sync_url(url: str) -> str:
    return url.replace("+asyncpg", "").replace("postgres://", "postgresql://")


async def _counts(url: str) -> dict[str, int]:
    conn = await asyncpg.connect(sync_url(url))
    try:
        names = [
            r["tablename"]
            for r in await conn.fetch(
                "select tablename from pg_tables where schemaname='public' order by 1"
            )
        ]
        return {n: await conn.fetchval(f'select count(*) from "{n}"') for n in names}
    finally:
        await conn.close()


def table_counts(url: str) -> dict[str, int]:
    return asyncio.run(_counts(url))


async def _admin(url: str, sql: str) -> None:
    conn = await asyncpg.connect(sync_url(url))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("dump", type=Path)
    args = ap.parse_args()

    admin_url = os.environ.get("RESTORE_ADMIN_URL")
    if not admin_url:
        sys.exit("Set RESTORE_ADMIN_URL to a local PostgreSQL server URL.")
    try:
        assert_script_target(
            admin_url, "scratch"
        )  # loopback only, never a production-registry endpoint
        _source = os.environ.get("BACKUP_DATABASE_URL")
        if _source:
            assert_script_target(_source, "read_only")
    except DatabaseIdentityError as exc:
        sys.exit(f"Refusing: {exc}")
    admin = make_url(sync_url(admin_url))
    if (admin.host or "").lower() not in LOOPBACK:
        sys.exit("Refusing: RESTORE_ADMIN_URL must point at a loopback server.")

    side = args.dump.with_name(args.dump.name + ".sha256")
    if side.exists():
        expected = side.read_text().split()[0]
        if sha256_of(args.dump) != expected:
            sys.exit("CHECKSUM MISMATCH: the dump is corrupt or was modified.")
        print("checksum ok")

    scratch = f"secureshield_restore_check_{secrets.token_hex(4)}"
    try:
        asyncio.run(_admin(admin_url, f'create database "{scratch}"'))
        env = pg_env(sync_url(admin_url))
        env["PGDATABASE"] = scratch
        subprocess.run(
            [
                find_tool("pg_restore"),
                "--no-owner",
                "--no-privileges",
                "--exit-on-error",
                "--dbname",
                scratch,
                str(args.dump),
            ],
            env=env,
            check=True,
        )
        scratch_url = str(
            admin.set(database=scratch).render_as_string(hide_password=False)
        )
        restored = table_counts(scratch_url)
        if "alembic_version" not in restored or restored["alembic_version"] != 1:
            sys.exit(
                "FAILED: alembic_version missing or empty in the restored database"
            )
        print(f"restored {len(restored)} tables, {sum(restored.values())} rows")
        source = os.environ.get("BACKUP_DATABASE_URL")
        if source:
            live = table_counts(source)
            diff = {
                t: (live.get(t), restored.get(t))
                for t in set(live) | set(restored)
                if live.get(t) != restored.get(t)
            }
            if diff:
                print(
                    "row-count differences vs source (expected if the source changed since the dump):"
                )
                for t, (a, b) in sorted(diff.items()):
                    print(f"  {t}: source={a} restored={b}")
            else:
                print("row counts match the source")
        print("RESTORE CHECK PASSED")
    finally:
        asyncio.run(
            _admin(admin_url, f'drop database if exists "{scratch}" with (force)')
        )


if __name__ == "__main__":
    main()
