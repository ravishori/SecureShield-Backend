"""Logical backup of the SecureShield PostgreSQL database (custom-format pg_dump).

    python scripts/db_backup.py                 # uses BACKUP_DATABASE_URL, else DATABASE_URL
    python scripts/db_backup.py --out backups/  # directory (default: ./backups)

Writes ``secureshield-YYYYmmddTHHMMSSZ.dump`` plus a ``.sha256`` sidecar and prunes dumps older
than ``--keep`` (default 14). The connection string is never printed or put on the command line:
credentials are passed to pg_dump through PG* environment variables.

Use a READ-ONLY role for production backups (GRANT pg_read_all_data). Store the dump somewhere
other than the database host (see docs/BACKUP_AND_RECOVERY.md).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.engine import make_url


def pg_env(url: str) -> dict[str, str]:
    u = make_url(url.replace("+asyncpg", "").replace("postgres://", "postgresql://"))
    env = dict(os.environ)
    env.update(
        PGHOST=u.host or "localhost",
        PGPORT=str(u.port or 5432),
        PGUSER=u.username or "",
        PGDATABASE=u.database or "",
    )
    if u.password:
        env["PGPASSWORD"] = u.password
    return env


def find_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        sys.exit(f"{name} not found on PATH (install the PostgreSQL client tools).")
    return path


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def backup(url: str, out_dir: Path, keep: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = out_dir / f"secureshield-{stamp}.dump"
    subprocess.run(
        [
            find_tool("pg_dump"),
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(target),
        ],
        env=pg_env(url),
        check=True,
    )
    if target.stat().st_size == 0:
        target.unlink()
        sys.exit("pg_dump produced an empty file")
    digest = sha256_of(target)
    (out_dir / (target.name + ".sha256")).write_text(f"{digest}  {target.name}\n")
    dumps = sorted(out_dir.glob("secureshield-*.dump"))
    for old in dumps[:-keep] if keep > 0 else []:
        old.unlink()
        side = old.with_name(old.name + ".sha256")
        if side.exists():
            side.unlink()
    return target


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", default="backups", type=Path)
    ap.add_argument("--keep", default=14, type=int)
    args = ap.parse_args()
    url = os.environ.get("BACKUP_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("Set BACKUP_DATABASE_URL (preferred, read-only role) or DATABASE_URL.")
    path = backup(url, args.out, args.keep)
    print(f"backup written: {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
