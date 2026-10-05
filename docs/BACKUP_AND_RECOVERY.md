# Backup and recovery runbook

Scope: the SecureShield PostgreSQL database and the uploaded evidence/recording files.
Verified locally (see "Evidence" at the bottom); the Railway-side schedule is a **manual/owner action**
(listed under "Not automated").

## What must be backed up

| Data | Where | How |
|---|---|---|
| PostgreSQL (29 tables, users, alerts, reports, ...) | Railway Postgres | `scripts/db_backup.py` (logical `pg_dump -Fc`) |
| Evidence + recordings | Railway volume mounted at `/app/uploads` | Railway volume backups (dashboard) **or** copy `/app/uploads` off-host |
| Secrets (`SECRET_KEY`, provider keys) | Railway variables | Keep an offline, access-controlled copy in the owner's password manager. Losing `SECRET_KEY` only invalidates sessions; losing nothing else is irreversible. |

Evidence files are **not** in the database dump. A database restore without the volume leaves evidence rows
whose downloads return 404.

## Taking a backup

```bash
# read-only role is strongly recommended for production:
#   CREATE ROLE secureshield_backup LOGIN PASSWORD '...';  GRANT pg_read_all_data TO secureshield_backup;
export BACKUP_DATABASE_URL='postgresql://secureshield_backup:***@<host>:<port>/<db>'
python scripts/db_backup.py --out backups/ --keep 14
```

* Output: `backups/secureshield-<UTC timestamp>.dump` and `.sha256`.
* The URL is never printed or placed on the command line; credentials travel in `PG*` environment variables.
* Run it from a machine outside Railway (or a Railway cron service that uploads the dump to object storage).
  Keep at least 14 daily dumps and 3 monthly ones. Encrypt dumps at rest (they contain personal data).

## Proving a backup is restorable (do this after every schedule change and monthly)

```bash
export RESTORE_ADMIN_URL='postgresql://postgres:***@localhost:5432/postgres'   # LOCAL server only
export BACKUP_DATABASE_URL='<source URL>'                                       # optional: compares row counts
python scripts/db_restore_check.py backups/secureshield-<ts>.dump
```

The script verifies the checksum, creates `secureshield_restore_check_<random>` on the loopback server,
runs `pg_restore --exit-on-error`, checks `alembic_version`, compares per-table row counts with the source,
and always drops the scratch database. It refuses non-loopback servers, so it cannot touch production.

## Recovery procedures

### A. Bad data change / deleted rows (database still healthy)
1. Restore the latest good dump into a scratch DB with `db_restore_check.py` logic (or `createdb` + `pg_restore`).
2. Copy the affected rows back with `INSERT ... SELECT` through `psql`. Do **not** overwrite the live DB.

### B. Database lost or corrupted
1. Provision a new Railway Postgres (or restore the Railway snapshot).
2. Create the roles: `secureshield_migrator` (owner/DDL) and `secureshield_app` (runtime, DML only).
3. `pg_restore --no-owner --dbname <new db> backups/<dump>`, then run
   `alembic upgrade head` as the migrator role (no-op if the dump is current).
4. `GRANT` the runtime role DML on all tables/sequences (see `docs/RAILWAY_DEPLOYMENT.md`).
5. Point `DATABASE_URL` / `MIGRATOR_DATABASE_URL` at the new database and redeploy; confirm `GET /health` = 200.
6. Re-attach the evidence volume at `/app/uploads`.

### C. Bad deploy
Railway keeps previous deployments: redeploy the last good one from the dashboard. Migrations are forward-only;
`alembic downgrade` is only safe for the revisions that define a downgrade (the enum migration `p1q2r3s4t5u6`
cannot be reversed - PostgreSQL cannot drop enum values - and is harmless to leave in place).

## Targets

* RPO (data you can lose): 24 h with a daily dump; reduce with Railway point-in-time backups if the plan allows.
* RTO (time to recover): ~1 h following procedure B once a dump is at hand.

## Not automated (owner actions)

* A schedule (Railway cron / GitHub Actions with a read-only DB credential and an object-storage target).
  No credential was created or rotated by this work.
* Off-site storage and encryption keys for the dumps.
* Evidence-volume backups (Railway dashboard setting; plan dependent).

## Evidence of verification

* `tests/unit/test_backup_scripts.py` (URL parsing, checksum, restore guard).
* Manual end-to-end run against the local migrated test database: backup written, checksum ok,
  restored 29 tables, row counts matched the source, a one-byte tampered copy was rejected with
  `CHECKSUM MISMATCH`, scratch database dropped.
