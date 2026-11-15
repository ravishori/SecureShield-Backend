# Local development: environment selection and database safety (Stage 1.1) and isolated local databases (Stage 1.2)

## Environment file selection
- The backend **never** reads `backend/.env` on its own. If that file exists and no file is selected, the app logs one warning (no values) and ignores it.
- Select a file with the process variable `SECURESHIELD_ENV_FILE`. A selected file that does not exist is a startup error; there is no fallback.
- Precedence: **process environment > selected file > defaults.** A shell or CI variable always wins over the file.
- `start.bat` selects `backend\.env.local` and refuses to start if it is missing. Create it from `.env.example` (it is git-ignored).
- Any other launch path (IDE run configuration, `uvicorn` typed by hand, `alembic`, the CLIs) must set `SECURESHIELD_ENV_FILE` or supply every variable in the process environment.

## Stage 1.2: isolated local development and test databases
**Status: prepared, not activated.** Nothing in this repository has created, connected to or migrated these databases. The steps below are manual and need the machine owner's approval first.

### Targets and roles
| | Development | Integration tests |
|---|---|---|
| Database | `secureshield_dev` | `secureshield_test` (must end in `_test`) |
| Runtime role (`DATABASE_URL`) | `secureshield_dev_app` (rows only: SELECT/INSERT/UPDATE/DELETE and sequence use on tables its owner creates; no DDL, no TRUNCATE) | `secureshield_test_owner` |
| Migration role (`MIGRATOR_DATABASE_URL`) | `secureshield_dev_owner` (owns the database; runs Alembic) | `secureshield_test_owner` (the harness requires `DATABASE_URL == MIGRATOR_DATABASE_URL == TEST_DATABASE_URL`) |
| Where it is configured | `.env.local` (git-ignored) selected with `SECURESHIELD_ENV_FILE` | `TEST_DATABASE_URL` in the shell only |
| `ENVIRONMENT` / `DATABASE_ENVIRONMENT` | `development` / `local` | `test` / `test` (forced by `tests/conftest.py`) |

- All roles are `LOGIN` without a password, and `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, members of no other role, with a connection limit of 20.
- `PUBLIC` has no privilege on either database or on their `public` schema. The development roles cannot connect to the test database and the test role cannot connect to the development database.
- Both databases are local and distinct. The production database name `SecureShieldDB` stays refused outside production on any host, and the registry endpoints (production and the recovery branch) stay refused outside production. No remote host is involved anywhere.
- No password exists in the repository. The SQL creates logins that cannot authenticate until you set a password by hand.

### One-time manual setup (after approval)
0. **Server check.** Use the local PostgreSQL service on `localhost:5432`. Recommended hardening, not done for you: `listen_addresses = 'localhost'` and SCRAM authentication for loopback in `pg_hba.conf` (this machine currently listens on `*`, but its `pg_hba.conf` holds only loopback `scram-sha-256` rules, so remote clients are rejected and a role without a password cannot log in).
1. **Review** `docs/database/STAGE_1_2_LOCAL_DATABASE_SETUP.sql`. It contains no destructive statement and is idempotent.
2. **Run it once** as the local administrative role, from the maintenance database (do **not** add `--single-transaction`: `CREATE DATABASE` cannot run in a transaction block, which is why the file is split into parts; see its header):
   ```
   "D:\Program Files\PostgreSQL\18\bin\psql.exe" -X -h localhost -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -f docs\database\STAGE_1_2_LOCAL_DATABASE_SETUP.sql
   ```
   It refuses to run against a non-loopback server, a server that looks like a hosted service (Neon, RDS, Azure, Cloud SQL), any database other than `postgres`, or as a non-superuser. It never alters an existing role: if a role of one of these names already exists with more than least privilege, it stops and asks for a manual review. psql may ask for the administrator password again at each `\connect`; that is expected. If `CREATE DATABASE` fails because another session is connected to `template1`, close that session and run the script again (it is safe to re-run). Read the result sets of Part 5; each says what to expect (5.1b must return no rows).
3. **Set the three passwords by hand** (never in a file or the command line):
   ```
   "D:\Program Files\PostgreSQL\18\bin\psql.exe" -h localhost -U postgres -d postgres
   \password secureshield_dev_owner
   \password secureshield_dev_app
   \password secureshield_test_owner
   ```
4. **Create `backend\.env.local`** from the active block at the top of `.env.example`, replacing `YOUR_DEV_APP_PASSWORD` and `YOUR_DEV_OWNER_PASSWORD`, plus the usual non-database settings. The file is git-ignored. Do not put `TEST_DATABASE_URL` in it.
5. **Verify the target without connecting** (PowerShell shown; in cmd use `set NAME=value`):
   ```
   $env:SECURESHIELD_ENV_FILE = ".env.local"
   python -m app.cli.show_database_target --expect development
   ```
   Expect `database identity OK: environment=development class=loopback database=secureshield_dev`, the two role names and `connection : none made by this command`. It exits 1 if the names do not look like the development database, and 2 if the identity checks refuse the target.
6. **Create the schema** (a manual step; the application never migrates at startup): `alembic upgrade head` with `SECURESHIELD_ENV_FILE` set. Alembic validates the identity and then runs a read-only `SELECT current_database()` before the first migration statement.
7. **Start the backend:** `start.bat` (it selects `.env.local` and refuses to start without it). The application does not create databases, run migrations or delete data at startup. If step 6 was skipped, requests fail until it is done. The startup check refuses to boot when the connected database name differs from the configured one.

### Running the tests
| | Unit tests | Integration tests |
|---|---|---|
| Needs a database | **No**. Every connection entry point is blocked and counted by `tests/unit/conftest.py` | Yes: a disposable local `*_test` database |
| Command | `pytest tests/unit` | `$env:TEST_DATABASE_URL = "postgresql+asyncpg://secureshield_test_owner:<password>@localhost:5432/secureshield_test"` then `pytest tests/integration` |
| If `TEST_DATABASE_URL` is unset | n/a | every integration test is **skipped** with the message "TEST_DATABASE_URL not set"; nothing falls back to `DATABASE_URL`, the development database or a default |
| What it refuses | n/a | any non-loopback host, any database not ending in `_test` (so never `secureshield_dev` or `SecureShieldDB`), any production or recovery endpoint or production database name, routing query parameters (`?host=`, `?port=`, `?database=`), lookalike hosts |

The integration harness runs Alembic and `TRUNCATE`s every application table between tests, but only inside the validated `*_test` database, after a read-only `current_database()` check. It never touches `secureshield_dev`.

### What fails, and how
| Situation | Result |
|---|---|
| `SECURESHIELD_ENV_FILE` unset, no `DATABASE_URL` in the environment | startup/import error: required setting missing (`backend/.env` is not read) |
| `SECURESHIELD_ENV_FILE` set to a missing file | `ConfigError`, no fallback |
| `DATABASE_ENVIRONMENT` missing or not matching `ENVIRONMENT` | `DatabaseIdentityError` before any engine is built |
| Development URL pointing at Neon/Railway/any remote host, a registry endpoint or `SecureShieldDB` | refused before any engine is built |
| `TEST_DATABASE_URL` unset | integration tests skipped |
| `TEST_DATABASE_URL` pointing at `secureshield_dev` or anything not ending in `_test` | refused (`UnsafeTestDatabaseError`) |
| The server answers with a different database name than the URL names (tunnel, port forward) | startup and Alembic refuse (`current_database()` check) |

### Rollback and manual removal
- The setup SQL changes nothing destructive and can be re-run safely. To switch the environment off without losing data, an administrator disables the three logins (`ALTER ROLE ... NOLOGIN`).
- **Manual removal (administrator decision, not scripted anywhere):** only after confirming that nothing you need is in them, an administrator may remove the two databases and then the three roles by hand with `DROP DATABASE` / `DROP OWNED BY` / `DROP ROLE`, in that order. Do this only on the local server and double-check the names first: `SecureShieldDB` is the legacy migration source and must not be touched.

## Required variables
| Variable | Local development |
|---|---|
| `ENVIRONMENT` | `development` (also `test`, `staging`, `production`) |
| `DATABASE_ENVIRONMENT` | `local` (must match: development→local, test→test, staging→staging, production→production) |
| `DATABASE_URL` / `MIGRATOR_DATABASE_URL` | the same **loopback** endpoint and database (`secureshield_dev`), app role and migrator role (see Stage 1.2 above) |
| `RETENTION_CLEANUP_ENABLED` | leave unset (off). Production must set `true` or `false` explicitly |

## Database identity rules (`app/db_identity.py`)
- `config/production_endpoints.txt` lists the production-class endpoints (the active production endpoint and the protected recovery endpoint). It holds identifiers only and is required in every environment. `PRODUCTION_DATABASE_ENDPOINTS` can add entries, never remove them.
- development/test: loopback hosts only, or hosts named in `DEV_DATABASE_ALLOWED_HOSTS`. A registry endpoint is refused even if listed there.
- staging: any non-registry endpoint. production: a registry endpoint only.
- `DATABASE_URL` and `MIGRATOR_DATABASE_URL` must name the same endpoint and database.
- The check runs before the application engine is built (`app/database.py`) and before Alembic runs. Messages never contain URLs, hosts or credentials.
- Registering a new production-class database means adding its endpoint id to the registry file in the same change.

## Retention (nothing is deleted at startup)
Deletion happens only when `RETENTION_CLEANUP_ENABLED=true` **and** the database identity is valid:
- `python -m app.cli.purge_error_logs [--dry-run]` (exit 0 ok, 1 failed, 2 refused/usage, 3 blocked by the flag)
- `python -m app.cli.purge_link_scans [--dry-run | --redact-existing]`
- the guardian-outbox worker purge and the once-per-hour link-scan trigger, which delete nothing while the flag is off.

## Guardian worker
- It can send real SMS/e-mail, so it is **off by default outside production**. Unset `GUARDIAN_WORKER_ENABLED` means on in production only; set it to `true` to run it elsewhere or `false` to stop it anywhere.
- The same switch gates the request-triggered attempt (`guardian_outbox.run_once_safe`, scheduled by `POST /app-monitor/sync` and `POST /elderly-protection/guardian-alert`) and the legacy `_deliver_guardian_alert`: with dispatch disabled an alert stays queued in the outbox and nothing is sent.
- Direct sends that are deliberately NOT gated because a person asked for them: the guardian verification e-mail, the panic-button alert, OTP codes, e-mail change confirmation, the daily report e-mail and the "claim released" notice. `tests/unit/test_guardian_dispatch_gate.py` lists every send site; a new one fails that test until it is reviewed.
- It does not depend on Twilio. `GUARDIAN_OUTBOX_POLL_SECONDS` (read through the shared settings, so a selected env file works; process environment wins) of 0 or less disables it.
- Startup no longer calls the Twilio API.

## Connection safety checks (all read-only)
- A database URL may not carry `host`, `hostaddr`, `port`, `database`, `dbname`, `user`, `username`, `password`, `passfile`, `service`, `servers`, `dsn` or `target_session_attrs` query parameters (any case or percent-encoding), and the driver's effective connection arguments must equal the host, port and database the URL names.
- A host is a Neon endpoint only on the exact `.neon.tech` domain; lookalike domains never match the registry. Hosts must be plain ASCII hostnames.
- The production database NAME (`database:SecureShieldDB` in `config/production_endpoints.txt`, plus `PRODUCTION_DATABASE_NAMES`) is refused outside production on any host. Localhost, an SSH tunnel and a port forward all look the same, so the name is the only tell. A local development database must therefore have another name (for example `secureshield_dev`).
- A URL must name a database, and the engine pins the port: asyncpg otherwise takes a missing port from `PGPORT` and a missing database from `PGDATABASE` (verified against asyncpg 0.29.0 with its own parser; `PGHOST` is never used because a host is mandatory). `PGPORT` cannot redirect a validated target.
- After the engine exists, `SELECT current_database()` must equal the configured database name. This runs at application startup (before anything else uses the database), in the maintenance CLIs, and inside Alembic before the first migration statement. If the database cannot be reached at startup the app refuses to boot (fail closed).
- `app/cli/admin_accounts.py` and `app/cli/bootstrap_admin.py` (including its dry run) validate the declared identity and run the `current_database()` check before touching the database; `check_rate_limit_config` validates identity (no connection) whenever the database URLs are in its environment.
- The integration harness (`tests/integration/conftest.py`) checks the effective identity of `TEST_DATABASE_URL` (routing parameters, lookalikes, empty database, production endpoints/names), pins the port of its engines and runs the read-only `current_database()` check.
- `docs/neon-migration/scripts/` (23 database-touching scripts) all import `connection_guard.py`: every `asyncpg.connect` (and so every SQLAlchemy engine) is checked, and every child process that can reach a database (pg_dump, pg_restore, alembic, the backend scripts) is checked first. Only a loopback server or a registry Neon endpoint is accepted. Production-class targets need an explicit confirmation in the environment: `SECURESHIELD_CONFIRM_PRODUCTION_READ=ep-cool-silence-aohbh87f,database:secureshielddb` (read: the Neon endpoint, and the legacy local source whose name is the production name) and `SECURESHIELD_CONFIRM_PRODUCTION_WRITE=ep-cool-silence-aohbh87f` (any write to the registry endpoint). Scratch/rehearsal databases need nothing. The documented workflows are otherwise unchanged. These scripts were written before Stage 1.1: scripts that import the application settings (`95_cutover_smoke.py`, `conn3.py`, `pooled_probe.py`) now need `SECURESHIELD_ENV_FILE`, `ENVIRONMENT` and `DATABASE_ENVIRONMENT` set explicitly.
- `scripts/migration_rehearsal.py` passes `ENVIRONMENT=development` and `DATABASE_ENVIRONMENT=local` to its Alembic subprocess and prints the child's error output (scrubbed) instead of discarding it.
- Operator scripts (`db_backup`, `db_restore_check`, `migration_rehearsal`, `premigration_report`) check their target first: scratch operations need a loopback, non-registry server; read-only scripts refuse a production-registry endpoint unless `SECURESHIELD_CONFIRM_PRODUCTION_READ` is set to that exact endpoint id. `seed_sms_registry` validates the declared environment.

## Deletion inventory (review item L3)
| Delete | Gated by `RETENTION_CLEANUP_ENABLED`? | Why |
|---|---|---|
| link-scan history older than `LINK_SCAN_RETENTION_DAYS` | yes | retention of user data |
| `error_logs` older than `LOG_RETENTION_DAYS` | yes | retention of operational data |
| terminal guardian-outbox rows past retention | yes | retention of user data |
| expired refresh-token uses and revoked token families (`app/routers/auth.py`, on refresh) | **no, by design** | token hygiene: rows past their own `expires_at` that can no longer be used for anything. They are not user data kept for a retention period. |
| expired `PendingRegistration` rows (`app/services/identity.py` `purge_expired_pending`, called while registering) | **no, by design** | not retention: these are unconfirmed sign-ups whose own `expires_at` has passed. Removing them is part of making registration work (`pending_registrations.email` is unique, so an expired row would block a retry with the same e-mail) and they hold no completed account data. Gating would break registration whenever the flag is off. It still only runs on a database that passed the identity checks. |
| account erasure (`account_erasure`) | no | user-requested deletion |

## Tests
`pytest tests/unit` needs no database and opens no database connection: `tests/unit/conftest.py` replaces every connection entry point (`asyncpg.connect`/`create_pool`, sockets and event loops to ports 5432/5433/6543, the identity-verification helper), counts any attempt and fails the test at teardown even if the code under test swallowed the error. The terminal summary reports the number of attempts. Tests that need to serve requests use the `no_database` fixture (an in-memory fake session). Integration tests need `TEST_DATABASE_URL` pointing at a disposable loopback database whose name ends in `_test`.
