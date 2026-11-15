# Stage 1.3: supervised local database migration report

Date: 2026-11-15 (migration run 21:22:36 to 21:22:37 +05:30). **Final status: PASSED.**
Target: database `secureshield_dev` on the local PostgreSQL 18.6 server (`localhost:5432`, reached over `::1`), environment `development` / `local`. Migration role: `secureshield_dev_owner` (through `MIGRATOR_DATABASE_URL`). Runtime role: `secureshield_dev_app` (never used to migrate).

**What was and was not done.** Executed: the preflight checks, one read-only inventory before, `python -m alembic upgrade head`, and read-only verification queries after. Not done: seed scripts, application startup, any SMS/e-mail/WhatsApp/AI call, any downgrade/reset/deletion, any code or migration change, any Git operation, any connection to Neon or another production-class endpoint, any use of the `postgres` superuser. Credentials were read by the application's own configuration loader from the explicitly selected `.env.local`; I never saw, printed or stored them.

## 1. Preflight (all gates passed before the migration ran)
| # | Check | Result | Status |
|---|---|---|---|
| 1 | Reference documents read (1.2E review, 1.2B runbook, `LOCAL_DEVELOPMENT.md`) | read; 1.2E verdict SAFE WITH CONDITIONS, no blockers | PASS |
| 2 | `SECURESHIELD_ENV_FILE` explicitly `.env.local`; no `PG*`, `DATABASE_URL`, `MIGRATOR_DATABASE_URL`, `TEST_DATABASE_URL` set in the shell | variable set for the commands only; no stray variables | PASS |
| 3 | `python -m app.cli.show_database_target --expect development` | exit 0: `database identity OK: environment=development class=loopback database=secureshield_dev`; runtime role `secureshield_dev_app`; migrator role `secureshield_dev_owner`; `connection: none made by this command` | PASS |
| 4 | URLs resolve to `secureshield_dev` | same output; additionally the live check below read `current_database()` = `secureshield_dev` | PASS |
| 5 | Free space on D: (limit: stop below 1 GB) | **1.68 GB** | PASS |
| 6 | Alembic has one head `x9y0z1a2b3c4` | `python -m alembic heads` printed exactly `x9y0z1a2b3c4 (head)`; exit 0 (this command reads the script directory and does not run `env.py`) | PASS |
| 7 | PostgreSQL service | `postgresql-x64-18` Running, `PostgreSQL18` Stopped | PASS |
| 8 | Target is the newly created, empty development database (read-only inventory as the owner role, `default_transaction_read_only=on`) | see section 2 | PASS |

## 2. Pre-migration inventory (read-only, executed)
| Item | Value |
|---|---|
| Database / user / superuser | `secureshield_dev` / `secureshield_dev_owner` / `false` |
| Server | PostgreSQL 18.6, address `::1/128`, port 5432 |
| Database owner / encoding / size | `secureshield_dev_owner` / UTF8 / **8102 kB** (8,296,127 bytes) |
| Schemas | `public` only |
| Extensions | `plpgsql` only |
| Relations in `public` | **none** (no tables, sequences, indexes or enum types) |
| `alembic_version` table | **absent** (no current revision) |
| Free space on D: | 1.68 GB |
Verdict of the inventory script: `PREFLIGHT_DATABASE_IS_NEW_AND_EMPTY: True`.

## 3. Migration execution (executed)
Command (from `backend`, with `SECURESHIELD_ENV_FILE=.env.local`): `python -m alembic upgrade head`. Alembic's `env.py` ran the Stage 1.1 identity checks, then the read-only `current_database()` check, then migrated through `MIGRATOR_DATABASE_URL` (the owner role). **Exit code: 0.** Duration about 1.4 seconds. 28 output lines: 2 context lines and 26 `Running upgrade` lines, no warning, no error, no traceback, no notice.
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 07cfca043074, initial
INFO  [alembic.runtime.migration] Running upgrade 07cfca043074 -> 3bf328167739, add_error_logs_table
INFO  [alembic.runtime.migration] Running upgrade 3bf328167739 -> 6098a82b5e06, phone_email_otp_support
INFO  [alembic.runtime.migration] Running upgrade 6098a82b5e06 -> 519e8e8aa0ae, add_address_profile_fields
INFO  [alembic.runtime.migration] Running upgrade 519e8e8aa0ae -> a1b2c3d4e5f6, add recordings table
INFO  [alembic.runtime.migration] Running upgrade a1b2c3d4e5f6 -> e9e22b86f70c, add_community_scam_behavior_event
INFO  [alembic.runtime.migration] Running upgrade e9e22b86f70c -> d845ea331d7d, add emergency_contacts
INFO  [alembic.runtime.migration] Running upgrade d845ea331d7d -> f1a2b3c4d5e6, recreate behavior_events, community_scam_reports and create emergency_contacts
INFO  [alembic.runtime.migration] Running upgrade f1a2b3c4d5e6 -> g2h3i4j5k6l7, add gsb_threats to link_scans
INFO  [alembic.runtime.migration] Running upgrade g2h3i4j5k6l7 -> h3i4j5k6l7m8, create sms registry tables (tsp_codes, lsa_codes, sms_sender_registry)
INFO  [alembic.runtime.migration] Running upgrade h3i4j5k6l7m8 -> i4j5k6l7m8n9, make wifi_scan device_id optional
INFO  [alembic.runtime.migration] Running upgrade i4j5k6l7m8n9 -> j5k6l7m8n9o0, make app_scan device_id optional
INFO  [alembic.runtime.migration] Running upgrade j5k6l7m8n9o0 -> k6l7m8n9o0p1, create app_install_events, clone_reports, elderly_configs
INFO  [alembic.runtime.migration] Running upgrade k6l7m8n9o0p1 -> l7m8n9o0p1q2, create warrior_applications, warrior_profiles, warrior_audit_logs
INFO  [alembic.runtime.migration] Running upgrade l7m8n9o0p1q2 -> m8n9o0p1q2r3, family members: consent workflow (consent_status, invited_phone)
INFO  [alembic.runtime.migration] Running upgrade m8n9o0p1q2r3 -> n9o0p1q2r3s4, security_reports: one report per user per day
INFO  [alembic.runtime.migration] Running upgrade n9o0p1q2r3s4 -> o0p1q2r3s4t5, app_scans / wifi_scans: add user_id
INFO  [alembic.runtime.migration] Running upgrade o0p1q2r3s4t5 -> p1q2r3s4t5u6, alerttype: add the members the application already uses
INFO  [alembic.runtime.migration] Running upgrade p1q2r3s4t5u6 -> q2r3s4t5u6v7, otps.code: widen to hold an HMAC and drop any plaintext codes
INFO  [alembic.runtime.migration] Running upgrade q2r3s4t5u6v7 -> r3s4t5u6v7w8, refresh token rotation: consumed-token and revoked-family tables
INFO  [alembic.runtime.migration] Running upgrade r3s4t5u6v7w8 -> s4t5u6v7w8x9, admin audit log
INFO  [alembic.runtime.migration] Running upgrade s4t5u6v7w8x9 -> t5u6v7w8x9y0, per-OTP failed-attempt counter
INFO  [alembic.runtime.migration] Running upgrade t5u6v7w8x9y0 -> u6v7w8x9y0z1, individual admin accounts, MFA sessions, audit actor columns
INFO  [alembic.runtime.migration] Running upgrade u6v7w8x9y0z1 -> v7w8x9y0z1a2, identity binding: verified identifiers, pending registrations, single-identifier OTP challenges, google_sub
INFO  [alembic.runtime.migration] Running upgrade v7w8x9y0z1a2 -> w8x9y0z1a2b3, consent records: user_consents + consent captured with a pending registration
INFO  [alembic.runtime.migration] Running upgrade w8x9y0z1a2b3 -> x9y0z1a2b3c4, app monitor: idempotent sync identity and a durable guardian-alert outbox
ALEMBIC EXIT CODE: 0
```
**The autocommit revision (18, `p1q2r3s4t5u6`) ran without incident**, and so did the five revisions that had no recorded execution before (22 to 26). The async `autocommit_block` path flagged as the one assumption in the 1.2E review worked.

## 4. Revision reached (executed)
`alembic_version` holds exactly one row: **`x9y0z1a2b3c4`** (the expected head). PASS.

## 5. Schema verification (read-only, executed, as the owner role)
| Check | Expected (from the 1.2E replay) | Actual | Status |
|---|---|---|---|
| Tables in `public` | 37 application tables + `alembic_version` = 38 | **38** | PASS |
| Primary keys | 38 | 38 | PASS |
| Foreign keys | 32 | **32** | PASS |
| Indexes (all, incl. PK indexes) | 38 + 14 unique + 61 other = 113 | **113** (52 unique) | PASS |
| Unique constraints (`contype = u`) | the rest are unique indexes | 5 | consistent |
| Check constraints | `ck_admin_accounts_role`, `ck_otps_single_identifier` | exactly those two | PASS |
| Enum types | 11 | **11**; `alerttype` has **16** labels (9 original + 7 added by revision 18) | PASS |
| Sequences | (autoincrement tables) | 3 | informational |
| Schemas | `public` only | `public` only | PASS |
| Extensions | `plpgsql` only | `plpgsql` only | PASS |
| Relations by kind | tables 38, indexes 113, sequences 3 | `r`=38, `i`=113, `S`=3, nothing else | PASS |
The counts (113 indexes, 32 foreign keys, 11 enums, 38 tables) match the offline replay of the 1.2E review exactly. The full table list was captured (38 names) in the session evidence.

## 6. Role and permission verification (read-only, executed)
| Check | Result | Status |
|---|---|---|
| Owner of all 38 tables | `secureshield_dev_owner` (38 of 38) | PASS |
| Owner of all 11 enum types | `secureshield_dev_owner` | PASS |
| Database owner | `secureshield_dev_owner`; the migration role is not a superuser | PASS |
| `secureshield_dev_app`: SELECT, INSERT, UPDATE, DELETE on every table | **missing on 0 of 38 tables** | PASS |
| `secureshield_dev_app`: TRUNCATE / REFERENCES / TRIGGER on any table | none | PASS |
| `secureshield_dev_app`: USAGE and SELECT on every sequence | none missing (3 of 3 covered) | PASS |
| `secureshield_dev_app` on schema `public` | USAGE yes, CREATE **no** | PASS |
| `secureshield_dev_app` on the database | CREATE **no**, TEMP **no** | PASS |
| `secureshield_dev_app` attributes | not superuser, no createdb, no createrole, no replication, no bypassrls | PASS |
| `public` schema ACL | `{pg_database_owner=UC/pg_database_owner, secureshield_dev_app=U/pg_database_owner}` (no PUBLIC entry) | PASS |
| Data rows | `users` 0, `otps` 0, `tsp_codes` 0, `lsa_codes` 0, `sms_sender_registry` 0 (no seed run, as instructed) | PASS |
One of my first verification queries (the table-privilege coverage) failed on a syntax error in my own SQL, which is why it is not in the first result set; I rewrote it and re-ran it (read-only); the second result is the one reported. It is a verification-tool fault, not a database fault.

## 7. Disk usage (executed)
| | Before | After |
|---|---|---|
| `secureshield_dev` size | 8102 kB | **10134 kB** (+2.0 MB) |
| Free space on D: | 1.68 GB | **1.67 GB** (about 10 MB used, including WAL and the Alembic version table) |
Well inside the 1 GB limit.

## 8. Failures and warnings
None. Alembic exit code 0, no warning in its output, every verification matched, no object outside `public`, no unexpected extension. No retry was needed and no repair, downgrade or deletion was attempted or required.

## 9. Executed vs not executed
**Executed:** preflight 1 to 8; read-only inventory (before); `alembic upgrade head`; read-only verification of revision, tables, constraints, indexes, enums, ownership and the runtime role's privileges via catalog functions; disk checks.
**Not executed (open items):**
- Logging in as `secureshield_dev_app` with its own password (privileges were checked through the catalog, not through a real login).
- The remaining Stage 1.2B activation checkpoints for the **test** side and role isolation (`secureshield_test`, `secureshield_test_owner`, cross-database login refusals P4 to P8, `pg_hba` trust check, password-presence query): this run only verified the development side. The Stage 1.2C activation review therefore stays open until that evidence is supplied.
- `alembic check` (model-versus-database drift on the live database), the seed scripts, application startup and any integration tests.

## 10. Final status: **PASSED**
The 26-revision chain applied to the new, empty `secureshield_dev` in one run to the expected head `x9y0z1a2b3c4`, as the owner role, with every structural and permission check matching the 1.2E review. The database is migrated but **not seeded and not in use**. Next separately authorised steps (not started): seed the registry tables, supervised application start against the development database, and completion of the remaining activation evidence.
