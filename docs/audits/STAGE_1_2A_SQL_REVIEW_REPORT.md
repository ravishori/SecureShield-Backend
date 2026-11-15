# Stage 1.2A: final SQL safety review

Date: 2026-11-15. File reviewed: `docs/database/STAGE_1_2_LOCAL_DATABASE_SETUP.sql` (read in full, line by line, and checked against the Stage 1.1 code and the documented URLs). **The SQL was not executed, `psql` was not run, and no database was contacted.**

## 1. Verdict: APPROVED WITH CONDITIONS
Safe for a later, explicitly approved, manual run **after the corrections below** (already applied). The conditions are about what static review cannot prove:
1. It has never run on a PostgreSQL server. Run it supervised, once, and check every Part 5 result against its stated expectation before using the databases.
2. Run it only as the local superuser, over loopback, on the machine's own PostgreSQL 18 service.
3. Treat any abort as a stop-and-review (every check aborts rather than "fixes").

## 2. Role and privilege review
| Requirement | Finding |
|---|---|
| Databases `secureshield_dev`, `secureshield_test`; roles `secureshield_dev_app`, `secureshield_dev_owner`, `secureshield_test_owner` | match the SQL, `.env.example`, `docs/LOCAL_DEVELOPMENT.md` and the harness (`*_test` suffix) exactly |
| No unnecessary SUPERUSER / CREATEDB / CREATEROLE / REPLICATION / BYPASSRLS | every role is created `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`; **new:** a pre-existing role with any of these, or with membership of another role, aborts Part 1 |
| Ownership | `CREATE DATABASE ... OWNER` gives each database to its owner role; an existing database with a different owner aborts the script |
| App role cannot migrate or administer | `secureshield_dev_app` has CONNECT, schema USAGE and default DML/sequence-USAGE privileges only. No CREATE on the database or schema (PUBLIC's CREATE/TEMP are revoked), not the owner of any table (so no DDL), no TRUNCATE/REFERENCES/TRIGGER, no CREATEROLE. I confirmed the application runs no DDL at runtime (no `create_all`, no `CREATE/ALTER/TRUNCATE` in `app/`). |
| Test role cannot reach the development database | `REVOKE ALL ON DATABASE secureshield_dev FROM PUBLIC` plus an explicit revoke from `secureshield_test_owner`; the dev roles are likewise revoked on `secureshield_test`. Part 5.4 prints the full connect matrix. |
| Passwords never in SQL or committed files | no password is created or set; roles have no password until `\password` is run by hand; `.env.example` holds `YOUR_...` placeholders only (tests assert it). Reading `pg_hba.conf` shows loopback `scram-sha-256` only, so a role without a password cannot log in. |
| Privileges granted only to the intended roles | every `GRANT` names a specific role; no `GRANT ALL`, grant option or `pg_*` role. Default privileges are scoped `FOR ROLE secureshield_dev_owner IN SCHEMA public`, so objects created by anyone else (for example a superuser running Alembic by mistake) get no automatic access: that fails visibly rather than silently over-granting. |

## 3. Transaction and idempotency review
| Part | Transaction | Re-run / interruption |
|---|---|---|
| 0 precheck | one `DO` | read-only |
| 1 roles | one `BEGIN/COMMIT`; `CREATE ROLE` only if missing; then a privilege check that rolls back everything on violation | safe; existing roles are **never altered** |
| 2 databases | **autocommit**, via `SELECT format(...) WHERE NOT EXISTS ... \gexec`; not inside any transaction | safe; a failure between the two creates leaves one database, the next run creates the other; a database that already exists is only checked for ownership |
| 3 connect privileges | one transaction | `GRANT`/`REVOKE` are idempotent |
| 4 schema privileges | one transaction per database after `\connect` | idempotent; a failed non-interactive `\connect` terminates psql |
| 5 verification | none, SELECT only | read-only |
`CREATE DATABASE` never appears inside `BEGIN..COMMIT` (a test checks every line). `ON_ERROR_STOP` and now `AUTOCOMMIT on` are set inside the script, so a psqlrc or `-v AUTOCOMMIT=off` cannot change that. A Ctrl-C or lost connection mid-transaction rolls the open part back. Nothing is dropped, reset or overwritten anywhere. Rollback needs no destructive operation: disable the logins (`NOLOGIN`) and re-enable them later; removal of the databases/roles stays an optional, manual administrator decision documented outside the SQL.

## 4. PostgreSQL 18 compatibility findings
Checked by reading each construct against PostgreSQL 15-18 semantics; **not proven by execution**.
| Construct | Assessment |
|---|---|
| `DO $$ ... $$` with `RAISE EXCEPTION`, `FOR spec IN SELECT ... FROM (VALUES ...)`, `format('%I', ...)`, `EXECUTE` | valid; transaction-safe |
| `CREATE ROLE ... LOGIN NOSUPERUSER ... NOINHERIT ... CONNECTION LIMIT n` | valid; no password option used; attribute order is free |
| `CREATE DATABASE %I OWNER %I` via `\gexec` | valid in autocommit; creating a database for another role as superuser is allowed; copies `template1` and fails if another session is connected to it (documented; harmless; re-run) |
| `REVOKE ALL ON DATABASE ... FROM PUBLIC`, `GRANT CONNECT` | valid; superuser bypasses CONNECT so the later `\connect` still works |
| `REVOKE ALL ON SCHEMA public FROM PUBLIC`, `GRANT USAGE` | valid; in PG15+ the schema is owned by `pg_database_owner`, so the database owner keeps CREATE/USAGE implicitly |
| `ALTER DEFAULT PRIVILEGES FOR ROLE ... IN SCHEMA public GRANT ... ON TABLES / SEQUENCES` | valid; applies to objects the owner role creates later (Alembic) |
| `inet_server_addr() <<= '127.0.0.0/8'::inet` | valid; NULL on a Unix socket is accepted |
| `pg_authid` (password presence), `pg_hba_file_rules`, `aclexplode`, `acldefault('d', ...)`, `has_database_privilege`, `pg_auth_members` | valid for a superuser in PG18 (`pg_auth_members` gained columns in PG16; only `roleid`/`member` are used) |
| psql: `\set ON_ERROR_STOP`, `\set AUTOCOMMIT on`, `\gexec`, `\connect` | valid; `\connect` may re-prompt for the administrator password |
Encoding and collation come from `template1`; Part 5.3 shows the encoding (expect UTF8). The file is pure ASCII with LF endings (a test enforces it), so a Windows console encoding cannot corrupt it.

## 5. Configuration consistency
| Item | Result |
|---|---|
| `.env.example` active block | `ENVIRONMENT=development`, `DATABASE_ENVIRONMENT=local`; `DATABASE_URL` → `secureshield_dev_app@localhost:5432/secureshield_dev`; `MIGRATOR_DATABASE_URL` → `secureshield_dev_owner` on the same endpoint and database; passes `validate_identity` (class `loopback`) |
| Test URL example | `secureshield_test_owner@localhost:5432/secureshield_test`, accepted by the integration harness; the development URLs and `SecureShieldDB` are refused by it |
| Alembic | `alembic/env.py` uses `MIGRATOR_DATABASE_URL` (the owner role), validates identity and the connected database name first, reads no `.env` |
| `app/config.py`, `app/database.py`, `app/db_identity.py`, `app/db_url.py` | unchanged; the production name, registry endpoints and remote hosts remain blocked outside production |
| Application connection pool vs role limits | SQLAlchemy's default pool is 5 + 10 overflow per process; dev auto-reload briefly runs two processes, so the app role's limit is **50** (it was 20; see C4) |
| Documented commands vs files | `LOCAL_DEVELOPMENT.md`, the SQL header and `.env.example` name the same databases, roles, variables and steps |

## 6. Corrections made (genuine issues only)
| # | Issue | Correction |
|---|---|---|
| C1 | "Existing roles are not destructively modified": Part 1 re-asserted attributes with `ALTER ROLE` on roles that already existed, i.e. it changed someone's existing role | removed; replaced with a **check** that aborts (and rolls back Part 1) if a role holds superuser/createdb/createrole/replication/bypassrls or any role membership |
| C2 | Verification 5.1 read `rolpassword` from `pg_roles`, which masks every password as `********`, so "has_password" would always have been true and mislead | reads `pg_authid` (superuser), selecting only `rolpassword IS NOT NULL`, never the hash |
| C3 | The no-password design assumed password authentication; a `trust` rule would let anyone in | added verification 5.1b (`pg_hba_file_rules`, expect no `trust` rows). I also read this machine's `pg_hba.conf`: loopback `scram-sha-256` only |
| C4 | `CONNECTION LIMIT 20` for the app role could exhaust under dev auto-reload | per-role limits: app 50, owners 20 |
| C5 | The loopback check alone cannot tell a local server from an SSH tunnel to a hosted one | precheck also refuses a server with hosted-service fingerprints (settings `neon.*`, roles such as `neon_superuser`, `rds_superuser`, `azure_pg_admin`, `cloudsqlsuperuser`); it already refuses non-superusers, which a hosted service never grants |
| C6 | `CREATE DATABASE` depends on autocommit | `\set AUTOCOMMIT on` inside the script |
| C7 | Verification 5.5 only looked for PUBLIC grants | now lists every non-owner grantee on both databases; expected: exactly one row (`secureshield_dev | secureshield_dev_app | CONNECT`) |
| C8 | Rollback wording was ambiguous; the `template1` and psql re-prompt behaviours were undocumented | clarified in the SQL header and `docs/LOCAL_DEVELOPMENT.md` |
No Stage 1.1 file was changed. `config/production_endpoints.txt` is unchanged.

## 7. Exact files changed
- `docs/database/STAGE_1_2_LOCAL_DATABASE_SETUP.sql` (C1-C8)
- `docs/LOCAL_DEVELOPMENT.md` (step 0 hardening note, the setup step's refusals and caveats)
- `tests/unit/test_local_environment_setup.py` (updated for the new SQL; 3 new tests: ASCII/LF file, pg_authid password check and trust check, dollar-quote and transaction balance)
- `docs/audits/STAGE_1_2_IMPLEMENTATION_REPORT.md` (the Part 1 description line; see its note)
- `docs/audits/STAGE_1_2A_SQL_REVIEW_REPORT.md` (new, this file)

## 8. Tests actually executed (no database)
| Run | Result |
|---|---|
| `tests/unit/test_local_environment_setup.py` | 40 passed |
| `pytest tests/unit` | **1281 passed, 3 skipped, 0 failed** (3 need `TEST_DATABASE_URL`) |
| `pytest tests` | 1281 passed, 939 skipped (integration tests skip without `TEST_DATABASE_URL`) |
| `ruff check --select F,E9` (`app`, `scripts`, `tests`, `alembic/env.py`) | all checks passed |
Not run: the SQL, `psql`, Alembic, integration tests, the backend.

## 9. Database connections attempted: zero
The connection-blocking plugin recorded 0 attempts reaching a real connect function, and the repository guard reported 0 attempts from any test other than its own self-tests (which call the blocking stubs on purpose). I read two configuration files on disk, `pg_hba.conf` and `postgresql.conf`, as text; that is not a connection.

## 10. Manual steps and remaining risks
- **Unproven by execution (Medium, inherent).** Run supervised; compare each Part 5 result with its expectation. Paste the results back for a second look before relying on the databases.
- **Hosted-service fingerprint is best-effort (Low).** A tunnel to a hosted server whose fingerprint is not in the list would still be stopped by the non-superuser refusal, but a tunnel to another *local-looking* superuser-accessible server cannot be detected by SQL.
- **Server listens on `*` (Low).** Remote clients are rejected by `pg_hba.conf`, but setting `listen_addresses = 'localhost'` is still recommended; not done by the script.
- **Same-name roles (Low).** Roles are cluster-wide; if the three names already exist, check Part 5.1 and the abort message.
- **Alembic must run as the owner (Informational).** Running it as the superuser would create tables the app role cannot read, which fails loudly.
- **Legacy local `SecureShieldDB` (Low).** Untouched; 5.6 reports whether it exists.

## 11. Recommended next action
Do a supervised manual run of the SQL as described in `docs/LOCAL_DEVELOPMENT.md` (read it once more, run step 2, set the passwords, and send back the Part 5 output and `show_database_target` result). Only after those match their expectations should migrations (`alembic upgrade head` against `secureshield_dev`) be approved as a separate step. Stage 1.3 has not been started.
