# Stage 1.6D-1A — Isolated PostgreSQL Integration Test

**Result (superseded by the Final update at the end): PASS.**
- The rollback-based test module is written, collects, lints clean and skips safely.
- `TEST_DATABASE_URL` is still not available to my process, so **no database connection was made and no integration test has run**.
- Nothing below reports a database result.

## Phase 1 — Configuration (done)
- `tests/conftest.py` forces `DATABASE_ENVIRONMENT=test` and `ENVIRONMENT=test` for every pytest run. It also builds `DATABASE_URL` and `MIGRATOR_DATABASE_URL` only from `TEST_DATABASE_URL`, and removes `SECURESHIELD_ENV_FILE`.
- The earlier "missing `DATABASE_ENVIRONMENT=test`" refusal came from running `show_database_target` against `.env.test`. That file is a legacy dev-style env file, and pytest never reads it. **I made no edit to `.env.test`**, since it holds credentials and the new module doesn't need it.
- `TEST_DATABASE_URL` must come from the process environment. It is **absent** in this session: not in the bash environment, nor in the Windows process, user or machine environment. I checked presence only and printed no value.
- The new module has no fallback to `DATABASE_URL` or `.env.local`. Without the variable, every test is skipped.

## Phase 2 — Database identity (not reached)
The module enforces, before any write, and again in its own fixture:
1. `parse_endpoint` on the URL: loopback host, port 5432, database exactly `secureshield_test`.
2. `SELECT current_database()` must be `secureshield_test`, and `inet_server_port()` must be 5432.
3. The Alembic revision is read (read-only) and compared again after cleanup.

None of this was executed.

## Phase 3 — The test module (written, not run)
`tests/integration/test_sender_registry_rollback.py`: 17 test cases.
- **Isolation:**
  - It does not use the harness fixtures, so there is no migration and no TRUNCATE, DELETE or DROP.
  - One outer transaction is opened on a single connection.
  - Inside it: one fixture user, plus three registry rows with made-up headers `RBTST1`, `RBTST2` and `RBTST3`. No dependence on any seeded data.
  - The router session joins through a SAVEPOINT. The router's `commit()` therefore only releases the savepoint, and the failure handler's rollback only returns to the savepoint. The fixture rows stay.
  - Teardown rolls back the outer transaction.
- **Cleanup check (in the fixture, so it runs for every test):** exact row counts of every public table, and the Alembic revision, must equal their values from before. The fixture rows must be gone.
- **Cases:**
  - Suffixed senders `VM-…-S`, `-T`, `AD-…-P`, lower case, and unsuffixed: REGISTERED through the real query.
  - `-X`, `-G`, a double suffix, an unknown header and an unregistered sender: UNREGISTERED.
  - Blank and phone-number senders.
  - Healthy-registry scoring: benign +0 / +20 / +10, and a scam text with an unregistered sender = 90.
  - **Two real PostgreSQL failures:** `UndefinedFunction`, raised by the server, and a server-side `statement_timeout` cancellation. Each is run through the actual `analyze_message` router function.
  - For each failure it asserts: the risk score (70) and patterns are preserved, the sender is `UNKNOWN` with `lookup_status="unavailable"`, there is no registry red flag, and the shared verdict carries the "could not be verified" limitation and no `sender_not_registered` evidence. It also asserts: the alert is still saved, the same session answers `select 1`, a healthy lookup works again, and the fixture rows survived.
- **Collected and linted without a database:** `pytest` skips all 17 cleanly, and `ruff --select F,E9` is clean.

## Phase 4 — Cleanup verification (not reached)
It happens automatically in the fixture's teardown once the module runs, as described above.

## What is needed to run it
`TEST_DATABASE_URL` must be in the environment of the process that runs pytest. I cannot set it for myself. Either run it yourself in PowerShell, from `backend`:
```powershell
$env:TEST_DATABASE_URL = "postgresql+asyncpg://secureshield_test_owner:<password>@localhost:5432/secureshield_test"
.venv\Scripts\python.exe -m pytest tests/integration/test_sender_registry_rollback.py -v -p no:cacheprovider
```
Or restart this session from a shell where the variable is already set, and I will run it and record the results. `secureshield_test` must already be migrated: this module never migrates.

## Remaining limitations
- No executed result exists for this stage.
- The two failure scenarios are server-side errors created by changing the lookup expression, not a lost connection. A dropped connection is not covered.
- `statement_timeout` takes effect for the whole outer transaction. The test sets it and then resets it with `SET LOCAL`.
- The Stage 1.6D-1 conclusions still rest on the 40 in-memory unit tests alone until this module runs.

---

## Update — run with the supplied URL (still FAIL: test database is empty)
- `TEST_DATABASE_URL` was read in-process from `D:\tmp\test_db_url.txt` (one line, scheme `postgresql+asyncpg`, role `secureshield_test_owner`, localhost:5432). Nothing was printed and the password was masked in all output.
- **Identity evidence (executed, read-only):**
  - `SELECT current_database()` returned `secureshield_test`.
  - `inet_server_port()` returned 5432.
  - `current_user` is `secureshield_test_owner`.
  - The read-only check ran before any write.
- **Result:** all 17 tests errored in fixture setup with `relation "alembic_version" does not exist`. No test body ran, so there are no pass or fail results for the Stage 1.6D-1 behaviour.
- **Cause:** a read-only listing shows `secureshield_test` has **no tables in `public`**. It was never migrated, so this module's precondition ("already migrated") is not met.
- **Not done, per the boundaries:** no migration, DDL or data change. The fixture failed before its transaction began, so nothing was written.
- **Needed:** your decision on how to prepare the test schema, for example a separately approved `alembic upgrade head` against `secureshield_test` only (never `secureshield_dev`) with `ENVIRONMENT=test` selected. This module then runs unchanged.
- **Status: FAIL — NOT EXECUTED.**

---

## Final update — schema prepared, tests executed

**Final status: PASS** (the earlier FAIL / NOT EXECUTED sections above are superseded).

### A. Migration results (authorised, `secureshield_test` only)
- Pre-checks (all passed):
  - `show_database_target --expect test`: environment `test/test`, `localhost:5432`, database `secureshield_test`, runtime and migrator role `secureshield_test_owner`, "no connection made".
  - `DATABASE_ENVIRONMENT=test` and `ENVIRONMENT=test` were set in the process. `SECURESHIELD_ENV_FILE` was unset, and `DATABASE_URL` and `MIGRATOR_DATABASE_URL` were both set from the test URL.
  - `SELECT current_database()` returned `secureshield_test` (port 5432). The public schema was empty, with no `alembic_version`.
  - `alembic heads` returned `y0z1a2b3c4d5`. The identity guards in `env.py` and `db_identity` stayed active.
- `alembic upgrade head`: **exit 0, 27 revisions applied**, ending with `x9y0z1a2b3c4 -> y0z1a2b3c4d5`. No revision file was generated or edited.
- `alembic current`: `y0z1a2b3c4d5 (head)`. `alembic check`: "No new upgrade operations detected."
- Schema verification: 38 tables, 412 columns, 114 indexes, 348 constraints and 38 table comments, **identical to the dev schema snapshot** (taken earlier, not by connecting to dev). `ix_sms_sender_header_upper` is present. All 38 tables are owned by `secureshield_test_owner`.
- Data: no seeding. The only non-empty table is `alembic_version` (1 row).
- Runtime-role privileges: the test environment uses the single owner role for both runtime and migrator, so there is no separate runtime role whose grants could be verified. This differs from dev (`secureshield_dev_app`) and is a limitation.
- `secureshield_dev` was never connected to. All connections used the test URL.

### B. Integration-test results (`tests/integration/test_sender_registry_rollback.py`, not the broad harness)
- **17 passed, 0 failed, 0 errors** (about 4.5 s). Ruff is clean.
- Identity test: `current_database()` is `secureshield_test`, port 5432.
- Registered suffixed senders (`VM-RBTST1-S`, `VM-RBTST1-T`, `AD-RBTST2-P`, lower case, unsuffixed): REGISTERED through the real PostgreSQL query.
- Unknown suffix (`-X`, `-G`, double suffix), unknown header and unregistered sender: UNREGISTERED. Blank is UNKNOWN. A phone number is PHONE_NUMBER.
- Healthy-registry scoring is unchanged. A benign message scores +0, +20 and +10 for registered, unregistered and phone senders. The scam text with an unregistered sender gives legacy 100 (capped) and verdict 90.
- Real PostgreSQL failures, both through the actual `analyze_message`:
  - Server-raised `UndefinedFunction`, which the app logged as a `ProgrammingError`.
  - Server-cancelled `statement_timeout`, logged as a `DBAPIError`.
  - Each time the analysis was preserved (legacy 90, verdict 70, same patterns).
  - The sender was UNKNOWN with `lookup_status=unavailable`, with no "TRAI registry" red flag.
  - The shared verdict carried the "could not be verified" limitation and no `sender_not_registered` evidence.
  - The alert was still saved, the same session answered `select 1`, and a healthy lookup worked again.
  - The fixture rows survived the savepoint rollback.
- One correction made while running: my first draft expected legacy scores of 70 and 90. The real values are 90 (baseline) and 100 (capped), with verdict 70 and 90. These three failures were wrong expectations in my own test, not product defects. I corrected the assertions and reran: 17 passed.

### C. Cleanup verification
- The fixture's teardown rolled the outer transaction back after every test. It compared the exact row count of **all 38 tables**, the revision and the three `RBTST*` registry rows against their values before. It raised no errors.
- Independent post-run check: the only non-empty table is `alembic_version` (1 row), 0 `RBTST%` rows remain, and the schema snapshot is unchanged.

### D. Remaining limitations
- The failures simulated are server-side errors and a timeout. A dropped connection and a pool exhaustion are not covered.
- The test environment uses a single role, so runtime-role privileges are untested here.
- The existing broad integration suite was not run (it truncates and migrates).
- `secureshield_test` now carries the schema. Other tests that use the old harness will truncate it as before.
- The credentials file `D:\tmp\test_db_url.txt` still exists and should be deleted when you no longer need it.
