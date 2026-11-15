# SecureShield — Backend CI Stabilisation Report (local validation only)

Branch `staging/candidate-2026-11-13` (HEAD `dcf9c15`). Reference CI run: 43751931463 (14 failed, 39 errors, 2370 passed, 2 skipped).
**Status: all four failure groups fixed locally. Nothing is staged, committed or pushed; no workflow was changed.** The changes are uncommitted working-tree edits waiting for your approval.

## 1. How the failures were reproduced
CI runs on Linux with a PostgreSQL service container and `TEST_DATABASE_URL` set. To reproduce it without touching any real database I started a **throw-away PostgreSQL 18 cluster** in the session scratchpad (loopback port 55432, trust authentication, database `secureshield_ci_test`), applied the whole migration chain to the blank database, and exported the same environment variables as the CI job (including `ENVIRONMENT=test` and `DATABASE_ENVIRONMENT=test`). Your real local PostgreSQL (port 5432), `secureshield_dev` and `secureshield_test` were not used and not touched; the scratch cluster has been stopped.
The baseline local run (`pytest tests`, same as CI) reproduced 3 of the 4 groups: **10 failed, 22 errors, 2436 passed**. The Neon group did not fail locally only because the scripts folder exists on this machine; the Linux-only socket failure could not be reproduced on Windows (see group 3).

## 2. Root causes and fixes
### Group 1 — Neon guard tests (`test_neon_migration_script_guards.py`: 3 failed, 16 errors)
- **Cause:** the tests parse the 23 scripts in `docs/neon-migration/scripts` of the **project-level** folder (`parents[3]`), which is a different repository. A clean checkout of the backend can never contain it.
- **Fix:** the module is skipped when that folder is absent, with an explicit reason. `REQUIRE_NEON_SCRIPT_TESTS=1` turns a missing folder into a **hard failure** instead, so a full local run cannot silently lose this coverage.
- **Verified:** folder present → 65 passed; simulated clean checkout → 21 skipped; same with the variable set → fails.
- **Coverage note:** these guards are therefore not exercised in CI until the scripts are vendored into the backend repository or run from the repository that holds them.

### Group 2 — Rollback integration module (19 errors)
- **Cause:** the module asserted `database name == secureshield_test` and errored on CI's `secureshield_ci_test`.
- **Fix:** an explicit authorisation model. The module runs **only** when the database name is in `ROLLBACK_TEST_ALLOWED_DATABASES` (default `secureshield_test`, and every name must end in `_test`), the port is in `ROLLBACK_TEST_ALLOWED_PORTS` (default 5432) and the host is loopback. Anything else, or an unparsable or production-class URL, is **skipped before any connection is opened**. After connecting it still verifies `current_database()` and the server port against the same lists and fails loudly on a mismatch. It never migrates, truncates or deletes; everything stays inside one rolled-back transaction.
- **Verified:** default authorisation on the scratch CI database → all skipped ("port 55432 is not authorised"); explicitly authorised → **19 passed**. New unit test file `test_rollback_module_authorisation.py` (10 tests, no connection) covers: accepted database, missing URL, `secureshield_dev`, the CI name, `postgres`, wrong port, non-loopback host, a Neon production URL, a malformed URL, no credential in any skip reason, and the rule that an allow-list entry not ending in `_test` is dropped.

### Group 3 — Unit test isolation (7 failed, 4 errors)
Three separate causes:
1. **`test_database_engine.py`** (3 failed, 3 errors): a "real connection" test inside the unit suite. With `TEST_DATABASE_URL` set (CI) it really connected and was blocked by the guard. **Moved** to `tests/integration/test_database_engine_real_connection.py`, where it first applies the harness safety check (`assert_safe_test_database`) and runs only against a disposable local test database. The unit module keeps its mock-based tests.
2. **`test_local_environment_setup.py`** (1 failed): asserted that `TEST_DATABASE_URL` is unset. The test now removes it with `monkeypatch.delenv` for its own duration (hermetic), still asserting the skip-and-never-fall-back behaviour.
3. **`test_final_corrections.py::…sockets_and_event_loops…`** (1 failed, 1 error, Linux only): the guard patches `asyncio.BaseEventLoop`. **Root cause found in the code:** `test_real_uvicorn_access_log_is_redacted` starts a real uvicorn server, and on Linux uvicorn installs **uvloop's event-loop policy process-wide**. Every later `asyncio.run` then uses uvloop's compiled loop, which the guard cannot patch, so the loop-level block silently stopped applying. **Fix:** the guard fixture pins the standard asyncio policy for every unit test and restores whatever was installed afterwards (a leaked policy can no longer survive into the next test). Two sequential regression tests (`TestUnitLoopPolicy`: leak a policy, then prove the next test is clean) cover it. **Limitation:** I could not run Linux/uvloop here, so this one fix is verified by the stand-in policy test and by reasoning, and needs the next CI run to confirm.
- The unit connection guard is **unchanged in strength**; it is now more robust. Both unit runs (with and without `TEST_DATABASE_URL`) report 0 connection attempts by tests.

### Group 4 — Guardian alert tests (6 failed)
- **Investigation:** `POST /elderly/guardian-alert` returns **202 `queued`**, writes a durable outbox row, and schedules `run_once_safe` as a background attempt. `run_once_safe` only delivers when `dispatch_enabled()` is true, which is **off outside production unless `GUARDIAN_WORKER_ENABLED=true`** (log line seen: "immediate dispatch skipped: guardian dispatch is disabled in this environment"). The six tests were written for the older synchronous design and expected the request to send SMS and e-mail itself.
- **Conclusion: no implementation defect.** The behaviour is intentional and safe (no real message from a test environment); the tests were stale. Delivery logic (`process`/`run_once`: channel independence, per-channel retry, log masking, hourly cap of 10) behaves as the tests expect once the worker runs.
- **Fix (tests only; HTTP 202 semantics untouched):** new shared helpers in `tests/integration/conftest.py` — `quiet_worker` (disables the immediate background attempt), `drain_guardian_outbox()` (runs the worker once in its own session) and `outbox_rows()`. The tests now (a) assert the request path queued the alert and sent nothing, then (b) drain the worker with **mocked providers** and assert delivery, channel independence, rate-limit behaviour and log content.
- **New regression test:** `test_request_path_only_enqueues_and_never_touches_a_provider`: with providers that would raise, the request still returns `{"status": "queued"}`, no provider is called while serving it, one pending outbox row exists, and after a failed delivery run the row stays pending for a retry rather than being lost.

## 3. Files changed (all tests; no application code, workflow or dependency changed)
Modified: `tests/integration/conftest.py`, `tests/integration/test_elderly_protection_api.py`, `tests/integration/test_guardian_alert_logging.py`, `tests/integration/test_sender_registry_rollback.py`, `tests/unit/conftest.py`, `tests/unit/test_database_engine.py`, `tests/unit/test_final_corrections.py`, `tests/unit/test_local_environment_setup.py`, `tests/unit/test_neon_migration_script_guards.py`.
New: `tests/integration/test_database_engine_real_connection.py`, `tests/unit/test_rollback_module_authorisation.py`. (Also untracked and unrelated: the earlier audit reports and `start.bat`.)

## 4. Results (local, CI-equivalent)
| Check | Result |
|---|---|
| Full backend suite, CI conditions (`pytest tests -q -ra`, blank database migrated to head, CI environment variables, `TEST_DATABASE_URL` set) | **2459 passed, 19 skipped, 0 failed, 0 errors** (the 19 skips are the rollback module's default-authorisation skip). Baseline before the fixes: 10 failed, 22 errors. |
| Unit suite with the connection-guard plugin, `TEST_DATABASE_URL` unset | **1519 passed**, 0 connection attempts by tests |
| Unit suite with `TEST_DATABASE_URL` set (CI condition) | **1519 passed**, 0 connection attempts |
| Rollback module on the scratch database, explicitly authorised | **19 passed** |
| Guardian tests (elderly + logging, including the new one) | all pass |
| Ruff check and format (`app tests scripts`, ruff 0.9.4) | clean; 260 files formatted |
| Gitleaks v8.21.2, config `.gitleaks.toml`, full working tree (367 files; ignored files excluded) | **0 findings** |
| Blank-database migration | `alembic upgrade head` on the blank scratch database reaches `y0z1a2b3c4d5` |
| Dependency scan | `pip-audit` is not installed locally and **no dependency changed**, so the last CI result (pass) stands; not re-run |

## 5. Security implications
- No guard was weakened. The unit connection guard now also pins the standard event loop, closing a hole where it silently stopped working after a uvicorn test on Linux.
- The rollback module is stricter than before in one respect (explicit allow-lists, skip-before-connect, names must end in `_test`) and looser only through an explicit opt-in environment variable. A skip never opens a connection.
- Tests still use mocked SMS and e-mail providers only; no real message can be sent. Guardian dispatch stays disabled outside production.
- The unit tests no longer contain a real-connection test; it lives behind the integration harness safety check.

## 6. Unresolved or follow-up
1. **CI will skip the rollback module** (19 tests) and the **Neon guard tests** (65) until you decide to: set `ROLLBACK_TEST_ALLOWED_DATABASES=secureshield_ci_test` in the CI job environment (a one-line workflow change), and vendor or relocate the Neon scripts. Both need a separate approval.
2. The Linux/uvloop fix in group 3 is unverified on Linux until CI runs it.
3. The local reproduction used port 55432, so the guard's blocked-port list (5432, 5433, 6543) was not exercised against a live server on a blocked port; that is the CI condition and is covered by the guard's own tests.
4. Not in scope and still open: the historical credential exposure, the in-memory rate limiter and the device-test gap from the master audit.

## 7. Next step (needs your approval)
Review the diff, then commit these tests as one focused commit and push to `staging/candidate-2026-11-13` as a fast-forward; confirm CI runs green (expected: test step passes with the rollback and Neon modules skipped).
