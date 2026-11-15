# Stage 1.2C: inventory of the pre-existing local SecureShield PostgreSQL objects

Date: 2026-11-15. Method: **repository evidence only** (documentation, scripts, tests, CI files, earlier audit reports). No PostgreSQL connection, no SQL, no `psql`, no Alembic, no backend start, no change to any database, role or permission, no Git operation. Search scope: `D:\ravishori\SecureShieldApp` (backend, docs, `docs\neon-migration`) and `D:\ravishori\claude workspace` (no match there). The Flutter repository was not searched (it holds no database names).

## 1. What was observed (reported by you at runbook §1.5)
Role `secureshield_rehearsal_owner`; databases `secureshield_cw_test`, `secureshield_drive_restore_20261113`, `secureshield_e2e_test`, `secureshield_migration_test`, `secureshield_neon_rehearsal_restored_20261018`, `secureshield_neon_rehearsal_s2_20261018`, `secureshield_neon_rehearsal_s3_20261018`, `secureshield_restore_check_20261113t140939z`.

**None of these names equals, or is a prefix of, any name this stage will create** (`secureshield_dev`, `secureshield_test`, `secureshield_dev_owner`, `secureshield_dev_app`, `secureshield_test_owner`). Note that the §1.5 query returned them only because it searched the broad pattern `secureshield\_%`, not the exact names.

## 2. Evidence and likely purpose of each object
| Object | Repository evidence | Likely purpose / origin | Confidence |
|---|---|---|---|
| role `secureshield_rehearsal_owner` | `docs/neon-migration/scripts/30_create_rehearsal_dbs.py:4,30` ("LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE - mimics Neon's non-superuser owner"); `rehearsal_env.py:32`; `DATA_VALIDATION_REPORT.md:52`; `MIGRATION_EXECUTION_REPORT.md:62,95,103` ("created: 3 scratch objects (2 databases, 1 role)"); inventories under `docs/neon-migration/baseline/*.json`; `ROLLBACK_PROCEDURE.md:31` (`DROP ROLE ...` listed as the rollback) | The non-superuser owner used to rehearse the Neon migration (2026-10-18). Its password is read from a file under `C:\Users\ravin\SecureShieldBackups\neon-migration-20261018\` (`rehearsal_env.py` OUT_DIR). I did not open that file. | High |
| `secureshield_neon_rehearsal_restored_20261018` | `30_create_rehearsal_dbs.py:6`, `40_restore_into_rehearsal.py:3`, `rehearsal_env.py:29`, `ROLLBACK_PROCEDURE.md:29`, `MIGRATION_EXECUTION_REPORT.md:95` | Restore of the local backup at head schema (superuser-owned, "like the source cluster"); Alembic rehearsal | High |
| `secureshield_neon_rehearsal_s2_20261018` | same files plus `70_validate_data.py`, `80_final_checks_s2.py`, `baseline/rehearsal_s2_inventory.json` (owner `secureshield_rehearsal_owner`) | Empty "Neon-like" target that received the data copy and the application smoke test | High |
| `secureshield_neon_rehearsal_s3_20261018` | `rehearsal_env.py:31`, `100_neon_migrate.py:20`, `94_negative_tests_rehearsal.py:3`, run records `baseline/runs/rehearsal_*_20261018T17*.json` | Empty target used to exercise `100_neon_migrate.py --target rehearsal` end to end and its negative tests. Created later than the first two (the execution report counts 2 databases; `ROLLBACK_PROCEDURE.md` does not list s3) | High |
| `secureshield_restore_check_20261113t140939z` | `docs/audit/SECURESHIELD_RELEASE_READINESS.md:541,586` ("retained pending separate cleanup approval"; owner decision whether to drop it); `scripts/db_restore_check.py:98` generates this name pattern | Scratch database of the 2026-11-13 backup restore exercise. `db_restore_check.py` normally drops its scratch databases itself, so this one was deliberately kept | High |
| `secureshield_drive_restore_20261113` | `docs/audit/SECURESHIELD_RELEASE_READINESS.md:710` (restore of the copy downloaded from Drive: "restored into the new local database `secureshield_drive_restore_20261113` ... 29 checks passed") | Verification restore of the off-machine backup, same exercise (2026-11-13). No evidence of a cleanup decision | High |
| `secureshield_cw_test` | `docs/neon-migration/scripts/run_with_local_test_db.py:4,35` (launcher "preferring `secureshield_cw_test`" among local `*_test` databases); `tests/unit/test_integration_db_guard.py:21` and `tests/unit/test_final_corrections.py:283` use it as the example of an acceptable test name | The local integration-test database used in earlier phases (the harness requires a `*_test` name). What "cw" stands for is not stated anywhere | Medium (purpose); name origin unknown |
| `secureshield_e2e_test` | **No repository reference to this name.** `scripts/e2e_local_server.py` takes its database from the process environment and names none | Plausibly the database of the on-device end-to-end harness (`e2e_local_server.py`), named to satisfy the `_test` rule. Pure inference | **Low / unknown** |
| `secureshield_migration_test` | **No repository reference to this name.** `scripts/migration_rehearsal.py:182` creates and drops `secureshield_migration_review_<random>` instead; `docs/MIGRATION_SAFETY_REVIEW.md` exists but does not name it | Plausibly a manual database for an earlier migration review. Pure inference | **Low / unknown** |

## 3. Is any of them configured as an active development or test target?
- **As the application's development database: no.** `.env.example`, `start.bat`, `docs/LOCAL_DEVELOPMENT.md` and every Stage 1.x document use `secureshield_dev` only; no `.env.local` exists. (The real `backend\.env` holds `LOCAL_DATABASE_URL` for the legacy local database; I did not read it and it is not loaded by the application.)
- **As the integration-test database: de facto `secureshield_cw_test`, through one launcher only.** `docs/neon-migration/scripts/run_with_local_test_db.py` selects "the first existing `*_test` database, preferring `secureshield_cw_test`" on the local server and builds `TEST_DATABASE_URL` from the **legacy local credentials** (not from the new roles). Nothing else in the repository names a local test database; CI uses its own GitHub service container (`secureshield_ci_test` in `.github/workflows/backend-ci.yml:35-39`), which is not this machine.
- **The four Neon-rehearsal databases and the two 2026-11-13 restore databases are targets of scripts and reports, never of the application, Alembic configuration or the test harness.** They are touched only by the scripts in `docs/neon-migration/scripts` (guarded since Stage 1.1) and by `db_restore_check.py` (which only creates its own scratch names).
- Two databases (`secureshield_e2e_test`, `secureshield_migration_test`) are not configured anywhere.

## 4. Can `secureshield_dev` and `secureshield_test` be created safely alongside them?
**Yes, on the evidence, with the conditions in section 6.**
- **No name collision.** `CREATE DATABASE`/`CREATE ROLE` for the new names cannot touch any listed object, and the SQL's existence checks look up the new names only.
- **The SQL never modifies another role or database.** Part 1 inspects only the three new roles (including the new "membership" check, which concerns those three); Parts 3 and 4 `REVOKE`/`GRANT` only on the two new databases and their `public` schemas. `secureshield_rehearsal_owner` is not a member of, and does not own, anything the script creates.
- **Isolation runs in the safe direction.** After Part 3, `PUBLIC` cannot connect to `secureshield_dev`/`secureshield_test`, so `secureshield_rehearsal_owner` and any other old role cannot reach the new databases.

## 5. Potential ownership or permission conflicts
| # | Conflict or interaction | Severity | Note |
|---|---|---|---|
| 1 | **Runbook §1.5 expectation is wrong for this machine.** It says "0 rows" for the broad `secureshield\_%` query, while its prose stop condition concerns only `secureshield_dev*`/`secureshield_test*`. The two statements disagree, and the broad one cannot hold on a machine that ran the Neon rehearsal | Medium (process) | Resolved by approving a narrower check (section 6, item 1). The stop condition is **not** bypassed by this report |
| 2 | The new roles keep PostgreSQL's default `PUBLIC` privileges on the **old** databases (CONNECT, TEMP). `secureshield_dev_app` could therefore connect to, say, `secureshield_cw_test` and create temporary tables, though not read tables it has no privilege on | Low | The SQL isolates dev from test but does not govern the old databases. Optional later hardening (a separate decision): revoke `PUBLIC` CONNECT on the old databases |
| 3 | `run_with_local_test_db.py` uses the **legacy local superuser credentials** and the first `*_test` database. If `secureshield_cw_test` is ever removed it would pick another `*_test`, possibly `secureshield_test`, and run tests there as the superuser instead of `secureshield_test_owner` | Low | Only the launcher is affected; the harness guards still apply. Avoid the launcher once the new test database exists |
| 4 | Three old databases that satisfy the `_test` rule (`secureshield_cw_test`, `secureshield_e2e_test`, `secureshield_migration_test`) would be accepted by the integration harness if `TEST_DATABASE_URL` pointed at them; the harness would then `TRUNCATE` their tables | Low | They are test-named and loopback, so by design; the risk is only picking the wrong one by mistake. Keep `TEST_DATABASE_URL` exactly as in the runbook (`secureshield_test`) |
| 5 | **Disk.** Eight old databases share the data volume that has 1.77 GB free; their sizes are unknown | Medium (capacity) | Look at the `\l+` sizes captured in runbook §1.8 before deciding anything; the two new empty databases need only about 20 MB |
| 6 | A plaintext password file for `secureshield_rehearsal_owner` exists under `C:\Users\ravin\SecureShieldBackups\neon-migration-20261018\` per the scripts | Low (hygiene) | Not opened or changed. Decide separately whether to keep it after the rehearsal databases are retired |
| 7 | **Side finding, outside this task:** `.github/workflows/backend-ci.yml:88` runs `python -m alembic upgrade head` with `DATABASE_URL`/`MIGRATOR_DATABASE_URL` set but without `ENVIRONMENT`/`DATABASE_ENVIRONMENT`. Since Stage 1.1 the identity check refuses that (`DATABASE_ENVIRONMENT` is required), so that CI step would fail closed | Medium (CI) | Not changed here. Setting `ENVIRONMENT: test` and `DATABASE_ENVIRONMENT: test` in that job's `env` would satisfy it; separate approval |

## 6. Unknowns (cannot be settled from the repository)
- The actual owner of each database (only `s2`/`s3` are documented as `secureshield_rehearsal_owner`; the others are likely the `postgres` superuser) and the actual attributes of `secureshield_rehearsal_owner` (documented as LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE).
- Sizes, contents and last use of every database. The `\l+`/`\du+` inventory in runbook §1.8 answers this without exposing data.
- Who created `secureshield_e2e_test` and `secureshield_migration_test`, and whether they hold anything worth keeping.
- Whether `SecureShieldDB` exists (the §1.5 pattern, which requires an underscore, would not list it).
- Whether the 2026-11-13 restore databases are still wanted (the readiness report leaves their cleanup as an owner decision).

## 7. Recommendation (safe, and it does not bypass the §1.5 stop)
1. **Treat §1.5 as having fired correctly and do not continue until you approve a corrected check.** Proposed replacement for §1.5 (**not applied, not run**; for your approval):
   - exact-name check, expected **0 rows, 0 rows, 0**:
     `SELECT rolname FROM pg_roles WHERE rolname IN ('secureshield_dev_owner','secureshield_dev_app','secureshield_test_owner') ORDER BY 1;`
     `SELECT datname FROM pg_database WHERE datname IN ('secureshield_dev','secureshield_test') ORDER BY 1;`
     `SELECT count(*) FROM pg_stat_activity WHERE datname = 'template1';`
   - plus an **informational** listing, expected to show the eight old databases and no others except `SecureShieldDB`, `postgres`, `template0/1`:
     `SELECT d.datname, r.rolname AS owner, pg_size_pretty(pg_database_size(d.datname)) AS size FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname !~ '^template' ORDER BY d.datname;`
   - **STOP** if either exact-name query returns a row (a same-named object would need a human decision) or the template1 count is not 0.
2. Capture the `\l+` and `\du+` inventory (runbook §1.8) and send it, so the unknowns above can be settled and the disk question answered.
3. **Do not drop, rename or modify any old database or role as part of the activation.** Their cleanup is a separate approval (the retained 2026-11-13 databases are already waiting for one).
4. Keep using exactly `secureshield_test` / `secureshield_test_owner` for `TEST_DATABASE_URL` and avoid `run_with_local_test_db.py` afterwards.
5. Separately decide the CI environment fix (5.7) and, later, whether to retire the rehearsal databases and their password file.

## 8. Status
This inventory is based on repository evidence only; **no database was contacted and database activation has not begun**. After you approve (or amend) the corrected §1.5 check and report its result, the runbook can resume at §1.6.
