# Stage 1.6A — Seed Data Readiness Audit

**Verdict: READY WITH CONDITIONS**

Audit only. I did no code edits, no seed or migration runs, no FastAPI startup and no new database connection. I did not read `.env.local`. Facts about the current database come from the read-only catalog snapshot taken in Stage 1.5F (`rowcounts` section). The XLSX was inspected with the stdlib `zipfile` only.

## 1. Files and functions inspected
- `scripts/seed_sms_registry.py`: `seed`, `load_sms_headers`, `_libpq_dsn`, the `TSP_CODES` and `LSA_CODES` constants
- `app/cli/bootstrap_admin.py`: `bootstrap_first_admin`
- `app/cli/admin_accounts.py`: `run`, `_password`
- `app/main.py`: `on_startup` and `app/startup_checks.py`
- `app/services/sms_header_validator.py`: `validate_sender` (lines 140-190)
- `app/models/sms_sender_registry.py`
- `alembic/versions/*`, searched for `bulk_insert` and `op.execute`
- `requirements-seed.txt`
- `.env.example`, for AI and environment flags only
- `tests/conftest.py`, `tests/integration/conftest.py`, by name and purpose only

## 2. Seed-data inventory and classification
| # | Operation | Target tables | Class | Notes |
|---|---|---|---|---|
| S1 | `seed_sms_registry.py`: 11 TSP codes and 22 LSA codes | `tsp_codes`, `lsa_codes` | **Required** for sender validation | The values are public TRAI reference data, hardcoded in the script. |
| S2 | `seed_sms_registry.py`: about 23,192 SMS headers from `../List_SMS_Headers_16062020_0.xlsx` (658 KB, public TRAI list) | `sms_sender_registry` | **Required** for sender and message scanning to give meaningful results | See finding F2. |
| S3 | `bootstrap_admin` (first Cyber Warriors admin) | `warrior_profiles`, `warrior_audit_logs` | Optional, a **dev-useful admin workflow** | Needs an existing user with a verified e-mail. Dry-run by default. Refuses if any admin exists. |
| S4 | `admin_accounts create` (admin-console superadmin) | `admin_accounts`, `admin_audit_logs` | Optional, a dev-useful admin workflow | The password comes from a hidden prompt or `ADMIN_CLI_PASSWORD`. It is stored hashed and must be changed at first sign-in. |
| S5 | Test users, scans and reports | many | Development/demo only | No script exists. Integration tests create their own data in a separate `TEST_DATABASE_URL` database. |
| S6 | Alembic data statements (`DELETE FROM otps` in `q2r3…`, enum values) | `otps` | Not seeds | These are historical migration side effects. |

**Not in the database:**
- Safety tips and cybercrime contacts are hardcoded in code, with no table: `app/routers/message_analyzer.py:484-488` (1930, `cybercrime.gov.in`, Childline 1098) and `app/routers/community_scam.py:271,424`. They need no seed.
- Startup hooks do not seed. `on_startup` only runs `run_startup_checks`, logs, and starts workers, which are gated.

Current state: every application table holds **0 rows**. Only `alembic_version` has one row.

## 3. Essentials by area
| Area | Needs seed? |
|---|---|
| Application startup | No. Startup works on empty tables. |
| Authentication and onboarding | No reference data. Users are created through registration and OTP. |
| Safety tips and cybercrime contacts | No. They are hardcoded. |
| URL scanning | No. External provider calls are off. |
| Message scanning | **S1 and S2.** With an empty registry every sender returns `UNREGISTERED` with a fraud warning (`sms_header_validator.py:177-190`). That is a false-positive-heavy dev experience. |
| Scam reporting | No seed. A user row is needed to test. |
| Admin workflows | S4 for the admin console. S3 for the warrior admin, and it needs a user with a verified e-mail first. |

## 4. Dependency and foreign-key map
- `tsp_codes` (PK `code`) and `lsa_codes` (PK `code`): **no foreign keys in or out**. `sms_sender_registry`: PK `id`, no foreign keys, indexes `ix_sms_sender_registry_header` and `ix_sms_sender_header_upper`. The three are independent, so there is no insert-order constraint.
- `warrior_profiles` and `warrior_audit_logs` reference `users`. The audit rows cascade only from profile-related FKs, and the audit FKs have no cascade (by design, append-only).
- `admin_accounts`, `admin_sessions` and `admin_audit_logs` are independent of `users`.
- Users cascade to `behavior_events`, `community_scam_reports` and `emergency_contacts` (Stage 1.5B).

## 5. Safety findings
| ID | Severity | Finding |
|---|---|---|
| F1 | Medium | **`--replace` is destructive.** It runs `TRUNCATE … RESTART IDENTITY CASCADE` on `tsp_codes`, `lsa_codes` and `sms_sender_registry`. Without `--replace` the script aborts if any table has data, which is a good default. The stage should not use `--replace`. |
| F2 | Medium | **Header length risk.** `sms_sender_registry.header` is `String(30)` and the XLSX has strings up to 161 characters. These may be entity names, but header lengths were not verified because `openpyxl` is not installed. An over-length header would fail the whole insert. The transaction rolls back (`conn.commit()` is last), so it is safe but not useful. |
| F3 | Medium | **Missing dependencies.** `psycopg2` and `openpyxl` are not installed in `.venv` (`requirements-seed.txt`). Installing them is a change to the environment and needs approval. |
| F4 | Low | **No uniqueness on `header`.** There is no unique constraint, so a second run on a populated table is prevented only by the abort check. |
| F5 | Low | **Hardcoded credentials: none found.** The passwords in S4 are interactive or come from the environment. No real personal data, OTPs or production records are in the seed inputs. The XLSX is a public TRAI list of company names and sender headers. |
| F6 | Low | **Environment restriction is built in.** Every seed or CLI path calls `validate_identity(settings)`, and `admin_accounts` also calls `verify_connected_database`. `seed_sms_registry.py` calls only the former and uses `MIGRATOR_DATABASE_URL`, so it never checks `current_database()`. This can be restricted to `secureshield_dev` by running it with `SECURESHIELD_ENV_FILE=.env.local` and `python -m app.cli.show_database_target --expect development` first. A `current_database()` check before the TRUNCATE is advisable (a code change for a later stage). |
| F7 | Info | **No external calls.** None of the seed scripts call providers. `AI_PROCESSING_ENABLED=false` is the `.env.example` default. S3 and S4 send no e-mail. |

## 6. Idempotency and rollback
- **S1 and S2:** guarded by the "tables already hold data" abort (exit 2). It is idempotent by refusal, not by upsert. The script's inserts and TRUNCATEs are in one transaction, so a failure rolls back with no partial state. The only intended reversal is `TRUNCATE` of the three tables. This is safe on dev, since no table references them. A pre-seed `pg_dump` of the local database is a simple extra safety net.
- **S3:** idempotent by design (refuses if any admin exists). Reversal: delete the profile and audit row by hand. The audit row is append-only by policy, so prefer re-creating the dev database over editing it.
- **S4:** `create` fails if the e-mail already exists. Reversal: `admin_accounts disable --email …`, or delete the row.

## 7. Minimal proposed development dataset
1. All 11 TSP and 22 LSA codes plus the full TRAI header list (S1 and S2). The full list is the smallest useful set. A hand-picked subset would make `REGISTERED` verdicts unrepresentative, and it is small (about 23k rows, a few MB).
2. One dev admin account via S4 (a synthetic e-mail such as `dev-admin@example.test`, a temporary password supplied at the prompt, not stored in a file).
3. Optional, later: one synthetic user with a verified e-mail created through the normal registration flow, to exercise S3. No real personal data.

## 8. Recommended execution sequence (for Stage 1.6B, not run here)
1. `SECURESHIELD_ENV_FILE=.env.local python -m app.cli.show_database_target --expect development`, and `alembic current` (expect `y0z1a2b3c4d5`).
2. Take a local backup first (`scripts/db_backup.py`, local target only), and check D: free space (1.7 GB now).
3. Get approval to install `psycopg2-binary` and `openpyxl` from `requirements-seed.txt` into `.venv`.
4. `python scripts/seed_sms_registry.py --dry-run` to parse only, and review the row count and header lengths against 30.
5. `python scripts/seed_sms_registry.py` (without `--replace`), then verify counts of 11, 22 and about 23,192.
6. `python -m app.cli.admin_accounts create --email dev-admin@example.test --role superadmin`.
7. Verify with read-only catalog queries and the sender validator unit tests.

## 9. Tests and verification commands
- Read-only counts: `SELECT count(*) FROM tsp_codes / lsa_codes / sms_sender_registry`.
- `SELECT count(*) FROM sms_sender_registry WHERE upper(header)='…'` using a known header, to confirm `ix_sms_sender_header_upper` is used (`EXPLAIN`).
- `alembic check` stays clean (seed data does not change schema).
- Full unit suite (1390 passed) and `tests/unit` SMS validator tests.
- Integration tests need a separate `TEST_DATABASE_URL`. They are not part of seeding.

## 10. Risks and unresolved questions
- F2 (header length) and F3 (missing packages) are unresolved until the dry run.
- Whether the `.xlsx` is the intended source version (it is dated 16 June 2020) and whether it may be redistributed. It is a public TRAI list, but check before committing it. It is currently outside the Git repository (`D:\ravishori\SecureShieldApp\`), so seeding depends on the local file.
- Should the seed script add a `current_database()` check and a dev-only guard? Recommended for Stage 1.6B, but it needs a code change and approval.
- Is a dev admin account wanted now, or only when the admin console is tested?
- The four revisions `v7w8…`, `w8x9…`, `x9y0…`, `y0z1…` are still untracked.

## Conclusion
**READY WITH CONDITIONS.** Conditions:
1. Approval to install `psycopg2-binary` and `openpyxl`.
2. A dry run that confirms header lengths fit `String(30)` before any write.
3. Do not use `--replace`, and take a local backup first.
4. Run only against `secureshield_dev`, after the identity check.
