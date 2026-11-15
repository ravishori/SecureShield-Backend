# Stage 1.6B-3 — Local SMS Registry Backup and Controlled Seed Report

**Result: PASS WITH CONDITIONS**
- The seed committed correctly and all verification passed.
- The condition is one cosmetic defect: the script's last console line crashes under Windows cp1252. This is detailed in section 6.

## 1. Phase A — Identity guard (change made)
`scripts/seed_sms_registry.py` already called `validate_identity(settings)` at import, but had **no `current_database()` check**. I added the smallest guard:
- `assert_seed_target(actual_database, cfg=None)` refuses with `SystemExit("Refusing to seed: …")`, with no credentials in the message, unless all of these hold:
  - `parse_endpoint` and `check_connected_database_name`: the connected name equals the configured name and is not a production name.
  - `ENVIRONMENT == "development"`.
  - The host is loopback and the port is 5432.
  - `current_database() == "secureshield_dev"`.
- In `seed()`, right after `psycopg2.connect` and **before the existing count query and every write**: `SELECT current_database()`, then the guard, closing the connection on refusal.
- Nothing existing was weakened. `--replace` and the "tables already hold data" abort are untouched.
- The new tests are in `tests/unit/test_seed_registry_guard.py`. They cover:
  - acceptance of the dev database;
  - refusal of other database names, non-development environments, non-local hosts or ports, and a mismatched configured name;
  - no credential leakage;
  - the check preceding every write in the source.
- Unit suite: **1404 passed, 3 skipped**, 0 database connection attempts by tests. Ruff `--select F,E9` is clean.

## 2. Phase B — Identity, pre-counts and backup
- Identity (read-only, `secureshield_dev_owner`):
  - environment `development`, host `localhost`, port 5432
  - `current_database() = secureshield_dev`
  - revision `y0z1a2b3c4d5`
  - DB size 10,393,279 bytes
- Pre-seed counts: `tsp_codes`, `lsa_codes` and `sms_sender_registry` were **0 / 0 / 0**.
- Backup, using the existing `scripts/db_backup.py` (custom-format `pg_dump`) and the migrator role:
  - Credentials were passed in-process through the environment, not on the command line or in any file.
  - Path: `backend/backups/stage_1_6b_3_pre_seed/secureshield-20261115T170032Z.dump`. The directory is new and Git-ignored (`.gitignore:58`).
  - Size: 101,789 bytes.
  - SHA256: `1a1be189d675bc7ade5563dd70c20a66b5a6673e97c29692febe02a8c9baf9e3`. It matches both the script's sidecar and an independent `certutil` hash.
  - `pg_restore --list` succeeds: dbname `secureshield_dev`, 250 TOC entries, 38 `TABLE DATA` entries, including `sms_sender_registry` and `tsp_codes`.
  - `--keep 0` disabled pruning, so no existing backup could be removed.

## 3. Phase C — Final preflight (just before seeding)
- Identity, revision and counts were reconfirmed as above (0 / 0 / 0).
- The XLSX md5 was unchanged.
- The dry run reported 23,192 headers, and the maximum header length is 9, so none exceeds 30 characters.

## 4. Phase D — Seed
- Command: `SECURESHIELD_ENV_FILE=.env.local .venv/Scripts/python.exe scripts/seed_sms_registry.py`. Normal mode, **no `--replace`**.
- Output: 11 TSP codes inserted, 22 LSA codes inserted, `Inserted 23,192/23,192`.
- The process then raised `UnicodeEncodeError` (exit 1) on the final `✅ Done!` print.
- `conn.commit()` runs **before** that print. The post-run query confirmed the data is committed. This is a console-encoding defect only, not a rollback.

## 5. Phase E — Verification (read-only)
| Check | Result |
|---|---|
| Row counts (before → after) | tsp 0 → **11**, lsa 0 → **22**, sms 0 → **23,192** |
| Empty or blank headers | 0 |
| Header length (max / min) | 9 / 1, nothing over 30 |
| Distinct `upper(header)` | 23,190 |
| Duplicates retained as expected | `ANJALI` ×2 and `IOCXRP` ×2, identical entities |
| IDs | 1 to 23,192, contiguous |
| Sample rows | `8`, `HP POL`, `IOCXRP`, `ANJALI` plus TSP `A` and `J`, LSA `D` and `M` all as expected |
| Unrelated tables | Snapshot diff against the pre-seed snapshot: schema (tables, columns, indexes, constraints, comments, owners, revision) unchanged. Row counts changed only for the three registry tables. DB size went from 10,150 kB to 13 MB. |
| `alembic check` | No new upgrade operations detected |
| Tests | 79 SMS, seed and schema-related unit tests passed. The full unit suite is 1404 passed, 3 skipped. |

## 6. Findings and remaining risks
- **Defect (cosmetic):** the final `print("\n✅ Done! …")` fails on a Windows cp1252 console. The remedy is either `PYTHONIOENCODING=utf-8` for future runs or replacing the glyph in the script (a separate small change). It is not fixed here, to keep this change minimal.
- Not executed: functional validator lookups through the API, because FastAPI and integration tests were out of scope. The index is in place, and the unit tests for the validator query pass.
- The two duplicate headers are retained intentionally (no unique constraint). The same consideration applies to any future re-seed: the script would refuse on populated tables, and `--replace` must not be used without a fresh backup.
- The backup lives on D:, the same disk as the database (1.7 GB free). Copy it elsewhere if it needs to survive a disk failure.
- The four revisions `v7w8…`, `w8x9…`, `x9y0…`, `y0z1…` are still untracked.

## 7. Files changed
- Modified: `scripts/seed_sms_registry.py` (the guard).
- New: `tests/unit/test_seed_registry_guard.py`.
- New (Git-ignored): `backups/stage_1_6b_3_pre_seed/` with the `.dump` and `.sha256`.
- New: this report.
- Scratchpad helpers are outside the repository.

## 8. Boundaries
- Only the local `secureshield_dev` was accessed (`localhost:5432`, owner role). Neon and production were untouched.
- No `--replace`, TRUNCATE, delete or reset by me (the seed's own TRUNCATE ran on the three empty tables, as designed).
- No migration, FastAPI startup, provider activation, `.env.local` change, commit or push. All uncommitted work is preserved.
