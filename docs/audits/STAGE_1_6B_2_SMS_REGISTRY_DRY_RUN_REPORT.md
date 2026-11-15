# Stage 1.6B-2 — SMS Registry XLSX Dry-run Report

**Result: PASS — READY FOR LOCAL BACKUP AND SEED**

## 1. Script inspection (before running)
- `scripts/seed_sms_registry.py` flow for `--dry-run`:
  - `argparse` sets `dry_run=True`.
  - At import time the script runs `validate_identity(settings)`, which makes no connection. It also builds a DSN string, which is not a connection.
  - `seed()` resolves the XLSX path and exits if the file is missing.
  - If `dry_run`: it calls `load_sms_headers`, prints the counts and **`return`s**.
- The `import psycopg2`, `psycopg2.connect`, `TRUNCATE` and `INSERT` statements all come **after** that return. The dry-run path has no database connection and no DML or DDL.
- Source files are only read: `openpyxl.load_workbook(path)`. The script never saves the workbook.
- Source inventory:

| File | Used by script | Size / checksum |
|---|---|---|
| `D:\ravishori\SecureShieldApp\List_SMS_Headers_16062020_0.xlsx` | Yes (headers) | 658,411 bytes, md5 `db80d565…dfd` unchanged before and after |
| `Detail_Header_Prefixes_16062020_0.pdf` | No (its TSP and LSA tables are embedded in the script) | Not opened |
| `Empanel_org.pdf` | No | Not opened |

## 2. Execution
- Command: `SECURESHIELD_ENV_FILE=.env.local .venv/Scripts/python.exe scripts/seed_sms_registry.py --dry-run`. The env file was selected only so settings validation can load. No credentials were printed.
- Exit code 0. Output:
  - `Loaded 23,192 SMS headers from XLSX`
  - `DRY RUN: would seed 11 TSP codes, 22 LSA codes, 23,192 SMS headers. No database contact.`
- The script was not modified.

## 3. Validation statistics
The script's dry-run prints only totals, so I added a **separate read-only analysis** of the XLSX with the script's own filtering rules. No file was written and no database was touched.

| # | Check | Result |
|---|---|---|
| 1 | TSP codes | **11** |
| 2 | LSA codes | **22** |
| 3 | SMS headers (data rows, header row excluded) | **23,192** |
| 4 | Duplicate headers (case-insensitive) | **2 extra rows**: `IOCXRP` and `ANJALI` each appear twice, each with an **identical entity**, so they are exact duplicate rows. 23,190 distinct headers. |
| 5 | Empty or null header / entity | **0 / 0** (nothing dropped by the script's filter) |
| 6 | Malformed entries | **0** unusual characters, 0 control characters. One header contains a space: `HP POL`. 7 rows contain non-ASCII text. 2,623 header cells are stored as integers (for example `8`, `91`, `111`). The script's `str()` renders them as digits. |
| 7 | Maximum header length | **9** characters (minimum 1). Maximum entity name length is 149, and the entity column is `Text`. |
| 8 | Headers over the 30-character column limit | **0** |
| 9 | Encoding or parsing errors | **None** |
| 10 | Valid, unique records eligible | **23,190** distinct (header, entity) pairs. The script would insert all **23,192** rows and does not de-duplicate. |

No header was truncated or modified.

## 4. Safety confirmation
- No database connection was attempted. No rows or schema changed. No migrations were run. No FastAPI startup.
- The XLSX is unchanged (md5 check OK after both steps).
- No external provider was contacted. No production or Neon credentials were accessed.
- I did not create a backup, install anything, or commit or push.

## 5. Findings and blockers
- **No blockers.**
- Minor note: the 2 duplicate rows (`IOCXRP`, `ANJALI`) would be inserted as duplicates, because `sms_sender_registry` has no unique constraint on `header`. This is harmless. The validator uses `LIMIT 10` and de-duplicates entity names with a set, so the verdict is unaffected. It is a data-quality point, not a reason to stop. The script was not changed to filter them, and expected counts after seeding should be 23,192.
- Minor note: integer header cells could have lost leading zeros in the source file. This cannot be recovered or checked from the XLSX alone.
- `HP POL` (with a space) is how TRAI lists it. The validator's lookup normalises case only.

## 6. Recommended next action
1. Approve Stage 1.6B-3: take a local backup (`scripts/db_backup.py`, `secureshield_dev` only) and confirm D: free space (1.7 GB at last check).
2. Run the real seed without `--replace`, as `secureshield_dev_owner`, after the `show_database_target --expect development` check.
3. Verify counts 11, 22 and 23,192, then `alembic check`.

**PASS — READY FOR LOCAL BACKUP AND SEED**
