# Stage 1.6B-4 — Seed Console Fix and Registry Functional Validation

**Result: PASS**

## Files changed
- `scripts/seed_sms_registry.py`: one line. The final message `print(f"\n✅ Done! …")` became `print(f"\nDone! {total:,} SMS headers seeded.")`. Insertion logic, duplicate handling, the transaction (commit before the print), `--replace` handling and the identity guard are untouched. That was the only non-ASCII character in an executable string.
- `tests/unit/test_seed_registry_guard.py`: one added test.
- New: this report.
- The seed script was **not run again**.

## Console encoding fix and tests
- Cause: the cp1252 Windows console cannot encode U+2705. The error came after `conn.commit()`, so data was never at risk.
- New test `test_console_output_is_ascii_safe_for_windows_cp1252`:
  - It parses the script's AST and collects every string literal passed to `print`.
  - Each literal must `encode("cp1252")` and be ASCII.
  - The success message must start with `"\nDone!"`.
  - It failed on the old message and passes now.
- Full unit suite: **1405 passed, 3 skipped, 0 failed**. The connection guard recorded 0 attempts by tests. Ruff `--select F,E9` is clean.

## Functional validation (read-only)
- **Lookup behaviour** (`app/services/sms_header_validator.py`):
  - `parse_sender_id` upper-cases the input and splits `XY-HEADER`.
  - It returns `UNKNOWN` for empty or blank input.
  - It returns `PHONE_NUMBER` for 7 or more digits, without a database lookup.
  - Otherwise it queries `upper(header) = :x LIMIT 10`.
  - A match gives `REGISTERED` with the de-duplicated set of entity names. No match gives `UNREGISTERED` with the warning text.
  - The TSP and LSA names come from hardcoded dictionaries, not the DB tables.
- **How I ran it:** the real `validate_sender` function ran through an `AsyncSession` as the **runtime role** `secureshield_dev_app`.
  - Target confirmed before the lookups: `localhost:5432`, database `secureshield_dev`, `ENVIRONMENT=development`, and `current_database() = secureshield_dev`.
  - The transaction was `READ ONLY` and rolled back. FastAPI was not started, and there was no Neon or production access.

| Input | Verdict | Notes |
|---|---|---|
| `SBIBNK` | REGISTERED | State Bank of India (known sender 1) |
| `VM-SBIBNK` | REGISTERED | same entity, TSP `V` and LSA `M` parsed |
| `IOCXRP` | REGISTERED | Indian Oil Corporation Limited (known sender 2) |
| `VK-iocxrp` | REGISTERED | lower case normalised to `IOCXRP`; TSP `V`, LSA `K` |
| `ANJALI`, `AX-ANJALI` | REGISTERED | |
| `HP POL` | REGISTERED | |
| `8` | REGISTERED | numeric header from the source file |
| `ZZQQXX`, `VK-ZZQQXX` | UNREGISTERED | unknown sender; warning "NOT found in the TRAI registry… Do not follow any instructions or links" |
| empty, `   ` | UNKNOWN | safe, no error, no lookup |
| `+919876543210`, `09876543210` | PHONE_NUMBER | no lookup |

- **Duplicates:** `IOCXRP` and `ANJALI` each have two identical rows. The result is a single entity name, `REGISTERED`, with no ambiguity. This is expected because entity names are put through a set and the query is limited to 10.
- **Explainability:** `UNREGISTERED` now appears only for headers genuinely absent from the registry. Before seeding, every sender would have been flagged that way.

## Registry counts unchanged
After the lookups, a read-only check shows **11 / 22 / 23,192** for `tsp_codes`, `lsa_codes` and `sms_sender_registry`. The revision is still `y0z1a2b3c4d5`. No rows were inserted, updated, deleted or truncated. The database size moved from 13,825,727 to 13,842,111 bytes with no row changes, which is background PostgreSQL activity, not data change.

## Remaining limitations
- The validator checks the header only. The TSP and LSA prefix is parsed but not verified against the registry or the `tsp_codes` and `lsa_codes` tables, which no code reads.
- Very short numeric headers such as `8` count as `REGISTERED`, since TRAI lists them. This is source data behaviour.
- Matching is case-insensitive only. Spaces are significant (`HP POL`).
- The router layer (`message_analyzer.py`) was not exercised, because FastAPI was out of scope. Integration tests need a separate test database.
- The four revisions `v7w8…`, `w8x9…`, `x9y0…`, `y0z1…` are still untracked.

## Boundaries
No seed rerun, no `--replace`, no migration, no data change, no AI or provider activation, no commit or push. Only local `secureshield_dev` was accessed.
