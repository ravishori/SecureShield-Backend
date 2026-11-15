# Stage 1.5D — Expression Index Correction Report

**Status: CORRECTED — READY FOR MIGRATION APPROVAL**

Resolves finding M1 from `STAGE_1_5C_INDEPENDENT_CODE_REVIEW.md`.

## Files changed
1. `app/models/sms_sender_registry.py`: the index expression and its comment.
2. `tests/unit/test_model_schema_contract.py`: the exact-expression assertion, plus two new tests.

Nothing else was touched. The migration is unchanged.

## Before and after
| | Before | After |
|---|---|---|
| Model (`sms_sender_registry.py`, `__table_args__`) | `Index("ix_sms_sender_header_upper", text("upper(header)"))` | `Index("ix_sms_sender_header_upper", text("upper((header)::text)"))` |
| Test assertion (`test_sms_header_index_is_an_upper_expression`) | `idx_text(i) == ["upper(header)"]` | `idx_text(i) == ["upper((header)::text)"]` |

The index name, non-uniqueness, and the existing plain index `ix_sms_sender_registry_header` are unchanged.

## New tests
- `test_sms_index_compares_equal_to_reflected_postgres_form_and_differs_from_old_text`:
  - It uses Alembic's real `PostgresqlImpl.compare_indexes`, in memory.
  - The model compares **equal** to a reflected `upper((header)::text)`.
  - It **differs** from a reflected `upper(header)`, which documents why the model text matters.
- `test_migration_still_issues_plain_upper_header`: the migration source still contains `[sa.text("upper(header)")]` and no `::text`.

## Test results (no database)
- Full unit suite: **1390 passed, 3 skipped, 0 failed**. The 3 skips are pre-existing.
  - It includes the updated contract tests, the migration-guard tests and the SMS header validator tests.
- Connection-blocking plugin: 0 attempts by tests. The 12 it reported were its own self-tests.
- Ruff `--select F,E9` on the changed files: clean.

## Static verification
- **Migration unchanged:** `y0z1a2b3c4d5` md5 is `1cf3015c75890caea7ceb7ca12820958` before and after.
  - It still emits `CREATE INDEX ix_sms_sender_header_upper ON sms_sender_registry (upper(header))`.
  - PostgreSQL stores that on a varchar column as `upper((header)::text)`, which is what the model now declares.
- **Validator behaviour:** the validator query (`app/services/sms_header_validator.py:152`, `func.upper(SmsSenderRegistry.header)`) is untouched. The existing compiled-query test still passes, so the planner can use the index. The index text in the model affects metadata comparison only, not queries.
- **Other models:** this stage changed only `sms_sender_registry.py`. The other model-diff hunks are Stage 1.5B and pre-existing work, with no new changes.
- **Guard:** untouched, and its 21 tests pass. Protected objects stay hidden only when database-only.

## Remaining uncertainty
- The reflected text `upper((header)::text)` is inferred from standard PostgreSQL behaviour and Alembic's comparison code. It is **not proven** until the migration is applied to the local dev database and `alembic check` is run.
- Expected result after applying: clean.
- If `alembic check` still reports this index, the fallback is to adjust the model text again. No database change is needed.

## Confirmation
- Zero PostgreSQL connections. No Alembic commands, migration execution, seeding, FastAPI startup, Neon or production access.
- No Git staging, commit or push. All uncommitted work is preserved.
