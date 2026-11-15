# Stage 1.5B — ORM Reconciliation Implementation Report

**Status: IMPLEMENTED — READY FOR REVIEW**

Scope: steps 1–4 of `STAGE_1_5A_ORM_RECONCILIATION_IMPLEMENTATION_PLAN.md`. Static work only.

## Safety confirmation
- PostgreSQL connections: **0**. The unit suite ran under a connection-blocking pytest plugin that recorded 0 attempts by tests. The 12 it reported were its own deliberate self-tests.
- Migration `y0z1a2b3c4d5` was **not executed**. `alembic check`, `upgrade` and `downgrade` were not run.
- No seeding, FastAPI startup, provider calls, Neon or production access.
- No `.env`, `.env.local` or endpoint-registry changes.
- No git staging, commit, reset, stash or push. Existing uncommitted work is preserved.

## Files created
| File | Purpose |
|---|---|
| `app/migration_guard.py` | `include_object` guard. Kept separate from `env.py` so it is unit-testable without a DB. |
| `alembic/versions/y0z1a2b3c4d5_sms_header_upper_index_and_audit_comment.py` | The one additive migration. |
| `tests/unit/test_migration_guard.py` | 21 tests. |
| `tests/unit/test_model_schema_contract.py` | Model metadata and static migration tests. |

## Files modified
- `alembic/env.py`: imports the guard and passes `include_object` to both `context.configure` calls (offline and online).
- `app/models/`:
  - `cyber_warrior.py`
  - `sms_sender_registry.py`
  - `behavior_event.py`
  - `community_scam.py`
  - `emergency_contact.py`
  - `clone_report.py`
  - `app_install_event.py`
  - `elderly_config.py`

## Protected-object behaviour
The guard returns False only for a database-only object (`reflected=True`, `compare_to=None`) that is one of:
- table `otp_vault_entries`, and any index on it;
- index `uq_warrior_app_user_pending`.

Everything else keeps normal comparison. Tests show:
- Without the guard, Alembic proposes removing both objects. With it, it does not.
- Unrelated DB-only tables and indexes are still reported.
- Lookalike names are not protected.
- A declared partial index is still compared, so a real change is not masked.
- `env.py` is wired into both configure calls, and `compare_type` and `compare_server_default` stay off.

## Model changes
- `warrior_applications`: declares partial unique index `uq_warrior_app_user_pending (user_id) WHERE status = 'pending'`.
- `sms_sender_registry`: `ix_sms_sender_header_upper` is now an `upper(header)` expression. This matches the validator query, whose compiled form was checked in a test. The registry is not seeded.
- `warrior_audit_logs`:
  - Two composite indexes with `created_at DESC`, and the table comment.
  - The stray per-column indexes are removed.
  - The FKs have no cascade, and a test asserts this.
- ON DELETE CASCADE on the user FK of `behavior_events`, `community_scam_reports` and `emergency_contacts`.
- DESC and name alignment:
  - `behavior_events`
  - `clone_reports`
  - `community_scam_reports` (four explicit names)
  - `app_install_events`
- `app_install_events`: declares `risk_level` and `flagged_as_clone` indexes.
- `elderly_configs`: declares the redundant `ix_elderly_configs_user_id` index alongside the unique constraint.
- `warrior_profiles`: uniqueness is now the unique constraint only, with no extra index.
- Not done, by design:
  - The 58 raw-SQL server defaults are not declared.
  - `otp_vault_entries` and all existing DB indexes are not removed.

## Migration `y0z1a2b3c4d5` (down_revision `x9y0z1a2b3c4`)
- Upgrade: `create_index ix_sms_sender_header_upper ON sms_sender_registry (upper(header))` and `create_table_comment` on `warrior_audit_logs`.
- Downgrade: `drop_table_comment` and `drop_index`, those two only.
- No table or column drops, no UPDATE/DELETE/TRUNCATE.
- A test confirms it is the single head and that it never references the protected objects.

## Test results
- Full unit suite: **1388 passed, 3 skipped, 0 failed** (23 s). The 3 skips are pre-existing.
- New tests: all pass.
- Ruff `--select F,E9` on all changed and new Python files: clean.
- Ruff on the whole `app alembic` tree reports 3 F401 findings in old migrations. These are pre-existing and untouched.
- Integration tests were not run, because they need a DB.

## Expected future `alembic check` (separately approved step)
- **Before** applying `y0z1a2b3c4d5` to `secureshield_dev`, exactly two differences are expected:
  - `add_index ix_sms_sender_header_upper`
  - `add_table_comment warrior_audit_logs`
- **After** applying it, the result should be clean.
- Known uncertainty: PostgreSQL reflects the expression index as `upper((header)::text)`, while the model says `upper(header)`.
  - Alembic may or may not treat these as equal. This can only be settled by running `alembic check` against a migrated DB.
  - Fallback if it reports a diff: change the model text to `upper((header)::text)`. This needs no DB change.

## Remaining risks
- `v7w8x9y0z1a2`, `w8x9y0z1a2b3`, `x9y0z1a2b3c4` and the new revision are all untracked. The new revision is not deployable until they are committed together.
- The expression-index reflection uncertainty above.
- Model-side drift is verified against the Stage 1.4 inventory and a migration replay, not a live DB.

## Next approval checkpoint
1. Review of this report and the diff.
2. Separate approval to apply `y0z1a2b3c4d5` to `secureshield_dev` only, then run `alembic check`.
