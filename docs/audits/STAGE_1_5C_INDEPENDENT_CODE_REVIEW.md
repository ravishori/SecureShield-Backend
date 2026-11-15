# Stage 1.5C — Independent Code Review of ORM Reconciliation (1.5B)

**Verdict: APPROVED WITH CONDITIONS**

Read-only review. No code or migration edits, no DB connection, no Alembic command, no staging or commit. The only artefact written besides this report is a scratch script outside the repo (`exprcheck.py`, scratchpad). It calls Alembic's PostgreSQL comparison logic in memory.

## 1. Preservation and diff inventory
- The working tree holds a large amount of **pre-existing uncommitted work**: 81 tracked files modified, about +3615/−801 lines, plus many untracked files. This includes the Stage 1.1 safeguards, `app/db_identity.py`, `app/db_url.py`, services, routers and tests.
- **Three earlier untracked migrations:** `v7w8x9y0z1a2_identity_binding.py`, `w8x9y0z1a2b3_consent_records.py`, `x9y0z1a2b3c4_app_monitor_sync_and_guardian_outbox.py`.
- **New migration:** `y0z1a2b3c4d5` (untracked), `down_revision = "x9y0z1a2b3c4"`.
  - It is the single head, per the static test and my own check.
  - It chains onto three untracked revisions, so all four must be committed together.
- **Stage 1.5B changes:**
  - New files:
    - `app/migration_guard.py`
    - `alembic/versions/y0z1a2b3c4d5_…py`
    - `tests/unit/test_migration_guard.py`
    - `tests/unit/test_model_schema_contract.py`
    - the 1.5B report
  - Modified:
    - `alembic/env.py` (import at line 20, `include_object=` at lines 72 and 84)
    - the 8 model files
- **Mixed hunks:** two files contain pre-existing uncommitted hunks alongside 1.5B edits.
  - `alembic/env.py`: the `validate_identity` and `check_connected_database_name` lines are Stage 1.1.
  - `app/models/elderly_config.py` and `app/models/app_install_event.py`: the guardian columns, `client_event_id`, `occurred_at`, and the `uq_app_events_*` partial indexes are earlier work. The 1.5B edits are only the `Index`/`index=True` and `ondelete` changes.

## 2. Guard review (mandatory item)
Alembic 1.13.3 source (`autogenerate/compare.py`), as installed:
- `obj_removed` (about line 654) calls `run_object_filters(obj, name, "index", True, None)`. It is reached only for names present in the database and absent from the metadata. Table removal is filtered at line 220 with `(t, tname, "table", True, None)`.
- A name present on **both** sides goes through `compare_to_reflected`. If different, `obj_changed` calls the filter with `(new.const, name, "index", False, old.const)`. If equal, the filter is not called at all.
- Reflected indexes are **not** pre-filtered before the name matching (lines 500–560). A reflected index with a model counterpart is therefore never hidden by the guard, and no duplicate CREATE INDEX can result.

Guard (`app/migration_guard.py:24-36`) returns False only when `reflected and compare_to is None`, and only for `otp_vault_entries` (table, and indexes on it) or `uq_warrior_app_user_pending`. No finding.

Tests (`tests/unit/test_migration_guard.py`, 21 tests, all pass):
- The hook is exercised directly, including `compare_to` set and `reflected=False`.
- Alembic's real `compare_metadata` runs on in-memory SQLite:
  - Without the guard, both protected objects are proposed for removal. With it, they are not.
  - The unrelated `legacy_unprotected` table and `ix_unrelated_extra` index are still reported.
  - A matching model-declared `uq_warrior_app_user_pending` produces no operation (no duplicate create).
  - A model-declared version with a different uniqueness is still detected.
- Limitation (informational): SQLite fixtures, not PostgreSQL reflection. The decision logic is dialect-independent, so I accept this.

## 3. Model review
Compared with the 1.5A plan and the Stage 1.4 inventory (diffs inspected line by line):

| Item | Result |
|---|---|
| `uq_warrior_app_user_pending` (`cyber_warrior.py:121-130`) | Correct: name, `user_id`, unique, predicate `status = 'pending'`. |
| `warrior_audit_logs` (`cyber_warrior.py:288-290`) | Two composite `…, created_at DESC` indexes and the table comment. The per-column indexes are removed. FKs carry no cascade, as intended. |
| `warrior_profiles.user_id` | Unique constraint only, no extra index. Correct. |
| CASCADE on `behavior_events`, `community_scam_reports`, `emergency_contacts` | Correct. DDL metadata only; no ORM relationship was added or changed. |
| DESC and names on `behavior_events`, `clone_reports`, `community_scam_reports`, `app_install_events` | Correct. |
| `app_install_events` `risk_level` and `flagged_as_clone` indexes | Correct (default `ix_<table>_<col>` names). |
| `elderly_configs.ix_elderly_configs_user_id` plus the unique constraint | Correct. |
| `ix_sms_sender_header_upper` (`sms_sender_registry.py:41`) | **See finding M1.** |

No accidental relationship, API or cascade-deletion semantic change. Only metadata and DDL hints changed.

## 4. Migration review (`y0z1a2b3c4d5`, not executed)
- `revision` and `down_revision` are exact.
- The upgrade has two operations: `create_index ix_sms_sender_header_upper (upper(header))` and `create_table_comment`.
- The downgrade has exactly their reversal. `existing_comment` is supplied.
- No table or column operations, data mutation or unrelated index operations.
- It is a plain, non-concurrent `CREATE INDEX`. The table is a small registry, so locking is trivial.
- Valid PostgreSQL 18 syntax and reversible.
- Note: with the model text from M1 corrected, the DDL the migration emits remains correct, because PostgreSQL stores `upper(header)` on a varchar column as `upper((header)::text)` either way.

## 5. Expected Alembic behaviour and the expression-index investigation
**Finding M1 (reproduced).** I fed Alembic's real `PostgresqlImpl.compare_indexes` (in memory, no DB) both forms.

| Model text | Reflected text | Result |
|---|---|---|
| `upper(header)` (current) | `upper((header)::text)` | **Different**: `expression #1 'upper((header)::text)' to 'upper(header)'` |
| `upper((header)::text)` | `upper((header)::text)` | Equal |

The cause is Alembic's `_cleanup_index_expr`. It strips `::text`, which leaves `upper((header))`, and it does not collapse the inner parentheses, so that never equals `upper(header)`. `header` is `String(30)`, i.e. varchar, so PostgreSQL's `pg_get_indexdef` yields the cast form.

Expected sequence:
1. **Before applying:** two operations, `add_index ix_sms_sender_header_upper` and `add_table_comment`. The protected objects stay hidden or declared.
2. **After applying, with the current model text:** one spurious drop-and-create pair for `ix_sms_sender_header_upper`.
3. **After applying, with the corrected model text:** clean. DESC indexes compare equal, which I confirmed: `text('created_at DESC')` matches the reflected `desc(col)` for single and composite forms.

The reflected cast form is inferred from standard PostgreSQL behaviour, not from a live database, so it should be confirmed once the dev DB is migrated.

## 6. Security and preservation
- No secret-like literals in the new or changed Stage 1.5B files.
- `.env.local` and `config/production_endpoints.txt` have modification times earlier than the first 1.5B file (21:49), so they are not from this stage.
- `.env.example` shows as modified, which is Stage 1.1 work. No 1.5B change touches env files or the endpoint registry.
- The unit suite ran under the connection-blocking plugin: 0 attempts. No external calls.
- I did not run `git diff` against anything that would modify state. All Git commands were read-only.

## Findings by severity
| ID | Severity | Location | Finding |
|---|---|---|---|
| M1 | **Medium** | `app/models/sms_sender_registry.py:41`; `tests/unit/test_model_schema_contract.py:48` | Model text `upper(header)` will not compare equal to the reflected `upper((header)::text)`. After the migration, `alembic check` will propose dropping and recreating the index. No data risk, since this affects autogenerate only. |
| L1 | Low | `tests/unit/test_model_schema_contract.py:48` | The test locks the M1 text in, so it must change together with the model. |
| L2 | Low | `alembic/versions/` | The new revision depends on three untracked revisions. Commit all four together. |
| L3 | Informational | Guard tests | SQLite fixtures, not PostgreSQL reflection. Logic is dialect-independent. |

## Required corrections (not made, per instructions)
1. In `sms_sender_registry.py:41`, change the text to `upper((header)::text)`. Update the comment, and the assertion at `test_model_schema_contract.py:48`. No migration change is needed.
2. Optionally, add a unit test that compares the model index to the reflected form through `PostgresqlImpl.compare_indexes`, as in the scratch script.

## Migration readiness
- The migration itself is safe to apply to local `secureshield_dev`. It is additive, reversible, and the guard is correct.
- Condition: apply correction 1 first, so that the post-migration `alembic check` can be clean.
- Then, under a separate approval: apply to `secureshield_dev` only, run `alembic check`, and confirm the reflected index text.
- Conditions L2 apply before any deployment.

**Final verdict: APPROVED WITH CONDITIONS**
