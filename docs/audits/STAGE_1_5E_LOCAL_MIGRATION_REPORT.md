# Stage 1.5E — Local Migration Report

**Final status: PARTIAL.**
- The migration applied correctly and verification passed.
- `alembic check` is **not clean**. One difference remains: the model text that Stage 1.5D set for the expression index does not match what Alembic reflects.

## Preflight (executed)
- `SECURESHIELD_ENV_FILE=.env.local`. `show_database_target --expect development` returned OK:
  - database `secureshield_dev` on `localhost:5432`
  - runtime role `secureshield_dev_app`, migrator role `secureshield_dev_owner`
- D: free space was 1.7 GB, above the 1 GB limit.
- `alembic current` returned `x9y0z1a2b3c4`. `alembic heads` returned `y0z1a2b3c4d5 (head)`, the only head.
- The migration source was inspected earlier (1.5C and 1.5D) and was byte-identical (md5 `1cf3015c…`).
- Pre-migration evidence, captured by a read-only snapshot script run in a `READ ONLY` transaction:
  - 38 tables (37 application tables plus `alembic_version`), 412 columns, 113 indexes, 348 constraints.
  - Database size 10,134 kB.
  - `warrior_audit_logs` had no table comment.
  - `uq_warrior_app_user_pending` was unique on `(user_id)` with predicate `status = 'pending'`.
  - `sms_sender_registry` had only `ix_sms_sender_registry_header`.

## Migration (executed)
- Command: `alembic upgrade head`, run as `secureshield_dev_owner`.
- Output (stdout and stderr):
  - `Context impl PostgresqlImpl.`
  - `Will assume transactional DDL.`
  - `Running upgrade x9y0z1a2b3c4 -> y0z1a2b3c4d5, sms_sender_registry: expression index on upper(header); warrior_audit_logs: table comment`
- **Exit code 0.**
- Revision before: `x9y0z1a2b3c4`. After: `y0z1a2b3c4d5`.

## Post-migration verification (executed, catalog queries)
- **Actual index:** `CREATE INDEX ix_sms_sender_header_upper ON public.sms_sender_registry USING btree (upper((header)::text))`, non-unique.
- **Comment:** `warrior_audit_logs` now has "Append-only. Do not UPDATE or DELETE rows here."
- **Partial unique index preserved:** `uq_warrior_app_user_pending`, unique, `(user_id)`, predicate `status = 'pending'`, unchanged.
- **Before-and-after snapshot diff covered:** tables, columns, indexes, constraints, comments, owners, row counts, runtime-role grants.
  - Differences: the revision row, +1 index (the new one), +1 table comment, and database size 10,134 kB → 10,150 kB.
  - Nothing else changed.
  - Table owners and `secureshield_dev_app` grants are identical to before, so migration ownership and runtime permissions are unchanged. I did not run per-privilege functional probes as the app role.
- D: free space after: 1.7 GB.

## `alembic check` (executed): FAILED, one difference
```
Detected changed index 'ix_sms_sender_header_upper' on 'sms_sender_registry':
  expression #1 'upper(header::text)' to 'upper((header)::text)'
New upgrade operations detected: remove_index + add_index (ix_sms_sender_header_upper)
```
- This is the **only** difference. There is no other table, column, index or comment drift.
- Cause: SQLAlchemy's reflection re-renders the stored `upper((header)::text)` as **`upper(header::text)`**. It does not hand Alembic the raw `pg_get_indexdef` text, as Stages 1.5C and 1.5D assumed.
- Offline confirmation with Alembic's own comparison, in memory with no DB:

| Model text | vs reflected `upper(header::text)` |
|---|---|
| `upper(header)` (the original 1.5B text) | **equal** |
| `upper(header::text)` | equal |
| `upper((header)::text)` (the Stage 1.5D text) | **different** |

- The Stage 1.5D change was therefore the wrong correction, and the 1.5B/1.5C analysis had inferred the reflected form incorrectly. This was caught only by the real catalog check.
- Per the restrictions I did **not** edit the model or tests, generate a migration, or suppress the difference.
- Ruled out as drift: the index is correct and functional in PostgreSQL, and no data is at risk. Only the autogenerate comparison is affected.

## Recommended correction (not applied, needs approval)
- In `app/models/sms_sender_registry.py`, change the model text to `upper(header)` or `upper(header::text)`, both equal against the real reflected form.
- Update the assertions in `tests/unit/test_model_schema_contract.py`: the exact-text assertion, the "equal to reflected" test, and the "differs from old text" test.
- Then re-run `alembic check`, a read-only comparison. No further migration is needed.

## Executed versus not executed
- **Executed:**
  - Identity check, `current` and `heads`.
  - Read-only pre and post snapshots.
  - `alembic upgrade head`.
  - `alembic check`.
  - The in-memory expression comparison.
- **Not executed:**
  - Downgrade, seeding, FastAPI startup, provider calls.
  - Any Neon, production or test database access.
  - Functional privilege probes as the runtime role.
  - Any source or migration edits.
  - Git staging or commits.
