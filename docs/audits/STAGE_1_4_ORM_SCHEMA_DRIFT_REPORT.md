# Stage 1.4: ORM models vs migrated PostgreSQL schema (drift audit)

Date: 2026-11-15. Target: database `secureshield_dev` (local PostgreSQL 18.6, `localhost:5432` over `::1`), Alembic revision `x9y0z1a2b3c4`.
**Final verdict: MATCH WITH DOCUMENTED DIFFERENCES.** No difference affects correctness or local startup. One model-side defect (a mis-declared index) and one process risk (the models omit a business-rule index that autogenerate would drop) are recorded below for later correction.

**Safety record.** All database access was read-only (the migration/owner role with `default_transaction_read_only=on`; one extra read-only session as the runtime role). I made no schema, data, code, model, migration or configuration change; generated no migration file; ran no seed script; did not start FastAPI; made no provider call; did not touch Neon or any production-class endpoint; no Git operation. Free space on D: stayed at 1.6 GB.

## 1. Checks actually executed
| # | Check | Result |
|---|---|---|
| 1 | Project instructions (`CLAUDE.md`), the 1.2E and 1.3 reports, `docs/LOCAL_DEVELOPMENT.md`, model sources, `alembic/env.py` read | done; `env.py` runs with `compare_type`/`compare_server_default` **off**, so the stock `alembic check` ignores types and defaults |
| 2 | Environment: `SECURESHIELD_ENV_FILE=.env.local`, no stray `PG*`/`*DATABASE_URL`/`ENVIRONMENT` variables in the shell | PASS |
| 3 | `python -m app.cli.show_database_target --expect development` | exit 0: `identity OK: environment=development class=loopback database=secureshield_dev`; runtime role `secureshield_dev_app`, migrator `secureshield_dev_owner` |
| 4 | Live identity: `current_database()` = `secureshield_dev`, user `secureshield_dev_owner`, not superuser, server 18.6, session read-only | PASS |
| 5 | `python -m alembic current` | `x9y0z1a2b3c4 (head)`; the `alembic_version` table holds exactly that one row | PASS |
| 6 | `python -m alembic check` (as instructed; it reports operations and applies nothing) | **exit non-zero** (`FAILED: New upgrade operations detected`): structural differences, listed in section 3 |
| 7 | Alembic API `compare_metadata` with `compare_type=True` and `compare_server_default=True` (read-only session) | 1 removed table, 14 removed + 13 added indexes, 3 removed + 3 added foreign keys, 2 removed constraints, 1 table comment, **58 server-default differences**, **0 type, length or nullability differences** |
| 8 | Independent catalog comparison (`pg_attribute`, `pg_constraint`, `pg_indexes`, `pg_enum`, `pg_sequences`, `pg_depend`) against `Base.metadata` | section 2 and 3 |
| 9 | Startup identity check run as the **runtime** role: `verify_connected_database(settings)` (the function `on_startup()` calls) and read-only `SELECT count(*)` on 6 tables | OK; connected as `secureshield_dev_app`, not superuser; all counts 0 except `alembic_version` = 1 |
**Not executed:** starting the application, the integration tests (including `tests/integration/test_schema_drift.py`), seed scripts, any write.

## 2. What matches (verified)
| Area | Result |
|---|---|
| Tables | all 36 model tables exist; the database has 37 application tables (+ `alembic_version`); the one extra is `otp_vault_entries` |
| Columns | every model column exists; no database column is missing from the models (except in `otp_vault_entries`) |
| Data types and lengths | **no difference** (VARCHAR lengths, UUID, JSONB, TIMESTAMP, BIGINT, enum types all equal) |
| Nullability | **no difference** |
| Primary keys | 38 (37 + `alembic_version`), all match |
| Foreign keys | all 32 exist on both sides with the same columns and targets; **ON DELETE differs in 3 places** (section 3) |
| Unique constraints | all model uniqueness is enforced in the database (see 3.6 for two equivalent-but-differently-built cases) |
| Check constraints | `ck_otps_single_identifier`, `ck_admin_accounts_role`: present, nothing missing |
| Enum types | 11 on each side, **identical names and identical label sets**; `alerttype` has 16 labels |
| Sequences | 3 (`error_logs_id_seq`, `otps_id_seq`, `sms_sender_registry_id_seq`), each owned by the right column of the right table, owner `secureshield_dev_owner`; they correspond exactly to the 3 integer primary keys in the models |
| Server defaults | no model-declared default is missing in the database |

## 3. Differences: classification, severity, action
Legend: **I** intentional (documented in a migration), **D** defect, **N** naming only.
| # | Difference | Class | Severity | Evidence and recommended action |
|---|---|---|---|---|
| 3.1 | **`otp_vault_entries`** exists in the database (10 columns, FK to `users`, index `ix_otp_vault_entries_user_id`) with no model. `alembic check` proposes `remove_table`. | I (legacy) | Info | Created by revision 1; the model file is gone (`alembic/env.py` imports it inside a `try`). **`app/services/account_erasure.py:222` still runs `DELETE FROM otp_vault_entries WHERE user_id = :u`**, so the table is required for account erasure. Keep it. Document as a model-less legacy table, or restore a minimal model; never apply the proposed drop. |
| 3.2 | **`warrior_audit_logs` indexes.** Database: `ix_warrior_audit_actor (actor_user_id, created_at DESC)` and `ix_warrior_audit_subject (subject_user_id, created_at DESC)`. Model: single-column `ix_..._action`, `..._actor_user_id`, `..._subject_user_id`. Model also declares the table comment "Append-only. Do not UPDATE or DELETE rows here."; the database has no comment. | I (migration) + N | Low | The database indexes are the more specific ones for "newest events per actor/subject"; there is no index on `action` in the database. Align the **model** to the migration (declare the two composite DESC indexes); add an `action` index only if a query needs it. The comment can be applied by a future comment-only migration. |
| 3.3 | **`warrior_applications` partial unique index** `uq_warrior_app_user_pending` (`UNIQUE (user_id) WHERE status = 'pending'`) exists in the database, not in the model. `alembic check` proposes `remove_index`. | I | **Medium (process risk)** | It enforces "at most one pending application per user" (revision 14's stated design). The behaviour is correct today. Risk: an autogenerated migration from the current models would **drop this business rule**. Add the partial unique `Index` to the model before anyone autogenerates; do not apply the proposed removal. |
| 3.4 | **`app_install_events`:** extra indexes `ix_..._flagged_as_clone (flagged_as_clone)` and `ix_..._risk_level (risk_level)`; `ix_..._created_at` is `created_at DESC` in the database, plain in the model. | I | Low | From revision 13 (raw SQL). Both extra indexes are on low-selectivity columns and are of doubtful value, but harmless on an empty table. Declare them (and DESC) in the model, or drop them in a future migration; no urgency. |
| 3.5 | **`elderly_configs.user_id` redundant index.** The database has `UNIQUE (user_id)` as constraint `elderly_configs_user_id_key` (its own unique index) **and** a separate plain index `ix_elderly_configs_user_id`. The model wants one unique index named `ix_elderly_configs_user_id`. | I (migration) | Low | Uniqueness is enforced either way; the plain index is redundant (extra write cost, about 8 KiB empty). Drop it in a future migration and align the model, or leave. |
| 3.6 | **`warrior_profiles.user_id`:** the database enforces uniqueness through the constraint `warrior_profiles_user_id_key`; the model declares a unique index `ix_warrior_profiles_user_id`. | N | Info | Equivalent. |
| 3.7 | **ON DELETE differs** for `behavior_events.user_id`, `community_scam_reports.user_id`, `emergency_contacts.user_id`: database **CASCADE**, model plain (NO ACTION). | I | Low | The raw-SQL revision 8 created them with `ON DELETE CASCADE` (user deletion cleans these rows). Runtime behaviour in this database is CASCADE; a database built by `create_all` would differ. Declare `ondelete="CASCADE"` in the models to match. |
| 3.8 | **`community_scam_reports` index names:** database `ix_community_scam_{city,created_at,pincode,user_id}` (created_at is DESC); model-style names `ix_community_scam_reports_*`. | N | Info | Same columns; only names (and DESC) differ. |
| 3.9 | **`sms_sender_registry`: model-side defect.** The model declares two identical plain indexes on `header`: `ix_sms_sender_registry_header` (from `index=True`) and an explicit `Index("ix_sms_sender_header_upper", "header")`. The database has one plain index. The second index's **name says "upper" but it indexes the raw column**. | **D** | Low-Medium | `app/services/sms_header_validator.py:152` looks senders up with `WHERE func.upper(header) = :x`, which the plain btree cannot serve, so every lookup scans the table (small until the TRAI registry is seeded; then noticeable). The intent was evidently an expression index on `upper(header)`. Recommend: fix the model to `Index("ix_sms_sender_header_upper", func.upper(header))` and add the matching migration **before seeding the registry**. Nothing needs to change for startup. |
| 3.10 | **58 columns carry a database default the model does not declare** (all on the raw-SQL tables: `gen_random_uuid()` ids, `now()` timestamps, boolean/integer/JSONB literals, enum defaults) across `app_install_events`, `behavior_events`, `clone_reports`, `community_scam_reports`, `elderly_configs`, `emergency_contacts`, `warrior_*`. | I | Info | The ORM supplies these values in Python, so behaviour through the application is unchanged. Note that `now()` produces the **session-timezone** time while the application writes UTC; do not rely on the database default for inserts that bypass the ORM. |
**No other difference was found.** In particular: no missing table, column, type, length, nullability, enum value, foreign-key target, unique/check constraint or sequence ownership.

## 4. What `alembic check` would do if it were a gate
It currently **fails**, for the structural reasons 3.1 to 3.9 (types and defaults are not even compared by `env.py`). It therefore cannot be used as a CI gate until the models and migrations are aligned; it also shows that **auto-generating the next migration from these models would produce destructive operations** (drop of `otp_vault_entries`, drop of the partial unique index, drop of three indexes). Nothing was generated or applied. The existing integration test `tests/integration/test_schema_drift.py` (tables, columns, enum values) is not affected by any difference above.

## 5. Suitability for local application startup
**Yes.** Evidence: the database is at the expected head; every table, column, type and enum the models use exists; the runtime role passes the application's own startup identity check against `secureshield_dev`, can read the tables, is not a superuser, and (from the 1.3 catalog checks) holds DML but no DDL; the DB-level differences above do not change what the application reads or writes. Not yet exercised: an actual start-up and request handling (not allowed in this task), and the SMS registry is empty until the seed script is run (lookups will report "not found", with a table scan once seeded: see 3.9).

## 6. Recommended follow-ups (none blocks startup; each needs its own approval)
1. **Before any autogenerate:** declare `uq_warrior_app_user_pending` (3.3) and keep `otp_vault_entries` accounted for (3.1) so the next generated migration is not destructive.
2. **Before seeding the SMS registry:** correct the `ix_sms_sender_header_upper` model/migration (3.9).
3. Align the remaining models with the migrations (3.2, 3.4, 3.7, 3.8), then enable `compare_type` and `compare_server_default` in `alembic/env.py` and make `alembic check` a gate.
4. Optional later migration: drop the redundant `elderly_configs` index (3.5) and add the `warrior_audit_logs` table comment (3.2).
