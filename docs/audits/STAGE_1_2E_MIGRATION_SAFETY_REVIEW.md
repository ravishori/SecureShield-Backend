# Stage 1.2E: Alembic migration safety review (target: empty `secureshield_dev`)

Date: 2026-11-15. Scope: the 26 revisions from `07cfca043074` (initial) to `x9y0z1a2b3c4`. **Strictly read-only.** No database connection, no `psql`, no Alembic command (neither `upgrade`, `downgrade`, `--sql` nor `current`), no backend start; no migration, SQL file, application code or configuration was modified.

**Evidence labels.** **[V]** verified by reading the code or by an offline check I ran. **[A]** assumption or inference that only a real PostgreSQL run can confirm.

## 1. Method
1. **Static reading [V]:** every `upgrade()` and `downgrade()` was read (all 26; the three newest in full).
2. **AST scan [V]:** revision ids, `down_revision` links and every `op.*` call per function.
3. **Offline replay [V, with limits]:** a throw-away script (kept in the session scratchpad, not in the repository) replaced `alembic.op` with an in-memory mock, ran each `upgrade()` in chain order, and recorded tables, columns, indexes, constraints, foreign keys and enum types. The mock **fails on any operation whose prerequisite does not exist at that point** (a missing table, column, constraint, index, referenced table or column). This models what an empty PostgreSQL would require; it is **not** PostgreSQL. Raw `CREATE TABLE`/`CREATE INDEX`/`DROP TABLE` SQL was parsed by pattern; `DO $$` blocks and enum additions were handled by pattern; real SQL semantics were not executed.
4. **Model comparison [V, with limits]:** the replayed head schema was compared with `Base.metadata` (SQLAlchemy models): tables, columns, nullability, type family, String lengths, indexes, unique constraints, foreign keys and enum names/values.

## 2. Revision chain
**Verified linear [V]:** 26 revisions, exactly one root (`07cfca043074`), exactly one head (`x9y0z1a2b3c4`), no branch point, no duplicate revision id, no missing parent.
| # | Revision | Name | Git |
|---|---|---|---|
| 1 | `07cfca043074` | initial | tracked |
| 2 | `3bf328167739` | add_error_logs_table | tracked |
| 3 | `6098a82b5e06` | phone_email_otp_support | tracked |
| 4 | `519e8e8aa0ae` | add_address_profile_fields | tracked |
| 5 | `a1b2c3d4e5f6` | add_recordings_table | tracked |
| 6 | `e9e22b86f70c` | add_community_scam_behavior_event (misnamed: see 4) | tracked |
| 7 | `d845ea331d7d` | add_emergency_contacts (misnamed: only conditional drops) | tracked |
| 8 | `f1a2b3c4d5e6` | recreate_missing_tables | tracked |
| 9 | `g2h3i4j5k6l7` | add_gsb_threats_to_link_scans | tracked |
| 10 | `h3i4j5k6l7m8` | create_sms_registry_tables | tracked |
| 11 | `i4j5k6l7m8n9` | make_wifi_scan_device_id_optional | tracked |
| 12 | `j5k6l7m8n9o0` | make_app_scan_device_id_optional | tracked |
| 13 | `k6l7m8n9o0p1` | add_app_install_clone_elderly | tracked |
| 14 | `l7m8n9o0p1q2` | create_cyber_warrior_tables | tracked |
| 15 | `m8n9o0p1q2r3` | family_member_consent | tracked |
| 16 | `n9o0p1q2r3s4` | security_report_unique_day | tracked |
| 17 | `o0p1q2r3s4t5` | scope_scans_to_users | tracked |
| 18 | `p1q2r3s4t5u6` | add_missing_alerttype_values | tracked |
| 19 | `q2r3s4t5u6v7` | hash_otp_codes | tracked |
| 20 | `r3s4t5u6v7w8` | refresh_token_rotation | tracked |
| 21 | `s4t5u6v7w8x9` | admin_audit_log | tracked |
| 22 | `t5u6v7w8x9y0` | otp_attempts | tracked |
| 23 | `u6v7w8x9y0z1` | admin_accounts | tracked |
| 24 | `v7w8x9y0z1a2` | identity_binding | **untracked** |
| 25 | `w8x9y0z1a2b3` | consent_records | **untracked** |
| 26 | `x9y0z1a2b3c4` | app_monitor_sync_and_guardian_outbox | **untracked** |
(The order in the table is the real upgrade order; the file names do not sort in that order.) `alembic.ini` holds only an inert placeholder URL; `alembic/env.py` uses `MIGRATOR_DATABASE_URL`, runs the identity checks first, and runs **all revisions in one transaction** (no `transaction_per_migration`) except at revision 18 (section 6).

## 3. Migration-by-migration findings (upgrade path on an empty database)
| Rev | Upgrade | Data / destructive effect | Empty-DB result | Depends on |
|---|---|---|---|---|
| 1 | creates 14 tables, 15 indexes, 6 enum types (`subscriptiontier`, `conversationrole`, `filetype`, `alerttype`, `alertseverity`, `risklevel`) via `sa.Enum` | none | OK [V replay] | none |
| 2 | `error_logs` + 2 indexes | none | OK | none |
| 3 | adds `otps.email`; makes `otps.phone`/`users.phone` nullable; replaces unique constraint `users_email_key` with unique index `ix_users_email` | none (empty) | OK; needs constraint `users_email_key` created by rev 1 [V] | 1 |
| 4 | 10 nullable address columns on `users` | none | OK | 1 |
| 5 | `recordings` table + index | none | OK | 1 |
| 6 | adds 3 `NOT NULL` boolean columns **without server default** to `family_members`; swaps the `share_token` unique constraint for a unique index | none on empty | OK on empty; **would fail on a table with rows** [V] | 5 (`recordings_share_token_key`, `ix_recordings_share_token`), 1 |
| 7 | `DROP TABLE IF EXISTS behavior_events/community_scam_reports CASCADE` | **destructive if those tables exist**; no-op here | OK (no-op) | none |
| 8 | creates 2 enum types (guarded `DO`), `behavior_events`, `community_scam_reports`, `emergency_contacts` with `IF NOT EXISTS`; uses `gen_random_uuid()` | none | OK (built into PostgreSQL 13+) | 1 (`users`) |
| 9 | `link_scans.gsb_threats` JSONB | none | OK | 1 |
| 10 | 3 registry tables + 1 index | none; **creates the tables empty, seeding is a separate script** | OK | none |
| 11 | drops the FK `wifi_scans.device_id -> devices` by catalog lookup, makes the column nullable | none | OK [A: lookup runs on real catalogs] | 1 |
| 12 | same for `app_scans` | none | OK [A] | 1 |
| 13 | raw `CREATE TABLE IF NOT EXISTS` x3 (`app_install_events`, `clone_reports`, `elderly_configs`) + 10 indexes | none | OK (these tables have no FK to `users`) | none |
| 14 | 3 enums, 3 warrior tables, 5 indexes incl. a **partial unique index** (`uq_warrior_app_user_pending`) | none | OK | 1 |
| 15 | 2 columns on `family_members` (`consent_status` NOT NULL **with** default) + 2 indexes | none | OK | 1 |
| 16 | **`DELETE`** of duplicate `security_reports` rows (self-join), then a unique constraint | **data deletion** (duplicates only); 0 rows on empty | OK | 1 (`report_date`, `created_at`, `id`, `user_id`) |
| 17 | `user_id` (nullable) + FK + index on `app_scans`, `wifi_scans` | none | OK | 1 |
| 18 | `ALTER TYPE alerttype ADD VALUE IF NOT EXISTS` x7, in an **autocommit block** | irreversible enum additions (harmless) | OK; commits the migration transaction here | 1 (`alerttype`) |
| 19 | **`DELETE FROM otps`** (all rows), widens `otps.code` to `VARCHAR(64)` | **deletes every OTP row** (by design: plaintext codes must not survive) | OK | 1 |
| 20 | `refresh_token_uses`, `revoked_token_families` + 5 indexes | none | OK | 1 (`users`) |
| 21 | `admin_audit_logs` + 3 indexes | none | OK | none |
| 22 | `otps.attempts` NOT NULL default 0 | none | OK | 19 |
| 23 | `admin_accounts`, `admin_sessions` (+ check constraint, FK cascade), 2 columns on `admin_audit_logs` | none | OK | 21 |
| 24 | 3 `users` columns, unique index `ix_users_google_sub`, `pending_registrations`, 5 `otps` columns, 2 FKs (cascade), check `ck_otps_single_identifier` | none; the check is satisfied by existing rows because the new columns are NULL | OK | 3 (`otps.email`, `otps.phone`), 1 |
| 25 | `user_consents` (FK cascade) + 4 nullable columns on `pending_registrations` | none | OK | 24 |
| 26 | 2 nullable columns + 2 **partial unique indexes** on `app_install_events`; `guardian_alert_outbox` (+ unique constraint, FK `SET NULL`), `guardian_alert_deliveries` (FK cascade); 6 nullable columns on `elderly_configs` | none | OK | 13 (`app_install_events`, `elderly_configs`) |
**Replay result [V]:** 0 prerequisite or ordering violations across all 26 upgrades. Head schema: **37 tables** (36 backed by models + `otp_vault_entries`), 411 columns, 61 non-unique indexes, 14 unique constraints/indexes, 32 foreign keys, **11 enum types**.

## 4. Destructive-operation register
**Upgrade path (what runs when you migrate an empty `secureshield_dev`)**
| Rev | Operation | Kind | Effect on an EMPTY database |
|---|---|---|---|
| 7 | `DROP TABLE IF EXISTS behavior_events, community_scam_reports CASCADE` | conditional drop | **none** (tables absent) |
| 16 | `DELETE` duplicate `security_reports` rows | bulk delete | none (0 rows) |
| 19 | `DELETE FROM otps` | bulk delete (all rows) | none (0 rows) |
| 3, 6, 11, 12 | drop a unique constraint / index / foreign key | schema change only | none |
No `DROP COLUMN`, `TRUNCATE`, bulk `UPDATE`, `INSERT`, `COPY`, `CREATE EXTENSION`, `GRANT`/`OWNER TO`, `CONCURRENTLY`, seed data or external side effect (network, file, subprocess) appears in any revision [V: pattern search over all 26 files]. Total upgrade-path data-loss exposure on `secureshield_dev`: **none**. (Against a populated database, 7/16/19 would delete data: that is irrelevant here but matters for the legacy `SecureShieldDB` and for Neon.)

**Downgrade path (not part of this task; hazards for the record)**
| Rev | Downgrade | Hazard |
|---|---|---|
| 1, 2, 5, 10, 13, 14, 20, 21, 23, 24, 25, 26 | `drop_table`/`DROP TABLE` | removes the tables and their data |
| 8 | `DROP TABLE ... CASCADE`, `DROP TYPE` | removes data |
| 7 | recreates the two dropped tables **empty** | cannot restore data |
| 16 | drops the unique constraint | deleted duplicates are not restored |
| 19 | `DELETE FROM otps` again | deletes OTPs |
| 11, 12 | `NOT NULL` + FK recreation | fails if any `device_id` is NULL |
| 3 | `NOT NULL` on phone | fails if any phone is NULL |
| 18 | no-op | enum values stay |
**Never run `alembic downgrade` against anything you want to keep; `downgrade base` would drop every table.**

## 5. Empty-database compatibility with PostgreSQL 18
- **Ordering and prerequisites [V replay]:** every table, column, index, constraint and referenced table used by a later revision exists at that point.
- **PostgreSQL-specific constructs [A, reasoned]:** `gen_random_uuid()` is built in since PostgreSQL 13 (no extension needed); `ALTER TYPE ... ADD VALUE IF NOT EXISTS` requires 9.6/12+; `DO $$` blocks and `IF NOT EXISTS` forms are standard; the row comparison in revision 16 is valid; the partial unique indexes and the check constraint are valid. No extension is created, so none is required.
- **Prior execution evidence [V from the repository's own records, not re-run by me]:** `scripts/migration_rehearsal.py` and the `docs/neon-migration` reports record revisions 15 to 21 (`m8n9...` through `s4t5...`) executed on scratch PostgreSQL 18.6 databases (the Neon rehearsal as the non-superuser rehearsal role). The legacy local source database was at revision 13 (`k6l7...`), so revisions 1 to 13 were applied to it historically; the chain from an empty database was last exercised by the Neon rehearsal path only up to the revisions listed. **No recorded execution** of revisions 22 to 26 (`t5u6`, `u6v7`, `v7w8`, `w8x9`, `x9y0`) was found: the three newest exist only with standalone review SQL marked "not executed anywhere". Revision 22 and 23 are simple additive revisions [V by reading]; 24 to 26 are additive too. This is the main residual risk.
- **Single-transaction behaviour [V by reading `env.py`]:** all revisions share one transaction **until revision 18**, whose autocommit block commits everything before it, then runs the enum additions in autocommit, then continues in a new transaction. A failure after revision 18 therefore rolls back only the later revisions: the schema stays at revision 17 (and the enum values added), and `alembic upgrade head` can simply be re-run (the additions are `IF NOT EXISTS`). A failure before revision 18 rolls back everything.
- **Driver [A]:** Alembic's `autocommit_block` under SQLAlchemy's asyncpg engine is supported and was part of the earlier rehearsals, but that exact async path is the one construct worth watching in the first run.
- **Privileges [V + A]:** run as `secureshield_dev_owner` (the `MIGRATOR_DATABASE_URL` role). It owns the database and so may create in `public` and create the enum types. Default privileges then give `secureshield_dev_app` row access and sequence use on everything created by the owner. Enum types are usable by `PUBLIC` by default. If the migrations were run as the superuser instead, the tables would be owned by `postgres` and the application role would have **no** access.

## 6. Disk and WAL assessment (all **[A]**: estimates, nothing measured)
| Item | Estimate |
|---|---|
| Size of the new `secureshield_dev` after migration | about 12 to 18 MB (the `template1` copy of roughly 7 to 8 MB plus catalog rows for 37 tables, 411 columns, 75 indexes and 11 enum types, plus about 8 KiB per empty index and some TOAST tables) |
| WAL from the migrations | a few MB of catalog changes; no table rewrite, no index build over existing rows |
| WAL from `CREATE DATABASE` (runbook Part 2, not the migrations) | roughly the size of `template1` per database, so about 15 MB for the two databases |
| Time | seconds |
No revision is expensive on an empty database. **Expensive on a populated database** (not the target): the non-concurrent index builds (revisions 1, 3, 6, 15, 17, 20 to 26) take locks; `ALTER COLUMN ... TYPE VARCHAR(64)` in revision 19 does not rewrite the table; the `NOT NULL ... DEFAULT` columns in revisions 15 and 22 are metadata-only on PostgreSQL 11+; revision 6's `NOT NULL` columns without a default fail on a populated `family_members`. Free space on D: was 1.77 GB when last checked, which is far above these figures.

## 7. Model versus schema (replayed head vs `Base.metadata`) [V, limits below]
**Matches:** every model table exists in the migrations; every model column exists with the same name, nullability, type family and, for strings, the same length; the 32 foreign-key column/target pairs; all enum names and the full `alerttype` value list (9 originals + 7 added in revision 18).
**Discrepancies (none blocking, none affecting an empty-database migration):**
| # | Finding | Severity | Note |
|---|---|---|---|
| D1 | Table `otp_vault_entries` is created by revision 1 but **no model exists** (`alembic/env.py` imports `app.models.otp_vault` inside a `try`; the module is absent). `app/services/account_erasure.py:222` deletes from it with raw SQL | Info | harmless legacy table |
| D2 | `warrior_audit_logs`: migrations create two composite indexes (`actor_user_id, created_at`) and (`subject_user_id, created_at`); the model declares single-column indexes on `action`, `actor_user_id`, `subject_user_id` instead | Low | affects autogenerate drift and the speed of `action` filters, not correctness |
| D3 | `warrior_applications`: the "one pending application per user" partial unique index exists only in the migration, not in the model | Low | the migration is authoritative; `create_all` would not create it |
| D4 | `app_install_events`: extra indexes `risk_level`, `flagged_as_clone` in the migration, absent from the model | Info | extra, harmless |
| D5 | `elderly_configs.user_id`: the model's `unique=True, index=True` implies one unique index; the migration has a unique constraint **and** a separate plain index of the same name | Info | redundant index; uniqueness is enforced |
**Not compared (limits) [V]:** server defaults, `ON DELETE` actions, CHECK constraint text, index and constraint names, partial-index `WHERE` clauses, column order, and real-PostgreSQL type details (the comparison uses type families and string lengths). Revision names `e9e22b86f70c` and `d845ea331d7d` do not describe what they do (cosmetic).

## 8. Blockers and recommended corrections
**Blockers for migrating `secureshield_dev`: none found.**
**Conditions / recommendations**
1. **Do not migrate before the database activation is complete and reviewed** (roles, ownership, privileges and the identity checks of the activation runbook), and use `SECURESHIELD_ENV_FILE=.env.local` so the owner role is the migrator.
2. **First run supervised, with the output captured**, because revisions 22 to 26 have no recorded execution. If it stops, read the error before retrying; before revision 18 nothing is kept, after it the schema stays at revision 17 and is safe to re-run.
3. **Never run `downgrade`** on this database for anything but a conscious reset decision.
4. **Seed data is outside the migrations:** `tsp_codes`, `lsa_codes` and `sms_sender_registry` will be empty; `scripts/seed_sms_registry.py` fills them (it `TRUNCATE`s and needs the owner role). Not a blocker.
5. Optional hygiene (separate decisions, none needed to migrate): add a server default to revision 6's columns only if a populated database must ever re-run it; align the `warrior_audit_logs` and `warrior_applications` index declarations between models and migrations; commit the three untracked revisions (a database migrated with them would otherwise be ahead of the repository).

## 9. Verdict: **SAFE WITH CONDITIONS**
For an empty `secureshield_dev`: linear chain, no prerequisite violation, no data-destroying operation takes effect, no external side effect, negligible disk and WAL. The conditions are procedural (section 8, items 1 to 3): it has never run on a PostgreSQL server in this form for the five newest revisions, and activation must be completed first. This review does not authorise running any migration.

**Verified vs assumed, in one line:** chain, operations, destructive register, prerequisite order and model comparison are **verified**; PostgreSQL's actual behaviour, the async autocommit path, sizes and WAL are **assumptions**.
