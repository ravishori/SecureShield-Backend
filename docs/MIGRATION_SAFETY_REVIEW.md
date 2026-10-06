# Migration safety review - seven unapplied revisions

Status: **none of these has been applied to Railway or any shared database.** They have run only on the
isolated local PostgreSQL 18 databases (the test database and a throw-away rehearsal database).
Do not apply them anywhere shared without reading this document.

Base revision before this work: `l7m8n9o0p1q2`. Head now: `s4t5u6v7w8x9`. Chain is linear
(21 history entries, no branches, `alembic heads` = one head).

## How this was verified

`python scripts/migration_rehearsal.py` (re-run on 2026-10-06 with all seven revisions) creates a scratch local database, upgrades to `l7m8n9o0p1q2`,
seeds rows that hit every destructive path, applies the six revisions one at a time printing row counts,
downgrades all six, and re-upgrades to head. Result on 2026-10-06 (PostgreSQL 18, loopback):

```
seeded at l7m8n9o0p1q2
  before      users=2 otps=3 family_members=1 security_reports=3 app_scans=1 wifi_scans=1 alerts=1
  after m8n9  users=2 otps=3 family_members=1 security_reports=3 app_scans=1 wifi_scans=1 alerts=1
  after n9o0  users=2 otps=3 family_members=1 security_reports=2 ...        (1 duplicate report deleted)
  after o0p1  (unchanged)
  after p1q2  (unchanged)
  after q2r3  otps=0 ...                                                      (3 OTP rows deleted)
  after r3s4  (unchanged)
  after s4t5  (unchanged)
downgrades: all seven ran without error (see "reversibility" - several do not restore data)
re-upgrade to head OK
```

Also: `tests/integration/test_schema_drift.py` (ORM enums, tables and columns versus the migrated DB) passes, and
`alembic check` reports only **pre-existing** index/foreign-key-name differences on older tables
(`warrior_*`, `community_scam_*`, `app_install_events`, ...) plus the `otp_vault_entries` table, which has
migrations but no ORM model. None involves the tables touched by these six revisions.

## Per-revision review (the first six were reviewed first; a seventh was added afterwards)

### m8n9o0p1q2r3 - family consent
| | |
|---|---|
| Tables | `family_members` (+2 columns, +2 indexes) |
| Change | `consent_status varchar(16) NOT NULL DEFAULT 'pending'`, `invited_phone varchar(20) NULL`, indexes on `member_user_id`, `invited_phone` |
| Destructive? | **Behavioural, not data-destroying**: every existing row gets `pending`, so existing family members immediately lose access to the other person's alerts until that person accepts. Intended (those links were never consented to). |
| Row impact | all rows in `family_members` get the default; no rows added/removed |
| Reversible? | Yes: downgrade drops the columns/indexes (consent state would be lost) |
| Failure/rollback | Runs in one transaction; a failure leaves the table unchanged. Adding a NOT NULL column with a constant default is metadata-only on PostgreSQL 11+; index builds briefly block writes to this small table |
| Backup needed? | Recommended (cheap) because behaviour changes for existing users |
| Safe for an isolated staging DB? | Yes |

### n9o0p1q2r3s4 - one security report per user per day
| | |
|---|---|
| Tables | `security_reports` |
| Change | `DELETE` older duplicates per (user_id, report_date) keeping the newest by (created_at, id); add `UNIQUE (user_id, report_date)` |
| Destructive? | **Yes - deletes duplicate rows** |
| Row impact | N-1 rows removed for every (user, day) with N reports. Rehearsal: 3 -> 2. Reports are derived data (recomputed on read), so the loss is cosmetic |
| Reversible? | Constraint removal yes; **deleted duplicates are not restored** |
| Failure/rollback | Single transaction, so a failure rolls the delete back. The `ALTER TABLE ADD CONSTRAINT` takes a short ACCESS EXCLUSIVE lock |
| Backup needed? | Yes if the reports table holds anything you care about; otherwise optional |
| Safe for isolated staging? | Yes |

### o0p1q2r3s4t5 - owner column for scans
| | |
|---|---|
| Tables | `app_scans`, `wifi_scans` |
| Change | add nullable `user_id UUID`, FK to `users(id)`, index |
| Destructive? | No |
| Row impact | none; existing rows keep `user_id = NULL` and are **never returned to any user** afterwards (they could not be attributed). Rehearsal: counts unchanged |
| Reversible? | Yes (drops the column; ownership data created after the upgrade is lost) |
| Failure/rollback | Transactional. FK validation scans the table (short lock; negligible for small tables, plan a window if either table is large) |
| Backup needed? | Optional |
| Safe for isolated staging? | Yes |

### p1q2r3s4t5u6 - 7 new `alerttype` values
| | |
|---|---|
| Tables | enum type `alerttype` |
| Change | `ALTER TYPE ... ADD VALUE IF NOT EXISTS` x7, executed in an autocommit block |
| Destructive? | No |
| Row impact | none |
| Reversible? | **No.** PostgreSQL cannot drop enum values; downgrade is a deliberate no-op (the "downgrade OK" line in the rehearsal is a no-op, not a reversal). Leaving the values is harmless |
| Failure/rollback | Because it runs outside the migration transaction, a crash after some values were added leaves them added; re-running is safe (`IF NOT EXISTS`). Alembic only advances the version after the block completes |
| Backup needed? | No |
| Safe for isolated staging? | Yes. Required for job-offer / suspicious-message / cyberbullying alerts to work at all |

### q2r3s4t5u6v7 - hashed OTP codes
| | |
|---|---|
| Tables | `otps` |
| Change | `DELETE FROM otps`; widen `code` from `varchar(10)` to `varchar(64)` |
| Destructive? | **Yes - deletes every OTP row**, intentionally, so no plaintext code remains at rest |
| Row impact | all rows (rehearsal 3 -> 0). OTPs live 10 minutes, so the effect is that in-flight verification codes stop working; users request a new one |
| Reversible? | Column width yes (and downgrade also deletes rows); deleted codes are not restored |
| Failure/rollback | Transactional. Widening a varchar is metadata-only (no table rewrite) |
| Backup needed? | No (ephemeral data) |
| Safe for isolated staging? | Yes. Coordinate with the app deployment: the new code verifies HMACs, the old code compares plaintext - run migration and deploy together |

### r3s4t5u6v7w8 - refresh-token rotation tables
| | |
|---|---|
| Tables | new `refresh_token_uses`, `revoked_token_families` |
| Change | create tables + indexes, FK to `users` |
| Destructive? | No data touched. **Behavioural:** refresh tokens issued before this release carry no `jti`/`fam` and are rejected, so every signed-in client must log in once more |
| Row impact | none |
| Reversible? | Yes (drops the tables) |
| Failure/rollback | Transactional; new tables only |
| Backup needed? | No |
| Safe for isolated staging? | Yes. Account erasure already removes these rows |

### s4t5u6v7w8x9 - admin audit log
| | |
|---|---|
| Tables | new `admin_audit_logs` (+3 indexes), no foreign key (rows must outlive an erased account) |
| Destructive? | No |
| Row impact | none (new table) |
| Reversible? | Yes (drops the table; audit history created after the upgrade is lost) |
| Failure/rollback | Transactional; new table only |
| Backup needed? | No |
| Safe for isolated staging? | Yes. The runtime role needs INSERT/SELECT on the new table (same GRANT step as the refresh-token tables) |

## Pre-deployment checks (mandatory before applying to ANY shared database)

Read-only tooling: `scripts/premigration_report.py` prints the counts below (connection is read-only; counts only,
never row contents; tables that do not exist yet read as `absent`). Verified on a seeded scratch database before and after
the migrations.

### Gate 0 - for all migrations
1. `python scripts/db_backup.py` -> dump + `.sha256`; **`python scripts/db_restore_check.py <dump>` must print
   `RESTORE CHECK PASSED`** (restores into a scratch local database and compares row counts).
2. `PREMIGRATION_DATABASE_URL=... python scripts/premigration_report.py > before.txt` (keep it with the dump).
3. Confirm the target is the isolated staging database, **not** the Railway environment named `production`.
4. Application code and migrations deploy together (the new code does not run on the old schema).

### Per data-affecting migration
| Migration | What users will experience | Pre-check (from `before.txt`) | Expected after | If the numbers differ |
|---|---|---|---|---|
| `m8n9o0p1q2r3` family consent reset | Every existing family link stops showing the other person's alerts until that person accepts the invitation. Inviters see "Waiting for approval"; invitees see an Invite | `family_members (all)` = N | `consent_status='pending'` = N, `consent_status<>'pending'` = 0, row count still N | Any non-pending row = the migration did not run; any row count change = stop and restore |
| `n9o0p1q2r3s4` duplicate reports | Nothing visible: reports are recomputed from live data on the next open | `security_reports (all)` = R, duplicates D | rows = R - D, and `select user_id, report_date from security_reports group by 1,2 having count(*)>1` returns 0 rows | rows != R - D = stop and restore |
| `q2r3s4t5u6v7` OTP deletion | A verification code requested in the last 10 minutes stops working; the user taps "Resend". Run in a quiet period | `otps (all)` = O, `still valid` = V (V = people affected) | `otps (all)` = 0 | any remaining row = plaintext codes still at rest: investigate before going on |
| `r3s4t5u6v7w8` refresh-token invalidation | **Every signed-in user is signed out once** (their stored refresh token has no `jti`/family) and must log in again with an OTP. OTP delivery must therefore be WORKING before this goes live (see staging plan) | `users (active)` = U (upper bound of people who must re-login) | tables exist and are empty; first refresh with a freshly issued token succeeds, a second use of it returns 401 | no re-login possible = do not deploy while OTP delivery is broken |

Other revisions need no data check beyond Gate 0 (`o0p1` leaves existing app/Wi-Fi scans unowned and invisible; `p1q2` adds enum
values; `s4t5` adds a table).

### Post-migration verification
`premigration_report.py > after.txt`, diff against `before.txt`, then `alembic current` = `s4t5u6v7w8x9`, `GET /health` = 200, and run
the smoke tests in `docs/STAGING_DEPLOYMENT_PLAN.md`. Keep both files and the dump until the release is accepted.

### Rollback
Preferred: restore the dump taken in Gate 0 into a new database and repoint the service (`docs/BACKUP_AND_RECOVERY.md`, procedure B).
`alembic downgrade` exists for every revision but does **not** bring deleted rows back (`n9o0`, `q2r3`), cannot drop enum values (`p1q2`)
and drops data written after the upgrade (`o0p1`, `r3s4`, `s4t5`); use it only for a failed, empty deployment.

## Deployment-order notes

* The application code and the migrations must ship together (hashed OTPs, rotation tables, `user_id` columns,
  consent column are all required by the new code; the new code is not compatible with the old schema).
* Run `alembic upgrade head` as the migrator role (the Railway `preDeploy` command does this) and confirm the runtime
  role has DML on the two new tables (`GRANT` as per `docs/RAILWAY_DEPLOYMENT.md`).
* Take a logical backup first with `scripts/db_backup.py` and prove it with `scripts/db_restore_check.py`
  (`docs/BACKUP_AND_RECOVERY.md`) - two of the six revisions delete rows.
* A staging database must be isolated from real user data and separate from the Railway environment named
  `production`.
