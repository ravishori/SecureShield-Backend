# Stage 1.2C: database activation evidence review

Date: 2026-11-15. Reference: `STAGE_1_2B_LOCAL_DATABASE_ACTIVATION_RUNBOOK.md` (SQL SHA-256 `CC6A851B48DBEFD2B87046137E91648C6BE410A54AE34CD4695140EE94EE9B06`).

## Status: NO EVIDENCE RECEIVED, so NO CHECKPOINT CAN BE REVIEWED
The request says the activation output "will be provided", but none came with it. I looked for it where the runbook tells you to put it:
- `C:\SecureShieldActivation` **does not exist** (no part logs, no inventory, no proofs).
- `backend\.env.local` **does not exist**.
- The message itself contains no pasted output.

Nothing was fabricated or assumed. No result below is marked PASS, because a PASS needs an actual result. I did not connect to PostgreSQL, run SQL or `psql`, run Alembic, start the backend, or change any role, privilege or password. This file is a review record that is ready to be completed; it records an honest "not reviewed", not a verdict.

**Classification used here:** PASS / FAIL / NEEDS INVESTIGATION as requested, plus **NOT REVIEWED** (no evidence supplied). Every mandatory check is currently NOT REVIEWED.

## Checkpoint table (expected values come from the runbook; actual values are empty until you supply them)
| # | Checkpoint | Expected (runbook ref.) | Actual | Status |
|---|---|---|---|---|
| 1 | `postgresql-x64-18` Running, `PostgreSQL18` Stopped | §1.1 | not provided | NOT REVIEWED |
| 2 | No `PG*` / `DATABASE_URL`-type variables in the shell | §1.2: no rows | not provided | NOT REVIEWED |
| 3 | Server identity: 18.x, loopback address, port 5432, data dir `D:/Program Files/PostgreSQL/18/data`, `scram-sha-256`, superuser | §1.3 | not provided | NOT REVIEWED |
| 4 | Free space D: >= 500 MB, C: >= 1 GB | §1.4 | not provided | NOT REVIEWED |
| 5 | Names free beforehand; 0 sessions on `template1` | §1.5: 0 / 0 / 0 | not provided | NOT REVIEWED |
| 6 | `pg_hba` rules loopback `scram-sha-256` only | §1.6 | not provided | NOT REVIEWED |
| 7 | SQL hash and line count; the two TRUNCATE comment lines (10, 192) | §1.7 | not provided | NOT REVIEWED |
| 8 | Part files identical to the original | §1.8: `True` | not provided | NOT REVIEWED |
| 9 | Part 0 | one `DO`, exit 0 | not provided | NOT REVIEWED |
| 10 | Part 1 | `BEGIN, DO, DO, COMMIT` | not provided | NOT REVIEWED |
| 11 | Part 2 | `CREATE DATABASE` x2, `DO` | not provided | NOT REVIEWED |
| 12 | Part 3 | `BEGIN, REVOKE x2, GRANT x2, REVOKE x2, COMMIT` | not provided | NOT REVIEWED |
| 13 | Part 4 | connects to dev, test, postgres; `ALTER DEFAULT PRIVILEGES` x2 | not provided | NOT REVIEWED |
| 14 | 5.1 roles: 3 rows, login only, no privileged attribute, limits 50/20/20, no password yet | §3 | not provided | NOT REVIEWED |
| 15 | 5.1b no `trust` rule | 0 rows | not provided | NOT REVIEWED |
| 16 | 5.2 no role membership | 0 rows | not provided | NOT REVIEWED |
| 17 | 5.3 `secureshield_dev` owned by `secureshield_dev_owner`, `secureshield_test` by `secureshield_test_owner`, UTF8 | 2 rows | not provided | NOT REVIEWED |
| 18 | 5.4 connect matrix isolates dev from test | 6 rows | not provided | NOT REVIEWED |
| 19 | 5.5 no unexpected non-owner grantee | exactly 1 row (`secureshield_dev_app` CONNECT on dev) | not provided | NOT REVIEWED |
| 20 | 5.6 / 5.7 legacy database info, server identity | informational / loopback | not provided | NOT REVIEWED |
| 21 | 5.8 schema ACLs: no PUBLIC entry; app USAGE; 2 default ACLs | §3 | not provided | NOT REVIEWED |
| 22 | Passwords set (no hash shown) | 3 rows, all `t` | not provided | NOT REVIEWED |
| 23 | P1 to P3 logins work | users/databases printed | not provided | NOT REVIEWED |
| 24 | P4, P5 cross-database logins refused | `permission denied for database` | not provided | NOT REVIEWED |
| 25 | P6 app role cannot create a table | `permission denied for schema public` | not provided | NOT REVIEWED |
| 26 | P7 app role cannot create a role | `permission denied to create role` | not provided | NOT REVIEWED |
| 27 | P8 app role cannot create a database | `permission denied to create database` | not provided | NOT REVIEWED |
| 28 | `show_database_target --expect development` (static and real `.env.local`) | `identity OK ... class=loopback database=secureshield_dev`, roles `_dev_app` / `_dev_owner`, `exit: 0` | not provided | NOT REVIEWED |
| 29 | `show_database_target --expect test` (static) | `... database=secureshield_test`, role `_test_owner` both, `exit: 0` | not provided | NOT REVIEWED |

## How each requested verification maps to the table
| Requested verification | Decided by checkpoints | Currently |
|---|---|---|
| `secureshield_dev` exists, correct owner | 17 | NOT REVIEWED |
| `secureshield_test` exists, correct owner | 17 | NOT REVIEWED |
| Roles have only intended privileges | 14, 16 | NOT REVIEWED |
| Passwords configured, nothing exposed | 22 (and that no hash appears anywhere in the returned text) | NOT REVIEWED |
| No unexpected TRUST rules | 6, 15 | NOT REVIEWED |
| Development and test isolated | 18, 24 | NOT REVIEWED |
| App role cannot create tables, roles, databases | 25, 26, 27 | NOT REVIEWED |
| No unexpected non-owner grants | 19, 21 | NOT REVIEWED |
| Target check outputs | 28, 29 | NOT REVIEWED |

## Decision rules to apply when the evidence arrives
- **PASS** needs the exact expected output, a psql exit code of 0 (or the specific expected error for P4 to P8) and no line starting `ERROR:`/`FATAL:`/`WARNING:` where none is expected.
- **FAIL** (blocking): any privileged role attribute, any `trust` rule, a wrong owner, a connection that should be refused succeeding, P6/P7/P8 succeeding, a `PUBLIC` or unknown grantee, a hash or password appearing in the evidence (then also rotate that password), a SQL hash that differs from the pinned one.
- **NEEDS INVESTIGATION**: a deviation that is not a privilege problem (for example a different encoding, a different row order, an extra informational row, the legacy `SecureShieldDB` showing up as expected in 5.6) and anything ambiguous.
- Any single FAIL keeps Stage 1.2 open; the databases must not be used until it is resolved.

## Outstanding problems
1. **The activation has not been evidenced.** Either it has not been run yet (the runbook says it is pending your execution and approval), or the output has not been sent.
2. Nothing else is outstanding from the Stage 1.2 / 1.2A reviews.

## Conclusions
| Question | Answer |
|---|---|
| Can Stage 1.2 be formally closed? | **No.** There is no activation evidence, so the databases' existence, ownership, privileges and isolation are unverified. |
| Is Stage 1.3 authorised for planning? | **Not yet.** |
| Is the next task (local development Alembic migration rehearsal) recommended for approval? | **Not yet.** It depends on all mandatory checkpoints 1 to 29 passing; Alembic against `secureshield_dev` must not run before that. |

## What to do next
Run the runbook yourself (`STAGE_1_2B_LOCAL_DATABASE_ACTIVATION_RUNBOOK.md`), then send the text of the files listed in its section 9 (they contain no passwords). I will then fill in the Actual and Status columns, apply the decision rules above, and give the closing verdict. If you already ran it and the output is somewhere other than `C:\SecureShieldActivation`, tell me where or paste it.
