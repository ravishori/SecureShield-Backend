# Isolated staging deployment plan (NOT executed)

Status: **written plan only.** Nothing has been pushed, deployed or changed on Railway. The existing Railway project
`secureshield-staging` has a single environment that is *named* `production`; nothing in this plan touches it.

## 0. Preconditions (all must be true before step 1)

| # | Precondition | Evidence today |
|---|---|---|
| P1 | The owner approves, in writing, the push of the branch and creation of the isolated target | **not given** |
| P2 | Local gate is green: backend pytest, ruff 0.9.4, `pip check`, `alembic heads` = 1, real gitleaks tree scan clean, Flutter analyze/test | see `SECURESHIELD_FEATURE_COMPLETION_MATRIX.md` |
| P3 | `docs/MIGRATION_SAFETY_REVIEW.md` Gate 0 checks are understood and the backup tooling has been verified | verified locally |
| P4 | A working OTP delivery path exists for the staging project (see 2.4) - otherwise nobody can log in after the refresh-token reset | **blocked on provider credentials** |
| P5 | The branch has no other pending/unreviewed changes (`git status` clean apart from the two known untracked/unrelated files) | `scripts/seed_sms_registry.py` (pre-existing, not part of this work) and `start.bat` must stay out of the push |

## 1. Isolation requirements

1. **New Railway project** (preferred) or a new environment inside a new project, named e.g. `secureshield-staging-gate`.
   Do not add a service to, rename, or redeploy anything in the project whose environment is called `production`.
2. **New PostgreSQL** instance in that project - never a connection string pointing at the existing database.
3. **Own variables**, none copied from the existing project except non-secret defaults:
   * `DATABASE_URL`, `MIGRATOR_DATABASE_URL` (separate migrator role from the runtime role),
   * a freshly generated `SECRET_KEY` (so tokens from any other environment are invalid here),
   * `ADMIN_TOKEN`: a new random value, used only for testing and discarded afterwards,
   * provider keys only if the owner supplies *staging* keys (Resend/Twilio/GSB/URLhaus/Anthropic); otherwise leave them
     unset - features that need them must then fail closed (verified in tests) and are marked EXTERNAL-unverified,
   * `FILE_ENCRYPTION_KEY` (new) if encryption is to be exercised,
   * `ENVIRONMENT=staging`,
   * `TRUSTED_PROXIES` = the range the platform proxy connects from (FG-167; unverified for Railway - determine it first; the staging environment does not enforce this check, so it must be set by hand).
4. **No real user data.** Seed with the scripted fixtures below; never restore a production dump into this project.
5. Config as code: copy `.railway/railway.ts` and edit `source` to the *new* repository branch/service names; keep
   `preDeploy: "alembic upgrade head"`, `healthcheck: "/health"`, `checkSuites: false` (see the known stale-check-suite problem).

## 2. Procedure

### 2.1 Branch hygiene (local, read-only)
```
git status --short                      # only the two known unrelated files may appear
git log --oneline origin/staging/railway-snapshot..HEAD | wc -l    # size of the delta being pushed
python -m ruff check app tests scripts && python -m ruff format --check app tests scripts
python -m pytest tests -q               # full suite, real PostgreSQL
/d/tmp/gl/gitleaks.exe dir <clean export of HEAD> --config .gitleaks.toml     # tree scan must be clean
```
Record the HEAD commit id: this is the **expected SHA** for step 2.6.

### 2.2 Create the target and its database
Create the project, add Postgres, set the variables from section 1. Create two roles (migrator = owner/DDL, runtime = DML only) as in
`docs/RAILWAY_DEPLOYMENT.md`.

### 2.3 Backup + baseline (even though the database is empty/new)
```
python scripts/db_backup.py --out backups/            # with BACKUP_DATABASE_URL = the NEW database
python scripts/db_restore_check.py backups/<dump>      # RESTORE CHECK PASSED required
PREMIGRATION_DATABASE_URL=... python scripts/premigration_report.py > before.txt
```
For a database that already holds data (a staging DB seeded from a *sanitised* copy), `before.txt` must show the expected counts from
`docs/MIGRATION_SAFETY_REVIEW.md` "Pre-deployment checks" before continuing.

### 2.4 OTP delivery check (blocking)
Before the first deploy confirm, from the target project, that one message can be delivered by the chosen provider (Resend domain verified
or Twilio credentials valid). If it cannot, stop: the refresh-token migration signs every user out and nobody could sign back in.

### 2.5 Push and deploy (needs P1)
Push only to the branch connected to the **new** project's service. Railway runs the pre-deploy command `alembic upgrade head` as the
migrator role (seven revisions `m8n9o0p1q2r3` ... `s4t5u6v7w8x9` on top of `l7m8n9o0p1q2`), then starts the service and waits for
`/health` (60 s timeout).

### 2.6 Post-deploy verification (all must pass)
| Check | Command / expectation |
|---|---|
| Migrations | `alembic current` (via `railway run`) = `s4t5u6v7w8x9`; `premigration_report.py > after.txt` matches the expectations table |
| Health | `GET /health` = `{"status":"healthy"}`; `GET /ready` = 200 with the staging database name (not the existing project's) |
| **Git SHA** | `GET /version` returns `git_sha` equal to the HEAD recorded in 2.1 and `alembic_head` = `s4t5u6v7w8x9`. A different SHA means a stale or foreign build: stop |
| CI | The GitHub Actions run for that exact SHA is green: `backend-ci` (gitleaks, lint, `alembic upgrade head` on blank Postgres, pytest) |
| Runtime role least privilege | the app role cannot `CREATE TABLE`; it can read/write the two new token tables and `admin_audit_logs` |

### 2.7 Smoke tests (run against the staging URL)
1. Register a test user, request OTP, verify, `GET /auth/me`.
2. `POST /auth/refresh` twice with the same refresh token: second call must be 401 (rotation) and the lineage revoked.
3. Create a family invite between two test users; the invitee sees it; accept; the inviter's `/family/dashboard` shows the link.
4. `POST /alerts/panic` with one emergency contact: 200 and, if a provider is configured, one message received.
5. Upload evidence (small file) and download it back; with `FILE_ENCRYPTION_KEY` set verify the stored file starts with `SSENC` (via `railway run`).
6. Admin console `/api/v1/admin/console` loads; token required for data; disable/enable a test user; the audit log shows both.
7. Reports: `/reports/daily` returns a security score; `/reports/daily/email` returns 200 only with a configured provider.
8. Run `node scripts/admin_console_browser_e2e.mjs` against a staging-sized local copy if a browser-based check of the real URL is required.
9. Rate-limit identity (FG-167): send more than `API_RATE_LIMIT` (default 100) requests within a minute to any non-exempt URL from one machine while changing `X-Forwarded-For` on every request; expect `429` after the budget. Then confirm a *second* machine is NOT limited at the same time (proving users are not collapsed onto the proxy address).
10. Point the **release APK** (`--dart-define=API_BASE_URL=https://<staging>/api/v1`) at it on an emulator: login, dashboard score, family invite, SOS.

### 2.8 Clean-up
Delete the test users with `DELETE /auth/me` (full erasure), remove the temporary `ADMIN_TOKEN`, keep `before.txt`, `after.txt` and the dump with the release record.

## 3. Rollback and recovery

| Situation | Action |
|---|---|
| Pre-deploy migration fails | Railway keeps the previous deployment running; nothing is half-applied except `p1q2r3s4t5u6` (enum values, idempotent) - fix and redeploy |
| `/health` or `/version` wrong after deploy | Redeploy the previous good deployment from the dashboard; the schema is forward-compatible for the *old* code only for revisions that add columns/tables, **not** for `q2r3` (OTP column holds hashes) and `r3s4` (old code ignores the tables but issues tokens without `jti`): treat a rollback of the code after migration as a database restore |
| Data problem found in staging | Restore `backups/<dump>` into a new database (`docs/BACKUP_AND_RECOVERY.md` procedure B), repoint `DATABASE_URL`, redeploy |
| Whole project unusable | Delete the project; nothing else depends on it (that is the point of isolation) |

## 4. Exit criteria for the staging gate
All of 2.6 and 2.7 pass on the recorded SHA, CI is green for that SHA, no secret appears in logs (`railway logs | gitleaks stdin`), and the owner signs off. Only then can a **separate** decision be made about any other environment.

## 5. What this gate will *not* prove
Provider-side behaviour without staging provider keys (OTP/SMS/e-mail delivery, Safe Browsing, URLhaus, Anthropic), native-speaker translation quality, Play Store acceptance, behaviour under production load.
