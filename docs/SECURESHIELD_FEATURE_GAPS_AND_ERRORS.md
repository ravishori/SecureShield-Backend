# SecureShield Feature Gaps and Errors

Authoritative backlog of unresolved staging/production issues. **No secret values appear in this
document.** The consolidated, ID-based register is in section 17; sections 1-16 give the detail.
Last updated after the hardening cycle of 2026-10-05 (token separation, account erasure, log scrubbing,
staging cleanup, reference-data seed, emulator test). Evidence was gathered on 2026-10-05 against the Railway *staging* environment
(project `secureshield-staging`, service `secureshield-api`) and the candidate commit set.

## Status legend

| Label | Meaning |
|---|---|
| BLOCKER | Production cannot ship until fixed |
| HIGH | Serious; fix before or immediately after production |
| MEDIUM | Should be fixed in the next hardening phase |
| LOW | Minor / hygiene |
| DEFERRED | Consciously postponed by the owner (recorded, not forgotten) |
| RESOLVED | Fixed and verified (test or staging evidence given) |

Feature-matrix status values: IMPLEMENTED, PARTIAL, NOT IMPLEMENTED, UNREVIEWED, BLOCKED, DEFERRED, RESOLVED.

**"UNREVIEWED"** = code that exists in the working tree but was deliberately excluded from the
candidate commits because nobody has reviewed it: `logger_service`, `gsb_service`, `ai_service`,
`link_scanner`, `community_scam`, `video_call`, `emergency_contacts`, `ai_coach`, the schemas
`ai_conversation` / `emergency_contact`, `urlhaus_service`, and the pre-existing "v2" parts of
`main.py` and `error_handler.py`. The **committed (HEAD) versions** of those modules are what the
candidate and the staging deployment contain.

---

## 1. Authentication / OTP

| # | Item | Status | Severity | Prod-blocking |
|---|---|---|---|---|
| 1.1 | Email OTP cannot be delivered from Railway (SMTP blocked on current plan) | OPEN | **BLOCKER** | Yes |
| 1.2 | SMS OTP fails: Twilio error 20003 (authentication failed) | OPEN | **BLOCKER** | Yes |
| 1.3 | No working OTP transport at all (consequence of 1.1 + 1.2) | OPEN | **BLOCKER** | Yes |
| 1.4 | OTP plaintext logging | RESOLVED | was HIGH | No |
| 1.5 | Refresh token accepted as a bearer access token | **RESOLVED** | was HIGH | No |
| 1.6 | OTP generated with `random.randint` (not a CSPRNG) | **RESOLVED 2026-10-06** (`secrets.randbelow`) | was MEDIUM | No |
| 1.7 | OTP stored in plaintext in `otps.code` | **RESOLVED 2026-10-06** (keyed HMAC, migration `q2r3s4t5u6v7`) | was MEDIUM | No |
| 1.8 | Rate limiter is in-memory, per process | OPEN | MEDIUM | Single replica only |
| 1.9 | `/auth/refresh` does not re-check the user is active | **RESOLVED** | was LOW | No |
| 1.11 | No server-side refresh-token rotation / revocation | **RESOLVED 2026-10-06** (jti + family, replay revokes lineage, migration `r3s4t5u6v7w8`) | was MEDIUM | No |
| 1.10 | OTP generation / verification / expiry / reuse / refresh | RESOLVED (verified) | — | No |

**1.1 SMTP.** Evidence: Railway documents outbound SMTP as available only on Pro and above; from the
staging container, IPv4 connections to `smtp.gmail.com` on 587 and 465 time out and IPv6 is unreachable
(`Errno 101`). Component: `app/services/otp_service.py::_send_email`. Fix: Option A (recommended) an
HTTPS email API (Resend, SendGrid, Mailgun, Postmark - Railway recommends these), implemented as a
~15-line branch inside `_send_email` gated by an API-key variable, SMTP kept as fallback; needs a
verified sending domain and an API key (owner action). Option B: Railway Pro + SMTP. Decision:
**deferred until Git-based staging is stable; current recommendation Option A.** The error-alert
emails sent by `logger_service` (UNREVIEWED) use the same SMTP transport and have the same limitation.

**1.2 Twilio 20003.** Evidence: staging startup log and the SMS path return "authentication failed".
The credentials copied from the local env file are invalid/expired. Fix: owner supplies valid
credentials (this is a credential *rotation/replacement*, which is DEFERRED - see section 2). India
SMS also requires DLT registration with the carrier; not investigated.

**1.4 OTP logging - RESOLVED.** Evidence: the old `_console_fallback` printed the code and the full
identifier to stdout and the logger when every channel failed. Replaced by `_log_delivery_failure`
(masked identifier, channels tried, error only). Tests: `tests/unit/test_otp_logging.py` (5) and
`tests/integration/test_otp_logging_api.py` (2) fail against the old code (mutation-checked).
Staging after redeploy: deployed logs contain no `DEV OTP`, no OTP value, only failure metadata.

**1.5 Refresh token as access token - RESOLVED.** Found on staging (a refresh token returned HTTP 200 on
`/auth/me`): access tokens had no `type` claim and `get_current_user` never checked one. Fix: access
tokens now carry `type=access`; `get_current_user` accepts only that (tokens without a type claim, refresh
tokens, tampered or foreign-signed tokens and non-UUID subjects are all 401, never 500); `/auth/refresh`
still requires `type=refresh` and rejects access tokens (400). Tests: `tests/integration/test_token_types_api.py`
(17; 11 fail against the old code). Verified on the redeployed staging API and from the real app on an emulator.
Deployment note: tokens issued before this change lack the claim and stop working (one forced re-login;
no production users exist yet).

**1.9 - RESOLVED.** `/auth/refresh` now loads the user and returns 401 for a missing/inactive account, so a
deleted account cannot mint tokens (tested, including after `DELETE /auth/me`).

**1.11 Refresh-token rotation.** There is no `jti` store: refreshing returns a new pair but the old refresh
token stays valid until it expires (30 days), and a stolen refresh token cannot be revoked short of
deactivating the user. A test pins this behaviour so adding rotation is a conscious change. Fix: store a
token family/`jti`, rotate on use, reject reuse, revoke on logout/password change.

**1.6/1.7.** `app/routers/auth.py` uses `random.randint(100000, 999999)`; use `secrets`. The code is
compared by equality against `otps.code`; store a hash (HMAC with a server key) instead.

**1.8.** Per-identifier OTP limits (5 sends/hour, 10 verifies/15 min) live in process memory, so they
reset on restart and do not work across replicas. Staging/production must stay at one replica until a
shared store (Redis) is added.

**1.10 Verified behaviour** (automated tests with real PostgreSQL + staging e2e): 6-digit code, 10-minute
TTL, wrong code -> 400, expired -> 400, reuse -> 400, code for another identifier rejected, token
refresh works, delivery failure on login -> 503 with no code in the response.

---

## 2. Security

Format per item: **Status - Severity - Evidence - Component - Recommended fix - Production-blocking - Current decision.**

### Credentials (all rotation intentionally DEFERRED; values never recorded)

| Item | Status | Severity | Evidence (non-secret) | Component | Recommended fix | Prod-blocking | Decision |
|---|---|---|---|---|---|---|---|
| Exposed credentials in Git history | DEFERRED | HIGH | Early commits of the backend repo contained a committed env file with an Anthropic key and the placeholder `SECRET_KEY`, a Twilio account SID in `config.py`/logs, and logs with personal data. The repo was public for ≥6 months before being made private. | Git history | Rotate everything first (rotation is the real fix), then rewrite history or abandon it; add the project gitleaks rules to CI | **Yes** (see below) | Deferred by owner |
| `SECRET_KEY` | DEFERRED | HIGH | The value in the committed env file was the public placeholder. Staging uses its own freshly generated key. | `app/config.py` | New random key (`secrets.token_urlsafe(48)`), invalidates all sessions | **Yes**: `ENVIRONMENT=production` startup *refuses* the placeholder | Deferred |
| `ADMIN_TOKEN` | DEFERRED | HIGH | Local value is a `...CHANGEME` placeholder. Staging uses its own value. | `app/routers/admin_errors.py` | New random value | **Yes**: production startup refuses the placeholder | Deferred |
| Anthropic API key | DEFERRED | HIGH | Present in public Git history (identical to the live key at the time) | `ai_service` | Revoke + reissue; review usage since 2026-03-20 | Yes | Deferred |
| Twilio credentials | DEFERRED | MEDIUM | Account SID in public history; auth token only on disk/transcripts; currently invalid (1.2) | `otp_service` | Rotate/replace token; consider restricted API key | Yes (OTP) | Deferred |
| SMTP (Gmail app password) | DEFERRED | MEDIUM | On disk/transcripts only | `otp_service`, `logger_service` | Revoke; superseded by 1.1 decision | Yes (OTP) | Deferred |
| Google Safe Browsing key | DEFERRED | MEDIUM | On disk/transcripts only | `gsb_service` | Regenerate + API/IP restrictions | No | Deferred |
| Azure Translator key | DEFERRED | MEDIUM | A shell environment variable was echoed once into an assistant transcript | developer machine | Regenerate | No | Deferred |
| Azure PostgreSQL credentials | DEFERRED | LOW | Server no longer exists; stale copies remain in local env files | local files | Delete the stale env files after the rotation phase | No | Deferred |
| Local Postgres `postgres` password | DEFERRED | MEDIUM | Historical variant hard-coded in 4 files in Git history; same string as the old Azure password | local DB | Change | No | Deferred |

Local leftovers to clean after rotation: stale env backups, temp files holding live values, and
~8 assistant session transcripts under the user profile.

### Error-log exposure

| Item | Status | Severity | Evidence | Component | Fix | Prod-blocking |
|---|---|---|---|---|---|---|
| JWT / Cookie / admin-token header capture | **RESOLVED** | was HIGH | Old code stored `dict(request.headers)` on every 500. Now an explicit allowlist (`_safe_headers`). 8 tests inspect the real `error_logs` row and alert e-mail; mutation-checked. Staging: 14 rows scanned, 0 credential matches. | `error_handler.py` | done | No |
| Request-body capture | **NOT PRESENT** in candidate | — | No `request.body/json/form` read anywhere in the candidate; a test asserts a body marker never reaches the row or e-mail. (The excluded v2 handler *does* capture up to 8 KB of body - it must not ship without review.) | `error_handler.py` | keep v2 excluded | No |
| Query-string values | **RESOLVED** (this cycle) | was MEDIUM | `extra.query` stored `str(request.query_params)` (e.g. `check-user?identifier=<email/phone>`). Now only parameter *names* are stored (`query_params`). Test + staging verified. | `error_handler.py` | done | No |
| Path parameters / share tokens | **RESOLVED** (this cycle) | was MEDIUM | `endpoint` stored the concrete path, so a 404/500 on `/recordings/share/{token}` stored the share token; `/scam-calls/block/{number}` stored a phone number. Now the matched route *template* is stored. A real-route test failed before the fix. | `error_handler.py` | done | No |
| Bound SQL parameters in DB error text | **RESOLVED** (this cycle) | was MEDIUM | SQLAlchemy appends `[parameters: (...)]` to DB errors (would include a submitted OTP, email, phone) into messages, tracebacks, `error_logs` and e-mails. Engine now created with `hide_parameters=True` (unit-tested, mutation-checked). | `app/database.py` | done | No |
| Exception text, tracebacks and context (driver DETAIL lines, pydantic input echoes, URLs with API keys, tokens) | **RESOLVED** (heuristic scrubber; residual risk noted) | was MEDIUM | Measured with real exceptions through the real `log_error`: a unique-violation DETAIL line stored the user's e-mail, a pydantic error echoed its input, an httpx status error embedded the request URL including the API key. `app/services/log_scrubber.py` now scrubs message, traceback and `extra` once in `log_error` (before the file log, the DB row and the alert e-mail): JWTs, Bearer/Basic values, `key=`/`token=`/`password=`/`otp=` pairs, known API-key shapes, URL passwords, driver `Key (col)=(value)`, pydantic `input_value`, e-mails (masked), phone numbers (masked), OTP-like numbers; output is length-bounded and the regexes are linear-time (ReDoS-tested; worst case 49 ms on adversarial input). 24 unit + 8 integration tests (real PostgreSQL rows and alert e-mail payloads). | `logger_service.log_error` (committed version) + new `log_scrubber.py` | Residual: heuristic matching cannot catch every value (a bare name or free text inside an exception); `error_logs` must still be treated as sensitive. | No |
| Which sensitive items *can* appear in `error_logs` today | — | — | **Email/phone**: possibly via driver `DETAIL` or pydantic exception text. **OTP**: no longer via parameters or logs; only if embedded in a driver message. **JWT/access/refresh token**: not captured (headers allowlisted, bodies not read). **Share token**: no (route template). **Password**: no passwords exist in the auth flow. **API credentials**: only if an exception message embeds one (e.g. a provider error echoing a key) - unverified. | | | | |
| `error_logs` retention | **OPEN** (account erasure now anonymises `user_id`; no age/size policy beyond the 90-day startup purge) | MEDIUM | Startup cleanup deletes rows older than `LOG_RETENTION_DAYS` (default 90); no policy for personal data, no export/erasure path; account deletion does not purge `error_logs.user_id` rows | `main.py`, models | Define retention (e.g. 30 days), purge on account deletion | No | Decision needed |
| Admin endpoint compares token with `!=` | OPEN | LOW | `admin_errors._check_admin` is not constant-time; no throttling beyond the global limiter | `admin_errors.py` | `hmac.compare_digest` + tighter rate limit | No | — |
| Pre-existing logging side effects (UNREVIEWED) | UNREVIEWED | ? | `logger_service` (working tree) adds SQLAlchemy event listeners, e-mail dedupe and hard-coded personal e-mail addresses; `error_handler` v2 adds body capture and unverified JWT decoding for `user_id` | | Review before any inclusion | Yes, if included | Excluded |

### Other security observations

| Item | Status | Severity | Note |
|---|---|---|---|
| `/ready` returns database and user names | OPEN | LOW | Minor information disclosure on a public URL |
| Staging smoke data | **RESOLVED** | was MEDIUM | Inventoried read-only, then removed (section 14). Staging currently holds no users, no admin, no uploaded files. |
| Local credential file uploaded to Railway (incident, FG-036) | OPEN (mitigated) | LOW-MEDIUM | During the 2026-10-05 candidate deploy a `ci_env.sh` helper containing the **local test-database URL (localhost, `postgres` role)** was in the uploaded source folder. It was never in the image (the Dockerfile copies only `app/`, `alembic/`, `alembic.ini`, `requirements.txt`). A clean redeploy replaced the live deployment. **Pre-push gate evidence:** a scan of the live container found no `ci_env*` or `.env*` file anywhere on the image and no credential shapes under `/app`; the two scratch copies of the helper were securely removed; `.gitignore` and `.dockerignore` now exclude `ci_env*`, `*_env.sh`, key/certificate material, `.env*` (any depth in `.dockerignore`), shell scripts, SQL, logs and dumps (commit `chore(security): block credential-bearing files...`); a Docker-semantics simulation of the build context contains no forbidden file. **Not done / unknown:** Railway keeps the earlier source archive (and deployment history) in the private project; there is no evidence it has been purged, so it must be treated as still existing. Fix still recommended: change the local `postgres` password (credential rotation is DEFERRED) and always deploy from a `git archive` export. |
| Staging API is public | OPEN | LOW | `secureshield-api-production-73ea.up.railway.app` (environment is named `production` inside the staging project; confusing, not an actual production environment) |
| Account deletion was PARTIAL but claimed full deletion | **RESOLVED** | was HIGH (privacy) | `DELETE /auth/me` now erases every user-linked table and the uploaded files, anonymises `error_logs`, and keeps only an inert tombstone plus the append-only warrior audit trail; the response states what is retained. 7 integration tests (all tables, physical files, share tokens, OTPs, devices, family links, bystander isolation, repeat deletion, post-deletion access, path-traversal guard, atomic rollback) and a live staging run (files on the volume 1+1 -> 0+0). See section 15. |
| Elderly guardian alert logs guardian PII and delivers nothing | OPEN | MEDIUM | `elderly_protection.py` `_deliver_guardian_alert` is a TODO stub: it writes the guardian's full phone/e-mail and 120 characters of the alert to the INFO log and sends nothing. Fix: implement delivery through the chosen OTP/e-mail/SMS transports, log only masked identifiers. |
| Hard-coded personal e-mail in alert path | UNREVIEWED | LOW | Appears in unreviewed `logger_service`/`error_handler` v2 |

---

## 3. Database

| Item | Status | Evidence |
|---|---|---|
| Railway PostgreSQL | IMPLEMENTED | PostgreSQL 18.6, UTF8, `en_US.utf8`; private network only (public TCP proxy was temporary and deleted) |
| Alembic head | RESOLVED | `l7m8n9o0p1q2`; single linear chain of 14 revisions; run as Railway pre-deploy step |
| Tables | IMPLEMENTED | **29** (27 ORM tables + `alembic_version` + legacy `otp_vault_entries`) |
| Enums / indexes / FKs / PKs / sequences / JSONB | verified | **11 / 76 / 22 / 29 / 3 / 15** |
| Least-privilege app role | IMPLEMENTED | `secureshield_app`: SELECT/INSERT/UPDATE/DELETE on all 29 tables, no schema CREATE, not superuser; used by the API (`/ready` runs as this role) |
| Migrator role | IMPLEMENTED | `secureshield_migrator` owns schema `public` and all tables; used only by Alembic and the seed script |
| Role creation is not in the repo | OPEN, MEDIUM | Roles and default privileges were created by hand on the Railway superuser; documented in `docs/RAILWAY_DEPLOYMENT.md` but not scripted | Recommendation: add an idempotent SQL bootstrap script |
| `otp_vault_entries` | LOW | Orphan table with no ORM model (the OTP Vault feature was removed from the app; the initial migration still creates it). Drop in a future migration. |
| Data migration from Azure | N/A | The Azure server no longer exists; Railway is a fresh database; no data was migrated |
| Reference-data seed | **RESOLVED on staging** | 11 / 22 / 23,192 rows loaded 2026-10-05; see section 4 |
| Backups | **NOT IMPLEMENTED**, HIGH | No backup/restore policy or test has been defined for Railway Postgres. Production-blocking until defined. |

---

## 4. Reference data

| Item | Status | Evidence |
|---|---|---|
| TSP codes (11) and LSA codes (22) | IMPLEMENTED in script | Embedded in `scripts/seed_sms_registry.py`, taken from `Detail_Header_Prefixes_16062020_0.pdf`; names match the PDF text (one spelling difference only) |
| SMS sender headers | IMPLEMENTED in script | Source `List_SMS_Headers_16062020_0.xlsx` (repo parent folder): **23,192** usable rows, 23,190 distinct headers (2 duplicates are allowed: the index is non-unique), max header length 9 |
| Seed script | RESOLVED | Uses the migrator URL (TRUNCATE needs ownership); `--dry-run`; `--xlsx`; refuses to run on populated tables unless `--replace`; translates `ssl`->`sslmode` for psycopg2. Needs `pip install -r requirements-seed.txt` |
| Dry run | RESOLVED | `DRY RUN: would seed 11 TSP codes, 22 LSA codes, 23,192 SMS headers. No database contact.` |
| Safety guard | RESOLVED (verified on a scratch DB) | seed -> 11/22/23192; second run aborts with exit 2 and leaves data untouched; `--replace` is the only wiping path |
| **Railway staging seed status** | **SEEDED** | Before: 0 / 0 / 0 (SELECT-only). Dry run: 11 / 22 / 23,192. After: `tsp_codes=11`, `lsa_codes=22`, `sms_sender_registry=23,192` (23,190 distinct headers = the 2 duplicates in the source file). Integrity: no duplicate TSP/LSA codes, no null/empty rows, unique primary keys, no FK constraints on these tables. Idempotency: a second run aborted (`exit 2`, tables already populated) and changed nothing. Executed through a temporary Railway TCP proxy (now deleted) with the migrator role; credentials were taken from the service variables inside the shell and never printed or written to the repository. |
| Impact | RESOLVED | Sender-header validation has its registry on staging |

**Exact command (not executed).** Needs a temporary Railway TCP proxy on the `Postgres` service (the
private network is unreachable from a laptop; delete the proxy afterwards):

```
pip install -r requirements-seed.txt
railway run -s secureshield-api -- sh -c 'MIGRATOR_DATABASE_URL="postgresql://secureshield_migrator:${MIGRATOR_DB_PASSWORD}@<proxy-host>:<proxy-port>/railway" python scripts/seed_sms_registry.py'
```

The password is expanded inside the shell and never printed. Never use `--replace` on a populated database.

---

## 5. Admin / RBAC (read-only audit, 2026-10-05)

**Target verified:** database `railway`, user `secureshield_app`, project `secureshield-staging`,
service `secureshield-api`, session forced read-only (a write attempt raised
`ReadOnlySQLTransactionError`). Only SELECT queries were run.

**Inventory:** users 2 (active 2, inactive 0) at audit start; warrior profiles 1; applications 1 (rejected);
audit log rows 2 (`application_submitted`, `application_rejected`).

**Admin existence (at audit time, before cleanup): one active admin EXISTED in Railway staging** (masked: email `s***@example.com`,
user `9eef…e2`, profile `db88…ce`, role `admin`, created 2026-10-05 06:48 UTC, last activity same day).
It is **not** a real person: it is the throw-away "Smoke Admin" the assistant inserted by direct SQL
during the earlier smoke test to exercise the admin routes. Consequences: (a) the statement "no admin
exists" is false; (b) `python -m app.cli.bootstrap_admin` would correctly **refuse** to run (one-admin
rule); (c) its mailbox is not reachable, so nobody can log in as it, but it is a privileged row on a
public staging API. Recommendation: before any real use, the owner decides whether to remove the smoke
admin (and smoke users/files) so the bootstrap can create the real first admin. It has since been removed together with all smoke data (section 14). **Current state: no admin user exists in Railway staging.** The bootstrap CLI is therefore usable; the real first admin has not been created (awaiting approval).

### RBAC implementation (read from code, not inferred)

| Aspect | Fact |
|---|---|
| Identity | JWT bearer (`HS256`, `SECRET_KEY`); `sub` = user UUID. `auth.get_current_user` decodes it, loads the `User`, requires `is_active`. |
| Role model | Table `warrior_profiles.role` (enum `WarriorRole`): `trainee < verified_warrior < mentor < moderator < admin`. Ordering in `_ROLE_ORDER`; `role_meets(current, required)`. A user has at most one profile (unique `user_id`). |
| Active/inactive | `WarriorProfile.is_active`; `User.is_active`. Missing or inactive profile -> the same 403 (no distinction revealed). |
| Admin dependency | `require_warrior_role(WarriorRole.admin)` (builds a FastAPI dependency on top of `get_current_user`). |
| `ADMIN_TOKEN` | **Endpoint-specific shared secret** for the `/api/v1/admin/errors*` routes only (header `X-Admin-Token`, compared with `!=`). Empty -> those routes return 503. **Also a startup check**: with `ENVIRONMENT=production`, the placeholder value stops the app from booting. It is *not* connected to the warrior RBAC and grants no user-level access. |
| DB role vs app role | Unrelated concepts: PostgreSQL roles (`secureshield_app` runtime, `secureshield_migrator` DDL) vs application roles (`WarriorRole`). |

### Admin-capable endpoints (complete; staged candidate = 87 routes)

| Method | Path | Purpose | Authentication | Authorization | DB action | Sensitive data |
|---|---|---|---|---|---|---|
| GET | `/api/v1/admin/errors` | List error logs (filters) | `X-Admin-Token` | token equality | read | error messages/IPs/user IDs |
| GET | `/api/v1/admin/errors/{id}` | One error incl. traceback/extra | `X-Admin-Token` | token equality | read | tracebacks, `extra` JSON |
| GET | `/api/v1/admin/errors/stats/summary` | Counts | `X-Admin-Token` | token equality | read | none |
| GET | `/api/v1/warriors/admin/applications` | List warrior applications | JWT | role >= `admin` | read | applicant PII (name, DOB, phone, email, motivation) |
| POST | `/api/v1/warriors/admin/applications/{id}/approve` | Approve + create profile (may assign any role incl. `admin`) | JWT | role >= `admin` | insert profile, update application, insert audit | PII |
| POST | `/api/v1/warriors/admin/applications/{id}/reject` | Reject (notes required) | JWT | role >= `admin` | update application, insert audit | PII |
| GET | `/api/v1/warriors/me` | Own warrior profile | JWT | role >= `trainee` | read | own data |

No other route requires an admin. Working-tree-only routes (UNREVIEWED, not in the candidate):
`GET /link-scanner/providers/status`, `GET /community-scams/news-feed`, `POST /video-call/generate-fir-stream`,
`PATCH /emergency-contacts/{id}`.

### Capability matrix

| Capability | Status |
|---|---|
| List / view / search users | **NOT IMPLEMENTED** |
| Deactivate / reactivate / delete a user (as admin) | **NOT IMPLEMENTED** (only self-deletion: `DELETE /auth/me`) |
| Reset credentials / inspect authentication / inspect OTP activity | **NOT IMPLEMENTED** |
| Promote / demote / manage warrior roles after approval | **NOT IMPLEMENTED** (the `role_promoted/demoted`, `profile_suspended/reactivated` audit actions exist in the enum but no endpoint writes them; approval can assign any role) |
| Cyber Warrior applications: list / approve / reject | IMPLEMENTED (tested) |
| Cyber Warrior profiles: view/suspend/reactivate/list | PARTIAL (own profile only; no admin list/suspend/reactivate) |
| Audit log viewing | **NOT IMPLEMENTED** (rows are written, no read endpoint) |
| Error log access | IMPLEMENTED (token-protected API) |
| Authentication-failure / security-event views | **NOT IMPLEMENTED** |
| Evidence / recordings: admin access | **NOT IMPLEMENTED** (owner-only; share links are the only non-owner path) |
| System configuration, OTP/SMS/e-mail admin, threat-intel admin, AI admin, notifications, dashboards, statistics | **NOT IMPLEMENTED** (`GET /link-scanner/providers/status` exists only in unreviewed working-tree code) |
| First-admin bootstrap | IMPLEMENTED (CLI only), see below |

### Bootstrap CLI (`python -m app.cli.bootstrap_admin`) - NOT executed

Present in the redeployed staging image (`--help` verified; no database access, nothing created).
Prerequisites: the person is already registered (OTP-verified) and active; adult date of birth; no admin
profile exists (active or not); dry-run by default; applying requires `--confirm <same email>`;
serialised by a Postgres advisory lock; writes a `role_promoted` audit row (`method: cli_bootstrap`);
prints only a masked email; no HTTP endpoint exists. Exact commands (placeholders only):

```
railway ssh -s secureshield-api -- python -m app.cli.bootstrap_admin --email <EMAIL> --date-of-birth <YYYY-MM-DD>
railway ssh -s secureshield-api -- python -m app.cli.bootstrap_admin --email <EMAIL> --date-of-birth <YYYY-MM-DD> --confirm <EMAIL>
```

Rollback implications: the audit row is append-only and the profile can only be removed by SQL
(`DELETE` on `warrior_profiles`; leave the audit row). It will now accept a registered user because no admin exists. **Awaiting explicit approval; no admin is created automatically.**

---

## 6. Admin UI

| Item | Answer |
|---|---|
| Backend admin API | **YES** (7 routes above) |
| Flutter admin UI | **NO** - no admin or Cyber Warrior code exists in `flutter_app/lib` |
| Web admin UI | **NO** - no web project exists in either repository |
| Admin dashboard | **NO** |
| Admin authentication flow | **PARTIAL** - JWT + warrior role for warrior admin; shared-secret header for error logs; no login UI |

Missing dashboard functionality: user management, warrior management, application review UI, error
viewer, audit viewer, statistics, content moderation. Today an admin must use `curl`/HTTP clients.

---

## 7. Evidence / Recordings

| Feature | Status | Tested |
|---|---|---|
| Evidence upload / list / get / delete (owner only) | IMPLEMENTED | automated + staging e2e |
| Evidence download | **NOT IMPLEMENTED** (no download route; files are stored but only metadata is served) | n/a |
| Recording upload / list / delete | IMPLEMENTED | automated + staging e2e |
| Recording share link (`POST .../share-link`) and public download (`GET /recordings/share/{token}`) | IMPLEMENTED (token is the only credential; unauthenticated by design; expiry stored) | automated + staging e2e |
| Persistence | RESOLVED | Railway volume `/app/uploads` (separate 4.6 GB device); files survived two redeploys with identical checksums |
| Admin access to evidence/recordings | **NOT IMPLEMENTED** | - |
| File validation (type/size limits, virus scan) | not assessed - treat as MEDIUM until reviewed | - |
| Single-replica constraint | LOW/known | Local-disk uploads on a single volume; cannot scale horizontally |

---

## 8. Cyber Warriors

| Feature | Status | Tested |
|---|---|---|
| Apply (adult, 3 consents, motivation length) | IMPLEMENTED | automated + staging |
| View own application | IMPLEMENTED | automated + staging |
| Admin approve / reject | IMPLEMENTED | automated + staging (reject) |
| Profile (`GET /warriors/me`) and role tiers | IMPLEMENTED (RBAC enforced) | automated |
| Audit trail | PARTIAL: written for submit/approve/reject; no read endpoint; promotion/suspension actions have no writers | automated |
| Admin management of profiles (list, suspend, promote) | NOT IMPLEMENTED | - |
| Account deletion erases warrior rows | IMPLEMENTED (but overall account deletion is PARTIAL, section 2) | automated |
| Client app (Flutter) | **NOT IMPLEMENTED** | - |

---

## 9. Error management

| Item | Status |
|---|---|
| `error_logs` table + admin read API | IMPLEMENTED |
| Alert e-mails | IMPLEMENTED but **non-functional on Railway** (SMTP blocked, 1.1); body contains message, endpoint, type, traceback (no headers) |
| JWT / Cookie / admin-token protection | RESOLVED |
| Query-string exposure | RESOLVED (names only) |
| Path-parameter / share-token exposure | RESOLVED (route template) |
| Bound SQL parameter exposure | RESOLVED (`hide_parameters`) |
| Traceback / exception-text exposure | OPEN (section 2) |
| Retention | OPEN (section 2) |
| Validation errors | RESOLVED: 422 (not 500) for custom validators; raw `input` stripped from logs |
| `Retry-After` / `WWW-Authenticate` preserved on error responses | RESOLVED |

---

## 10. Threat intelligence / AI (code inspected, NOT modified)

The 87 candidate routes use the **committed** versions of these modules; changes in the working tree
are UNREVIEWED.

| Capability | Backend | Status |
|---|---|---|
| Link scanning (`/link-scanner/scan`, `/history`) with Google Safe Browsing | `gsb_service` (HEAD) | IMPLEMENTED (needs a valid API key; key rotation deferred); working-tree version adds caching/provider status: UNREVIEWED |
| URLHaus lookups | `urlhaus_service` | UNREVIEWED (untracked; sends scanned URLs to a third party) |
| Provider status admin endpoint | `link_scanner` (working tree) | UNREVIEWED |
| AI coach chat, complaint e-mail, message/job-offer analysis, app-threat explanation, security tips | `ai_service` (Anthropic, models `claude-sonnet-4-6` / `claude-haiku-4-5`) | IMPLEMENTED (HEAD); extended version UNREVIEWED; depends on the Anthropic key |
| FIR draft + streaming | `video_call`, `ai_service` | PARTIAL (non-streaming IMPLEMENTED at HEAD; streaming UNREVIEWED) |
| Community scam reports/feed/trending/upvote | `community_scam` | IMPLEMENTED (HEAD); news-feed UNREVIEWED |
| Emergency contacts (list/create/delete) | `emergency_contacts` | IMPLEMENTED (HEAD); PATCH update UNREVIEWED (authorization to be reviewed) |
| SMS sender-header validation | `sms_header_validator` + registry tables | PARTIAL: code exists, registry **empty** on staging (section 4) |
| Risk engine / threat analyzer / clone analyzer | `risk_engine`, `threat_analyzer`, `clone_analyzer` | IMPLEMENTED (untested here) |
| Automated tests for any of the above | none in this repo | NOT IMPLEMENTED |

---

## 11. Flutter

| Item | Status | Evidence |
|---|---|---|
| Staging endpoint | READY | `https://secureshield-api-production-73ea.up.railway.app/api/v1` via Settings -> Server URL (see `flutter_app/STAGING_API.md`); production endpoint untouched (there is none: the client defaults to LAN/emulator hosts) |
| HTTPS probe fix | RESOLVED | `AppConfig._isReachable` always probed `http://`, dropping a pinned `https://` URL on restart. One-line fix uses `uri.scheme`; verified against the live staging URL with the real Dart VM (old logic false, new logic true; dead LAN URL still false). The probe's 1-second timeout may be tight for TLS on slow mobile networks. |
| Flutter SDK corruption | RESOLVED | The Dart SDK folder was incomplete (`snapshots/`, `resources/devtools` missing). Renamed to `dart-sdk.broken`, stamp renamed, SDK re-downloaded (Dart 3.11.0). Old copies remain on disk (`dart-sdk.broken`, `dart-sdk.old1`, `engine-dart-sdk.stamp.bak`); delete after you are satisfied. Cause of the original damage is unknown (interrupted update or antivirus). |
| `flutter pub get` | PASS | `pubspec.lock` was already modified before this work |
| `flutter analyze` | **639 issues, 0 errors**, 21 warnings, 618 infos (469 `deprecated_member_use` - mostly `withOpacity`; 97 `prefer_const_constructors`) | exit code 1 because infos count |
| `flutter test` | PASS: **19/19** (similarity metrics suite ran for the first time; `widget_test.dart` is a placeholder) | |
| Emulator verification (Pixel_5 AVD, debug APK built from the working tree) | **PARTIAL - done** | Against the staging API, from the real app: cold start with the HTTPS override logs `Using manual override: https://...` (the probe fix works on device); **registration** (`POST /auth/register` 200); **OTP verification and login** (`POST /auth/verify-otp` 200; the OTP was read from the DB because delivery is blocked, then typed into the app); authenticated screens; **My Profile** (`GET /auth/me` 200, real user data shown); **logout** (returns to the logged-out home). Not exercised on the device: the token-refresh path (needs an expired access token), evidence/recording upload (camera/file picker), Cyber Warrior (no client), account deletion (no UI path assessed). Evidence, recordings, refresh and refresh-token rejection were verified over HTTP against the same staging API (34/34 checks). |
| Client coverage of backend features | Cyber Warriors, admin: no client. Auth/profile/evidence/recordings/scanners: modules exist, not exercised against staging from the app. The backend flows the app uses were verified over HTTP. | |
| Cleartext/TLS config | not reviewed | LOW |

---

## 12. Deployment

| Item | Status | Detail |
|---|---|---|
| Railway API | RUNNING | CLI-uploaded deployment of the staged candidate (87 routes); `/health` 200 |
| Railway PostgreSQL | RUNNING | private network; roles as in section 3 |
| Volume | RESOLVED | `secureshield-api-volume` -> `/app/uploads`; persistence verified twice |
| Healthcheck | `/health` (60 s) | |
| Readiness | `/ready` 200: executes `SELECT current_database(), current_user` as the app role | not wired as a Railway check (Railway supports one path) |
| Pre-deploy migration | `alembic upgrade head` (no-op at head) | failure blocks the deploy |
| Git deployment | **NOT CONNECTED** | Branch `staging/railway-snapshot` is local only; nothing pushed; Railway service has no Git source. Target: repo `ravishori/SecureShield-Backend` (private), root `/`, Dockerfile, `railway.toml` |
| `railway.toml` deprecation | OPEN, LOW | Railway's config-as-code is deprecated; keeps working until 2026-12-01. Migration: `railway config migrate --service secureshield-api` (dry-run), `railway config plan`, then `--apply`. `restartPolicy*` is not carried over. Deferred until Git deployment exists. |
| CI | **NOT RUN ON GITHUB** (reproduced locally with the workflow's own environment block: ruff, `alembic upgrade head`, pytest 300 passed) | Workflow reproduced locally with the CI environment: ruff, `alembic upgrade head`, pytest. Do not claim it passes until it runs on GitHub. |
| Production env requirements | NOTE | `ENVIRONMENT=production` requires `TRUST_PROXY_TLS=true`, non-placeholder `SECRET_KEY` and `ADMIN_TOKEN`, and an explicit `CORS_ALLOWED_ORIGINS`, otherwise startup fails (by design). Staging runs `ENVIRONMENT=staging`. |
| Environment naming | LOW | Railway's default environment inside `secureshield-staging` is called `production` |
| Single replica | known | in-memory rate limiter, local-disk uploads |
| Backups / disaster recovery | **NOT IMPLEMENTED** | see section 3 |
| Secret scanning in CI | IMPLEMENTED (current tree) / history scan PENDING | The workflow runs a pinned, checksum-verified gitleaks 8.21.2 with `--no-git` and the project rules in `.gitleaks.toml` (default rules miss Anthropic keys; custom rules added, canary-tested; an SMTP rule bug that read the next line as a value was fixed). The allowlist is exact-value only (deliberate fake fixtures and the `YOUR_*` placeholder convention): there is NO path allowlist, so a real secret anywhere (`app/`, `scripts/`, `tests/`, `.github/`, Docker/Railway files, docs) is reported; verified with 5 secret types x 10 locations. History is not scanned in CI because it still contains secrets committed before rotation (FG-020). Not yet run on GitHub. |

---

## 13. Production readiness

| Area | Status | Production blocker | Resolution |
|---|---|---|---|
| OTP delivery (e-mail) | BLOCKED | **Yes** | HTTPS e-mail provider (Option A) or Railway Pro (Option B) |
| OTP delivery (SMS) | BLOCKED | **Yes** | Valid Twilio credentials (+ DLT registration for India) |
| Credential rotation / Git-history secrets | DEFERRED | **Yes** (production refuses placeholder `SECRET_KEY`/`ADMIN_TOKEN`; exposed keys must be rotated) | Rotation phase, then history decision |
| Refresh token usable as access token | RESOLVED | No | `type` claim enforced; tests + staging + device |
| First admin | OPEN | **Yes** (nobody can administer warriors) | Smoke admin removed; run the bootstrap CLI after approval |
| Reference data on target DB | RESOLVED on staging | No | Repeat on any new database (section 4) |
| Backups / DR | NOT IMPLEMENTED | **Yes** | Define + test restore |
| Git-based deployment + CI on GitHub | NOT DONE | Yes (reproducible deploys) | Push after approval, connect Railway, run CI |
| Error-log exception text | RESOLVED (heuristic) | No | `log_scrubber` |
| `error_logs` retention policy | OPEN | No | Decide retention + purge |
| Account deletion completeness | RESOLVED | No | Section 15 |
| Staging smoke data | RESOLVED | No | Section 14 |
| Refresh-token rotation / revocation | OPEN | No (recommended) | `jti` store |
| Unreviewed code (11 files + v2 pieces) | UNREVIEWED | Only if included | Review per group |
| Admin tooling / UI | NOT IMPLEMENTED | No (API only) | Build admin UI later |
| Flutter on device | UNVERIFIED | Yes for release | Run on device against staging |
| Automated tests for scanners/AI/threat intel | NOT IMPLEMENTED | No | Add |
| Header/query/param/path/exception-text leakage in error logs | RESOLVED | No | - |
| OTP logging | RESOLVED | No | - |
| Database, volume, healthchecks, migrations | RESOLVED | No | - |

**Current production readiness: RED.**

---

## 14. Staging smoke-test cleanup record (2026-10-05)

**Method.** Read-only inventory first (session forced read-only, SELECT only), captured, then a guarded
deletion inside one transaction through the runtime role. Guards: abort unless every user is a recognised
test identity (e-mail pattern `smoke-*@example.com`, `e2e-user-*@example.com`, `device-test-*@example.com`, or an
inert deletion tombstone), abort unless every evidence/recording row and every file belongs to those
identities, abort on any file path outside `/app/uploads`.

**Inventory before the first cleanup** (all of it belonged to the three smoke/e2e identities):

| Item | Count |
|---|---|
| users (all matched the smoke patterns; none other existed) | 3 |
| warrior profiles (1 was the **assistant-created smoke admin**) | 1 |
| warrior applications / audit-log rows | 2 / 3 |
| evidence rows + files, recording rows + files (2 recordings had share tokens) | 2 + 2, 2 + 2 |
| OTP rows | 4 |
| devices, family, emergency contacts, alerts, scans | 0 |
| files on the volume | 4 (all referenced by those rows; no orphans, none belonging to other data) |
| `error_logs` rows | 14 (tied to no user; verified free of credentials) |

**Removed:** exactly those rows and the 4 files (counts equal to the inventory). `error_logs` was left in place
(diagnostics, no personal data).

**Verified afterwards:** 0 users, 0 warrior profiles/applications/audit rows, 0 admins, 0 evidence/recordings,
0 OTPs, 0 files on the volume; tables and the volume themselves untouched. No replacement admin was created.

**Second cleanup (end of the same cycle).** The final end-to-end run, the emulator test and the live
account-deletion test created more throw-away data (one emulator user + its device row and OTP, one e2e user
turned into a deletion tombstone with one audit row). They were removed with the same guarded procedure
(extended to device-linked tables). Final state: **0 users, 0 admins, 0 uploaded files**, reference data intact
(11 / 22 / 23,192), `error_logs` 29 rows retained.

## 15. Account deletion and retention policy (`DELETE /auth/me`)

Implemented in `app/services/account_erasure.py`; the endpoint requires `{"confirm": "DELETE"}`.

| Data | Action | Why |
|---|---|---|
| User profile fields (e-mail, phone, alt phone, names, address, password hash) | **cleared** | identity removal |
| `users` row | **kept as an inert tombstone** (`id`, `created_at`; `is_active=false`; all personal columns NULL) | the append-only audit trail references it by foreign key; e-mail/phone are NULL so the person can register again as a new account |
| Evidence and recordings (rows, share tokens, **uploaded files**) | **deleted** (files removed after the DB commit; only inside the configured upload directories) | user content; a share link dies with the row |
| OTP rows for the user's e-mail/phone | **deleted** | credentials/identifiers |
| Devices and everything on them (alerts, network activity, app scans, Wi-Fi scans) | **deleted** | device data |
| AI conversations, link scans, scam calls, security reports, behaviour events, clone reports, app-install events, community scam reports | **deleted** | user activity |
| Emergency contacts, elderly/guardian configuration, family members | **deleted** | third-party personal data entered by the user; other users' family entries that pointed at this account are **unlinked, not deleted** |
| Cyber Warrior profile and application | **deleted** | volunteer PII (name, DOB, phone, e-mail, motivation) |
| `error_logs` | **anonymised** (`user_id` -> NULL), rows kept | diagnostics without the link to a person |
| `warrior_audit_logs` | **retained** (append-only moderation/security trail: ids, action, timestamps, structured context, reviewer's free-text reason) | accountability; reviewers must not put personal details in notes |
| Legacy `otp_vault_entries` | **deleted** | removed feature |

Properties: one transaction (a failure rolls everything back and the account stays active - tested); files
are removed only after a successful commit and a failure to remove a file is logged as an error; repeated
deletion, any API call and `/auth/refresh` with previously issued tokens all return 401 afterwards. The
response (`message` + `retained`) no longer claims "permanent" deletion. Open policy decisions for the
owner: audit-log retention period, whether reviewer notes need scrubbing, backup retention of deleted data
(no backups exist yet, see FG-052).

## 16. Review of the unreviewed backend files (decisions)

None of these was committed. Decision vocabulary: COMMIT (ready), FIX-THEN-COMMIT, DEFER (needs tests/review),
DO NOT COMMIT. "Needed for staging" means needed for the validated staging scope.

| File | Purpose | Production relevance | Security risks found | Data/privacy | Tested | Needed for staging | Decision |
|---|---|---|---|---|---|---|---|
| `services/logger_service.py` (+374/-119) | Error logging v2: DB + file + e-mail with dedupe/rate limit, process-wide `sys.excepthook`/asyncio handlers, SQLAlchemy event listeners writing slow/failed SQL to `secureshield.sql.log`, `safe_background` | High (alerting) | Global hooks change process behaviour; SQL text (<=500 chars, no bound values) goes to a second on-disk log; alert e-mails use SMTP (blocked on Railway); personal address appears in a docstring (recipient itself comes from `ERROR_NOTIFY_EMAIL`). The committed version gets the same `log_scrubber` hook (committed), so exception text is scrubbed in both. | scrubbed by `log_scrubber`; SQL log needs review | scrubber only; hooks untested | No (committed version suffices) | **DEFER** - review hooks, add tests, then commit |
| `services/gsb_service.py` (+218/-49) | Google Safe Browsing client with 5-min in-memory cache, error classification, startup key verification | Medium | API key is sent as `?key=` in the URL (visible in any httpx error text; the committed scrubber now masks it; prefer the header form); scanned URLs (possibly with tokens) are sent to Google and cached in memory | URL egress to a third party | none | No | **DEFER** - move key to header, add mocked-httpx tests |
| `services/urlhaus_service.py` (new, 164) | abuse.ch URLhaus lookup, written as "no API key required" | Medium | **Broken as written: abuse.ch returns HTTP 401 `Unauthorized` without an Auth-Key (verified 2026-10-05)**, so every lookup degrades to an error status; needs a credential (owner action); URLs sent to a third party | URL egress | none | No | **DO NOT COMMIT** until an Auth-Key exists or the feature is dropped |
| `routers/link_scanner.py` (+127/-35) | Orchestrates GSB then URLhaus then internal rules; adds `GET /link-scanner/providers/status` | Medium | Depends on gsb v2 + urlhaus; status endpoint exposes provider configuration to any logged-in user | URLs | none | No | **DEFER** (with the threat-intel group) |
| `services/ai_service.py` (+479/-47) | Multilingual coach prompts, streaming FIR draft, AI error classification, more Anthropic calls | High | `language` is allow-listed (no prompt injection through it); **operational hints are returned to end users** ("check ANTHROPIC_API_KEY in .env", "add credits at console.anthropic.com"); user chat text is sent to a third party | user content to Anthropic (needs a privacy notice) | none | No | **DEFER** - replace hints with generic messages, add mocked-client tests |
| `routers/ai_coach.py` (+7/-1) and `schemas/ai_conversation.py` (+5) | Pass `language` through to the coach/e-mail generator | Low | none beyond ai_service | - | none | No | **DEFER** (coupled to `ai_service`; commit together) |
| `routers/video_call.py` (+118/-1) | SSE streaming FIR draft (`POST /video-call/generate-fir-stream`) | Medium | On failure the stream sends `Streaming failed: {exception text}` to the client (information disclosure; the committed scrubber does not cover client responses); unauthenticated-stream abuse is limited by JWT | FIR text may contain victim PII (stored as evidence) | none | No | **DEFER** - generic client error, tests |
| `routers/community_scam.py` (+219/-1) | `GET /community-scams/news-feed`: weekly aggregation + editorial advisories with sample phone numbers/URLs from user reports | Medium | Exposes unmoderated, user-submitted phone numbers/URLs to every logged-in user (defamation/abuse risk); `ilike` on a user-supplied city | third-party phone numbers | none | No | **DEFER** - moderation/verification and tests |
| `routers/emergency_contacts.py` (+55/-3) and `schemas/emergency_contact.py` (+8) | `PATCH /emergency-contacts/{id}` partial update; safer UUID parsing | Low-medium | Authorization is correct (owner-scoped query, field set restricted to name/relationship/phone/email, no mass assignment); **no length limits or e-mail validation** (a long value would 500 on the column size) | third-party PII | none | No | **FIX-THEN-COMMIT** (closest to ready: add length/format validation + 5-6 tests) |
| `app/middleware/error_handler.py` v2 parts and `app/main.py` hooks (pre-existing hunks) | request-id header, body capture (<=8 KB), unverified JWT decode for `user_id`, `install_process_handlers`, SQL listeners, threat-intel startup verifier | High | body capture would store OTPs/PII; unverified JWT decode lets a forged token write arbitrary `user_id` into logs | high | none | No | **DO NOT COMMIT** body capture/JWT decode; request-id and startup hooks may come later |
| `start.bat` | Local dev launcher | none | no secrets; hard-coded LAN IP and `--reload` | - | n/a | No | **DO NOT COMMIT** (developer-machine specific); leave untracked |
| `migrations/create_recordings_table.sql` (pending deletion) | Raw SQL for the recordings table | none | superseded by Alembic revision `a1b2c3d4e5f6_add_recordings_table` (and its DDL differs: `ON DELETE CASCADE` vs the real FK) | - | n/a | No | **COMMIT the deletion** (safe) |

## 17. Master register (authoritative)

Columns: ID, category, feature/problem, status, severity, evidence, component, current behaviour, required fix,
tested?, production-blocking?, decision, follow-up. "n/a" = not applicable. "s2" in the evidence column means
section 2 of this document, "s16" section 16, and so on.

| ID | Category | Feature / problem | Status | Severity | Evidence | Component | Current behaviour | Required fix | Tested? | Prod-blocking? | Decision | Follow-up |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| FG-001 | Auth/OTP | E-mail OTP cannot be delivered from Railway | BLOCKED | BLOCKER | Railway docs: SMTP Pro-only; measured IPv4 587/465 timeouts, IPv6 unreachable (s1) | `otp_service._send_email` | send fails, failure logged (masked), API returns 503 on login | HTTPS e-mail provider (Option A, recommended) or Railway Pro (Option B) | failure path tested | Yes | Decision deferred until Git staging is stable | owner: choose provider, verify domain, supply key |
| FG-002 | Auth/OTP | SMS OTP fails: Twilio 20003 | BLOCKED | BLOCKER | startup log + send path (s1) | `otp_service._send_sms` | auth failure | valid Twilio credentials (+ DLT registration for India) | failure path tested | Yes | Credential work is DEFERRED | owner: credentials |
| FG-003 | Auth/OTP | No working OTP transport | BLOCKED | BLOCKER | FG-001 + FG-002 | auth flow | users cannot receive codes (tests/e2e read them from the DB) | resolve FG-001/002 | e2e with DB-read OTP | Yes | - | - |
| FG-004 | Auth/OTP | OTP plaintext logging | RESOLVED | was HIGH | mutation-checked tests; staging logs clean (s1.4) | `otp_service` | metadata only | - | Yes (7) | No | closed | - |
| FG-005 | Auth | Refresh token accepted as access token | RESOLVED | was HIGH | staging 200 before; 401 after; 17 tests; device test (s1.5) | `routers/auth.py` | typed tokens enforced | - | Yes | No | closed | - |
| FG-006 | Auth | `/auth/refresh` ignored inactive/deleted users | RESOLVED | was LOW | tests (s1.9) | `routers/auth.py` | 401 | - | Yes | No | closed | - |
| FG-007 | Auth | No refresh rotation/revocation | RESOLVED 2026-10-06 | MEDIUM | pinned by test (s1.11) | `routers/auth.py` | used refresh token stays valid 30 days | `jti` family store, rotate + reuse detection | pinned only | No | next auth phase | schedule |
| FG-008 | Auth/OTP | OTP generated with `random.randint` | RESOLVED 2026-10-06 | MEDIUM | code (s1.6) | `routers/auth.py` | non-cryptographic PRNG | `secrets.randbelow` | no | No | next auth phase | - |
| FG-009 | Auth/OTP | OTP stored in plaintext | RESOLVED 2026-10-06 | MEDIUM | model `otps.code` (s1.7) | `models/user.py` | equality compare | store HMAC, compare constant-time | no | No | next auth phase | - |
| FG-010 | Auth | Rate limiter is in-memory | OPEN | MEDIUM | code (s1.8) | `middleware/rate_limiter.py` | per-process, resets on restart | Redis backend | factory tested | single replica only | keep 1 replica | - |
| FG-020 | Security | Secrets in Git history | DEFERRED | HIGH | s2 | git history | exposed (repo now private) | rotate first, then history decision | gitleaks | **Yes** | deferred by owner | rotation phase |
| FG-021 | Security | `SECRET_KEY` rotation | DEFERRED | HIGH | s2 | `config.py` | placeholder in history; staging uses its own | new random key | startup check | **Yes** (prod refuses placeholder) | deferred | rotation phase |
| FG-022 | Security | `ADMIN_TOKEN` rotation | DEFERRED | HIGH | s2 | `admin_errors.py` | placeholder locally | new random value | startup check | **Yes** | deferred | rotation phase |
| FG-023 | Security | Anthropic key rotation | DEFERRED | HIGH | s2 | `ai_service` | in public history | revoke + reissue | n/a | Yes | deferred | rotation phase |
| FG-024 | Security | Twilio credential rotation/replacement | DEFERRED | MEDIUM | s2 | `otp_service` | invalid (FG-002) | rotate | n/a | Yes | deferred | rotation phase |
| FG-025 | Security | Gmail SMTP credential rotation | DEFERRED | MEDIUM | s2 | `otp_service`, `logger_service` | on disk only | revoke | n/a | Yes | deferred | rotation phase |
| FG-026 | Security | Safe Browsing key rotation | DEFERRED | MEDIUM | s2 | `gsb_service` | on disk only | regenerate + restrict | n/a | No | deferred | rotation phase |
| FG-027 | Security | Translator key rotation | DEFERRED | MEDIUM | echoed once in a transcript | dev machine | exposed locally | regenerate | n/a | No | deferred | rotation phase |
| FG-028 | Security | Azure PostgreSQL credentials | DEFERRED | LOW | server no longer exists | local files | stale copies | delete stale env files later | n/a | No | deferred | cleanup |
| FG-029 | Security | Local `postgres` password (reused, in history, and in an uploaded helper file, FG-036) | DEFERRED | MEDIUM | s2 | local DB | unchanged | change | n/a | No | deferred; recommended soon | owner |
| FG-030 | Security | JWT/Cookie/admin-token header capture in `error_logs` | RESOLVED | was HIGH | 8 tests, staging 0 matches (s2) | `error_handler.py` | allowlist | - | Yes | No | closed | - |
| FG-031 | Security | Request-body capture | RESOLVED / NOT PRESENT | - | no body reads in candidate; test (s2) | `error_handler.py` | not captured | keep v2 excluded | Yes | No | closed | - |
| FG-032 | Security | Query values, path params, share tokens, SQL params in logs | RESOLVED | was MEDIUM | tests, real 404 on share route (s2) | `error_handler.py`, `database.py` | names/templates only; `hide_parameters` | - | Yes | No | closed | - |
| FG-033 | Security | Exception text / tracebacks may carry secrets/PII | RESOLVED (heuristic) | was MEDIUM | 3 real leaks reproduced then fixed (s2) | `log_scrubber.py`, `logger_service` | scrubbed + bounded | review residual patterns over time | Yes (32) | No | closed with residual risk | periodic review |
| FG-034 | Security | `error_logs` retention | OPEN | MEDIUM | s2 | `main.py` startup purge | 90 days, no PII policy | define retention/export | no | No | decision needed | owner |
| FG-035 | Security | Admin token compared with `!=` | OPEN | LOW | s2 | `admin_errors.py` | not constant-time | `hmac.compare_digest` | no | No | later | - |
| FG-036 | Security | Local DB URL file uploaded to Railway source archive (incident) | OPEN (mitigated) | LOW-MEDIUM | s2, s18 | deploy process | live container verified clean; scratch copies removed; ignore rules committed; historical Railway source archive NOT purged (no evidence) | change the local password (deferred rotation); deploy only `git archive` exports | context simulation + live container scan | No | recommended soon | owner |
| FG-037 | Security | `/ready` returns database and role names | OPEN | LOW | code | `main.py` | minor disclosure | return only status | no | No | later | - |
| FG-038 | Security | AI errors expose config hints to users | UNREVIEWED | MEDIUM | `ai_service` (s16) | unreviewed file | hints in chat reply | generic messages | no | No | deferred | with AI group |
| FG-040 | Privacy | Account deletion incomplete / false claim | RESOLVED | was HIGH | 7 tests + live volume test (s15) | `account_erasure.py` | full erasure, explicit retention | owner decisions on audit retention | Yes | No | closed | retention decisions |
| FG-041 | Privacy | Elderly guardian alert is a stub that logs guardian phone/e-mail | OPEN | MEDIUM | code (s2) | `elderly_protection.py` | logs PII, sends nothing | implement delivery, mask logs | no | No | later | after OTP transport |
| FG-042 | Privacy | Community feed exposes user-submitted numbers | UNREVIEWED | MEDIUM | s16 | unreviewed `community_scam` | not deployed | moderation | no | No | deferred | - |
| FG-050 | Database | Railway PostgreSQL | IMPLEMENTED | - | s3 | Railway | operational | - | Yes | No | - | - |
| FG-051 | Database | DB roles and default privileges created by hand | OPEN | MEDIUM | s3 | ops | not scripted | idempotent SQL bootstrap script | n/a | No | later | - |
| FG-052 | Database | No backups / restore test | NOT IMPLEMENTED | HIGH | s3 | Railway | none defined | backup policy + tested restore | no | **Yes** | needed before production | owner |
| FG-053 | Database | Orphan `otp_vault_entries` table | OPEN | LOW | s3 | migration 1 | unused | drop migration | n/a | No | later | - |
| FG-054 | Database | Reference data (TSP/LSA/SMS headers) | RESOLVED | was MEDIUM | s4 | seed script | seeded on staging | repeat per new DB | scratch DB + staging | No | closed | - |
| FG-060 | Admin | First admin | OPEN | HIGH | s5 | `app/cli/bootstrap_admin.py` | none exists; CLI ready, not executed | run after approval | 9 tests + subprocess run | **Yes** | awaiting approval | owner |
| FG-061 | Admin | Admin APIs limited to error logs + warrior applications | PARTIAL | MEDIUM | s5 | routers | 7 endpoints | add as needed | partly | No | later | - |
| FG-062 | Admin | No admin UI (Flutter or web) | NOT IMPLEMENTED | MEDIUM | s6 | frontend | none | build | n/a | No | later | - |
| FG-063 | Admin | No user management / audit viewer / dashboards | NOT IMPLEMENTED | MEDIUM | s5 | backend | none | build | n/a | No | later | - |
| FG-070 | Files | No evidence download route | NOT IMPLEMENTED | LOW | s7 | `evidence.py` | metadata only | add if needed | n/a | No | later | - |
| FG-071 | Files | Upload validation (type/size/AV) not assessed | OPEN | MEDIUM | s7 | evidence/recordings | unknown | review | no | No | next phase | - |
| FG-072 | Files | Single volume, single replica | OPEN | LOW | s7 | Railway | cannot scale out | object storage later | n/a | No | known | - |
| FG-080 | Cyber Warriors | Admin profile management, promotion/suspension | NOT IMPLEMENTED | MEDIUM | s8 | router | audit actions exist, no writers | build | n/a | No | later | - |
| FG-081 | Cyber Warriors | Flutter client | NOT IMPLEMENTED | MEDIUM | s11 | frontend | none | build | n/a | No | later | - |
| FG-090 | Unreviewed | `logger_service` v2 | UNREVIEWED | MEDIUM | s16 | file | not committed | review + tests | no | No | DEFER | - |
| FG-091 | Unreviewed | `error_handler` v2 (body capture, unverified JWT decode) | UNREVIEWED | HIGH if shipped | s16 | file | not committed | do not ship as is | no | If included | DO NOT COMMIT | - |
| FG-092 | Unreviewed | `gsb_service` v2 | UNREVIEWED | MEDIUM | s16 | file | not committed | key to header, tests | no | No | DEFER | - |
| FG-093 | Unreviewed | `urlhaus_service` (HTTP 401 without Auth-Key) | UNREVIEWED / BROKEN | MEDIUM | verified 401 | file | not committed | key or drop | no | No | DO NOT COMMIT | owner |
| FG-094 | Unreviewed | `link_scanner` v2 | UNREVIEWED | MEDIUM | s16 | file | not committed | with threat-intel group | no | No | DEFER | - |
| FG-095 | Unreviewed | `ai_service`, `ai_coach`, `ai_conversation` | UNREVIEWED | MEDIUM | s16 | files | not committed | generic errors, tests | no | No | DEFER | - |
| FG-096 | Unreviewed | `video_call` streaming | RESOLVED 2026-10-06 (reviewed, hardened, committed) | MEDIUM | s16 | file | not committed | generic client error | no | No | DEFER | - |
| FG-097 | Unreviewed | `community_scam` news feed | RESOLVED 2026-10-06 (corroboration threshold, escaped filter, tests) | MEDIUM | s16 | file | not committed | moderation | no | No | DEFER | - |
| FG-098 | Unreviewed | `emergency_contacts` PATCH + schema | RESOLVED (committed `ef54a21`) | LOW | s16 | files | not committed | validation + tests | no | No | FIX-THEN-COMMIT | next |
| FG-099 | Hygiene | `start.bat` | n/a | LOW | s16 | local file | untracked | - | n/a | No | do not commit | - |
| FG-100 | Hygiene | `migrations/create_recordings_table.sql` deletion | RESOLVED (committed) | LOW | s16 | repo | superseded by Alembic | - | n/a | No | committed | - |
| FG-110 | Flutter | HTTPS probe fix | RESOLVED | was MEDIUM | script + emulator log (s11) | `app_config.dart` | https override survives restart | - | Yes (device) | No | closed | commit by hunk in the Flutter repo |
| FG-111 | Flutter | SDK corruption | RESOLVED | was MEDIUM | s11 | local SDK | repaired; leftovers on disk | delete `dart-sdk.broken`, `dart-sdk.old1`, `*.stamp.bak` later | n/a | No | closed | owner cleanup |
| FG-112 | Flutter | analyze 639 issues (0 errors) | RESOLVED 2026-10-06 (0 issues) | LOW | s11 | app code | infos/warnings | clean up | analyze | No | later | - |
| FG-113 | Flutter | Device verification partial | PARTIAL | MEDIUM | s11 | app | register/login/profile/logout done | refresh path, uploads, deletion UI | partly | Yes for release | continue | - |
| FG-120 | Deploy | Git-based deployment | NOT IMPLEMENTED | HIGH | s12 | Railway | CLI uploads only | push branch, connect Railway | n/a | **Yes** | awaiting approval | owner |
| FG-121 | Deploy | CI on GitHub | NOT IMPLEMENTED (workflow ready, **not yet run - push required**) | MEDIUM | local reproduction with the workflow's own environment (ruff, `alembic upgrade head`, pytest 300 passed, gitleaks command identical); the workflow now also triggers on pushes to `staging/**` (before, only `main` pushes and pull requests ran it, so pushing the staging branch alone would have run nothing) | `.github/workflows/backend-ci.yml` | not run | push the branch, observe the run | local Yes | Yes (reproducibility) | awaiting push approval | owner |
| FG-122 | Deploy | `railway.toml` deprecation | RESOLVED (replaced by `.railway/railway.ts` IaC) | LOW | cutoff 2026-12-01 | repo | works | `railway config migrate --service secureshield-api` | n/a | No | after Git deploy | - |
| FG-123 | Deploy | Railway environment named `production` inside the staging project | OPEN | LOW | s12 | Railway | confusing | rename | n/a | No | later | - |

---

## 18. Pre-push security gate record (2026-10-05)

Verification-only gate; no push, no Railway Git connection, no credential rotation, no admin created.

| Gate | Result |
|---|---|
| Git | branch `staging/railway-snapshot`, linear history, no merges/amend/rebase (branch reflog shows only commit batches), backup refs present, `origin` has no staging branch |
| Deployment contexts | repository, Docker context (simulated with Docker semantics), CI checkout, Railway source and the live container contain no `ci_env*`, `.env*`, key files, dumps or credential shapes; explicit ignore rules added |
| Credential audit of the committed tree | no real active credential; matches are placeholders, test fixtures, documentation references and one personal e-mail address used as a masking example in a pre-existing docstring and in tests (not a secret; WARN) |
| Gitleaks (CI command, pinned 8.21.2) | current tree clean; custom rules catch Anthropic/Google/Twilio/SMTP/Azure-DB canaries in 10 location classes; empty values and newline boundaries give no false positives; allowlist is exact-value only |
| Backend suite (CI environment, Python 3.11) | 300 passed; ruff clean; Alembic head `l7m8n9o0p1q2` |
| Staging (read-only) | 29 tables, 0 users, 0 admins, 0 uploaded files, 0 user-data rows, reference data 11 / 22 / 23,192, `error_logs` 29 rows with no credential patterns, app role least-privilege |
| GitHub CI | **NOT YET RUN - PUSH REQUIRED** |
| Historical secrets in Git history | **YES** (rotation deferred; history not rewritten) |

---

## Master feature matrix

"Tested" = automated test and/or staging end-to-end in this cycle. Features are those found in the code
(backend routers/models and Flutter feature folders); nothing here is invented.

| Module | Feature | Status | Tested | Production blocker | Issue | Planned fix |
|---|---|---|---|---|---|---|
| Auth | Register (name+e-mail[+phone]) | IMPLEMENTED | Yes | OTP delivery | 1.1-1.3 | transport |
| Auth | check-user (public, rate-limited) | IMPLEMENTED | Yes | No | account enumeration by design | review |
| Auth | Send / verify OTP, single use, 10-min TTL | IMPLEMENTED | Yes | Delivery | 1.6, 1.7 | `secrets`, hashed OTP |
| Auth | Token refresh | IMPLEMENTED | Yes | No | 1.5 refresh used as access | `type` claim |
| Auth | Profile get/update | IMPLEMENTED | Yes | No | - | - |
| Auth | Account deletion | PARTIAL | Yes (warrior data only) | **Yes** (privacy) | leaves evidence/recordings/files/OTPs/devices/family/etc.; claims full deletion | delete/anonymise all user-linked data |
| Auth | Device registration + new-device check | IMPLEMENTED | No | No | untested | tests |
| Security | Rate limiting | PARTIAL | Yes | Single replica | in-memory | Redis |
| Security | Startup production checks, CORS fail-closed | IMPLEMENTED | Yes | No | - | - |
| Security | OTP logging | RESOLVED | Yes | No | - | - |
| Security | Error-log header/query/path/param protection | RESOLVED | Yes | No | - | - |
| Security | Traceback/exception text scrubbing | NOT IMPLEMENTED | No | No | section 2 | review logger_service |
| Database | Railway PostgreSQL, Alembic, roles | IMPLEMENTED | Yes | Backups | - | DR plan |
| Database | Reference data seed | PARTIAL (script ready, DB empty) | Scratch DB | Sender validation | not seeded | run seed |
| Admin | Error log API (token) | IMPLEMENTED | Yes | Prod secrets | placeholder token | rotate |
| Admin | Warrior application review (JWT role) | IMPLEMENTED | Yes | Needs first admin | smoke admin only | bootstrap |
| Admin | User management / audit viewer / dashboards | NOT IMPLEMENTED | - | No | gap | build later |
| Admin | Admin UI (Flutter/web) | NOT IMPLEMENTED | - | No | gap | build later |
| Admin | First-admin bootstrap CLI | IMPLEMENTED | Yes (9 tests; scratch DB e2e) | No | refuses while smoke admin exists | owner decision |
| Cyber Warriors | Apply / status / profile / RBAC / audit write | IMPLEMENTED | Yes | No | - | - |
| Cyber Warriors | Admin profile management, promotion, suspension | NOT IMPLEMENTED | - | No | gap | build |
| Cyber Warriors | Flutter client | NOT IMPLEMENTED | - | No | gap | build |
| Evidence | Upload/list/get/delete (owner) | IMPLEMENTED | Yes | No | no download route | add if needed |
| Recordings | Upload/list/delete/share/download | IMPLEMENTED | Yes | No | - | - |
| Storage | Persistent volume | RESOLVED | Yes | No | single replica | object storage later |
| Alerts | List/read/dismiss/delete/panic | IMPLEMENTED | No | No | untested | tests |
| Family | Members CRUD + member alerts | IMPLEMENTED | No | No | untested | tests |
| Elderly protection | Config | IMPLEMENTED | No | No | - | tests |
| Elderly protection | Guardian alert delivery | NOT IMPLEMENTED (TODO stub; logs guardian phone/e-mail) | No | No | PII in logs, nothing sent | implement + mask |
| Devices | CRUD | IMPLEMENTED | No | No | - | tests |
| App scanner | Scan / results / spyware check | IMPLEMENTED | No | No | - | tests |
| App monitor | Sync / history / summary / delete | IMPLEMENTED | No | No | - | tests |
| Clone detection | Scan / history / feedback / catalogue | IMPLEMENTED | No | No | - | tests |
| Wi-Fi scanner | Scan / history | IMPLEMENTED | No | No | - | tests |
| Network | Activity / suspicious | IMPLEMENTED | No | No | - | tests |
| Reports | Daily / history / weekly insights / log-behavior | IMPLEMENTED | No | No | - | tests |
| Scam calls | Report / history / block | IMPLEMENTED | No | No | path contains phone number | route-template logging done |
| Message analyzer | Analyze / extract-screenshot / validate sender / job offer / bullying | IMPLEMENTED | No | Registry empty | seed + Anthropic key | seed |
| Link scanner | Scan + history (GSB) | IMPLEMENTED (HEAD); extended UNREVIEWED | No | No | key rotation deferred | review |
| Threat intel | URLHaus | UNREVIEWED | No | If included | third-party URL egress | review |
| AI | Coach, complaint e-mail, tips, FIR draft | IMPLEMENTED (HEAD); streaming/extended UNREVIEWED | No | Anthropic key | rotation deferred | review |
| Community | Reports/feed/trending/upvote | IMPLEMENTED (HEAD); news feed UNREVIEWED | No | No | - | review |
| Emergency contacts | List/create/delete | IMPLEMENTED (HEAD); update UNREVIEWED | No | No | auth of PATCH to review | review |
| Video call | Room / police contacts / FIR | PARTIAL | No | No | - | tests |
| Flutter | Staging HTTPS endpoint + probe fix | RESOLVED | Yes (script) | No | - | - |
| Flutter | SDK, `pub get`, analyze, tests | RESOLVED | Yes | No | 639 infos/warnings | clean up |
| Flutter | Feature modules (ai_coach, alerts, app_monitor, app_scanner, auth, bank_otp, banking_protection, call_recording, clone_detector, community_scam, complaint_email, consent_manager, dashboard, device_scan, digital_arrest, elderly_protection, evidence, fake_bank_sms, family, link_scanner, message_analyzer, package_monitor, payment_verifier, profile, qr_scanner, remote_detector, reports, scam_news, screen_recorder, settings, sim_integrity, video_call, vpn_monitor, welcome, wifi_scanner) | modules exist | No (not run on a device) | Yes for release | unverified on device | device test |
| Flutter | `bank_otp`, `qr_scanner`, `sim_integrity`, `vpn_monitor`, `package_monitor`, `payment_verifier`, `fake_bank_sms`, `digital_arrest`, `scam_news` | client-side modules; backend dependency not assessed | No | No | not assessed | assess |
| Deployment | Railway API/DB/volume/healthcheck/pre-deploy | IMPLEMENTED | Yes | No | - | - |
| Deployment | Git-based deploy + CI on GitHub | NOT IMPLEMENTED | Local reproduction only | Yes | not pushed | after approval |
| Deployment | `railway.toml` deprecation | DEFERRED | - | No | cutoff 2026-12-01 | `railway config migrate` |
| Ops | Backups / DR / monitoring / alerting | NOT IMPLEMENTED | - | Yes | alert e-mail blocked | plan |
| Legacy | `otp_vault_entries` orphan table | LOW | - | No | no ORM model | drop migration |

---

## 19. Completion pass of 2026-10-06 (no push, no deployment, no credential change)

Scope: local repository only. Totals at the end of the pass: backend **572 passed**, ruff 0.9.4 clean,
`flutter analyze` clean, Flutter **26 passed**. Evidence levels: *impl* = code exists, *int* = integration-tested
against real PostgreSQL, *e2e* = exercised on a device, *ext* = verified against the real external service.

### 19.1 Security defects found and fixed in this pass

| ID | Defect (all reproduced by a failing test first, unless noted) | Severity | Fix | Evidence |
|---|---|---|---|---|
| FG-130 | **Family: anyone could read another person's alerts** by adding their phone number with `can_view_alerts` (no consent) | HIGH | consent workflow (pending/accepted/declined), only the invitee can answer or revoke; migration `m8n9o0p1q2r3` resets existing links to pending | int (10 tests) |
| FG-131 | **App-scan results, spyware check, Wi-Fi history and network "suspicious" returned every user's rows** (scans stored without owner); network writes accepted any device id | HIGH | `user_id` on `app_scans`/`wifi_scans` (migration `o0p1q2r3s4t5`), owner filters, device-ownership check; pre-existing orphan rows are never returned | int (9 tests) |
| FG-132 | `/devices/register` returned another account's device record when the token matched | MEDIUM | 409 | int |
| FG-133 | Daily report counted other users' app scans; was frozen after the first request of the day; duplicate rows possible; local/UTC day mismatch | MEDIUM | per-user count, refresh on read, unique (user, day) (migration `n9o0p1q2r3s4`), UTC dates | int (13 tests) |
| FG-134 | `alerttype` DB enum lacked 7 members used by the code: job-offer, suspicious-message, cyberbullying alerts (and 4 more) failed with HTTP 500 in any migrated DB | HIGH | migration `p1q2r3s4t5u6`; schema-drift tests compare ORM enums/tables/columns with the migrated DB | int |
| FG-135 | App-monitor sync created an `Alert` with non-existent enum members/columns (500 on every risky install); sync not idempotent | MEDIUM | fixed + dedupe | int |
| FG-136 | Guardian alert only logged (TODO) and logged the guardian's phone/e-mail | MEDIUM | real SMS/e-mail delivery, no PII in logs, threshold, rate limit | int (mocked providers) |
| FG-137 | Panic notified nobody | MEDIUM | SMS/e-mail to the user's emergency contacts | int (mocked providers) |
| FG-138 | Evidence/recordings: whole-file reads, no size cap, unsanitised filenames, trusted DB paths, server path exposed, share link not revocable and always served as `audio/aac` | MEDIUM | streaming + caps, sanitising, path containment, owner-only download, revoke | int (22 tests) |
| FG-139 | Message analyzer: unbounded inputs, blocking sync AI call on the event loop, exception text returned to the client | MEDIUM | bounds, async + timeout, generic note, magic-byte check, shared AI rate limit | int |
| FG-140 | Alembic `fileConfig()` disabled all existing loggers when migrations ran in-process | LOW | `disable_existing_loggers=False` | made an AI-logging test order-dependent |
| FG-141 | Release app allowed cleartext HTTP, `allowBackup` on, unused `SEND_SMS`/`REQUEST_INSTALL_PACKAGES` declared | MEDIUM | network security config (release HTTPS-only), `allowBackup=false`, permissions removed | build + emulator launch |
| FG-142 | Client ignored the rotated refresh token and could fire concurrent refreshes (would trip replay detection) | MEDIUM | store new token, single in-flight refresh | analyze only (no device test) |
| FG-143 | `ADMIN_TOKEN` compared with `!=` | LOW | `hmac.compare_digest` | int |

### 19.2 Previously open items now implemented

OTP CSPRNG + HMAC at rest (FG-008/009), refresh rotation (FG-007), Google ID-token verification (backend),
Resend HTTPS e-mail adapter, admin stats/user control, family dashboard, daily-report e-mail, evidence
encryption at rest (code), backup/restore tooling, localization wiring (partial), `flutter analyze` clean.

### 19.3 Remaining items by verification level

| Item | impl | int | e2e | ext | Blocker |
|---|---|---|---|---|---|
| Live OTP e-mail (Resend) | yes | mocked | no | no | API key + verified sender domain (owner) |
| Live OTP SMS (Twilio) | yes | mocked | no | no | valid Twilio credentials; India DLT registration |
| Google Sign-In | backend yes | yes (signed test tokens) | no | no | OAuth client IDs; client plugin not added |
| Safe Browsing / URLhaus | yes | mocked | no | no | API keys on the target environment |
| Anthropic AI features | yes | fake client | no | no | real key + spend |
| Panic / guardian / report SMS+e-mail | yes | mocked | no | no | working providers |
| Evidence encryption | yes | yes | no | no | `FILE_ENCRYPTION_KEY` (owner), rotation tooling not built |
| Localization (all screens) | partial (~56 of ~444 literals) | n/a | no | no | none - independent work remains |
| Family/Invites client UI | yes | backend yes | **no** | no | device run |
| Network-activity producer (client) | **no** | backend yes | no | no | independent work remains |
| Admin UI / per-admin audit trail | no | endpoints yes | no | no | independent work remains; no admin may be created without approval |
| Backups schedule + off-site storage | tooling yes | local restore verified | no | no | owner/Railway action |
| Android upload signing | config yes | n/a | no | no | keystore (owner); **current artifacts use the debug key** |
| Flutter SDK `font-subset` artifact | RESOLVED 2026-10-06 | `flutter precache --force`; builds pass without `--no-tree-shake-icons` | - |
| Railway staging verification (migrate + `/health` + SHA) | config yes | no | no | **no** | push not authorised; only environment is named `production` |
| GitHub CI run | workflow yes | no | no | no | push required. Real gitleaks 8.21.2 **was run locally** on 2026-10-06: tree clean; history shows only the 14 known historical findings |
| Historical secrets in Git history | n/a | n/a | n/a | n/a | rotation DEFERRED by the owner |

### 19.4 Migrations created in this pass (head `s4t5u6v7w8x9`; none applied outside local disposable databases)

| Revision | Purpose | Data impact |
|---|---|---|
| `m8n9o0p1q2r3` | family consent (`consent_status`, `invited_phone`) | existing links become `pending` (access removed until accepted) |
| `n9o0p1q2r3s4` | one security report per user per day | **deletes** older duplicates (keeps newest) |
| `o0p1q2r3s4t5` | `user_id` on app/Wi-Fi scans | none; existing rows stay unowned and are never returned |
| `p1q2r3s4t5u6` | 7 new `alerttype` values | none; not reversible (PostgreSQL) |
| `q2r3s4t5u6v7` | `otps.code` -> 64 chars | **deletes all OTP rows** (plaintext codes) |
| `r3s4t5u6v7w8` | refresh-token rotation tables | none; pre-rotation refresh tokens stop working (one re-login) |


### 19.5 Stabilization pass 1 additions (2026-10-06)

| ID | Item | Status |
|---|---|---|
| FG-144 | Real gitleaks flagged `SMTP_PASSWORD: preserve()` in `.railway/railway.ts` (false positive) and a fake `sk-ant-...LEAKY...` test key; the CI job would have failed on push | RESOLVED (exact-value allowlist entries, commit `902064d`) |
| FG-145 | Flutter SDK missing `font-subset` artifact | RESOLVED (`flutter precache --force`) |
| FG-146 | Migration safety review + rehearsal script | DONE (`MIGRATION_SAFETY_REVIEW.md`, `scripts/migration_rehearsal.py`) |
| FG-147 | `alembic check` reports pre-existing index/FK-name drift on older tables and an ORM-less `otp_vault_entries` table | OPEN, LOW, not caused by the six new revisions |
| FG-148 | OTP vault has a table and an erasure statement but no backend model/router | OPEN, LOW (feature is device-local) |
| `s4t5u6v7w8x9` | admin audit log table | none; new table |

### 19.6 Later in stabilization pass 1

| ID | Item | Status |
|---|---|---|
| FG-149 | Admin actions had no audit trail; no operator UI | audit log + same-origin console implemented, backend-int tested; console not run in a browser; still a single shared token (no per-person identity) |
| FG-150 | Evidence encryption had no key lifecycle | keyring + key ids + rotation script implemented and unit-tested; never run on real data |
| FG-151 | Backups had no schedule | opt-in workflow written (disabled), YAML-validated only |
| FG-152 | Google Sign-In client missing | client code written, disabled without a client ID; no E2E possible |
| FG-153 | E2E harness read the developer's real `.env` (settings give `.env` priority over process variables) and made one Twilio auth check at startup in earlier runs | harness fixed to ignore `.env` and use inert values; no SMS/e-mail was sent in any run |
| FG-154 | Local device E2E | login with OTP, dashboard score, Family Invites -> Accept, SOS fan-out verified on the emulator against the local backend (local harness; no real provider) |

### 19.7 Pre-staging release gate pass (2026-10-06)

| ID | Item | Status |
|---|---|---|
| FG-155 | VPN monitor black-holed all traffic (no forwarding) | RESOLVED: blocklist mode, device-verified |
| FG-156 | Bank OTP detection missed "OTP is <code>"; text read via `getString` | RESOLVED, device-verified |
| FG-157 | Biometric/PIN prompts never appeared (`local_auth` needs FragmentActivity + AppCompat) | RESOLVED, device-verified (also fixes biometric login) |
| FG-158 | OTP Vault feature (BRD #9) had no screen | IMPLEMENTED (device-local, PIN/biometric gated), device-verified |
| FG-159 | Scam-call endpoints never used by the client; user-reported scams scored 0 | RESOLVED (screen + scoring), device-verified |
| FG-160 | Emergency recording share link was a relative path | RESOLVED |
| FG-161 | Screen-recorder **detector** (BRD #13): implemented for Android 15+ only (own windows); unsupported below; detection of a genuine MediaProjection recording and its stop proven manually on API 36 emulator; `adb screenrecord` is not detected (by design); no automated device test | PARTIAL - AMBER (platform limitation documented) |
| FG-163 | `ScreenRecordService` (the recorder) never recorded: it treated `RESULT_OK` (-1) as 'missing' and stopped itself; then crashed on Android 14+ (no `MediaProjection.Callback`); then crashed with `setAudioSource failed` whenever the RECORD_AUDIO runtime permission was not granted (it was never requested) | **CLOSED** (local). Root causes fixed: result-code check; callback registered; microphone requested via `permission_handler` and, if refused, the screen is recorded **without audio** and the user is told; any native failure releases resources, deletes the partial file, reports `lastError` to Flutter and never crashes. Verified manually on API 36 (mic denied: video-only mp4, no `mp4a` track, notice shown, 0 fatal exceptions; mic granted: audio track present). Automated: 6 Dart tests with a faked channel (`screen_recorder_service_test.dart`); **no automated Kotlin/device test exists**. Failure path re-verified on API 36 by making the recordings directory unusable (replaced by a file): native start failed with `FileNotFoundException`, status reached Flutter (red message 'Screen recording could not start (FileNotFoundException)'), UI stayed on RECORD (recording=false), no projection session (`dumpsys media_projection` null), service gone, 0 fatal exceptions, no file created. Not exercised on a device: deletion of a partially written file (no reliable way to fail after the file is created; the delete is in `stopRecording` when `lastError` is set, covered by inspection only) |
| FG-162 | `EncryptionService` (Flutter) used a fixed IV and silently returned plaintext on failure | RESOLVED locally: AES-256-GCM, random 96-bit nonce per message, `EncryptionException` on any failure, legacy CBC read-only; 12 regression tests (mutation-checked) |
| FG-163 | `/version` endpoint for SHA verification; staging plan | DONE (plan not executed) |
| FG-164 | Localization coverage 43.7% (heuristic), translations unreviewed | OPEN, AMBER; external blocker = native-speaker review |

