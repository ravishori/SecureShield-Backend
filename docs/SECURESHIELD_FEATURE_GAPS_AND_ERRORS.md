# SecureShield Feature Gaps and Errors

Authoritative backlog of unresolved staging/production issues. **No secret values appear in this
document.** Evidence was gathered on 2026-10-05 against the Railway *staging* environment
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
| 1.5 | Refresh token accepted as a bearer access token | OPEN | **HIGH** | Recommended |
| 1.6 | OTP generated with `random.randint` (not a CSPRNG) | OPEN | MEDIUM | No |
| 1.7 | OTP stored in plaintext in `otps.code` | OPEN | MEDIUM | No |
| 1.8 | Rate limiter is in-memory, per process | OPEN | MEDIUM | Single replica only |
| 1.9 | `/auth/refresh` does not re-check the user is active | OPEN | LOW | No |
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

**1.5 Refresh token as access token.** Evidence (staging, 2026-10-05): `GET /auth/me` with the
*refresh* token as bearer returns HTTP 200. Cause: access tokens carry no `type` claim and
`get_current_user` never checks one; `/auth/refresh` does require `type=refresh` (an access token is
correctly rejected with 400). Impact: a stolen refresh token (30-day lifetime) is a full 30-day
access token, which defeats the 1-hour access-token hardening. Fix: put `type: "access"` in access
tokens and reject anything else in `get_current_user` (migration: tokens issued before the change
lack the claim - accept missing-type for one access TTL or force re-login). Not changed here because
it alters client-visible behaviour and needs a decision on existing sessions.

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
| Driver-level messages in tracebacks/exception text | **OPEN** | MEDIUM | asyncpg error `DETAIL` text can contain values (e.g. `Key (email)=(...) already exists`); pydantic `ValidationError` `str()` includes `input_value`. `logger_service.log_error` stores `str(exc)` and the full traceback and e-mails them. | `logger_service` (UNREVIEWED - not modified) | Review `logger_service`; scrub/shorten exception text before persisting and e-mailing; reduce e-mail body to type + endpoint + ID | No (but treat `error_logs` as sensitive) | Next hardening phase |
| Which sensitive items *can* appear in `error_logs` today | — | — | **Email/phone**: possibly via driver `DETAIL` or pydantic exception text. **OTP**: no longer via parameters or logs; only if embedded in a driver message. **JWT/access/refresh token**: not captured (headers allowlisted, bodies not read). **Share token**: no (route template). **Password**: no passwords exist in the auth flow. **API credentials**: only if an exception message embeds one (e.g. a provider error echoing a key) - unverified. | | | | |
| `error_logs` retention | **OPEN** | MEDIUM | Startup cleanup deletes rows older than `LOG_RETENTION_DAYS` (default 90); no policy for personal data, no export/erasure path; account deletion does not purge `error_logs.user_id` rows | `main.py`, models | Define retention (e.g. 30 days), purge on account deletion | No | Decision needed |
| Admin endpoint compares token with `!=` | OPEN | LOW | `admin_errors._check_admin` is not constant-time; no throttling beyond the global limiter | `admin_errors.py` | `hmac.compare_digest` + tighter rate limit | No | — |
| Pre-existing logging side effects (UNREVIEWED) | UNREVIEWED | ? | `logger_service` (working tree) adds SQLAlchemy event listeners, e-mail dedupe and hard-coded personal e-mail addresses; `error_handler` v2 adds body capture and unverified JWT decoding for `user_id` | | Review before any inclusion | Yes, if included | Excluded |

### Other security observations

| Item | Status | Severity | Note |
|---|---|---|---|
| `/ready` returns database and user names | OPEN | LOW | Minor information disclosure on a public URL |
| Staging smoke data | OPEN | MEDIUM | Staging DB holds throw-away smoke-test users (example.com addresses), one **admin profile created by the assistant during smoke testing**, one rejected application, evidence/recording files. See section 5. Owner decides on cleanup. |
| Staging API is public | OPEN | LOW | `secureshield-api-production-73ea.up.railway.app` (environment is named `production` inside the staging project; confusing, not an actual production environment) |
| Account deletion is PARTIAL but reports "permanently deleted" | OPEN | **HIGH** (privacy) | `DELETE /auth/me` (`auth.py::delete_account`) nulls the user's profile fields, sets `is_active=false` and deletes Cyber Warrior rows only. It does **not** remove evidence/recording rows or their files on the volume, OTP rows (email/phone), devices, family members, emergency contacts, scam reports, scan history, alerts or `error_logs`, and the response/docstring claim full deletion (and that deactivation blocks refresh - `/auth/refresh` does not check `is_active`; tokens minted that way are rejected on use). Fix: delete or anonymise every user-linked table and delete the files, add a test per table; correct the message. Production-blocking for privacy compliance (DPDP). |
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
| Reference-data seed | OPEN | See section 4 |
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
| **Railway staging seed status** | **EMPTY - NOT SEEDED** | `tsp_codes=0, lsa_codes=0, sms_sender_registry=0` (SELECT-only check, 2026-10-05) |
| Impact | MEDIUM | Sender-header validation (`/message/validate-sender`) has no registry to match against on staging |

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

**Admin existence: one active admin EXISTS in Railway staging** (masked: email `s***@example.com`,
user `9eef…e2`, profile `db88…ce`, role `admin`, created 2026-10-05 06:48 UTC, last activity same day).
It is **not** a real person: it is the throw-away "Smoke Admin" the assistant inserted by direct SQL
during the earlier smoke test to exercise the admin routes. Consequences: (a) the statement "no admin
exists" is false; (b) `python -m app.cli.bootstrap_admin` would correctly **refuse** to run (one-admin
rule); (c) its mailbox is not reachable, so nobody can log in as it, but it is a privileged row on a
public staging API. Recommendation: before any real use, the owner decides whether to remove the smoke
admin (and smoke users/files) so the bootstrap can create the real first admin. Nothing was changed.

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
(`DELETE` on `warrior_profiles`; leave the audit row). **Currently it would refuse** because the smoke
admin exists (see above). **Awaiting explicit approval; no admin is created automatically.**

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
| Device / emulator verification | **NOT DONE** - no device in this environment | MEDIUM |
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
| CI | **NOT RUN ON GITHUB** | Workflow reproduced locally with the CI environment: ruff, `alembic upgrade head`, pytest. Do not claim it passes until it runs on GitHub. |
| Production env requirements | NOTE | `ENVIRONMENT=production` requires `TRUST_PROXY_TLS=true`, non-placeholder `SECRET_KEY` and `ADMIN_TOKEN`, and an explicit `CORS_ALLOWED_ORIGINS`, otherwise startup fails (by design). Staging runs `ENVIRONMENT=staging`. |
| Environment naming | LOW | Railway's default environment inside `secureshield-staging` is called `production` |
| Single replica | known | in-memory rate limiter, local-disk uploads |
| Backups / disaster recovery | **NOT IMPLEMENTED** | see section 3 |
| Secret scanning in CI | PARTIAL | project gitleaks rules + allowlist prepared in `.gitleaks.toml`; default gitleaks rules miss Anthropic keys (custom rule added) |

---

## 13. Production readiness

| Area | Status | Production blocker | Resolution |
|---|---|---|---|
| OTP delivery (e-mail) | BLOCKED | **Yes** | HTTPS e-mail provider (Option A) or Railway Pro (Option B) |
| OTP delivery (SMS) | BLOCKED | **Yes** | Valid Twilio credentials (+ DLT registration for India) |
| Credential rotation / Git-history secrets | DEFERRED | **Yes** (production refuses placeholder `SECRET_KEY`/`ADMIN_TOKEN`; exposed keys must be rotated) | Rotation phase, then history decision |
| Refresh token usable as access token | OPEN | Recommended | Add token `type` claim + enforcement |
| First admin | OPEN | **Yes** (nobody can administer warriors) | Owner decision on smoke admin, then bootstrap CLI |
| Reference data on target DB | EMPTY | Yes for sender validation | Run seed (section 4) |
| Backups / DR | NOT IMPLEMENTED | **Yes** | Define + test restore |
| Git-based deployment + CI on GitHub | NOT DONE | Yes (reproducible deploys) | Push after approval, connect Railway, run CI |
| Error-log traceback/exception text, retention | OPEN | No | Review `logger_service`; retention policy |
| Unreviewed code (11 files + v2 pieces) | UNREVIEWED | Only if included | Review per group |
| Admin tooling / UI | NOT IMPLEMENTED | No (API only) | Build admin UI later |
| Flutter on device | UNVERIFIED | Yes for release | Run on device against staging |
| Automated tests for scanners/AI/threat intel | NOT IMPLEMENTED | No | Add |
| Header/query/param/path leakage in error logs | RESOLVED | No | - |
| OTP logging | RESOLVED | No | - |
| Database, volume, healthchecks, migrations | RESOLVED | No | - |

**Current production readiness: RED.**

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
