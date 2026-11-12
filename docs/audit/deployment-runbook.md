# Deployment and release runbook (staging first, production only with approval)

Prepared 2026-11-13 from the code at backend `28a490c` / Flutter `5898b1e`. **Nothing here has been executed against a real environment.** Hard rules: no push or deploy while the
repositories are public with exposed history; never deploy a credential that has appeared in Git history; do not disable authentication, MFA or startup checks to go faster.

## Docker-free architecture (decided 2026-11-13; configured, not yet deployed)

* **Backend:** Railway native Python build (Railpack) from `requirements.txt`; Python from `.python-version` (3.11); start command `uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips "${TRUSTED_PROXIES:-127.0.0.1}"`; healthcheck `/health`; **migrations run as Railway's pre-deploy step (`alembic upgrade head`), separate from application start**; one replica; volume at `/app/uploads`. All in `.railway/railway.ts` (`build: { builder: "RAILPACK" }`; secrets are `preserve()` only). `railway config plan` must be reviewed before `apply`.
* **Database:** a separate Railway PostgreSQL per environment (staging now, production later in its own project/environment); never shared. Existing data is untouched; migrations are additive.
* **CI/CD (GitHub Actions, no Docker):** `backend-ci` (tests on a Postgres service, gitleaks, ruff check+format, `pip-audit`, migrations on a blank DB), `flutter-ci` (analyze, test, tool tests, OSV scan; signed APK/AAB build + signature verification only in the approval-gated `android-release` environment), `deploy-staging` (manual, approval-gated `staging` environment, staging-scoped `RAILWAY_TOKEN`, `railway up`, smoke test). No workflow builds an image. All YAML parses; **no workflow has run** (repositories are public and nothing is pushed).
* **Dockerfile / `.dockerignore`:** no longer a prerequisite. Kept unchanged until the Railpack deployment is proven on staging; the only references are in documentation and the superseded builder choice. Remove them in a separate commit after that.
* **Non-root / healthcheck:** Railpack manages the runtime user; Railway volumes require the app to run as the volume owner, so this is a platform property to verify on staging (check that evidence upload works and note the process user), not a Dockerfile `USER` line.
* **Email OTP:** Resend only (see `docs/RESEND_SETUP.md`); Twilio stays dormant (placeholders) and is not introduced anywhere new.

### Checklist (no duplicate work)

| Item | State | Evidence |
|---|---|---|
| Resend e-mail provider, OTP hashing/expiry/attempts/resend limits/replay, failure handling, masked logs | **ALREADY IMPLEMENTED** - verified, not rewritten | `otp_service.py`, `otp_codes.py`, 16 OTP tests + provider tests; `docs/RESEND_SETUP.md` added |
| Provider verification tool | **ALREADY IMPLEMENTED** | `scripts/otp_provider_check.py` (offline / `--live` / opt-in send) |
| Android Gradle signing, verifier, comparer, docs | **ALREADY IMPLEMENTED** | `build.gradle.kts`, `tool/verify_apk_signature.py`, `docs/ANDROID_RELEASE.md` |
| Backend CI (tests, gitleaks, migrations) | **ALREADY IMPLEMENTED**; ruff format + pip-audit steps **added** | `backend-ci.yml` |
| Railway IaC (preDeploy migration, healthcheck, volume) | **PARTIALLY** -> builder, start command and new variables **added** | `.railway/railway.ts`, `.python-version` |
| Controlled staging deploy workflow | **NOT -> IMPLEMENTED** (unrun) | `deploy-staging.yml` |
| Flutter CI (analyze, test, OSV, signed build, signature check) | **NOT -> IMPLEMENTED** (unrun) | `flutter_app/.github/workflows/flutter-ci.yml`, `tool/osv_pub_scan.py` |
| Device/emulator utilities | adb + AVD `Pixel_5` exist; no scripted E2E | - |
| Private repositories | **NOT DONE** (both still public when checked 2026-11-13) | `gh repo view` |
| Railway staging project/environment, Resend domain/key, upload keystore, device | **NOT DONE (owner)** | - |

Estimated monthly cost (list prices, verify before committing; USD): Railway Hobby about 5 (usage credit included) to Pro 20/seat; staging API + small Postgres + 5 GB volume roughly 8-15 of usage; GitHub Actions private repos: 2,000 free Linux minutes/month (this pipeline uses roughly 15-25 min per run); Resend free tier 3,000 e-mails/month then about 20/month for 50,000; Anthropic and Safe Browsing are usage-based; Twilio none (not used). Typical staging total: about 15-35/month.

## 0. Go/no-go preconditions (all owner actions)

1. Repositories private; all historical credentials rotated (see `p1-closure-report.md`).
2. Isolated **staging** environment: its own project/environment, **its own PostgreSQL**, its own secrets and domain. (The existing Railway environment is named `production`; do not reuse it for tests.)
3. Working OTP channel(s) and AI/threat-intel keys *for staging only* (spend limits set).
4. Upload keystore created for Android.

## 1. Backend production configuration (what the app enforces)

`ENVIRONMENT=production` makes startup **refuse** to boot unless: `SECRET_KEY` is not a development/placeholder value (use >= 32 random bytes: `python -c "import secrets;print(secrets.token_urlsafe(48))"`), `ADMIN_TOKEN` is not a placeholder, TLS is declared (`TRUST_PROXY_TLS=true` behind Railway/any TLS-terminating proxy, or `FORCE_HTTPS`), `TRUSTED_PROXIES` is set whenever `TRUST_PROXY_TLS=true`, and `CORS_ALLOWED_ORIGINS` is explicit (empty is fail-closed; `*` is refused). Interactive docs (`/docs`, `/redoc`, `/openapi.json`) are off in production (`28a490c`).

| Variable | Required | Notes |
|---|---|---|
| `ENVIRONMENT` | yes | `production` (or `staging` for the staging environment; staging does not enforce the production checks - run one production-mode boot against staging config before go-live) |
| `DATABASE_URL` / `MIGRATOR_DATABASE_URL` | yes | runtime role (DML only) / migrator role (DDL). Neon: pooled endpoint for runtime, direct for migrator; requires the uncommitted connection fix (`docs/neon-migration/CONNECTION_FIX.patch`) - decide and commit it first |
| `SECRET_KEY` | yes | signs JWTs, OTP HMAC, encrypts admin TOTP secrets. Rotating it logs everyone out, voids open OTPs and requires `reset-mfa` for every admin |
| `ADMIN_TOKEN` | only while legacy is on | set `ADMIN_LEGACY_TOKEN_ENABLED=false` after named admins exist; then `ADMIN_TOKEN` can be removed from the environment |
| `ADMIN_LEGACY_TOKEN_ENABLED` | set explicitly | default `true`; target value for production `false` |
| `ADMIN_ACCESS_TOKEN_MINUTES` (30), `ADMIN_SESSION_MAX_HOURS` (8), `ADMIN_LOGIN_MAX_FAILURES` (5), `ADMIN_LOCKOUT_MINUTES` (15), `ADMIN_LOGIN_IP_LIMIT` (30) | optional | defaults shown |
| `TRUST_PROXY_TLS`, `TRUSTED_PROXIES` | yes | `TRUSTED_PROXIES` must be the *measured* proxy range of the host (also passed to uvicorn `--forwarded-allow-ips`) |
| `CORS_ALLOWED_ORIGINS` | yes | explicit origins only (the mobile app does not need CORS; the admin console is same-origin) |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_SMS_NUMBER` / `TWILIO_WHATSAPP_NUMBER` | for SMS OTP | verify with `python scripts/otp_provider_check.py --live` |
| `RESEND_API_KEY` / `RESEND_FROM_EMAIL` | for e-mail OTP on Railway | SMTP is blocked there; verified sender domain |
| `ANTHROPIC_API_KEY`, `GSB_API_KEY`-style keys, `GOOGLE_CLIENT_IDS` | per feature | without a key the AI features fall back to localised canned text (tests: provider failure -> generic message) |
| `FILE_ENCRYPTION_KEY` (+`FILE_ENCRYPTION_KEYS` for rotation) | strongly recommended | evidence/recordings are stored unencrypted until set; back the key up separately from the data |
| `UPLOAD_DIR` / volume | yes | persistent volume mounted at `/app/uploads` (single replica) |
| `LOG_RETENTION_DAYS` | set explicitly | purge runs at every start; <1 is ignored; pick the owner-approved period |
| `ERROR_NOTIFY_EMAIL`, SMTP_* | optional | error alert mail uses SMTP (blocked on Railway): alerts do not work there until a provider path exists |

Injection: set variables in the platform's secret store (Railway variables / CI masked secrets). `backend/.env*` are git-ignored and must never be copied into the image (`.dockerignore` excludes them). `.railway/railway.ts` uses `preserve()` so IaC applies never overwrite secret values.

## 2. Database migration procedure

1. Take and verify a backup (`BACKUP_AND_RECOVERY.md`; `scripts/` backup + restore check) **before** touching the target. Record the checksum.
2. Confirm the current revision (`select version_num from alembic_version`): expected `s4t5u6v7w8x9` on Neon / staging at the 2026-10-18 state.
3. Apply with the **migrator** role: `python -m alembic upgrade head` -> `t5u6v7w8x9y0` (adds `otps.attempts`, NOT NULL DEFAULT 0) then `u6v7w8x9y0z1` (tables `admin_accounts`, `admin_sessions`; nullable `actor_admin_id`, `actor_label` on `admin_audit_logs`). Both are additive; no data is read or rewritten. On Railway the IaC runs this as the pre-deploy step.
4. Grant the runtime role DML on the two new tables (`secureshield_app`: SELECT/INSERT/UPDATE/DELETE) if default privileges are not already set; the migrator must own them.
5. Verify `GET /version` -> `alembic_head: u6v7w8x9y0z1`, `/ready` 200.
6. **Order:** migrate first, then deploy the new application. The old application keeps working on the new schema (verified), so a failed deploy needs no database rollback.
7. Rollback of the schema is almost never needed. `alembic downgrade s4t5u6v7w8x9` removes only the new objects and **deletes admin accounts and sessions**; export them first if any exist.

## 3. Backend deployment procedure (staging, then production)

1. Release SHA chosen; CI green on that SHA (`backend-ci`: gitleaks, ruff, migrations on a blank DB, full pytest). A Flutter workflow does not exist yet.
2. Run the app locally from a clean venv against a scratch database (`uvicorn app.main:app`), check `/health`, `/ready`, `/version`; CI runs the same suite. (Docker is not used.)
3. Deploy with the `deploy-staging` workflow (or `railway up` from a clean `git archive` export, never a working folder); Railpack builds, pre-deploy migrates, healthcheck `/health`; one replica (in-memory limiter, local-disk uploads).
4. Smoke (section 5), then watch logs for 30 minutes.
5. Rollback: redeploy the previous image/commit (schema is compatible); restore variables if changed.
6. Runtime user and healthcheck are platform-managed on the native builder; on staging confirm the process can write `/app/uploads` (upload an evidence file) and that the Railway healthcheck gates the switch-over. The Dockerfile is no longer part of the procedure.

## 4. Flutter release procedure

1. Version: `pubspec.yaml` `version: 1.0.0+1` (bump the build number for every upload); application ID `com.secureshield.secureshield_app` (permanent once published).
2. Network: release is HTTPS-only (`network_security_config.xml`); `allowBackup=false`; build with `--dart-define=API_BASE_URL=https://<api>/api/v1` so the app never probes LAN hosts.
3. Signing: follow `flutter_app/docs/ANDROID_RELEASE.md`; the build refuses to run without an external upload key. Build `appbundle` for Play and `apk` for sideload tests; verify both signatures against the upload-key fingerprint.
4. Run `flutter analyze`, `flutter test` (95), then device checks (below).
5. Permissions review for Play (manifest declares SMS/call log/outgoing calls/phone state, all-packages query, usage stats, VPN, MediaProjection, boot completed, notification listener): remove what no shipped feature needs; SMS and call-log permissions need a Play declaration and usually default-handler status - plan a notification-based design instead. Prepare a privacy policy URL, the Data safety form (location, SMS-derived data, files, device identifiers, URLs sent to Google Safe Browsing/abuse.ch, text sent to Anthropic), foreground-service declarations, and demo videos.

## 5. Staging end-to-end smoke (to run once staging exists; nothing run yet)

Server side evidence already exists from the automated suites (stubbed providers); the **real** checks are:

| # | Flow | Automated evidence today | Real check needed |
|---|---|---|---|
| 1 | Register -> OTP -> login -> refresh | `test_otp_auth_flow_api`, `test_auth_hardening_api`, `test_otp_hardening_api`, `test_refresh_rotation_api` | live SMS/e-mail delivery; device login |
| 2 | URL scan / QR scan | `test_link_scanner_api`, threat-intel unit tests (simulated providers); QR is client-only with no tests | live Safe Browsing key; scan on device |
| 3 | App-risk assessment | `test_app_monitor_clone_api`, `test_device_scoped_data_api`; Kotlin analysers untested | device scan |
| 4 | Scam report | scam-call routes covered in the integration suites | device |
| 5 | Evidence upload + retrieval | `test_evidence_recordings_api`, `test_upload_type_policy`, `test_file_encryption_api`; Flutter 13 + 3 tests | device incl. share sheet and expired-token retry |
| 6 | Panic + emergency contacts | `test_emergency_contacts_api`, `test_guardian_alert_logging`, alerts tests (providers mocked) | real SMS/e-mail to a test contact |
| 7 | Family consent + alerts | `test_family_api` | two devices |
| 8 | AI coach + fallback | `test_ai_coach_api` (fake client; provider failure -> generic message) | live key; offline behaviour |
| 9 | Admin sign-in + MFA | `test_admin_accounts_api`, CLI, browser run (local) | on staging with a real authenticator |

Also verify: logs contain no OTPs/tokens, `/docs` is 404 in production mode, wrong-token throttling, rollback by redeploying the previous version.

## 6. DNS, HTTPS, monitoring, backups

* **DNS/HTTPS:** one API hostname with a platform-issued certificate; HSTS at the edge; `TRUST_PROXY_TLS=true` + measured `TRUSTED_PROXIES`; point `API_BASE_URL` at it; keep the admin console on the same origin.
* **Monitoring/alerting:** Railway healthcheck `/health` (60 s); an external uptime check on `/ready`; review `error_logs` and `admin_audit_logs` (`/admin/errors`, `/admin/audit`); error e-mail needs a non-SMTP route on Railway (not built); alert on repeated `admin.login_failed` / `admin.account_locked` rows (not built).
* **Backups:** logical `pg_dump` + restore proof (tooling in `backend/scripts`, workflow `db-backup.yml` is disabled until the owner opts in), plus the evidence volume and `FILE_ENCRYPTION_KEY` backed up together but stored separately. Restore rehearsal must be repeated for the production database before launch.
* **Rollback:** application redeploy of the previous version; database restore only for data corruption.

## 7. Readiness estimate

Dev effort to a verified staging with all priority flows exercised: about 8-12 days (Docker/CI/Railway verification, staging bring-up, provider tests, device E2E fixes), plus owner lead time. Earliest realistic closed beta: **2-3 weeks** after the owner actions are complete; public Play release **4-8 weeks** (restricted-permission review dominates).
