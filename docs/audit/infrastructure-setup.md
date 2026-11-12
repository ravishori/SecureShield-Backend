# Infrastructure setup and owner action plan (audit and preparation only)

Prepared 2026-11-13 at backend `5303750` / Flutter `815cbd9`. **No external account was changed, no paid resource created, no e-mail sent, no key generated, nothing pushed.**
Uncommitted user work (Neon connection fix, `scripts/seed_sms_registry.py`, `start.bat`) is untouched. Existing implementations are reused; this document adds no new configuration files.

## Audit findings (read-only)

| Area | Finding |
|---|---|
| GitHub | Both repositories are **public** (you have admin rights). **No `staging` or `android-release` environment exists**; no repository secrets or variables exist. The backend repo has only a Railway-created deployment environment named `secureshield-staging / production`. |
| Railway | Logged in; projects visible: `secureshield-staging` (contains `Postgres`, `secureshield-api`, volumes; its only environment is named `production`) plus unrelated projects. No project is linked in this folder. |
| Resend | Integration already exists (`otp_service._send_email_resend`; settings `RESEND_API_KEY`, `RESEND_FROM_EMAIL`); no key or domain is configured. Guide: `docs/RESEND_SETUP.md`. |
| Android | Gradle fail-closed signing, `tool/verify_apk_signature.py`, `docs/ANDROID_RELEASE.md`, `flutter-ci.yml` exist. No keystore exists. A JDK `keytool` is available at `C:\Program Files\Java\jdk-17\bin\keytool.exe`. |
| Settings (from `app/config.py`, `app/admin_settings.py`) | **Required (no default):** `DATABASE_URL`, `MIGRATOR_DATABASE_URL`, `SECRET_KEY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `ERROR_NOTIFY_EMAIL`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_SMS_NUMBER`, `TWILIO_WHATSAPP_NUMBER` (empty values count as unset, so placeholders are needed). **Optional:** `ENVIRONMENT`, `FORCE_HTTPS`, `TRUST_PROXY_TLS`, `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`, `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `ADMIN_TOKEN`, `ADMIN_LEGACY_TOKEN_ENABLED`, `ADMIN_ACCESS_TOKEN_MINUTES`, `ADMIN_SESSION_MAX_HOURS`, `ADMIN_LOGIN_MAX_FAILURES`, `ADMIN_LOCKOUT_MINUTES`, `ADMIN_LOGIN_IP_LIMIT`, `ADMIN_TOTP_ISSUER`, `FILE_ENCRYPTION_KEY`, `FILE_ENCRYPTION_KEYS`, `FILE_ENCRYPTION_ACTIVE_KEY_ID`, `ANTHROPIC_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`, `GOOGLE_CLIENT_IDS`, `LOG_RETENTION_DAYS`, `OTP_SEND_LIMIT`, `OTP_VERIFY_LIMIT`, `API_RATE_LIMIT`, `AI_REQUESTS_PER_MINUTE`, size caps. The IaC already preserves most of them; `GOOGLE_CLIENT_IDS`, `URLHAUS_AUTH_KEY`, `FORCE_HTTPS` are not yet listed (add when needed). |

**Decision needed (Railway):** reuse the existing `secureshield-staging` project (rename its `production` environment to `staging`, and either wipe its smoke data or keep it) **or** create a new project. Recommended: reuse and rename, because the IaC, volumes and roles already describe it; a rename changes only the label. Production later = a **separate project** so it can never share a database.

## The six tasks

State vocabulary: PLANNED / BUILDING / BUILT / TESTED / REVIEWED / PRODUCTION (see `feature-completion-matrix.md`).

### 1. Resend domain and DNS - state: PLANNED
* **A. Claude automatically:** nothing external. Can validate DNS after you add records (`nslookup -type=TXT ...`, read-only) and run `scripts/otp_provider_check.py`.
* **B. You manually:** buy/choose the domain, add the DNS records at your DNS host.
* **C. Needs approval:** any DNS or Resend account change by me (I will not make any).
* **D. Navigation:** resend.com -> **Domains** -> **Add Domain** -> enter `mail.<your-domain>` -> choose region -> Resend lists the records -> copy each into your DNS host -> **Verify DNS Records**.
* **E. Records (do not invent; copy from the dashboard):** Resend generates the exact values. The record *types* are: SPF `TXT` (name and value shown), bounce `MX` (shown), DKIM `TXT` at `resend._domainkey` (public key shown), and your own DMARC `TXT` at `_dmarc.<domain>` starting `v=DMARC1; p=none; rua=mailto:<mailbox>`. Verification record template - fill in from the dashboard:

  | Type | Name | Value (from Resend) | Added | Verified |
  |---|---|---|---|---|
  | TXT (SPF) | | | | |
  | MX (bounce) | | | | |
  | TXT (DKIM) | | | | |
  | TXT (DMARC, yours) | `_dmarc` | `v=DMARC1; p=none; rua=mailto:<mailbox>` | | |

  Validation: `nslookup -type=TXT resend._domainkey.<sub-domain>` returns the key; Resend shows *Verified*.
* **F. Risks/rollback:** wrong DNS can break other mail on the domain - use a dedicated sub-domain; roll back by deleting the added records. DMARC `p=reject` too early can drop legitimate mail - start at `p=none`.

### 2. Resend API key and staging sender - state: PLANNED (code BUILT and TESTED)
* **A.** Reads configuration, runs `otp_provider_check.py` offline/`--live`, wires the variable names.
* **B.** Create the key (Resend -> **API Keys** -> **Create API Key** -> name `secureshield-staging`, permission **Sending access**, domain = your sub-domain) and put it into Railway yourself.
* **C.** The one real test send (`--send-test-email <your address>`) needs your explicit approval each time.
* **D.** Railway -> project -> `secureshield-api` -> **Variables** -> add `RESEND_API_KEY` (paste into the dashboard field, never into chat) and `RESEND_FROM_EMAIL=SecureShield <no-reply@mail.<your-domain>>`.
* **E.** `python scripts/otp_provider_check.py --live` (key authenticated or 401/403 for a send-only key), then approved single send, then register-and-login on staging.
* **F.** A leaked key can send mail as your domain: send-only, domain-restricted, staging-only key; rotate by creating a new key and deleting the old one in the dashboard. Subject contains the OTP (accepted trade-off, see `RESEND_SETUP.md`).

### 3. Android upload keystore - state: PLANNED (signing enforcement and verifiers BUILT and TESTED)
* **A.** Cannot generate it (rule: never generate or transmit signing keys). Can build/verify once you supply it, and set GitHub secrets only if you approve (values still come from your machine, never shown to me).
* **B.** Generate locally, back up, store passwords in a password manager.
* **C.** Setting the GitHub `android-release` secrets/variables (I would run `gh secret set ... < file` with hidden input; you must approve each).
* **D/E. Commands (PowerShell, on your machine; keytool prompts for passwords with hidden input):**
  ```
  New-Item -ItemType Directory -Force "$env:USERPROFILE\secureshield-keys" | Out-Null
  & "C:\Program Files\Java\jdk-17\bin\keytool.exe" -genkeypair -v -keystore "$env:USERPROFILE\secureshield-keys\upload.jks" -alias upload -keyalg RSA -keysize 2048 -validity 10000
  & "C:\Program Files\Java\jdk-17\bin\keytool.exe" -list -v -keystore "$env:USERPROFILE\secureshield-keys\upload.jks" -alias upload
  ```
  The folder is outside every repository (Gradle also refuses an in-project keystore). Copy the printed **SHA-256 certificate fingerprint** (public) - it becomes the variable `ANDROID_UPLOAD_CERT_SHA256`. Back up `upload.jks` to two separate locations (encrypted USB/vault), passwords in a password manager. Local build: copy `android/key.properties.example` to `android/key.properties` (git-ignored) with an **absolute** `storeFile`.
* **F.** Loss = upload-key reset via Play Console support (enrol in **Play App Signing** first); theft = revoke the upload key in Play Console and register a new one. Never commit, e-mail or paste the file or passwords.

### 4. Railway staging project and PostgreSQL - state: PLANNED (IaC BUILT, unverified)
* **A.** Can run read-only `railway status/list`, review `railway config plan` once a project is linked, and prepare variables lists. Will not create or apply anything without approval.
* **B.** Decide reuse-vs-new project; create the staging **project token** (below).
* **C.** Any `railway config apply`, rename, resource creation (costs money), first deploy.
* **D.** railway.com -> **secureshield-staging** -> environment selector -> **Environments** -> rename `production` to `staging` (or **New Environment**) -> confirm the **Postgres** service is *its own* database (staging only) and the volume is attached to `secureshield-api` at `/app/uploads`.
* **E.** `railway link` (select project + `staging`), `railway config plan` (review: builder RAILPACK, start command, pre-deploy `alembic upgrade head`, healthcheck `/health`), then (approved) `railway config apply`. Staging variables: `ENVIRONMENT=staging`, `DATABASE_URL`/`MIGRATOR_DATABASE_URL` as Railway reference variables to the staging Postgres private domain (never the Neon or any production URL), `TRUST_PROXY_TLS=true`, `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`, `ADMIN_LEGACY_TOKEN_ENABLED=false`. Isolation proof: print only the host/database *names* of both URLs and confirm they point at the staging Postgres.
* **F.** Rollback: redeploy the previous deployment; migrations are additive. Delete the environment/service to remove cost. Never link this folder to a production project.

### 5. GitHub `staging` and `android-release` environments - state: PLANNED (workflows BUILT, unrun)
* **A.** Can create the environments and variables via `gh api` (you have admin) once you approve; cannot create reviewers' accounts.
* **B.** Add yourself as required reviewer; decide plan/visibility.
* **C.** Creating environments and any secret.
* **D.** GitHub -> repo -> **Settings** -> **Environments** -> **New environment** (`staging` in the backend repo; `android-release` in the Frontend repo) -> **Required reviewers** -> add yourself.
* **E.** `gh api repos/ravishori/SecureShield-Backend/environments --jq '.environments[].name'` must list `staging`; same for Frontend/`android-release`.
* **F.** **Caveat:** required reviewers on **private** repositories need a paid GitHub plan; on a free plan the approval gate would not exist - then keep the deploy workflow `workflow_dispatch`-only, restrict who has write access, and treat the manual trigger as the approval. Remove an environment to roll back; secrets live inside it, so deleting it deletes them.

### 6. Staging-scoped secrets - state: PLANNED (inventory prepared)
* **A.** Can generate random application secrets *locally into the clipboard/secret store without printing them* only if you approve; recommended instead: you run the generator commands below.
* **B/C.** Entering secrets in Railway/GitHub dashboards; any `gh secret set` I run needs your approval and uses hidden input.
* **D.** Railway -> service -> **Variables**; GitHub -> **Settings** -> **Environments** -> *env* -> **Environment secrets / variables**.
* **E.** Generators (output goes straight to the clipboard, never displayed): `python -c "import secrets,subprocess;subprocess.run('clip',input=secrets.token_urlsafe(48).encode())"` for `SECRET_KEY`; `python -c "import base64,os,subprocess;subprocess.run('clip',input=base64.urlsafe_b64encode(os.urandom(32)))"` for `FILE_ENCRYPTION_KEY`. Check names only: `railway variables --kv | ForEach-Object { ($_ -split '=')[0] }`.
* **F.** Never reuse a value across staging and production; rotate by replacing the variable and redeploying. `SECRET_KEY` rotation logs everyone out and requires `reset-mfa` for admins; `FILE_ENCRYPTION_KEY` rotation needs the key-rotation script (`FILE_ENCRYPTION_KEYS`).

## Staging secrets inventory

| Name | Source | Destination | Purpose | Scope |
|---|---|---|---|---|
| `SECRET_KEY` | generate locally (48 random bytes) | Railway staging service variable | JWT signing, OTP HMAC, admin TOTP encryption | staging only; unique |
| `DATABASE_URL`, `MIGRATOR_DATABASE_URL` | Railway reference variables to the staging Postgres | Railway staging service | runtime (DML) and migration (DDL) connections | staging only; never a Neon/production URL |
| `APP_DB_PASSWORD`, `MIGRATOR_DB_PASSWORD` | generate locally | Railway staging (Postgres role setup) | passwords of `secureshield_app` / `secureshield_migrator` | staging only |
| `RESEND_API_KEY` | Resend dashboard (send-only, domain-restricted) | Railway staging service | e-mail OTP | staging key |
| `RESEND_FROM_EMAIL` (not secret) | your verified sub-domain | Railway staging service | sender | staging |
| `FILE_ENCRYPTION_KEY` | generate locally | Railway staging + offline backup (password manager) | evidence/recordings encryption at rest | staging only; losing it makes stored files unreadable |
| `ENVIRONMENT=staging`, `TRUST_PROXY_TLS=true`, `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`, `ADMIN_LEGACY_TOKEN_ENABLED=false`, `LOG_RETENTION_DAYS` (not secrets) | decisions | Railway staging service | behaviour | staging |
| `SMTP_HOST=localhost`, `SMTP_PORT=1`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `ERROR_NOTIFY_EMAIL` | placeholders / owner mailbox | Railway staging | required by settings; `localhost:1` makes the SMTP fallback fail fast | staging |
| `TWILIO_*` = `disabled` | placeholders | Railway staging | required by settings; SMS path stays off | staging |
| `ANTHROPIC_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`, `GOOGLE_CLIENT_IDS` | provider dashboards (optional; separate staging keys with spend limits) | Railway staging | AI, URL scanning, Google sign-in | staging |
| `RAILWAY_TOKEN` | Railway -> project -> **Settings -> Tokens** (project token for the *staging* environment) | GitHub `staging` environment secret (backend repo) | `railway up` in `deploy-staging` | staging environment only |
| `STAGING_URL` (variable) | Railway public domain | GitHub `staging` environment variable | smoke test | staging |
| `ANDROID_UPLOAD_KEYSTORE_B64`, `ANDROID_UPLOAD_KEYSTORE_PASSWORD`, `ANDROID_UPLOAD_KEY_ALIAS`, `ANDROID_UPLOAD_KEY_PASSWORD` | your local keystore (base64 piped from file; passwords typed hidden) | GitHub `android-release` environment secrets (Frontend repo) | signed APK/AAB in CI | release environment only |
| `ANDROID_UPLOAD_CERT_SHA256`, `API_BASE_URL` (variables, not secret) | `keytool -list -v`; staging API URL | GitHub `android-release` variables | fingerprint check; API pin | release |

**Log safety:** GitHub masks registered secrets in logs, but only exact values - workflows never print, `echo` or `set -x` a secret (the keystore is decoded into a temp file, passwords reach Gradle only as environment variables). Keep it that way when editing workflows; never pass secrets as command-line arguments or write them to artifacts (the release artifact contains only the APK/AAB).

## Registers

**Owner action register (in order):** (1) make repos private + rotate historical credentials; (2) choose the domain and add Resend DNS records; (3) create the Resend send-only key and put it in Railway; (4) generate and back up the keystore, note the SHA-256; (5) decide Railway reuse-vs-new, rename/create `staging`, create the project token; (6) create GitHub environments and add secrets/variables; (7) approve each of: first deploy, migrations on staging, the one test e-mail, first superadmin creation.

**Claude automation register:** read-only audits (`gh`, `railway`, DNS lookups); `otp_provider_check.py`; `railway config plan` review; creating GitHub environments/variables via `gh` **after approval**; building and verifying signed artifacts once the keystore exists; deploying to **staging** after approval; running migrations on staging after approval; smoke and end-to-end tests; documentation. Never: generating/transmitting signing keys, handling pasted secrets, touching production, pushing without approval.

## Readiness status (2026-11-13)

| Task | State | Done by Claude | Done by owner | Pending approval | Evidence | Next action |
|---|---|---|---|---|---|---|
| 1 Resend domain/DNS | PLANNED | instructions, record template | - | - | `docs/RESEND_SETUP.md` | owner adds the domain in Resend and DNS |
| 2 Resend key/sender | PLANNED | integration (BUILT, TESTED), env names verified from code | - | test send | 16 OTP tests, provider check | owner creates send-only key |
| 3 Android keystore | PLANNED | signing enforcement, verifiers, CI (BUILT, TESTED) | - | CI secret entry | 5 fail-closed builds, 9 tool tests | owner runs the keytool commands |
| 4 Railway staging + Postgres | PLANNED | IaC edited (unverified) | - | plan/apply, rename, deploy | `railway list`: project exists | owner decides reuse-vs-new |
| 5 GitHub environments | PLANNED | workflows BUILT (YAML valid, unrun) | - | environment creation | `gh api`: none exist | approve creation (note private-plan limitation) |
| 6 Staging secrets | PLANNED | inventory, generator commands | - | secret entry | this document | owner generates and enters secrets |

**Outstanding blockers:** repositories public; no credentials rotated; no domain/key/keystore; Railway environment still named `production`; GitHub environments absent; Twilio rejected (not needed for e-mail OTP).
