# P1 closure verification report

Verified **2026-11-13** at backend `28a490c` (`staging/railway-snapshot`) and Flutter `5898b1e` (`main`). Nothing was pushed, deployed, rotated or changed in any real environment.
Rule applied: a blocker is **CLOSED** only with evidence at all four levels. **No blocker is closed.**

## Status per blocker

| Blocker | Code implemented | Automated tests passed | External integration verified | Production deployment verified | Closure |
|---|---|---|---|---|---|
| 1. OTP delivery | **Yes** (`f06a3d8`, `be9faad`) | **Yes** (13 hardening + 3 provider-check tests; mutation-checked) | **No** - Twilio rejects the credentials (20003, live read-only check); SMTP login works locally but no message was sent; no Resend key | **No** | **OPEN** (external) |
| 2. Release signing | **Yes** (`6cd21d4`, `5898b1e`) | **Yes** for fail-closed behaviour (5 failing-build runs) and the tools (7 unit tests); a successful signed build is **not** tested | **No** - no upload keystore exists, no signed APK/AAB, no fingerprint comparison | **No** | **OPEN** (owner keystore) |
| 3. Anti-screenshot | **Yes** (`5d4d16a`) | **Yes, mocked** (10 tests incl. Kotlin contract) | **No** - no device/emulator run; the real window flag is unobserved | **No** | **OPEN** (device) |
| 4. Dependencies | **Yes** (`b9be388`, `28a490c`) | **Yes** - 1009 backend tests on a clean install of `requirements.txt` | **Scan only:** `pip-audit` clean for runtime packages, OSV 0 for 207 Dart packages. Docker build, Railway build, CI: **not run** | **No** | **CODE-COMPLETE, not closed** |
| 5. Admin identity + MFA | **Yes** (`86b3ba2`) | **Yes** (67 tests, 13/13 mutations caught, legacy switch verified on a real server) | **Local only:** console flow driven in a browser against a local server; no real environment, no admin created | **No** | **OPEN** (deploy + first superadmin + legacy off) |

## Verification of the seven requested points

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Security fixes committed; trees understood | **PASS** | All P1 work is committed. Backend uncommitted files are exactly the pre-existing Neon connection fix (`.env.example`, `app/config.py`, `app/database.py`, `tests/unit/test_db_url_normalization.py`, `tests/unit/test_database_engine.py`) plus your `scripts/seed_sms_registry.py` and `start.bat`; none were touched or committed. A clean checkout of HEAD (git worktree) passes all 315 unit tests, so the commits do not depend on the uncommitted files. Flutter tree is clean. Full suite at HEAD before the docs gate: 1009 passed. |
| 2 | No credentials in the new commits | **PASS** (scanner-limited) | Regex scan of all added lines (backend `742380c..HEAD`: 4,327 lines / 45 files; Flutter `0e08d30..HEAD`: 1,219 lines / 29 files): 0 Anthropic/Twilio/Google/GitHub/AWS/Slack keys, 0 private-key blocks, 0 URLs with passwords, 0 long hex secrets, 0 keystore/`.env` files, 0 personal e-mail addresses. 8 quoted password-like strings are deliberate test fixtures (now allowlisted by exact value in `.gitleaks.toml`). **gitleaks itself was not run** (not installed; no download made), so CI is the real confirmation. |
| 3 | Migrations compatible and deployment-ready | **PASS on a disposable database; not applied anywhere real** | `t5u6v7w8x9y0` adds `otps.attempts` NOT NULL DEFAULT 0; `u6v7w8x9y0z1` creates two tables and adds two nullable audit columns. Verified on a populated test DB: upgrade keeps all 50 OTP rows (`attempts`=0) and the audit row (actor NULL); a second upgrade is a no-op; old-application INSERTs (no new columns) still work on the new schema (so migrate-then-deploy is safe and an old app keeps running); downgrade keeps pre-existing data and removes only the new objects (it **destroys admin accounts/sessions** if any exist); re-upgrade works; `test_schema_drift` passes. Neon is at `s4t5u6v7w8x9` (2026-10-18 state, not re-read today). |
| 4 | Legacy admin-token disablement tested | **PASS** | Integration test (`ADMIN_LEGACY_TOKEN_ENABLED=false` -> 401 while named admins keep working; throttle not consumed) **and** a real server run on 2026-11-13: unset -> 200 + startup notice; `false` -> **401** and no notice; `true` -> 200. Default stays **true** (migration path) until you switch it off. |
| 5 | OTP provider verification ready for owner-authorised testing | **PASS after a fix** | `scripts/otp_provider_check.py` offline (no network), `--live` (read-only auth), `--send-test-email/--send-test-sms` (opt-in real send of dummy `000000`). **Verification found a real defect:** the send block was duplicated and would have sent every test message twice - fixed in `be9faad` with 3 mutation-checked tests. Nothing was sent. |
| 6 | Android signing instructions complete | **PASS** | `flutter_app/docs/ANDROID_RELEASE.md`: keystore creation, Play App Signing, env/`key.properties` inputs, enforced rules, APK verification, bundle verification (`jarsigner`), fingerprint source, versionCode, pre-upload checklist, explicit "not verified" status. `key.properties.example` and ignore rules in place. |
| 7 | Device, Docker, Railway, CI gaps documented | **PASS** | Listed below and in `deployment-runbook.md`. |

## Defects found during this verification

1. `otp_provider_check.py` double-sent opt-in test messages (fixed, tested).
2. CI secret scan would likely have tripped on deliberate fake passwords in the new tests (exact-value allowlist added; unverified until CI runs).
3. Interactive API docs were exposed in every environment (fixed: off when `ENVIRONMENT=production`, `28a490c`, 3 tests).
4. Still open: Dockerfile runs as root and has no image `HEALTHCHECK` (not changed: a non-root user would need the Railway volume to be writable and cannot be tested without Docker).

## Unverified gaps (environment or authority)

| Area | Why unverified | How it closes |
|---|---|---|
| Real device / emulator | none attached; AVD not started | run the device steps in `audit-history.md` (FLAG_SECURE, share sheet, signed install) |
| Docker image | Docker is not installed on this machine | `docker build` of `backend/Dockerfile`, run, `/health`, `/ready`, `/version` |
| Railway | only environment is named `production`; deploying needs your approval and the repositories are public | create an isolated staging environment (new project/environment, own database and secrets) after S-01 |
| GitHub CI | no push (repositories are public with exposed history) | one green `backend-ci` run on the release SHA; add a Flutter workflow |
| Real providers | Twilio credentials rejected; no e-mail provider | fix credentials, run `--live`, then `--send-test-*` |
| Signed build | no keystore | create it, build APK and AAB, run the verifiers |

## Exact remaining owner actions (in order)

1. **Make both GitHub repositories private** and **rotate every credential** that ever appeared in history (Anthropic, Twilio, Gmail app password, Safe Browsing, Azure Translator, local Postgres password, `SECRET_KEY`, `ADMIN_TOKEN`); decide history rewrite. Do this **before** any push.
2. In the Twilio Console, compare/replace the Account SID and Auth Token; choose an e-mail provider (Resend recommended on Railway) and verify its sender domain.
3. Create the Android upload keystore outside the repository and back it up; supply it via `SECURESHIELD_*` or `android/key.properties`.
4. Approve creation of an isolated **staging** environment (separate database, secrets, domain) - or tell me which existing one may be used.
5. After approval, apply the two additive migrations to staging first, create the first superadmin (`python -m app.cli.admin_accounts create`), enrol MFA, set `ADMIN_LEGACY_TOKEN_ENABLED=false`.
6. Decide the retention periods and the SMS/call-log feature scope (Play policy).
7. Provide a physical Android device (or approve starting the emulator) for the device checks.

## Recommendation

**NO-GO for production. NO-GO for any push or public deployment today.** Reasons: repositories are public with unrotated credentials (blocker by your own rule), no working OTP channel, no signing key, no environment has run the new code, no device test. The code side is largely ready for a **staging** deployment once actions 1-4 are done.
