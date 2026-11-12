# Audit history

Newest first. Each entry records what was assessed or changed, the evidence, and the effect on [`project-status.md`](project-status.md). Entries are append-only; corrections are
new entries.

## 2026-11-13 - Staging deployment attempt: STOPPED at preflight

Preflight (read-only) on 2026-11-13, backend `cef1407` / Flutter `5898b1e`: repositories **PUBLIC** (both); Twilio still **rejected (20003)**, so credentials are not rotated/valid and there is no phone OTP channel; no Resend key (SMTP login works locally only); **no upload keystore** (no `key.properties`, no `SECURESHIELD_KEYSTORE_PATH`); **Docker not installed**; Railway CLI logged in but **no project linked** and no isolated staging environment exists. Working trees unchanged (only the pre-existing Neon-fix / seed / `start.bat` files). Mandatory prerequisites failed, so nothing was built, migrated, deployed or sent; no secrets were touched. Steps 2-6 remain to be run after the owner actions in `p1-closure-report.md`.

## 2026-11-13 - P1 closure verification and deployment preparation

**Commits (nothing pushed):** backend `be9faad` (provider-check double-send fix), `1bcdf16` (exact-value gitleaks allowlist for fake test passwords), `28a490c` (API docs off in production), documentation commit follows; Flutter `5898b1e` (signing doc: bundle verification, checklist). **No migration applied anywhere; no deployment; repositories still PUBLIC.**
**Evidence:** backend 1009 passed at `1bcdf16`; clean-worktree unit run 315 passed; migrations verified on a populated disposable DB; legacy-token switch verified on a real server; added-lines secret scan clean. Details in [`p1-closure-report.md`](p1-closure-report.md) and [`testing-and-qa.md`](testing-and-qa.md).
**Verdict:** no blocker CLOSED; NO-GO. Procedures prepared in [`deployment-runbook.md`](deployment-runbook.md).
**Requested but not possible without you:** staging deployment, signed APK/AAB, provider tests, device tests (private repositories, rotation, keystore, provider credentials, an approved isolated environment and a device are required).

## 2026-11-13 - P1 functional blockers remediation (five items)

**Commits (nothing pushed):** backend `f06a3d8` (OTP), `b9be388` (dependencies), `86b3ba2` (admin identity); Flutter `5d4d16a` (FLAG_SECURE), `6cd21d4` (release signing); documentation commits follow this entry.
**Migrations (both additive, nothing destroyed):** `t5u6v7w8x9y0` adds `otps.attempts` (default 0); `u6v7w8x9y0z1` creates `admin_accounts`, `admin_sessions` and adds nullable `actor_admin_id`/`actor_label` to `admin_audit_logs`. Neither was applied to Neon or any real database; head is now `u6v7w8x9y0z1`.
**Results:** backend **1006 passed** (923 before) on a clean install of the new requirements; Flutter analyze clean, **95** tests (85 before); `ruff` clean; 13/13 security mutations caught; details in [`testing-and-qa.md`](testing-and-qa.md).

| Blocker | Root cause | Change | Status after |
|---|---|---|---|
| OTP delivery | Twilio 20003 = credentials rejected by Twilio (present and well-formed; wrong/rotated token, or token of another account); no e-mail provider configured for Railway; verification also lacked a per-code attempt limit, allowed several valid codes, was non-atomic and `send-otp` had no per-source cap | `routers/auth.py`, `services/otp_codes.py`, `models/user.py`, migration `t5u6v7w8x9y0`, `scripts/otp_provider_check.py`, 13 tests | Logic hardened and tested. **Delivery still not working:** Twilio rejected live (read-only check), SMTP login works locally, nothing sent. Provider-verified: **no** |
| Release signing | `build.gradle.kts` silently fell back to the debug key | fail-closed signing config, `key.properties.example`, ignore rules, `docs/ANDROID_RELEASE.md`, `tool/verify_apk_signature.py`, `tool/compare_apks.py` + tests | Fail-closed behaviour verified (5 negative builds). **No keystore; signed build unverified** |
| Anti-screenshot | Dart called `addFlags`/`clearFlags`, Kotlin handled `enableSecure`/`disableSecure`; no screen used the wrapper | Dart rewrite (ref-count, queue, resume), Kotlin `isSecure`, 12 routes wrapped, 10 tests | Code complete and unit-tested. **Device-verified: no** |
| Dependencies | stale pins (python-jose 3.3.0, starlette 0.38.6, python-multipart 0.0.12, cryptography 43.0.3); 147 advisories in a stale venv, 36 in a clean install of the old pins | `requirements.txt` (FastAPI 0.133, Starlette >= 1.3.1, python-multipart 0.0.33, cryptography 50.0.2, PyJWT 2.15.1; passlib removed; floors), `google_auth.py` and 7 tests ported | Clean install: 0 runtime advisories; Dart 0 (OSV, 207 packages). Docker/Railway/CI not verified |
| Admin identity + MFA | single shared static token | models, migration, `admin_security`, `admin_access`, `admin_auth`, CLI, console page, 4 older tests updated | Code complete, tested, mutation-checked, browser-verified locally. Not deployed; legacy token still enabled by default |

**Defects found in my own work and fixed before commit:** naive-UTC timestamps in the admin token (tokens appeared expired by the UTC offset); a JS escaping slip that broke the console page (found only in the browser); a superadmin self-removal race (reproduced 3/3, fixed with an advisory lock); four surviving mutants turned into tests.
**Note:** python-jose was used by `routers/auth.py` and `services/google_auth.py`; both now use PyJWT (`jwt`, `PyJWK`).
**Percentages:** implementation 74.5, frontend 75.2, backend 85.7, integration 63.7, testing/QA 45.0, security 60.7, deployment 34.5, production readiness 40 (raw 55.5). **Verdict: NO-GO** (unchanged).
**Unresolved:** repositories still public (S-01); no live OTP; no keystore; no device test; legacy admin token enabled; nothing deployed.
**Manual verification steps (not done):** (1) Twilio Console: compare SID/token, then `python scripts/otp_provider_check.py --live`; (2) after credentials are fixed, `--send-test-email <your address>` / `--send-test-sms <your number>`; (3) device: open Evidence, OTP vault, Family and confirm a screenshot is blocked/black and the recents thumbnail is blank, then confirm an unprotected screen can be captured again; (4) create the keystore, build, `python tool/verify_apk_signature.py <apk> --expect-sha256 <fingerprint>`; (5) `python -m app.cli.admin_accounts create ...`, sign in at `/api/v1/admin/console`, enrol MFA, then set `ADMIN_LEGACY_TOKEN_ENABLED=false` and confirm the old token is refused; (6) rebuild the venv and Docker image from `requirements.txt` and re-run `pip-audit`.

## 2026-11-12 - Comprehensive audit and creation of `docs/audit/`

**Scope:** both repositories (backend `30664ce`, Flutter `ac5cd50`), all documentation, code, tests, builds, dependencies, GitHub state (read-only).
**Application code changed: none.** Files created: the nine documents in this folder, plus `CLAUDE.md` in both repositories with the maintenance rule.

**Executed:** backend pytest **923 passed**; `flutter analyze` clean; `flutter test` **85 passed**; `flutter build apk --release` built a 108.4 MB debug-key-signed APK;
`pip-audit` on the backend environment (**147 advisories / 16 packages**); route enumeration (107 routes); read-only `gh` queries. Details in
[`testing-and-qa.md`](testing-and-qa.md).

**New findings (not in the earlier registers):**

| Finding | Severity | Evidence |
|---|---|---|
| Both GitHub repositories are PUBLIC while history holds exposed credentials (registers said the repository had been made private) | Critical | `gh repo view ... --json visibility` -> `PUBLIC` for both repositories |
| 147 known dependency advisories in 16 packages, including the JWT library and Starlette/python-multipart | High | `pip-audit` |
| Anti-screenshot protection never works and is not applied anywhere (the feature list says it is built) | Medium | `screenshot_prevention.dart:51,64` vs `MainActivity.kt:157-158`; no callers |
| OpenAPI/Swagger exposed in production | Medium | `app/main.py:42` |
| Container runs as root | Medium | `Dockerfile` has no `USER` |
| Flutter repository has no CI workflow (the only Flutter jobs are in a `.github` folder that belongs to no repository) | Medium | `git ls-files` in `flutter_app`; `D:\ravishori\SecureShieldApp\.github\workflows\ci.yml` is outside both repos |
| `D:\` is itself a Git repository with the whole drive untracked | Low-Medium | `git rev-parse --show-toplevel` from the project folder returned `D:/` |

**Corrections to earlier statements:**

* Router modules are **24** (`docs/AUDIT_2026-10-19.md` said 25 because `__init__.py` was counted; corrected in place).
* GitHub CI **did run once** (2026-10-05, green, commit `976ce42`); the matrix of 2026-10-06 and register FG-121 say "not run / push required". `origin/staging/railway-snapshot` exists; the local branch is 61 commits ahead.
* The 2026-10-06 matrix says "nothing pushed": the staging branch had been pushed on 2026-10-05.
* `Features of the app.txt`: "13 routers / 14 models / all routers JWT-protected" -> actual 24 routers, 107 routes, 30 ORM tables, 15 intentionally unauthenticated routes.

**Percentages recorded:** implementation 73, frontend 74, backend 85, integration 63, testing/QA 44, security hardening 52, deployment 32, production readiness 40 (raw 52).
**Verdict:** NO-GO.

## 2026-10-19 - Audit follow-ups (FG-034 guard, FG-070 retrieval)

* Backend `742380c`: startup purge no longer deletes everything when `LOG_RETENTION_DAYS` < 1; 5 new tests; audit note `../AUDIT_2026-10-19.md` created; stale FG-061/062/063/070 corrected. Backend `30664ce`: FG-070 documentation.
* Flutter `65ac73b`: evidence items can be opened/shared (tap -> download -> share sheet); 12 tests. Flutter `ac5cd50`: shared copies kept for 30 minutes instead of being deleted when the screen closes; loopback test of the 401-refresh retry on a streamed download; 85 Flutter tests total.
* Evidence at that time: backend suite 918 passed (+5), Flutter analyze clean, 69 -> 85 tests. Device behaviour unverified.
* Twilio `20003` diagnosed (credentials present and well-formed; rejected by Twilio; cause needs the Console).

## 2026-10-18 - Neon PostgreSQL migration (schema + data), cutover prepared

* Schema built with Alembic on an empty Neon database; data copied with a guarded single-transaction restore; validated against a rehearsal reference (32 tables, 285 constraints, 92 indexes, 3 sequences, 23,313 rows, 26 FKs with 0 orphans). Reports in `../neon-migration/`.
* Application cutover not performed; local app was started against Neon for a read-only smoke test (`/health`, `/ready`, `/version`, `/admin/stats` all 200; Alembic `s4t5u6v7w8x9`; `error_logs` rows preserved with `LOG_RETENTION_DAYS=365`). The connection fix needed for Neon remains uncommitted.
* Local PostgreSQL password was printed once in a test assertion; rotation deferred by the owner.

## 2026-10-06 - Stabilisation and release-gate passes (register)

* Backend 592 -> 886 tests; Flutter 26 -> 69; findings FG-130..167 fixed (family consent, BOLA on scans, enum drift, refresh rotation, OTP HMAC, admin throttle, client-IP trust, log privacy, VPN black-hole, encryption IV, screen recorder).
* Manual emulator runs against a local backend with an outbox (login, panic, family, VPN, bank OTP, recording, share). Source: `../SECURESHIELD_FEATURE_COMPLETION_MATRIX.md`.

## 2026-10-05 - Staging deployment and pre-push security gate (register)

* Railway staging (API, PostgreSQL, volume) deployed by CLI upload; pre-push gate, gitleaks, one GitHub CI run (green, `976ce42`). Findings FG-001..FG-063 recorded in `../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`.
