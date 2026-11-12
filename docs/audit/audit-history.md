# Audit history

Newest first. Each entry records what was assessed or changed, the evidence, and the effect on [`project-status.md`](project-status.md). Entries are append-only; corrections are
new entries.

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
