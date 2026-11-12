# Testing and QA

All runs were executed on 2026-11-12 on the audit workstation (Windows 11, PowerShell, backend Python 3.11 venv, Flutter stable at `D:\flutter`, Postgres 18
local server). Nothing was run against Neon, Railway or any third-party provider. Test output was captured to files outside the repositories and only
summary lines were read, so no credential could be echoed.

## Remediation run, 2026-11-13 (P1 blockers)

Backend tests ran on a **clean virtual environment built from the new `requirements.txt`** (so they exercise the upgraded stack), against the disposable local
`*_test` database (never Neon or a real database; `.env` ignored). All output was captured to files and only summary lines were read.

| # | Command (from the repository folder) | Result |
|---|---|---|
| 1 | `backend`: launcher `run_with_local_test_db.py -- <clean-venv>\python -m pytest -q --tb=short -p no:cacheprovider -rs` | **1006 passed, 0 failed, 0 skipped**, 124 warnings, 533 s (was 923; +83: OTP hardening 13, admin accounts 31, admin CLI 3, admin security unit 33, console page 3) |
| 2 | First run on the upgraded stack (before porting the JWT forgery test) | 922 passed, 1 failed (`alg=none` test could not be encoded by PyJWT) - fixed by crafting the token by hand |
| 3 | Run after the admin work (before aligning four older tests with the new "no credentials = 401" contract) | 992 passed, 4 failed (the old single-token contract) - tests updated, behaviour documented |
| 4 | `ruff check app tests scripts` and `ruff format --check` | clean (184 files) |
| 5 | `pip-audit` on the old environment / a clean install of the old pins / a clean install of the new pins | 147 advisories (16 packages) / 36 (7 packages) / **11 in 2 packages (pip 24.0, setuptools 65.5.0: build tooling only)** |
| 6 | OSV batch query for every hosted package in `flutter_app/pubspec.lock` (207 packages; names and versions only) | **0 advisories** (OSV pub coverage is partial; Gradle/AndroidX dependencies not scanned) |
| 7 | `flutter analyze --no-pub` | no issues |
| 8 | `flutter test --no-pub` | **95 passed** (was 85; +10 `screenshot_prevention_test.dart`) |
| 9 | `python -m unittest discover -s tool -p test_apk_tools.py` | 7 passed |
| 10 | `flutter build apk --release` with: no config / placeholder `key.properties` / missing keystore / keystore inside the project / empty alias | **all five fail in ~9 s with a clear message, nothing built, no password printed** |
| 11 | `tool/verify_apk_signature.py` on the stale 2026-11-12 APK (debug-signed) | **FAIL** (CN=Android Debug detected, v2 verified) - proves the detector |
| 12 | Real app start (`uvicorn app.main:app`, lifespan on) on FastAPI 0.133 / Starlette 1.10 against the test database | startup hook ran; `/health`, `/ready`, `/version`, `/docs`, `/api/v1/admin/console` all 200 |
| 13 | Admin console driven in the built-in browser against that local server: sign in -> forced password change -> authenticator enrolment (code computed from the displayed secret) -> 8 recovery codes shown once -> dashboard; sign out; password-only login rejected; old password rejected; password + fresh code accepted | all as designed; found and fixed a JS escaping bug on the way |
| 14 | `scripts/otp_provider_check.py` offline and `--live` (read-only, nothing sent) | Twilio **REJECTED 20003**; SMTP login **authenticated**; Resend not configured |
| 15 | Mutation checks (`mutate.py`, 13 mutations of OTP and admin controls; each file restored after) | **13/13 caught** after adding 4 tests for the 4 that first survived (see below) |

Mutation survivors found and killed: (a) resend-invalidation was masked by the "newest code only" rule - new test burns the newest code and checks the older one stays dead;
(b) the dependency's `is_active` check was masked by session revocation - new test deactivates the row directly; (c) the token-type check was masked by an id lookup - new test creates an end user with the
same id as the admin; (d) the last-superadmin guard was masked by the self-guard - new concurrency test (also revealed the real race fixed with an advisory lock; fails 3/3 without the lock).

**Not run / unverified in this session:** any real device or emulator (FLAG_SECURE effect, share sheet, signed APK install), a signed release build, any real provider send, the Docker/Railway build, GitHub CI.

## Closure verification run, 2026-11-13 (backend `1bcdf16` / `28a490c`)

| # | Command | Result |
|---|---|---|
| 1 | full backend suite on the clean venv at `1bcdf16` | **1009 passed, 0 failed, 0 skipped** (449 s) |
| 2 | clean `git worktree` of HEAD, `pytest tests/unit` | **315 passed** - the commits do not depend on the uncommitted Neon-fix files |
| 3 | temporary migration test on a populated disposable DB (50 OTP rows + 1 audit row): downgrade to `s4t5u6v7w8x9`, upgrade to head, repeat upgrade, old-style INSERTs, downgrade, re-upgrade; plus `test_schema_drift` | **passed** (test file deleted afterwards, not committed) |
| 4 | real server runs with `ADMIN_LEGACY_TOKEN_ENABLED` unset / `false` / `true` | 200 / **401** / 200 for the legacy token; no credentials always 401 |
| 5 | regex secret scan of all added lines in committed work (backend 4,327, Flutter 1,219) | 0 credential patterns, 0 credential files, 0 personal e-mails; gitleaks not run |
| 6 | `tests/unit/test_api_docs_gate.py` + startup checks | 20 passed; docs routes 404 in production mode |
| 7 | `otp_provider_check.py` send path with the provider stubbed | exposed a double-send defect (fixed, 3 mutation-checked tests) |

Not run: Docker build (Docker absent), Railway/staging deploy, GitHub CI, any device, any real provider send, signed build.

## Baseline commands executed on 2026-11-12

| # | Command (from the repository folder) | Result |
|---|---|---|
| 1 | `backend`: `python docs/neon-migration/scripts/run_with_local_test_db.py -- .venv\Scripts\python.exe -m pytest -q --tb=no -p no:cacheprovider -rs` (launcher points `TEST_DATABASE_URL` at the existing disposable local `*_test` database; conftest ignores `.env`) | **923 passed, 0 failed, 0 skipped**, 22 deprecation warnings, 477 s |
| 2 | `backend`: `ruff check app tests scripts` and `ruff format --check app tests scripts` (ruff 0.9.4, run 2026-10-19; unchanged code since) | all checks passed / formatted |
| 3 | `backend`: `python -m pip check` (2026-10-19) | no broken requirements |
| 4 | `pip-audit --path backend\.venv\Lib\site-packages` (tool installed in a throw-away venv outside the project; queries PyPI/OSV with package names only) | **147 known vulnerabilities in 16 packages** (see `security-audit.md` S-02) |
| 5 | `flutter_app`: `flutter analyze --no-pub` | **No issues found** (66 s) |
| 6 | `flutter_app`: `flutter test --no-pub` | **85 passed, 0 failed** (11 test files) |
| 7 | `flutter_app`: `flutter build apk --release --no-pub` | **Built `app-release.apk`, 108.4 MB, 6.0 min**; signed with the **debug key** (no `android/key.properties`, see `build.gradle.kts`); not installed or launched in this audit |
| 8 | Route enumeration of the FastAPI object (`app.routes`, `SECURESHIELD_ENV_FILE=.env.test`) | 107 routes; the only routes without a JWT dependency are the expected 15 (list in `security-audit.md`) |
| 9 | `gh run list` / `gh repo view` (read-only GitHub queries) | backend CI: one run, **success**, 2026-10-05, commit `976ce42`; Flutter repo: no workflow runs; both repos PUBLIC |

Earlier same-session verification (2026-10-18/19, repeated here as history): migration guard tests 70/70; evidence retrieval 13 + 3 new Flutter tests;
evidence-related backend tests 143/143; 5 new purge tests (`tests/integration/test_startup_error_log_purge.py`, mutation-checked).

## Backend suite composition (63 files, 1006 tests as of 2026-11-13; 58 / 923 on 2026-11-12)

* Integration (35 files, real PostgreSQL, Alembic-migrated, providers simulated): auth and OTP flow/hardening/logging, token types, refresh rotation, Google sign-in with locally signed tokens, evidence/recordings/upload policy/encryption, family consent, device-scoped data, admin users/throttle/token compare/bootstrap, account deletion, error-log exposure (3 files), reports, message analyzer, link scanner, AI coach, community news, elderly, emergency contacts, cyber warriors, client-IP rate limiting, schema drift, startup purge.
* Unit (23 files): JWT, rate limiter(s), CORS, startup checks, log scrubber, safe headers, client IP parsing, database URL normalisation/engine config (the last two cover uncommitted code), file-key rotation, backup scripts, threat-intel clients, RBAC/schema validation.
* Security regression tests are mutation-checked per the register (e.g. FG-166: 9 mutations; FG-167: 9; FG-165: 9; purge guard: 3 cases fail without the guard).

## Coverage

* **Line/branch coverage was not measured**: no coverage tool is installed in the project environment and nothing was installed into it.
* Structural proxy: 63 of 107 routes are referenced by a literal path in test source; the remaining 44 include family, admin-users, reports and message-analyzer routes that **are** exercised by dedicated files using path variables, so the true route coverage is higher but unmeasured. Not exercised by any test (by name search): `admin_console` page, several `video_call` and `community_scam` routes.
* Flutter: 12 test files for 160 source files; one widget-level test (FLAG_SECURE lifecycle), no screen-level tests; only `auth` (Google), `evidence`, `otp_vault`, `screen_recorder`/detector, the network reporter, encryption, similarity metrics and localisation have dedicated tests; most of the 37 feature folders have none.
* Kotlin: no unit or instrumentation tests for any of the 12 files / 2,677 lines.

## Not verified (environment limits)

| Area | Why |
|---|---|
| Real devices / emulator in this audit | none used; the last manual emulator runs were 2026-10-06 against a local backend with an outbox, and are history, not current evidence |
| Release APK behaviour (install, launch, R8 effects) | built only; earlier run on 2026-10-06 launched an equivalent APK on an emulator |
| Third-party providers | no valid credentials in scope; none were used |
| GitHub CI at the current SHA | the branch is 61 commits ahead of the last CI run; no push was made |
| Flutter/Dart dependency vulnerabilities | no scanner |
| Gitleaks over history | tool not installed on this machine |
| Load, soak, multi-worker behaviour | in-memory limiter and single volume; never exercised |
| Accessibility, localisation quality | 44% string coverage; translations unreviewed |
| Backup restore at the current schema | tooling tested earlier (2026-10-06); Neon migration rehearsals (2026-10-18) restored dumps successfully |

## QA controls scored (10 controls, weighted; result 45.0% on 2026-11-13, 44.2% before)

| Control | Weight | Credit | Basis |
|---|---|---|---|
| Backend suite passes on real PostgreSQL | 3 | 1.00 | run 1 |
| Backend coverage measured | 2 | 0 | not measured |
| Routes referenced by tests | 2 | 0.75 | 63/107 literal + dedicated files |
| Flutter unit/widget tests | 3 | 0.30 | 95 tests, thin coverage, 1 widget-level lifecycle test |
| Static analysis clean | 1 | 1.00 | runs 2, 5 |
| Kotlin tests | 2 | 0 | none |
| Device end-to-end | 2 | 0.50 | manual, historic, local backend |
| External provider verification | 2 | 0 | none |
| CI executing suites | 2 | 0.30 | backend once (stale SHA, 65 commits old); Flutter none |
| Mutation-checked security tests | 1 | 1.00 | register + this audit |

## Recommended QA work (see roadmap)

Add `pytest-cov` to the dev requirements and set a floor; add a Flutter workflow to the Flutter repository (the only `ci.yml` containing Flutter jobs sits in
`D:\ravishori\SecureShieldApp\.github`, which belongs to no repository); add Kotlin unit tests for the OTP regexes and the VPN blocklist; add screen widget tests for the evidence
and family flows; run the release APK on a device matrix (Android 10, 13, 15).
