# Testing and QA

All runs were executed on 2026-11-12 on the audit workstation (Windows 11, PowerShell, backend Python 3.11 venv, Flutter stable at `D:\flutter`, Postgres 18
local server). Nothing was run against Neon, Railway or any third-party provider. Test output was captured to files outside the repositories and only
summary lines were read, so no credential could be echoed.

## Commands executed and results

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

## Backend suite composition (58 files, 923 tests)

* Integration (35 files, real PostgreSQL, Alembic-migrated, providers simulated): auth and OTP flow/hardening/logging, token types, refresh rotation, Google sign-in with locally signed tokens, evidence/recordings/upload policy/encryption, family consent, device-scoped data, admin users/throttle/token compare/bootstrap, account deletion, error-log exposure (3 files), reports, message analyzer, link scanner, AI coach, community news, elderly, emergency contacts, cyber warriors, client-IP rate limiting, schema drift, startup purge.
* Unit (23 files): JWT, rate limiter(s), CORS, startup checks, log scrubber, safe headers, client IP parsing, database URL normalisation/engine config (the last two cover uncommitted code), file-key rotation, backup scripts, threat-intel clients, RBAC/schema validation.
* Security regression tests are mutation-checked per the register (e.g. FG-166: 9 mutations; FG-167: 9; FG-165: 9; purge guard: 3 cases fail without the guard).

## Coverage

* **Line/branch coverage was not measured**: no coverage tool is installed in the project environment and nothing was installed into it.
* Structural proxy: 63 of 107 routes are referenced by a literal path in test source; the remaining 44 include family, admin-users, reports and message-analyzer routes that **are** exercised by dedicated files using path variables, so the true route coverage is higher but unmeasured. Not exercised by any test (by name search): `admin_console` page, several `video_call` and `community_scam` routes.
* Flutter: 11 test files for 160 source files; no screen-level widget test; only `auth` (Google), `evidence`, `otp_vault`, `screen_recorder`/detector, the network reporter, encryption, similarity metrics and localisation have dedicated tests; most of the 37 feature folders have none.
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

## QA controls scored (10 controls, weighted; result 44%)

| Control | Weight | Credit | Basis |
|---|---|---|---|
| Backend suite passes on real PostgreSQL | 3 | 1.00 | run 1 |
| Backend coverage measured | 2 | 0 | not measured |
| Routes referenced by tests | 2 | 0.75 | 63/107 literal + dedicated files |
| Flutter unit/widget tests | 3 | 0.25 | 85 tests, thin coverage, no screens |
| Static analysis clean | 1 | 1.00 | runs 2, 5 |
| Kotlin tests | 2 | 0 | none |
| Device end-to-end | 2 | 0.50 | manual, historic, local backend |
| External provider verification | 2 | 0 | none |
| CI executing suites | 2 | 0.30 | backend once (stale SHA); Flutter none |
| Mutation-checked security tests | 1 | 1.00 | register + this audit |

## Recommended QA work (see roadmap)

Add `pytest-cov` to the dev requirements and set a floor; add a Flutter workflow to the Flutter repository (the only `ci.yml` containing Flutter jobs sits in
`D:\ravishori\SecureShieldApp\.github`, which belongs to no repository); add Kotlin unit tests for the OTP regexes and the VPN blocklist; add screen widget tests for the evidence
and family flows; run the release APK on a device matrix (Android 10, 13, 15).
