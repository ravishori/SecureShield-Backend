# SecureShield - Feature Completion Matrix

Built from `Features of the app.txt` (23 features + infrastructure table) and the repository state on
**2026-10-06** (backend branch `staging/railway-snapshot`, local commits only - **nothing pushed, nothing
deployed**; Flutter repo `main`, local commits only). Companion register: `SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`.

**Overall status: AMBER. This is not a 100% completion claim.**

## How to read the evidence columns

Six independent questions are answered per feature. "yes" means evidence exists in the repo; nothing is assumed.

| Column | Meaning |
|---|---|
| **IMPLEMENTED** | Code exists |
| **INTEGRATED** | The Flutter client actually calls the backend endpoint / the module is wired into the app (so it is reachable by a user) |
| **TESTED** | Automated tests exist: *unit* (pure logic), *backend-int* (real FastAPI app + real PostgreSQL, third-party providers simulated), *flutter* (widget/unit tests) |
| **E2E** | Exercised through the app on a device/emulator against a running backend |
| **EXTERNAL** | Verified against the real third-party service or the real Railway environment |
| **BLOCKED** | Missing credential/account/decision that code cannot supply |

**No feature is GREEN in this matrix.** Backend code plus backend tests is not enough: E2E and EXTERNAL are "no" for
everything except one release-APK smoke launch. This run had no external credentials, and Railway was off-limits
(its only environment is named `production`). Status vocabulary: AMBER = implemented, evidence incomplete;
BLOCKED = cannot progress without an external input; RED = not implemented.

## Verification totals (2026-10-06, stabilization pass 1)

| Check | Result |
|---|---|
| Backend `pytest` (real PostgreSQL, Alembic-migrated) | **572 passed, 0 failed** |
| `ruff check app tests` (repo-pinned 0.9.4) | All checks passed |
| `ruff format --check app tests` (0.9.4) | 152 files already formatted |
| `pip check` | No broken requirements |
| Alembic | single head `r3s4t5u6v7w8`, linear chain, no branches; migrations rehearsed on seeded data (`MIGRATION_SAFETY_REVIEW.md`) |
| **Real gitleaks 8.21.2** (official release binary, repo `.gitleaks.toml`) | HEAD tree of backend: **no leaks** (after two exact-value allowlist entries for a false positive and a fake test key). Flutter tree + history: no leaks. Backend **git history: 14 findings, all in two old commits** (`6465d52`: an old `.env`/`app/config.py`; `8fcb5af`: committed log files) - the known historical secrets whose rotation is DEFERRED. The 30 commits made in this work contain no finding |
| GitHub CI | **not run** (no push) |
| `flutter analyze` | No issues found |
| `flutter test` | 26 passed |
| `flutter build apk --release` | built, **107.5 MB**, no workaround flags |
| `flutter build appbundle --release` | built, **70.4 MB**, no workaround flags |
| Signing | **debug key** (no `key.properties`) - not uploadable to Play |

## The 23 features

| # | Feature | IMPLEMENTED | INTEGRATED | TESTED | E2E | EXTERNAL | BLOCKED / remaining gap | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | Authentication & onboarding | yes (OTP, register, refresh rotation, Google ID-token verify) | yes (OTP, register, refresh); **Google: no** (no client plugin, `/auth/google` path fixed only) | unit + backend-int (OTP flow, hashing, rotation, Google with signed tokens) | no (release APK reaches welcome screen only) | no | **Live OTP delivery**: Resend needs API key + verified domain; Twilio fails 20003. **Google**: needs OAuth client IDs + plugin. Pre-rotation refresh tokens force one re-login | AMBER / BLOCKED (delivery, Google) |
| 2 | Security dashboard | yes | yes (home screen loads `/reports/daily` and shows the server `security_score`) | backend-int (reports); no Flutter test | no | no | device E2E | AMBER |
| 3 | Alerts | yes | yes (`AlertsApi`) | backend-int | no | no | device E2E | AMBER |
| 4 | Settings & profile (theme, senior mode, language) | yes | yes | flutter (6-language key parity + render) + backend-int | no | no | Localization wired for ~56 of ~444 literals; rest English-only | AMBER |
| 5 | App risk scanner | yes | yes | flutter (risk engine) + backend-int (isolation, bounds) | no | no | device E2E | AMBER |
| 6 | Link/URL scanner | yes | yes | unit + backend-int (providers simulated) | no | **no** (real GSB/URLhaus never called) | live `GSB_API_KEY` / `URLHAUS_AUTH_KEY` on the target env | AMBER |
| 7 | Wi-Fi scanner | yes | yes | backend-int | no | no | device E2E | AMBER |
| 8 | Scam-call detection, recordings, emergency share | yes | yes (report/history/upload/share-link) | backend-int (privacy, lifecycle, share revoke/expiry, encryption) | no | no | client call-log + upload flows unverified on device; Play policy on call-log/recording permissions | AMBER |
| 9 | OTP vault | yes (device-local) | n/a (no backend model/router; `otp_vault_entries` table orphaned) | none | no | no | untested; SMS permissions are a Play-policy risk | AMBER |
| 10 | Bank OTP fraud detection | yes | yes (device) | flutter (classifier) | no | no | device E2E | AMBER |
| 11 | Device security scan | yes | yes | partial | partial (emulator flagged as expected) | no | root/Frida checks need a rooted device | AMBER |
| 12 | Remote-access detector | yes | yes | none | no | no | device-only, untested | AMBER |
| 13 | Screen-recorder detector | yes | yes | none | no | no | device-only, untested | AMBER |
| 14 | VPN monitor | yes | yes | none | no | no | device-only; `BIND_VPN_SERVICE` Play declaration | AMBER |
| 15 | Package monitor | yes | yes (`/app-monitor/sync`) | backend-int (idempotent sync, alert fix) | no | no | device E2E | AMBER |
| 16 | Network activity monitor | yes | yes (VPN-monitor destination events are batched to `POST /network/activity` by `NetworkActivityReporter`; only runs while the user has started the VPN monitor) | backend-int + flutter (6 reporter tests) | no | no | device E2E (needs the VPN monitor running on a device); privacy policy must mention destination upload | AMBER |
| 17 | Evidence locker | yes | yes (upload; download via `download_url` untested in client) | unit (format tamper/truncation) + backend-int | no | no | encryption disabled until `FILE_ENCRYPTION_KEY` is set; no rotation tooling | AMBER |
| 18 | AI security coach | yes | yes | backend-int (fake Anthropic client) | no | **no** (real model never called) | real `ANTHROPIC_API_KEY` | AMBER |
| 19 | Complaint e-mail generator | yes | yes (`/ai/generate-complaint-email`) | partial | no | no | as #18 | AMBER |
| 20 | Family safety dashboard | yes (consent flow, dashboard) | yes (Invites tab, consent badges - **not run on a device**) | backend-int (10 tests) | no | no | device run; panic fan-out to family members not implemented | AMBER |
| 21 | Panic button | yes (contacts SMS/e-mail) | yes (`/alerts/panic`) | backend-int (providers mocked) | no | **no** (nothing real sent) | working Twilio/Resend; BRD says family contacts - only emergency contacts notified | AMBER |
| 22 | Security reports | yes (daily/weekly/e-mail) | yes (daily, history, weekly); e-mail endpoint **not called by client** | backend-int (13 tests) | no | no | e-mail needs a provider; no scheduler | AMBER |
| 23 | Consent manager | yes | yes | none | no | no | device-only, untested | AMBER |

Also implemented and integration-tested this run (not numbered in the BRD): community scam news feed with
corroboration threshold, admin stats/users/enable-disable, elderly (senior) guardian alerts with real delivery
code, AI-limit sharing, message analyzer (pattern + AI, screenshot upload safety), clone detection, FIR drafts
persisted as files.

## Infrastructure / cross-cutting

| Item | Status | Evidence | Blocker / remaining gap |
|---|---|---|---|
| Real OTP delivery (Resend + Twilio + SMTP) | BLOCKED | adapter + 14 mocked tests | provider key/domain, valid Twilio creds |
| OTP hardening (CSPRNG, HMAC at rest) | AMBER (backend-int only) | integration + unit | - |
| Refresh-token rotation + replay revocation | AMBER (backend-int; client path not run on a device) | 7 new rotation tests incl. a concurrent-exchange race plus the 17 token-type tests; client stores rotated token, shares one in-flight refresh | client path not run on a device |
| Google Sign-In | BLOCKED (client) / AMBER (backend verification, backend-int) | 12 tests with locally signed tokens | OAuth client IDs |
| Biometric / device verification | AMBER | `local_auth` present; new-device alert code exists | not tested |
| Threat intel (GSB / URLhaus) | AMBER | simulated providers | live keys |
| Evidence encryption at rest | AMBER | see #17 | key + rotation |
| Admin / RBAC | AMBER | static `ADMIN_TOKEN` endpoints + warrior RBAC tested | no admin UI; no per-admin identity/audit trail for token-based actions (actions are logged without an actor); no real admin created (by instruction) |
| Localization | AMBER | see #4 | remaining screens |
| Uvicorn access-log redaction | AMBER (unit tests; not observed on a real server) | unit tests | - |
| DB backups / recovery | AMBER | scripts + runbook verified locally, tamper detection | no schedule, no off-site storage, evidence volume backup is an owner/Railway action |
| Schema drift guard | AMBER (backend-int) | tests compare ORM enums/tables/columns to the migrated DB | - |
| Lint / format / CI parity | AMBER (local only) | ruff 0.9.4 clean | GitHub CI **not run** (no push) |
| Railway migration + healthcheck | AMBER | config-as-code `.railway/railway.ts` (preDeploy `alembic upgrade head`, `/health`) verified in an earlier gate | **Six new migrations have never run on Railway.** Deploy intentionally not done; the Railway project's only environment is named `production` |
| Railway Git SHA consistency / CI-gated deploy | BLOCKED | - | no push authorised; stale check suites from other apps block `checkSuites` |
| Flutter startup / network reliability | AMBER | `API_BASE_URL` pinning, bounded optional init, release smoke on emulator | LAN-probe path (dev builds) unchanged; no E2E |
| Android release signing | **AMBER** | `build.gradle.kts` reads `key.properties` | **The produced AAB/APK are signed with the DEBUG key** - no upload keystore exists; cannot be uploaded to Play |
| R8 / resource shrinking | AMBER (build + launch only) | release APK/AAB build with R8; ML Kit missing-class rules added; APK launches on emulator | only a launch smoke test; feature regression under R8 not tested |
| `const_finder.dart.snapshot` / icon tree-shaking | RESOLVED | `flutter precache --force`; builds pass without the workaround | - |
| Play Store readiness | AMBER | `ANDROID_RELEASE_AND_PLAY.md`; unused `SEND_SMS` / `REQUEST_INSTALL_PACKAGES` removed | restricted permissions (SMS, call log), `QUERY_ALL_PACKAGES`, FGS types, data-safety form, privacy policy - owner decisions |

## Android build result and the `const_finder` issue (RESOLVED)

* Cause: the Flutter SDK cache was missing the `windows-x64/font-subset` engine artifact
  (`const_finder.dart.snapshot`, `font-subset.exe`); icon tree-shaking therefore failed. Defender had no detection.
* Fix: `flutter precache --force` (authorised download of SDK artifacts). No application code was changed for this.
* Result: `flutter build apk --release` and `flutter build appbundle --release` both succeed **without**
  `--no-tree-shake-icons` (APK 107.5 MB, AAB 70.4 MB; the earlier workaround builds were 108.1 / 71.0 MB).
* The artifacts are still signed with the debug key, so release signing remains AMBER.

## Not done (explicitly)

No push, no deployment, no Railway change, no credential created or rotated, no admin created, no real third-party
provider call, no GitHub CI run, no device E2E of the new client screens.
