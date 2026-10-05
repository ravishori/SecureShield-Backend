# SecureShield - Feature Completion Matrix

Built from `Features of the app.txt` (23 features + infrastructure table) and the repository state on
**2026-10-06** (backend branch `staging/railway-snapshot`, local commits only - **nothing pushed, nothing
deployed**; Flutter repo `main`, local commits only). Companion register: `SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`.

**Overall status: AMBER. This is not a 100% completion claim.**

## How to read the evidence columns

Each row separates *how far a feature has actually been verified*. A "yes" means evidence exists in the repo;
nothing is assumed.

| Column | Meaning |
|---|---|
| **Impl** | Code exists and is wired into the app/router |
| **Unit/local** | Pure-logic tests or manual local run |
| **Integration** | Automated test through the real FastAPI app against a real PostgreSQL database (provider calls simulated) |
| **E2E** | Exercised through the Flutter app on a device/emulator against a running backend |
| **External** | Verified against the real third-party service / the real Railway environment |
| **Blocker** | Missing credential, account or decision that code cannot supply |

E2E and External are **"no" almost everywhere**: this run had no external credentials, and Railway was off-limits
(its only environment is named `production`; deployment was not authorised). The only device evidence is that the
release APK installs and reaches the welcome screen on the emulator with the pinned HTTPS backend.

Status: GREEN = implemented + integration-tested, remaining gaps are only external verification;
AMBER = implemented but a material part is untested, partial, or a security/design gap remains;
RED = not implemented; BLOCKED = cannot proceed without an external input; DEFERRED = owner decision to postpone.

## Verification totals (2026-10-06)

| Check | Result |
|---|---|
| Backend `pytest` (real PostgreSQL, Alembic-migrated) | **572 passed, 0 failed** |
| `ruff check app tests` (repo-pinned 0.9.4) | All checks passed |
| `ruff format --check app tests` (0.9.4) | 148 files already formatted |
| Alembic | single head `r3s4t5u6v7w8` |
| `pip check` | no broken requirements |
| Secret scan | **own regex scan of tracked files**: only known placeholders/fixtures. **Real gitleaks was not run** (binary not installed; CI runs it) |
| `flutter analyze` | No issues found |
| `flutter test` | 26 passed |
| `flutter build apk --release` / `appbundle --release` | see "Android" below |

## The 23 features

| # | Feature | Status | Impl | Unit/local | Integration | E2E | External | Blocker / remaining gap |
|---|---|---|---|---|---|---|---|---|
| 1 | Authentication & onboarding | **AMBER** | yes | yes | yes (OTP flow, hashing, rotation, Google) | no (release APK reaches welcome screen only) | no | **Live OTP delivery BLOCKED**: Resend needs an API key + verified sender domain; Twilio fails with 20003 (credentials). **Google client BLOCKED**: needs real OAuth client IDs (`GOOGLE_CLIENT_IDS`) and the `google_sign_in` plugin. Pre-rotation refresh tokens force one re-login. |
| 2 | Security dashboard | AMBER | yes | n/a | yes (`/reports/daily` score) | no | no | Dashboard tiles use local device scoring; server `security_score` is not yet shown in the client |
| 3 | Alerts | GREEN | yes | n/a | yes (owner-only, malformed ids, 7 missing enum values fixed) | no | no | Device E2E |
| 4 | Settings & profile (theme, senior mode, language) | AMBER | yes | yes (6-language key parity + render tests) | yes (profile, senior config) | no | no | Localization wired for ~56 literals on onboarding/auth/dashboard/profile/settings only; most other screens (~390 literals) still English-only |
| 5 | App risk scanner | GREEN | yes | yes (Flutter risk engine) | yes (tenant isolation, bounds) | no | no | Device E2E |
| 6 | Link/URL scanner | AMBER | yes | yes | yes (GSB + URLhaus simulated with MockTransport, 12+ cases) | no | **no** (never called the real Safe Browsing / URLhaus) | Needs `GSB_API_KEY` / `URLHAUS_AUTH_KEY` on the target environment to verify live |
| 7 | Wi-Fi scanner | GREEN | yes | yes | yes (owner-scoped history) | no | no | Device E2E |
| 8 | Scam-call detection + recordings + emergency share | AMBER | yes | yes | yes (history privacy, block idempotent, recording lifecycle, share link revoke/expiry) | no | no | Client call-log detection and recording upload not E2E-verified; Play policy on call-log/recording permissions |
| 9 | OTP vault | AMBER | yes | partial | no backend (device-local feature) | no | no | Biometric gate and SMS interception are device-only; not tested this run; SMS permissions are a Play-policy risk |
| 10 | Bank OTP fraud detection | AMBER | yes | yes (classifier tests) | n/a | no | no | Device E2E |
| 11 | Device security scan | AMBER | yes | partial | n/a | partial (emulator is flagged as expected) | no | Root/Frida checks need a rooted device |
| 12 | Remote-access detector | AMBER | yes | no | n/a | no | no | Device-only; untested |
| 13 | Screen-recorder detector | AMBER | yes | no | n/a | no | no | Device-only; untested |
| 14 | VPN monitor | AMBER | yes | no | n/a | no | no | Device-only; `BIND_VPN_SERVICE` needs Play declaration |
| 15 | Package monitor | GREEN | yes | yes | yes (idempotent sync, alert creation fixed) | no | no | Device E2E |
| 16 | Network activity monitor | AMBER | yes | yes | yes (device ownership, scoping) | no | no | **Client does not call `POST /network/activity`** (no producer of traffic data on the device) |
| 17 | Evidence locker | AMBER | yes | yes (format tamper/truncation) | yes (upload/download/delete, caps, path safety, encryption) | no | no | Encryption **disabled until the owner sets `FILE_ENCRYPTION_KEY`**; no key-rotation tooling; client download UI uses the new `download_url` but is untested |
| 18 | AI security coach | AMBER | yes | yes | yes (fake Anthropic client: IDOR, timeouts, rate limit, hint leakage) | no | **no** (never called the real model) | Needs a real `ANTHROPIC_API_KEY` to verify |
| 19 | Complaint e-mail generator | AMBER | yes | partial | partial | no | no (model not called) | As #18 |
| 20 | Family safety dashboard | AMBER | yes | n/a | yes (consent flow, dashboard counts, 10 tests) | no | no | Client Invites tab/consent badges implemented, **not run on a device**; panic fan-out to family members (only emergency contacts are notified) |
| 21 | Panic button | AMBER | yes | n/a | yes (contact fan-out, rate limit, sanitised text) | no | **no** (SMS/e-mail never sent for real) | Needs working Twilio/Resend to verify delivery; BRD mentions family contacts - only emergency contacts are notified |
| 22 | Security reports | AMBER | yes | n/a | yes (13 tests: scoping, freshness, UTC, e-mail) | no | no | E-mail delivery needs a working provider; no scheduler (user-triggered only) |
| 23 | Consent manager | AMBER | yes | no | n/a | no | no | Device-only; untested |

Also implemented and integration-tested this run (not numbered in the BRD): community scam news feed with
corroboration threshold, admin stats/users/enable-disable, elderly (senior) guardian alerts with real delivery
code, AI-limit sharing, message analyzer (pattern + AI, screenshot upload safety), clone detection, FIR drafts
persisted as files.

## Infrastructure / cross-cutting

| Item | Status | Evidence | Blocker / remaining gap |
|---|---|---|---|
| Real OTP delivery (Resend + Twilio + SMTP) | BLOCKED | adapter + 14 mocked tests | provider key/domain, valid Twilio creds |
| OTP hardening (CSPRNG, HMAC at rest) | GREEN | integration + unit | - |
| Refresh-token rotation + replay revocation | GREEN (backend) | 7 new rotation tests incl. a concurrent-exchange race plus the 17 token-type tests; client stores rotated token, shares one in-flight refresh | client path not run on a device |
| Google Sign-In | BLOCKED (client) / GREEN (backend verification) | 12 tests with locally signed tokens | OAuth client IDs |
| Biometric / device verification | AMBER | `local_auth` present; new-device alert code exists | not tested |
| Threat intel (GSB / URLhaus) | AMBER | simulated providers | live keys |
| Evidence encryption at rest | AMBER | see #17 | key + rotation |
| Admin / RBAC | AMBER | static `ADMIN_TOKEN` endpoints + warrior RBAC tested | no admin UI; no per-admin identity/audit trail for token-based actions (actions are logged without an actor); no real admin created (by instruction) |
| Localization | AMBER | see #4 | remaining screens |
| Uvicorn access-log redaction | GREEN | unit tests | - |
| DB backups / recovery | AMBER | scripts + runbook verified locally, tamper detection | no schedule, no off-site storage, evidence volume backup is an owner/Railway action |
| Schema drift guard | GREEN | tests compare ORM enums/tables/columns to the migrated DB | - |
| Lint / format / CI parity | GREEN locally | ruff 0.9.4 clean | GitHub CI **not run** (no push) |
| Railway migration + healthcheck | AMBER | config-as-code `.railway/railway.ts` (preDeploy `alembic upgrade head`, `/health`) verified in an earlier gate | **Six new migrations have never run on Railway.** Deploy intentionally not done; the Railway project's only environment is named `production` |
| Railway Git SHA consistency / CI-gated deploy | BLOCKED | - | no push authorised; stale check suites from other apps block `checkSuites` |
| Flutter startup / network reliability | AMBER | `API_BASE_URL` pinning, bounded optional init, release smoke on emulator | LAN-probe path (dev builds) unchanged; no E2E |
| Android release signing | **AMBER** | `build.gradle.kts` reads `key.properties` | **The produced AAB/APK are signed with the DEBUG key** - no upload keystore exists; cannot be uploaded to Play |
| R8 / resource shrinking | GREEN (build) | release APK/AAB build with R8; ML Kit missing-class rules added; APK launches on emulator | only a launch smoke test; feature regression under R8 not tested |
| `const_finder.dart.snapshot` / icon tree-shaking | **OPEN (diagnosed, not fixed)** | see below | needs the Flutter SDK artifact re-fetched (a download) |
| Play Store readiness | AMBER | `ANDROID_RELEASE_AND_PLAY.md`; unused `SEND_SMS` / `REQUEST_INSTALL_PACKAGES` removed | restricted permissions (SMS, call log), `QUERY_ALL_PACKAGES`, FGS types, data-safety form, privacy policy - owner decisions |

## Android build result and the `const_finder` investigation

* `flutter build apk --release` and `flutter build appbundle --release` **succeeded only with
  `--no-tree-shake-icons`**. Without it both fail with `IconTreeShakerException: ConstFinder failure: Could not
  find a command named ...\windows-x64\const_finder.dart.snapshot`.
* Diagnosis: the SDK itself is consistent (`engine.stamp` = `engine.version` = `3452d735bd...`, Flutter 3.41.0,
  Dart 3.11.0). `bin/cache/artifacts/engine/windows-x64/` contains 11 entries all written within seconds of each
  other on 2026-10-04 20:58, none of them `const_finder.dart.snapshot` or `font-subset(.exe)`. Those two come from the
  separate `font-subset` engine artifact, which was never downloaded or was not extracted. Windows Defender has no
  detection for the Flutter folder (`Get-MpThreatDetection`), so quarantine is not the cause.
* The fix is `flutter precache --force` (downloads the artifact from Google storage). I did **not** run it
  because it is a download that was not authorised. The `--no-tree-shake-icons` flag is therefore a **workaround**
  that makes the APK larger (108 MB universal APK; 70.9 MB AAB at last build) and must not be treated as the fix.

## Not done (explicitly)

No push, no deployment, no Railway change, no credential created or rotated, no admin created, no real third-party
provider call, no real gitleaks run, no GitHub CI run, no device E2E of the new client screens.
