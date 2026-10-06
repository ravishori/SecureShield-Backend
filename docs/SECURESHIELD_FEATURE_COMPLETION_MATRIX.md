# SecureShield - Feature Completion Matrix

Built from `Features of the app.txt` (23 features + infrastructure table) and the repository state on
**2026-10-06** (backend branch `staging/railway-snapshot`, Flutter repo `main`; **local commits only - nothing pushed,
nothing deployed**). Companion documents: `SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md` (register),
`MIGRATION_SAFETY_REVIEW.md`, `STAGING_DEPLOYMENT_PLAN.md`, `BACKUP_AND_RECOVERY.md`, `ANDROID_RELEASE_AND_PLAY.md`.

**Overall status: AMBER. This is not a 100% completion claim and no feature is marked GREEN.**

## The eight evidence levels (answered separately for every feature)

| Column | Meaning |
|---|---|
| **IMPL** | Code exists |
| **INTEGR** | The Flutter client actually calls the backend / the module is reachable from the app |
| **UNIT** | Automated pure-logic tests (backend `tests/unit`, Flutter `test/`) |
| **INTEG-T** | Integration tests: real FastAPI app + real PostgreSQL, third-party providers simulated |
| **DEVICE** | Driven by hand on the Android emulator through the real UI, against the real app code and a real (local) backend. Provider delivery goes to a local outbox (`scripts/e2e_local_server.py`) |
| **EXTERNAL** | Verified against the real third-party service (Resend, Twilio, Google, GSB, URLhaus, Anthropic) |
| **DEPLOY** | Verified on a deployed environment (Railway) at a known SHA |
| **BLOCKER** | What stops the next level |

`yes` = evidence exists in the repo or in the recorded run; `no` = not done; `partial` = said precisely. **EXTERNAL and DEPLOY are `no` for
every row**: no provider credentials were available and Railway was off limits (its only environment is named `production`).

## Verification totals (2026-10-06)

| Check | Result |
|---|---|
| Backend `pytest` (real PostgreSQL, Alembic-migrated) | **777 passed** (full suite, real PostgreSQL, 0 skipped; verified after the FG-035 admin-token tests; 733 after FG-165, 711 after FG-041, 691 after FG-071, 592 before). Flutter: `flutter analyze` clean, **69/69** tests pass |
| `ruff check` / `ruff format --check` (repo-pinned 0.9.4; `app tests scripts`) | clean / 162 files formatted |
| `pip check`, Alembic | clean; single linear head `s4t5u6v7w8x9` |
| Real gitleaks 8.21.2 | backend HEAD tree clean; Flutter tree + history clean; backend history = 14 known historical findings in 2 old commits (rotation DEFERRED) |
| GitHub CI | **not run** (no push). Real CI file: `backend/.github/workflows/backend-ci.yml` |
| `flutter analyze` / `flutter test` | no issues / **43 passed** |
| `flutter build apk --release` / `appbundle --release` | built, 108.2 MB / 71.1 MB, no workaround flags; release APK installs and launches on the emulator with no crash. **Signed with the debug key** (no `key.properties`) |
| Migrations | 7 new, all rehearsed on seeded data (upgrade, downgrade, re-upgrade) |
| Localization coverage (heuristic, `flutter_app/tool/l10n_coverage.py`) | **312 localized / 400 hard-coded UI strings = 43.8%**; 352 ARB keys x 6 languages (339 before the screen-recording-detector keys were added; the earlier figure of 307 was wrong); translations are machine-authored and **not reviewed by native speakers** |

## The 23 features

| # | Feature | IMPL | INTEGR | UNIT | INTEG-T | DEVICE | EXTERNAL | DEPLOY | BLOCKER / remaining gap | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Authentication & onboarding | yes | OTP, register, refresh: yes. **Google: client code written, disabled without `GOOGLE_WEB_CLIENT_ID`** | yes | yes (OTP flow, HMAC at rest, rotation, Google with locally signed tokens) | partial: phone login with OTP verified; rotation/refresh and Google not driven | no | no | Live OTP delivery needs a Resend key + verified domain (Twilio fails 20003); Google needs OAuth client IDs | AMBER / BLOCKED |
| 2 | Security dashboard | yes | yes (`/reports/daily` score) | no | yes | yes (score 100 shown after login) | no | no | threat-heavy states not driven | AMBER |
| 3 | Alerts | yes | yes | no | yes | yes (panic alert listed with severity) | no | no | dismiss/delete not driven | AMBER |
| 4 | Settings, profile, language, senior mode | yes | yes | yes (key/placeholder parity, Hindi rendering) | yes | partial: Hindi switch verified on screen; senior-mode toggle and profile edit not driven | no | no | 43.7% of UI strings localized; native review pending | AMBER |
| 5 | App risk scanner | yes | yes | yes (Flutter risk engine) | yes (tenant isolation, bounds) | no | no | no | not driven on device this session | AMBER |
| 6 | Link/URL scanner | yes | yes | yes | yes (GSB + URLhaus simulated) | no | no | no | live keys; not driven | AMBER |
| 7 | Wi-Fi scanner | yes | yes | no | yes | no | no | no | not driven (needs location services) | AMBER |
| 8 | Scam calls, recordings, emergency share | yes | **scam-call client screen added this session** (was never wired); recording upload/share: yes | no (backend) | yes (scoring, privacy, share revoke/expiry, encryption) | **yes**: mic recording 23 s -> upload -> 24 h share link -> public download returned the exact 398,950 bytes; scam report scored 90 -> blocked -> alert; block button | no | no | No automatic call detection (call-log permission is Play-restricted); server-side encryption off until a key is set | AMBER |
| 9 | OTP vault | **yes - new screen written this session (it did not exist)** | yes (fed by the bank-OTP monitor) | yes (store + screen, 9 tests) | n/a (device-local by design) | **yes**: system PIN prompt, 2 captured bank OTPs listed masked | no | no | records only while the Bank OTP Monitor screen's stream is alive; local only (no backup/sync) | AMBER |
| 10 | Bank OTP fraud detection | yes | yes | no (Kotlin regex untested by unit tests) | n/a | **yes**: listener enabled, 2 notifications detected, non-OTP ignored, shown in history. Found and fixed: "OTP is 482916" phrasing was missed | no | no | detection only sees notifications; SMS-based path not driven | AMBER |
| 11 | Device security scan | yes | yes | no | n/a | **yes**: 258 apps scanned, verdict shown | no | no | root/Frida checks need a rooted device | AMBER |
| 12 | Remote-access detector | yes | yes | no | n/a | **yes**: flagged ADB enabled (true on the emulator) | no | no | no remote-control app installed to test positive app detection | AMBER |
| 13 | Screen-recorder **detector** | **partial (Android 15+ only)**: `WindowManager.addScreenRecordingCallback` reports whether *SecureShield's own windows* are being recorded; the screen is honest about that scope and shows 'not supported' on Android 14 and below (no public API exists). 8 unit/widget tests; idle and unsupported states verified on API 36 emulator. **Device-proven on API 36 emulator** (evidence `docs/evidence_detector_recording.png`): with a genuine MediaProjection session active (`dumpsys media_projection` = `TYPE_SCREEN_CAPTURE`, status-bar recording chip) the detector screen showed 'SCREEN IS BEING RECORDED' and logged 'Recording started 08:04:14'; stopping the share flipped it live to 'Not being recorded' and logged 'Recording stopped 08:04:38'. `adb shell screenrecord` does NOT trigger it (shell recorder is not a projection of the app's windows). Single emulator, one Android version, manual UI-driven run - no automated device test. It cannot detect other apps recording or a recording of other apps | yes | yes | n/a | yes (manual) | no | no | Android limit: Android 15+ only, own windows only; not automated on a device | **AMBER** |
| 14 | VPN monitor | yes | yes | no | n/a | **yes**: started, system VPN dialog, flagged range attempts blocked and listed, normal traffic unaffected. **Found: the old design routed ALL traffic into the tunnel and dropped it (no internet while on); rewritten to blocklist mode** | no | no | domain-based detection no longer possible (documented in the UI); `BIND_VPN_SERVICE` Play declaration | AMBER |
| 15 | Package monitor | yes | yes | no | yes (idempotent sync, alert fix) | no | no | no | not driven | AMBER |
| 16 | Network activity monitor | yes | **yes - added this session** (VPN events batched to `/network/activity`) | yes (6 reporter tests) | yes | **yes**: blocked attempts reached the backend, the flagged one stored as suspicious | no | no | only runs while the VPN monitor is on | AMBER |
| 17 | Evidence locker | yes | yes | yes (format, rotation, failure injection: 14 tests) | yes (upload/download/delete, caps, path safety, encryption) | no | no | no | not driven through the UI; encryption disabled until `FILE_ENCRYPTION_KEY` is set; **upload type policy added (extension allow-list + content signature + fixed served media types, 99 tests; IMPLEMENTED + TESTED, not device-driven)**; no AV scan, no per-user quota | AMBER |
| 18 | AI security coach | yes | yes | no | yes (fake client: IDOR, timeouts, rate limit, leakage) | no | **no** | no | real `ANTHROPIC_API_KEY` | AMBER |
| 19 | Complaint e-mail generator | yes | yes | no | partial | no | **no** | no | as #18 | AMBER |
| 20 | Family safety dashboard | yes | yes | yes (localization tests) | yes (consent, dashboard) | **yes**: invitation received, **Accept** -> backend `accepted`, inviter dashboard showed the invitee's alert; **Decline** -> `declined` | no | no | adding a member through the dialog and the Kids tab not driven; panic is not pushed to family members | AMBER |
| 21 | Panic button | yes | yes | no | yes (providers mocked) | **yes**: SOS in the app -> alert stored -> SMS + e-mail for the emergency contact captured by the outbox | **no** (nothing real sent) | no | working Twilio/Resend; **delivery logs masked (FG-041: IMPLEMENTED + TESTED, 20 tests)** | AMBER |
| 22 | Security reports | yes | daily/history/weekly: yes; **e-mail endpoint not called by the client** | no | yes | partial: dashboard shows the report | no | no | e-mail needs a provider; no scheduler | AMBER |
| 23 | Consent manager | yes | yes | no | n/a | **yes**: Grant SMS -> system dialog -> counter 1/8 | no | no | other permissions not driven | AMBER |

## Bugs found by the device/browser runs this session (all fixed and re-verified)

| Where | Defect | Fix |
|---|---|---|
| VPN monitor | routed 0.0.0.0/0 into the tunnel and never forwarded: the phone had no internet while monitoring | blocklist mode (only known-bad ranges routed); UI text corrected |
| Bank OTP | "Your OTP is 482916" (the usual phrasing) matched no pattern; notification text read with `getString` (null for spanned text) | regexes + `getCharSequence` |
| Biometric / PIN (OTP vault, biometric login) | `local_auth` needs a `FlutterFragmentActivity` + AppCompat theme; it silently returned false | `MainActivity` base class, themes, appcompat dependency |
| Recordings | share link shown as a relative path (not shareable) | client prepends the server origin |
| Scam calls | endpoints never called by the client; a reported call about OTP/gift cards scored 0 | new screen; server floor 50 + script keywords |
| Network monitor | server flagged fewer ranges than the device blocks | server list aligned |
| Admin console (real Chrome) | none found; 24/24 checks passed | - |

## Infrastructure / cross-cutting

| Item | IMPL | UNIT | INTEG-T | DEVICE/BROWSER | EXTERNAL | DEPLOY | BLOCKER / note | Status |
|---|---|---|---|---|---|---|---|---|
| Real OTP delivery (Resend + Twilio + SMTP) | yes | yes (mock transport) | yes | local outbox only | no | no | provider key/domain, valid Twilio creds | BLOCKED |
| OTP hardening (CSPRNG, HMAC at rest) | yes | yes | yes | login verified | n/a | no | - | AMBER |
| Refresh-token rotation + replay revocation | yes | no | yes (7 + 17 tests incl. race) | client path not driven | n/a | no | pre-rotation tokens force one re-login | AMBER |
| Google Sign-In | client + backend | no | backend yes | no | no | no | OAuth client IDs | BLOCKED |
| Admin API, audit log, console | yes | no | yes | **real Chrome: 24/24** (`scripts/admin_console_browser_e2e.mjs`): wrong token, stats, search, disable/enable with confirmation, audit, CSP, cross-origin fetch blocked, not framable, HTML in a name rendered as text, offline failure, token not stored | n/a | no | single shared admin token (no per-person identity); no real admin was created ; admin-token comparison verified constant-time-primitive based and tested (FG-035, 44 tests; no timing measurement); no failed-attempt lockout (FG-166) | AMBER |
| Evidence encryption at rest + key lifecycle | yes | yes: round-trip at record boundaries, tamper, truncation, reorder, wrong key | yes | no | n/a | no | **14 rotation tests incl. crash mid-write, final-record crash, verification failure, replace failure, wrong old key, re-run after interruption, stale temp files; mutation-checked**. Disabled until the owner sets a key; custody/backup of the key is the owner's | AMBER |
| Backups | yes | yes | n/a | local backup -> checksum -> restore into scratch DB -> counts match; tamper rejected; openssl encrypt/decrypt round-trip; wrong passphrase rejected | n/a | no | scheduled workflow written, **disabled**, YAML-validated only; no off-site storage | AMBER |
| Migration safety | n/a | n/a | schema-drift tests | 7 revisions rehearsed on seeded data | n/a | no | `premigration_report.py` (read-only) + checklist in `MIGRATION_SAFETY_REVIEW.md` | AMBER |
| Deployment verification (SHA, health) | `/version`, `/health`, `/ready` | n/a | yes | n/a | n/a | **no** | plan in `STAGING_DEPLOYMENT_PLAN.md`; push not authorised | BLOCKED |
| Lint / format / CI parity | n/a | n/a | n/a | n/a | n/a | no | local only | AMBER |
| Android release build | yes | n/a | n/a | release APK launches | n/a | n/a | **debug-key signing** (no keystore); R8 only smoke-tested | AMBER |
| Play Store readiness | doc | n/a | n/a | n/a | n/a | n/a | restricted permissions (SMS, call log), `QUERY_ALL_PACKAGES`, FGS types, data-safety form, privacy policy: owner decisions | AMBER |
| Localization | 352 keys x 6 | key/placeholder parity + Hindi render tests | n/a | Hindi verified on the Settings screen | n/a | n/a | 43.8% coverage; native-speaker review is an external quality blocker | AMBER |

## Not done (explicitly)

No push, deployment, Railway change, credential creation or rotation, permanent admin, real third-party call, GitHub CI run.
The `font-subset` Flutter artifact was fetched with `flutter precache --force` (authorised); that is why release builds no longer need `--no-tree-shake-icons`.

## Local E2E harness

`scripts/e2e_local_server.py` runs the real FastAPI app on a disposable, migrated local PostgreSQL and replaces only outbound delivery (OTP / SMS /
e-mail go to a git-ignored `e2e_outbox.log`); it ignores the developer's real `backend/.env` (settings give `.env` priority over process variables) and
uses inert provider values. The debug app on the emulator finds it at `10.0.2.2:8000`. This is app+backend E2E, **not** external verification.
