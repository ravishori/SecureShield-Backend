# Feature completion matrix

Last assessed: **2026-11-12** (backend `30664ce`, Flutter `ac5cd50`). Every row was re-derived from code, tests and the recorded runs listed in
[`testing-and-qa.md`](testing-and-qa.md); earlier register statements (`../SECURESHIELD_FEATURE_COMPLETION_MATRIX.md`,
`../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`) were treated as claims, not as evidence.

## Status vocabulary (strict)

| Status | Meaning | Credit used in the status-weighted figure |
|---|---|---|
| PLANNED | Documented or requested, no code | 0 |
| BUILDING | Partly implemented, not wired end to end, or blocked before it can work | 0.25 |
| BUILT | Code exists and is wired UI -> API -> database in the code; no automated test of the main path (device-manual runs may exist) | 0.50 |
| TESTED | Automated tests of the main path exist and pass (backend: real PostgreSQL; Flutter: unit/loopback). Providers simulated | 0.75 |
| REVIEWED | TESTED + a documented security review with defects fixed and mutation-checked regression tests, and nothing blocking it from working | 0.90 |
| PRODUCTION | Deployed, externally verified (real providers, real device) and monitored | 1.00 |

**No feature is PRODUCTION.** Nothing in this project has been verified against a real third-party provider or on a deployed environment at the
current SHA.

## Scoring method

Each axis is scored 0-100 per feature (`n/a` = the axis does not exist for that feature, e.g. a device-local feature has no backend and is excluded
from the backend average). Rubric:

* **FE** - screen complete, wired, error/empty states: 100; wired with gaps: 70-85; partly wired or local only: 40-60; absent: 0.
* **BE** - endpoints, validation, ownership checks, migrations: 100 complete; deductions for missing capabilities listed in the gaps column.
* **INT** - the whole chain works end to end including the external provider; capped at 60 when the provider has never been run, 40 when also mocked in tests.
* **TEST** - automated evidence: 80-90 integration tests on real PostgreSQL covering success + authorisation + failure; 50-70 partial; 10-20 device-manual only; 0 none.
* **SEC** - ownership/authorisation, input safety, data exposure and privacy for that feature (not a penetration test).
* **Impl** = mean of the applicable FE/BE/INT values.
* **Weight** 1-3 = user impact / criticality (3 = sign-in, sessions, evidence, panic).

Percentages in [`project-status.md`](project-status.md) are weight-weighted means of these columns. Planned work is never counted as done.

## Feature inventory (38 rows: 29 trace to `Features of the app.txt` including its infrastructure table, 9 exist in code but are not in that document)

| # | Feature | W | Status | FE | BE | INT | TEST | SEC | Impl |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Phone/e-mail OTP login and registration | 3 | **TESTED** | 85 | 90 | 55 | 85 | 80 | 77 |
| 2 | Google Sign-In | 1 | **BUILDING** | 60 | 75 | 20 | 50 | 70 | 52 |
| 3 | Session / JWT lifecycle (access, refresh rotation, replay revoke) | 3 | **REVIEWED** | 80 | 95 | 80 | 90 | 85 | 85 |
| 4 | Device registration and new-device alert | 1 | **TESTED** | 70 | 80 | 60 | 65 | 70 | 70 |
| 5 | Security dashboard (score) | 2 | **BUILT** | 80 | 80 | 80 | 55 | 70 | 80 |
| 6 | Alerts (list, read, dismiss, delete) | 2 | **TESTED** | 85 | 90 | 85 | 70 | 80 | 87 |
| 7 | Settings, profile, language, senior mode | 1 | **BUILT** | 75 | 85 | 80 | 40 | 75 | 80 |
| 8 | App risk scanner | 2 | **TESTED** | 85 | 85 | 70 | 75 | 80 | 80 |
| 9 | Link / URL scanner | 2 | **TESTED** | 85 | 80 | 60 | 70 | 70 | 75 |
| 10 | Wi-Fi scanner | 1 | **TESTED** | 80 | 80 | 75 | 65 | 75 | 78 |
| 11 | Scam-call report, scoring and block | 2 | **TESTED** | 70 | 80 | 80 | 70 | 70 | 77 |
| 12 | Call/screen recording and emergency share | 2 | **TESTED** | 75 | 90 | 80 | 80 | 85 | 82 |
| 13 | OTP vault (device-local, biometric/PIN) | 1 | **TESTED** | 85 | n/a | n/a | 70 | 70 | 85 |
| 14 | Bank OTP fraud detection (notification listener) | 2 | **BUILT** | 75 | n/a | n/a | 20 | 60 | 75 |
| 15 | Device security scan (root, emulator, integrity) | 2 | **BUILT** | 85 | n/a | n/a | 15 | 65 | 85 |
| 16 | Remote-access detector | 2 | **BUILT** | 75 | n/a | n/a | 15 | 60 | 75 |
| 17 | Screen-recorder detector (Android 15+) | 1 | **TESTED** | 70 | n/a | n/a | 60 | 60 | 70 |
| 18 | VPN monitor (blocklist mode) | 2 | **BUILT** | 80 | n/a | 60 | 35 | 60 | 70 |
| 19 | Package-install monitor | 1 | **TESTED** | 70 | 85 | 70 | 50 | 65 | 75 |
| 20 | Network activity monitor | 1 | **TESTED** | 60 | 85 | 75 | 70 | 70 | 73 |
| 21 | Evidence locker (upload, list, delete, retrieve) | 3 | **TESTED** | 75 | 90 | 80 | 85 | 85 | 82 |
| 22 | AI security coach | 2 | **BUILT** | 85 | 80 | 30 | 55 | 70 | 65 |
| 23 | Complaint e-mail generator | 1 | **BUILT** | 85 | 80 | 30 | 40 | 70 | 65 |
| 24 | Family safety (consent, invitations, dashboard) | 2 | **TESTED** | 70 | 90 | 70 | 80 | 85 | 77 |
| 25 | Panic button and emergency contacts | 3 | **TESTED** | 80 | 80 | 40 | 75 | 70 | 67 |
| 26 | Security reports (daily, weekly, history) | 1 | **TESTED** | 80 | 80 | 60 | 60 | 75 | 73 |
| 27 | Consent / permission manager | 1 | **BUILT** | 80 | n/a | n/a | 15 | 65 | 80 |
| 28 | Anti-screenshot protection (FLAG_SECURE) | 1 | **BUILDING** | 10 | n/a | 0 | 0 | 0 | 5 |
| 29 | Clone / fake-app detection | 1 | **TESTED** | 80 | 85 | 80 | 65 | 70 | 82 |
| 30 | Message, job-offer and bullying analyzer | 1 | **TESTED** | 80 | 80 | 40 | 60 | 65 | 67 |
| 31 | Community scam reports and news feed | 1 | **TESTED** | 75 | 80 | 70 | 50 | 65 | 75 |
| 32 | Elderly protection and guardian alerts | 1 | **TESTED** | 70 | 80 | 50 | 65 | 70 | 67 |
| 33 | Client-only detectors (digital arrest, payment verifier, QR, fake-bank SMS, SIM integrity, scam news) | 1 | **BUILT** | 70 | n/a | n/a | 10 | 50 | 70 |
| 34 | Video-call room and FIR draft | 1 | **BUILT** | 70 | 65 | 55 | 25 | 60 | 63 |
| 35 | Cyber Warriors programme (backend only, no client) | 1 | **BUILDING** | 0 | 90 | 0 | 70 | 80 | 30 |
| 36 | Admin API and web console | 2 | **TESTED** | 70 | 85 | 80 | 70 | 65 | 78 |
| 37 | Account deletion / data erasure | 2 | **REVIEWED** | 60 | 95 | 80 | 90 | 90 | 78 |
| 38 | Localization (6 languages) | 1 | **BUILDING** | 44 | n/a | n/a | 60 | n/a | 44 |

Status counts: TESTED 21, BUILT 11, BUILDING 4, REVIEWED 2, PLANNED 0, PRODUCTION 0.

## Working functionality vs placeholders

* **Real and tested end to end in code (providers simulated):** sessions/JWT, alerts, recordings and evidence storage, family consent, account erasure, admin API, link/app/Wi-Fi scanners' server side.
* **Real but unverified against its provider:** every OTP channel, Anthropic features (coach, complaint e-mail, message analyzer, FIR draft), Safe Browsing / URLhaus, Google Sign-In, panic/guardian/report SMS and e-mail.
* **Client-side only, no automated test:** Kotlin detectors (bank OTP, remote access, device integrity, VPN, package install, SIM), consent manager, the six client-only detectors (row 33).
* **Does not work:** anti-screenshot protection (row 28).
* **Backend without a client:** Cyber Warriors (row 35); backend endpoints that no screen calls: `GET /app-scanner/spyware-check`, `GET /app-scanner/results/{scan_id}`,
  `GET /ai/history/{session_id}`, `GET /family/members/{member_id}/alerts`, `POST /family/links/{link_id}/revoke`, `GET /network/suspicious`,
  `POST /reports/daily/email`, `POST /reports/log-behavior`, `GET /recordings/`, `GET /recordings/{id}/download`.
* **No placeholder/mock data was found in shipped screens.** A case-insensitive search of `flutter_app/lib` (excluding `l10n`) for TODO, FIXME, HACK, "coming soon", "not implemented", mock/sample data, lorem, dummy and stub found only a stale `(stub)` comment on the implemented Google sign-in (`features/auth/auth_provider.dart:272`); the backend search (`backend/app`) found none. The earlier guardian-alert stub was replaced (FG-136). A search is not proof: screens were not each opened on a device.

## Per-feature trace, tests, gaps and remaining effort

Effort is developer-days for one engineer, excluding owner-side waiting (credentials, store review) and excluding native-speaker translation review.

| # | UI -> state -> API -> router -> service -> model -> provider (verified in code) | Tests / runs | Missing or unverified | Effort (days) |
|---|---|---|---|---|
| 1 | Flutter `features/auth` -> `POST /auth/{register,send-otp,verify-otp}` (`routers/auth.py`) -> `otp_service.deliver_otp` -> `otps` (HMAC) -> Twilio / WhatsApp / Resend / SMTP | `test_otp_auth_flow_api`, `test_auth_hardening_api`, `test_otp_delivery_logging`, unit `test_otp_resend`; local-outbox emulator run only | No live OTP channel works: Twilio 20003 (diagnosed), no e-mail provider key/domain, India DLT not done | 3-5 (owner credentials + provider setup + live verification) |
| 2 | `google_auth_service.dart` (disabled without `GOOGLE_WEB_CLIENT_ID`) -> `POST /auth/google` -> `google_auth.py` (token verification) | `test_google_signin_api` (locally signed tokens), `google_auth_service_test.dart` | OAuth client IDs; never run against Google | 1-2 |
| 3 | `dio_client.dart` interceptor (single in-flight refresh) -> `POST /auth/refresh` -> `refresh_tokens` family/jti | `test_refresh_rotation_api`, `test_token_types_api`, unit `test_jwt`; `evidence_token_refresh_test.dart` (loopback HTTP) | HS256 shared secret; 60-min access / 30-day refresh unchanged; client path not device-driven | 1 |
| 4 | `/devices/register` -> `device_service.send_new_device_alert` (e-mail) | `test_devices_alerts_api`, `test_device_scoped_data_api` | Alert e-mail cannot be sent (no working transport) | 1 |
| 5 | `dashboard/home_screen.dart` -> `GET /reports/daily` | `test_reports_api`; emulator run (score shown) | Threat-heavy states not driven; no widget test | 2 |
| 6 | `alerts` screen -> `/alerts` list, `PATCH .../read|dismiss`, `DELETE` | `test_devices_alerts_api` | Dismiss/delete not driven on a device | 1 |
| 7 | `settings`, `profile` -> `/auth/me`; ARB localization | `localization_test.dart`, `test_delete_account_schema` | 44% of UI strings localized; translations not native-reviewed; senior-mode and profile edit not device-driven | 6-8 (strings) + external review |
| 8 | `app_scanner` + Kotlin `AppInstallAnalyzer` -> `/app-scanner/scan|results` | `test_app_monitor_clone_api`, `test_device_scoped_data_api`; Flutter risk-engine tests partly | Backend `spyware-check` and `results/{id}` unused by the app; device scan of 258 apps only on an emulator | 2 |
| 9 | `link_scanner_screen.dart` -> `/link-scanner/scan|history` -> `gsb_service`, `urlhaus_service` | `test_link_scanner_api`, unit `test_threat_intel_clients` (simulated providers) | No live GSB/URLhaus run; scanned URLs leave to third parties (privacy notice) | 1-2 |
| 10 | `wifi_scanner` -> `/wifi/scan|history` | `test_device_scoped_data_api` | Not driven on a device (location permission) | 1 |
| 11 | `scam_calls` screen -> `/scam-calls/{report,history,block/{n}}` | `test_devices_alerts_api` area; emulator run | No automatic call detection (call-log permission is Play-restricted) | 5+ (product decision) |
| 12 | `call_recording` + Kotlin `ScreenRecordService`, `emergency_share_screen.dart` -> `/recordings/*` | `test_evidence_recordings_api`, `test_file_encryption_api`, `screen_recorder_service_test.dart`; emulator run (23 s upload + share) | Kotlin recorder has no automated test; server encryption off until a key is set | 2 |
| 13 | `otp_vault` (device-local, `FlutterSecureStorage`) | `otp_vault_test.dart` (9) | Device-local only; no backup or sync (by design) | 0 |
| 14 | Kotlin `SecureShieldNotificationListener` -> EventChannel `bank_otp_events` -> `bank_otp` screen / vault | None automated (Kotlin regex untested); emulator run | Notification path only; SMS path not driven | 3 |
| 15 | Kotlin `DeviceIntegrityProbe`, `device_scan` screens | None automated; emulator run | Root/Frida checks need a rooted device | 2 |
| 16 | Kotlin remote-detector channel -> `remote_detector` screen | None automated; emulator flagged ADB | Positive remote-app detection never exercised | 2 |
| 17 | `ScreenRecordingDetector.kt` (WindowManager callback) -> `screen_recorder` screen | `screen_recording_detector_test.dart` (8); API 36 emulator run | Android 15+ and own windows only (platform limit) | 0 |
| 18 | `SecureShieldVpnService.kt` -> `vpn_events` -> `network_activity_reporter` -> `POST /network/activity` | `network_activity_reporter_test.dart` (6) | Runs only while the monitor is on; Play `BIND_VPN_SERVICE` declaration | 2 |
| 19 | `PackageInstallReceiver.kt`, `AppMonitorService.kt` -> `/app-monitor/*` | `test_app_monitor_clone_api` | Never driven on a device; receiver is exported (input validation not assessed) | 1-2 |
| 20 | VPN events -> `/network/activity`; `GET /network/suspicious` unused by the app | `test_device_scoped_data_api` | Only populated while VPN monitor runs | 1 |
| 21 | `evidence_screen.dart` -> `evidence_api.dart` -> `/evidence/*` -> `upload_safety`, `file_crypto` -> disk under `UPLOAD_DIR`; retrieval via `GET /evidence/{id}/download` -> OS share sheet (commits `65ac73b`, `ac5cd50`) | `test_evidence_recordings_api`, `test_upload_type_policy`, `test_file_encryption_api`; `evidence_download_test.dart` (13), `evidence_token_refresh_test.dart` (3) | Retrieval not device-verified; encryption at rest off until `FILE_ENCRYPTION_KEY` set; no AV scan, no quota; local-disk storage | 2 |
| 22 | `ai_coach` -> `/ai/chat` -> `ai_service` (Anthropic `claude-sonnet-4-6`) | `test_ai_coach_api` (fake client) | Never run against a real key; `GET /ai/history/{id}` unused; model ids hard-coded in 8 places | 2 |
| 23 | `complaint_email` -> `/ai/generate-complaint-email` | Covered with 22 only | As 22 | 1 |
| 24 | `family` screens -> `/family/*` (consent workflow) | `test_family_api` (10+); emulator accept/decline run | Members alerts view and link revoke endpoints unused by the app; panic not pushed to family | 3 |
| 25 | `POST /alerts/panic` -> `_notify_emergency_contacts` -> Twilio/e-mail; `/emergency-contacts` | `test_devices_alerts_api`, `test_emergency_contacts_api`, `test_guardian_alert_logging` (providers mocked) | Family e-mail and recording share token promised in the feature text are not implemented; nothing real ever sent | 3 |
| 26 | `reports` screen -> `/reports/{daily,history,weekly-insights}` | `test_reports_api` | `POST /reports/daily/email` and `/reports/log-behavior` unused by the app; no scheduler | 3 |
| 27 | `consent_manager_screen.dart` + `permission_handler` | None automated; emulator run (SMS grant) | Other permissions not driven | 1 |
| 28 | Dart `ScreenshotPrevention` calls `addFlags/clearFlags`; Kotlin `window_flags` handles only `enableSecure/disableSecure`; no screen calls either | None | Feature does not work and is not applied anywhere (verified by code reading) | 1 |
| 29 | `clone_detector` + `fake_app_detector.dart` -> `/clone-detection/*` | `test_app_monitor_clone_api`, `similarity_metrics_test.dart` | - | 1 |
| 30 | `message_analyzer` -> `/message/*` -> `ai_service` | `test_message_analyzer_api` (fake AI) | No live AI run; registry seeded only on staging | 1-2 |
| 31 | `community_scam`, `scam_news` -> `/community-scams/*` | `test_community_news_feed_api` | Moderation of user reports not implemented | 2 |
| 32 | `elderly_protection` + Kotlin `ElderlyProtectionManager` -> `/elderly/*` | `test_elderly_protection_api`, `test_guardian_alert_logging` | Delivery mocked | 1 |
| 33 | `digital_arrest`, `payment_verifier`, `qr_scanner`, `fake_bank_sms`, `sim_integrity` (Kotlin `SimFingerprintProvider`), `scam_news`: client-side logic, no backend call | None automated | Not documented in the feature list; never run on a device; accuracy unmeasured | 5 |
| 34 | `video_call` -> `/video-call/*` (room, police contacts, FIR) | None dedicated | Streaming FIR draft code unreviewed; no tests | 2 |
| 35 | `/warriors/*` (apply, status, admin approve/reject) | `test_cyber_warriors_api`, unit rbac/schema | No Flutter client; no admin profile management | 5-8 |
| 36 | `/admin/{stats,users,audit,errors}` + `/admin/console` (static page) | `test_admin_users_api`, `test_admin_auth_throttle` (28), `test_admin_token_compare` (44); browser run 24/24 (2026-10-06) | Single shared token, no identity/MFA; throttle per process | 4-6 |
| 37 | `DELETE /auth/me` -> `account_erasure.py` | `test_account_deletion_api` (7), `test_delete_account_schema` | UI path not assessed; retained tombstone + warrior audit trail by design | 1 |
| 38 | `lib/l10n/*.arb` x6, `flutter gen-l10n` | `localization_test.dart` (parity, Hindi render) | 44% coverage by heuristic; unreviewed machine translations | 6-8 |
