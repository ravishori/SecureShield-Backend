# Development roadmap (prioritised, with estimates)

Estimates are developer-days for one engineer already familiar with the code, excluding owner-side waiting (credential issuance, provider onboarding, Play review,
translation review). They are planning figures, not commitments. Gate numbers refer to [`production-readiness.md`](production-readiness.md); finding numbers to [`security-audit.md`](security-audit.md).
Planned work is **not** counted as complete anywhere in these documents.

| Phase total | Dev-days |
|---|---|
| 0 Immediate containment | 2 |
| 1 Security and supply chain | 15.5 |
| 2 Functional completion and verification | 33.5 |
| 3 Compliance, deployment, operations | 29.5 |
| **Phases 0-3 (to CONDITIONAL GO / closed beta), original estimate** | **~80 (range 70-95)**; remaining after 2026-11-13: ~68 (60-75) |
| 4 Post-launch scope | 15-20 |

## Progress 2026-11-13 (P1 blockers worked; estimates below are the original figures, status marked per row)

| Item | Status | Evidence |
|---|---|---|
| 1.1 Dependency upgrade (python-jose -> PyJWT, FastAPI/Starlette, python-multipart, cryptography) | **DONE in repo** (not deployed) | `b9be388`; 1006 tests; clean-install audit 0 runtime advisories |
| 1.5 FLAG_SECURE fix and application | **DONE, device check pending** (1 day left) | `5d4d16a`; 10 tests |
| 1.6 Named admin identities + MFA | **DONE** (alerting on admin actions and switching the legacy token off remain) | `86b3ba2`; browser-verified |
| 1.8 Signed release build | **Code DONE; blocked on the owner's keystore** | `6cd21d4` |
| 2.1 OTP channels | **Hardening DONE; live verification blocked on credentials** (about 3 days left) | `f06a3d8` |
| 1.2 / 1.3 / 1.4 / 1.7 / 1.9 / 1.10, 0.x, 2.2-2.9, Phase 3-4 | not started | - |

Remaining after this progress: Phase 0 about 2 days, Phase 1 about 4 days (pip-audit in CI 0.5, docs gate 0.5, non-root image 0.5, `/ready` 0.5, Flutter CI 1, coverage 1),
Phase 2 about 32.5 days, Phase 3 about 29.5 days = **~68 developer-days (range 60-75)**.

Docker is no longer part of this path (decision 2026-11-13): the image/Dockerfile items below are replaced by verifying the Railway native build on staging, and the Dockerfile can be removed afterwards.

## Critical path to a verified staging (added 2026-11-13)

Owner first (see `p1-closure-report.md`): private repositories + rotation -> Twilio/e-mail provider -> keystore -> approval of an isolated staging environment. Then development, about 8-12 days:
Docker build + non-root image (1-2), CI run on the release SHA incl. gitleaks and a Flutter workflow (1-2), staging bring-up with migrations and first superadmin (1-2), provider smoke tests (1-2), device end-to-end of the nine priority flows and fixes (3-4), backup/restore rehearsal and rollback drill (1).

## Phase 0 - immediate containment (this week)

| # | Task | Owner | Dev-days | Closes |
|---|---|---|---|---|
| 0.1 | Make both GitHub repositories private; rotate every credential listed in `security-audit.md`; decide history rewrite vs abandon | Owner | - | S-01, G2 |
| 0.2 | Verify the Twilio SID/token pair in the Console (rejected 20003 again on 2026-11-13); choose and onboard an HTTPS e-mail provider; then run `python scripts/otp_provider_check.py --live` | Owner | - | S-03, G1 |
| 0.3 | Review and commit (or discard) the uncommitted Neon connection fix (`app/config.py`, `app/database.py`, `.env.example`, `tests/unit/test_database_engine.py`) and decide the fate of `scripts/seed_sms_registry.py` / `start.bat` | Owner + dev | 1 | architecture |
| 0.4 | Remove stale credential copies and the drive-wide `D:\.git` once rotation is done | Owner | 0.5 | S-15 |
| 0.5 | Decide retention periods (FG-034) and the SMS/call-log feature scope | Owner | 0.5 | S-05, S-07 |
| 0.6 | Create the upload keystore (outside the repository), set `SECURESHIELD_*` or `android/key.properties`, build and run `tool/verify_apk_signature.py --expect-sha256 <fingerprint>` | Owner | - | S-04, G7 |
| 0.7 | Create the first superadmin (`python -m app.cli.admin_accounts create`), enrol MFA, set `ADMIN_LEGACY_TOKEN_ENABLED=false`; rebuild the local `.venv` from `requirements.txt` | Owner/ops | 0.5 | S-06, S-02 |

## Phase 1 - security and supply chain

| # | Task | Dev-days | Closes |
|---|---|---|---|
| 1.1 | Upgrade FastAPI/Starlette/python-multipart/cryptography/python-jose (or migrate to PyJWT) and transitive pins; run 923 tests; re-run `pip-audit` | 4 | S-02, G3 |
| 1.2 | Add `pip-audit` (and a Dart vulnerability check) to CI | 0.5 | S-02 |
| 1.3 | Disable `/docs`, `/redoc`, `/openapi.json` in production | 0.5 | S-09 |
| 1.4 | Non-root container user and image healthcheck | 0.5 | S-12 |
| 1.5 | Fix `FLAG_SECURE` method names, apply to evidence, OTP vault, family, recordings screens, add a channel test | 1.5 | S-08 |
| 1.6 | Per-person admin identity (JWT + role + MFA), shared token as break-glass, shared-store throttle | 5 | S-06, G12 |
| 1.7 | Split `/ready` (public status vs private detail) | 0.5 | S-13 |
| 1.8 | Create upload keystore wiring, signed release build, App Signing notes | 1 | S-04, G7 |
| 1.9 | Add a Flutter CI workflow to the Flutter repository (analyze, test, build) | 1 | G4 |
| 1.10 | Add `pytest-cov`, publish coverage, set a floor | 1 | testing |

## Phase 2 - functional completion and verification

| # | Task | Dev-days | Notes |
|---|---|---|---|
| 2.1 | Live verification of OTP channels (SMS, WhatsApp, e-mail) and fix what it reveals | 4 | needs 0.2 |
| 2.2 | Device-verify evidence retrieval (steps in `../AUDIT_2026-10-19.md`) and the share-sheet grace period | 1 | |
| 2.3 | Panic escalation: notify accepted family members, create a recording share token, GPS accuracy handling | 3 | product decision |
| 2.4 | Daily/weekly report e-mail: call the endpoint from the client, add a scheduler | 3 | provider needed |
| 2.5 | Wire unused backend endpoints (family alerts/revoke, AI history, spyware check, recordings list/download) or delete them | 4 | |
| 2.6 | Google Sign-In: OAuth client IDs, device test | 1.5 | owner IDs |
| 2.7 | Kotlin unit tests: OTP regexes, VPN blocklist, APK analysis | 4 | |
| 2.8 | Flutter widget tests for auth, evidence, family, panic flows | 6 | |
| 2.9 | Localisation to full coverage (44% now) | 7 | native review extra |
| 2.10 | Live verification of Anthropic, Safe Browsing, URLhaus with spend limits | included in 2.1 effort pool | needs keys |

## Phase 3 - compliance, deployment, operations

| # | Task | Dev-days | Closes |
|---|---|---|---|
| 3.1 | Implement retention (purge jobs for `error_logs`, audit logs, `otps`, activity tables) after the owner's decision; test it | 5 | S-07, S-14, G11 |
| 3.2 | Privacy notice, consent capture and records, grievance contact, minors/Family handling, deletion path in the UI | 4 | S-07, G11 |
| 3.3 | Play Console package: permission minimisation, declarations, data-safety form, demo videos | 5 | S-05, G8 |
| 3.4 | Production environment: provider decision (Neon vs Railway), secrets, `TRUSTED_PROXIES` measured, Git-based deploy, app cutover to the migrated database | 3 | G5, G6 |
| 3.5 | Monitoring and alerting (working error transport, metrics, uptime check) | 3 | G12 |
| 3.6 | Shared-store rate limiter (Redis) before scaling beyond 1 replica | 3.5 | S-10 |
| 3.7 | Device test matrix on the signed release (Android 10 / 13 / 15) | 4 | G10 |
| 3.8 | Load and abuse test (OTP send, AI endpoints, uploads) | 2 | G12 |

## Phase 4 - post-launch scope

Cyber Warriors client and admin profile management (5-8); moderation for community reports (2); accuracy evaluation and tests for the six client-only
detectors (5); object storage and quotas for evidence (3); certificate pinning decision (1); hard-coded model ids to configuration (0.5).

## Critical path

0.1 + 0.2 (owner) -> 1.1 -> 2.1 -> 3.4 -> 3.7 -> release. Everything else can run in parallel by a second engineer. Play restricted-permission review (3.3) typically adds
2-6 weeks of elapsed time after submission.


## Product development programme: baseline and register (added 2026-11-14, Phase 0)

Strategy: finish all 38 features through development, integration and functional testing first; run the comprehensive security, privacy, compliance and release audits afterwards. Development statuses: PLANNED, BUILDING, BUILT, FUNCTIONALLY COMPLETE, INTEGRATION TESTED, DEVELOPMENT COMPLETE, BLOCKED, DEFERRED (PRODUCTION is not a development status). INTEGRATION TESTED means backend tests on real PostgreSQL plus a client-side test of the call path exist; provider calls are still simulated unless the Provider column says otherwise. **Nothing is DEVELOPMENT COMPLETE.** Feature numbers are the numbers in `feature-completion-matrix.md` (38 rows); an earlier 33-row regrouping omitted five of them: F07 Settings/profile, F17 Screen-recorder detector, F23 Complaint e-mail generator, F27 Consent/permission manager, F29 Clone detection.

Baseline (working tree, 2026-11-14): backend branch `staging/candidate-2026-11-13` at `15f5ea6`, frontend `main` at `815cbd9`, all F1, Phase G and Phase 0 work uncommitted. 28 routers, 140 routes, 27 models, 26 migrations (two pending: `v7w8x9y0z1a2`, `w8x9y0z1a2b3`), 12 Kotlin classes, 36 Flutter feature folders.

| ID | Feature | Dev status | Frontend | Backend | Database | Android native | Provider | Existing tests | Missing | Depends on | Days | Phase |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Phone/e-mail OTP login, registration, identity binding, consent | INTEGRATION TESTED | register, OTP, phone-verify, consent screens | auth.py, identity.py, privacy.py | User, OTP, PendingRegistration, UserConsent (2 pending migrations) | - | Resend simulated only; SMS BLOCKED (no provider) | backend ~120 focused + Flutter 40 | live Resend send; SMS provider for phone codes; device run; consent enforcement for pre-existing accounts at API level | none (foundation) | 3 | P1 |
| F02 | Google Sign-In and account linking | FUNCTIONALLY COMPLETE | google_auth_service, login button, consent retry | POST /auth/google (verified-email linking, google_sub) | users.google_sub | - | Google OAuth client IDs not created (BLOCKED for real use) | backend 18 + Flutter 15 (SDK faked) | create OAuth clients; real-device test | F01 | 2 | P1 |
| F03 | Session / JWT lifecycle (refresh rotation, replay revoke) | INTEGRATION TESTED | DioClient interceptor, token storage | auth.py refresh, refresh_token models | RefreshTokenUse, RevokedTokenFamily | - | - | refresh_rotation, token_types, Flutter token-refresh tests | revoke pre-F1 sessions at deploy; shared rate limiter | F01 | 1 | P1 |
| F04 | Device registration and new-device alert | FUNCTIONALLY COMPLETE | device info sent at login (no device-list screen) | devices.py, device_service.py | Device | - | email alert via Resend (simulated) | devices_alerts | device list/revoke UI | F01 | 2 | P4 |
| F05 | Security dashboard (score) | BUILT | dashboard (2 files) | risk_engine.py, reports | - | - | - | none specific | explainable risk breakdown; tests; shared risk-verdict model | F06,F08,F09 | 4 | P2 |
| F06 | Alerts (list, read, dismiss, delete) | FUNCTIONALLY COMPLETE | alerts (2) | alerts.py (5 routes) | Alert | notification channel (local) | - | devices_alerts | push delivery (none; local notifications only); shared alert service | F01 | 2 | P1 |
| F07 | Settings, profile, language, senior mode, privacy and data | BUILT | settings, profile, privacy settings screens | auth.py /me, privacy.py | User fields | - | - | privacy/profile widget tests only | tests for settings and profile; tidy | F01 | 2 | P7 |
| F08 | App risk scanner and permission analysis | FUNCTIONALLY COMPLETE | app_scanner (3) | app_scanner.py (4) | AppScan | AppInstallAnalyzer, ApkSignatureVerifier; QUERY_ALL_PACKAGES | - | device_scoped_data | Play declaration; device test; catalogue upkeep | none | 3 | P3 |
| F09 | Link / URL scanner | FUNCTIONALLY COMPLETE | link_scanner (2) | link_scanner.py (3), gsb_service, urlhaus_service | LinkScan | - | Safe Browsing BLOCKED commercially; URLhaus key unset; both simulated | link_scanner, threat_intel_clients | commercial-safe provider decision; offline heuristics; hub integration with message and QR | none | 4 | P2 |
| F10 | Wi-Fi scanner | FUNCTIONALLY COMPLETE | wifi_scanner (2) | wifi.py (2) | WifiScan | location + Wi-Fi permissions | - | covered indirectly | device test | none | 1 | P3 |
| F11 | Scam-call report, scoring and block | FUNCTIONALLY COMPLETE | scam_calls (2) | scam_calls.py (3) | ScamCall | READ_PHONE_STATE | no external reputation feed | none specific | number-reputation source (community aggregate); call screening needs Android role | F31 | 5 | P2 |
| F12 | Call/screen recording and emergency share | FUNCTIONALLY COMPLETE | call_recording (6) | recordings.py (7) | Recording + encrypted files | ScreenRecordService (media projection), RECORD_AUDIO | - | evidence_recordings | telephony audio capture is limited by Android; device tests; legal review | F21 | 5 | P6 |
| F13 | OTP vault (device-local, biometric/PIN) | INTEGRATION TESTED | otp_vault (2) | - | - | biometric prompt | - | otp_vault tests | none | none | 1 | P3 |
| F14 | Bank OTP fraud detection | BUILT | bank_otp (2) | - | - | SecureShieldNotificationListener (special access) | - | none | tests; prominent disclosure; device validation | none | 3 | P3 |
| F15 | Device security scan (root, emulator, integrity) | BUILT | device_scan (3) | - | - | DeviceIntegrityProbe | Play Integrity API not used | none | tests; optional Play Integrity (provider) | none | 3 | P3 |
| F16 | Remote-access detector | BUILT | remote_detector (2) | - | - | package list in MainActivity | - | none | tests; list upkeep | F08 | 2 | P3 |
| F17 | Screen-recorder detector (Android 15+) | INTEGRATION TESTED | screen_recorder (4) | - | - | ScreenRecordingDetector, DETECT_SCREEN_RECORDING | - | screen_recording_detector, screen_recorder_service | device test on Android 15 | none | 1 | P3 |
| F18 | VPN monitor (blocklist mode) | BUILT | vpn_monitor (3) | network.py | NetworkActivity | SecureShieldVpnService, BIND_VPN_SERVICE, FGS types | Play VpnService declaration (owner decision) | none | Play-eligibility decision; tests | F20 | 4 | P6 |
| F19 | Package-install monitor and app monitor | FUNCTIONALLY COMPLETE (Phase 1A; not yet run on a device) | package_monitor, app_monitor (5); status only claims what the native service confirmed; disclosure card; notification permission requested first | app_monitor.py (4) | AppInstallEvent | AppMonitorService now declared (non-exported, specialUse foreground service), START_NOT_STICKY, duplicate-start guard, MonitorLifecycle | - | app_monitor_clone, MonitorLifecycleTest (11, JVM), app_monitor_test (17), manifest service tests | device test (Android 10, 13, 15); Stage 1 and 1B done (notification visibility enforced: monitoring pauses and the preference clears if notifications or the monitor channel are off; receiver non-exported and gated by one persisted preference, REQUEST_DELETE_PACKAGES owned in the source manifest, unused installed_apps removed); Stage 2A (backend: idempotent per-event sync, durable guardian outbox, guardian authorisation + e-mail verification required before any alert, server-calculated score only, legacy guardian-alert via the outbox, 90-day retention of terminal alerts; migration x9y0z1a2b3c4 prepared, not executed; 1411 backend tests pass) done; known limits: Flutter guardian-alert disclosure missing, e-mail only, no guardian opt-out;  Stage 2B/2C (native event queue, Flutter coordinator, WorkManager) not started: events that arrive while the app UI is closed are not queued for history (notification and elderly check still run); Play specialUse declaration | F08 | 1 | P3 |
| F20 | Network activity monitor | FUNCTIONALLY COMPLETE | network reporter | network.py (2) | NetworkActivity | needs VPN service | - | network_activity_reporter | depends on F18 decision | F18 | 2 | P6 |
| F21 | Evidence locker (upload, list, delete, retrieve) | INTEGRATION TESTED | evidence (2) | evidence.py (5), file_crypto, upload_safety | Evidence + encrypted files | CAMERA, media permissions | - | evidence_recordings, file_encryption, upload_type_policy, Flutter download tests | retention controls; antivirus; quotas | none | 3 | P4 |
| F22 | AI security coach | BLOCKED | ai_coach (2) | ai_coach.py (3), ai_service.py | AiConversation | - | Anthropic: external AI DISABLED (kill switch); mock-tested | ai_coach, ai_containment (fake provider) | per-user consent enforcement; redaction; spend cap; owner approval | F01,F07 | 6 | P5 |
| F23 | Complaint e-mail generator | BUILT | complaint_email (1) | /ai/generate-complaint-email, email_generator | - | - | works locally from a template while AI is off | ai_coach (fake) | tests of the local template; mailto/share delivery | F22 (optional) | 2 | P5 |
| F24 | Family safety (consent, invitations, dashboard) | FUNCTIONALLY COMPLETE | family (2) | family.py (9) | FamilyMember | - | guardian SMS BLOCKED | family, family_identity | minors consent flow; notifications | F01 | 5 | P4 |
| F25 | Panic button and emergency contacts | BLOCKED | profile contacts, panic UI | emergency_contacts.py (4), alerts | EmergencyContact | location | SMS provider BLOCKED; e-mail alert only | emergency_contacts | SMS provider; live verification | F01,F06 | 4 | P4 |
| F26 | Security reports (daily, weekly, history) | FUNCTIONALLY COMPLETE | reports (2) | reports.py (5) | SecurityReport | - | default tips while AI is off | reports | e-mail delivery live check | F06 | 2 | P4 |
| F27 | Consent / permission manager | BUILT | consent_manager (1) | - | - | runtime permission requests | - | android_manifest_permissions (indirect) | remove unused usage-access item; tests | none | 2 | P1 |
| F28 | Anti-screenshot protection (FLAG_SECURE) | FUNCTIONALLY COMPLETE | ScreenshotPrevention | - | - | FLAG_SECURE | - | screenshot_prevention | device test | none | 1 | P3 |
| F29 | Clone / fake-app detection | FUNCTIONALLY COMPLETE | clone_detector (3) | clone_detection.py (4), clone_analyzer | CloneReport | package list | - | app_monitor_clone | device test; catalogue upkeep | F08 | 2 | P3 |
| F30 | Message, job-offer and bullying analyzer | FUNCTIONALLY COMPLETE | message_analyzer (2) | message_analyzer.py (5), sms_header_validator | SmsSenderRegistry | - | AI step disabled (local pattern engine is the answer) | message_analyzer, ai_containment | unify with URL and QR; on-device OCR; explainable verdict | F09,F33 | 6 | P2 |
| F31 | Community scam reports and news feed | FUNCTIONALLY COMPLETE | community_scam (2), scam_news (1) | community_scam.py (5) | CommunityScamReport | - | - | community_news_feed | moderation workflow; per-user vote dedupe; number-reputation export | F36 | 5 | P2 |
| F32 | Elderly protection and guardian alerts | FUNCTIONALLY COMPLETE | elderly_protection (3) | elderly_protection.py (3) | ElderlyConfig | ElderlyProtectionManager | guardian SMS BLOCKED | elderly_protection, guardian_alert_logging | SMS provider; device test | F24,F25 | 3 | P4 |
| F33 | Client-only detectors (digital arrest, payment verifier, QR, fake-bank SMS, SIM integrity) | BUILT | digital_arrest, payment_verifier, qr_scanner, fake_bank_sms, sim_integrity (9 files) | none | - | SimFingerprintProvider, camera | - | none (~10%) | unit tests; route results into the shared analysis hub | none | 6 | P2 |
| F34 | Video-call room and FIR draft | BUILT | video_call (3) | video_call.py (4) | - | - | public Jitsi (privacy decision); FIR template local | none specific | privacy decision; tests | F22 (optional) | 4 | P6 |
| F35 | Cyber Warriors programme | BUILDING | none | cyber_warrior.py (6) | Warrior* models | - | - | cyber_warriors | entire client; moderation UI | F36 | 12 | P6 |
| F36 | Admin API and web console | INTEGRATION TESTED | admin console page | admin_* (27 routes) | Admin* models | - | - | admin_accounts, admin_users, admin_auth_throttle, files_and_admin | first superadmin and MFA enrolment in an environment | none | 2 | P7 |
| F37 | Account deletion and data erasure | INTEGRATION TESTED | delete_account screen | account_erasure, DELETE /auth/me, delete/start | all user tables | - | third-party deletion not automated | account_deletion, consent_and_deletion, Flutter delete tests | third-party and backup deletion procedure | F01 | 1 | P7 |
| F38 | Localization (6 languages) | BUILDING | l10n (44% of strings) | - | - | - | - | localization_test | finish translations | none | 5 | P7 |

Total estimate to finish the listed gaps: about 123 engineer-days (estimates, not commitments; excludes owner decisions, provider onboarding and the final audit).

### Dependency order

1. **Shared foundations first (P1):** F01 (finish live email, decide SMS), F03, F06 (one alert service), F27, the consent-enforcement dependency and a shared **scam-verdict model** (risk level, score, reasons, source) that F05, F09, F30, F33 all use.
2. **Core scam analysis (P2):** F09, F30, F33 (QR) integrated through one analysis hub; then F11 reputation, F31 moderation, F05 explainable dashboard.
3. **Device and app protection (P3):** F08, F10, F13, F14, F15, F16, F17, F19, F28, F29: independent of each other; mostly Android and device testing.
4. **People and incident flows (P4):** F04, F21, F24, F25, F26, F32; the guardian SMS parts wait for an SMS provider.
5. **AI module (P5):** F22, F23, F34 FIR; needs per-user consent enforcement, redaction, a spend cap and owner approval before the kill switch is ever turned on.
6. **Restricted and advanced (P6):** F12 call recording, F18 and F20 VPN and network monitor, F34 Jitsi, F35 Cyber Warriors client; each needs a Play or legal decision first.
7. **Platform (P7):** F07, F36, F37, F38.

Modules that need no paid provider: F03, F05, F07, F08, F10, F13, F14, F15, F16, F17, F19, F21, F24, F26, F27, F28, F29, F31, F33, F36, F37, F38 and the local parts of F09 and F30. Provider-dependent: F01 (Resend, SMS), F02 (Google), F09 (threat feeds), F22/F23/F34 (AI), F25/F32 (SMS), F18 (Play declaration).

### Next module recommendation: integrated scam analysis (F30 + F33 QR + F09)

Reasons: highest user value; the message analyzer (`message_analyzer.py`, pattern engine plus sender-ID registry) and the QR scanner already work locally; the URL scanner and a verdict shape exist; no paid provider is needed if the hub uses local heuristics first and keeps Safe Browsing and URLhaus as optional, owner-approved enrichments (Safe Browsing stays BLOCKED for commercial use). Reuse: `analyze_message_content`, `validate_sender`, `LinkScan`, the QR reader, the alert service. Likely schema impact: none required (reuse `LinkScan` and `Alert`); an optional shared `ScamAnalysis` history table only if the owner wants cross-input history.
