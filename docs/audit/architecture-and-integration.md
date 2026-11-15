# Architecture and integration (verified 2026-11-12; updated 2026-11-13)

Everything below was read from code or enumerated from the running application object; statements about runtime behaviour against real providers are
explicitly marked unverified.

## Components

```
Android app (Flutter 3 / Dart, Riverpod, GoRouter, Dio)  ──HTTPS──►  FastAPI 0.115 (Python 3.11, SQLAlchemy 2 async + asyncpg, Alembic)  ──►  PostgreSQL 18
   │  Kotlin native layer (12 files): notification listener, VPN service,           │  middleware added: GlobalErrorHandler, CORS, RateLimit
   │  MediaProjection recorder, package/APK analysis, device integrity, SIM         │  25 router modules, 126 routes under /api/v1 (+ /, /health, /ready, /version)
   │  flutter_secure_storage (Keystore) for tokens + AES-256-GCM key                ├─ services: otp_service, notifications, ai_service, gsb_service,
   └─ local stores: OTP vault, scan history, recordings (app-private folder)        │  urlhaus_service, upload_safety, file_crypto, log_scrubber, client_ip ...
                                                                                    └─ providers: Twilio (SMS/WhatsApp), Resend / SMTP, Anthropic, Google ID tokens,
                                                                                       Google Safe Browsing, abuse.ch URLhaus
```

| Layer | Facts (verified) |
|---|---|
| Backend entry | `app/main.py`; one `@app.on_event("startup")` hook: production checks -> `error_logs` purge (`LOG_RETENTION_DAYS`, guarded since `742380c`) -> Twilio account lookup (no SMS) -> e-mail status log. No scheduler, no background workers, no `create_all` |
| Data | 32 ORM tables (`users`, `otps` (+`attempts`), `admin_accounts`, `admin_sessions`, `refresh_token_uses`, `revoked_token_families`, `devices`, `alerts`, `evidence`, `recordings`, `family_members`, `emergency_contacts`, `app_scans`, `wifi_scans`, `link_scans`, `network_activities`, `scam_calls`, `security_reports`, `behavior_events`, `app_install_events`, `clone_reports`, `community_scam_reports`, `elderly_configs`, `ai_conversations`, `warrior_*`, `admin_audit_logs`, `error_logs`, `tsp_codes`, `lsa_codes`, `sms_sender_registry`); 23 Alembic revisions, single head `u6v7w8x9y0z1`; `tests/integration/test_schema_drift.py` compares ORM and migrated schema |
| Config | `pydantic-settings` (`app/config.py`; admin-account settings in `app/admin_settings.py`: `ADMIN_LEGACY_TOKEN_ENABLED`, token/session lifetimes, lockout); `.env` values win over process environment; production startup refuses placeholder `SECRET_KEY`/`ADMIN_TOKEN`, empty CORS, missing `TRUSTED_PROXIES` when `TRUST_PROXY_TLS=true` |
| Database access | `app/database.py` builds the async engine (`hide_parameters=True`); runtime URL and migrator URL are separate settings; Neon pooled/direct handling is in the **uncommitted** connection fix (see below) |
| Storage | uploads on local disk (`UPLOAD_DIR`), served only through owner-checked routes; optional AES-GCM at rest (`FILE_ENCRYPTION_KEY(S)`) |
| Deployment (declared) | **Railway Railpack** (approved build path; Docker is not an approved deployment builder, owner decision 2026-11-13; a `Dockerfile` remains in the repository as an unused artefact), `.railway/railway.ts` (`RAILPACK` builder, 1 replica, healthcheck `/health`, pre-deploy `alembic upgrade head`, volume `/app/uploads`) |
| Client | 160 Dart files, 48 screens, 37 feature folders; central `DioClient` (JWT attach, single-flight refresh, connection re-detection); `AppConfig` resolves the base URL (`--dart-define=API_BASE_URL` pins it) |

## Verified end-to-end traces (UI -> state -> API -> router -> service -> model -> provider)

| Flow | Chain | Status |
|---|---|---|
| Login | `auth` screens / `auth_provider.dart` -> `POST /auth/send-otp` (`routers/auth.py`) -> `otp_service.deliver_otp` (Twilio SMS -> WhatsApp; Resend/SMTP e-mail) -> `otps` (HMAC) -> `POST /auth/verify-otp` -> JWT pair (PyJWT) -> `FlutterSecureStorage` | Code and tests complete; **provider legs unverified, Twilio rejects credentials (20003)** |
| Token refresh | any 401 -> `DioClient` interceptor -> `POST /auth/refresh` -> `refresh_token_uses`/`revoked_token_families` -> retry original request | Verified with a real loopback HTTP test including a streamed download (`evidence_token_refresh_test.dart`) |
| Evidence upload / retrieve | `evidence_screen.dart` -> `evidence_api.dart` -> `/evidence/upload`, `GET /evidence`, `GET /evidence/{id}/download` -> `upload_safety` (type, size, path) + `file_crypto` -> disk; client saves to `evidence_downloads/<id>/`, length-checked, shares via OS sheet | Backend integration-tested; client unit-tested; **share sheet unverified on a device** |
| Recording + emergency share | `emergency_share_screen.dart` -> `/recordings/upload`, `/recordings/{id}/share-link` -> public `GET /recordings/share/{token}` | Integration-tested; emulator-verified 2026-10-06 |
| Panic | home/SOS -> `POST /alerts/panic` -> `Alert` row -> background task `_notify_emergency_contacts` -> `notifications.send_sms/send_email` | Integration-tested with mocked providers; family notification and share token **not implemented** |
| Link scan | `link_scanner_screen.dart` -> `/link-scanner/scan` -> `gsb_service`, `urlhaus_service` -> `link_scans` | Simulated providers only |
| AI coach | `ai_coach` -> `/ai/chat` -> `ai_service` (Anthropic) -> `ai_conversations` | Fake client only; never run against a real key |
| Bank OTP | Kotlin `SecureShieldNotificationListener` -> EventChannel `bank_otp_events` -> `bank_otp` screen -> `otp_vault_store` (device-local, PIN/biometric) | Emulator-verified 2026-10-06; no automated test |
| VPN -> network log | `SecureShieldVpnService` -> `vpn_events` -> `network_activity_reporter` -> `POST /network/activity` -> `network_activities` | Reporter unit-tested (6); emulator-verified 2026-10-06 |
| Family consent | `family` screens -> `/family/invitations`, accept/decline -> `family_members.consent_status` | Integration-tested; emulator accept/decline 2026-10-06 |
| Account erasure | `DELETE /auth/me` -> `account_erasure.py` (all user-linked tables, files, tombstone) | Integration-tested (7) |
| Admin sign-in | `/admin/console` page (e-mail, password, TOTP) -> `POST /admin/auth/login` -> `admin_accounts` (scrypt hash, encrypted TOTP secret) -> `admin_sessions` row -> bearer token (`type=admin`, `sid`, `scope`) -> `admin_access.require_role` re-reads session, account state and role from the database on every request | Integration-tested (31 + 3 + 33 unit); first-login setup scope (password change, mandatory MFA enrolment) and sign-out/MFA enforcement driven in the built-in browser on 2026-11-13 |
| Admin data | `require_role("support" / "admin" / "superadmin")` -> `/admin/{stats,users,audit,errors}` and `/admin/auth/accounts/*` -> `admin_audit_logs` with `actor_admin_id` / `actor_label` | Integration-tested incl. privilege-escalation and concurrency cases; legacy `X-Admin-Token` still accepted as `admin` role while `ADMIN_LEGACY_TOKEN_ENABLED` |
| OTP verification | `POST /auth/verify-otp` -> newest open `otps` row locked `FOR UPDATE` -> constant-time HMAC compare -> `attempts` counter (burn after 5) -> single use; `POST /auth/send-otp` invalidates open codes and is capped per source address | Integration-tested (13); mutation-checked |

## Screenshot protection (2026-11-13)

`core/router.dart` wraps 12 sensitive routes in `ScreenshotPrevention.protect` -> `secureshield/window_flags` (`enableSecure` / `disableSecure` / `isSecure`) -> `MainActivity.kt` (`FLAG_SECURE`). The holder count is kept in Dart so stacked protected screens keep the flag until the last one closes; it is re-applied on resume. Effect on a real window is **not device-verified**.

## Native channel parity (verified)

All 13 Dart `MethodChannel` names have a Kotlin handler (`window_flags` method names fixed on 2026-11-13) (`apk_signature`, `app_monitor`, `call_state`, `device_integrity`, `device_scanner`, `elderly`,
`remote_detector`, `screen_record`, `screen_recording_detector`, `sim_integrity`, `system`, `vpn_monitor`, `window_flags`). **Method-level parity is not
guaranteed in general**: `window_flags` is now covered by a contract test (`screenshot_prevention_test.dart` reads `MainActivity.kt`); the other channels' method sets
were not compared one by one.

## Integration gaps

* Backend routes with no client caller: `app-scanner/spyware-check`, `app-scanner/results/{id}`, `ai/history/{id}`, `family/members/{id}/alerts`, `family/links/{id}/revoke`, `network/suspicious`, `reports/daily/email`, `reports/log-behavior`, `recordings/` (list) and `recordings/{id}/download`.
* The Cyber Warriors backend (`/warriors/*`) has no Flutter client.
* Six Flutter detectors run entirely on-device and have no backend (see matrix row 33).
* `Features of the app.txt` describes panic as sending GPS + e-mail to *family* contacts with a share token; the code notifies *emergency contacts* with a map link only.

## Database migration to Neon (state as of 2026-10-18; not re-checked today)

Schema built with Alembic on an empty Neon database and data copied with a single-transaction `pg_restore --data-only` (excluding `otps`, `alembic_version`);
validated by schema diff, per-table checksums and sequence/FK checks (`../neon-migration/`). The **application cutover has not been performed**: the
committed code cannot connect to Neon's pooled endpoint without the engine fix (`channel_binding`, `statement_cache_size` option handling in
`app/config.py` and `app/database.py`), which remains an **uncommitted working-tree change** together with `tests/unit/test_database_engine.py` and
`.env.example`. A local run against Neon on 2026-10-18 passed `/health`, `/ready`, `/version`, `/admin/stats`.

## Facts that differ from earlier documents

* Routers: **24 modules / 107 routes** (an earlier note said 25 and `Features of the app.txt` says 13); tables: 30 ORM tables (document says 14).
* GitHub CI **did run** once (2026-10-05, green, old SHA) - earlier registers say it never ran.
* `origin/staging/railway-snapshot` exists on GitHub (tip `976ce42`); the local branch is 61 commits ahead.
