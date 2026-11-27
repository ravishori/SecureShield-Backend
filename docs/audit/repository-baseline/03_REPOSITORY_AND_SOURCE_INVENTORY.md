# SecureShield AI — Repository and Source Inventory

**Snapshot date:** 27 November 2026

## 1. Repository identity

| Property | Backend | Frontend |
|---|---|---|
| URL | https://github.com/ravishori/SecureShield-Backend | https://github.com/ravishori/SecureShield-Frontend |
| Default branch reviewed | `main` | `main` |
| Stack observed | Python, FastAPI, SQLAlchemy, Pydantic/Alembic, PostgreSQL | Flutter/Dart, Kotlin, Riverpod, GoRouter, Dio |
| Tree entries reported | 7,840 | 259 |

Counts are a snapshot of the GitHub recursive tree response and can change as repositories change.

## 2. Backend files inspected

| Path | Review purpose |
|---|---|
| `.env` | Confirmed tracked configuration file; values intentionally not copied |
| `app/config.py` | Secret/configuration handling |
| `app/main.py` | Application entry point (selected inspection) |
| `app/database.py` | Database setup (selected inspection) |
| `app/routers/auth.py` | OTP, account lookup, verification |
| `app/services/otp_service.py` | SMS, WhatsApp, email and fallback |
| `app/middleware/rate_limiter.py` | OTP/API rate limiting |
| `app/middleware/error_handler.py` | Global exception handling |
| `app/services/logger_service.py` | File/database/email logging |
| `app/models/user.py` | User and OTP schema |
| `app/models/error_log.py` | Error-log schema |
| `app/routers/recordings.py` | Recording upload, list, delete, share |
| `app/routers/evidence.py` | Evidence upload/list/delete |
| `app/services/ai_service.py` | Anthropic provider calls and AI tasks |
| `alembic/env.py` | Alembic metadata registration |
| `alembic/versions/07cfca043074_initial.py` | Initial schema migration |
| `alembic/versions/3bf328167739_add_error_logs_table.py` | Error log migration |

### Backend repository hygiene

The tree inspection reported:
- 7,840 total entries.
- 7,623 entries under `.venv/`.
- 3,490 paths containing `__pycache__`.
- Root `.env` tracked.
- `logs/secureshield.log` tracked.
- `logs/uvicorn-runtime.log` tracked.

The `.venv` and `__pycache__` categories overlap.

## 3. Frontend files inspected

| Path | Review purpose |
|---|---|
| `pubspec.yaml` | Flutter dependency inventory |
| `android/app/src/main/AndroidManifest.xml` | Android permissions, components and network flags |
| `android/app/build.gradle.kts` | SDK delegation, app ID and release signing |
| `lib/core/app_config.dart` | API URL resolution and LAN address |
| `lib/core/security/encryption_service.dart` | Local encryption and failure behaviour |
| `lib/features/auth/auth_provider.dart` | Authentication state (selected inspection) |
| `lib/features/call_recording/services/recording_service.dart` | Microphone recording implementation |
| `lib/features/call_recording/services/recording_storage_service.dart` | Local encrypted recording storage |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/MainActivity.kt` | Native channels and service starts |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/AppMonitorService.kt` | App-install monitoring service |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/ScreenRecordService.kt` | Screen-record service (file existence/selected inspection) |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/SecureShieldVpnService.kt` | VPN capture and threat classification |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/SecureShieldNotificationListener.kt` | Notification-listener implementation (file inventory) |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/AppInstallAnalyzer.kt` | App analysis implementation (file inventory) |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/PackageInstallReceiver.kt` | Package install receiver (file inventory) |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/ApkSignatureVerifier.kt` | APK signature verifier (file inventory) |
| `android/app/src/main/kotlin/com/secureshield/secureshield_app/ElderlyProtectionManager.kt` | Senior/elderly workflow (file inventory) |

A file being listed or present does not mean its complete behaviour has been verified.

## 4. Third-party components observed

### Frontend dependencies (from `pubspec.yaml`)

- `dio`
- `flutter_riverpod`, `riverpod_annotation`, `riverpod_generator`
- `go_router`
- `flutter_secure_storage`
- `shared_preferences`
- `local_auth`
- `permission_handler`
- `device_info_plus`, `package_info_plus`
- `installed_apps`
- `wifi_scan`, `network_info_plus`
- `video_player`
- `url_launcher`
- `qr_flutter`
- `intl`, `uuid`, `crypto`, `encrypt`
- `fl_chart`
- `image_picker`, `file_picker`, `path_provider`
- `record`, `audioplayers`
- `share_plus`
- `flutter_local_notifications`, `workmanager`
- `google_fonts`

### Backend/provider components observed

- Anthropic SDK in AI service.
- Twilio in OTP delivery.
- SMTP email delivery.
- PostgreSQL/SQLAlchemy/Alembic.
- Additional installed packages are present in the tracked `.venv`; use declared dependency manifests and runtime call paths to establish the true production SDK inventory.

## 5. Key call paths requiring a deeper trace

The first review did not fully trace every screen and API. Future feature audits should map:

`Flutter screen → Riverpod provider/state → Dio client → FastAPI router → service → SQLAlchemy model/database → third-party provider`

Prioritise:
- OTP/authentication.
- AI Coach and user-submitted message analysis.
- App scanner and app-install monitoring.
- Link scanning.
- OTP Vault/notification listener.
- Recording and evidence upload/share/delete.
- VPN monitoring.
- SOS/location.
- Family dashboard.
- Subscription and premium entitlements.

## 6. Repository baseline update fields

For each new audit, append:
- Backend commit SHA.
- Frontend commit SHA.
- Audit date/time and reviewer.
- Files changed since prior baseline.
- New/changed endpoints and schema.
- New dependencies/SDKs.
- New permissions/services/receivers.
- New data categories and recipients.
- Test commands and exact results.
