# SecureShield AI — Repository Security & Google Play Readiness Audit

**Audit snapshot:** 27 November 2026  
**Repositories:** `ravishori/SecureShield-Backend`, `ravishori/SecureShield-Frontend`  
**Branches reviewed:** `main`  
**Audit type:** Remote source-code review and repository-tree inspection  
**Overall conclusion:** **Not ready for public Google Play release based on the inspected source**

---

## 1. Executive summary

Both public GitHub repositories were accessible during this review. The first source inspection identified several high-impact issues that should be addressed before a public release:

- Backend credentials and configuration values are present in tracked source/configuration files; a tracked `.env` file was found.
- The backend repository contains a large tracked `.venv` and Python bytecode footprint, plus committed runtime logs.
- OTP generation, storage, delivery fallback and rate limiting need security hardening.
- The Android manifest declares multiple restricted or sensitive permissions, including SMS and call-log permissions.
- The local encryption service uses AES-CBC with a static stored IV and silently falls back to plaintext on initialization/encryption failure.
- The release Gradle configuration uses the debug signing configuration.
- The Android app configuration contains a hardcoded LAN address and the manifest permits cleartext traffic.
- The VPN service creates a TUN interface and reads outbound IPv4 packets, but no packet forwarding/write path was identified in the inspected implementation. This may disrupt connectivity.
- The global exception/logging flow requires privacy redaction review.
- Account deletion, public privacy-policy implementation, Play Billing and end-to-end release tests were not established by the selected source review.

**Recommendation:** Do not submit the current build to Google Play until P0/P1 findings are remediated and evidence is recorded.

## 2. Audit scope and confidence

### Inspected repositories

- Backend: https://github.com/ravishori/SecureShield-Backend
- Frontend: https://github.com/ravishori/SecureShield-Frontend

### Inspection approach

- Confirmed repository accessibility and default branch.
- Retrieved recursive Git trees.
- Inspected selected configuration, authentication, OTP, logging, recording/evidence, Android manifest, Gradle, Flutter encryption and Kotlin service files.
- Reviewed selected model and Alembic migration definitions.
- Performed limited pattern checks on committed log files without reproducing their contents.

### Not performed

- No clone/build/test execution.
- No device or emulator verification.
- No live API traffic or production database inspection.
- No penetration test or dynamic analysis.
- No review of every API route, service, model, UI screen or provider integration.
- No Play Console access or submission.
- No verification of actual deployed environment values or whether exposed credentials remain active.

The findings below are source-review findings, not proof that a production system has been exploited.

## 3. Repository snapshot

| Item | Backend | Frontend |
|---|---:|---:|
| Repository | `SecureShield-Backend` | `SecureShield-Frontend` |
| Branch | `main` | `main` |
| Recursive tree entries reported | 7,840 | 259 |
| Tracked `.venv` entries | 7,623 | Not observed |
| Tracked `__pycache__` entries | 3,490 | Not observed |
| Tracked `.env` at repository root | Yes | Not observed |
| Committed log files | 2 | Not observed |

The `.venv` and `__pycache__` counts overlap; do not add them together.

## 4. Critical and high-priority findings

### P0 — Credential exposure and repository hygiene

Evidence inspected:
- Backend `.env`
- `app/config.py`
- Repository tree and committed logs

The repository contains a tracked `.env` file with credential/configuration entries. `app/config.py` also contains hardcoded configuration/credential values for sensitive integrations, including database/JWT/SMTP/Twilio-related settings.

The backend repository tree contains a large virtual environment and Python bytecode footprint. Two log files are committed:
- `logs/secureshield.log`
- `logs/uvicorn-runtime.log`

Pattern checks found email-like strings, phone-like strings, six-digit values and secret-like terms in those logs. These are indicators for manual review, not a definitive classification of each match.

**Required response**
1. Rotate every potentially exposed credential and revoke old tokens/keys.
2. Review provider access logs and database access logs for suspicious activity.
3. Remove secrets from tracked files and Git history using a reviewed history-rewrite process.
4. Remove virtual environments, bytecode, runtime logs and local artifacts from version control.
5. Add and validate root `.gitignore`.
6. Move all runtime secrets to managed environment configuration.
7. Ensure logs are scrubbed before committing or exporting.

Do not publish replacement secrets in GitHub issues, PRs, chat or this audit package.

### P1 — OTP/authentication hardening

Files inspected:
- `app/routers/auth.py`
- `app/models/user.py`
- `app/services/otp_service.py`
- `app/middleware/rate_limiter.py`

Observed:
- OTP generation uses `random.randint()`.
- OTP values are stored in the `OTP.code` database field as ordinary strings.
- OTP expiry is configured for 10 minutes.
- Rate limiting is backed by in-memory dictionaries.
- The delivery service has a console fallback that prints the OTP and logs it.
- `/auth/check-user` returns whether an account exists.
- OTP verification checks identifier, code, unused status and expiry, then marks the OTP used.

**Required response**
- Use `secrets` for OTP generation.
- Store a keyed hash/verifier rather than a plaintext OTP.
- Make verification and single-use consumption atomic.
- Apply distributed rate limiting with identifier, IP/device and abuse controls.
- Disable console OTP fallback in production and ensure no OTP reaches logs.
- Review enumeration resistance and uniform responses.
- Review resend invalidation, concurrent requests, replay, brute-force and delivery failure handling.
- Add tests for race conditions and multi-worker deployments.

### P1 — Android permissions and Google Play policy exposure

File inspected:
- `android/app/src/main/AndroidManifest.xml`

The manifest declares permissions including:
- `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`
- `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS`
- `QUERY_ALL_PACKAGES`
- `PACKAGE_USAGE_STATS`
- `RECORD_AUDIO`
- Fine/coarse location
- Camera
- Legacy external storage permissions
- `REQUEST_INSTALL_PACKAGES`
- VPN-related and foreground-service-related permissions
- Notification listener binding permission

These permissions are not automatically acceptable because the app is a cyber-safety product. SMS/Call Log permissions are particularly restricted. Other permissions require purpose limitation, disclosures, user consent, technical justification and possibly Play Console declarations.

**Required response**
- Build a permission-to-feature traceability matrix.
- Remove every permission not necessary for the first release.
- Avoid SMS/Call Log permissions unless the app qualifies under current Play policy and the use is accepted.
- Evaluate less sensitive alternatives, such as user-submitted content and supported SMS retrieval flows.
- Verify notification-listener disclosure and user-controlled enable/disable.
- Verify QUERY_ALL_PACKAGES and package visibility justification.
- Complete declarations and demo evidence for applicable services.

### P1 — Encryption service can silently return plaintext

File inspected:
- `lib/core/security/encryption_service.dart`

Observed:
- AES-256-CBC is used.
- A single IV is stored and reused.
- Key and IV are stored through `FlutterSecureStorage`.
- If initialization fails, `encrypt()` returns the original plaintext.
- If encryption fails, it also returns plaintext.
- Debug messages are emitted during encryption operations.

**Required response**
- Replace the format with authenticated encryption, preferably AES-256-GCM.
- Generate a unique nonce for every encryption operation.
- Use Android Keystore-backed key management and define key separation/rotation.
- Never silently return plaintext from an encryption API.
- Fail closed and surface an actionable error.
- Version ciphertext envelopes and plan migration for existing encrypted data.
- Remove sensitive values from logs.
- Add tamper, wrong-key, nonce, migration and failure-path tests.

### P1 — Release signing is configured to use debug keys

File inspected:
- `android/app/build.gradle.kts`

Observed:
- `targetSdk` delegates to `flutter.targetSdkVersion`; the effective resolved value was not verified.
- Release `signingConfig` is set to `signingConfigs.getByName("debug")`.

**Required response**
- Configure production upload signing securely outside source control.
- Confirm Play App Signing setup.
- Verify the built AAB signing certificate.
- Verify target API 36 or higher for new app submissions as of the audit date.
- Record effective `compileSdk`, `targetSdk`, `minSdk`, version code and version name from the actual release build.
- Test upgrade paths and signing continuity.

### P1 — VPN service has no identified packet-forwarding path

File inspected:
- `SecureShieldVpnService.kt`

Observed:
- Establishes a TUN interface.
- Adds a default IPv4 route.
- Configures DNS servers.
- Reads IPv4 packets and extracts destination IP addresses.
- Performs reverse DNS and local-list classification.
- No packet output/forwarding path was identified in the inspected service.

**Impact**
A VPN that captures all device traffic but does not forward it through a valid network path can disrupt internet connectivity. It must not be enabled in a public build until its data plane is implemented and tested.

**Required response**
- Disable the feature in release builds until corrected.
- Design and review a valid forwarding architecture.
- Test IPv4 and IPv6, DNS, TCP, UDP, captive portals, VPN coexistence, battery, reconnect, failure recovery and emergency stop.
- Validate current Google Play VpnService policy and declaration requirements.
- Do not describe the service as threat-blocking or full traffic protection unless that behaviour is demonstrated.

## 5. Additional findings

### P1/P2 — Network configuration

Files:
- `lib/core/app_config.dart`
- `AndroidManifest.xml`

Observed:
- Hardcoded physical-device LAN IP address.
- HTTP URLs are used in development configuration.
- `usesCleartextTraffic="true"`.
- `requestLegacyExternalStorage="true"`.

Required:
- Environment-specific HTTPS API base URL.
- Production configuration must not depend on a developer LAN.
- Disable cleartext traffic in production.
- Remove legacy storage compatibility flags if not required.
- Validate certificate handling and network security configuration.

### P1/P2 — AppMonitorService registration

Files:
- `AppMonitorService.kt`
- `MainActivity.kt`
- `AndroidManifest.xml`

The MainActivity starts the app-monitor service, and the Kotlin class exists. The inspected manifest did not declare `AppMonitorService`.

Required:
- Verify the merged manifest and runtime behaviour.
- Declare the service correctly if needed.
- Apply current foreground-service type/permission requirements.
- Test Android 14+ and newer background execution restrictions.
- Provide a user-visible stop control and clear explanation.

### P1/P2 — Recording capability must be described accurately

File:
- `lib/features/call_recording/services/recording_service.dart`

The service comments explicitly state that Android 9+ blocks third-party access to the telephony audio stream and that the implementation records microphone audio only.

Required:
- Do not market this as guaranteed two-way call recording.
- Ensure user-initiated start/stop, prominent recording indication and consent-aware UX.
- Review Indian legal requirements and Google Play policy.
- Remove or redesign the feature if the user benefit cannot be delivered lawfully and reliably.

### P1/P2 — Recording/evidence uploads

Files:
- `app/routers/recordings.py`
- `app/routers/evidence.py`

Observed:
- Upload handlers read the entire upload into memory.
- File paths are constructed from a generated ID plus the submitted filename.
- Files are written to local upload directories.
- Recording share links are bearer-token URLs with a 24-hour expiry.
- User ownership checks are present on several authenticated recording/evidence operations.

Required:
- Enforce request and file size limits before loading full content.
- Validate actual file signatures and MIME types.
- Generate server-side filenames; never trust client filenames.
- Store files outside executable/web roots or use controlled object storage.
- Add malware scanning where appropriate.
- Protect share tokens, support revocation and avoid logging them.
- Define retention, access audit and deletion behaviour.
- Test cross-user IDOR/BOLA, expired links, revoked links and upload abuse.

### P1 — Logging and exception privacy

Files:
- `app/middleware/error_handler.py`
- `app/services/logger_service.py`
- `app/models/error_log.py`

The logging architecture includes file, database and email paths. The inspected global error handler/logging flow requires redaction review because request metadata, headers, query parameters, exception details and tracebacks may contain secrets or personal information.

Required:
- Redact Authorization, Cookie, OTP, password, API key, token and sensitive query/body fields before every sink.
- Do not email raw tracebacks or request payloads.
- Apply access controls and retention to error logs.
- Add tests proving redaction across file, DB and email outputs.

### P2 — Account deletion and privacy implementation not established

The selected source search did not establish a complete account deletion workflow or a public privacy-policy implementation.

Required:
- Trace all user-owned data and object relationships.
- Implement in-app account deletion and a public web deletion request path if account creation is supported.
- Delete or anonymise linked data, evidence, recordings, devices, AI history and family relationships according to a documented retention schedule.
- Document lawful retention exceptions and backup expiry.
- Publish a public, app-specific privacy policy and keep it consistent with actual data flows and Play Data Safety answers.

### P2 — Google Play Billing not established

The `SubscriptionTier` enum includes `free` and `premium`, but the inspected dependency inventory/source review did not establish a complete Play Billing implementation.

Required:
- Integrate Play Billing if digital premium features are sold in the Play-distributed app, subject to current policy.
- Verify purchase tokens on the backend.
- Handle acknowledgement, renewal, cancellation, grace period, refund, revocation and restore.
- Never grant premium access based only on a client-side flag.

## 6. Release decision

**Current recommendation: NO-GO for public release.**

Minimum conditions to reconsider:
1. P0 credential exposure contained and repository cleaned.
2. P1 authentication and encryption issues fixed and tested.
3. Restricted permissions removed or policy eligibility established.
4. VPN disabled until forwarding is proven.
5. Release signing and effective target API verified.
6. HTTPS-only production configuration verified.
7. Privacy policy, Data Safety, account deletion and third-party disclosures reconciled with actual behaviour.
8. Critical/high security defects closed.
9. Release candidate tested on supported Android versions and real devices.
10. Reviewer instructions and accurate store listing prepared.

## 7. Source references

- [Backend repository](https://github.com/ravishori/SecureShield-Backend)
- [Frontend repository](https://github.com/ravishori/SecureShield-Frontend)
- [Backend configuration](https://github.com/ravishori/SecureShield-Backend/blob/main/app/config.py)
- [Backend authentication](https://github.com/ravishori/SecureShield-Backend/blob/main/app/routers/auth.py)
- [OTP delivery](https://github.com/ravishori/SecureShield-Backend/blob/main/app/services/otp_service.py)
- [Rate limiter](https://github.com/ravishori/SecureShield-Backend/blob/main/app/middleware/rate_limiter.py)
- [Global exception handler](https://github.com/ravishori/SecureShield-Backend/blob/main/app/middleware/error_handler.py)
- [Logging service](https://github.com/ravishori/SecureShield-Backend/blob/main/app/services/logger_service.py)
- [Recording API](https://github.com/ravishori/SecureShield-Backend/blob/main/app/routers/recordings.py)
- [Evidence API](https://github.com/ravishori/SecureShield-Backend/blob/main/app/routers/evidence.py)
- [Android manifest](https://github.com/ravishori/SecureShield-Frontend/blob/main/android/app/src/main/AndroidManifest.xml)
- [Android Gradle configuration](https://github.com/ravishori/SecureShield-Frontend/blob/main/android/app/build.gradle.kts)
- [Flutter app configuration](https://github.com/ravishori/SecureShield-Frontend/blob/main/lib/core/app_config.dart)
- [Encryption service](https://github.com/ravishori/SecureShield-Frontend/blob/main/lib/core/security/encryption_service.dart)
- [Recording service](https://github.com/ravishori/SecureShield-Frontend/blob/main/lib/features/call_recording/services/recording_service.dart)
- [VPN service](https://github.com/ravishori/SecureShield-Frontend/blob/main/android/app/src/main/kotlin/com/secureshield/secureshield_app/SecureShieldVpnService.kt)
