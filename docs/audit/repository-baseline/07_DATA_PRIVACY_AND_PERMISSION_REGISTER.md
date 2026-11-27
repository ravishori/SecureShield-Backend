# SecureShield AI — Data, SDK and Android Permission Register

**Baseline date:** 27 November 2026  
**Status:** Preliminary inventory. Must be reconciled against current code, runtime traffic and SDK documentation before Data Safety submission.

## 1. Data categories to investigate

| Data category | Evidence/feature association | Questions to resolve |
|---|---|---|
| Phone number/email | User model, OTP | Required/optional? Sent to Twilio/SMTP? Retention? |
| Password/credential verifier | User model | Hash algorithm, reset, retention, logging |
| OTP code | OTP model and delivery | Replace plaintext storage; never log |
| User profile/address | User model | Is all address data necessary? |
| Device token/fingerprint | Device model and registration | Purpose, uniqueness, retention, reset |
| Installed app/package metadata | App scan and package monitor | On-device only or backend upload? |
| SMS/notification content | OTP Vault/notification listener | Exact fields, local vs remote, user disclosure |
| URLs and submitted messages | Link/message analysis | Provider transmission and retention |
| Location | SOS/Wi-Fi features | Precise/approximate, foreground/background |
| Audio recordings | Recording feature | Microphone-only, user initiated, upload destination |
| Screen recordings | MediaProjection service | User action, visible indication, upload and retention |
| Evidence files | Evidence API | Storage region, access, sharing and deletion |
| AI conversation/message | AI service | Provider, model, data sent, retention and training policy |
| Logs/crash metadata | Backend error logging | Redaction, access, email, retention |
| Subscription status | User tier | Billing provider, purchase token, entitlement |
| Network destination metadata | VPN service | On-device or uploaded, domain/IP accuracy, retention |

Do not declare all candidate categories as collected without checking actual runtime behaviour. Equally, do not omit SDK collection merely because the app code does not explicitly store it.

## 2. Third-party providers observed in selected code

| Provider/component | Observed purpose | Data questions |
|---|---|---|
| Twilio | OTP SMS/WhatsApp | Phone number, message body, metadata, region and retention |
| SMTP provider | Email OTP | Recipient, message content, logs and retention |
| Anthropic | AI Coach and other AI service methods | User content, identifiers, retention, training and cross-border processing |
| PostgreSQL host | Application database | Hosting region, backups, access and retention |
| Flutter packages | Local app functions | SDK collection, telemetry and transitive dependencies |
| Google Fonts | Typography package | Network requests and data handling |
| Google ML Kit | Mentioned in historical project notes; current dependency not established in this selected `pubspec.yaml` | Verify if used and whether processing is on-device |
| Google Safe Browsing / URLhaus | Mentioned in older project documentation; current live integration not established | Verify current code and data-sharing terms |

## 3. Android permission register

| Permission/API | Declared in inspected manifest? | Feature association/comment | Action |
|---|---|---|---|
| `READ_SMS` | Yes | OTP Vault | Restricted; remove unless eligible and approved |
| `RECEIVE_SMS` | Yes | OTP Vault | Restricted; assess alternatives |
| `SEND_SMS` | Yes | SMS function unclear | Remove unless essential and policy-qualified |
| `READ_CALL_LOG` | Yes | Scam call detection | Restricted; remove unless eligible |
| `PROCESS_OUTGOING_CALLS` | Yes | Call detection | Verify current platform support/policy; likely remove |
| `READ_PHONE_STATE` | Yes | Call-state detection | Justify and minimise |
| `QUERY_ALL_PACKAGES` | Yes | Installed-app scanning | Strong policy justification required |
| `PACKAGE_USAGE_STATS` | Yes | Usage-based device checks | Special access; user explanation and minimisation |
| Notification listener | Service declared | OTP/notification monitoring | Prominent disclosure and explicit settings consent |
| `RECORD_AUDIO` | Yes | Microphone recording | Request only after user initiates; recording indication |
| `CAMERA` | Yes | Evidence capture/QR | Request on demand |
| Fine/coarse location | Yes | SOS/Wi-Fi | Request only when feature requires it |
| `REQUEST_INSTALL_PACKAGES` | Yes | APK handling unclear | Remove unless core permitted use |
| Legacy storage | Yes | Evidence | Replace with scoped storage/pickers |
| VPNService binding | Yes | Traffic monitoring | Disable until functional and Play-policy compliant |
| Foreground service | Yes | Monitoring/recording/VPN | Correct type, declaration and user-visible lifecycle |
| `FOREGROUND_SERVICE_MEDIA_PROJECTION` | Yes | Screen capture | Review MediaProjection consent and foreground service rules |

## 4. Required disclosure design

For every sensitive capability, the app should explain before permission/consent:
- What data is accessed.
- Why it is needed.
- Whether it stays on-device or leaves the device.
- Which provider receives it.
- How long it is retained.
- How to stop the feature.
- How to delete associated data.

Consent must be specific, informed and affirmative where required. Do not bundle unrelated purposes into one consent.

## 5. Retention schedule — must be decided

Create a product-approved retention table for:
- OTP records.
- Authentication/security logs.
- AI conversation history.
- Submitted links/messages.
- Recordings and evidence.
- Device registration records.
- Family alerts.
- Subscription and transaction records.
- Backups.
- Provider-side data.

Specify retention duration, deletion trigger, backup expiry and lawful retention exceptions. Do not invent retention periods in the privacy policy before the engineering and legal teams agree on them.
