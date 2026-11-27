# SecureShield AI — Testing and Evidence Register

**Baseline date:** 27 November 2026  
**Execution status:** No tests were run as part of the remote source review.

## 1. Required test suites

| Suite ID | Area | Required coverage |
|---|---|---|
| TEST-AUTH | Authentication | OTP, enumeration, replay, expiry, brute force, JWT refresh/revocation |
| TEST-CRYPTO | Cryptography | GCM nonce uniqueness, tamper detection, wrong key, migration, failure closed |
| TEST-API-AUTHZ | API authorisation | IDOR/BOLA, cross-user access, role and ownership checks |
| TEST-UPLOAD | Upload/evidence | Size, signature, MIME, path traversal, storage, deletion, share expiry/revocation |
| TEST-LOG | Logging | Redaction of secrets, tokens, OTP, PII and exception traces in all sinks |
| TEST-PERM | Android permissions | First request, denial, permanent denial, revocation, settings return |
| TEST-ANDROID-SVC | Android services | Foreground service lifecycle, stop, process death, Android-version restrictions |
| TEST-VPN | VPN | Connectivity, IPv4/IPv6, DNS, TCP/UDP, recovery, coexistence, battery |
| TEST-RECORD | Recording | User initiation, visible state, permission denial, stop, deletion, no unsupported call-audio claims |
| TEST-PRIVACY | Privacy | Consent, policy link, account deletion, data deletion, retention |
| TEST-AI | AI/provider | Provider failure, prompt injection, schema validation, sensitive data notice, cost limits |
| TEST-BILLING | Billing | Purchase verification, acknowledge, renew, cancel, refund, restore, entitlement revocation |
| TEST-RELEASE | Release | Signed AAB, target API, install/upgrade, crash/ANR, device matrix |

## 2. High-priority regression scenarios

### Authentication
- Request OTP for phone and email.
- Ensure OTP is never printed or persisted in plaintext.
- Invalid, expired, used and replayed OTP must fail.
- Concurrent verification must not allow multiple successful consumption.
- Repeated requests and attempts must be rate-limited across backend workers.
- Account lookup must not enable easy enumeration.
- JWT refresh rotation and revoked-token behaviour must be verified.

### Data isolation
- User A cannot list/download/delete User B's recordings or evidence.
- User A cannot use User B's IDs to access family, device, alert or report data.
- Share links expire and can be revoked.
- Expired/revoked links cannot download files.

### Encryption
- Encryption failure does not return plaintext.
- Every encryption uses a unique nonce.
- Tampered ciphertext fails authentication.
- Wrong key fails closed.
- Upgrade migration preserves data and has a recovery plan.

### Android permissions and services
- App remains usable when optional permissions are denied.
- Permission can be revoked in Android Settings and app recovers safely.
- Service has a visible purpose and stop control.
- App does not start restricted/background activity unexpectedly.
- VPN feature is not exposed until connectivity tests pass.

### Privacy and deletion
- User can request deletion in-app.
- Public deletion request flow works.
- Data in database, object storage, AI history, recordings and family links is addressed.
- Backup expiry and lawful retention exceptions are communicated.
- Data Safety answers match observed network traffic and SDK collection.

## 3. Evidence format

Store evidence using a stable structure, for example:

```text
qa/
  release-1.0.0/
    environment.md
    test-summary.md
    auth/
    crypto/
    api-security/
    android-permissions/
    vpn/
    uploads/
    privacy-deletion/
    billing/
    screenshots/
    logs-redacted/
```

Evidence must not contain secrets, OTPs, personal messages, real user recordings or unredacted production identifiers.

## 4. Test report template

For each test case:

```text
Test ID:
Feature:
Repository commit SHA:
Build/version:
Environment:
Device/Android version:
Preconditions:
Steps:
Expected result:
Actual result:
Status: PASS / FAIL / BLOCKED / NOT RUN
Evidence path:
Defect ID:
Tester:
Date:
```

## 5. Release gate

Internal release recommendation:
- Zero open P0/P1 security findings.
- All release-critical tests pass.
- No test marked PASS without execution evidence.
- No secrets/OTP in logs.
- No cross-user data exposure.
- No plaintext fallback for protected data.
- Permission and privacy declarations verified.
- Release AAB signed and tested.
- Rollback and incident-response process ready.
