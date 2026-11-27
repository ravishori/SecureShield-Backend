# SecureShield AI — Security Remediation Roadmap

**Starting point:** 27 November 2026 audit baseline  
**Principle:** Contain exposure first; then repair authentication, cryptography and Android policy blockers; then establish release evidence.

## Stage 0 — Incident containment

**Goal:** Reduce the immediate impact of publicly exposed configuration.

Tasks:
- Rotate/revoke all potentially exposed database, JWT, SMTP, Twilio, Anthropic and other provider credentials.
- Review database/provider logs for suspicious access.
- Verify production secrets are not sourced from committed files.
- Remove tracked `.env`, runtime logs, `.venv`, `__pycache__` and generated artifacts.
- Add root `.gitignore`.
- Review Git history and perform a coordinated history cleanup if appropriate.
- Force refresh/rotation of any sessions or signing material affected by secret rotation.
- Confirm no replacement secret is committed.

Exit evidence:
- Rotation/change records (without secret values).
- Git history scan report.
- Secret scanning report.
- Clean repository tree.
- Provider/database access review outcome.

## Stage 1 — Authentication and OTP

Tasks:
- Replace non-cryptographic OTP generation.
- Store keyed OTP verifiers.
- Implement atomic verification and single-use consumption.
- Add distributed rate limiting and abuse detection.
- Disable OTP console fallback in production.
- Redesign account lookup responses to resist enumeration.
- Add resend invalidation, attempt caps, expiry and replay tests.
- Verify JWT algorithm, issuer, audience, expiry, refresh rotation, revocation and signing-key rotation.
- Review account/device registration and session lifecycle.

Exit evidence:
- Auth threat model.
- OTP test report.
- Multi-worker rate-limit test.
- Session lifecycle test.
- No OTP values in logs.

## Stage 2 — Cryptography and sensitive data

Tasks:
- Design a versioned AES-GCM envelope.
- Generate unique nonce per encryption operation.
- Use Keystore-backed keys and key separation.
- Fail closed on crypto errors.
- Migrate old ciphertext safely.
- Review OTP vault, recordings, evidence, device identifiers and cached content.
- Review backup and restore behaviour.
- Add tamper, wrong-key, migration and data-loss recovery tests.

Exit evidence:
- Cryptographic design review.
- Migration plan and rollback strategy.
- Automated encryption tests.
- Device-level Keystore verification.

## Stage 3 — Android platform and Google Play policy

Tasks:
- Build a permission-to-feature matrix.
- Remove SMS/call-log permissions unless eligibility and Play approval path are established.
- Review `QUERY_ALL_PACKAGES`, usage access, notification listener, install packages, camera, microphone and location.
- Correct service declarations and Android 14+ foreground service types.
- Disable VPN until packet forwarding works and policy is reviewed.
- Remove cleartext traffic and legacy storage flags where unnecessary.
- Configure production API URL.
- Verify Android 16 / API 36 target for new app submission as required at this baseline date.
- Configure production signing and Play App Signing.
- Check current Play policy immediately before submission.

Exit evidence:
- Merged manifest.
- Permission declaration matrix.
- Foreground-service/VPN declarations and demo videos where applicable.
- Signed AAB verification.
- Device compatibility report.

## Stage 4 — API, file handling and privacy

Tasks:
- Add upload size limits and streaming.
- Validate MIME and file signatures.
- Generate safe server filenames.
- Use controlled file/object storage.
- Add share-link revocation and access audit.
- Redact request metadata, headers, query strings, exception traces and email alerts.
- Add account deletion and public deletion request workflow.
- Map retention/deletion across database, object storage, logs, AI providers, email and backups.
- Publish privacy policy, terms and grievance/support contact.
- Complete Data Safety worksheet based on actual SDK/network flows.
- Review DPDP Act/Rules and obtain qualified legal review.

Exit evidence:
- Data flow diagram.
- Data inventory and retention schedule.
- Privacy policy and deletion workflow tests.
- Upload security tests.
- Logging redaction tests.

## Stage 5 — Commercial and AI readiness

Tasks:
- Verify AI provider routing and all data sent to Anthropic or other providers.
- Add user notice/consent before sensitive content is sent to AI.
- Add structured output validation, uncertainty and safe fallback.
- Add budget limits, quotas and provider kill switches.
- Implement Google Play Billing if premium digital functionality is sold through the Play-distributed app.
- Verify purchase tokens server-side and implement renewals/cancellations/refunds/revocation.

Exit evidence:
- Provider/data disclosure register.
- AI privacy and quality tests.
- Billing sandbox and server verification report.

## Stage 6 — Release quality gates

Internal SecureShield release gates (not Google approval criteria):
- Zero open P0/P1 security findings.
- 100% of release-critical test cases pass.
- No known cross-user access or IDOR/BOLA defects.
- No plaintext fallback for protected data.
- No OTP, token or secret in logs.
- All permissions justified and disclosed.
- Privacy policy, Data Safety and in-app behaviour reconciled.
- Release-signed AAB tested.
- Crash/ANR and performance review completed.
- Rollback and incident-response plans approved.

## Suggested execution order

Do not begin store artwork as the main workstream while P0/P1 defects remain. Store assets can be prepared in parallel, but launch approval should remain blocked until the technical and policy gates are met.
