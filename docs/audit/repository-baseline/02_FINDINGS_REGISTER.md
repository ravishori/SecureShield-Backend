# SecureShield AI — Findings Register

**Baseline:** 27 November 2026  
**Status vocabulary:** Open / In Progress / Fixed — Awaiting Verification / Verified Closed / Accepted Risk

> All findings start as **Open**. No remediation has been performed or verified as part of this audit.

| ID | Severity | Area | Finding | Evidence | Required outcome |
|---|---|---|---|---|---|
| SS-AUD-001 | P0 | Secrets | Tracked `.env` and hardcoded credentials/configuration | Backend `.env`, `app/config.py` | Rotate, revoke, remove from history, managed secrets |
| SS-AUD-002 | P0 | Repository hygiene | `.venv`, bytecode and runtime logs tracked | Backend recursive tree | Remove artifacts; add root `.gitignore` |
| SS-AUD-003 | P1 | OTP | OTP uses `random.randint()` | `app/routers/auth.py` | Use cryptographic RNG |
| SS-AUD-004 | P1 | OTP | OTP stored as plaintext | `app/models/user.py`, auth router | Store keyed verifier/hash; atomic consume |
| SS-AUD-005 | P1 | OTP | Console fallback prints OTP | `app/services/otp_service.py` | Fail closed; no OTP in logs |
| SS-AUD-006 | P1 | Rate limiting | OTP/API limiter is process-local memory | `app/middleware/rate_limiter.py` | Shared/distributed limiter |
| SS-AUD-007 | P1 | Enumeration | Account lookup endpoint reveals existence | `app/routers/auth.py` | Enumeration-resistant responses and abuse controls |
| SS-AUD-008 | P1 | Android permissions | SMS and call-log permissions declared | Android manifest | Remove unless policy-qualified and approved |
| SS-AUD-009 | P1 | Android permissions | Broad package visibility/usage access declared | Android manifest | Justify, minimise and declare |
| SS-AUD-010 | P1 | Encryption | AES-CBC with reused IV | Flutter encryption service | AEAD, unique nonce and versioned format |
| SS-AUD-011 | P1 | Encryption | Plaintext returned on crypto failure | Flutter encryption service | Fail closed; never silently downgrade |
| SS-AUD-012 | P1 | Release | Debug signing used for release | `android/app/build.gradle.kts` | Secure release signing and verify AAB |
| SS-AUD-013 | P1 | VPN | TUN capture path has no identified packet forwarding | Kotlin VPN service | Disable until functional forwarding and tests |
| SS-AUD-014 | P1 | Network | Cleartext traffic enabled | Android manifest | HTTPS-only production policy |
| SS-AUD-015 | P1 | Network | Hardcoded LAN IP in app config | `lib/core/app_config.dart` | Environment-specific production URL |
| SS-AUD-016 | P1 | Logging | Potential sensitive headers/query/traceback exposure | Error handler/logger | Redaction and privacy-safe sinks |
| SS-AUD-017 | P1 | Uploads | Entire upload read into memory | Recording/evidence routers | Streaming/size limits and content validation |
| SS-AUD-018 | P1 | Uploads | Client filename used in storage path | Recording/evidence routers | Server-generated filename and safe storage |
| SS-AUD-019 | P1 | Service | AppMonitorService absent from inspected manifest | Manifest, Kotlin service, MainActivity | Verify merged manifest; register correctly |
| SS-AUD-020 | P1 | Recording | Microphone capture is not telephony audio | Recording service | Accurate feature claim and consent/legal review |
| SS-AUD-021 | P2 | Privacy | Account deletion workflow not established | Selected source search | Implement end-to-end deletion |
| SS-AUD-022 | P2 | Privacy | Privacy policy and data flow not established in source | Selected source search | Public policy aligned with actual data |
| SS-AUD-023 | P2 | Billing | Premium tier exists; billing integration not established | User model/dependencies | Play Billing and server-side entitlement |
| SS-AUD-024 | P2 | Release | Effective target API not confirmed | Gradle delegates to Flutter | Verify built artifact targets API 36+ |
| SS-AUD-025 | P2 | Storage | Legacy storage flags remain | Android manifest | Remove if not required; modern scoped storage |
| SS-AUD-026 | P2 | Evidence | Share-link revocation/access controls need review | Recording router | Revoke, audit and test bearer-link lifecycle |
| SS-AUD-027 | P2 | Data model | OTP model and initial migration require schema reconciliation | User model and Alembic initial revision | Review model/migration drift before next migration |

## Finding lifecycle

For each finding, maintain:
- Owner
- Target milestone
- Fix PR/commit
- Tests added
- Test execution result
- Manual/device evidence
- Reviewer
- Closure date
- Residual risk

A finding may only become `Verified Closed` after the evidence is recorded. A code change alone is not closure.

## Suggested priority order

1. SS-AUD-001 and SS-AUD-002 — contain exposure and repository leakage.
2. SS-AUD-003 through SS-AUD-007 — authentication/OTP.
3. SS-AUD-010 and SS-AUD-011 — encryption.
4. SS-AUD-008 and SS-AUD-009 — permissions and Play policy.
5. SS-AUD-012 through SS-AUD-015 — release/network/VPN.
6. SS-AUD-016 through SS-AUD-020 — logging, uploads and Android services.
7. SS-AUD-021 through SS-AUD-027 — privacy, billing, migrations and release evidence.
