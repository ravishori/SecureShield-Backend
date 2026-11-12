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
| **Phases 0-3 (to CONDITIONAL GO / closed beta)** | **~80 (range 70-95)** |
| 4 Post-launch scope | 15-20 |

## Phase 0 - immediate containment (this week)

| # | Task | Owner | Dev-days | Closes |
|---|---|---|---|---|
| 0.1 | Make both GitHub repositories private; rotate every credential listed in `security-audit.md`; decide history rewrite vs abandon | Owner | - | S-01, G2 |
| 0.2 | Verify the Twilio SID/token pair in the Console (see 2026-10-18 diagnosis); choose and onboard an HTTPS e-mail provider | Owner | - | S-03, G1 |
| 0.3 | Review and commit (or discard) the uncommitted Neon connection fix (`app/config.py`, `app/database.py`, `.env.example`, `tests/unit/test_database_engine.py`) and decide the fate of `scripts/seed_sms_registry.py` / `start.bat` | Owner + dev | 1 | architecture |
| 0.4 | Remove stale credential copies and the drive-wide `D:\.git` once rotation is done | Owner | 0.5 | S-15 |
| 0.5 | Decide retention periods (FG-034) and the SMS/call-log feature scope | Owner | 0.5 | S-05, S-07 |

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
