# Production readiness - Go / No-Go

Assessed 2026-11-12. **Verdict: NO-GO.** Overall production readiness **40%** (raw weighted composite 52%, capped at 40% because go-live blockers are open;
method in [`project-status.md`](project-status.md)). Proposed next verdict after phases 0-2 of [`development-roadmap.md`](development-roadmap.md): CONDITIONAL GO for a limited
closed beta; GO only after every gate below passes.

## Go-live gates (all must pass; 0 of 12 pass today)

| # | Gate | State | Evidence |
|---|---|---|---|
| G1 | A user can receive a login code (at least one real OTP channel verified live) | **FAIL** | Twilio 20003; no e-mail provider; delivery only simulated (`otp_service.py`, FG-001..003) |
| G2 | All credentials that ever appeared in Git history rotated; repositories private | **FAIL** | repos PUBLIC (verified); rotation deferred (security-audit S-01) |
| G3 | No known-vulnerable runtime dependency left unmitigated | **FAIL** | 147 advisories / 16 packages (S-02) |
| G4 | CI green on GitHub at the release SHA for both repositories | **FAIL** | backend: one green run on an SHA 61 commits old; Flutter repo has no workflow |
| G5 | Production environment configured: real secrets, `TRUSTED_PROXIES` verified for the host, CORS, `ENVIRONMENT=production` startup checks pass | **FAIL** | proxy range unmeasured (FG-167); production environment not created |
| G6 | Production database ready and backed up with a proven restore | **PARTIAL** | Neon schema + data migrated and validated 2026-10-18, cutover not done; backup tooling exists, schedule disabled |
| G7 | Release APK/AAB signed with an upload key | **FAIL** | debug-key fallback (S-04) |
| G8 | Play Console compliance: permission declarations, data-safety form, privacy policy | **FAIL** | restricted permissions (S-05); no notice artefacts |
| G9 | Real-provider verification of each shipped integration (Anthropic, Safe Browsing, URLhaus, Google, panic SMS/e-mail) | **FAIL** | none run |
| G10 | Device end-to-end on the release build (Android 10/13/15) including evidence retrieval and panic | **FAIL** | no device run in this audit; manual runs of 2026-10-06 are historical and used a local backend |
| G11 | Retention and DPDP basics: retention periods implemented, notice/consent captured, erasure path reachable in the UI | **FAIL** | FG-034 open; erasure UI path not assessed |
| G12 | Monitoring and incident response: alerting that works, error mail transport, a named admin with individual identity | **FAIL** | error alert e-mail blocked on Railway; shared admin token; no admin created |

## Deployment controls scored (12 weighted controls; result 32%)

| Control | Weight | Credit | Note |
|---|---|---|---|
| Image, start command, `/health` `/ready` `/version` | 2 | 1.0 | `Dockerfile`, `.railway/railway.ts` |
| Migrations as a controlled pre-deploy step | 2 | 0.9 | `alembic upgrade head` pre-deploy; single head verified |
| Production database provisioned and migrated | 3 | 0.5 | Neon done/validated; no cutover; Railway production not created |
| Git-based deployment connected | 2 | 0 | CLI uploads only |
| CI run on GitHub | 3 | 0.3 | one stale green run |
| Production secrets set; placeholders refused at boot | 3 | 0.25 | startup refuses placeholders; real values not provisioned |
| Trusted proxy verified | 2 | 0 | unknown |
| Monitoring/alerting | 2 | 0.1 | none working |
| Horizontal scale readiness | 1 | 0 | in-memory limiter, local-disk uploads, 1 replica |
| Release signing and Play prerequisites | 3 | 0.1 | debug key |
| Rollback and DR procedure | 2 | 0.8 | `../neon-migration/ROLLBACK_PROCEDURE.md`, backup tooling; rehearsed |
| Live provider verification | 3 | 0 | none |

## What is solid

Sessions and token lifecycle, object-level authorisation tests, upload/evidence safety, log scrubbing, account erasure, schema-drift protection, a
rehearsed and validated database migration, a guarded migration toolkit, clean static analysis, 923 backend tests and 85 Flutter tests.

## Outstanding requirements to reach GO (owner / external)

1. Rotate credentials, make repositories private, decide history handling (owner).
2. Twilio Console verification + e-mail provider + India DLT (owner).
3. Upload keystore, Play Console set-up and restricted-permission declarations (owner).
4. Legal review of DPDP position, retention periods, minors (owner/legal).
5. Provide and verify the proxy range of the chosen host (owner/ops).
6. Provide real provider keys with spend limits for verification (owner).

## Decision log needed from the owner

Retention periods (FG-034); whether to keep SMS/call-log features given Play policy; per-person admin identities vs shared token; Neon vs Railway as the
production database; whether the Cyber Warriors programme and the client-only detectors ship in v1.
