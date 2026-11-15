# Production readiness - Go / No-Go

Assessed 2026-11-12, updated 2026-11-13 after the P1 remediation. **Verdict: NO-GO.** Overall production readiness **40%** (raw weighted composite 55.5%, was 52.3%, capped at 40% because go-live blockers are open;
method in [`project-status.md`](project-status.md)). Proposed next verdict after phases 0-2 of [`development-roadmap.md`](development-roadmap.md): CONDITIONAL GO for a limited
closed beta; GO only after every gate below passes.

Closure verification of 2026-11-13 and the procedures needed to pass these gates: [`p1-closure-report.md`](p1-closure-report.md), [`deployment-runbook.md`](deployment-runbook.md).

Architecture note 2026-11-13: deployment is Docker-free (Railway native Python); Docker is **not** a prerequisite for any gate. See `deployment-runbook.md`.

## Go-live gates (all must pass; 0 of 12 pass today)

| # | Gate | State | Evidence |
|---|---|---|---|
| G1 | A user can receive a login code (at least one real OTP channel verified live) | **FAIL** | OTP logic hardened 2026-11-13 (attempt limit, single code, per-source cap). Twilio still rejects the credentials (20003, live read-only check); SMTP login works locally but Railway blocks SMTP; no Resend key; no message has been sent end to end. Use `scripts/otp_provider_check.py --live --send-test-email/--send-test-sms` once credentials are fixed |
| G2 | All credentials that ever appeared in Git history rotated; repositories private | **FAIL** | repos PUBLIC (verified); rotation deferred (security-audit S-01) |
| G3 | No known-vulnerable runtime dependency left unmitigated | **PARTIAL** | Fixed in the repository (commit `b9be388`): a clean install has 0 runtime advisories, Dart 0 (OSV). Not yet shown on a Docker/Railway build or in CI; the local `.venv` is stale and must be rebuilt (S-02) |
| G4 | CI green on GitHub at the release SHA for both repositories | **FAIL** | backend: one green run on an SHA 61 commits old; Flutter repo has no workflow |
| G5 | Production environment configured: real secrets, `TRUSTED_PROXIES` verified for the host, CORS, `ENVIRONMENT=production` startup checks pass | **FAIL** | proxy range unmeasured (FG-167); production environment not created |
| G6 | Production database ready and backed up with a proven restore | **PARTIAL** | Neon schema + data migrated and validated 2026-10-18, cutover not done; backup tooling exists, schedule disabled |
| G7 | Release APK/AAB signed with an upload key | **FAIL** | Debug-key fallback removed and release builds fail without an external key (verified); **no upload keystore exists**, so no signed build or fingerprint check yet (S-04) |
| G8 | Play Console compliance: permission declarations, data-safety form, privacy policy | **FAIL** | restricted permissions (S-05); no notice artefacts |
| G9 | Real-provider verification of each shipped integration (Anthropic, Safe Browsing, URLhaus, Google, panic SMS/e-mail) | **FAIL** | none run |
| G10 | Device end-to-end on the release build (Android 10/13/15) including evidence retrieval and panic | **FAIL** | no device run in this audit; manual runs of 2026-10-06 are historical and used a local backend |
| G11 | Retention and DPDP basics: retention periods implemented, notice/consent captured, erasure path reachable in the UI | **FAIL** | FG-034 open; erasure UI path not assessed |
| G12 | Monitoring and incident response: alerting that works, error mail transport, a named admin with individual identity | **PARTIAL** | Named admin accounts with TOTP MFA, RBAC, sessions and audit exist and are tested (S-06); **no admin account has been created in any real environment**, the legacy token is still enabled by default, error alert e-mail is blocked on Railway, no alerting on admin actions |

## Deployment controls scored (12 weighted controls; result 34.5%, was 32.3%)

| Control | Weight | Credit | Note |
|---|---|---|---|
| Build, start command, `/health` `/ready` `/version` | 2 | 1.0 | `.railway/railway.ts` (Railpack; the `Dockerfile` is an unused artefact) |
| Migrations as a controlled pre-deploy step | 2 | 0.9 | `alembic upgrade head` pre-deploy; single head verified |
| Production database provisioned and migrated | 3 | 0.5 | Neon done/validated; no cutover; Railway production not created |
| Git-based deployment connected | 2 | 0 | CLI uploads only |
| CI run on GitHub | 3 | 0.3 | one stale green run |
| Production secrets set; placeholders refused at boot | 3 | 0.25 | startup refuses placeholders; real values not provisioned |
| Trusted proxy verified | 2 | 0 | unknown |
| Monitoring/alerting | 2 | 0.1 | none working |
| Horizontal scale readiness | 1 | 0 | in-memory limiter, local-disk uploads, 1 replica |
| Release signing and Play prerequisites | 3 | 0.3 | signing is enforced fail-closed and verifiable (`tool/verify_apk_signature.py`); no keystore, no Play prerequisites |
| Rollback and DR procedure | 2 | 0.8 | `../neon-migration/ROLLBACK_PROCEDURE.md`, backup tooling; rehearsed |
| Live provider verification | 3 | 0 | none |

## What is solid

Sessions and token lifecycle, object-level authorisation tests, hardened OTP verification, named admin accounts with MFA, upload/evidence safety, log scrubbing, account erasure, schema-drift protection, a
rehearsed and validated database migration, a guarded migration toolkit, clean static analysis, a clean dependency scan, 1006 backend tests and 95 Flutter tests.

## Outstanding requirements to reach GO (owner / external)

1. Rotate credentials, make repositories private, decide history handling (owner).
2. Twilio Console verification (the SID/token pair is rejected) + e-mail provider + India DLT (owner); then one live send per channel.
3. Upload keystore (the build now refuses to produce a release without it), Play Console set-up and restricted-permission declarations (owner).
4. Legal review of DPDP position, retention periods, minors (owner/legal).
5. Provide and verify the proxy range of the chosen host (owner/ops).
6. Provide real provider keys with spend limits for verification (owner).

## Decision log needed from the owner

Retention periods (FG-034); whether to keep SMS/call-log features given Play policy; per-person admin identities vs shared token; Neon vs Railway as the
production database; whether the Cyber Warriors programme and the client-only detectors ship in v1.
7. Create the first superadmin with `python -m app.cli.admin_accounts create`, enrol MFA, then set `ADMIN_LEGACY_TOKEN_ENABLED=false` (owner/ops).
8. Rebuild the local virtual environment from the new `requirements.txt`, and verify the Railway (Railpack) build and deploy of the upgraded stack on staging (ops). Docker is not an approved deployment path.
