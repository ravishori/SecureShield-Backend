# Project status dashboard

Assessed **2026-11-13** (baseline audit 2026-11-12; P1 remediation 2026-11-13). Backend `staging/railway-snapshot` at `86b3ba2` (65 commits ahead of
`origin/staging/railway-snapshot`), Flutter `main` at `6cd21d4` (20 commits ahead of `origin/main`). **Nothing is pushed or deployed.**

## Verdict

Update 2026-11-13 (closure verification, backend `28a490c`): see [`p1-closure-report.md`](p1-closure-report.md) - **no P1 blocker is CLOSED** (none has external or production evidence) and publishing/deploying is blocked while the repositories are public. Backend suite at HEAD: 1009 passed. Interactive API docs are now off in production.

**NO-GO for production** (unchanged). About **40%** production-ready (capped; raw weighted composite 55.5%). Details and the 12 go-live gates are in
[`production-readiness.md`](production-readiness.md).

What changed since the 2026-11-12 baseline (52.3% raw / 40% capped): five P1 blockers were worked. Code-side results are in; **external steps remain**, so no gate flipped to PASS:

| P1 blocker | Result | Still needed |
|---|---|---|
| OTP delivery | Hardened (one valid code, per-code attempts, atomic use, per-source send limit). Twilio still rejects the credentials (20003, re-checked live); SMTP login with the configured account works locally (no mail sent). **No live channel proven** | Owner: fix/rotate Twilio credentials, pick e-mail provider; one live send per channel (`scripts/otp_provider_check.py --send-test-*`) |
| Release signing | Debug-key fallback removed; release builds **fail** without an external upload key; verifier and docs added | Owner: create the upload keystore; signed build + `verify_apk_signature.py` against its fingerprint |
| Anti-screenshot | Method mismatch fixed, ref-counted lifecycle, applied to 12 screens, 10 tests | Device/emulator check of the actual flag |
| Dependencies | Python: 147 advisories (stale env) / 36 (clean install of old pins) -> **0 runtime advisories** on a clean install of the new pins (2 pip/setuptools build-tool advisories remain); Dart: 0 (OSV, 207 packages); python-jose replaced by PyJWT | Rebuild local venv; Docker/Railway build; CI scan |
| Admin identity and MFA | Named accounts, RBAC, TOTP MFA, sessions, audit, CLI recovery; legacy token kept as break-glass | Create the first superadmin; set `ADMIN_LEGACY_TOKEN_ENABLED=false` after enrolment |

## Completion percentages

Method: [`feature-completion-matrix.md`](feature-completion-matrix.md) (38 weighted features, 0-100 per axis) and the control checklists in
[`security-audit.md`](security-audit.md), [`testing-and-qa.md`](testing-and-qa.md) and [`production-readiness.md`](production-readiness.md). Planned work is never counted. Baseline column = 2026-11-12.

| Dimension | Now | Baseline | How it is computed |
|---|---|---|---|
| **Overall feature implementation** | **74.5** | 73.3 | weight-weighted mean over 38 features of mean(FE, BE, INT) |
| Frontend completion | 75.2 | 73.9 | weighted mean of FE scores over all 38 rows (a backend-only feature scores 0) |
| Backend completion | 85.7 | 84.9 | weighted mean of BE scores over the 29 rows that have a backend |
| API and database integration | 63.7 | 62.9 | weighted mean of INT; capped at 60 when the external provider was never run |
| Testing and QA | 45.0 | 44.2 | 10 weighted QA controls |
| Security hardening | 60.7 | 52.0 | 26 weighted controls |
| Deployment readiness | 34.5 | 32.3 | 12 weighted deployment controls |
| Status-weighted feature maturity | 66.2 | 65.8 | PLANNED 0 / BUILDING .25 / BUILT .5 / TESTED .75 / REVIEWED .9 / PRODUCTION 1 |
| **Overall production readiness** | **40** (raw 55.5) | 40 (raw 52.3) | 0.25 impl + 0.10 integration + 0.15 testing + 0.25 security + 0.25 deployment; **capped at 40** while any go-live blocker is open |

Feature status counts: **TESTED 21, BUILT 12, BUILDING 3, REVIEWED 2, PLANNED 0, PRODUCTION 0.** (Anti-screenshot BUILDING -> BUILT.)

## Size of the code base (measured 2026-11-13)

| Item | Value |
|---|---|
| Backend app code | 25 router modules / 126 routes, 22 services, 25 model files (32 ORM tables), 23 Alembic revisions (head `u6v7w8x9y0z1`) |
| Backend tests | 63 test files; **1009 passed** at `1bcdf16` (was 923); +3 docs-gate tests added afterwards |
| Flutter app | 160 Dart files, 48 screens; **95 tests** in 12 files (was 85); 3 Python tool tests |
| Android native | 12 Kotlin files; no automated tests |

## Critical gaps (ranked detail in `security-audit.md`)

1. **Both GitHub repositories are PUBLIC** with exposed historical credentials, rotation deferred (S-01, Critical) - unchanged and still the first thing to do.
2. **No live OTP channel** (Twilio 20003; no Resend key; Railway blocks SMTP) - nobody can sign in on a deployed instance.
3. No upload keystore: nothing built from this repository can be distributed.
4. No external verification anywhere and no deployed environment at the current SHA; GitHub CI has not run for 65 commits.
5. Play restricted-permission risk and DPDP gaps (retention, notices, minors) - unchanged.
6. Shared legacy admin token is still enabled by default until named admins are enrolled.

## Realistic remaining effort

About **~60-75 developer-days** (was 70-95) for phases 1-3 of [`development-roadmap.md`](development-roadmap.md), plus owner-side lead time (credentials, provider onboarding, Play review, translation review).

## What could not be verified (and why)

* Android behaviour on a real device in this session (no device attached; an AVD exists but was not started): FLAG_SECURE effect, share sheet, release APK install.
* A successful signed release build (needs the owner's keystore, which this repository never generates).
* Any real third-party delivery or API call: Twilio rejects the credentials; no message of any kind was sent.
* A Railway (Railpack) build and deployment of the upgraded dependencies on staging (Docker is not an approved deployment path).
* GitHub CI at the current SHA; Dart vulnerability coverage beyond OSV's pub data; Gradle/AndroidX native dependency advisories.
* Git-history contents (gitleaks not installed); DPDP legal compliance.
