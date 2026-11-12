# Project status dashboard

Assessed **2026-11-12** against backend `30664ce` (branch `staging/railway-snapshot`, 61 commits ahead of `origin/staging/railway-snapshot`) and Flutter
`ac5cd50` (`main`, 17 commits ahead of `origin/main`). Nothing was changed in application code, configuration, databases or providers by this audit.

## Verdict

**NO-GO for production.** About **40%** production-ready (capped; raw weighted composite 52%). Details and the 12 go-live gates are in
[`production-readiness.md`](production-readiness.md). The product is a broad, well-tested *prototype*: the code and the automated server-side tests are
substantial, but no user can currently receive a login code, the repositories are public with exposed historical credentials, dependencies carry known
vulnerabilities, and nothing has run against a real provider or a deployed environment.

## Completion percentages

Method: [`feature-completion-matrix.md`](feature-completion-matrix.md) (38 weighted features, 0-100 per axis) and the control checklists in
[`security-audit.md`](security-audit.md), [`testing-and-qa.md`](testing-and-qa.md) and [`production-readiness.md`](production-readiness.md). Planned work is never counted.

| Dimension | % | How it is computed |
|---|---|---|
| **Overall feature implementation** | **73** | weight-weighted mean over 38 features of mean(FE, BE, INT) |
| Frontend completion | 74 | weighted mean of FE scores over all 38 rows (a backend-only feature scores 0) |
| Backend completion | 85 | weighted mean of BE scores over the 29 rows that have a backend (device-local features excluded) |
| API and database integration | 63 | weighted mean of INT; capped at 60 when the external provider was never run |
| Testing and QA | 44 | 10 weighted QA controls (suite, coverage, Flutter, Kotlin, device, external, CI, mutation checks) |
| Security hardening | 52 | 25 weighted controls (credential hygiene, authz, crypto, privacy, supply chain, signing ...) |
| Deployment readiness | 32 | 12 weighted deployment controls |
| Status-weighted feature maturity | 66 | PLANNED 0 / BUILDING .25 / BUILT .5 / TESTED .75 / REVIEWED .9 / PRODUCTION 1 |
| **Overall production readiness** | **40** (raw 52) | 0.25 impl + 0.10 integration + 0.15 testing + 0.25 security + 0.25 deployment = 52.3; **capped at 40** while any go-live blocker is open, because a product nobody can sign in to is not "half ready" |

Feature status counts: **TESTED 21, BUILT 11, BUILDING 4, REVIEWED 2, PLANNED 0, PRODUCTION 0.**

## Size of the code base (measured 2026-11-12)

| Item | Value |
|---|---|
| Backend app code | 12,604 lines Python: 24 routers, 107 routes, 20 services, 24 model files (30 ORM tables), 21 Alembic revisions (head `s4t5u6v7w8x9`) |
| Backend tests | 58 test files, 9,727 lines; **923 passed** |
| Flutter app | 160 Dart files, 39,232 lines (excl. generated l10n), 48 screens, 37 feature folders; 85 tests in 11 files |
| Android native | 12 Kotlin files, 2,677 lines; no automated tests |
| Dependencies | 16 backend requirement lines (`requirements.txt`); Flutter dependencies in `pubspec.yaml` |

## Critical gaps (summary; ranked detail in `security-audit.md`)

1. **Both GitHub repositories are PUBLIC** (verified read-only with `gh repo view` on 2026-11-12) and the backend history contains exposed credentials whose rotation was deferred.
2. **No working OTP delivery** (Twilio rejects the credentials with 20003; no e-mail provider configured) - nobody can log in on a deployed instance.
3. **Dependency vulnerabilities:** `pip-audit` reports 147 advisories in 16 packages of the backend environment, including direct pins `python-jose 3.3.0`, `starlette 0.38.6`, `python-multipart 0.0.12`, `cryptography 43.0.3`.
4. **Release APK is signed with the debug key** (no `android/key.properties`) and requests Play-restricted permissions (SMS, call log, all-packages).
5. **No external verification anywhere** (Twilio, Resend, Anthropic, Google, Safe Browsing, URLhaus) and **no deployed environment at the current SHA**.
6. **Anti-screenshot protection does not work** (method-name mismatch, never called).
7. **Retention/DPDP gaps:** no log retention policy, no privacy-notice/consent evidence in the repositories, children's data (Family "Kids") not assessed.

## Realistic remaining effort

About **70-95 developer-days** for one engineer to reach a defensible "CONDITIONAL GO" (all code-side items in [`development-roadmap.md`](development-roadmap.md)
phases 0-3), plus owner-side lead time (credential rotation, Twilio/Resend/DLT onboarding, Google Play restricted-permission review, native-speaker
translation review) that cannot be compressed by development effort - typically 3-6 weeks elapsed for Play review alone.

## What could not be verified (and why)

* Any device or emulator behaviour in this audit (no device run was performed; earlier manual runs of 2026-10-06 are cited as history, not as current evidence).
* Any real third-party provider (no credentials are valid or in scope; none were used).
* GitHub CI at the current SHA (only the 2026-10-05 run on an old SHA exists).
* Backend line/branch coverage (no coverage tool is installed in the project environment; nothing was installed into it).
* Dart dependency vulnerabilities (no Dart/OSV scanner available offline; `pip-audit` covers Python only).
* Git-history contents beyond what the register records (gitleaks is not installed on this machine; history was not re-scanned and no secret value was read).
* DPDP legal compliance (a legal determination; only technical readiness is assessed).
