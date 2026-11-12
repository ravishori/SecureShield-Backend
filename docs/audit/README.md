# SecureShield AI - audit documentation (living source of truth)

This folder is the authoritative record of what the SecureShield AI project **actually** does, how well it is tested, how secure it is and how far it is
from production. It covers both repositories (backend: this repository; Flutter app: `SecureShield-Frontend`, checked out beside it as `../flutter_app`).
It is **evidence-based**: a feature is never listed as TESTED or PRODUCTION because a file, screen or document says so.

Last full audit: **2026-11-12**; last update **2026-11-13** (P1 remediation) - verdict **NO-GO**, production readiness **40%** (see [`project-status.md`](project-status.md)).

| Document | Contents |
|---|---|
| [`project-status.md`](project-status.md) | Dashboard: verdict, completion percentages, size of the code base, critical gaps, unverifiable items |
| [`feature-completion-matrix.md`](feature-completion-matrix.md) | 38 weighted features with status (PLANNED / BUILDING / BUILT / TESTED / REVIEWED / PRODUCTION), per-axis scores, traces, gaps, effort |
| [`architecture-and-integration.md`](architecture-and-integration.md) | Verified architecture, end-to-end flows, integration gaps, state of the Neon migration |
| [`security-audit.md`](security-audit.md) | Findings ranked Critical/High/Medium/Low, MASVS and OWASP API summaries, credentials to rotate (names only) |
| [`testing-and-qa.md`](testing-and-qa.md) | Commands executed, results, coverage, what could not be verified |
| [`production-readiness.md`](production-readiness.md) | The 12 go-live gates, deployment controls, Go/No-Go |
| [`development-roadmap.md`](development-roadmap.md) | Prioritised remaining work with estimates |
| [`p1-closure-report.md`](p1-closure-report.md) | P1 closure verification: four-level status per blocker, evidence for the seven closure checks, owner actions, GO/NO-GO |
| [`deployment-runbook.md`](deployment-runbook.md) | Configuration checklist, migration/backend/Flutter procedures, staging smoke plan, DNS/monitoring/backup/rollback, Play checklist (prepared, not executed) |
| [`audit-history.md`](audit-history.md) | Dated, append-only history of findings, changes and test evidence |

Related older records (kept, not replaced): `../SECURESHIELD_FEATURE_COMPLETION_MATRIX.md`, `../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`
(register FG-001..167), `../AUDIT_2026-10-19.md`, `../neon-migration/`, `../FG-034_LOG_RETENTION_AUDIT.md`. Where they disagree with this folder, this folder reflects the
more recent verification and `audit-history.md` lists the corrections.

## Rules for editing these documents

1. **Evidence or it did not happen.** Cite file paths, function/class names, endpoints, migration ids or test results. Never mark TESTED without an automated test that passes; never mark REVIEWED without a documented security review and mutation-checked regression tests; never mark PRODUCTION without real-provider and deployed verification.
2. **Never write secrets or personal data** (keys, tokens, passwords, connection strings, phone numbers, e-mail addresses of users). Name credentials, never show them.
3. **Update the status words and the scores together**; recompute the percentages in `project-status.md` using the method in `feature-completion-matrix.md`.
4. **Record every change in `audit-history.md`** with the date, commit ids and test evidence.
5. State plainly what could not be verified and why.

The maintenance rule for contributors (human or AI) is in `CLAUDE.md` at the root of each repository.
