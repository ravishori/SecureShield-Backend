# SecureShield AI - Release Readiness (master control document)

Repository: `ravishori/SecureShield-Backend` (Flutter app: `ravishori/SecureShield-Frontend`). Created **2026-11-13**.
This is the primary operational reference. It consolidates the existing reports in this folder; it is **not** a new audit. Detail stays in the linked documents; this file holds status, risks, decisions and next actions.

> **Evidence rule.** Every status below cites a source document and an evidence date. Values marked *(reported)* were supplied as historical facts by the owner or taken from earlier session records and were **not re-verified when this document was written**. Nothing here claims an operation happened unless the cited record shows it.

## CHANGE CONTROL - AVOID REPEATED AUDITS

1. Do **not** repeat a completed audit without a specific, written reason (new code, new environment, contradicted evidence).
2. **Reuse existing evidence.** Link to it; do not re-derive it.
3. **Update only the affected sections** of this file (and the matching detail document).
4. **Retest only the affected components** plus the necessary regression tests.
5. Record every new finding in the **Security Risk Register** (section 13) with an ID.
6. **Close a finding only with verifiable evidence** (command + result + date, or a link to a record). "Code written" is not closure.
7. Record owner **approvals and deployment decisions** in section 16.
8. **Never claim an operation happened without evidence** (push, deploy, migration, rotation, e-mail sent, CI run).
9. Append every edit to section 18 with date, commit ids and test evidence.

### Status vocabulary (only these eight words)

| Status | Meaning here |
|---|---|
| PLANNED | decided or designed, no code or configuration yet |
| BUILDING | partly implemented |
| BUILT | implemented in a repository; no passing automated test is claimed |
| TESTED | automated tests pass (tests run against simulated providers/local DB) |
| REVIEWED | TESTED plus a documented security review and mutation-checked regression tests |
| PRODUCTION | verified against the real provider **and** in a deployed environment (nothing is at this level) |
| BLOCKED | cannot proceed without an external action (owner, provider, approval) |
| DEFERRED | consciously postponed by owner decision |

Implementation, deployment and provider verification are **three separate facts**. A row can be TESTED (code) and still be BLOCKED for deployment or provider verification; those are stated in separate columns where it matters.

### Source documents used

Present and used: `README.md`, `project-status.md`, `feature-completion-matrix.md`, `architecture-and-integration.md`, `security-audit.md`, `testing-and-qa.md`, `production-readiness.md`, `development-roadmap.md`, `p1-closure-report.md`, `deployment-runbook.md`, `infrastructure-setup.md` (uncommitted), `audit-history.md`, `../RESEND_SETUP.md`, `../RAILWAY_DEPLOYMENT.md`, `../STAGING_DEPLOYMENT_PLAN.md`, `../MIGRATION_SAFETY_REVIEW.md`, `../BACKUP_AND_RECOVERY.md`, `../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`.
**Requested but not present in the repository:** `system-inventory.md`, `findings-register.md`, `test-evidence-log.md`, `admin-security.md`, `payments.md`, `pyq-answer-quality.md`. Their equivalents are `architecture-and-integration.md`, `security-audit.md` + `../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md` (FG-001..167), `testing-and-qa.md` + `audit-history.md`, and the admin section of `security-audit.md`. No payments or PYQ-answer-quality documentation exists in the repository; this document makes **no statement** about those topics.

---

## 1. Executive Project Dashboard

| Item | State | Evidence (date) |
|---|---|---|
| **Overall verdict** | **NO-GO for production** | `production-readiness.md` (2026-11-13) |
| Production readiness | **40%** (raw weighted 55.5%, capped while go-live blockers are open) | `project-status.md` (2026-11-13) |
| Feature implementation (weighted) | 74.5% - TESTED 21, BUILT 12, BUILDING 3, REVIEWED 2, PLANNED 0, PRODUCTION 0 | `feature-completion-matrix.md` |
| Go-live gates passing | **0 of 12** | `production-readiness.md` |
| Backend release candidate | 74 commits ahead of the deployed commit; **not pushed, not deployed** | *(reported)* |
| Staging environment | Railway runs old commit `976ce42` (no Resend code); new code not deployed | *(reported)* |
| Blocking items | exposed credentials un-rotated (DEFERRED by owner), no live OTP channel, no CI run on the release, no backup/restore proof, pending migrations, no upload keystore, no device test | section 15 |

**Latest backend test evidence:** 1009 backend tests passed on a clean install at `1bcdf16`; 3 docs-gate tests added at `28a490c` (`testing-and-qa.md`, 2026-11-13). Flutter: 95 tests passed (2026-11-13).

## 2. Product Overview and Architecture

Android security companion for India: OTP login, scam/phishing/app/Wi-Fi/link scanners, evidence locker, panic and guardian alerts, family safety, AI coach (Anthropic), reports, admin console. Details: `architecture-and-integration.md`.

* **Client:** Flutter/Dart (Riverpod, GoRouter, Dio) + 12 Kotlin native files; 160 Dart files, 48 screens.
* **Backend:** FastAPI (Python 3.11), SQLAlchemy 2 async + asyncpg, Alembic; 25 routers / 126 routes, 22 services, 32 ORM tables, 23 revisions (head `u6v7w8x9y0z1`). Dependency set upgraded in `b9be388` (PyJWT replaces python-jose; current FastAPI/Starlette). *(The version string "FastAPI 0.115" in older diagrams is stale.)*
* **Data:** PostgreSQL. Staging DB is a Railway Postgres service. Neon migration was validated 2026-10-18 but cutover is **not** done (`../neon-migration/`).
* **Hosting decision:** Docker-free. Railway native builder (Railpack), `alembic upgrade head` as pre-deploy step, health check `/health`. GitHub Actions without Docker. A `Dockerfile` still exists but is not part of the deployment path.
* **Email:** Resend (HTTPS) is the chosen provider. Twilio is not to be reintroduced for e-mail; the SMS/WhatsApp code path exists and fails closed without valid credentials.

## 3. Frontend and Backend Repository Status

| Repository | Local | Remote | Divergence | Pushed? | Source |
|---|---|---|---|---|---|
| Backend `SecureShield-Backend` | `staging/railway-snapshot` @ `a91c79a` | staging branch @ `976ce42`; `main` @ `8fcb5af` | **74 commits ahead** (all intended as one release) | **No** | *(reported)* |
| Backend candidate branch | `staging/candidate-2026-11-13` created locally 2026-11-13 | not pushed | holds Phase 7 working-tree changes (uncommitted) | **No** | local git (2026-11-13) |
| Frontend `SecureShield-Frontend` | `main` @ `815cbd9` | `main` @ `6a191b5` | **23 commits ahead** | **No** | *(reported)* |

* Both repositories were made **private** by the owner on 2026-11-13 (`infrastructure-setup.md` execution record). History still contains previously exposed credentials (R-01).
* **Uncommitted owner work in the backend (must be preserved, never staged by release tooling):** Neon connection fix (`app/config.py`, `app/database.py`, `.env.example`, `tests/unit/test_db_url_normalization.py`, `tests/unit/test_database_engine.py`), `scripts/seed_sms_registry.py`, `start.bat`, `docs/audit/infrastructure-setup.md`.
* **Uncommitted Phase 7 work (this branch):** `app/delivery_settings.py`, edits to `otp_service.py`, `notifications.py`, `logger_service.py`, `file_crypto.py`, `upload_safety.py`, `startup_checks.py`, new `tests/unit/test_smtp_fallback_switch.py`. See section 4 and section 12.
* Release-range secret scan (`976ce42..a91c79a`, 214 files, about 21,163 added lines, session record 2026-11-13): only deliberately fake test fixtures (allowlisted in `.gitleaks.toml`); no real secrets, keystores, `.env` files, logs or personal e-mail addresses. gitleaks itself has not been run (CI will).

## 4. Feature Implementation Inventory

38 weighted features; full per-feature trace, tests and gaps are in `feature-completion-matrix.md` (do not duplicate here). Summary by status (2026-11-13):

| Status | Count | Examples |
|---|---|---|
| REVIEWED | 2 | Session/JWT lifecycle; account deletion/erasure |
| TESTED | 21 | OTP login (logic), alerts, scanners, evidence locker, recordings, family, panic (mocked providers), reports, admin API and console |
| BUILT | 12 | Security dashboard, bank-OTP detection, device scan, remote-access detector, VPN monitor, AI coach, anti-screenshot, client-only detectors, video call |
| BUILDING | 3 | Google Sign-In (no OAuth client IDs), Cyber Warriors (no client), localization (44%) |
| PLANNED / PRODUCTION | 0 / 0 | - |

"TESTED" means automated tests with simulated providers. **No feature is PRODUCTION.**

### Release-hardening work in progress (Phase 7, 2026-11-13)

| Item | Status | Evidence / gap |
|---|---|---|
| Resend e-mail adapter (`otp_service._send_email_resend`, introduced in `1335678`) | TESTED (simulated provider) | `tests/unit/test_otp_resend.py`; **not deployed, not verified against the real provider** |
| `SMTP_FALLBACK_ENABLED` switch (default `true`; gates OTP fallback, guardian/panic/report mail, error-alert mail) | TESTED (simulated providers) | `app/delivery_settings.py` + 3 call sites. `tests/unit/test_smtp_fallback_switch.py`: 13 passed, 0 skipped. The error-alert path is now genuinely tested (database write replaced; enabled -> sent, disabled -> not sent, no recipient -> not sent). 4 gate mutations caught. **Uncommitted; not deployed; no real SMTP/Resend traffic** |
| `FILE_ENCRYPTION_REQUIRED` + key validation at startup (32 decoded bytes, AES-256-GCM unchanged, plaintext files stay readable, no plaintext writes when required) | TESTED (local) | `startup_checks.check_file_encryption`, `file_crypto.active_key_for_write`, `upload_safety._write_key`. `tests/unit/test_file_encryption_required.py` (missing/blank/malformed/wrong-length/valid/unpadded keys, keyring errors, no key text in errors, 503 and no file written when required, `save_text` encrypt/plain) plus 2 integration tests (required+no key -> 503, nothing written; legacy plaintext downloads still work after the key and `REQUIRED` are set, new uploads encrypted). 6 mutations caught. **Uncommitted; staging key not set; startup behaviour on Railway unverified** |
| `deploy-staging.yml` allowed refs | TESTED (guard script executed locally) | only the exact branch `staging/railway-snapshot` (tags incl. all `v*`, candidate and other branches rejected); guard runs **before** checkout and takes the ref via `env` (no inline interpolation); `tests/unit/test_deploy_workflow_refs.py` runs the guard in bash against 14 refs (accepted: 1; rejected: candidate, other staging branches, look-alikes, `refs/heads/...`, 4 `v*` tags, `release/1`, `main`, empty) and asserts manual-only trigger and that CI still covers `staging/**` independently; re-adding `v*` is caught by 4 failing cases. The workflow itself has never executed on GitHub |

## 5. Security and Privacy Status

Source: `security-audit.md` (baseline 2026-11-12, updated 2026-11-13). Security hardening score **60.7%** (26 weighted controls).

| Area | Status | Notes |
|---|---|---|
| Session/token lifecycle | REVIEWED | refresh rotation, replay revoke, token-type checks |
| Dependencies | BUILT (repo) | clean install: 0 runtime advisories; 11 build-tool advisories (pip/setuptools); Dart 0 (OSV). Not shown on a Railway build or in CI |
| Admin identity and MFA | TESTED | named accounts, TOTP, RBAC, audit; **no admin created in any real environment** (R-08) |
| Upload safety, log scrubbing, erasure | TESTED / REVIEWED | see matrix |
| Server-side file encryption | BUILT | off until `FILE_ENCRYPTION_KEY` is set (R-03) |
| API docs in production | TESTED | disabled when `ENVIRONMENT=production` (`28a490c`) |
| Rate limiting | BUILT | in-memory, per process (R-12) |
| Anti-screenshot (FLAG_SECURE) | BUILT | mocked tests only; no device check |
| DPDP readiness | PLANNED | retention, notice, consent, minors unresolved (R-13) |
| Play restricted permissions | BLOCKED | SMS/call-log/QUERY_ALL_PACKAGES risk (R-14) |

## 6. Authentication and OTP Status

| Item | Status | Evidence |
|---|---|---|
| OTP generation, HMAC at rest, 10-min TTL, per-code attempt burn after 5, newest-code-only, atomic use, 20 sends/h/source | TESTED | 13 hardening tests; 4 mutations caught (`f06a3d8`) |
| Delivery order: Resend -> SMTP (only if `SMTP_HOST` set) -> generic 503 | TESTED (simulated) | `test_otp_resend.py` |
| SMTP gate for this order | BUILT | Phase 7 (section 4) |
| Resend live send | BLOCKED | no real message has been sent; owner approval required for one test send |
| Twilio SMS/WhatsApp | BLOCKED / DEFERRED | credentials rejected (20003, 2026-11-13); owner decision: do not introduce Twilio for e-mail |
| Google Sign-In | BUILDING | needs OAuth client IDs (`GOOGLE_CLIENT_IDS`) |
| Admin legacy token | BUILT | `ADMIN_LEGACY_TOKEN_ENABLED` default `true`; the owner-authorised Railway setting `false` is *(reported)*; verified on a local server 2026-11-13 |

Gate G1 (a user can receive a login code on a deployed instance): **FAIL / BLOCKED** until Resend is deployed and verified.

## 7. AI and Third-party Provider Status

No provider has been verified live from this code. All entries are TESTED against simulated providers at most.

| Provider | Use | Code | Live verification | Notes |
|---|---|---|---|---|
| Resend | OTP and notification e-mail | TESTED | **not run** | domain `mail.trinetralab.net` Verified *(reported)*; sending-only key restricted to that domain *(reported)*; SPF/DKIM/MX present and `_dmarc` = `p=none` (session record 2026-11-13); sender `SecureShield <no-reply@mail.trinetralab.net>` |
| Anthropic | AI coach, complaint mail, message analyzer | TESTED (fake client) | not run | model ids hard-coded (S-20); previously exposed key (R-01) |
| Google Safe Browsing / abuse.ch URLhaus | link scanner | TESTED (simulated) | not run | URLs leave the device; privacy notice needed (S-16) |
| Twilio | SMS/WhatsApp, guardian SMS | BUILT | **rejected** (20003) | do not reintroduce; credentials exposed (R-01) |
| Google ID tokens | Google Sign-In | BUILDING | not run | needs client IDs |
| Azure Translator | localization tooling | - | not run | listed in compromised-credentials inventory |

## 8. Database and Migration Status

| Item | Value | Source |
|---|---|---|
| Staging DB (Railway Postgres service) | 29 tables, 23,278 rows; `sms_sender_registry` 23,192 rows; user-data tables empty | *(reported; read-only probe 2026-11-13)* |
| Current staging revision | `l7m8n9o0p1q2` | *(reported)* |
| Target revision | `u6v7w8x9y0z1` (single head) | `architecture-and-integration.md` |
| Pending migrations | **9** (`m8n9o0p1q2r3`, `n9o0p1q2r3s4`, `o0p1q2r3s4t5`, `p1q2r3s4t5u6`, `q2r3s4t5u6v7`, `r3s4t5u6v7w8`, `s4t5u6v7w8x9`, `t5u6v7w8x9y0`, `u6v7w8x9y0z1`) | `../MIGRATION_SAFETY_REVIEW.md` |
| Executed during the reported deployment | **None** - deployment `e75a63cd` ran old commit; revision unchanged | *(reported)* |
| Destructive steps among the nine | `n9o0...` deletes duplicate `security_reports`; `q2r3...` empties `otps`; `p1q2...` alerttype enum is irreversible; `u6v7...` downgrade destroys admin accounts. All affected staging tables were empty when probed | migration safety review (2026-11-13) |
| Migration test evidence | upgrade/repeat/downgrade/re-upgrade passed on a populated **disposable** DB; `test_schema_drift` passes | `p1-closure-report.md` |
| Neon | at `s4t5u6v7w8x9` (2026-10-18 state, not re-read); cutover not done | `p1-closure-report.md` |
| Backup / restore | tooling exists; **no backup taken and no restore proven** for staging | R-07 |

**Status: BUILT and TESTED (disposable DB). Not applied to any real database.** Applying requires explicit approval (section 16) and a prior backup.

## 9. Infrastructure and Cloud Services

| Service | Detail | Status |
|---|---|---|
| Railway project | `secureshield-staging`, environment `staging` (renamed from `production` by owner 2026-11-13) | PRODUCTION-equivalent *(staging only)* - old commit running |
| API service | `secureshield-api`, GitHub source `ravishori/SecureShield-Backend`, branch **`staging/railway-snapshot`**, builder Railpack, pre-deploy `alembic upgrade head`, health `/health` (60 s). **Auto-deploys on push** to that branch | configuration read 2026-11-13 |
| Postgres service | `Postgres` (internal host, database `railway`) | running |
| Latest reported API deployment | `e75a63cd` (triggered by a variable change; runs `976ce42`) | *(reported)* |
| Railway variables | `RESEND_FROM_EMAIL`, `RESEND_API_KEY` present *(reported)*; values never printed. Missing/unset: `FILE_ENCRYPTION_KEY`, `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`; start command and Python version not verified | R-03..R-06, R-11 |
| Resend | sending domain Verified; key restricted to domain | *(reported)* |
| Secrets present in Railway staging from the old setup | Twilio, Anthropic, Safe Browsing, SMTP, `SECRET_KEY`, `ADMIN_TOKEN` (exposed history) | R-01, R-02 (rotation DEFERRED) |
| Android upload keystore | does **not** exist | BLOCKED (R-15) |

## 10. GitHub and CI/CD Status

| Workflow | Trigger | Behaviour | Executed? |
|---|---|---|---|
| `backend-ci.yml` | push to `main` and `staging/**`; pull requests | gitleaks, ruff check/format, pip-audit, alembic on a blank DB, pytest on a Postgres service; inert CI placeholder values only | **Run 43381648865 on `e367eb6` (2026-11-13): FAILED** at the ruff format step (see CI-1 below); later steps (pip-audit, alembic, pytest) did not execute. Previous green run: 2026-10-05 at `976ce42` |
| `deploy-staging.yml` | `workflow_dispatch` only; GitHub environment `staging` | `railway up` to staging; requires secret `RAILWAY_TOKEN` | never |
| `flutter-ci.yml` (frontend) | push/PR | analyze, test, build; approval-gated `android-release` job | never |

* GitHub environments `staging` and `android-release` exist (created by the owner-approved action 2026-11-13). Repository and environment secrets/variables: none found (names-only check, 2026-11-13). **Required reviewers are not configured.**
* **Candidate-branch protection (verified by reading the workflows, nothing run):** `staging/candidate-2026-11-13` matches `staging/**`, so CI runs on it. Railway watches only `staging/railway-snapshot`, so a push of the candidate does not deploy. **R-16 (partly mitigated 2026-11-13):** `deploy-staging.yml` now accepts only the exact branch `staging/railway-snapshot`; `v*` tags and candidate branches are rejected (guard tested locally, uncommitted); candidate branches cannot pass it. Still open: `staging` environment required reviewers are not configured and the workflow has never run on GitHub.
* CI workflows give candidate runs **no production secrets**: they use inert placeholders; the only secret planned (`RAILWAY_TOKEN`) is scoped to the `staging` environment used by the manual deploy workflow.

### CI failure record

| ID | Run | Failure | Root cause | Status |
|---|---|---|---|---|
| CI-1 | [43381648865](https://github.com/ravishori/SecureShield-Backend/actions/runs/43381648865), job `pytest (unit + PostgreSQL integration)`, step "Lint and format", commit `e367eb6` | `Would reformat: scripts/seed_sms_registry.py` / `1 file would be reformatted, 188 files already formatted`, exit 1 | **Genuine formatting defect in the committed file** `scripts/seed_sms_registry.py` (from commit `984c190`, inside the 74-commit range). Local ruff runs had passed because the working-tree copy of that file carries the owner's **uncommitted** change, which is exactly the ruff-formatted version (verified byte-identical apart from line endings), masking the defect. Not a PostgreSQL, environment, ordering or dependency issue; `ruff check` passed in CI (ruff 0.9.4 pinned) | **FIX READY, NOT COMMITTED** - see below |

Fix: commit the ruff-formatted `scripts/seed_sms_registry.py` (format-only: 36 insertions, 12 deletions, no behavioural change). The working-tree file already contains it; it is owner-owned and was deliberately left alone. A corrective commit **is required** (do not amend `e367eb6`). Verified in a **clean checkout of `e367eb6` with only that formatting applied**: `ruff check` and `ruff format --check` clean (189 files) and full backend suite **1069 passed, 0 failed, 0 skipped** (473 s, disposable local DB), which also shows the commits do not depend on any uncommitted file. Not run locally for this commit: gitleaks, `pip-audit` (last clean run earlier on 2026-11-13), a standalone `alembic upgrade head` on a blank DB (covered indirectly by the schema-drift tests); these remain for CI.
**Lesson (process):** lint, format and tests must be run in a clean checkout of the exact commit, not in a working tree that contains uncommitted owner changes.

## 11. Test Evidence and Quality Metrics

Source: `testing-and-qa.md`. All backend runs used a disposable local test database, never Neon or Railway.

| Metric | Result | Date / commit |
|---|---|---|
| Backend full suite | **1009 passed, 0 failed, 0 skipped** (clean install of `requirements.txt`) | 2026-11-13, `1bcdf16` (+3 docs-gate tests at `28a490c`) |
| Clean checkout unit tests | 315 passed (commits independent of uncommitted Neon files) | 2026-11-13 |
| Ruff check and format | clean (184 files) | 2026-11-13 |
| `pip-audit` clean install | 0 runtime advisories (11 in pip/setuptools build tooling) | 2026-11-13 |
| Dart OSV scan | 0 advisories, 207 packages | 2026-11-13 |
| Flutter | `analyze` clean; **95 tests passed** | 2026-11-13 |
| Mutation checks | 13/13 OTP/admin mutations caught after adding 4 tests | 2026-11-13 |
| Release signing fail-closed | 5 failing-build runs behave as designed | 2026-11-13 |
| **Backend full suite with Phase 7 changes** | **1062 passed, 0 failed, 0 skipped** (clean venv, disposable local DB, 580 s). Includes 13 SMTP-switch, 29 encryption-required/startup, 2 encryption integration and 9 deploy-guard tests | 2026-11-13, working tree on `staging/candidate-2026-11-13`, **uncommitted** |
| Ruff check / format (`app tests scripts`) | clean, 190 files | 2026-11-13 |
| Mutation checks on Phase 7 gates | 11/11 caught (OTP, notifications, error-alert, encryption write/startup/key length, startup registration, workflow ref) | 2026-11-13 |
| Frontend checks | **NOT RUN** - no Flutter file changed in this phase (tree clean at `815cbd9`); last results (analyze clean, 95 tests) are from 2026-11-13 earlier | - |
| gitleaks / GitHub CI | **NOT RUN** (nothing pushed) | - |
| **Not run, ever:** GitHub CI on the release, Railway build/deploy of the new code, any real provider send, any physical device or signed build, coverage measurement, gitleaks | - | - |

## 12. Deployment Readiness

Gates from `production-readiness.md` (0 of 12 pass). Staging readiness for the 74-commit release:

| Prerequisite | State |
|---|---|
| Code complete and unit-tested | yes (TESTED), Phase 7 additions not yet in a full run |
| Release range scanned for secrets | yes, regex scan only (gitleaks pending CI) |
| Pushed to a CI-only branch and CI green | **no** |
| Backup of staging DB with a proven restore | **no** |
| Approval to apply 9 migrations | **no** |
| `FILE_ENCRYPTION_KEY`, `TRUSTED_PROXIES`, CORS configured | **no** |
| Railway start command / Python version verified | **no** |
| Controlled fast-forward of `staging/railway-snapshot` | **no** (auto-deploys on push; only after the above) |
| Production environment | does not exist; production deploy is not approved |

Release strategy (decision, section 16): push the 74 commits first to a CI-only branch; fast-forward `staging/railway-snapshot` only after CI is green, backup verified, and migrations approved.

## 13. Security Risk Register

Owner "Owner" = repository owner (ravishori). Closure evidence is always "to be produced" unless stated. **No risk below is resolved.** `S-xx` = ID in `security-audit.md`; `FG-xxx` = gaps register.

| ID | Description | Severity | Component | Status | Mitigation | Owner | Required approval | Closure evidence |
|---|---|---|---|---|---|---|---|---|
| R-01 | Credentials that appeared in Git history (Anthropic key, Twilio SID/token, Gmail app password, Safe Browsing, Azure Translator, local DB password, placeholder `SECRET_KEY`, committed `.env`, personal-data logs) await rotation. Repos now private; history not rewritten (S-01) | Critical | Repos, all providers | **OPEN - rotation DEFERRED by owner** | Repos private; never deploy known-compromised creds to production; rotate before any production use | Owner | Owner (rotation timing) | new credentials issued and old ones revoked at each provider; history decision recorded |
| R-02 | Staging Railway variables still hold the exposed `SECRET_KEY`, `ADMIN_TOKEN` and old provider keys | High | Railway staging | **OPEN - DEFERRED** | Staging holds no user data; legacy admin token disabled; do not reuse in production | Owner | Owner | variable audit after rotation |
| R-03 | `FILE_ENCRYPTION_KEY` not set: evidence/recordings stored in plaintext; before Phase 7 a missing key silently stored plaintext (S-11) | High | `file_crypto`, uploads | **OPEN** (code gate TESTED locally, uncommitted; staging key not set) | `FILE_ENCRYPTION_REQUIRED` + startup validation; owner generates and escrows a 32-byte urlsafe-base64 key | Owner (key); dev (tests) | Owner approves key creation | local tests for missing/malformed/valid key pass (done, see section 4); still needed: key set in staging; startup fails without it; round-trip upload verified on staging |
| R-04 | SMTP fallback would use the exposed SMTP credentials if `SMTP_HOST` is set | High | OTP, notifications, error mail | **OPEN** (switch TESTED locally incl. error-alert path, uncommitted; variable not set on staging) | `SMTP_FALLBACK_ENABLED=false` on staging; Resend only | Dev / Owner | Owner sets variable | all three SMTP paths gated by passing tests (done locally); still needed: variable set on staging + no SMTP connection in staging logs |
| R-05 | `TRUSTED_PROXIES` not set; only one observed Railway proxy address (`100.64.0.1`) (FG-167) | Medium | client-IP, rate limits, HTTPS detection | **OPEN** | Measure real proxy range on staging, set variable | Owner/ops | Owner | measured range recorded; startup check passes with `TRUST_PROXY_TLS` |
| R-06 | CORS is a wildcard in non-production; production requires an explicit list | Medium | API | **OPEN** | Set `CORS_ALLOWED_ORIGINS` for staging/production | Owner/ops | Owner | variable set; preflight check from an allowed and a disallowed origin |
| R-07 | No staging database backup and no proven restore (`../BACKUP_AND_RECOVERY.md`) | High | Postgres | **OPEN** | Take backup before migrations; rehearse restore to a scratch DB | Owner/ops | Owner approves backup/restore action | backup artefact id + successful restore with row counts matching |
| R-08 | 9 pending migrations never applied to a real database; four are destructive on non-empty tables (S-xx in migration review) | High | Alembic | **OPEN** | Apply only after backup, on staging, in a controlled deploy; tables empty at last probe | Owner + dev | **Explicit owner approval** | revision equals `u6v7w8x9y0z1`, row-count probe unchanged, smoke tests pass |
| R-09 | Admin MFA and initial superadmin not provisioned in any real environment; legacy token break-glass default `true` in code (S-06) | High | Admin console | **OPEN** | Create first superadmin after migration (CLI), enrol MFA; keep legacy token off | Owner/ops | Owner | admin login with MFA on staging; legacy token returns 401 on staging |
| R-10 | No live OTP channel proven; Twilio rejected (S-03) | High | Auth | **BLOCKED** | Deploy Resend build; one approved test send | Owner | Owner approves each real send | one real OTP received and used to sign in on staging; provider-failure test |
| R-11 | Railway start command and Python version unverified; IaC and Railway may disagree (no `startCommand` observed in Railway) | Medium | Railway service | **OPEN** | Read-only verification in Railway; align with `.railway/railway.ts` and `.python-version` | Dev/Owner | Owner for any change | deployment log shows expected start command and Python 3.11 |
| R-12 | Rate limiter is in-memory per process; one replica required (S-10) | Medium | Middleware | **OPEN** | Keep single replica; Redis store before scaling | Dev | - | shared-store limiter tested |
| R-13 | DPDP gaps: retention, notice, consent, minors, cross-border processing (S-07, FG-034) | High | Product/legal | **OPEN** | Owner decisions + implementation | Owner/legal | Owner | retention jobs tested; notices in app |
| R-14 | Google Play restricted permissions (S-05) | High | Android | **OPEN** | Minimise permissions; declarations | Owner | Owner | Play review outcome |
| R-15 | No Android upload keystore; unsigned/uncertain release (S-04) | High | Android signing | **BLOCKED** | Build fails without a key (tested); owner creates keystore | Owner | Owner | signed APK/AAB + `verify_apk_signature.py` fingerprint match |
| R-16 | `deploy-staging.yml` previously accepted `staging/*` refs (included the CI candidate); required environment reviewers not set | Medium | GitHub Actions | **OPEN - code fix done locally, uncommitted** | Allowed ref narrowed to exactly `staging/railway-snapshot`; reviewers still to configure; no `RAILWAY_TOKEN` stored | Dev/Owner | Owner (reviewers, secrets) | guard tested locally (done); closure needs the workflow committed, CI-validated, and a real dispatch from a candidate ref rejected |
| R-17 | Railway auto-deploys on any push to `staging/railway-snapshot`; a premature push would deploy and run 9 migrations | High | Railway source | **OPEN (controlled)** | CI-only candidate first; push the Railway branch only on approval | Dev/Owner | Owner | documented push approval + backup |
| R-18 | Dependency state shown only locally; Railway/CI builds of upgraded pins never run (S-02) | Medium | Supply chain | **OPEN** | CI pip-audit run; Railway build | Dev | - | green CI run with pip-audit |
| R-19 | Anti-screenshot never observed on a device (S-08) | Medium | Android | **OPEN** | Device/emulator check | Dev/Owner | - | screenshot test showing flag effect |
| R-20 | Interactive-docs, error-log retention, exported `PackageInstallReceiver`, public `/ready` details (S-09, S-13, S-14, S-17) | Low-Medium | Various | **OPEN** except docs gate (TESTED) | See `security-audit.md` | Dev | - | per item |

## 14. Completed Audit Findings

Fixed in the repository (not deployed; "fixed" means code + passing tests, not production-closed). Source: `security-audit.md`, `p1-closure-report.md`, `audit-history.md`.

| Finding | Result | Evidence |
|---|---|---|
| S-02 vulnerable dependencies (147 advisories) | FIXED in repo: 0 runtime advisories on clean install | `b9be388` |
| S-04 debug-key release signing | MITIGATED: release fails without external key | `6cd21d4` |
| S-06 shared admin token | MITIGATED: named accounts, MFA, RBAC, audit | `86b3ba2`; 67 tests, 13/13 mutations caught |
| S-08 anti-screenshot mismatch | FIXED, device-unverified | `5d4d16a` |
| S-09 API docs in production | FIXED | `28a490c` |
| S-24 OTP brute-force/race/send cap | FIXED | `f06a3d8` |
| S-25 superadmin lockout race | FIXED (advisory lock) | `86b3ba2` |
| S-26 admin console JS defect | FIXED | `86b3ba2` |
| `otp_provider_check.py` double-send | FIXED, mutation-checked | `be9faad` |
| CI secret scan vs test fixtures | allowlisted by exact value (unverified until CI runs) | `.gitleaks.toml` |

**No finding is CLOSED at production level.**

## 15. Outstanding Blockers

1. **Owner:** credential rotation (deferred), upload keystore, Play/DPDP decisions, retention periods, approvals for push/backup/migration/deploy/test send.
2. **CI not run** on the 74-commit range (never pushed).
3. **No backup/restore proof** before migrations.
4. **Nine pending migrations** unapproved.
5. **Phase 7 changes are uncommitted** and wait for the owner's explicit commit approval; nothing is on GitHub, so CI has not validated them.
6. **Staging variables:** `FILE_ENCRYPTION_KEY`, `TRUSTED_PROXIES`, CORS, `SMTP_FALLBACK_ENABLED=false`, Railway start command.
7. **First superadmin** and MFA enrolment.
8. **Live provider verification** (Resend first) and **device end-to-end** on a signed build.

## 16. Decisions and Approvals Log

| Date | Decision / approval | By | Source |
|---|---|---|---|
| 2026-11-13 | Docker is not used; Railway native Python builder; GitHub Actions without Docker | Owner | `deployment-runbook.md` |
| 2026-11-13 | Reuse the Railway staging project; environment named `staging` (renamed from `production`) | Owner (executed under approval) | `infrastructure-setup.md` |
| 2026-11-13 | Existing database and volumes are preserved | Owner | session record |
| 2026-11-13 | Repositories made private until project completion | Owner | `infrastructure-setup.md` |
| 2026-11-13 | GitHub environments `staging` and `android-release` created | Owner (approved) | `infrastructure-setup.md` |
| 2026-11-13 | Resend is the e-mail provider using `mail.trinetralab.net`; sending-only key restricted to that domain; do not introduce Twilio | Owner | `../RESEND_SETUP.md` |
| 2026-11-13 | Only `RESEND_FROM_EMAIL` (exact value `SecureShield <no-reply@mail.trinetralab.net>`) and `ADMIN_LEGACY_TOKEN_ENABLED=false` authorised as Railway variable changes | Owner | session record |
| 2026-11-13 | **Credential rotation deferred** by owner; no replacement `SECRET_KEY`/`ADMIN_TOKEN`/`FILE_ENCRYPTION_KEY` generated; no variable deletion; compromised credentials never to production | Owner | session record |
| 2026-11-13 | All 74 backend commits are one coherent release (not cherry-pickable) | Owner / audit | Phase 6 audit |
| 2026-11-13 | CI-only candidate branch (`staging/candidate-2026-11-13`) preferred before updating the Railway-connected branch | Owner | Phase 7 request |
| 2026-11-13 | **No production deployment without explicit approval**; no push, migration, rotation, e-mail send without approval | Owner | standing rule |
| 2026-11-13 | Uncommitted owner files (Neon fix, seed script, `start.bat`, `infrastructure-setup.md`) must be preserved and not committed by release work | Owner | standing rule |

**Not approved (as of this document):** pushing any branch or tag, creating PRs, applying migrations, deploying or redeploying, rotating credentials, adding GitHub/Railway secrets, sending any real e-mail.

## 17. Next Actions and Milestones

Priority order. Each item needs the stated approval before any external effect.

| # | Action | Needs approval for | Done when |
|---|---|---|---|
| 1 | **Resend integration release:** keep the Resend adapter (commit `1335678`) in the 74-commit release; confirm no deployed behaviour change until the branch is fast-forwarded | - | included in release range, CI green |
| 2 | **SMTP fallback control:** code and tests DONE locally; **commit** (approval) then set `SMTP_FALLBACK_ENABLED=false` on staging later | commit approval; variable change | R-04 closure evidence |
| 3 | **File encryption startup validation:** code and tests DONE locally; **commit** (approval); owner creates and escrows the key; set `FILE_ENCRYPTION_REQUIRED=true` on staging | commit approval; key creation | R-03 closure evidence |
| 4 | **CI candidate branch:** commit Phase 7 files only (never the owner's uncommitted files; workflow already narrowed locally); push `staging/candidate-2026-11-13` | **commit approval, then push approval** | branch visible on GitHub, Railway did not deploy |
| 5 | **Backend CI validation:** read the first CI run (gitleaks, ruff, pip-audit, alembic, pytest); fix failures | - | one green `backend-ci` run on the release SHA |
| 6 | **Database backup and restore verification** on staging | backup/restore approval | R-07 closure evidence |
| 7 | **Migration approval:** owner reviews `../MIGRATION_SAFETY_REVIEW.md`; approval recorded in section 16 | **owner approval** | approval entry exists |
| 8 | **Controlled Railway staging deployment:** set remaining variables (`TRUSTED_PROXIES` measured, CORS, encryption, SMTP switch), fast-forward `staging/railway-snapshot`, watch pre-deploy migrations and health checks, create first superadmin | **push + deploy + migration approval** | revision `u6v7w8x9y0z1`, `/health` ok, smoke tests pass |
| 9 | **OTP delivery and authentication testing:** one owner-approved real Resend send, sign-in, rate-limit and provider-failure tests | **send approval** | R-10 closure evidence |
| 10 | **Credential rotation** at a later approved stage (before any production use) | owner schedule | R-01, R-02 closure evidence |

Milestones: M1 candidate branch CI-green -> M2 staging deployed with migrations -> M3 OTP live on staging -> M4 rotation and keystore -> M5 device end-to-end on a signed build -> M6 closed-beta Go/No-Go (`development-roadmap.md`; about 60-75 developer-days remaining in the 2026-11-13 estimate, plus owner lead time).

## 18. Change History

| Date | Change | Evidence |
|---|---|---|
| 2026-11-13 | Document created from existing audit reports and reported release facts; no new technical audit; no application source changed by this document | this file |
| 2026-11-13 | Phase 7 working-tree changes recorded as BUILT / uncommitted (SMTP switch, encryption-required validation, partial tests) | local branch `staging/candidate-2026-11-13` |
| 2026-11-13 | CI run 43381648865 failed on `e367eb6` (CI-1, ruff format of `scripts/seed_sms_registry.py`); root cause and ready fix recorded; clean-checkout verification 1069 passed; corrective commit pending owner approval | CI log; clean worktree |
| 2026-11-13 | Final review: deploy workflow narrowed from `staging/railway-snapshot`+`v*` to the exact branch only; test extended to 14 refs; focused tests 15 passed, ruff clean | working tree |
| 2026-11-13 | Phase 7 completed locally, **uncommitted**: error-alert gate test fixed (no skip), encryption startup validation tests, `deploy-staging.yml` restricted to the exact branch `staging/railway-snapshot` (no tags); full suite 1062 passed, 11/11 mutations caught. Changed files: `app/delivery_settings.py`, `app/services/{otp_service,notifications,logger_service,file_crypto,upload_safety}.py`, `app/startup_checks.py`, `.github/workflows/deploy-staging.yml`, `tests/unit/test_{smtp_fallback_switch,file_encryption_required,deploy_workflow_refs}.py`, `tests/integration/test_file_encryption_api.py`, this document | working tree |

Earlier history: `audit-history.md`.
