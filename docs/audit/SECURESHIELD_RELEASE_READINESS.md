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
10. **Scorecard numbers are computed, never hand-edited.** The formulas and denominators are in section 1; change the source rows in `feature-completion-matrix.md` first, then recompute and record the recomputation in section 18.
11. **Freshness rule (two triggers).** Every section has an entry in the Section Freshness Register below. A section is **STALE** when (a) its evidence is older than **14 days**, or (b) a later event listed in that section's **Invalidated by** column contradicts it. Event invalidation is **immediate and section-specific**: it applies only to sections whose evidence depends on that event (for example a new backup file or checksum invalidates backup status, not the CERT-In section). STALE sections stay flagged in the register (and on the scorecard where a row depends on them) until re-verified.
12. **Consistency check.** After editing this file run the documentation consistency checks (heading order, risk IDs, register shape, matrix recomputation, evidence-ladder coverage, relative links, secret scan, F-series preservation) and record the result in section 18. (The check script currently lives outside the repository; adding it under `scripts/` and to CI is a proposal, not done.)

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

### Evidence levels (never upgraded without proof)

| Level | Meaning | Highest level reached today |
|---|---|---|
| Reported by Claude | stated in a session record, not independently re-checked | provider and cost facts, Railway plan facts |
| Verified locally | checked on the developer machine (read-only probe, hash, local restore, local run) | backups and restores, credential exposure scan, authorisation audit and proof of concept |
| Verified by automated tests | tests pass locally or in CI | Phase A and Phase 7 code (1227 local tests; GitHub Actions run 43430344346 on `15f5ea6`) |
| Verified on an Android device | run on a real device or emulator at the current code | **none** (emulator runs of 2026-10-06 are historical and on older code) |
| Verified in staging | the current code runs and was validated in Railway staging | **none** (staging runs the older commit `976ce42`) |
| Verified in production | validated in an approved production environment | **none** (no production environment exists) |

Unless a row states otherwise, evidence in this document is at "Reported by Claude" or "Verified locally". **No claim is above "Verified by automated tests"**; nothing is verified on a device at the current code, in staging at the current code, or in production.

### Source documents used

Present and used: `README.md`, `project-status.md`, `feature-completion-matrix.md`, `architecture-and-integration.md`, `security-audit.md`, `testing-and-qa.md`, `production-readiness.md`, `development-roadmap.md`, `p1-closure-report.md`, `deployment-runbook.md`, `infrastructure-setup.md` (uncommitted), `audit-history.md`, `../RESEND_SETUP.md`, `../RAILWAY_DEPLOYMENT.md`, `../STAGING_DEPLOYMENT_PLAN.md`, `../MIGRATION_SAFETY_REVIEW.md`, `../BACKUP_AND_RECOVERY.md`, `../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`.
**Requested but not present in the repository:** `system-inventory.md`, `findings-register.md`, `test-evidence-log.md`, `admin-security.md`, `payments.md`, `pyq-answer-quality.md`. Their equivalents are `architecture-and-integration.md`, `security-audit.md` + `../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md` (FG-001..167), `testing-and-qa.md` + `audit-history.md`, and the admin section of `security-audit.md`. No payments or PYQ-answer-quality documentation exists in the repository; this document makes **no statement** about those topics.

### Section Freshness Register (rule 11)

| Section | Last verified | Evidence reference | State | Invalidated by (relevant events only) |
|---|---|---|---|---|
| 1 Dashboard and scorecard | 2026-11-13 | formulas below; `feature-completion-matrix.md` recomputed | CURRENT (contains estimates flagged UNVERIFIED) | any change to matrix rows or statuses; a new commit or branch push; a new finding; any gate or pilot-gate status change |
| 2 Architecture | 2026-11-13 | `architecture-and-integration.md`; `requirements.txt` | CURRENT | a dependency or version change; a change to the architecture document |
| 3 Repository status | 2026-11-13 | `git rev-list`, `git ls-remote`, `git status` | CURRENT | any new commit, push or divergence change; a change to uncommitted release files |
| 4 Feature inventory and evidence ladder | 2026-11-13 | matrix (statuses dated 2026-11-12/13; two rows adjusted) | CURRENT, adjusted | a matrix edit; a new test, device, staging or provider result for a feature |
| 5 Security and privacy | 2026-11-13 | `security-audit.md`; Phases A, C, E2, F | CURRENT | a new security finding; a code or configuration change to the control concerned |
| 5a Compliance obligations | 2026-11-13 | CERT-In official PDFs; DPDP dates owner-confirmed; Play and provider terms from web search | CURRENT, legal review pending | a change in the law, policy or provider terms; counsel advice |
| 6 Authentication and OTP | 2026-11-13 | code at `15f5ea6` plus the F1 working tree | CURRENT, F1 in progress | an F1 commit or merge; any change to authentication code; provider configuration |
| 7 Providers and costs | 2026-11-13 | code; no live calls; **costs not verified** | CURRENT, costs UNVERIFIED | provider configuration or key change; a live verification; pricing information |
| 8 Database and migrations | 2026-11-13 | read-only probes; migration files | CURRENT | a new or changed migration file; a Railway revision change; a backup or restore event |
| 9 Infrastructure | 2026-11-13 | read-only Railway CLI probes (Phases B, E2) | CURRENT | a Railway variable or configuration change; a new deployment; a service change |
| 10 GitHub and CI/CD | 2026-11-13 | run 43430344346 on `15f5ea6` | CURRENT for `15f5ea6`; **F1 working tree not covered by CI** | a new push; a new workflow run; a workflow file change |
| 11 Test evidence | 2026-11-13 | see rows; Flutter results not re-run in this pass | PARTLY STALE (rows marked historical) | any new test run or count change |
| 12 Deployment readiness | 2026-11-13 | section 12 table (corrected) | CURRENT | a deployment, migration or variable change; a gate change |
| 12a Phase A hardening | 2026-11-13 | Phase A record; commit `15f5ea6`; CI run 43430344346 | CURRENT | a change to the Phase A code; a staging variable being set |
| 12b Phase B backup and restore | 2026-11-13 | Phase B record; local verification report | CURRENT (procedure text is long; moving it is an open proposal) | a new or changed backup file or checksum; a restore event; a Drive copy change |
| 12c Release gates and the three denominators | 2026-11-13 | Phases C and D; `production-readiness.md` | CURRENT | a gate acceptance change; an owner decision; a new finding that affects a gate |
| 12d Phase E (restore, credentials) | 2026-11-13 | E1 report file; E2 scan; backup hashes (final correction pass) | CURRENT | a backup artefact change; a credential rotation or revocation; a provider key event |
| 12e Phases F and F1 | 2026-11-13 | audit and proof of concept; F1 working tree | CURRENT, F1 BUILDING | an F1 commit or test change; a new finding |
| 12f Phase G (privacy, consent, Android permissions) | 2026-11-14 | working tree (uncommitted); test runs recorded in 12f | CURRENT, uncommitted | a commit or any test change; a Play Console decision; counsel review of the notice; a manifest change |
| 12g Phase 0 (development baseline, AI containment) | 2026-11-14 | working tree (uncommitted); test runs in 12g | CURRENT, uncommitted | a commit; a change to `AI_PROCESSING_ENABLED` handling; any new AI call path |
| 12h Phase 1A (F19 app monitor service) | 2026-11-14 | working tree (uncommitted); debug merged manifest; test runs in 12h | CURRENT, uncommitted | a commit; a manifest or service change; a device test result |
| 13 Risk register | 2026-11-13 | rows R-01..R-34 with evidence references | CURRENT | any new finding; any status change in the evidence a row cites |
| 14 Completed audit findings | 2026-11-13 | `security-audit.md`, Phases A-F | CURRENT | a new audit phase completing |
| 15 Blockers and pilot decision | 2026-11-13 | this pass | CURRENT | a risk or gate change |
| 16 Decisions | 2026-11-13 | owner instructions | CURRENT | a new owner decision |
| 17 Next actions | 2026-11-13 | this pass | CURRENT | a blocker or gate change |
| 18 Change history | append-only | - | - | - |

### Document inventory, reconciliation and archival PROPOSAL

Only this file was edited. **No other document was changed, moved, renamed or deleted; the dispositions below are proposals awaiting separate owner approval.**

| Document | Role today | Proposal |
|---|---|---|
| `docs/audit/SECURESHIELD_RELEASE_READINESS.md` | the master control document and scorecard | **keep, single source of truth** |
| `docs/audit/feature-completion-matrix.md` | per-feature data (38 rows, weights, FE/BE/INT/TEST/SEC); the scorecard is computed from it | **keep as the data source**; fix rows 1 and 37 there when F1 is verified |
| `docs/audit/architecture-and-integration.md`, `deployment-runbook.md`, `infrastructure-setup.md` (uncommitted, owner-owned), `development-roadmap.md`, `security-audit.md` | detail references | keep as references; add a "details for the master document" banner |
| `docs/audit/project-status.md`, `production-readiness.md`, `testing-and-qa.md`, `p1-closure-report.md` | earlier dashboards and gate lists, now partly contradicted (see below) | propose a "HISTORICAL - superseded by the master document" banner (no deletion) |
| `docs/audit/audit-history.md` | append-only history | keep |
| `docs/audit/README.md` | index; **does not list the master document** | add the master document as the first entry |
| `docs/SECURESHIELD_FEATURE_COMPLETION_MATRIX.md` (2026-10-06, 67 rows), `docs/AUDIT_2026-10-19.md` | older duplicate of the matrix and an older audit | propose a "HISTORICAL" banner |
| `docs/BACKUP_AND_RECOVERY.md`, `RESEND_SETUP.md`, `MIGRATION_SAFETY_REVIEW.md`, `RAILWAY_DEPLOYMENT.md`, `STAGING_DEPLOYMENT_PLAN.md`, `ANDROID_RELEASE_AND_PLAY.md`, `SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md` (FG-001..167) | procedures and registers | keep |
| 14 loose files in the project folder outside both repositories, e.g. `BUILD_STATUS_FINAL.md`, `FINAL_SUMMARY.md`, `INTEGRATION_COMPLETE.md`, `KOTLIN_FIXES_COMPLETE.md`, `QUICK_REFERENCE.md`, `NEXT_STEPS_AND_ENHANCEMENTS.md` | completion claims ("ALL ERRORS FIXED", "Complete") with no test evidence; untracked | propose moving to an `archive/` folder or banner; **owner decides** |
| `Features of the app.txt` | overstates several controls (S-23) | keep as a source, never as evidence |
| Optional: moving the Phase B backup procedure (section 12b) into `docs/BACKUP_AND_RECOVERY.md` | master document is 560+ lines | **not done**; needs owner confirmation |

**Contradictions found in other documents (corrected here; the other documents are unchanged):**

| Document says | Verified fact | Corrected in |
|---|---|---|
| `security-audit.md` S-01 and `production-readiness.md` G2: repositories are PUBLIC | private since 2026-11-13 (S-01 stays open for rotation) | sections 3, 12c, 13 |
| `project-status.md`: "nothing is pushed", 65 commits ahead, Flutter `6cd21d4` | candidate branch pushed at `15f5ea6` and CI-green; 77 commits ahead; Flutter local `815cbd9` (23 ahead of `origin/main`) | sections 1, 3 |
| `production-readiness.md` G4: no CI on the release | backend CI green on `15f5ea6` | sections 10, 12c |
| `testing-and-qa.md`, `project-status.md`: 1009 tests | 1227 passed (before the F1 changes) | section 11 |
| matrix row 1 (OTP login): TESTED, SEC 90 | F-01 and F-02 confirmed by proof of concept: BUILDING until F1 is verified | sections 4, 12e |
| matrix row 37 (account deletion): REVIEWED, FE 60 | backend tested; the Flutter client has no deletion call or screen: BUILT end to end | sections 4, 12c |
| `production-readiness.md`, `architecture-and-integration.md`: Docker image, FastAPI 0.115 | the project is Docker-free; backend runs FastAPI 0.133; `db-backup.yml` still starts a Docker service | sections 2, 12b |
| this document (earlier text): section 3 "uncommitted Phase 7 work", section 12 "no proven restore", "Phase 7 additions not yet in a full run", "nine migrations" | those were committed or completed; the uncommitted work is F1 | corrected in this pass |

---

## 1. Executive Project Dashboard
### Scorecard (formulas, denominators, evidence) - computed 2026-11-13

Feature data comes ONLY from `feature-completion-matrix.md`: 38 features, weight 1-3 each (**weights total 60**); FE, BE, INT, TEST, SEC scored 0-100 by the rubric in that file. The arithmetic of every documented percentage was **recomputed from the matrix rows and reproduces exactly** (check recorded in section 18).

| Metric | Value | Formula and denominator | Evidence | Confidence |
|---|---|---|---|---|
| **Build completeness** (development progress) | **79.2%** | sum(w x mean(FE, BE applicable)) / 60 | matrix rows | Medium (rubric scores are assessor judgements) |
| Implementation "Impl" (documented) | 74.5% | sum(w x mean(FE, BE, INT)) / 60; INT is capped at 60 until a real provider has run, so this mixes build with verification | matrix; reproduced | Medium |
| Frontend completion | 76.4% over the 37 features that have a client (75.2% over all 38, counting the backend-only feature as 0) | sum(w x FE) / sum(w of rows with a client) | matrix | Medium |
| Backend completion | 85.7% over the 28 features with a backend | sum(w x BE) / sum(w of rows with a backend) | matrix | Medium |
| **Verification maturity** (status-weighted) | documented 66.2%; **62.4% adjusted now**; 64.9% after F1 is verified | sum(w x s) / 60 with PLANNED 0, BUILDING .25, BUILT .5, TESTED .75, REVIEWED .9, PRODUCTION 1. Adjustments: row 1 OTP login TESTED to BUILDING (F-01/F-02 confirmed), row 37 account deletion REVIEWED to BUILT (no client path) | section 4 ladder; section 12e | Medium |
| Status counts (matrix) | TESTED 21, BUILT 12, BUILDING 3, REVIEWED 2, PLANNED 0, PRODUCTION **0** | count of rows | matrix | High |
| **Production readiness** | **40% (capped)** | 0.25 Impl + 0.10 Integration + 0.15 Testing + 0.25 Security + 0.25 Deployment, **capped at 40 while any go-live blocker is open**. Documented inputs 74.5, 63.7, 45.0, 60.7, 34.5 give raw 55.5; they predate Phases 7 to F1. **UNVERIFIED indicative re-estimate:** testing about 48, security about 62, deployment about 40 give a raw of **57.7%** (0.25 x 74.5 + 0.10 x 63.7 + 0.15 x 48 + 0.25 x 62 + 0.25 x 40 = 57.70). This is an indicative calculation from judgement inputs, **not a measured production-readiness certification**; a true re-score needs the 26-control security and 12-control deployment checklists re-scored, which was not done. The cap keeps the reported result at 40. | `project-status.md` (method); this section | Low-Medium |
| Go-live gates passing | **0 of 12 PASS (0%)**: all twelve are FAIL on the binary acceptance scale; evidence status per gate is in the G1-G12 table in section 12c | the original gates G1-G12, reproduced verbatim from `production-readiness.md` in section 12c (**separate denominator**: 12) | section 12c | High |
| **Private pilot readiness** | **NO-GO; 0 of 11 accepted gates (0%)** | the 11 pilot P0 gates of section 12c (**separate denominator**: 11), equal weight; a gate counts only when its full acceptance criterion is evidenced; **no fractional credit**. This is a gate-acceptance measure, not a measure of engineering progress. **Remains NO-GO until F-01 and F-02 are remediated and independently tested** | section 12c | High |
| Target-specific release gates | **0 of 26 accepted** (26 gates across Dev, Pilot, Play, Commercial; the 11 pilot gates are gates 1-11 of this list; **separate denominator**: 26) | section 12c table | section 12c | High |
| Backend tests | **1227 passed, 0 failed, 0 skipped** (local, before the F1 changes); GitHub CI green on `15f5ea6` | pytest on a disposable local database; CI run 43430344346 | section 11 | High (not re-run on the F1 working tree) |
| Flutter tests | 95 passed; analyze clean | **not re-run in this pass** | section 11 | STALE |
| Open risks | see section 13 | count by severity: Critical 1, High 18, Medium 12, Low-Medium 1, Low 2 (total 34, all open or blocked; none closed) | section 13 | High |

**Separation of concepts:** build completeness and verification maturity measure the product; production readiness and pilot readiness measure release gates. Historical audit work (Phases A-F, backups, restores) is **not** counted as product features. **No feature is PRODUCTION: none has run against a real provider, been deployed to staging at the current code, and been validated there.**

| Item | State | Evidence (date) |
|---|---|---|
| **Overall verdict** | **NO-GO for production** | `production-readiness.md` (2026-11-13) |
| Production readiness | **40%** (raw weighted 55.5%, capped while go-live blockers are open) | `project-status.md` (2026-11-13) |
| Feature implementation (weighted) | see the scorecard above (build completeness 79.2%, verification maturity 62.4% adjusted) | `feature-completion-matrix.md` |
| Go-live gates passing | **0 of 12** | `production-readiness.md` |
| Backend release candidate | the local `staging/railway-snapshot` tip `a91c79a` is **74** commits ahead of `976ce42` *(reported; verified with `git rev-list 976ce42..a91c79a`)*. **Update 2026-11-13:** the candidate branch `staging/candidate-2026-11-13` is **pushed** at `15f5ea6`, **77** commits ahead of the Railway-watched branch (the 74 plus Phase 7 `e367eb6`, CI fix `b130d04` and Phase A `15f5ea6`), and **CI-green**; **none of the 77 commits is deployed** (Railway still runs `976ce42`; `staging/railway-snapshot` unchanged) | GitHub run 43430344346; `git rev-list`; `git ls-remote` |
| Staging environment | Railway runs old commit `976ce42` (no Resend code); new code not deployed | *(reported)* |
| Blocking items | **PRIVATE PILOT BLOCKERS: confirmed account-takeover weaknesses F-01 and F-02 (fix BUILDING, uncommitted, incomplete; the private pilot remains NO-GO until both are remediated and independently tested);** exposed credentials un-rotated (DEFERRED by owner; Anthropic key confirmed exposed); no live OTP channel (and no SMS provider for phone verification); no deployment of the candidate; ten pending migrations (nine plus the F1 revision); no upload keystore; no privacy notice or account-deletion UI; no device test | section 15 |

**Update 2026-11-13 (latest):** backend full suite **1227 passed, 0 failed, 0 skipped** locally with the Phase A changes (section 12a); GitHub CI green on `15f5ea6` (run 43430344346; gitleaks, ruff, pip-audit, blank-DB Alembic chain, pytest all passed; per-test counts not read from the logs). Phase B: encrypted staging backup taken, restored in isolation and copied off-machine (section 12b); full disaster recovery NOT TESTED.

**Earlier evidence (kept):** 1009 backend tests passed on a clean install at `1bcdf16`; 3 docs-gate tests added at `28a490c` (`testing-and-qa.md`, 2026-11-13). Flutter: 95 tests passed (2026-11-13).

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
| Backend `SecureShield-Backend` | `staging/railway-snapshot` @ `a91c79a` | staging branch @ `976ce42`; `main` @ `8fcb5af` | **74 commits ahead** of `976ce42` (local branch tip only; the candidate branch adds 3 more, 77 in total; all intended as one release) | **No** | *(reported)* |
| Backend candidate branch | `staging/candidate-2026-11-13` @ `15f5ea6` (Phase 7 `e367eb6`, CI fix `b130d04`, Phase A `15f5ea6`) | `staging/candidate-2026-11-13` @ `15f5ea6` | in sync; 77 commits ahead of `staging/railway-snapshot` (`976ce42`) | **Yes (CI-only branch; Railway watches `staging/railway-snapshot` only)** | `git ls-remote` (2026-11-13) |
| Frontend `SecureShield-Frontend` | `main` @ `815cbd9` | `main` @ `6a191b5` | **23 commits ahead** (216 files) | **No** | `git rev-list` (verified 2026-11-13) |

* Both repositories were made **private** by the owner on 2026-11-13 (`infrastructure-setup.md` execution record). History still contains previously exposed credentials (R-01).
* **Uncommitted owner work in the backend (must be preserved, never staged by release tooling):** Neon connection fix (`app/config.py`, `app/database.py`, `.env.example`, `tests/unit/test_db_url_normalization.py`, `tests/unit/test_database_engine.py`), `scripts/seed_sms_registry.py`, `start.bat`, `docs/audit/infrastructure-setup.md`.
* **Uncommitted F1 identity-binding work (this branch, Phase F1 Stage B in progress, NOT committed, NOT covered by CI):** `app/models/user.py`, new `app/models/pending_registration.py`, `app/models/__init__.py`, new `alembic/versions/v7w8x9y0z1a2_identity_binding.py`, `app/schemas/auth.py`, `app/routers/auth.py`, new `app/routers/identity.py`, `app/main.py`, new `app/services/identity.py`, `app/services/otp_codes.py`, `app/services/account_erasure.py`, `tests/integration/conftest.py`. State: see section 12e. (Phase 7 and Phase A work is committed: `e367eb6`, `b130d04`, `15f5ea6`.)
* **Client-backend compatibility (Phase D, path level, 2026-11-13):** every real API path used by the local-main Flutter client (57 of its 67 endpoint strings; the other 10 are screen routes) matches a route in the candidate backend; the older `origin/main` client calls `/auth/google-signin`, which the backend does not serve (local main uses `/auth/google`). Only the auth request/response field names were compared in detail. **No runtime or device pairing test has ever run**, and backend CI is not evidence of compatibility.
* Release-range secret scan (`976ce42..a91c79a`, 214 files, about 21,163 added lines, session record 2026-11-13): only deliberately fake test fixtures (allowlisted in `.gitleaks.toml`); no real secrets, keystores, `.env` files, logs or personal e-mail addresses. gitleaks (current tree) then passed in CI run `43399687864` on `b130d04` (2026-11-13); it scans the checked-out tree, not full history, so exposed history credentials remain R-01.

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
### Evidence ladder per feature (generated from `feature-completion-matrix.md`, 2026-11-13)

Seven levels, answered separately for every feature: **Code** (implemented in a repository), **Auto tests** (automated tests pass, simulated providers), **Manual (historical)** (emulator run recorded in the matrix, mostly 2026-10-06, not repeated on the current code), **Real provider** (a real third-party call was made: **none ever**; n/a = no provider in the chain), **Staging deployed** (the current code runs in staging: **none**; staging runs the older commit `976ce42`), **Staging validated**, **Prod approved**. Y = evidenced, - = not evidenced. Rows marked * were adjusted from the matrix status on the evidence in section 12e (row 1) and section 12c (row 37).

| # | Feature | Matrix status | Scorecard status | Code | Auto tests | Manual (historical) | Real provider | Staging deployed | Staging validated | Prod approved |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Phone/e-mail OTP login and registration | TESTED | BUILDING * | Y | Y (simulated) | - | - | -  | -  | - |
| 2 | Google Sign-In | BUILDING | BUILDING | Y | - | - | - | -  | -  | - |
| 3 | Session / JWT lifecycle (access, refresh rotation, replay revoke) | REVIEWED | REVIEWED | Y | Y (simulated) | - | - | -  | -  | - |
| 4 | Device registration and new-device alert | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 5 | Security dashboard (score) | BUILT | BUILT | Y | - | hist. | - | -  | -  | - |
| 6 | Alerts (list, read, dismiss, delete) | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 7 | Settings, profile, language, senior mode | BUILT | BUILT | Y | - | - | - | -  | -  | - |
| 8 | App risk scanner | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 9 | Link / URL scanner | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 10 | Wi-Fi scanner | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 11 | Scam-call report, scoring and block | TESTED | TESTED | Y | Y (simulated) | hist. | - | -  | -  | - |
| 12 | Call/screen recording and emergency share | TESTED | TESTED | Y | Y (simulated) | hist. | - | -  | -  | - |
| 13 | OTP vault (device-local, biometric/PIN) | TESTED | TESTED | Y | Y (simulated) | - | n/a | -  | -  | - |
| 14 | Bank OTP fraud detection (notification listener) | BUILT | BUILT | Y | - | hist. | n/a | -  | -  | - |
| 15 | Device security scan (root, emulator, integrity) | BUILT | BUILT | Y | - | hist. | n/a | -  | -  | - |
| 16 | Remote-access detector | BUILT | BUILT | Y | - | hist. | n/a | -  | -  | - |
| 17 | Screen-recorder detector (Android 15+) | TESTED | TESTED | Y | Y (simulated) | hist. | n/a | -  | -  | - |
| 18 | VPN monitor (blocklist mode) | BUILT | BUILT | Y | - | - | - | -  | -  | - |
| 19 | Package-install monitor | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 20 | Network activity monitor | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 21 | Evidence locker (upload, list, delete, retrieve) | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 22 | AI security coach | BUILT | BUILT | Y | - | - | - | -  | -  | - |
| 23 | Complaint e-mail generator | BUILT | BUILT | Y | - | - | - | -  | -  | - |
| 24 | Family safety (consent, invitations, dashboard) | TESTED | TESTED | Y | Y (simulated) | hist. | - | -  | -  | - |
| 25 | Panic button and emergency contacts | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 26 | Security reports (daily, weekly, history) | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 27 | Consent / permission manager | BUILT | BUILT | Y | - | hist. | n/a | -  | -  | - |
| 28 | Anti-screenshot protection (FLAG_SECURE) | BUILT | BUILT | Y | - | - | - | -  | -  | - |
| 29 | Clone / fake-app detection | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 30 | Message, job-offer and bullying analyzer | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 31 | Community scam reports and news feed | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 32 | Elderly protection and guardian alerts | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 33 | Client-only detectors (digital arrest, payment verifier, QR, fake-bank SMS, SIM integrity, scam news) | BUILT | BUILT | Y | - | - | n/a | -  | -  | - |
| 34 | Video-call room and FIR draft | BUILT | BUILT | Y | - | - | - | -  | -  | - |
| 35 | Cyber Warriors programme (backend only, no client) | BUILDING | BUILDING | Y | - | - | - | -  | -  | - |
| 36 | Admin API and web console | TESTED | TESTED | Y | Y (simulated) | - | - | -  | -  | - |
| 37 | Account deletion / data erasure | REVIEWED | BUILT * | Y | Y (simulated) | - | - | -  | -  | - |
| 38 | Localization (6 languages) | BUILDING | BUILDING | Y | - | - | n/a | -  | -  | - |

Summary: code Y for 38 of 38; automated tests for 23 of 38 (TESTED or REVIEWED); manual (historical) for the rows marked hist.; real provider 0; staging deployed 0; staging validated 0; production approved 0.

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
| Server-side file encryption | TESTED (local) | startup validation and `FILE_ENCRYPTION_REQUIRED` enforcement built in Phase 7/A, CI-green at `15f5ea6`; **off in staging until `FILE_ENCRYPTION_KEY` is set (R-03)**; no encrypted files exist |
| API docs in production | TESTED | disabled when `ENVIRONMENT=production` (`28a490c`) |
| Rate limiting | BUILT | in-memory, per process (R-12) |
| Anti-screenshot (FLAG_SECURE) | BUILT | mocked tests only; no device check |
| DPDP readiness | PLANNED | retention, notice, consent, minors unresolved (R-13) |
| Play restricted permissions | BLOCKED | SMS/call-log/QUERY_ALL_PACKAGES risk (R-14) |
| CORS, client-IP/trusted-proxy handling, SMTP gate | TESTED | Phase A, committed `15f5ea6`, CI-green; not deployed; staging variables unset (R-04, R-05, R-06) |
| Object-level authorisation and data isolation | TESTED | Phase F audit: no BOLA/IDOR found in evidence, recordings, alerts, devices, scans, contacts, family, reports, AI history, admin; see section 12e |
| **Identity binding (F-01, F-02)** | **BUILDING** | confirmed account-takeover weaknesses; fix in progress, uncommitted (R-21, R-22, R-23) |
| Credentials | **BLOCKED** | Anthropic key confirmed exposed; rotation deferred by owner (R-01); plan in section 12d |
| Logging and incident readiness (CERT-In) | PLANNED | no durable 180-day log store; no named contact or procedure (R-27) |
| Privacy notice, consent, account deletion UI | PLANNED | none exists in the app (R-28, R-30) |

## 5a. Compliance obligations

Separated by type. **Legal applicability and interpretation need qualified Indian legal advice; nothing here is legal advice.**

| Obligation | Type | What it requires | SecureShield status | Evidence |
|---|---|---|---|---|
| CERT-In Directions of 28 Apr 2022: ICT logs | statutory direction (IT Act s.70B) | enable logs of ICT systems and keep them for a rolling 180 days; official text says "within the Indian jurisdiction"; **official FAQ Q35 says logs may be stored outside India if produced to CERT-In in reasonable time** | **not demonstrated**: ephemeral file log (10 MB x 7, lost on redeploy), Railway platform logs (retention and region unknown), `error_logs` purged at 90 days at startup (`app/main.py:153`), `admin_audit_logs` never purged, no persistent end-user auth event log | official PDFs read 2026-11-13; `logger_service.py`, `main.py`; R-27 |
| CERT-In: point of contact and incident reporting | statutory direction | designate a point of contact (Annexure II); report listed incidents within 6 hours of noticing, by email, phone or form; **FAQ Q30 allows partial reports with the rest later** | **no named contact, no written procedure** | official PDFs; R-27 |
| CERT-In: clock synchronisation | statutory direction | time source traceable to NIC or NPL; **FAQ Q40: IST not required** | unverified (hosting-provider matter) | official FAQ |
| CERT-In applicability | legal interpretation | applies to "service providers, intermediaries, data centres, body corporate" (FAQ names cloud and VPS providers too) | **counsel to confirm** for this operator | official FAQ |
| IT Act s.43A and SPDI Rules 2011 | statutory (current law until DPDP replaces it, per counsel) | privacy policy, consent for sensitive data, grievance officer | **not met**: no privacy notice screen found | R-28 Phase G adds a draft notice and consent capture (section 12f); counsel review pending |
| DPDP Act 2023 and Rules 2025 | statutory | notified by Gazette 13 Nov 2025 (**owner-confirmed**); **one-year provisions 13 Nov 2026**; **eighteen-month provisions 13 May 2027** (main duties: notice, consent, safeguards, breach notification, retention, erasure, children). **Rule 4 applies only to Consent Managers: SecureShield is not one and needs no registration merely because it obtains consent** | main duties start in about 6 months; design now (retention, deletion, notices, minors) | owner statement; R-13, R-28 |
| Google Play: restricted permissions | platform policy | SMS and call-log permissions only for default handlers; declarations; a July 2026 policy preview narrows call-log use | `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS` are declared but **no code path uses them**; `QUERY_ALL_PACKAGES` is used (app scanner) | manifest and Kotlin grep (Phase C); R-29 Phase G removed the four unused permissions; other declarations listed in section 12f |
| Google Play: account deletion and data safety | platform policy | users must be able to request deletion (in-app or web link); data-safety form | backend `DELETE /auth/me` tested; **no client path** | R-30 Phase G added the in-app path (section 12f); data-safety form not submitted |
| Safe Browsing API v4 terms | contractual | non-commercial use only; Web Risk or a separate agreement for commercial use | **BLOCKED for commercial use**; key present on staging, never called live | Google developer terms (web search, not opened in full); R-32 |
| AI provider terms (Anthropic API) | contractual | 30-day default deletion, zero retention by agreement, US-or-global processing, no training under commercial terms (training point from third-party sources) | **no agreement evidenced; no redaction; no spend cap; live AI of real user data stays disabled until reviewed** | provider privacy pages (web search); `ai_service.py`; R-31 |
| Statutory / platform / contractual / risk-based | | OWASP-style controls (pinning, SIEM, SOC) are recommended practice, **not law** | deferred | Phase C |

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
| **Identity binding (F1)**: verified-only login, single-identifier OTP challenges, pending registration, verified email change, `google_sub` | **BUILDING** | approved architecture in section 12e; code partly written and **uncommitted**; 23 existing tests await adaptation; the 12 mandatory security tests and the Flutter work are not yet written |
| Phone verification (second registration step) | **BLOCKED** | needs an SMS provider; Twilio is rejected (20003) and is not to be re-enabled (R-26) |

Gate G1 (a user can receive a login code on a deployed instance): **FAIL / BLOCKED** until Resend is deployed and verified.

## 7. AI and Third-party Provider Status

No provider has been verified live from this code. All entries are TESTED against simulated providers at most.

| Provider | Use | Code | Live verification | Cost drivers (**amounts UNVERIFIED - owner to supply**) | Notes |
|---|---|---|---|---|---|
| Resend | OTP and notification e-mail | TESTED | **not run** | per-message above the plan allowance; plan pricing not checked | domain `mail.trinetralab.net` Verified *(reported)*; sending-only key restricted to that domain *(reported)*; SPF/DKIM/MX present, `_dmarc` = `p=none`; sender `SecureShield <no-reply@mail.trinetralab.net>` |
| Anthropic | AI coach, complaint mail, FIR, message analyzer | TESTED (fake client) | not run | per-token usage; **no spend cap in code, only a per-minute limit**; provider-side spend limit is an owner action | **BLOCKED for real user data** until redaction, agreement, spend cap and kill switch exist; key exposed (R-01), present on staging |
| Google Safe Browsing / abuse.ch URLhaus | link scanner | TESTED (simulated) | not run | Safe Browsing v4 is free but **non-commercial only**; Web Risk pricing not retrieved; URLhaus needs an auth key (unset) | **Safe Browsing BLOCKED commercially** (R-32); URLs leave the device (S-16) |
| Twilio | SMS/WhatsApp, guardian SMS | BUILT | **rejected** (20003) | per-SMS, plus India DLT registration costs | do not reintroduce; startup makes a live account lookup when the SID starts with `AC`; blocks phone verification (R-26) |
| Google ID tokens | Google Sign-In | BUILDING | not run | free | needs OAuth client IDs (`GOOGLE_CLIENT_IDS`); account linking is being redesigned in F1 |
| Railway | hosting, Postgres, volumes | n/a | staging only | usage-based; plan, PITR and volume-backup pricing not verified | region unknown (matters for log location under CERT-In) |
| Jitsi (`meet.jit.si`) | video-call room | BUILT | not run | free public instance | video passes through a third-party public server (privacy decision pending) |
| Google Play | distribution | n/a | not started | one-time developer registration fee, amount not verified | restricted-permission review may add weeks |
| Azure Translator | localization tooling | - | not run | not used at runtime | listed in compromised-credentials inventory |

## 8. Database and Migration Status

| Item | Value | Source |
|---|---|---|
| Staging DB (Railway Postgres service) | 29 tables, 23,278 rows; `sms_sender_registry` 23,192 rows; user-data tables empty | *(reported; read-only probe 2026-11-13)* |
| Current staging revision | `l7m8n9o0p1q2` | *(reported)* |
| Target revision | `u6v7w8x9y0z1` (single head at `15f5ea6`). **F1 working tree adds `v7w8x9y0z1a2` (uncommitted), which would become the head** | `architecture-and-integration.md`; F1 working tree |
| Pending migrations | **9 committed** (`m8n9o0p1q2r3`, `n9o0p1q2r3s4`, `o0p1q2r3s4t5`, `p1q2r3s4t5u6`, `q2r3s4t5u6v7`, `r3s4t5u6v7w8`, `s4t5u6v7w8x9`, `t5u6v7w8x9y0`, `u6v7w8x9y0z1`) **plus 1 uncommitted F1 revision `v7w8x9y0z1a2`** (additive: verified-identifier columns, `google_sub`, `pending_registrations`, OTP binding columns; deletes nothing, marks nothing verified) | `../MIGRATION_SAFETY_REVIEW.md`; F1 working tree |
| Executed during the reported deployment | **None** - deployment `e75a63cd` ran old commit; revision unchanged | *(reported)* |
| Destructive steps among the nine | `n9o0...` deletes duplicate `security_reports`; `q2r3...` empties `otps`; `p1q2...` alerttype enum is irreversible; `u6v7...` downgrade destroys admin accounts. All affected staging tables were empty when probed | migration safety review (2026-11-13) |
| Migration test evidence | upgrade/repeat/downgrade/re-upgrade passed on a populated **disposable** DB; `test_schema_drift` passes | `p1-closure-report.md` |
| Neon | at `s4t5u6v7w8x9` (2026-10-18 state, not re-read); cutover not done | `p1-closure-report.md` |
| Backup / restore | tooling exists; **(as of the original reconciliation) no backup taken and no restore proven** for staging; **superseded by section 12b: one backup and isolated restore completed 2026-11-13** | R-07 |

**Status: BUILT and TESTED (disposable DB). Not applied to any real database.** Applying requires explicit approval (section 16) and a prior backup.
**Migration risk register (Phase D, 2026-11-13; nothing was executed):**

| Revision | Effect | Data risk | Downgrade |
|---|---|---|---|
| `m8n9...` family consent | adds `consent_status` default `pending`; existing links would turn pending | low | drops columns |
| `n9o0...` report unique | **DELETE** of duplicate `(user_id, report_date)` rows, keeping the newest | loss only if duplicates exist | drops the constraint; deleted rows not restored |
| `o0p1...` scan scoping | nullable `user_id` on `app_scans`, `wifi_scans`; old rows unscoped | low | drops column |
| `p1q2...` alerttype | `ALTER TYPE ... ADD VALUE` in an autocommit block | **irreversible** | `pass` |
| `q2r3...` OTP hashing | **`DELETE FROM otps`**, widens `code` | invalidates pending OTPs | also deletes OTPs |
| `r3s4...` refresh tables | creates tables | low | drops tables (loses revocation state) |
| `s4t5...` audit log | creates `admin_audit_logs` | low | **drops the audit history** |
| `t5u6...` OTP attempts | adds a column | low | drops column |
| `u6v7...` admin accounts | admin tables and audit columns | low | **drops admin accounts and sessions** |
| `v7w8...` identity binding (F1, uncommitted) | additive columns and tables; **no delete, no backfill** | none for existing data; legacy identifiers stay unverified | drops verification state; **re-opens the takeover weakness** |

Staging holds no user data today (all user tables 0 rows, 2026-11-13 probe), so none of this would lose data there now. Safe order: back up, re-probe counts, run the chain once through the pre-deploy step, smoke test; do not run a downgrade once real data exists. Unverified: whether a mid-chain failure leaves partial application (`p1q2...` commits mid-run).

## 9. Infrastructure and Cloud Services

| Service | Detail | Status |
|---|---|---|
| Railway project | `secureshield-staging`, environment `staging` (renamed from `production` by owner 2026-11-13) | **staging environment** (not production; not approved or verified as production); old commit `976ce42` running |
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
| `backend-ci.yml` | push to `main` and `staging/**`; pull requests | gitleaks, ruff check/format, pip-audit, alembic on a blank DB, pytest on a Postgres service; inert CI placeholder values only | **Run 43399687864 on `b130d04` (branch `staging/candidate-2026-11-13`, 2026-11-13): SUCCESS** - every step passed (see CI result below). Earlier run 43381648865 on `e367eb6` failed at ruff format (CI-1, fixed). Previous green run before this: 2026-10-05 at `976ce42` |
| `deploy-staging.yml` | `workflow_dispatch` only; GitHub environment `staging` | `railway up` to staging; requires secret `RAILWAY_TOKEN` | never |
| `flutter-ci.yml` (frontend) | push/PR | analyze, test, build; approval-gated `android-release` job | never |

* GitHub environments `staging` and `android-release` exist (created by the owner-approved action 2026-11-13). Repository and environment secrets/variables: none found (names-only check, 2026-11-13). **Required reviewers are not configured.**
* **Candidate-branch protection (verified by reading the workflows, nothing run):** `staging/candidate-2026-11-13` matches `staging/**`, so CI runs on it. Railway watches only `staging/railway-snapshot`, so a push of the candidate does not deploy. **R-16 (partly mitigated 2026-11-13):** `deploy-staging.yml` now accepts only the exact branch `staging/railway-snapshot`; `v*` tags and candidate branches are rejected (guard tested locally, uncommitted); candidate branches cannot pass it. Still open: `staging` environment required reviewers are not configured and the workflow has never run on GitHub.
* CI workflows give candidate runs **no production secrets**: they use inert placeholders; the only secret planned (`RAILWAY_TOKEN`) is scoped to the `staging` environment used by the manual deploy workflow.

### CI result for this candidate revision (2026-11-13)

* **Commit** `b130d04` on `staging/candidate-2026-11-13`; **workflow run** [43399687864](https://github.com/ravishori/SecureShield-Backend/actions/runs/43399687864) (`backend-ci`); **conclusion: SUCCESS**.
* Steps that all passed (from the run's step list): secret scan (gitleaks, current tree), lint for syntax errors/undefined names, lint and format (ruff check and format, project standard), dependency vulnerability scan (pip-audit, runtime packages), apply migrations to a blank database (full Alembic chain), run tests (pytest on a PostgreSQL service).
* Individual test counts were **not** read from the workflow logs and are not recorded here; the 1069-passed figure is from the local clean-checkout run, not from CI.
* **CI validation is complete for this candidate revision (`b130d04`).** This does **not** close any open infrastructure, credential, deployment or provider risk (R-01..R-20 unchanged), and it validates only this revision; any later commit needs a new CI run.
* Nothing was deployed or migrated: Railway still watches only `staging/railway-snapshot` (remote `976ce42`), and no database change was made.

### CI failure record

| ID | Run | Failure | Root cause | Status |
|---|---|---|---|---|
| CI-1 | [43381648865](https://github.com/ravishori/SecureShield-Backend/actions/runs/43381648865), job `pytest (unit + PostgreSQL integration)`, step "Lint and format", commit `e367eb6` | `Would reformat: scripts/seed_sms_registry.py` / `1 file would be reformatted, 188 files already formatted`, exit 1 | **Genuine formatting defect in the committed file** `scripts/seed_sms_registry.py` (from commit `984c190`, inside the 74-commit range). Local ruff runs had passed because the working-tree copy of that file carries the owner's **uncommitted** change, which is exactly the ruff-formatted version (verified byte-identical apart from line endings), masking the defect. Not a PostgreSQL, environment, ordering or dependency issue; `ruff check` passed in CI (ruff 0.9.4 pinned) | **FIXED, VERIFIED IN CI** - fixed by `b130d04`; run 43399687864 green |

Fix: commit the ruff-formatted `scripts/seed_sms_registry.py` (format-only: 36 insertions, 12 deletions, no behavioural change). The working-tree file already contains it; it is owner-owned and was deliberately left alone. The corrective commit `b130d04` was approved, created (without amending `e367eb6`) and pushed on 2026-11-13. Verified in a **clean checkout of `e367eb6` with only that formatting applied**: `ruff check` and `ruff format --check` clean (189 files) and full backend suite **1069 passed, 0 failed, 0 skipped** (473 s, disposable local DB), which also shows the commits do not depend on any uncommitted file. Not run locally for this commit: gitleaks, `pip-audit` (last clean run earlier on 2026-11-13), a standalone `alembic upgrade head` on a blank DB (covered indirectly by the schema-drift tests); these remain for CI.
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
| GitHub CI (gitleaks, ruff, pip-audit, blank-DB Alembic, pytest) | **PASSED** on `b130d04`, run 43399687864 (first run on `e367eb6` failed, CI-1) | 2026-11-13 |
| Backend full suite with the Phase A changes | **1227 passed, 0 failed, 0 skipped** (disposable local DB, 684 s); clean-checkout unit tests 526 passed | 2026-11-13, before the F1 changes |
| GitHub CI on `15f5ea6` | **success**: gitleaks, lint, ruff, pip-audit, blank-DB Alembic, pytest (run 43430344346) | 2026-11-13 |
| Mutation checks, Phase A | 12/12 caught | 2026-11-13 |
| Phase B restore (isolated, local) | 22 checks passed after two reported corrections | 2026-11-13 |
| Phase E1 restore from the Drive copy | **RESTORE PARTIALLY VERIFIED**: 29 checks passed; ownership/grants, sequence values and row-level data against the source NOT verified | 2026-11-13 |
| Phase F proof of concept (synthetic accounts, disposable DB) | 3 passed: F-01 and F-02 **exploitable** at `15f5ea6`, control case blocked | 2026-11-13 |
| **F1 working tree (uncommitted)** | ten existing auth-related test files: **88 passed, 23 failed** (they assume the old register/login behaviour and still need adapting); schema-drift test passes; the 12 mandatory new tests are **not written**; full suite **not run**; Flutter tests **not run** | 2026-11-13 |
| Documentation consistency checks | see section 18 | 2026-11-13 |
| STALE rows above | rows "1009 passed", "1062 passed" and "Flutter 95 tests" are historical; the Flutter suite was **not re-run** in this pass | - |
| **Not run, ever:** Railway build/deploy of the new code, any real provider send, any physical device or signed build, coverage measurement, full-history secret scan | - | - |

## 12. Deployment Readiness

Gates from `production-readiness.md` (0 of 12 pass; see the G1-G12 table in section 12c). Staging readiness for the **77-commit release candidate** (77 commits ahead of `976ce42`; **none deployed**):

| Prerequisite | State |
|---|---|
| Code complete and unit-tested | Phase 7 and Phase A: yes (TESTED, 1227 passed, CI-green at `15f5ea6`); **F1 identity-binding fix: not complete** (BUILDING) |
| Release range scanned for secrets | yes: regex scan plus gitleaks (current tree) green in CI on `15f5ea6`; **full-history scan not run** (history holds a confirmed exposed Anthropic key) |
| Pushed to a CI-only branch and CI green | **yes** - `staging/candidate-2026-11-13` @ `15f5ea6`, run 43430344346 SUCCESS (earlier `b130d04`, run 43399687864 SUCCESS; CI-only, Railway not triggered) |
| Backup of staging DB with a proven restore | **partly**: manual backup, isolated restore and a restore from the Drive copy done (section 12b, 12d); **re-backup after any migration, automation and uploads recovery not done** |
| Approval to apply the migrations | **no** (nine committed plus the uncommitted F1 revision) |
| `FILE_ENCRYPTION_KEY`, `TRUSTED_PROXIES`, CORS configured | **no** |
| Railway start command / Python version verified | **no** |
| Controlled fast-forward of `staging/railway-snapshot` | **no** (auto-deploys on push; only after the above) |
| Production environment | does not exist; production deploy is not approved |
| Identity-binding fix (F-01/F-02) implemented, tested, CI-green | **no** (section 12e) |
| Credential remediation executed (Anthropic, Gmail app password, Safe Browsing, Twilio token revoked; `SECRET_KEY` rotated) | **no** (plan in section 12d, awaiting approval) |
| Client and backend tested together on a device | **no** |

Release strategy (decision, section 16): the release candidate (77 commits ahead of `976ce42`) was pushed first to a CI-only branch (done, `15f5ea6`); fast-forward `staging/railway-snapshot` only after CI is green, backup verified, and migrations approved.

### 12a. Phase A - application security hardening (2026-11-13; **committed as `15f5ea6`, pushed to the candidate branch, CI green**; not deployed)

Application-code status is kept separate from actual staging configuration. **Nothing here is deployed; no Railway variable was changed.**

| Task | Code status | Staging configuration status | Files | Variables and safe defaults |
|---|---|---|---|---|
| File encryption | TESTED (local) | **not configured** (`FILE_ENCRYPTION_KEY` and `FILE_ENCRYPTION_REQUIRED` unset on Railway) | `app/services/upload_safety.py` (`save_text` now deletes a partial file on failure); Phase 7 files unchanged | `FILE_ENCRYPTION_KEY` (urlsafe-base64, exactly 32 bytes; default empty), `FILE_ENCRYPTION_REQUIRED` (default `false`) |
| SMTP fallback control | TESTED (local) | **not configured** (`SMTP_FALLBACK_ENABLED` unset; `SMTP_HOST` is set, so SMTP would be used) | `app/services/device_service.py` (**fourth SMTP path found and gated**: the new-device login alert, missed in Phase 7) | `SMTP_FALLBACK_ENABLED` (default `true`; recommended staging value `false`) |
| Trusted proxy / client IP | TESTED (local) | **not configured** (`TRUSTED_PROXIES` unset while `TRUST_PROXY_TLS=true`) | `app/services/client_ip.py` (`client_ip_for`), `app/middleware/{rate_limiter,error_handler}.py`, `app/routers/{auth,admin_auth}.py`, `app/services/admin_access.py`, `app/startup_checks.py` | `TRUSTED_PROXIES` (default empty = trust nobody; wildcard, `/0` and malformed values stop startup) |
| CORS | TESTED (local) | **not configured** (`CORS_ALLOWED_ORIGINS` unset; `ENVIRONMENT=staging`) | new `app/cors_policy.py`, `app/main.py`, `app/startup_checks.py` | `CORS_ALLOWED_ORIGINS` (default empty). Empty means no browser origin in staging/production; `*` only in development |

**What changed and why**
* **SMTP:** every module that calls `smtplib` is now gated (OTP fallback, guardian/panic/report mail, error-alert mail, new-device alert). Resend stays primary. Tests assert that with the switch off none of the paths connects, for every Resend failure mode (401, 403, 429, 500, 503, timeout, connection error), and that failure is never reported as delivery.
* **Client IP:** the rate limiter honoured `TRUSTED_PROXIES` but 13 other places (auth rate limits, device registration, error logs, admin audit rows) used the raw peer address, so behind a proxy they would all see the proxy. All now use `client_ip_for`. A guard test fails if any module reads `request.client.host` directly. The trust logic is unchanged: `X-Forwarded-For` is believed only from an explicitly trusted peer, read right to left, never the left-most entry.
* **Proxy startup policy:** production with `TRUST_PROXY_TLS=true` and no `TRUSTED_PROXIES` still refuses to boot (existing). New: staging/dev logs a warning instead of silently degrading; it does not block the deploy.
* **CORS:** staging used to fall back to `*` when unset (any environment name except `production`). Now only `development`, `dev`, `local`, `test` do; an unknown or mistyped environment name gets no origins. Entries must be plain `scheme://host[:port]`; malformed entries, `*` mixed with origins, `*` outside development and non-https in production all stop startup. Methods and headers are an explicit list (was `*`). Credentials only with an explicit list. No cookies are used (bearer tokens), so there is no CSRF surface. `app/config.py` was **not** modified (owner-owned, uncommitted); `main.py` now uses `cors_policy` and the old `Settings.cors_*` helpers are unused.
* **Encryption:** key validation, `REQUIRED` enforcement and the 503-without-writing behaviour were done in Phase 7; this phase added partial-file cleanup for generated text files and tests for failure cleanup, tamper (ciphertext and tag), nonce uniqueness, key never in error text, plaintext compatibility and optional-mode startup. Existing files are not re-encrypted; the file format is unchanged.

**Frontend evidence (read-only):** the Flutter app has no web target and is Android/iOS only; native HTTP clients do not use CORS. The admin console is served by the API itself (same origin). The URL in `STAGING_API.md` is the **API** host, not a browser origin. **No cross-origin browser client exists, so no origin was invented and none should be configured.**

**CI (update):** GitHub Actions run [43430344346](https://github.com/ravishori/SecureShield-Backend/actions/runs/43430344346) on `15f5ea6`: conclusion **success**; steps gitleaks (current tree), lint, ruff check/format, pip-audit, blank-database Alembic migrations and pytest all succeeded. Individual test counts were not read from the logs.

**Test evidence (local, before the commit; working tree on `b130d04`)**
* Full backend suite on the disposable local DB: **1227 passed, 0 failed, 0 skipped** (684 s).
* New or extended: `tests/unit/test_cors_policy.py`, `test_client_ip_request.py`, `test_email_provider_failures.py`, `test_file_encryption_required.py` (extended), `tests/integration/test_client_ip_endpoint_limits.py`.
* Clean checkout of `b130d04` with only the Phase A files copied in: ruff check and format clean (194 files), unit suite **526 passed, 0 skipped**.
* Mutation checks on the new gates: **12/12 caught**. Incident: the mutation script crashed on a file write and left `device_service.py` mutated; it was noticed, restored and re-verified (no mutation markers in any source file).
* **Not run locally at the time (CI has since passed, see above):** GitHub CI; **never run:** frontend checks (no frontend file changed), real providers, a real proxy or uvicorn socket (proxy tests simulate the peer address), standalone Alembic run (no migration changed).

**Manual Railway actions required from the owner (not performed)**
1. `SMTP_FALLBACK_ENABLED=false`.
2. Create and escrow a 32-byte urlsafe-base64 key (`FILE_ENCRYPTION_KEY`), then set `FILE_ENCRYPTION_REQUIRED=true`. Set the key first: with `REQUIRED` and no key the app will not boot. Losing the key makes encrypted files unreadable.
3. **`TRUSTED_PROXIES`: do not guess.** The only observation so far is one peer address (`100.64.0.1`), which does not establish a range. Deploy with it empty (safe: the header is ignored), log the peer address and `X-Forwarded-For` of a few real requests from different networks, confirm every request arrives from the same private range and the platform appends the real client as the last hop, then set the smallest range covering the observed peers. Keep the start command's `--forwarded-allow-ips` consistent (start command still unverified, R-11).
4. `CORS_ALLOWED_ORIGINS`: leave **unset** unless a browser client exists.

**Deployment and rollback:** none of this is live; deploying needs a push (separate approval). On first deploy with the variables unset: staging CORS goes from `*` to none (no impact on the native app) and a startup warning about `TRUSTED_PROXIES` appears. Rollback: revert the commit, or set `SMTP_FALLBACK_ENABLED=true`, `FILE_ENCRYPTION_REQUIRED=false`, and clear `TRUSTED_PROXIES` and `CORS_ALLOWED_ORIGINS`. No data or schema is involved; existing encrypted files stay readable as long as the key is kept.

### 12b. Phase B - PostgreSQL backup and isolated restoration (2026-11-13: inspected, planned, then executed with owner approval)

**Status: the database backup and the isolated restoration were EXECUTED and VERIFIED on 2026-11-13 (see "Execution results" below). Railway staging was not changed and no Railway resource was created.** The inventory below is read-only, aggregate-only output (no URLs, credentials, personal data or file contents) and was re-checked immediately before the backup: identical.

**Phase B status (updated 2026-11-13 after the Google Drive verification):**
* **DATABASE BACKUP AND ISOLATED RESTORE: TESTED**
* **OFF-MACHINE ENCRYPTED COPY: VERIFIED** (byte-identical copy confirmed by size and SHA-256; **not** restored from)
* **FULL DISASTER RECOVERY: NOT TESTED**

| Item | Status |
|---|---|
| Database backup (`pg_dump -Fc`) | **TESTED** (executed and verified once; this is a manual, one-off backup, not a schedule) |
| Uploads backup | **TESTED** as a manifest only: the volume held **0 files**, so no uploads archive exists and none is claimed |
| Isolated restoration (local scratch database) | **TESTED** (restored and verified; scratch database retained) |
| Integrity verification (`pg_restore --list`, SHA-256, GPG, row counts, revision, schema fingerprints) | **TESTED** |
| Recovery acceptance criteria | **TESTED** (measured below, 10 of 10 met; see limitations) |
| Railway point-in-time recovery (PITR) | **DEFERRED** (disabled, no bucket wired; not requested) |
| Scheduled backups (`db-backup.yml`) | **BLOCKED** - disabled, and see finding F-3 |
| Off-machine copy of the encrypted backup (Google Drive) | **VERIFIED** (uploaded by the owner, downloaded back, size and SHA-256 identical; see "Google Drive verification") |
| Passphrase custody (Bitwarden Secure Note, two-step login, offline recovery code) | **owner-reported, not verifiable by Claude** (Bitwarden was never accessed) |
| Full disaster recovery (restore from the Drive copy, populated data, uploads, schedule, retention) | **NOT TESTED** |

**1. Inventory (read-only, 2026-11-13)**

| Item | Observed |
|---|---|
| PostgreSQL server | 18.6 (Debian), database `railway`, UTF8 / `en_US.utf8`, schema `public` only |
| Database size | 12,678,847 bytes (about 12.1 MB); Postgres volume 168.6 MB used of 5,000 MB |
| Alembic revision | `l7m8n9o0p1q2` (unchanged at that time; nine committed migrations were pending then, **ten pending migration files now** counting the uncommitted F1 revision; none has been executed on Railway) |
| Objects | 29 tables, 3 sequences, 76 indexes, 22 foreign keys, 29 primary keys, 3 unique constraints, 209 NOT NULL, 11 enum types, 0 views, 0 triggers, 0 functions, 0 large objects |
| Extensions | `plpgsql` only |
| Rows | **23,278 total**: `sms_sender_registry` 23,192 (2.9 MB, the bulk), `error_logs` 52, `lsa_codes` 22, `tsp_codes` 11, `alembic_version` 1; **every user-data table is 0** (`users`, `otps`, `devices`, `alerts`, `evidence`, `recordings`, `family_members`, `app_scans`, ...) |
| Replication | none: 0 slots, 0 replicas, 0 publications or subscriptions, no foreign tables; `wal_level=replica`; no HA cluster |
| Privileges seen by the application role | not superuser, no `CREATEDB`, can connect; the migrator (owner) role was not used |
| Uploads volume `/app/uploads` | 3 directories (`evidence`, `recordings`, `lost+found`), **0 files, 0 bytes**; filesystem 4.84 GB total, 4.82 GB free; 0 encrypted (SSENC1/SSENC2), 0 plaintext; **no orphaned files and no dangling references possible** (0 files, `evidence` and `recordings` have 0 rows) |
| File metadata in the database | yes: `evidence.file_path` and `recordings.file_path` (the only file-referencing columns); FIR draft files are also written under the same volume by the video-call router |
| Postgres client in the API container | none (`pg_dump`, `pg_restore`, `psql` absent) |
| This workstation | PostgreSQL 18.6 client tools and a local 18.x server accepting connections: **client matches the server's major and minor version**. **Disk space is tight: C: 6.1 GB free, D: 555 MB free (100% full).** |

**2. Railway capabilities (from CLI help and read-only status; billing/plan limits not verified)**
* Postgres service has **no public TCP proxy** and no `DATABASE_PUBLIC_URL`: the database is reachable only from inside Railway's private network or via `railway ssh` / `railway connect`.
* `railway postgres pitr` (continuous backups) exists; here it is `disabled` and no storage bucket is wired. Enabling it creates a bucket and changes the service: **not done, not recommended as the first step**, plan/cost unknown.
* The CLI has no volume-snapshot command. `railway volume files download|list` can copy files out of a volume; dashboard volume backups are plan dependent and **unverified**.
* Creating a temporary Postgres service is possible in principle, but it is **not needed**: the restoration plan uses a scratch database on the local server (no Railway resource, no cost).
* Existing tooling: `scripts/db_backup.py` (pg_dump -Fc + SHA-256 + pruning; no encryption, no manifest, no version/revision record), `scripts/db_restore_check.py`, `docs/BACKUP_AND_RECOVERY.md`, `.github/workflows/db-backup.yml` (disabled).

**Execution results (2026-11-13, owner-approved; dump started 14:09:39 UTC)**

| Item | Result |
|---|---|
| Pre-flight | branch `staging/candidate-2026-11-13`; Railway identity project `secureshield-staging`, environment `staging`, service `Postgres`, database `railway`, PostgreSQL 18.6, revision `l7m8n9o0p1q2`; inventory identical to the earlier read-only probe (12,678,847 bytes, 23,278 rows, 0 uploads files); local PostgreSQL 18.6 accepting connections; GPG 2.4.9 round trip worked; `C:\SecureShield-Backups` is outside every Git repository (no repository found above it) and its permissions were restricted to the owner's account |
| Method | `pg_dump -Fc -Z 6` executed **inside the existing Postgres service**, written to `/tmp` (container filesystem, **not** the data volume), streamed out through `railway ssh` as base64, decoded locally. **No TCP proxy and no other Railway resource was created.** The remote temp file was removed only after the local encrypted copy had been verified |
| Archive | 369,844 bytes; SHA-256 `d286d0277aeb8cf4...` equal inside the container and locally; `pg_restore --list` rc 0 |
| Encrypted backup | `C:\SecureShield-Backups\secureshield-staging-20261113T140939Z.dump.gpg`, 302,986 bytes, GPG symmetric **AES-256** (cipher 9, salted iterated S2K); decrypting yields the identical SHA-256; a wrong passphrase fails (rc 2); GPG file SHA-256 `c07c36fa3676eefe...` recorded and re-verified after the restore |
| Other retained artefacts | `.dump.sha256`, `.dump.gpg.sha256`, `.manifest.json` (timestamp, source identity without host or credentials, versions, revision, per-table counts, schema inventory), `.pg_restore_list.txt`, `.uploads-manifest.json`, `.restore-verification.json` |
| Restore target | scratch database `secureshield_restore_check_20261113t140939z` on the **local** PostgreSQL 18.6 server, created new (name checked not to exist). It is **retained** pending separate cleanup approval. No Alembic command was run; the Railway database was never a target; no API was connected to it |
| Restore verification | 22 checks, all passed after one correction (below): decrypt, create, `pg_restore` rc 0, 29 tables and only schema `public`, revision `l7m8n9o0p1q2`, every row count equal to the manifest, constraints 22 FK + 29 PK + 3 unique all validated, 76 indexes, 3 sequences, 11 enum types, extension `plpgsql`, representative read-only queries, original encrypted file unchanged. Definition-level comparison with the source (columns 300, indexes 76, constraints 54, enum labels 61, sequences 3, extensions 1) matched |
| Durations (measured) | dump 4 s; download 4 s; restore 0.6 s; verification about 2.4 s; whole exercise (first command to Railway-unchanged check) about 7 minutes, mostly my own tooling |
| Railway unchanged | latest API deployment still `e75a63cd` (2026-11-13 05:27 UTC), Postgres `5388eacf` (2026-10-23); revision, size, row total and uploads count identical after the exercise; volumes Ready at 168.6 MB and 83.1 MB; remote `staging/railway-snapshot` still `976ce42` |

**Google Drive verification (2026-11-13, read-only; supersedes the "off-machine copy still needed" point below)**

| Item | Result |
|---|---|
| Original encrypted backup | `C:\\SecureShield-Backups\\secureshield-staging-20261113T140939Z.dump.gpg`, **302,986 bytes** |
| Downloaded Google Drive copy | `C:\\SecureShield-Backups\\verification-download\\secureshield-staging-20261113T140939Z.dump.gpg`, **302,986 bytes** |
| SHA-256, original | `c07c36fa3676eefeb7c2e09bad39183c7bb0a6067dbdd712761b714947fb2d77` |
| SHA-256, downloaded copy | `c07c36fa3676eefeb7c2e09bad39183c7bb0a6067dbdd712761b714947fb2d77` |
| SHA-256, recorded Phase B checksum (`...dump.gpg.sha256`) | `c07c36fa3676eefeb7c2e09bad39183c7bb0a6067dbdd712761b714947fb2d77` |
| Result | **PASS**: both files exist, sizes equal, all three hashes equal. Only sizes and hashes were read; neither file was opened, decrypted, modified, renamed, moved or deleted, and the Bitwarden passphrase was not accessed |

Owner-reported (not verifiable by Claude): the passphrase is stored in a Bitwarden Secure Note; Bitwarden two-step login is enabled; the recovery code is saved offline.
**Discrepancy to resolve:** the owner states the temporary plaintext passphrase file was deleted, but when this document was updated the file `C:\\Users\\ravin\\SecureShield-Backup-Secrets\\backup-passphrase.txt` was **still listed in that folder** (only the directory listing was read, never the file). Until the owner confirms the deletion, treat the plaintext passphrase as still present on this workstation. Claude did not delete it (not authorised).
**Recheck at the owner's request (same day, after the first update): the file is STILL PRESENT** (`ls`: 48 bytes, last modified 19:38; no other file named like a passphrase exists under the user profile or `C:\\SecureShield-Backups`). Status at that time: not deleted.
**Second recheck after the owner deleted it (same day, folder timestamp 20:41): RESOLVED.** The folder `C:\\Users\\ravin\\SecureShield-Backup-Secrets` is now empty and no file named like a passphrase exists under the user profile or `C:\\SecureShield-Backups`. Limitation: the Recycle Bin contents were not inspected, so whether a recoverable copy remains there is unverified (the owner should empty the Recycle Bin if it was not bypassed).
Railway staging and the Git history were not changed by this verification (no Railway or Git command was run; the working tree contains only the seven user-owned files plus this uncommitted document).

**Errors and corrections during the exercise (reported, not hidden)**
1. The first schema-fingerprint comparison was **vacuous** (the source query failed on a `"char"` type, producing an empty file, and the comparison `None == None` passed). Found immediately, discarded, query fixed, and the comparison re-run with an assertion that both sides are non-empty.
2. The corrected comparison showed a **real mismatch** in the constraints fingerprint. Investigation showed all 54 constraint definitions are identical; only the ordering differed (source Linux `en_US.utf8` versus the local Windows server collation). The check was changed to an order-independent comparison of the sorted definitions and the explanation is stored in the verification report.
3. A first attempt to list GPG packets hung waiting for a passphrase (no data affected); an unrelated `icacls` syntax error was fixed and the folder permissions verified.

**Limitations (measured scope only)**
* Sequence values were not compared with the source (restored: `error_logs_id_seq` 52, `otps_id_seq` 11, `sms_sender_registry_id_seq` 23,192).
* Ownership and grants were **not** exercised (`--no-owner --no-acl`; the application roles do not exist locally).
* Consistency is single-snapshot for the database only; the source was quiet (identical size and row total before and after). **Not** a cross-store guarantee and not a result for a populated system.
* The uploads volume was empty, so no uploads archive, no encrypted/plaintext sample and no database-to-file reference could be exercised.
* **Passphrase custody:** a random 48-character passphrase was generated for this backup and stored in a user-only file in the owner's profile (`C:\Users\ravin\SecureShield-Backup-Secrets\backup-passphrase.txt`); it was never printed or logged. **The owner must move it into a password manager and delete the file.** Anyone with both that file and the encrypted backup can decrypt it.
* The backup and passphrase are on one workstation with very little free disk space: **an off-machine encrypted copy is still needed** for real disaster recovery. The scratch database lives on that same machine and holds a clear copy of the (non-personal) data.
* This was a manual, one-off backup: no schedule, no retention policy, no automated restore test exist. PITR remains disabled.

**Remaining limitations after the Google Drive verification (all still true):**
* **No restore was performed directly from the Google Drive copy** (only its hash was compared; a restore from it is the real proof of the off-machine copy).
* **No automated backup schedule** exists.
* **No formal retention policy** exists.
* **No populated user-data recovery exercise** (the database holds no user data).
* **No upload-volume recovery test** (the volume held 0 files).
* Ownership/grants, sequence values against the source, and cross-store consistency remain as listed above.
* Therefore **full disaster recovery is NOT TESTED**; do not describe the system as disaster-recovery ready.

**Outstanding approvals / actions (original list, kept for history; items 1-2 are reported done by the owner):** move the passphrase to a password manager and delete the file; decide where the off-machine copy lives; approve (or not) dropping the scratch database `secureshield_restore_check_20261113t140939z`; approve a backup schedule design that does not use Docker (F-3) before any automation; repeat the exercise, including uploads and a populated database, before any production use.

**Findings**
* **F-1** Backup and restore have never been exercised on staging (R-07). The database is tiny and holds no user data, so the exercise is cheap and low-risk now; it gets harder once users exist.
* **F-2** The database is only reachable privately, so the dump must run inside Railway's network or through a temporary public proxy (a new Railway resource). The plan prefers the first.
* **F-3** `db-backup.yml` starts a `postgres:18` **Docker service container**, which contradicts the Docker-free decision. It is disabled; do not enable it without reworking that step.
* **F-4** Local disk space is very low; the exercise itself needs well under 50 MB, but the backup location must be chosen deliberately.
* **F-5** `D:\` is itself a Git repository with the whole drive untracked (S-15); a backup stored under `D:\` risks an accidental `git add`. Store backups outside any repository.

**3. Proposed database backup procedure (not executed)**
1. Pre-flight read-only re-check: revision, size, per-table row counts and the uploads file count (re-run the same probe). Record UTC timestamp, server and client versions.
2. **Preferred method (no new Railway resource):** run `pg_dump` inside the Postgres service container, which carries the matching 18.x client, writing to `/tmp` (the container's ephemeral disk, **not** the Postgres volume), and stream it out through `railway ssh` to a file on the owner's machine. Command shape (credentials are already in that container's `PG*` environment, so none is typed or logged): `railway ssh -s Postgres -- sh -c "pg_dump -Fc --no-password -Z 6 -f /tmp/ss.dump && cat /tmp/ss.dump && rm /tmp/ss.dump" > ss-<UTC>.dump`. **Binary streaming through `railway ssh` is unproven**; if the SHA-256 or `pg_restore --list` check on the local copy fails, fall back to method B.
3. Method B (needs approval, creates a resource): temporary public TCP proxy on the Postgres service, run `scripts/db_backup.py` from this workstation with a read-only role or the existing credentials in `PG*` environment variables, then **delete the proxy immediately**.
4. Dump uses one snapshot transaction, so the database file is internally consistent. Options: custom format (`-Fc`), keep ownership and privilege information in the archive (no `--no-owner` / `--no-acl` at dump time), schema `public`.
5. Verify immediately: `pg_restore --list` exits 0 and lists all 29 tables; compute SHA-256; write a manifest (UTC timestamp, source revision, versions, per-table counts, dump size, SHA-256).
6. Encrypt at rest with `gpg --symmetric --cipher-algo AES256` (passphrase entered interactively or from the owner's password manager, never in shell history, code or logs); keep only the encrypted file and its checksum; securely remove the clear dump.
7. Store outside the source service and volume and outside any Git repository (see F-4/F-5): an owner-chosen encrypted location with at most owner access. Not personal e-mail, not public storage.

**4. Proposed uploads backup procedure (not executed)**
* Today the volume holds no files, so the backup is a verified **empty manifest** plus the directory layout. Re-count immediately before the real run; if files appear, the steps below apply.
* Copy: `railway volume files download` (or `tar` inside the API container streamed out the same way), preserving the directory hierarchy; build a manifest of relative path, size and SHA-256 for every file; `tar -tf` and a test extraction into a scratch directory; encrypt the archive with gpg as above. Do **not** include `FILE_ENCRYPTION_KEY` or any key: encrypted files stay encrypted, and the key lives only in the owner's password manager (losing it makes SSENC files unreadable).

**5. Consistency (honest assessment)**
* The database dump is a single-snapshot consistent copy of the database only. There is **no cross-store (database plus uploads) point-in-time guarantee** from this method.
* Right now the question is moot: user-data tables and the uploads volume are empty, and only `error_logs` (52 rows) can change. The manifest records counts before and after the dump; any table whose count differs is listed as non-quiescent.
* Once real data exists, a coordinated recovery point needs a controlled maintenance window (stop the API service or block writes, then dump and copy, then restart). That would interrupt service and **requires explicit owner approval at that time**. A timestamp-and-manifest strategy alone would not guarantee consistency.

**6. Proposed isolated restoration (not executed)**
* Target: a **new scratch database on the local PostgreSQL 18 server** (for example `secureshield_restore_check_<UTC>`). Never the Railway database, never its volume, never a production database, no live API connected to it.
* `createdb`, then `pg_restore --no-owner --no-acl --exit-on-error -d <scratch> <decrypted dump>` (roles `secureshield_app` / `secureshield_migrator` do not exist locally; ownership information stays in the archive). **No Alembic command is run.** The original encrypted backup is never modified (work on a copy; verify its SHA-256 before and after).
* Verify: all 29 tables exist; `alembic_version` equals the manifest revision (`l7m8n9o0p1q2` unless it changed); per-table row counts equal the manifest; 3 sequences, 76 indexes, all 22 foreign keys and the 11 enum types exist; extension list equals source; foreign keys validated; read-only application queries succeed (for example counts and `SELECT` through the ORM read paths against the scratch database).
* Uploads: extract into an empty scratch folder; compare file count, total size and every checksum with the manifest; check that every `evidence.file_path` / `recordings.file_path` resolves (vacuous today: 0 rows).
* Cleanup: drop the scratch database, delete the scratch folder and clear decrypted copies; keep only the encrypted backup, its manifest and checksum.

**7. Recovery acceptance criteria (measurable; nothing measured yet)**

| # | Criterion | Result |
|---|---|---|
| 1 | Backup command exits 0 | **met** (`pg_dump` rc 0, 4 s) |
| 2 | `pg_restore --list` of the archive exits 0 and shows 29 tables | **met** (rc 0; 220 TOC entries, 29 table-data entries) |
| 3 | Uploads archive lists and extracts without error (or manifest empty and verified) | **met as a verified empty manifest** (0 files, 0 bytes; no archive exists) |
| 4 | SHA-256 of every artefact matches its recorded value (before and after transfer) | **met** (container hash = local hash; decrypted hash = clear hash; GPG file hash unchanged after the restore) |
| 5 | Restore into the scratch database exits 0 | **met** (`pg_restore` rc 0, 0.6 s) |
| 6 | Restored schema equals the source inventory (tables, indexes, constraints, sequences, enums, extensions) | **met** (counts and definition fingerprints equal; constraints compared order-independently, see limitations) |
| 7 | Row counts equal the manifest for every table (quiescent tables exactly) | **met** (all 29 tables, 23,278 rows, 0 differences) |
| 8 | Upload manifest verifies (count, bytes, checksums) | **met** (0 / 0 / none) |
| 9 | Database-to-file references resolve | **met vacuously** (0 evidence rows, 0 recording rows, 0 files) |
| 10 | Limitations documented; duration and failures recorded | **met** (below) |

No RPO or RTO is claimed. Measured durations from this exercise are listed below; they apply to a 12 MB database with no user data and say nothing about a populated system.

**8. Expected cost, volume and interruption**
* Data volume: about 12 MB database (a compressed dump is expected to be a few MB, unmeasured), 0 bytes of uploads.
* Method A (`railway ssh`): no new resource; negligible CPU and egress; **no service interruption** (a read-only snapshot on a 12 MB database). Method B adds a temporary public proxy: small or zero cost (**plan pricing not verified**) and a short exposure window. Local restore: no Railway cost.
* Time: minutes; the real figure will be measured.

**9. Owner approvals needed before any execution**
1. Approval to run the read-only pre-flight and the dump inside the Postgres service (method A), or, if A fails, a separate approval for a temporary TCP proxy and its deletion.
2. The backup storage location (outside Git, owner-controlled) and who holds the gpg passphrase.
3. Approval to create the scratch database on the local server and to use the scratch folder.
4. Approval to keep or delete the artefacts after the exercise.
5. Later, once real users exist: approval for any maintenance window needed for a coordinated database-plus-uploads recovery point.

**Risks and limitations:** the dump-streaming method is unproven; no cross-store consistency guarantee beyond the quiet-system observation; local disk space is very low; PITR and Railway volume backups are not enabled or verified; the observation will be stale by the time of execution; a successful `pg_dump` alone does not prove recoverability, which is why the restore verification is part of the acceptance criteria.

### 12c. Release gates by target (Phases C and D, 2026-11-13)

Targets: **Dev** (development), **Pilot** (small invited sideloaded Android pilot), **Play** (public Google Play MVP), **Commercial** (commercial production). P0 = required before that target, P1 = required before the specific feature is activated, P2 = recommended, DEF = deferred. Status column reflects evidence, not intent.

#### Original 12 go-live gates (G1-G12) - separate denominator from the 26 target gates and the 11 pilot gates

Requirements are reproduced **verbatim** from `production-readiness.md` (go-live gates table). "Source state" is that document's own label. "Acceptance result" is binary (PASS only when the whole requirement is evidenced). "Evidence status" uses the approved vocabulary. **Result: 0 of 12 PASS (0%).**

| Gate | Original requirement (verbatim) | Source state | Acceptance result | Evidence status | Evidence reference | Outstanding acceptance criteria | Related target gates (section 12c) |
|---|---|---|---|---|---|---|---|
| G1 | A user can receive a login code (at least one real OTP channel verified live) | FAIL (as written there) | **FAIL** | BLOCKED | section 6; section 7 (Resend row); `app/services/otp_service.py`; `tests/unit/test_otp_resend.py` (simulated provider only) | deploy the candidate; one owner-approved real Resend send; sign-in on staging; **F-01 and F-02 fixed first (login is not safe until then)** | 4, 11 |
| G2 | All credentials that ever appeared in Git history rotated; repositories private | FAIL (as written there) | **FAIL** | DEFERRED | R-01, R-02; section 12d (E2); repositories private (section 3, `infrastructure-setup.md` record) | rotate or revoke every credential that appeared in history (the Anthropic key is confirmed exposed); decide history handling | 1 |
| G3 | No known-vulnerable runtime dependency left unmitigated | PARTIAL (as written there) | **FAIL** | TESTED | section 10 (CI `pip-audit` step green on `15f5ea6`); `testing-and-qa.md` (local clean-install audit, 0 runtime advisories, historical) | same result on a Railway build of the candidate; Dart advisories only checked locally (OSV), the Flutter workflow has never run | - |
| G4 | CI green on GitHub at the release SHA for both repositories | FAIL (as written there) | **FAIL** | BUILT | section 10: backend run 43430344346 green on `15f5ea6` (verified by automated tests); `flutter-ci.yml` exists in the frontend repository (`815cbd9`, unpushed) and **has never run** | **both repositories** green at their release SHAs: a green Flutter workflow run on the pushed frontend release SHA is **unverified**; backend CI does not cover the F1 working tree | - |
| G5 | Production environment configured: real secrets, `TRUSTED_PROXIES` verified for the host, CORS, `ENVIRONMENT=production` startup checks pass | FAIL (as written there) | **FAIL** | PLANNED | section 9; R-03, R-04, R-05, R-06; no production environment exists | real secrets, measured `TRUSTED_PROXIES`, CORS and `ENVIRONMENT=production` startup checks on a production environment | 2 |
| G6 | Production database ready and backed up with a proven restore | PARTIAL (as written there) | **FAIL** | BUILDING | sections 12b and 12d; R-07 (manual backup and restores on staging data, verified locally) | a production database (Neon cutover not done), automated schedule, restore proven on the production target, uploads recovery | 9, 15 |
| G7 | Release APK/AAB signed with an upload key | FAIL (as written there) | **FAIL** | BLOCKED | R-15; build fails closed without a key (verified by 5 failing-build runs); no keystore exists | owner creates the upload keystore; signed build; fingerprint check with `verify_apk_signature.py` | 6 |
| G8 | Play Console compliance: permission declarations, data-safety form, privacy policy | FAIL (as written there) | **FAIL** | PLANNED | section 5a; R-28, R-29, R-30 | permission declarations, data-safety form, privacy policy | 7, 8, 12, 16, 21 |
| G9 | Real-provider verification of each shipped integration (Anthropic, Safe Browsing, URLhaus, Google, panic SMS/e-mail) | FAIL (as written there) | **FAIL** | BLOCKED | section 7; R-10, R-31, R-32; no live provider call has ever been made | one verified live call per shipped integration, each approved by the owner | 4, 17, 18, 20 |
| G10 | Device end-to-end on the release build (Android 10/13/15) including evidence retrieval and panic | FAIL (as written there) | **FAIL** | PLANNED | section 11 (not run, ever); emulator runs of 2026-10-06 are historical | device end-to-end on a signed release build (Android 10/13/15) including evidence retrieval and panic | 5 |
| G11 | Retention and DPDP basics: retention periods implemented, notice/consent captured, erasure path reachable in the UI | FAIL (as written there) | **FAIL** | PLANNED | R-13, R-28, R-30; FG-034; backend erasure tested | retention periods implemented, notice and consent captured, erasure reachable in the app UI | 7, 12, 22 |
| G12 | Monitoring and incident response: alerting that works, error mail transport, a named admin with individual identity | PARTIAL (as written there) | **FAIL** | BUILDING | section 5; R-09, R-27; named admin accounts and MFA TESTED locally, none created in any real environment; error alert e-mail is SMTP-only and switched off | working alerting, a created named admin account, incident contact and procedure | 3, 13, 14 |

Mapping notes: the F-01 and F-02 identity weaknesses (pilot gate 11, R-21, R-22) bear on G1 (a login code is only meaningful if the identifier it proves is bound to the right account) and block the private pilot independently of the other gates. G4 is **FAIL**, not partial: its wording covers both repositories and backend-only evidence does not satisfy it.

#### 26 target-specific release gates (gates 1-11 are the 11 private-pilot gates)
| # | Gate | Pilot | Play | Commercial | Status | Acceptance criterion |
|---|---|---|---|---|---|---|
| 1 | Rotate exposed credentials; never promote staging secrets | P0 | P0 | P0 | PLANNED (deferred by owner) | old values rejected by each provider; Railway holds new ones |
| 2 | Deploy the candidate with the Phase A variables and migrations | P0 | P0 | P0 | PLANNED | `/version` shows the expected revision, `/health` OK, variables set |
| 3 | First superadmin with MFA; legacy admin token off | P0 | P0 | P0 | PLANNED | MFA login works; legacy token returns 401 on staging |
| 4 | Live OTP login through Resend | P0 | P0 | P0 | BLOCKED (needs approved real send) | a real email arrives and signs in on staging |
| 5 | Client and backend tested as a pair on a device | P0 | P0 | P0 | PLANNED | register, login, refresh, logout and core flows on a signed APK |
| 6 | Signed release APK (upload keystore) | P0 | P0 | P0 | BLOCKED (no keystore) | fingerprint matches via `verify_apk_signature.py` |
| 7 | Privacy notice and consent (counsel-reviewed) | P0 | P0 | P0 | BUILDING (draft notice and consent screens built and tested in Phase G; not counsel-reviewed; not on a device) | shown before sign-up |
| 8 | Remove unused `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS` | P0 | P0 | P0 | BUILT (removed from the source manifest; source-level regression test passes; built-APK check pending) | absent from the built manifest, behaviour unchanged |
| 9 | Restore from the Drive copy; re-backup after migrations | P0 | P0 | P0 | BUILDING (E1 outcome RESTORE PARTIALLY VERIFIED; ownership/grants, source sequence values and row-level data unverified; re-backup after migrations pending) | restore passes using the downloaded copy **with all checks verified**, then a re-backup after migrations |
| 10 | Pilot features off by default (AI on real data, Safe Browsing, panic SMS, family minors, video call, recordings) | P0 | P1 | P1 | PLANNED | verified disabled on staging |
| 11 | **Identity binding fix (F-01/F-02)** | P0 | P0 | P0 | **BUILDING** | proof-of-concept attacks fail; the 12 mandatory tests and CI pass |
| 12 | In-app or web account deletion reachable by users | P2 | P0 | P0 | BUILT (in-app path and re-authenticated backend built and tested in Phase G; Play data-safety declaration and device check pending) | deletion path in the client; declared in Play data-safety |
| 13 | CERT-In: named contact, written 6-hour procedure, 180-day log plan | P1 | P0 | P0 | PLANNED | contact registered, procedure written, retention demonstrated |
| 14 | Minimal alerting (error mail is SMTP-only and off) | P1 | P0 | P0 | PLANNED | an alert reaches the owner on a test fault |
| 15 | Automated backup schedule (no Docker) | P2 | P1 | P0 | PLANNED | scheduled run plus a restore test |
| 16 | `QUERY_ALL_PACKAGES`, notification-access, VPN, media-projection declarations and disclosures | P1 | P1 | P1 | PLANNED | declared and disclosed before each feature ships |
| 17 | Safe Browsing commercial use | P1 | **BLOCKED** | **BLOCKED** | BLOCKED | separate agreement or Web Risk/alternative approved |
| 18 | AI processing of real user data (redaction, agreement, spend cap, kill switch) | P1 | P1 | P0 | BLOCKED (owner: disabled until reviewed) | controls exist and the owner approves |
| 19 | Family and kids flows (parental consent) | DEF | P1 | P1 | PLANNED | consent flow tested; counsel for DPDP s.9 from 13 May 2027 |
| 20 | Panic and guardian SMS (DLT registration, live verification) | P1 | P1 | P1 | BLOCKED (no SMS provider) | live provider verified |
| 21 | Play declarations and data-safety form | - | P0 | P0 | PLANNED | submitted |
| 22 | DPDP readiness before 13 May 2027 (notice, breach process, erasure, retention) | - | P1 | P0 | PLANNED | evidenced in app and process |
| 23 | Independent penetration test | DEF | P2 | P2 | PLANNED | report received |
| 24 | Shared rate limiter, antivirus scan, quotas | DEF | DEF | P2 | PLANNED | - |
| 25 | Cyber Warriors programme | DEF | DEF | P1 | DEFERRED | no client exists |
| 26 | Certificate pinning, SIEM, 24/7 SOC, multi-region, certifications | DEF | DEF | DEF | DEFERRED | no demonstrated reason |

**Pilot readiness = 0 of 11 accepted gates (0%).** A gate is accepted only when its whole acceptance criterion is evidenced; there is **no fractional credit** (and none is defined or approved). Gate 9 is not accepted because E1 was RESTORE PARTIALLY VERIFIED. This is a gate-acceptance measure, **not a general measure of engineering progress** (the Phase A hardening, CI, backups and the F1 work in progress are real progress that no pilot gate accepts yet). **Pilot decision: NO-GO today, and it remains NO-GO until F-01 and F-02 are remediated and independently tested.** Permissions are assessed individually: the four unused SMS and call-log permissions go (gate 8); `QUERY_ALL_PACKAGES` stays for the app scanner with disclosure; `READ_PHONE_STATE` and `READ_PHONE_NUMBERS` serve SIM integrity; notification access serves bank-OTP detection and needs prominent consent.

### 12d. Phase E: recovery from the Drive copy and credential remediation planning (2026-11-13)

**E1: restore from the Google Drive copy.** Outcome **RESTORE PARTIALLY VERIFIED**. The downloaded copy (302,986 bytes, SHA-256 matching the recorded manifest value) was decrypted (passphrase entered only in the local GnuPG dialog), its clear archive matched the manifest hash, and it restored into the new local database `secureshield_drive_restore_20261113` with `pg_restore` exit 0. 29 checks passed: 29 tables, revision `l7m8n9o0p1q2`, all row counts, constraints 29 PK / 22 FK / 3 unique validated, 76 indexes, 3 sequences, 11 enum types, extension list, definition fingerprints against the Phase B source evidence, data fingerprints against the first restore. **Not verified:** ownership and grants (restored with `--no-owner --no-acl`), sequence values and row-level data against the source, application-level queries. Report: `C:\SecureShield-Backups\secureshield-staging-20261113T140939Z.drive-restore-report.json`. The checksum quoted in the E1 instruction was mistyped (62 characters); the manifest value was used. The earlier scratch database is preserved. The first script run crashed on a coding bug after the restore had succeeded; verification was resumed read-only without restoring again. **Backup files (re-verified in the final correction pass, 2026-11-13):** the encrypted backup exists as **two** files, both 302,986 bytes with SHA-256 `c07c36fa3676eefe...` equal to the recorded value in `secureshield-staging-20261113T140939Z.dump.gpg.sha256`: `C:\SecureShield-Backups\secureshield-staging-20261113T140939Z.dump.gpg` and `C:\SecureShield-Backups\verification-download\secureshield-staging-20261113T140939Z.dump.gpg`. The top-level file was observed **absent** during the Phase D and E1 checks and **present** at this pass. Both files carry the same modification time (20:31:59), whereas the manifest and checksum sidecar were written at 19:41:28, so the top-level file is **not proven to be the original creation file** (it may be a copy of the download); matching hashes prove identical content, not provenance. E1 restored from the `verification-download` file only. Neither file was opened, moved, decrypted or changed in this pass; the Drive-side copy and the Bitwarden passphrase remain owner-reported and cannot be checked from here. Checksum verification is not a restore; only E1 is a restore from the downloaded copy. The Drive-side copy itself cannot be checked from here.

**E2: credential exposure and remediation plan (planning only; nothing rotated, revoked or changed).** Method: staging and local values compared in memory against all 99 commits of both repositories; output was names, booleans, commits and paths only.

| Credential (names only) | Evidence | Plan |
|---|---|---|
| `ANTHROPIC_API_KEY` | **current staging value verbatim in public history** (commit `6465d52`, `.env`, on `origin/main` and both staging branches): confirmed exposed; active status unknown | revoke at the provider, unset on Railway; AI stays disabled |
| `SMTP_USER`, `SMTP_PASSWORD` | user identifier in history; current password not in history but **active** (SMTP login worked locally) | revoke the Gmail app password; inert placeholders (the settings are required, so they cannot be deleted); `SMTP_FALLBACK_ENABLED=false` |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` | SID in history; current token not in history; token **rejected** (20003); startup makes a live lookup when the SID starts with `AC` | non-`AC` placeholder SID; delete the old token; do not enable Twilio |
| `GOOGLE_SAFE_BROWSING_API_KEY` | not in history; never called live | revoke or restrict, unset; feature stays BLOCKED |
| `SECRET_KEY`, `ADMIN_TOKEN` | **current values not in history**; `ADMIN_LEGACY_TOKEN_ENABLED=false` | rotate `SECRET_KEY` before the pilot (free now: staging has no users, admins or pending OTPs); `ADMIN_TOKEN` can stay (dormant) |
| `DATABASE_URL`, `MIGRATOR_DATABASE_URL`, `APP_DB_PASSWORD`, `MIGRATOR_DB_PASSWORD` | not in history; dedicated non-superuser roles; internal host | leave unchanged |
| `RESEND_API_KEY` | not in history; sending-only, domain-restricted | leave unchanged |
| `FILE_ENCRYPTION_KEY` | unset; zero encrypted files exist | owner generates and escrows a new key, then `FILE_ENCRYPTION_REQUIRED=true` |
| Staging versus local | staging Anthropic, SMTP, Twilio and Safe Browsing values equal the developer's local `.env` and backups | separate dev, staging and production secrets |

Order: disable AI and Safe Browsing, revoke SMTP and Twilio, rotate `SECRET_KEY`, set the file key, clean local env files, then deploy (separate approval). Set all Railway variables with deploys skipped, because any variable change redeploys the connected commit. Unknowns: whether the Anthropic key was auto-revoked, whether older historical values still authenticate, whether any secret leaked outside Git (the repository was public for up to about eight months), the Railway Postgres superuser credentials.

### 12e. Phases F and F1: authorisation audit and identity binding (2026-11-13)

**Phase F (read-only authorisation audit).** 130 routes; 88 require a signed-in user; admin routes use server-side role ranks. **No BOLA or IDOR was found**: evidence, recordings, alerts, devices, app and Wi-Fi scans, link scans, scam calls, contacts, family alert access, reports, AI history, admin and warrior admin are scoped to the authenticated user (helpers such as `_owned`, `user_id == current_user.id` predicates, consent checks). Two weaknesses were **confirmed by proof of concept** (synthetic accounts, disposable database, temporary checkout):

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| F-01 | High, CONFIRMED | `POST /auth/register` creates a user with an unverified phone and email, stores one OTP for both and delivers the same code to both; either identifier verifies. An attacker registering with their own email and a victim's phone becomes the account the victim later logs into | `app/routers/auth.py:264-345`, `548-575` at `15f5ea6`; proof of concept passed |
| F-02 | High, CONFIRMED | `PATCH /auth/me` sets the email with no verification; the victim's later email OTP login lands in the attacker's row | `auth.py:825-850`; proof of concept passed; control case (existing account email) blocked |
| (Google) | High, code-confirmed, not executed | Google sign-in resolves by email regardless of verification state and stores no subject | `auth.py:672-676` |
| F-03 | Low | family invite response returns `member_user_id` before consent | `family.py:75-108`, `schemas/family.py:22` |
| F-04 | Low | community upvote has no per-user dedupe; malformed id gives 500 | `community_scam.py:437-452` |
| F-05 | Low | email collision on `PATCH /auth/me` returns a generic 500 and the error path hits `PendingRollbackError` | proof-of-concept control output |
| F-06, F-07 | Info | guardian alerts expose the full alert shape; recording share link is a 24-hour bearer URL (by design) | `family.py:253-259`; `recordings.py:29,204-219` |

Existing tests prove owner-only access, cross-user denial and consent for evidence, recordings, devices, alerts, contacts, family and account deletion. **Missing tests:** identifier squatting (register, email change, Google), email-collision 409, upvote dedupe and malformed id, a route-wide authentication check, guardian field allowlist, cross-user checks for reports and community feeds.

**Phase F1 (identity binding), owner-approved architecture, status BUILDING.** Approved decisions: registration requires both email and phone; email is verified first and creates the account, phone is verified separately and phone login stays disabled until then; unverified identifiers never authenticate or resolve an account; legacy accounts are preserved and nothing is auto-marked verified; ownership of a previously unverified identifier may be proven with explicit safeguards (no merge, no data transfer); `PATCH /auth/me` rejects email changes; separate email-change start and confirm endpoints, old email active until confirmed; Google sign-in with a unique `google_sub` and safe linking; backend and frontend as one coordinated feature. **Stage B state (uncommitted, nothing committed, pushed, migrated or deployed):** written so far: model changes, additive migration `v7w8x9y0z1a2`, bound-challenge service, pending-registration registration and verify endpoints, verified-only login, Google linking rules, phone-add, email-change and claim-release endpoints, erasure additions (files listed in section 3). Not done: adapting the 23 failing existing tests, the 12 mandatory security tests, the Flutter implementation and tests, the reviewed SQL migration script, a full test run, CI. Owner rule applied: the migration does not delete existing OTPs (legacy OTP rows are ignored). Dependency: **phone verification needs an SMS provider** (R-26). Work paused on the owner's instruction for this documentation pass.

### 12f. Phase G: privacy, consent and Android compliance foundation (2026-11-14)

Status **BUILT / TESTED in code, uncommitted, not on a device, not counsel-reviewed.** Nothing was committed, pushed, deployed or executed against a database outside the disposable local test database (its harness applies the Alembic chain, as in Phase F1).

**What the application collects (from code review of models, routers and Flutter features).**

| Category | Data | Where processed | Third party |
|---|---|---|---|
| Account and identity | name, email (verified), phone (optional, verified separately), address, Google subject and email, consent records | backend database | Resend (email), Google (sign-in) |
| Device | device token, name, platform, OS and app version, source IP | backend | none |
| Installed apps | package names and permissions (when a scan is run) | backend; scoring also on device | none |
| Links and QR | scanned URL and result | backend; QR decode on device | Google Safe Browsing and abuse.ch URLhaus (links), when enabled; not yet verified live |
| Messages | text the user submits to the analyser or AI coach | backend | none while external AI is DISABLED (Phase 0 kill switch); Anthropic only if the owner later enables it, after per-user consent enforcement exists |
| Notifications and SMS | bank-OTP alerts read notifications on the device when the user enables them; the app does not read the SMS inbox | device | none |
| Evidence and recordings | files (encrypted at rest), share tokens | backend volume | Railway (hosting) |
| Location | only when a feature that needs it is used and Android permission is granted | backend when attached to evidence or a panic alert | none |
| Family and emergency contacts | third-party names, phones, emails; invitations need the invitee to accept | backend | none |
| Wi-Fi and network activity | scan results, destination IPs from the optional local VPN monitor | backend | none |
| Logs | error logs (detached from the account on deletion) | backend | none; no analytics or advertising SDK is present in `pubspec.yaml` |

**Files changed (backend).** `app/models/user_consent.py` (new), `app/models/pending_registration.py`, `app/models/__init__.py`, `app/services/consent.py` (new), `app/services/identity.py` (purpose `delete_account`, `reauth_channel`), `app/services/account_erasure.py` (erases consent rows), `app/routers/privacy.py` (new), `app/routers/auth.py` (register, register/verify, google, delete), `app/schemas/auth.py`, `app/main.py`, `alembic/versions/w8x9y0z1a2b3_consent_records.py` (new), `docs/audit/g_consent_review.sql` (new), tests: `test_consent_and_deletion_api.py` (new, 23 tests), `conftest.py` (`delete_body` helper) and adaptation of the existing registration, deletion and Google tests.

**Files changed (Flutter).** New: `lib/features/privacy/` (`privacy_content.dart`, `privacy_api.dart`, `consent_choices.dart`, `consent_gate.dart`, `screens/consent_screen.dart`, `privacy_notice_screen.dart`, `privacy_settings_screen.dart`, `delete_account_screen.dart`). Changed: `auth_provider.dart` (consent on register and Google, `clearAllLocalData`, injectable Google functions), `register_screen.dart`, `phone_screen.dart`, `router.dart`, `main.dart`, `settings_screen.dart`, `consent_manager_screen.dart` (SMS item removed), `AndroidManifest.xml`. Tests: `test/features/privacy/` (3 files), `test/android_manifest_permissions_test.dart`, additions to `auth_flows_test.dart` and `google_linking_test.dart`.

**API changes (breaking for any client that does not send the new fields; no released client exists).**

| Endpoint | Change |
|---|---|
| `POST /auth/register` | `consent` object required (terms and privacy versions; optional `ai_processing`). Missing: 422 with `X-Consent-Error: consent_required`; stale version: 409 with `X-Consent-Error: stale_version` |
| `POST /auth/register/verify` | copies the consent to `user_consents` when the account is created; a registration with no consent on record creates nothing |
| `POST /auth/google` | `consent` required only when the sign-in would create an account; otherwise unchanged |
| `DELETE /auth/me` | body is now `{confirm: "DELETE", code}`; the code comes from the new start endpoint, is bound to the account and to the purpose, and is consumed in the same transaction as the erasure (a failed erasure can be retried). An account with no verified email or phone gets 409 |
| `POST /auth/me/delete/start` | new: sends the code to the verified email (else verified phone); nothing is deleted |
| `GET /auth/consents`, `PUT /auth/consents` | new: newest decision per purpose; optional purposes can be granted and withdrawn (append-only history); the two mandatory acknowledgements cannot be withdrawn while the account exists |

**Database.** One additive migration `w8x9y0z1a2b3` (down revision `v7w8x9y0z1a2`): table `user_consents` (user, purpose, version, granted, source, time; cascade on user delete) and four nullable consent columns on `pending_registrations`. Reviewed standalone SQL with preconditions, verification and rollback notes: `docs/audit/g_consent_review.sql`. **Neither was executed on any application database.** Existing users have no consent rows; the app asks them to accept on next sign-in (a client gate reading the server state; fail-open when the server cannot be reached).

**Permissions.**

| Permission | Decision | Reason and consequence |
|---|---|---|
| `READ_SMS`, `RECEIVE_SMS` | **removed** | no code reads the inbox (no `content://sms`, no SMS receiver, no SMS plugin); the fake-bank-SMS classifier works on text the user pastes; the consent manager asked for the SMS group with a reason ("read SMS to detect OTPs") that no feature delivers, so that item is removed. No functional loss. Play treats these as restricted |
| `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS` | **removed** | referenced only in lists that classify OTHER apps (`MainActivity.kt`, `AppInstallAnalyzer.kt`, `app_risk_engine.dart`); no call-log read, no outgoing-call receiver. `PROCESS_OUTGOING_CALLS` is also deprecated by Android. No functional loss |
| `READ_PHONE_STATE` | retained | call-state detection for recording and SIM-change detection |
| `READ_PHONE_NUMBERS` | retained, **review** | no direct use found in the Kotlin code, but not proven unused on a device (SIM information may need it); verify on a device before removal |
| `PACKAGE_USAGE_STATS` | retained, **review** | special access granted by the user; confirm the app monitor needs it |
| `QUERY_ALL_PACKAGES` | retained | core to the app and clone scanners; **needs a Play declaration**; fallback if rejected: narrow `<queries>` and a user-initiated scan |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | retained | user-granted special access for bank-OTP alerts; needs prominent in-app disclosure; keep optional |
| `BIND_VPN_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`, `FOREGROUND_SERVICE_SPECIAL_USE` | retained, **owner decision** | Play restricts VPN and system-exempted foreground services to specific uses; a local-only monitor may not qualify. Options: submit the declaration, or defer the VPN monitor for the Play MVP |
| `FOREGROUND_SERVICE_MEDIA_PROJECTION` | retained | user-started screen recording; foreground-service declaration needed |
| camera, microphone, location, media, notifications, biometric, Wi-Fi, boot, vibrate, wake lock | retained | each tied to a feature; runtime permissions are requested one at a time with a reason, not bundled into the consent |

Play policy statements above come from the team's earlier review and from general knowledge; they were not re-verified against the current Play Console in this phase (UNVERIFIED).

**Tests.** Backend full suite: 1305 passed, 0 failed (local disposable test database, 9m11s). Flutter full suite: 180 passed, 0 failed. `ruff check` clean; `ruff format --check` clean; `flutter analyze` no issues. Covered: consent required, stale versions, persistence per purpose with version, user and time, optional versus mandatory separation, withdrawal and history, cross-user isolation, Google sign-up consent, deletion without or with a wrong, replayed, other-account or login-purpose code, no verified identifier, rollback and retry, rate limit, local data cleanup, manifest permission allow-list and restricted-permission regression, notice content (names providers, no "never shared" claim), consent screen accessibility basics, deletion flow states (loading, failure, retry, confirmed success only).

**Not tested.** Android device or emulator; TalkBack on a real device; the built APK manifest; real email delivery of the deletion code; Google sign-in against Google; the SQL script and the migration on any application database; screen-reader reading order beyond the semantics assertions.

**Outstanding legal questions (for counsel).** Adequacy of the notice and consent under the SPDI Rules now and the DPDP duties from 13 May 2027; whether consent records should be kept after erasure (they are erased with the account today); retention periods for data, logs and backups; the operator's legal name, grievance contact and cross-border transfers (Resend, Anthropic, Railway region); rules for minors in the family features; notice language coverage beyond English; whether the optional AI consent is specific enough; breach-notification process.

**Google Play declarations still needed.** `QUERY_ALL_PACKAGES`; VpnService and foreground-service types (systemExempted, specialUse, mediaProjection); notification-listener disclosure; permissions declaration form; data-safety form (including account deletion URL or in-app path); privacy policy URL.

**Manual Android test steps (not yet run).** (1) Fresh install: open Register; the consent screen appears first; Continue stays disabled until both required boxes are ticked; the AI switch is off. (2) Read the notice from the consent screen and return. (3) Register with email; after verifying, the app continues to phone verification. (4) Settings > Privacy and data: toggle the AI choice and confirm it persists after restarting the app. (5) Delete account: tick "I understand", request the code, confirm it arrives by email only, enter a wrong code (error, account intact), enter the right code and DELETE (signed out, welcome screen), then confirm sign-in with the same email fails and registration starts fresh. (6) Install the release build and inspect the merged manifest: none of `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS`. (7) Turn on TalkBack and traverse the consent screen: headings announced, checkboxes announced with their state. (8) Existing account with no consent record: sign in; the update screen appears before the dashboard.

**Scorecard.** `feature-completion-matrix.md` and the scorecard figures were not re-scored in Phase G; the next scoring pass will include these items. Pilot acceptance stays **0 of 11** (gates 7 and 8 need counsel review and a built-APK check).


### 12g. Phase 0: development baseline and AI containment (2026-11-14)

**Defect contained.** The Phase G review proved that every AI endpoint sent user content to the provider regardless of the user's consent record (G-01) while the notice said otherwise (G-02). Decision: contain now, build per-user consent enforcement with the AI module.

**What changed.** New `app/services/ai_gate.py`: `AI_PROCESSING_ENABLED` is read on every call (environment, then the backend `.env`), is a plain string so a malformed value cannot raise, and only `1/true/yes/on` enable it; unset, empty, `false` or garbage mean disabled; `ANTHROPIC_API_KEY` never enables anything. It is enforced in `ai_service.get_client`, `get_async_client` and `_create_message` (the one boundary every provider call uses), so a patched or new caller cannot bypass it. Endpoint behaviour while disabled: coach chat and screenshot extraction return **503** with `X-AI-Status: disabled` and a plain message (nothing is stored or sent); message analysis and job-offer checks return the local pattern-engine result; complaint e-mail and FIR draft return their local templates (the FIR note says AI is disabled); security tips use the defaults. The Flutter coach screen shows a specific "switched off" message for that header. Notice, consent screen and settings text now say external AI processing is currently disabled and that the optional choice only records a preference.

**Not done (by decision).** Per-user consent enforcement, redaction, spend cap and the per-purpose gate remain for the AI module; consent records are unchanged. The notice version was not bumped (no real consent has been collected); bump it before the first real consent is collected. `.env.example` (user-owned) was not edited: the variable is documented here and in `ai_gate.py`. No Railway or production variable was changed or read. Do not set `AI_PROCESSING_ENABLED=true` on any environment until the AI module's consent enforcement exists.

**Tests.** `tests/integration/test_ai_containment_api.py` (35 tests, recording fakes only): switch absent, empty, false, garbage and true values; key present but switch off; true with no credential; true with a credential against the mock only; the boundary refuses even with a swapped client; every known AI path while disabled (chat, complaint e-mail, message analysis, job offer, screenshot, FIR, FIR stream, daily report) with zero provider constructions or calls; a recorded consent does not open the switch; a static guard that no module other than the gateway imports the SDK. Existing AI tests enable the switch explicitly against their fake provider.


### 12h. Phase 1A: F19 app monitor service (2026-11-14)

**Finding confirmed.** `MainActivity.kt` started `AppMonitorService` but the manifest had no `<service>` entry, so Android could not start it; `startMonitor` still answered `true`, so the screen could claim monitoring that never ran (G-07).

**Change.** The service is declared: explicit class, `exported=false`, `foregroundServiceType="specialUse"` with the required subtype property; it needs only `FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_SPECIAL_USE`, both already declared (no permission added). The service now uses `START_NOT_STICKY` (after a process kill monitoring is off until the user turns it on; nothing restarts silently), never registers a second receiver on a duplicate start, rolls back and stops itself if the foreground promotion is refused, registers its package receiver `NOT_EXPORTED`, and posts risky-app warnings on a separate high-importance channel. `MainActivity` refuses to start without the notification permission on Android 13+ (the persistent notice is the disclosure) and answers only after the service itself reports running. Flutter reads the real state on open and on every app resume, shows a typed reason for each failure, offers app settings when notifications are denied, and shows a disclosure card; a failed sync can no longer leave the screen stuck.

**Evidence.** `MonitorLifecycleTest` 11 JVM tests pass (Gradle `:app:testDebugUnitTest`, offline; the app's Kotlin compiled). Flutter: `app_monitor_test.dart` 17 tests (channel and screen), manifest service tests (declared once, not exported, every foreground service typed, every Kotlin `Service` subclass declared). `flutter build apk --debug` succeeded; the merged debug manifest lists `AppMonitorService` (`exported=false`, `specialUse`), still has no `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG` or `PROCESS_OUTGOING_CALLS`, and shows the plugin-added `REQUEST_DELETE_PACKAGES` (open decision from the Phase G review).

**Not done / limits.** No device or emulator run (Android 10, 13 and 15 behaviour is reasoned, not observed). Events that arrive while the app UI is closed are not queued for the history upload: the warning notification and the elderly-protection check still run. Play needs a foreground-service `specialUse` declaration. Status: F19 FUNCTIONALLY COMPLETE (code), not INTEGRATION TESTED.

**Stage 1 (receiver hardening and permission ownership, 2026-11-14, uncommitted).** `PackageInstallReceiver` is `exported=false` (PACKAGE_ADDED is a protected system broadcast and still reaches it) and acts only while the single persisted preference `monitoring_enabled` (native `MonitorPreference`, `MonitorPolicy.kt`) is true; a missing, wrong-typed or unreadable value means OFF. The preference is written true only after the service confirms it started and false by any explicit stop (screen, notification Stop, failed restore); it survives a process kill so background installs are still handled, and the app restores the service on open or turns the preference off. While the service runs the receiver stays silent (one notification per install). `REQUEST_DELETE_PACKAGES` is now declared in the source manifest (both ACTION_DELETE uninstall flows need it) and in the reviewed allow-list; the unused `installed_apps` plugin (the previous source of the permission) was removed after confirming no import, no dependent package and no build reference. Evidence: Kotlin `MonitorPolicyTest` 12 and `MonitorLifecycleTest` 11 pass; Flutter 213 pass; `flutter analyze` clean; debug APK built; the merged manifest shows the receiver non-exported, the permission now sourced from the app manifest, `QUERY_ALL_PACKAGES` kept, and no SMS or call-log permission. Not done: no device run; native event queue and deferred upload (Stage 2); foreground-service decision.

**Stage 1B (notification visibility, 2026-11-14, uncommitted).** Monitoring may run only while the user can see it: `MonitorPolicy.isVisible` requires the app-level notification state to be on and the App Install Monitor channel to exist and not be `IMPORTANCE_NONE` (before Android 8 only the app switch); any unknown or failed check means not visible. It is evaluated on service start (before the lifecycle flag is set, so nothing can observe a refused start as running), on every package event in both the service and the manifest receiver (so a revocation is noticed when the next event arrives even though the app was not running), mid-analysis, and on every app resume (`enforceVisibility`). When monitoring is ON but not visible: the preference is cleared once, the service is stopped, nothing is analysed and no guardian alert is raised, and the screen shows a paused message with an app-settings button. Repeated checks do not repeat the stop or the preference write (writes are skipped when unchanged); `onDestroy` never clears the preference. Android cannot tell an app that is not running that a permission or channel changed, so detection is lazy by design (next event or next resume). Evidence: Kotlin `MonitorPolicyTest` 22 and `MonitorLifecycleTest` 11 pass; Flutter 222 pass; `flutter analyze` clean; debug APK built; merged manifest unchanged (34 permissions, receiver and service not exported, no SMS or call-log permission). Not done: no device run; the in-service `NotificationVisibility` and receiver code paths are covered by the pure policy tests and source-level tests, not by an instrumented test.

**Stage 2A (backend, 2026-11-14, uncommitted).** `POST /app-monitor/sync` is now idempotent and race-safe (nullable `client_event_id` and `occurred_at`, two partial unique indexes, insert-or-ignore), returns ordered per-event `outcomes` (created, duplicate, rejected; a malformed event no longer fails the batch; `synced` and `results` keep their meaning), no longer drops a second update of the same app, and is rate-limited per user (429 with Retry-After). Guardian alerts go through a durable outbox (`guardian_alert_outbox`, `guardian_alert_deliveries`): unique per event, atomic claim with `FOR UPDATE SKIP LOCKED` and a lease, compare-and-set results, per-channel progress so a retry never repeats a channel that succeeded, exponential backoff, 7-day expiry, a durable hourly cap, live-config re-check at delivery, independent of the history record. Delivery is at-least-once; exactly-once against an external provider is not claimed. A periodic worker starts at application startup (`GUARDIAN_OUTBOX_POLL_SECONDS`, default 30, 0 disables) in addition to a best-effort immediate run. Migration `x9y0z1a2b3c4` and `docs/audit/f19_stage2a_review.sql` are prepared and NOT executed (third pending migration). **Stage 2A final corrections (2026-11-14, uncommitted).** (1) Consent: a guardian alert is delivered only if the account holder authorised it against the current disclosure version (`GUARDIAN_NOTICE_VERSION` 2026-11-14; a stale or missing version is refused with 409 and `X-Consent-Error: stale_guardian_notice`) AND the guardian has verified the channel (e-mail: a code sent to the guardian; `POST /elderly/guardian/verify/start` and `/confirm`). SMS verification is unavailable (no provider), so only e-mail can be delivered. Changing a guardian contact withdraws authorisation and that channel's verification; withdrawing authorisation clears everything; delivery re-checks both at send time. Existing guardian settings become unauthorised and unverified after the migration, so alerts stop until the holder re-authorises and the guardian verifies (deliberate behaviour change). (2) Scoring: eligibility uses only the server-calculated score (`compute_risk`) on both `/app-monitor/sync` and the legacy `/elderly/guardian-alert`; any device-reported score is ignored. The legacy endpoint uses the stored server score of the newest synced event for that package, else a clone-analysis-only score. (3) Retention: terminal outbox rows (sent, skipped, expired, failed) are purged 90 days after `updated_at`, delivery audit with them (cascade); checked hourly by the worker; in-flight rows are never purged by age. (4) The legacy `/elderly/guardian-alert` now stores the alert in the durable outbox (one per package per hour; returns `queued` or `skipped`) and the worker delivers it, with retry. (5) Worker attempts never exceed `max_attempts` (an exhausted row becomes `failed`, code `attempts_exhausted`). (6) `ix_guardian_outbox_event_id` added; the SQL script now verifies the runtime role's DML privileges (`secureshield_app`). Migration `x9y0z1a2b3c4` was corrected in place (still unexecuted on any application database): it also adds six nullable `elderly_configs` columns; the offline upgrade SQL matches `f19_stage2a_review.sql` statement for statement. Known limits: the Flutter privacy notice has no guardian-alert disclosure yet (Flutter untouched; required before release); no guardian opt-out or unsubscribe; e-mail only; the in-memory 10 per hour limiter on the legacy endpoint is kept; the worker runs in-process; the lease-branch index (L4) is deferred. Evidence: backend full suite 1411 passed; Ruff clean; new `test_guardian_authorisation_api.py`; mutation checks (no lease compare-and-set, resent channels, no SKIP LOCKED) each caught in the first Stage 2A pass. Not done: Android, Flutter and WorkManager (Stage 2B/2C); no device or real provider test; SMS has no provider, so guardian delivery is e-mail only in practice.


## 13. Security Risk Register

Owner "Owner" = repository owner (ravishori). Closure evidence is always "to be produced" unless stated. **No risk below is resolved.** `S-xx` = ID in `security-audit.md`; `FG-xxx` = gaps register.

| ID | Description | Severity | Component | Status | Mitigation | Owner | Required approval | Closure evidence | Evidence reference |
|---|---|---|---|---|---|---|---|---|---|
| R-01 | Credentials that appeared in Git history (Anthropic key, Twilio SID/token, Gmail app password, Safe Browsing, Azure Translator, local DB password, placeholder `SECRET_KEY`, committed `.env`, personal-data logs) await rotation. Repos now private; history not rewritten (S-01) | Critical | Repos, all providers | **OPEN - rotation DEFERRED by owner. E2 (2026-11-13): the CURRENT Anthropic key value is verbatim in public history (commit `6465d52`): CONFIRMED exposed. Current Twilio SID and SMTP user identifiers are also in history; the current SMTP password, Twilio token, Safe Browsing key, `SECRET_KEY`, `ADMIN_TOKEN` and database passwords were NOT found in history** | Repos private; never deploy known-compromised creds to production; rotate before any production use | Owner | Owner (rotation timing) | new credentials issued and old ones revoked at each provider; history decision recorded | section 12d (E2 scan); `security-audit.md` S-01; commit `6465d52` (`.env` in history). Level: verified locally (history search); no provider-side check |
| R-02 | Staging Railway variables still hold the exposed `SECRET_KEY`, `ADMIN_TOKEN` and old provider keys | High | Railway staging | **OPEN - DEFERRED. E2: staging `SECRET_KEY` and `ADMIN_TOKEN` are not in history (exposure not evidenced); staging Anthropic, SMTP, Twilio and Safe Browsing values equal the local `.env` and its backups** | Staging holds no user data; legacy admin token disabled; do not reuse in production | Owner | Owner | variable audit after rotation | section 12d (E2); `security-audit.md`; Railway variable names read-only 2026-11-13 |
| R-03 | `FILE_ENCRYPTION_KEY` not set: evidence/recordings stored in plaintext; before Phase 7 a missing key silently stored plaintext (S-11) | High | `file_crypto`, uploads | **OPEN** (code gate TESTED, committed in `15f5ea6`, CI green; not deployed; staging key not set) | `FILE_ENCRYPTION_REQUIRED` + startup validation; owner generates and escrows a 32-byte urlsafe-base64 key | Owner (key); dev (tests) | Owner approves key creation | local tests for missing/malformed/valid key pass (done, see section 4); still needed: key set in staging; startup fails without it; round-trip upload verified on staging | section 12a; `app/services/file_crypto.py`, `app/startup_checks.py` at `15f5ea6`; `tests/unit/test_file_encryption_required.py`; CI run 43430344346 |
| R-04 | SMTP fallback would use the exposed SMTP credentials if `SMTP_HOST` is set | High | OTP, notifications, error mail | **OPEN** (switch TESTED incl. error-alert and new-device paths, committed in `15f5ea6`, CI green; not deployed; variable not set on staging) | `SMTP_FALLBACK_ENABLED=false` on staging; Resend only | Dev / Owner | Owner sets variable | all three SMTP paths gated by passing tests (done locally); still needed: variable set on staging + no SMTP connection in staging logs | section 12a; `app/delivery_settings.py`; `tests/unit/test_smtp_fallback_switch.py`, `tests/unit/test_email_provider_failures.py`; CI run 43430344346 |
| R-05 | `TRUSTED_PROXIES` not set; only one observed Railway proxy address (`100.64.0.1`) (FG-167) | Medium | client-IP, rate limits, HTTPS detection | **OPEN** (code TESTED, committed in `15f5ea6`, CI green; not deployed; staging value unmeasured) | Measure real proxy range on staging, set variable | Owner/ops | Owner | measured range recorded; startup check passes with `TRUST_PROXY_TLS` | section 12a; `app/services/client_ip.py`; `tests/unit/test_client_ip_request.py`, `tests/integration/test_client_ip_endpoint_limits.py`; **gap:** staging proxy range unmeasured |
| R-06 | CORS fell back to `*` outside production (including staging) | Medium | API | **OPEN** (code fix TESTED, committed in `15f5ea6`, CI green; takes effect only after deploy) | Set `CORS_ALLOWED_ORIGINS` for staging/production | Owner/ops | Owner | variable set; preflight check from an allowed and a disallowed origin | section 12a; `app/cors_policy.py`; `tests/unit/test_cors_policy.py` |
| R-07 | No staging database backup and no proven restore (`../BACKUP_AND_RECOVERY.md`) | High | Postgres | **PARTLY MITIGATED**: one manual backup taken, restored in isolation and copied off-machine (Google Drive, hash-verified) on 2026-11-13 (section 12b); still open: restore from the Drive copy, schedule, retention, uploads, populated-data restore, confirmation that the plaintext passphrase file is gone | Take backup before migrations; rehearse restore to a scratch DB | Owner/ops | Owner approves backup/restore action | backup artefact id + successful restore with row counts matching | sections 12b and 12d; local verification reports under `C:\SecureShield-Backups` |
| R-08 | 10 pending migration files (9 committed plus the uncommitted, not yet reviewed F1 revision `v7w8x9y0z1a2`) have never been applied to a real database; staging is at `l7m8n9o0p1q2` (read-only probe 2026-11-13); four of the committed nine are destructive on non-empty tables (section 8) | High | Alembic | **OPEN** | Apply only after backup, on staging, in a controlled deploy; tables empty at last probe | Owner + dev | **Explicit owner approval** | revision equals the approved head (`u6v7w8x9y0z1`, or `v7w8x9y0z1a2` if F1 is committed and approved), row-count probe unchanged, smoke tests pass | section 8 (migration risk register); `../MIGRATION_SAFETY_REVIEW.md`; `alembic/versions/` |
| R-09 | Admin MFA and initial superadmin not provisioned in any real environment; legacy token break-glass default `true` in code (S-06) | High | Admin console | **OPEN** | Create first superadmin after migration (CLI), enrol MFA; keep legacy token off | Owner/ops | Owner | admin login with MFA on staging; legacy token returns 401 on staging | `security-audit.md` S-06; `tests/integration/test_admin_accounts_api.py`; **gap:** no admin created in any real environment |
| R-10 | No live OTP channel proven; Twilio rejected (S-03) | High | Auth | **BLOCKED** | Deploy Resend build; one approved test send | Owner | Owner approves each real send | one real OTP received and used to sign in on staging; provider-failure test | section 6; `p1-closure-report.md`; **gap:** no live send has ever been made |
| R-11 | Railway start command and Python version unverified; IaC and Railway may disagree (no `startCommand` observed in Railway) | Medium | Railway service | **OPEN** | Read-only verification in Railway; align with `.railway/railway.ts` and `.python-version` | Dev/Owner | Owner for any change | deployment log shows expected start command and Python 3.11 | `.railway/railway.ts`; section 9; **gap:** the Railway start command was not read |
| R-12 | Rate limiter is in-memory per process; one replica required (S-10) | Medium | Middleware | **OPEN** | Keep single replica; Redis store before scaling | Dev | - | shared-store limiter tested | `security-audit.md` S-10; `app/middleware/rate_limiter.py` |
| R-13 | DPDP gaps: retention, notice, consent, minors, cross-border processing (S-07, FG-034) | High | Product/legal | **OPEN** | Owner decisions + implementation | Owner/legal | Owner | retention jobs tested; notices in app | section 5a; `security-audit.md` S-07; `../FG-034_LOG_RETENTION_AUDIT.md` |
| R-14 | Google Play restricted permissions (S-05) | High | Android | **OPEN** | Minimise permissions; declarations | Owner | Owner | Play review outcome | section 5a; `security-audit.md` S-05; `flutter_app/android/app/src/main/AndroidManifest.xml` |
| R-15 | No Android upload keystore; unsigned/uncertain release (S-04) | High | Android signing | **BLOCKED** | Build fails without a key (tested); owner creates keystore | Owner | Owner | signed APK/AAB + `verify_apk_signature.py` fingerprint match | section 12c gate 6 and G7; `security-audit.md` S-04; `flutter_app/android/app/build.gradle.kts` |
| R-16 | `deploy-staging.yml` previously accepted `staging/*` refs (included the CI candidate); required environment reviewers not set | Medium | GitHub Actions | **OPEN - code fix committed (`e367eb6`) and CI-green** | Allowed ref narrowed to exactly `staging/railway-snapshot`; reviewers still to configure; no `RAILWAY_TOKEN` stored | Dev/Owner | Owner (reviewers, secrets) | guard tested locally and in CI (done); closure still needs a real dispatch from a candidate ref to be rejected on GitHub, and reviewers configured | section 10; `.github/workflows/deploy-staging.yml`; `tests/unit/test_deploy_workflow_refs.py`; CI run 43430344346 |
| R-17 | Railway auto-deploys on any push to `staging/railway-snapshot`; a premature push would deploy and run the pending migrations (9 committed; 10 if the F1 revision were committed) | High | Railway source | **OPEN (controlled)** | CI-only candidate first; push the Railway branch only on approval | Dev/Owner | Owner | documented push approval + backup | section 9; Railway source read-only 2026-11-13; `.railway/railway.ts` |
| R-18 | Dependency state shown only locally; Railway/CI builds of upgraded pins never run (S-02) | Medium | Supply chain | **OPEN** | CI pip-audit run; Railway build | Dev | - | green CI run with pip-audit | section 11; CI run 43430344346; `requirements.txt` |
| R-19 | Anti-screenshot never observed on a device (S-08) | Medium | Android | **OPEN** | Device/emulator check | Dev/Owner | - | screenshot test showing flag effect | `security-audit.md` S-08; **gap:** no device check |
| R-20 | Interactive-docs, error-log retention, exported `PackageInstallReceiver`, public `/ready` details (S-09, S-13, S-14, S-17) | Low-Medium | Various | **OPEN** except docs gate (TESTED) | See `security-audit.md` | Dev | - | per item | `security-audit.md` S-09, S-13, S-14, S-17; `tests/unit/test_api_docs_gate.py` |
| R-21 | Identity squatting through `POST /auth/register`: unverified email and phone stored on `users`, one code delivered to both channels, either identifier verifies (F-01) | High | Auth | **PRIVATE PILOT BLOCKER. OPEN - CONFIRMED by proof of concept 2026-11-13; F1 fix BUILDING (uncommitted, incomplete)** | pending registration, verified-only login, single-identifier challenges | Dev | owner approval to commit and deploy | the 12 mandatory tests and CI pass; staging check | section 12e (F-01); section 12c gate 11; `app/routers/auth.py:264-345` and `:548-575` at commit `15f5ea6`; proof of concept 2026-11-13, 3 passed (verified locally, disposable database). **Gap:** the proof-of-concept script is kept in the session scratch folder, not in the repository |
| R-22 | Unverified email claim through `PATCH /auth/me` (F-02) | High | Auth | **PRIVATE PILOT BLOCKER. OPEN - CONFIRMED by proof of concept; F1 fix BUILDING (uncommitted, incomplete)** | reject direct changes; verified email-change flow | Dev | as R-21 | as R-21 | section 12e (F-02); section 12c gate 11; `app/routers/auth.py:825-850` at `15f5ea6`; proof of concept passed, control case blocked (same gap as R-21) |
| R-23 | Google sign-in resolves by email without regard to verification state; no stored subject (code-confirmed, not executed) | High | Auth | OPEN; part of the F1 pilot gate (gate 11); the F1 work is incomplete | `google_sub`, link only to verified-email rows, never relink silently | Dev | as R-21 | Google scenarios in the 12 tests | section 12e (Google row); section 12c gate 11; `app/routers/auth.py:672-676` at `15f5ea6`. **Evidence gap:** code-confirmed only, not executed |
| R-24 | Family invite response exposes `member_user_id` before consent (phone-registration oracle) (F-03) | Low | Family | OPEN (code-evidenced, not exploited) | drop the field pre-consent | Dev | - | test added | section 12e (F-03); `app/routers/family.py:75-108`, `app/schemas/family.py:22` at `15f5ea6`; not exploited |
| R-25 | Community upvote: no per-user dedupe; malformed id gives 500 (F-04) | Low | Community | OPEN | record votes per user; 404 | Dev | - | tests added | section 12e (F-04); `app/routers/community_scam.py:437-452` at `15f5ea6`; not exploited |
| R-26 | Phone verification needs an SMS provider; Twilio is rejected and is not to be re-enabled | High | F1 phone step, panic SMS | **BLOCKED** | owner decision on a DLT-registered SMS provider, or defer phone login | Owner | owner decision | a real code delivered and verified | section 6 (phone verification row); section 7 (Twilio row); section 12c gate 20; `p1-closure-report.md` (Twilio rejected, code 20003, live read-only check 2026-11-13, not repeated); `_verify_twilio` in `app/main.py`. **Gap:** no current check of the Twilio credential state |
| R-27 | CERT-In: no durable 180-day log store; `error_logs` purged at 90 days; no named contact or written 6-hour procedure (applicability per counsel) | High | Logging, operations | OPEN | log plan, contact, procedure, counsel | Owner and counsel | owner | retention demonstrated, contact registered | section 5a (CERT-In rows); section 12c gates 13, 14; `app/services/logger_service.py:40-54`; `app/main.py:153` at `15f5ea6` (purge); `app/config.py:202` (working tree, `LOG_RETENTION_DAYS=90`). **Gap:** Railway log retention and region not verified |
| R-28 | No privacy notice, consent capture or grievance contact (SPDI now; DPDP main duties 13 May 2027) | High | Product, legal | OPEN | counsel-reviewed notice and consent screens | Owner and legal | owner | shown in the app before sign-up | section 5a (SPDI and DPDP rows); section 12c gate 7; Phase C code search of `flutter_app/lib` found no privacy-notice screen. **Gap:** absence not exhaustively proven **Phase G (2026-11-14, uncommitted):** consent screen before registration, privacy notice screen, consent records (`user_consents`) and an optional AI choice built and tested; the notice is a DRAFT with owner items marked "to be completed" (legal name and contact, retention periods); counsel review and a grievance contact are still outstanding; see section 12f |
| R-29 | `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS` declared but no code path uses them (Play-restricted) | Medium | Android manifest | OPEN | remove and test | Dev | - | built manifest checked | section 5a (Play restricted permissions); section 12c gate 8; `flutter_app/android/app/src/main/AndroidManifest.xml:12-13,45-46`; `MainActivity.kt` and `AppInstallAnalyzer.kt` list the permissions only to classify other apps. **Gap:** removal not yet tested for behaviour change **Phase G:** all four permissions removed from the source manifest and the consent manager no longer requests the SMS group; built-APK check pending; see section 12f |
| R-30 | Account deletion has no client path (backend `DELETE /auth/me` tested) | Medium | Flutter | OPEN | add the path; declare it | Dev | - | device check | section 5a (account deletion); section 12c gate 12; backend `app/routers/auth.py:901` at `15f5ea6` (`DELETE /auth/me`, tested); client absence from a code search of `flutter_app/lib`. **Gap:** absence not exhaustively proven **Phase G:** in-app deletion built (Settings > Privacy and data > Delete account) with a code sent to the verified email or phone; `DELETE /auth/me` now requires that code; device check and Play data-safety declaration pending; see section 12f |
| R-31 | AI processing: user text and personal details sent unredacted to Anthropic; no spend cap or kill switch; key present on staging | High | `ai_service.py` | **BLOCKED** (owner: disabled until reviewed) | unset the key until review; redaction, agreement, spend cap, kill switch | Owner and dev | owner | controls exist and owner approves | section 7 (Anthropic row); section 5a (AI terms); section 12d (E2); section 12c gate 18; `app/services/ai_service.py:187,282,477,680`; `app/services/ai_limits.py:11` (per-minute limit only); `app/config.py:157,215` (working tree). **Gap:** provider terms from web search, no signed agreement evidenced |
| R-32 | Safe Browsing API v4 is non-commercial only | Medium | link scanner | **BLOCKED** (commercial) | keep off; evaluate Web Risk or alternatives (pricing unverified) | Owner | owner | agreement or replacement approved | section 5a (Safe Browsing row); section 7; section 12c gate 17; `app/services/gsb_service.py:32`. **Gap:** Google developer terms were read via web search, the page was not opened in full |
| R-33 | Recovery dependencies: two local copies of the encrypted backup (`C:\SecureShield-Backups\...dump.gpg` and `verification-download\...dump.gpg`), same size and SHA-256 as the recorded value (verified 2026-11-13); the top-level file was absent in the Phase D and E1 checks and present later, with a modification time equal to the download copy, so it is **not proven to be the original creation file**; the Drive copy and Bitwarden passphrase are owner-reported | Medium | Backup | OPEN | keep at least two verified copies; periodic restore test | Owner | - | second copy and passphrase access confirmed | section 12d (E1 and backup files); section 12b; hashes re-verified in the final correction pass; `C:\SecureShield-Backups\secureshield-staging-20261113T140939Z.dump.gpg.sha256`. **Gap:** provenance of the top-level file and the Drive copy not provable from here |
| R-34 | Staging shares provider keys with the developer's local `.env` and backups; no separate dev, staging and production secrets | Medium | Secrets | OPEN | separate secret sets | Owner | owner | inventory shows no sharing | section 12d (E2 table); in-memory comparison of Railway and local values (nothing printed); local file names only. **Gap:** local files' contents deliberately not read |

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

**Audit phases completed (findings recorded, not closed):** Phase C classification (release gates, regulation), Phase D pilot validation (evidence-corrected register, migration risk, compatibility, credentials, logging), Phase E1 (restore from the Drive copy), Phase E2 (credential plan), Phase F (authorisation: F-01..F-07), scorecard audit (this consolidation). Their fixes are tracked as risks R-21 to R-34 in section 13.

**No finding is CLOSED at production level.**

## 15. Outstanding Blockers
**Private pilot decision: NO-GO.** It remains NO-GO until F-01 and F-02 (and the Google account-linking weakness, R-23) are remediated and independently tested. The F1 implementation has started but is incomplete and uncommitted: it is **not** a remediation yet, and the pilot acceptance count is 0 of 11.

1. **Owner:** credential rotation (deferred), upload keystore, Play/DPDP decisions, retention periods, approvals for push/backup/migration/deploy/test send.
2. ~~CI not run~~ **Resolved for `b130d04`** (run 43399687864 SUCCESS). The fast-forward of `staging/railway-snapshot` still needs every later gate below.
3. **Recovery only partly proven**: manual backup, isolated restore and a restore from the Drive copy done (sections 12b, 12d; E1 RESTORE PARTIALLY VERIFIED); no schedule, no uploads or populated-data recovery; two local copies of the encrypted backup exist with hashes equal to the recorded value, but which is the original creation file is unproven (R-33); full disaster recovery NOT TESTED.
4. **Ten pending migrations** (nine committed plus the uncommitted F1 revision), unapproved.
5. ~~Phase 7 / Phase A changes uncommitted~~ **Resolved 2026-11-13:** committed (`e367eb6`, `b130d04`, `15f5ea6`), pushed to the CI-only candidate branch and validated by CI (run 43430344346). Still not deployed.
6. **Staging variables:** `FILE_ENCRYPTION_KEY`, `TRUSTED_PROXIES`, CORS, `SMTP_FALLBACK_ENABLED=false`, Railway start command.
7. **First superadmin** and MFA enrolment.
8. **Live provider verification** (Resend first) and **device end-to-end** on a signed build.
9. **Identity binding (F-01/F-02/Google)**: confirmed takeover weaknesses; fix BUILDING and uncommitted (R-21..R-23). **Pilot gate 11.**
10. **No SMS provider** for the phone verification step (R-26).
11. **Privacy notice, consent and account-deletion path**: built in Phase G (draft, uncommitted, section 12f); still needed: counsel review, owner-supplied contact and retention periods, Play data-safety form, device verification (R-28, R-30).
12. **CERT-In readiness** (log store, contact, procedure) not in place (R-27); applicability to be confirmed by counsel.
13. **Credentials**: remediation plan prepared, not executed (section 12d, R-01, R-02, R-34).
14. **AI and Safe Browsing** remain BLOCKED for real data and commercial use (R-31, R-32).

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
| 2026-11-13 | DPDP Act and Rules dates taken from the Gazette of 13 Nov 2025: one-year provisions 13 Nov 2026, eighteen-month provisions 13 May 2027; Rule 4 applies only to Consent Managers (SecureShield is not one) | Owner | Phase C correction |
| 2026-11-13 | Safe Browsing commercial use is BLOCKED unless a separate agreement applies; no commercial integration without approval | Owner | Phase C correction |
| 2026-11-13 | Live AI processing of real user data stays disabled until privacy, provider terms, redaction, spend controls and a kill switch are reviewed and approved | Owner | Phases C, D |
| 2026-11-13 | Manual tested recovery is distinguished from automated backup scheduling; automation is not universally mandatory; the Google Drive checksum evidence is retained | Owner | Phase C correction |
| 2026-11-13 | Android permissions are assessed individually; private sideloaded pilot requirements are separate from Play submission requirements; privacy and consent safeguards are not weakened | Owner | Phase C correction |
| 2026-11-13 | Backup passphrase stored in a Bitwarden Secure Note with two-step login and an offline recovery code (owner-reported); plaintext passphrase file deleted (verified by directory check, Recycle Bin not inspected) | Owner | Phase B |
| 2026-11-13 | Phase F1 architecture approved (11 decisions, listed in section 12e); Stage B implementation authorised; no commit, push, migration or deployment authorised | Owner | Phase F1 |
| 2026-11-13 | Documentation consolidation authorised: update this document only; archival of other documents is a proposal pending approval; moving the backup procedure needs confirmation; F1 work must not be overwritten | Owner | consolidation request |

**Not approved (as of this document):** pushing any branch or tag, creating PRs, applying migrations, deploying or redeploying, rotating credentials, adding GitHub/Railway secrets, sending any real e-mail.

## 17. Next Actions and Milestones

Priority order. Each item needs the stated approval before any external effect.

| # | Action | Needs approval for | Done when |
|---|---|---|---|
| 1 | **Resend integration release:** keep the Resend adapter (commit `1335678`) in the 77-commit release candidate (not deployed); confirm no deployed behaviour change until the branch is fast-forwarded | - | included in release range, CI green |
| 2 | **SMTP fallback control:** code and tests DONE locally; **commit** (approval) then set `SMTP_FALLBACK_ENABLED=false` on staging later | commit approval; variable change | R-04 closure evidence |
| 3 | **File encryption startup validation:** code and tests DONE locally; **commit** (approval); owner creates and escrows the key; set `FILE_ENCRYPTION_REQUIRED=true` on staging | commit approval; key creation | R-03 closure evidence |
| 4 | **CI candidate branch:** commit Phase 7 files only (never the owner's uncommitted files; workflow already narrowed locally); push `staging/candidate-2026-11-13` | **commit approval, then push approval** | **DONE 2026-11-13:** pushed at `15f5ea6`; Railway did not deploy |
| 5 | **Backend CI validation:** read the first CI run (gitleaks, ruff, pip-audit, alembic, pytest); fix failures | - | one green `backend-ci` run on the release SHA - **DONE for `b130d04`** (run 43399687864); repeat if any later commit is added |
| 6 | **Database backup and restore verification** on staging | backup/restore approval | **DONE for the first exercise (2026-11-13)**, see section 12b: backup, GPG encryption, isolated restore, Drive copy hash-verified. Remaining: restore from the Drive copy, schedule, retention, uploads and populated-data tests (R-07 stays partly open) |
| 7 | **Migration approval:** owner reviews `../MIGRATION_SAFETY_REVIEW.md`; approval recorded in section 16 | **owner approval** | approval entry exists |
| 8 | **Controlled Railway staging deployment:** set remaining variables (`TRUSTED_PROXIES` measured, CORS, encryption, SMTP switch), fast-forward `staging/railway-snapshot`, watch pre-deploy migrations and health checks, create first superadmin | **push + deploy + migration approval** | revision `u6v7w8x9y0z1`, `/health` ok, smoke tests pass |
| 9 | **OTP delivery and authentication testing:** one owner-approved real Resend send, sign-in, rate-limit and provider-failure tests | **send approval** | R-10 closure evidence |
| 10 | **Credential rotation** at a later approved stage (before any production use) | owner schedule | R-01, R-02 closure evidence |

Milestones (**M1 reached 2026-11-13**; backup/restore first exercise done): M1 candidate branch CI-green -> M2 staging deployed with migrations -> M3 OTP live on staging -> M4 rotation and keystore -> M5 device end-to-end on a signed build -> M6 closed-beta Go/No-Go (`development-roadmap.md`; about 60-75 developer-days remaining in the 2026-11-13 estimate, plus owner lead time).
**Updated priority order (2026-11-13, supersedes the order above where they differ):**
1. **Finish F1 (gate 11):** adapt the 23 failing tests, write the 12 mandatory tests, Flutter changes and tests, reviewed SQL script, full suite and CI; then request commit approval.
2. **Credential remediation (gate 1)** per section 12d, after approval; rotate `SECRET_KEY` before real users exist.
3. **Decide the SMS provider** or defer phone login (R-26).
4. Counsel on CERT-In and SPDI/DPDP applicability; name a contact; write the 6-hour procedure (R-27, R-28).
5. Remove unused permissions, add the account-deletion path and privacy notice (gates 7, 8, 12).
6. Deploy the candidate pair (gate 2) with Phase A variables; first superadmin (gate 3); live Resend OTP (gate 4); device pairing test (gate 5); signed APK (gate 6).
7. Re-backup after migrations; automate backups later (gates 9, 15).
8. Apply the documentation archival proposal if approved (section "Document inventory").

## 18. Change History

| Date | Change | Evidence |
|---|---|---|
| 2026-11-14 | **Phase 1A (uncommitted):** `AppMonitorService` declared in the manifest (it was started but undeclared, so it could never run); non-exported specialUse foreground service, START_NOT_STICKY, duplicate-start guard, separate high-importance channel for risky-app alerts; start confirmed by the service before the UI says active; notification permission required; disclosure card; 11 JVM tests, 17 channel and screen tests, 4 manifest tests; debug APK built and merged manifest inspected; not run on a device; see section 12h | working tree |
| 2026-11-14 | **Phase 0 (uncommitted):** global fail-closed switch `AI_PROCESSING_ENABLED` (default off) enforced at the single provider boundary; chat and screenshot extraction return 503 with `X-AI-Status: disabled`; message and job-offer analysis, complaint email, FIR draft and tips keep working locally; privacy notice, consent screen and settings text corrected to say external AI is disabled; 38-module development register added to `development-roadmap.md`; see section 12g | working tree |
| 2026-11-14 | **Phase G (uncommitted):** privacy notice and consent screens, consent records (migration `w8x9y0z1a2b3` prepared, reviewed SQL `g_consent_review.sql`, neither executed), re-authenticated in-app account deletion, removal of four unused Android permissions with a manifest regression test; backend 1305 passed, 0 failed (local disposable test database, 9m11s); Flutter 180 passed, 0 failed; see section 12f | working tree |
| 2026-11-13 | **Final correction pass** (this file only; independent-verification checklist D-01..D-09 plus consistency items): backup-file status re-verified (two copies, equal hashes, provenance unproven); pilot readiness corrected to 0 of 11 accepted gates; original G1-G12 gates added verbatim as a separate table (all FAIL, G4 FAIL); the unofficial status label removed; migration (10 pending files, none executed) and commit (77, none deployed) counts corrected; Evidence reference column added to the risk register; 57.7% estimate stated with its UNVERIFIED qualification; staging described as a staging environment only; F-01/F-02 shown as private-pilot blockers in the scorecard, R-21, R-22, section 15 and the gate mapping; freshness rule given an Invalidated-by field; evidence-levels table added. No other file changed | final consistency checks (see the report of this pass) |
| 2026-11-13 | **Documentation consolidation** (this file only): added the scorecard with formulas and denominators, the Section Freshness Register, rules 10-12, the per-feature evidence ladder, section 5a (compliance), cost column in section 7, migration risk register, sections 12c (release gates and pilot readiness), 12d (Phase E), 12e (Phases F and F1), risks R-21..R-34, blockers, decisions and updated next actions; corrected stale statements in sections 1, 3, 8, 11, 12, 14, 15; inventory and archival PROPOSAL (no file moved, renamed or deleted; other documents unchanged); the backup-procedure move NOT done. Scorecard arithmetic recomputed from the matrix and reproduced exactly; F1 files verified unchanged by hash | 20 of 20 documentation consistency checks passed (2026-11-13); the check script is kept outside the repository and is not part of CI |
| 2026-11-13 | Document created from existing audit reports and reported release facts; no new technical audit; no application source changed by this document | this file |
| 2026-11-13 | Phase 7 working-tree changes recorded as BUILT / uncommitted (SMTP switch, encryption-required validation, partial tests) | local branch `staging/candidate-2026-11-13` |
| 2026-11-13 | CI run 43381648865 failed on `e367eb6` (CI-1, ruff format of `scripts/seed_sms_registry.py`); root cause and ready fix recorded; clean-checkout verification 1069 passed; corrective commit `b130d04` approved, created and pushed | CI log; clean worktree |
| 2026-11-13 | **Documentation sync:** Phase A committed (`15f5ea6`), pushed to the candidate branch; CI run 43430344346 on `15f5ea6` succeeded (gitleaks, lint, ruff, pip-audit, Alembic, pytest); stale "uncommitted / not pushed" statuses updated across sections 1, 3, 12, 12a, 13, 15 and 17; Railway and `staging/railway-snapshot` unchanged | `gh run view`, `git ls-remote` |
| 2026-11-13 | Second recheck: plaintext passphrase file **no longer present** (folder empty; Recycle Bin not inspected); discrepancy resolved | directory listing and name search |
| 2026-11-13 | Recheck of the plaintext passphrase file requested by the owner: **still present** (48 bytes); recorded as unresolved, nothing deleted by Claude | directory listing only |
| 2026-11-13 | **Phase B Google Drive verification (uncommitted):** encrypted backup copied off-machine by the owner and verified byte-identical (302,986 bytes; SHA-256 `c07c36fa...fb2d77` equal for original, download and recorded value); statuses set to: database backup and isolated restore TESTED, off-machine encrypted copy VERIFIED, full disaster recovery NOT TESTED; Bitwarden custody recorded as owner-reported; plaintext passphrase file still present at update time (discrepancy recorded) | size and SHA-256 comparison |
| 2026-11-13 | **Phase B executed (uncommitted):** staging database backed up (pg_dump -Fc inside the Postgres service, 369,844 bytes, GPG AES-256 encrypted to `C:\SecureShield-Backups`), restored into a local scratch database, 22 checks passed after two reported corrections; uploads volume empty (manifest only); Railway unchanged | local artefacts and verification report |
| 2026-11-13 | **Phase B (inspection and plan only, uncommitted):** read-only inventory of the staging database (PostgreSQL 18.6, 12.1 MB, 29 tables, 23,278 rows, revision `l7m8n9o0p1q2`, all user tables empty) and uploads volume (0 files); backup, upload backup and isolated restore procedures and acceptance criteria written; nothing executed; see section 12b | read-only probe |
| 2026-11-13 | **Phase A (local, uncommitted):** SMTP gate extended to the new-device alert, single client-IP helper everywhere, CORS policy module, encryption cleanup and tests; full suite 1227 passed, 12/12 mutations caught; see section 12a | working tree |
| 2026-11-13 | **CI SUCCESS** on `b130d04` (run 43399687864): gitleaks, lint, ruff, pip-audit, blank-DB Alembic chain and PostgreSQL pytest all passed; CI validation complete for this candidate revision; infrastructure/credential risks unchanged | `gh run view` step list |
| 2026-11-13 | Final review: deploy workflow narrowed from `staging/railway-snapshot`+`v*` to the exact branch only; test extended to 14 refs; focused tests 15 passed, ruff clean | working tree |
| 2026-11-13 | Phase 7 completed locally, **uncommitted**: error-alert gate test fixed (no skip), encryption startup validation tests, `deploy-staging.yml` restricted to the exact branch `staging/railway-snapshot` (no tags); full suite 1062 passed, 11/11 mutations caught. Changed files: `app/delivery_settings.py`, `app/services/{otp_service,notifications,logger_service,file_crypto,upload_safety}.py`, `app/startup_checks.py`, `.github/workflows/deploy-staging.yml`, `tests/unit/test_{smtp_fallback_switch,file_encryption_required,deploy_workflow_refs}.py`, `tests/integration/test_file_encryption_api.py`, this document | working tree |

Earlier history: `audit-history.md`.
