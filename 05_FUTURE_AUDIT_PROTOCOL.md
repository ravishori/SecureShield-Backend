# SecureShield AI — Future Repository Audit Protocol

## 1. Purpose

Avoid repeating a full repository discovery exercise for every task. Use this baseline as the starting point and perform **change-focused audits**.

## 2. Start-of-task checks

Before any code change:
1. Confirm repository and branch.
2. Record current backend and frontend commit SHAs.
3. Check working tree status.
4. Read this baseline and relevant open findings.
5. Identify the feature's complete call path.
6. Identify data categories, permissions, providers, DB changes and tests affected.
7. Check whether the requested change touches an open P0/P1 finding.

## 3. Change-trigger matrix

| Change made | Minimum re-audit scope |
|---|---|
| Flutter screen/layout only | Screen, state provider, navigation, accessibility, loading/error/empty states and UI tests |
| Riverpod state/provider | UI → state → API path, caching, lifecycle, auth and tests |
| API client/Dio | Base URL, TLS, auth headers, token refresh, error handling, retries and logging |
| FastAPI router | Authn/authz, ownership checks, validation, rate limit, response model, API tests |
| Service/business logic | Router → service → DB/provider, failure paths, idempotency and tests |
| SQLAlchemy model/Alembic | Model, migration, constraints/indexes, backfill, downgrade/rollback and data safety |
| OTP/auth/JWT | Full auth flow, enumeration, replay, brute force, expiry, refresh/revocation, logs |
| Encryption/key storage | Threat model, nonce/key lifecycle, migration, backup, tamper and device tests |
| Android manifest/permission | Permission policy, runtime UX, disclosure, target SDK, Play declarations and device tests |
| Kotlin service/receiver | Manifest registration, Android version limits, foreground service, lifecycle, battery and failure behaviour |
| Third-party SDK/provider | SDK data collection, privacy terms, permissions, network calls, retention, cross-border processing, cost and kill switch |
| AI prompt/provider | Sensitive data disclosure, prompt injection, output schema, uncertainty, cost and safe fallback |
| Upload/evidence/recording | File validation, size, storage, access control, sharing, retention and deletion |
| Billing/subscription | Play policy, purchase token verification, entitlement lifecycle, refund and restore |
| Release/build config | Signing, target API, dependency inventory, R8, AAB, artifact tests and rollback |

## 4. Full audit triggers

Run a broader cross-repository audit when:
- Preparing the first public production release.
- Changing authentication or cryptographic architecture.
- Adding a new high-risk permission or Android background service.
- Introducing a new data category or third-party processor.
- Reworking VPN, call, SMS, notification or accessibility functionality.
- Adding family/senior monitoring or data sharing.
- Changing account deletion, retention or consent.
- Changing billing or subscription entitlement.
- A security incident or credential exposure occurs.
- A major framework/SDK/target API upgrade occurs.
- The previous baseline is more than 90 days old before a release, or current policy changes materially.

## 5. Required call-chain trace

For every feature change, document:

`Screen → Riverpod state/provider → Dio/API client → FastAPI router → service → model/database → external provider`

For each hop, capture:
- File path and relevant symbol.
- Input/output contract.
- Authentication and authorisation.
- Data handled.
- Error/fallback behaviour.
- Logs/telemetry.
- Tests.

Do not assume a UI button proves the feature works end-to-end.

## 6. Evidence and status rules

Use these statuses:
- **Planned** — approved design only.
- **Building** — implementation in progress.
- **Built** — code exists.
- **Tested** — specified tests executed and passed.
- **Reviewed** — security/platform review completed.
- **Production** — deployed and verified in production.

For each test, record:
- Test ID.
- Environment/device/OS.
- Exact command or steps.
- Expected result.
- Actual result.
- Pass/fail/blocked/not run.
- Build/commit SHA.
- Evidence location.

Never mark a test as passed if it was not executed.

## 7. Updating the baseline

When a task changes the code:
1. Update `02_FINDINGS_REGISTER.md` for affected findings.
2. Update `03_REPOSITORY_AND_SOURCE_INVENTORY.md` if files, APIs, SDKs or components changed.
3. Update `04_REMEDIATION_ROADMAP.md` if priority/order changes.
4. Update `06_PLAY_STORE_READINESS_CHECKLIST.md` and `07_DATA_PRIVACY_AND_PERMISSION_REGISTER.md` when release/privacy behaviour changes.
5. Update `08_TESTING_AND_EVIDENCE_REGISTER.md` with test outcomes.
6. Append a dated entry to `09_CHANGELOG.md`.
7. Include repository commit SHAs in the task completion report.

## 8. Suggested audit command set

Run from local repository roots using ordinary developer commands:

### Backend
```bash
git status --short
git rev-parse HEAD
git ls-files
git ls-files .env '*.log' '.venv/**' '**/__pycache__/**'
git grep -n -I -E 'password|secret|api[_-]?key|token|DATABASE_URL|JWT' -- ':!*.lock'
python -m pytest
```

### Frontend
```bash
git status --short
git rev-parse HEAD
git ls-files
git grep -n -I -E 'http://|usesCleartextTraffic|READ_SMS|READ_CALL_LOG|QUERY_ALL_PACKAGES|RECORD_AUDIO|ACCESS_FINE_LOCATION'
flutter analyze
flutter test
flutter build appbundle --release
```

These are suggested checks, not results from the 27 November 2026 review. Review matches manually; pattern searches can produce false positives and must never print secrets into shared CI logs.

## 9. Baseline trust rule

If current source conflicts with this document, current source wins. Update this document after verifying the difference. Do not preserve stale findings as current facts.
