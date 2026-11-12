# Security audit

Assessed 2026-11-12. Frameworks: OWASP MASVS v2 / MASTG (Android client), OWASP API Security Top 10 (2023), India DPDP Act 2023 / Rules readiness.
Method: code reading, route enumeration of the live FastAPI app (107 routes), `pip-audit` against the installed backend environment, read-only `gh`
queries, the existing hardening records (`../SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`) re-checked against code, and the automated suites. This is **not** a penetration
test; no exploit was attempted and no production system was touched. **No secret value appears in this document or was read to write it.**

Ratings: Critical (exploitable now / blocks any release), High, Medium, Low. "Verified" = observed in this audit; "Register" = recorded earlier and not re-verified.

## Critical

| ID | Finding | Evidence | Recommendation |
|---|---|---|---|
| S-01 | **Both repositories are PUBLIC on GitHub while the backend Git history contains exposed credentials.** The register records an Anthropic API key, a Twilio account SID, the placeholder `SECRET_KEY`, a committed `.env`, logs with personal data, and 14 gitleaks findings in 2 old commits; rotation was deferred. `staging/railway-snapshot` (infrastructure names, the staging URL, role names) is also public | **Verified:** `gh repo view ravishori/SecureShield-Backend --json visibility` -> `PUBLIC`; same for `SecureShield-Frontend`. `git log --diff-filter=A -- '.env*'` in the backend repo lists `.env` and `.env.example` additions. Register: FG-020, section 2 "Credentials" | Treat every credential that ever appeared in history as compromised: rotate (Anthropic, Twilio, Gmail app password, Safe Browsing, Azure Translator, any database password, `SECRET_KEY`, `ADMIN_TOKEN`) **before** anything else; make the repositories private now; decide between history rewrite (BFG/filter-repo + force-push + cache purge request to GitHub) and abandoning the history. Rotation, not rewriting, is the real fix because public repositories are mirrored |

## High

| ID | Finding | Evidence | Recommendation |
|---|---|---|---|
| S-02 | **Known-vulnerable dependencies:** `pip-audit` (2026-11-12, OSV/PyPI) reports **147 advisories in 16 packages** of the backend environment | Direct pins: `python-jose 3.3.0` (2 advisories, fix 3.4.0; it signs/verifies every JWT: `routers/auth.py`, `services/google_auth.py`), `starlette 0.38.6` (7), `python-multipart 0.0.12` (7, upload endpoints), `cryptography 43.0.3` (6; file encryption), plus transitive `aiohttp 3.13.5` (22), `pyjwt 2.12.1` (15), `pyasn1` (7), `urllib3` (5), `anyio`, `certifi`, `dnspython`, `idna`, `multidict`, `pip`, `setuptools`. Exploitability per advisory was **not** assessed. Flutter/Dart packages were **not** scanned (no scanner available) | Upgrade pins in a dedicated branch (FastAPI/Starlette/python-multipart together, `python-jose` 3.4.0 or move to PyJWT, `cryptography` current), run the 923-test suite, add `pip-audit` to CI. Re-scan; record the result here |
| S-03 | **No working OTP channel** - the only login path cannot deliver codes | Twilio `20003` on the configured SID/token (diagnosed 2026-10-18, values well-formed, rejected by Twilio); no Resend key/domain; Railway blocks SMTP (FG-001..003) | Owner: verify the SID/token pair in the Twilio Console, choose an HTTPS e-mail provider, complete India DLT registration; then verify live |
| S-04 | **Release builds are signed with the debug key** and cannot be distributed or updated safely | `android/app/build.gradle.kts:46-63` falls back to the debug config when `android/key.properties` is absent; the file is absent (verified); `flutter build apk --release` produced a 108.4 MB APK on 2026-11-12 | Create an upload keystore (owner custody), enrol in Play App Signing, keep `key.properties` out of Git (already ignored) |
| S-05 | **Play policy risk from restricted permissions** | `AndroidManifest.xml` declares `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS`, `READ_PHONE_STATE/NUMBERS`, `QUERY_ALL_PACKAGES`, `PACKAGE_USAGE_STATS`, `BIND_VPN_SERVICE`, MediaProjection/`systemExempted`/`specialUse` foreground services, `RECEIVE_BOOT_COMPLETED`, `DETECT_SCREEN_RECORDING` | Remove every permission a shipped feature does not strictly need; prepare Play declaration forms and demo videos for the rest; expect SMS/call-log use to be rejected unless the app is a default handler - redesign those paths on notification access only (already the working bank-OTP path) |
| S-06 | **Admin authority is one shared static token** with no identity, MFA or rotation path; it reads user data, disables accounts and views audit logs | `routers/admin_errors._check_admin`, `admin_users.py` (`stats`, `users`, `PATCH users/{id}/status`, `audit`); throttle is global and per-process (FG-166); constant-time compare verified by tests | Per-person admin identities (JWT + role, MFA), keep the token only as break-glass, store a hashed token, move throttling to a shared store, add alerting on admin actions |
| S-07 | **DPDP readiness gaps** | No log/data retention policy (FG-034 open; `error_logs` purged only at startup; `admin_audit_logs`, `warrior_audit_logs`, `otps` never purged); `client_ip` stored on every error row; no privacy notice / consent-record / grievance-officer artefacts in either repository; Family "Kids" flows involve minors (verifiable parental consent under s.9 not assessed); URLs go to Google Safe Browsing / abuse.ch, message text to Anthropic (cross-border processing notice) | Legal review; define retention per table and implement purge jobs; add notice + consent capture; document processors and transfers; confirm child-data handling |

## Medium

| ID | Finding | Evidence | Recommendation |
|---|---|---|---|
| S-08 | **Anti-screenshot protection does not work** and is not applied | Dart `ScreenshotPrevention` invokes `addFlags`/`clearFlags` (`lib/core/security/screenshot_prevention.dart:51,64`); Kotlin `MainActivity` handles only `enableSecure`/`disableSecure` (`MainActivity.kt:157-158`); no screen references `ScreenshotPrevention` or the Kotlin methods. The feature list claims it | Align the method names, apply `FLAG_SECURE` on evidence, OTP vault, family and recordings screens, add a channel test |
| S-09 | **OpenAPI/Swagger exposed in every environment** | `app = FastAPI(title=..., version=...)` in `app/main.py:42` has no `docs_url/openapi_url` override; the rate limiter even whitelists `/docs` | Disable or gate docs when `ENVIRONMENT=production` |
| S-10 | **Rate limiting is in-memory and per process**; restart clears it; N workers multiply budgets; Redis backend is a stub | `middleware/rate_limiter.py`, FG-010 | Shared store before any horizontal scaling; keep one replica until then |
| S-11 | **Server-side encryption of evidence/recordings is off until an owner sets `FILE_ENCRYPTION_KEY`**; no AV scan; no per-user quota; local-disk storage on one volume | `config.py:220-222`, `services/file_crypto.py`, `upload_safety.py` | Set and escrow the key, rehearse rotation (`scripts/`), add quota |
| S-12 | **Container runs as root; no `HEALTHCHECK`** in the image | `Dockerfile` has no `USER`; health check lives only in Railway IaC | Add a non-root user and an image-level healthcheck |
| S-13 | **Public information disclosure endpoints** | `GET /ready` returns database and role names (FG-037, kept for deployment verification); `GET /auth/check-user` reveals whether an account exists (rate-limited 30/min/IP, by design) | Return only status from `/ready` behind a private check; consider uniform responses for `check-user` |
| S-14 | **Error logs hold sensitive context** | `error_logs` stores `client_ip`, scrubbed messages/tracebacks; scrubbing is heuristic (FG residual risk) | Retention (S-07) and restricted admin access; treat as sensitive |
| S-15 | **Local credential-bearing files and a drive-wide repository** | `backend/.env`, `.env.phase1b-backup`, ` - Copy.env`, `env.txt` (parent folder) exist (all git-ignored or outside the repos; contents not read). `D:\` itself is a Git repository with the whole drive untracked, so a stray `git add -A` there would stage personal documents and these files | Delete stale copies after rotation; remove `D:\.git` or scope it; never run `git add -A` there |
| S-16 | **Third-party data egress without a documented notice** | `gsb_service.py`, `urlhaus_service.py` send scanned URLs; `ai_service.py` sends user text/screenshots to Anthropic | Disclose in the privacy notice, minimise payloads |
| S-17 | **Exported receiver** `PackageInstallReceiver` (`PACKAGE_ADDED`) is `exported="true"` | `AndroidManifest.xml`; input validation of the intent was not assessed | Confirm it validates the action/data or make it non-exported where possible |
| S-18 | **No certificate pinning** on the client (MASVS-NETWORK-2) | `core/network/dio_client.dart` uses system trust only | Optional; weigh against Railway certificate rotation |

## Low

* S-19 Orphan table `otp_vault_entries` (no model) and Alembic drift on older index/FK names (FG-053, FG-147).
* S-20 Model ids hard-coded in `ai_service.py` (7) and `message_analyzer.py` (1): upgrades require code changes; no per-user spend cap beyond rate limits (`ai_limits.py`).
* S-21 Release build without `--dart-define=API_BASE_URL` falls back to LAN probing (cleartext is blocked in release by `network_security_config.xml`, so it fails closed) - a deployment-configuration trap, not a vulnerability.
* S-22 Environment named `production` inside the Railway *staging* project (FG-123).
* S-23 `Features of the app.txt` overstates several controls (see `audit-history.md`).

## Local database credential exposure (record only)

On 2026-10-18 the local PostgreSQL password was printed once in a pytest assertion in a tool transcript. Rotation was deferred by the owner ("after the
migration preparation stage"). Treat it as exposed; the migrated Neon database uses separate credentials that were never printed.

## Credentials to treat as potentially compromised (names only)

Anthropic API key; Twilio account SID/auth token; Gmail SMTP app password; Google Safe Browsing key; Azure Translator key; former Azure PostgreSQL
credentials; local PostgreSQL `postgres` password; any `SECRET_KEY`/`ADMIN_TOKEN` value used before 2026-10-05; Neon role passwords only if the
local `.env` files are ever shared. **Rotate all of them; then re-run secret scanning on history.**

## OWASP MASVS v2 summary (Android client)

| Area | Result | Evidence |
|---|---|---|
| STORAGE | Mostly met | `allowBackup="false"`; `EncryptionService` = AES-256-GCM, random nonce, key in Keystore-backed `FlutterSecureStorage` (`encryption_service_test.dart`); tokens in secure storage; recordings stored in an app-private folder (encryption of the files themselves not verified) |
| CRYPTO | Met | GCM with authentication, CSPRNG key, legacy CBC read-only |
| AUTH | Partly met | Biometric/PIN gate for the vault (`local_auth`, `FlutterFragmentActivity` fix); no re-auth for evidence |
| NETWORK | Partly met | Cleartext off in release, system trust anchors only; no pinning |
| PLATFORM | Not met | `FLAG_SECURE` broken (S-08); exported receiver (S-17); broad permissions (S-05) |
| CODE | Partly met | R8 minify + shrink enabled; dependency scan missing for Dart; debug-key release (S-04) |
| RESILIENCE | Partly met | Detects rooted/emulated device (`DeviceIntegrityProbe.kt`) - no self-integrity or anti-tamper of the app itself |
| PRIVACY | Not met | Permission rationale/consent manager exists; no privacy notice, data-safety form or deletion UI path assessed |

## OWASP API Security Top 10 (2023) summary

| Item | Result | Evidence |
|---|---|---|
| API1 BOLA | Good | Owner filters + other-user 404 tests: evidence, recordings, family (consent), scans, devices, alerts, reports (`test_device_scoped_data_api`, `test_family_api`, `test_evidence_recordings_api`); register FG-130/131/132 fixed |
| API2 Broken authentication | Good in code, unusable in practice | type-separated JWT, rotation with replay revocation, HMAC'd OTP, send/verify limits; delivery blocked |
| API3 Property-level authorisation | Fair | response models used; not systematically audited |
| API4 Resource consumption | Fair | body/upload caps, AI rate limits, global IP limiter (in-memory) |
| API5 Function-level authorisation | Fair | admin routes require the shared token; warrior admin uses role >= admin; shared token is weak (S-06) |
| API6 Sensitive business flows | Fair | OTP send limits (5/h), panic limit 10/10 min |
| API7 SSRF | Low exposure | outbound calls go to fixed provider hosts; scanned URLs are sent *to* providers, not fetched by the server |
| API8 Misconfiguration | Fair | CORS fail-closed in production, production startup checks; docs exposed (S-09), root container (S-12) |
| API9 Inventory | Fair | 107 routes enumerated; 10 unused by the client; staging environment name confusing |
| API10 Unsafe consumption | Fair | provider responses handled defensively in tests (simulated); never run live |

## What passed re-verification in this audit

923 backend tests pass on real PostgreSQL; `ruff` clean; route enumeration found only expected unauthenticated routes (`/`, `/health`, `/ready`,
`/version`, 6 `/auth/*` routes, public share download, admin console page, admin token routes); `.env*` files are git-ignored and not tracked in either repository.
