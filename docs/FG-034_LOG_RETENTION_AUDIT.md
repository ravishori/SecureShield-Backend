# FG-034 - Log and security-record retention: policy/design audit

**Status: OPEN - POLICY DECISION REQUIRED.** This is an audit and decision paper. Nothing was implemented, no schema,
migration, configuration, test or log behaviour was changed, and no data was touched. No retention period is chosen
here: the repository contains no owner direction or legal requirement for one (section 8).

How to read it: **FACT** = verified in this repository (file/line or measurement), **RECOMMENDATION** = engineering
opinion, **DECISION** = needs the owner. Dates are 2026-10-06.

## 1. Logging architecture (FACT)

```
                    log_error(...)  (logger_service.py; called by the 4 global handlers + 7 auth.py sites)
                         |  scrub_text/scrub_obj once (log_scrubber.py)
        +----------------+--------------------+-------------------------+
        v                v                    v                         
  logs/secureshield.log   error_logs (Postgres)   e-mail to ERROR_NOTIFY_EMAIL (ERROR/CRITICAL only)
  (RotatingFileHandler)   (one row per call)     (SMTP, thread pool)

  get_logger(...).info/warning/error  ->  logs/secureshield.log (DEBUG+)  and  console/stdout (INFO+)
  uvicorn access log  ->  stdout, target rewritten by access_log.py (query values / share tokens / ids removed)
  admin actions       ->  admin_audit_logs (Postgres)         warrior moderation -> warrior_audit_logs (Postgres)
```

* No external log destination exists in code (no Sentry/Datadog/Loki/CloudWatch/syslog/etc.; grep of `app/` and the
  requirements files). What the host does with stdout/stderr (Railway log retention, forwarding) is **not in the
  repository and was not verified**.
* **Every** `fastapi.HTTPException` (any 4xx/5xx, including 401, 403, 429, 400) and every 422 writes an `error_logs` row
  through the global handlers (`error_handler.py`); 5xx also e-mails. Unknown-URL 404s raised by Starlette itself are
  **not** persisted (measured: 20 requests, 0 rows). Responses produced directly by `RateLimitMiddleware` (the global
  per-IP 429) are not persisted, but the FG-166 admin throttle 429 is an HTTPException and **is** (measured: 20 wrong
  admin tokens -> 20 rows, 10 of them 429).

## 2. Inventory of retained categories

| # | Category | Where | Data stored | PII? | Secrets/tokens excluded? | Timestamp | Index | Deletion today | Investigation value |
|---|---|---|---|---|---|---|---|---|---|
| A | **Application error log** `error_logs` | Postgres | `level`, `message` (<=4,000 chars after scrub), `exception_type`, `traceback` (<=20,000), `endpoint` (route template), `method`, `user_id`, `client_ip`, `extra` JSONB (allow-listed request headers incl. `user-agent`, `x-forwarded-for`, `x-real-ip`; query-parameter *names*; validation errors without input), `email_sent` | **Yes**: `client_ip` always; `user_id` only where a caller passes it (the global handlers do not: measured `user_id` NULL on handler-written rows); user UUID and masked identifiers can sit inside `message` (e.g. "Profile update failed for user <uuid>", "OTP verification failed for r***@x.com"); driver/library text can carry data the heuristic scrubber missed (residual risk documented in the gaps register) | Headers are an explicit allow-list; bodies are never read; JWT/Bearer/`key=`/`otp=`/known API-key shapes/URL passwords/driver DETAIL/pydantic input are scrubbed; **heuristic, not proof** | `created_at` (UTC, naive) | `created_at`, `level`, pk | **Only** `_cleanup_old_error_logs` at **startup**: `DELETE ... WHERE created_at < NOW() - INTERVAL '<LOG_RETENTION_DAYS> days' RETURNING id` (default 90). Account erasure sets `user_id` to NULL but keeps the row | High (failed logins, abuse, 5xx diagnostics) |
| B | **Rotating file log** | `logs/secureshield.log` inside the container (not on the uploads volume; `logs/` is git- and docker-ignored) | everything `get_logger` and `log_error` emit at DEBUG+, incl. scrubbed tracebacks; user UUIDs, masked e-mails/phones (`[phone ...NN]`, `a***@domain`), channel outcomes | Pseudonymous ids + masked recipients; `client_ip` only where logged | Same scrubber for `log_error`; FG-041/FG-165 removed recipient/provider text from delivery logs | `asctime` | n/a | `RotatingFileHandler` 10 MB x (1 + 7 backups) = **<= 80 MB**, oldest overwritten; file is lost on redeploy (ephemeral container FS) | Medium (short horizon only) |
| C | **Console / stdout / platform logs** | process stdout -> host | INFO+ of the above, uvicorn access log (redacted target), startup lines | as B | as B; access log redacted | host-defined | host | **Unknown - host policy, not in repo** | Medium; only copy that survives a redeploy if the host keeps it |
| D | **Alert e-mails** | mailbox of `ERROR_NOTIFY_EMAIL` (SMTP; copy leaves the system) | time, endpoint, error type, scrubbed message, **user id, client IP**, scrubbed traceback | Yes (user id, IP) | as A | mail headers | n/a | **None possible from the app**; depends on the mailbox. No de-duplication/rate limit on alert mails (every 5xx / CRITICAL sends one) | Medium |
| E | **Admin audit** `admin_audit_logs` | Postgres | `action` (`user.enable`/`user.disable`), `target_user_id` (no FK), `detail` JSONB, `client_ip` of the caller, `created_at` | `client_ip` (the caller of the shared admin token); target UUID (pseudonymous once the user is erased) | "Never store tokens, credentials or message bodies" (model docstring) | `created_at` | `action`, `target_user_id`, `created_at` | **None**; append-only; survives account erasure by design (tested) | **High** (accountability for the only state-changing admin action) |
| F | **Cyber-warrior moderation audit** `warrior_audit_logs` | Postgres | actor/subject user ids (FK to `users`), action, structured context, reviewer free-text reason, timestamps | Reviewer free text may contain personal details (documented caution); FK keeps the inert `users` tombstone | Not applicable | yes | actor/subject idx | **None**; "append-only" is application discipline (REVOKE not yet applied); **retained** through erasure by design | High |
| G | **Authentication / security events** | no dedicated table | login/registration/refresh outcomes are INFO lines in B/C ("User authenticated: <uuid> via <partial mask>", "New user registered"); failures appear as 4xx rows in A. State tables: `refresh_token_uses`, `revoked_token_families` (jti/family/user ids, expiry) - **self-pruned** (`expires_at < now` deleted on every refresh); `otps` (e-mail/phone in clear, HMAC of code, `expires_at`, `is_used`, `created_at`) - **never purged** except by account erasure (by identifier) | `otps`: e-mail/phone in clear (PII) | codes are HMAC at rest | yes | `otps`: e-mail, phone | see left | Medium; there is no queryable security-event store |
| H | **Notification / delivery errors** (OTP, guardian, panic) | B/C only, plus A when `auth.py` calls `log_error` ("Failed to send OTP to <mask>") | channel, outcome, masked recipient, error class/Twilio code (FG-041, FG-165); delivery results are not persisted | masked only | provider text and bodies never logged | `asctime` / A | - | as A or B | Medium |
| I | **Adjacent, not logs** (listed because they grow without bound and have no age policy): `alerts`, `app_install_events`, `behavior_events`, `network_activities`, `link_scans`, `wifi_scans`, `app_scans`, `scam_calls`, `ai_conversations`, `devices.last_seen`, `security_reports` | Postgres | user activity/telemetry (URLs, SSIDs/BSSIDs, caller numbers, package lists, conversation text) | **Yes, high** | n/a | per-table `*_at` | mostly user/device idx | **Deleted only at account erasure** (section 15 of the gaps register). A comment in `auth.py` (~line 831) says these tables "have their own retention policy": **no such policy exists in code or docs** | Product data, not forensic logs |
| J | **Backups** | `scripts/db_backup.py` (`--keep 14`), disabled workflow (14-day artifact) | full dumps of all of the above | Yes | encrypted when the workflow is used | - | - | rotation 14; **no backups exist yet / schedule disabled**; purge or erasure does not reach copies already made | Needed for recovery, outside log policy |

## 3. Can logs grow without bound? (FACT + arithmetic, no production volumes invented)

* **A (`error_logs`): yes between purges, and the purge is weak.**
  * Measured on the disposable local database with the real handlers: anonymous wrong-admin-token 401/429 row **152 B**
    (max 168), wrong-OTP 400 row **176 B**, anonymous 422 row **320 B**; one worst-case row built through the real
    `log_error` with incompressible data: message 4,025 + traceback 20,025 + extra 5,510 chars = **29,672 B**
    (tracebacks only exist for exceptions, not for anonymous 4xx). `pg_total_relation_size('error_logs')` was 65,536 B with one row (each of the 3 indexes 16,384 B); index
    growth per row at scale was not measured).
  * Ceiling set by configuration, not by traffic: the per-IP limiter allows `API_RATE_LIMIT` (100)/minute per peer
    address, i.e. at most **144,000 rows/day/source address** at 152-320 B = **~22-46 MB/day/source** of heap data
    (before indexes/WAL). Per-IP only, so it multiplies with the number of sources (FG-167 now ties the limiter to the
    real peer; a botnet is not limited by it). A single request can also create a row without authentication (401/400/422).
  * The purge: `DELETE ... RETURNING id` is **one unbatched statement** whose `RETURNING` set is fully materialised in
    the app (`fetchall()`); it runs **inside the startup sequence before the app serves** (Railway health-check timeout
    is 60 s in the deployment plan). With a large backlog this can lock the table, spike memory and delay/fail a deploy.
  * It runs **only at process start**: a process that stays up for months keeps rows past the setting until the next restart.
  * `LOG_RETENTION_DAYS` is an unvalidated `int` interpolated into the SQL text: `0` or a **negative value deletes every
    row** at the next start (verified read-only on the local test database: with `-5` the cutoff `NOW() - INTERVAL '-5 days'`
    lies in the future, with `0` it equals now; the purge itself was not executed).
  * **No test exercises `_cleanup_old_error_logs`** (grep over `tests/`).
* **B file log: bounded** (<= 80 MB), ephemeral.
* **C stdout:** depends on the host (unknown).
* **E, F audit tables: unbounded by design** (append-only; one row per admin action / warrior transition - low rate, but never deleted).
* **G `otps`: unbounded** (one row per OTP request, expired and used rows kept; holds e-mail/phone in clear).
  `refresh_token_uses` / `revoked_token_families` are bounded by token lifetime but only pruned when somebody refreshes.
* **I activity tables: unbounded until erasure.**
* **D mailbox: unbounded, outside the app; alert mails are un-throttled** (an error storm = a mail storm).

## 4. Security and privacy observations (FACT unless marked)

1. `client_ip` (personal data in many regimes) is stored in A and E and mailed in D, for the whole retention period, with no
   shorter horizon for IPs than for the rest of the row.
2. Erasure anonymises `error_logs.user_id` but not a user UUID embedded in `message` text, nor `client_ip`; the UUID
   remains meaningful through the kept tombstone row (pseudonymous, not anonymous).
3. No export/subject-access path for log data; the only read path is the shared-token admin API (`/admin/errors*`).
4. E and F survive erasure on purpose (accountability); the repository documents the open questions (audit-log retention
   period, reviewer-note scrubbing, backup retention of deleted data - gaps register section 15) but answers none.
5. Retention evidence is thin: no test for the purge, no metrics, no alert when it fails (a failure is a warning that
   says "possibly first run").
6. An attacker can create A rows at the limiter rate with no authentication (and D mails for 5xx), which turns A into
   a disk and mailbox consumption surface.
7. The `otps` table keeps contact data in clear indefinitely.
8. The repository makes **no compliance claim** and none is introduced here; which law/contract applies is for the owner.

## 5. Operational / storage considerations

* Per-row sizes above are the only measured inputs; real volume is unknown (no production traffic data in the repo; the
  staging DB holds 29 rows). Any sizing beyond "ceiling per source address" would be invention.
* Deleting by `created_at` is index-supported (`ix_error_logs_created_at`); large deletes still need batching and
  autovacuum headroom. Time partitioning would make dropping old data O(1) but needs a migration (not proposed now).
* The app runs a single replica today (in-memory limiter, local-disk uploads), so only one process runs the startup
  purge; with more replicas each start would run it (harmless but redundant) - a scheduled job needs a single-runner guarantee.
* Alert e-mails are the only copy that escapes any app-side deletion.

## 6. Options (RECOMMENDATION frame - periods are illustrative ranges, not choices)

Different categories need different horizons; one blanket number would be wrong for at least one of them.

| Category | Short operational | Medium investigation | Long forensic | Delete mode that fits |
|---|---|---|---|---|
| A `error_logs` rows | 14-30 days | 60-90 days (**current default 90 is the only value that exists in the project; it is a code default, not a documented owner decision**) | 180-365 days | Age-based **hard delete**, batched. Optional earlier step: **anonymise** `client_ip` (NULL or truncate /24, /48) after a shorter period than the row, so investigation of a pattern stays possible without keeping the address |
| A: noise at source (401/422/429, throttle hits) | do not persist, or sample/count | persist with short horizon | - | **Reduce at source** (aggregate counters instead of rows) is an alternative to retention |
| B file log | keep as is (<= 80 MB ring) | - | - | already self-limiting; ephemeral |
| C host/stdout | per host plan | - | - | cannot be controlled by the app; **needs a fact from the host** |
| D alert mails | - | - | - | cannot be enforced by the app; options: throttle/dedupe, drop IP/user id from mail body, mailbox rule |
| E `admin_audit_logs` | not suitable | 1 year | multi-year | **Retain** (accountability), **archive** rather than delete; consider pseudonymising `client_ip` after a period |
| F `warrior_audit_logs` | not suitable | 1 year | multi-year | **Retain/archive**; reviewer-note scrubbing policy needed |
| G `otps` | purge expired/used after 1 day-7 days | - | - | **Hard delete** (no investigative value once expired) |
| G token-state tables | keep until `expires_at` (already) | - | - | already pruned; add a periodic prune so they do not depend on refresh traffic |
| I activity/telemetry | owner product/privacy decision per table | | | outside FG-034 log scope; hard delete or aggregate (e.g. keep counts in `security_reports`) |
| J backups | align with the above: a deleted row persists in dumps up to the backup rotation (14 days when enabled) | | | state it in the privacy text; cannot be selectively purged |

**Recommended model (structure, not numbers):** tiered by category (A/G short, E/F long with archive), time-based hard
delete for A and G, earlier IP anonymisation as an option, E/F retained and archived, a statement for C/D/J, enforcement
in a scheduled maintenance job (section 9), measurable and tested.

## 7. Which layer should enforce retention (RECOMMENDATION)

| Layer | Fit |
|---|---|
| Startup hook in the web process (today) | Poor: not periodic, delays startup, untested, runs per replica |
| In-process background task | Possible but needs a single-runner guard (Postgres advisory lock) and shutdown handling |
| **Scheduled maintenance job** (a separate command in the repo, run by Railway cron/GitHub Actions/the operator) with batched deletes and an advisory lock | **Best fit now**: testable, observable, independent of web restarts, no schema change needed |
| Database-native (pg_cron, partition drop) | Strong for A at scale; needs extensions/migration; not available/verified on the host |
| Infrastructure logging (host retention, mailbox) | The only layer that can control C and D; must be configured outside the code |

## 8. What the repository already says about policy (FACT)

* `LOG_RETENTION_DAYS=90` default and the startup purge (no rationale recorded).
* Gaps register section 15: erasure table (`error_logs` anonymised; `warrior_audit_logs` retained) and "open policy
  decisions for the owner: audit-log retention period, whether reviewer notes need scrubbing, backup retention of deleted data".
* `ANDROID_RELEASE_AND_PLAY.md`: privacy policy / data-safety form are owner deliverables (not written).
* No statement of any legal retention duty, no privacy policy text, no compliance claim anywhere in the repository.

## 9. Decisions that need the owner

1. **Retention period per category** (A, G-otps, E, F, and an explicit statement for C, D, J) - or confirmation that 90 days for A stands.
2. **Is `client_ip` kept for the whole retention period or anonymised earlier** (and how: NULL vs truncation)?
3. **Hard delete vs archive for E and F**; where an archive would live and who may read it.
4. **Stop persisting high-volume low-value events** (401/403/422/429, throttle hits) as rows, or keep them with the short horizon?
5. **Alert e-mail policy**: throttling/dedupe and whether user id/IP belong in the mail body; who owns the mailbox retention.
6. **Host log retention (Railway)**: obtain the fact, accept it, or configure a drain.
7. **Backup retention for deleted/expired data** and what the privacy text will say.
8. **Where enforcement runs** (cron service / Actions / manual) and who is accountable for it.
9. **Scope**: do the activity tables in category I (no age policy at all) belong to this decision or to a separate one?
10. **Legal basis/regulatory duties** that fix a minimum or maximum (the repo has none; the owner or counsel must supply them).

## 10. Work required after approval (exact)

1. Settings with validation (positive ints, sane bounds, explicit "disabled" handling) per category, replacing the single
   unvalidated `LOG_RETENTION_DAYS`; a startup check that rejects 0/negative values.
2. A maintenance command (e.g. `python -m app.cli.purge_logs`) that: takes an advisory lock; deletes in batches
   (`WHERE id IN (SELECT id ... ORDER BY created_at LIMIT n)`), commits per batch, never materialises `RETURNING`, logs counts only; covers `error_logs`, expired/used `otps`, expired token-state rows; optional IP anonymisation step; dry-run mode.
3. Remove the startup purge or reduce it to a bounded, non-blocking call.
4. Policy for E/F: archive/export procedure or explicit "retain" statement; REVOKE UPDATE/DELETE on the audit tables if append-only is to be enforced.
5. Optional source-side reduction of persisted 4xx noise and alert-mail throttling.
6. Erasure alignment: decide whether `message` text containing the user UUID is rewritten or accepted as pseudonymous.
7. Tests (real PostgreSQL): boundary (exactly N days kept / N+1 deleted) using an injected clock or inserted timestamps, batching and idempotence, concurrent runners (lock), invalid settings, erasure interplay, IP anonymisation, no tokens/PII in the job's own logs, and a regression test for the current silent-failure path.
8. Documentation: retention table in the privacy text/data-safety form, operations runbook for the job, evidence updates.
9. **No migration is required for the minimum design** (time-based deletes use the existing `created_at` indexes). A migration would only be needed for partitioning, new columns (e.g. `anonymised_at`) or REVOKE-based append-only enforcement.

## 11. Risks of getting the period wrong (FACT-based reasoning)

| Too short | Too long |
|---|---|
| Incident or abuse investigation loses evidence before it is noticed (a slow credential-guessing campaign or a regression discovered weeks later) | Larger exposure if the database or a backup leaks: IPs, user UUIDs, masked identifiers stay readable longer |
| Admin accountability (E) and moderation accountability (F) lost; cannot answer "who disabled this account" | Privacy obligations/commitments in the (still unwritten) privacy policy may be breached; erasure promises weaken because rows and backups outlive them |
| Repeated-failure patterns (FG-166/FG-167 type) cannot be seen | Unbounded disk/vacuum cost and slow startup purge; mailbox and host copies grow outside control |
| A `0`/negative misconfiguration silently deletes everything at the next start (today's behaviour) | Larger blast radius of any scrubber miss (heuristic redaction) |

## 12. Evidence and limits of this audit

* Read: `logger_service.py`, `log_scrubber.py`, `error_handler.py`, `main.py` (startup purge), `access_log.py`, models
  (`error_log`, `admin_audit`, `refresh_token`, `user.OTP`, `cyber_warrior`, activity models), `account_erasure.py`,
  `auth.py` (erasure comment, `log_error` calls, refresh pruning), config, Dockerfile/`.gitignore`/`.dockerignore`,
  backup and Railway docs, the gaps register sections 2 and 15.
* Measured: row sizes and row counts on the disposable local test database (temporary test file, deleted afterwards;
  `git status` shows no change from this audit other than documentation).
* Not verified: real traffic volume, index growth at scale, Railway log retention/forwarding, mailbox retention, any
  behaviour on a deployed environment.
* No code, schema, migration, test, configuration or data was changed.
