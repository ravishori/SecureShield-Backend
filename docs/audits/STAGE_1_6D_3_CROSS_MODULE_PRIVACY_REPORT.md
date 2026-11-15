# Stage 1.6D-3 — Cross-Module Alert Privacy and Flutter Protection

**Result: PASS WITH CONDITIONS**
- Alert writers and Flutter notifications are fixed and tested, and nothing was modified in any database.
- The conditions are in section 6: historical rows and the remaining deliberate raw-data stores.

## 1. Git context first
Before editing: `community_scam.py`, `link_scanner.py`, `app_monitor.py` and the Flutter `message_analyzer_*` files already had earlier uncommitted work. I changed only the alert lines in those files. `scam_calls.py`, `wifi.py` and `notification_service.dart` were clean. Nothing was staged, committed or pushed.

## 2. Alert writers audited (backend)
| Writer | Raw data before | Action |
|---|---|---|
| `message_analyzer` `/analyze` and `/check-bullying` | sender, message preview, reporter note | **Fixed in 1.6D-2** |
| `message_analyzer` `/check-job-offer` | none (score and red flags) | none needed |
| **`scam_calls.py`** | caller number in title, message and `extra_data`; free-text detection reason | **Fixed**: `redact_sender`, `redact_note` |
| **`community_scam.py`** | reported phone number in message and `extra_data` | **Fixed**: `redact_sender` |
| **`wifi.py`** | SSID (may be a name or number) in title, message and `extra_data` | **Fixed**: `redact_note` |
| `link_scanner.py` | URL already stored redacted (`stored_url`) | none needed |
| `app_scanner.py`, `app_monitor.py` | app name and package id (not personal data) | none needed |
| `alerts.py` SOS (panic) | the user's typed message and GPS coordinates | **Left as is, deliberately**: the SOS alert exists to send them to the user's emergency contacts. Redacting would defeat it. Listed under risks. |

No alert writer exists outside `app/routers`; the services and the guardian outbox do not create `Alert` rows.

Deliberately not changed, because the data is the feature:
- the user's own `scam_calls.caller_number` record (needed to block the number);
- the `community_scam_reports.phone_number` row (what other users look up).

## 3. Files changed
- Backend: `app/routers/scam_calls.py`, `app/routers/community_scam.py`, `app/routers/wifi.py`. Each reuses `app/services/alert_redaction.py`, with no change to risk scoring or API contracts.
- Backend tests: new `tests/unit/test_alert_privacy_other_paths.py` (7 tests, plus a static guard that no alert writer takes a raw request phone, sender or SSID). One new test added to `tests/integration/test_sender_registry_rollback.py`.
- Flutter:
  - New `lib/core/services/notification_content.dart`.
  - `lib/core/services/notification_service.dart`.
  - `lib/features/message_analyzer/screens/message_analyzer_screen.dart` (the call site).
  - New `test/core/services/notification_content_test.dart`.

## 4. Flutter notification findings and fixes
- **Finding (High):** `showFraudAlert` took the analysed message and used its first 100 characters as the notification body and in the expanded text, with the matched keywords. On Android the notification was public by default, so an OTP, account number or phone number in an SMS could be shown on the lock screen, in the shade, or on a paired watch.
- **Fix:**
  - `showFraudAlert` now accepts only a scam category and a match count. The signature no longer has a `message` or keywords parameter, so the text cannot be passed by mistake.
  - Content comes from `buildFraudNotificationContent`: title "Possible scam: <category>", the body "Open SecureShield to review. Do not share OTP, PIN or bank details.", plus a strength line ("Several warning signs found").
  - `safeNotificationText` strips control characters and any run of 4 or more digits, and bounds the length. A 4-digit year is therefore masked too.
  - Every Android notification (fraud, fake app, banking, security) now sets `visibility: NotificationVisibility.private`, so a secure lock screen hides its content. This is the "private" behaviour of the plugin and depends on the user's lock-screen setting.
  - The analyzer screen passes only `category.label` and the match count.
- **Reviewed, unchanged:** the other three notification types contain app names, a fixed banking message and detector reasons, which are not message content.
- **Permissions and preferences:** `POST_NOTIFICATIONS` is declared and requested through the consent manager (`Permission.notification`). I found **no in-app preference** for notification content, so users cannot switch notifications off per category. This is a finding and not implemented here.
- **Message-analysis UI:** the result screen shows the analysis, which is the user's own request. The error snackbar still prints `Error: $e` (raw exception text), which can include a server address. This is noted but outside this stage.

## 5. Tests and results
- **Backend unit:** `tests/unit`: **1507 passed, 3 skipped, 0 failed**. The connection guard recorded 0 attempts by tests. Ruff `--select F,E9` on `app` and the new tests is clean.
- **Backend isolated PostgreSQL integration** (`secureshield_test`, rolled-back transaction, not the broad harness): **19 passed**.
  - The new test saves scam-call, community and Wi-Fi alerts to the real database and reads the rows back: no phone, OTP or account number in any title, message or `extra_data`.
  - The user's own scam-call and community records keep the number.
  - Cleanup verified: only `alembic_version` is non-empty afterwards.
- **Redaction regression:** the 55 tests from Stage 1.6D-2 are included in the unit run above.
- **Flutter:** `flutter test` **524 passed, 0 failed** (11 new tests). `flutter analyze`: **No issues found**.
  - The new tests cover the content builder, number stripping, bounds, and three source guards: `showFraudAlert` has no message parameter, the analyzer passes no message text, and every Android notification has private visibility.
  - I added no widget test for the analyzer screen. It needs the network client and the plugin, and the source guards cover the property that matters. A real device test of lock-screen behaviour has not been done.
- **Verification that nothing raw is persisted or notified:** by the backend row-level tests above, and by the Flutter content and source tests. Not verified on a device.

## 6. Historical data audit and remediation (no rows modified)
- **What exists:** alerts created before 1.6D-2 and 1.6D-3 may hold a raw sender, a message preview with OTPs or numbers, caller numbers, reported numbers and SSIDs. The local `secureshield_dev` snapshot taken in earlier stages showed 0 alert rows. I did not query any staging, Neon or production database, so how many exist there is **unknown**.
- **Recommended strategy (needs separate approval, not done):**
  1. **Count first, read-only:** per alert type, count rows whose `extra_data` or `message` match phone, 9-18 digit, OTP-keyword or UPI patterns.
  2. **Back up** the `alerts` table (a dump) and rehearse on a restored copy.
  3. **One-off redaction job:** run the same `app.services.alert_redaction` functions over `message`, `title` and the relevant `extra_data` keys (`sender`, `message_preview`, `caller_number`, `phone`, `ssid`), in batches inside a transaction, writing only rows that change. This reuses tested code and keeps the evidence wording.
  4. **Verify** with the step-1 queries returning 0, and spot-check by alert type.
  5. **Alternative** if rows are low-value: delete alerts older than a retention window instead of rewriting them.
  - Rollback: restore from the dump. No schema change is needed.
- **Related risk:** alert e-mails and logs written earlier may also contain the old content, and cannot be recalled.

## 7. Remaining risks
- Regex redaction is heuristic: words, names and addresses can survive, and a 5-8 digit number in a message that mentions "code" or "login" is masked even when harmless.
- The SOS alert still stores the user's message and location by design (sent to their emergency contacts).
- Local scam-call, community-report and Wi-Fi scan records keep the raw values they exist to provide.
- No notification-preference screen, and no device test of lock-screen behaviour.
- Error snackbars still show raw exception text.
- The Wi-Fi scan table keeps the raw SSID, and the app-risk alerts keep app names.
