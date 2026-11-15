# Stage 1.6D-2 — Sensitive Alert Data Redaction

**Result: PASS WITH CONDITIONS**
- SMS-analysis alerts are now redacted before they reach the database, and the tests pass.
- The conditions are the other alert writers and the existing rows (section 6).

## 1. Audit of what was stored
Alert creation points: `message_analyzer.py` (SMS analysis, job offer, cyberbullying), `community_scam.py`, `scam_calls.py`, `link_scanner.py`, `app_scanner.py`, `app_monitor.py`, `wifi.py`, `alerts.py` (SOS).

In scope (SMS analysis):
- **`/message/analyze`** stored `extra_data.sender` and the alert message with the **raw sender**, which may be a personal phone number. It also stored a 100-character **message preview** with only URLs redacted. An OTP, account number, phone number, card number, UPI id or e-mail in those characters was persisted. The alert is listed to the user and can be e-mailed.
- **`/message/check-bullying`** stored the same kind of preview, and put `reporter_note` (free text) into the alert message unredacted.
- The job-offer alert stores no message content.
- **Logging:** the analyzer and registry validator log nothing that contains message or sender text (the registry failure path logs only the exception class, as of Stage 1.6D-1). `validate_sender` errors are not echoed.

Git context: `message_analyzer.py` and `log_scrubber.py` already had uncommitted earlier work. I changed only the alert lines in the router. `log_scrubber.py` was not edited.

## 2. Files changed
- New `app/services/alert_redaction.py`: `redact_sensitive_text`, `redact_message_preview` (100 characters), `redact_note` (200), `redact_sender`.
- `app/routers/message_analyzer.py`: the analyze and bullying alerts use these functions. The `redact_urls_in_text` import was replaced by them.
- New `tests/unit/test_alert_redaction.py` (55 tests).
- `tests/integration/test_sender_registry_rollback.py`: one added persistence test.
- Not changed: API response models, risk scoring, the shared verdict, encryption or access control, the registry data.

## 3. Redaction rules (applied in this order, then cut to the limit)
| Rule | Result |
|---|---|
| URLs | `[link: host]`, so the phishing host stays as evidence (existing helper) |
| E-mail | `b***@example.test` |
| UPI id (`name@bank`) | `[UPI ID]` |
| IFSC, PAN | `[IFSC]`, `[PAN]` |
| OTP, code, PIN, CVV next to a number of 4-8 digits (either order) | `[OTP]` |
| `a/c`, `account`, `acct` + 5-18 digits | `[ACCOUNT]` (a bank-masked `XX1234` tail stays) |
| 13-19 digit or 4-4-4-4 card numbers | `[CARD]` |
| Aadhaar-shaped 4-4-4 numbers | `[AADHAAR]` |
| Indian mobile and international numbers | `[PHONE ...NN]` (last two digits, like the log scrubber) |
| Other 9-18 digit runs | `[NUMBER]` |
| 5-8 digit numbers in a message that mentions OTP, code, PIN, password, login or verify (not after `Rs`, `INR`, `₹`) | `[CODE]` |

Sender: a personal phone number becomes `[PHONE ...NN]`. An alphabetic header such as `VM-SBIBNK-S` is a public registry value and is kept, because it is the evidence.

Properties: redaction runs on the whole bounded text (2,000 characters) before the cut, so a value cannot survive by straddling the limit. It is idempotent and never raises. On an unexpected internal error the result is `[redacted]`, never the raw text.

## 4. Before and after (synthetic data)
| Before | After |
|---|---|
| `Your OTP is 482913. Do not share it.` | `Your OTP is [OTP]. Do not share it.` |
| `Dear customer your A/c No 123456789012 is blocked, update KYC at http://bit.ly/x?t=SECRET1` | `Dear customer your A/c No [ACCOUNT] is blocked, update KYC at [link: bit.ly]` |
| `Use 482913 to login to your account` | `Use [CODE] to login to your account` |
| `Pay to rahul.s@okbank or 4111 1111 1111 1111 now` | `Pay to [UPI ID] or [CARD] now` |
| `Call +91 98765 43210 or mail bob@example.test` | `Call [PHONE ...10] or mail b***@example.test` |
| `A/c XX1234 debited Rs 5000.00 on 12-11-2026. Call 9876543210` | `A/c XX1234 debited Rs 5000.00 on 12-11-2026. Call [PHONE ...10]` |
| sender `+919876543210` | `[PHONE ...10]` |
| sender `VM-SBIBNK-S` | `VM-SBIBNK-S` (unchanged) |

## 5. Tests
- **Unit** (`tests/unit/test_alert_redaction.py`, executed): 55 tests.
  - OTP and account number variants, phone and payment identifiers, URLs, many values in one message, a value straddling the length limit.
  - False positives: amounts, dates, bank-masked tails and ordinary wording are not changed.
  - Missing and malformed input (None, empty, bytes, control characters, Cyrillic, a huge message), idempotency, and the internal-error placeholder.
  - Sender masking.
  - Persistence through the real router functions with a capturing session: no raw identifier in title, message or `extra_data`.
  - Scoring and the verdict equal the detector's own result on the raw text (+20 still applies for an unregistered header).
  - A low-risk message stores nothing.
  - The bullying alert is redacted.
  - No logging of message content.
- Full unit suite: **1500 passed, 3 skipped, 0 failed**. The connection guard recorded 0 attempts by tests. Ruff `--select F,E9` is clean.
- **Integration** (executed against local `secureshield_test`, in the rolled-back transaction): the module now has **18 passed**. The new test reads the persisted alert row back from PostgreSQL and finds only redacted values. Cleanup was verified afterwards: only `alembic_version` is non-empty.
- The older broad integration suite was not run.

## 6. Limitations, risks and rollback
- **Other alert writers still store raw identifiers:** `scam_calls.py` stores `caller_number` in the title, message and `extra_data`. `community_scam.py` stores the reported phone number. These are not SMS analysis, so I left them, but they need the same treatment (recommended next).
- **Existing rows:** alerts written before this change keep their unredacted previews. A one-off redaction of old `alerts.extra_data`/`message` would be a separate, approved data change. I did not touch any database rows.
- **Heuristics:** regex redaction is not perfect. A name, an address, or an account number written as words can survive, and an unusual format can be missed. A 5-8 digit number in a message that mentions "code" or "login" is masked even when it is harmless (documented, favours privacy).
- **Other places that handle message text:** the request is still sent to the API in full, the Flutter app shows a local notification with up to 100 characters of the message (Flutter was not touched), and FastAPI's 422 validation error echoes the submitted input to the caller. The global error logger already scrubs text via `log_scrubber`.
- **Rollback:** the change is code-only. Reverting `message_analyzer.py` to the previous alert lines and deleting `alert_redaction.py` restores the old behaviour. No schema or data change was made, and the API contract is unchanged.
