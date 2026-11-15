# Stage 1.6C — SMS Analyzer Integration Audit

**Verdict: READY WITH CONDITIONS**

Audit only. No application code was changed, FastAPI was not started, nothing was seeded, migrated, committed or pushed, and no secrets were read.

Evidence comes from two sources:
- Source code was read statically.
- Direct `validate_sender` calls were made through a **read-only** session as the runtime role `secureshield_dev_app`. They used local `secureshield_dev` (localhost:5432, `current_database()` confirmed), and the transaction was rolled back.

Integration tests were **not executed**, because they need a separate test database. Anything below marked "executed" refers only to those read-only lookups.

## 1. Architecture and execution trace
```
Flutter MessageAnalyzerScreen (StatefulWidget)
  -> MessageAnalyzerApi.analyzeMessage  POST /message/analyze {message_text, sender?, use_ai}
Backend analyze_message (app/routers/message_analyzer.py:235)
  1. analyze_message_signals(text)  -> pattern score, category, patterns, signals   (deterministic)
  2. ai_result defaults to the pattern analysis; Claude is called only if use_ai and ai_enabled()
  3. combined_risk = max(pattern score, risk-level score of ai_result)
  4. if request.sender: validate_sender(sender, db)  [sms_header_validator.py]
        parse_sender_id -> upper-case, split "XY-HEADER" on the first "-"
        blank -> UNKNOWN; digits>=7 -> PHONE_NUMBER; else SELECT ... WHERE upper(header)=:x LIMIT 10
        -> REGISTERED / UNREGISTERED
     UNREGISTERED: +20 and a red flag; PHONE_NUMBER: +10 and a red flag
  5. combined_risk >= 50 -> an Alert row (sender and a 100-character preview stored) + commit
  6. response: MessageAnalyzeResponse {risk_*, red_flags, sender_validation, verdict}
        verdict = safe_verdict(from_message, pattern_score, signals, sender_verdict)  [scam_verdict_adapters.py:401]
Flutter: _buildMessageResult shows the header, _SenderValidationCard, analysis, action and red flags.
```
Also: `POST /message/validate-sender` (typed body, 400 on blank) and `/extract-screenshot` (Claude vision, AI-gated).

## 2. Files and functions inspected
- Backend:
  - `app/routers/message_analyzer.py`: `analyze_message`, `validate_sender_id`, the schemas (lines 54-128)
  - `app/services/sms_header_validator.py`: `parse_sender_id`, `is_phone_number`, `validate_sender`
  - `app/services/scam_verdict_adapters.py`: `from_message` (lines 401-475) and the boost constants (line 38)
  - `app/schemas/scam_verdict.py`
  - `app/services/url_privacy.py`: `redact_urls_in_text`
  - `app/database.py`: `get_db`
  - `app/models/sms_sender_registry.py`
  - `tests/integration/test_message_analyzer_api.py`
  - `tests/unit/test_scam_verdict_adapters.py`
- Flutter:
  - `lib/features/message_analyzer/message_analyzer_api.dart`
  - `lib/features/message_analyzer/screens/message_analyzer_screen.dart` (`_analyzeMessage`, `_buildMessageResult`, `_SenderValidationCard`)
  - `lib/features/scam_hub/scam_hub_provider.dart`
  - `test/` (listing only)

## 3. Backend integration status
| Question | Finding |
|---|---|
| Is `validate_sender` called? | **Yes**, at `message_analyzer.py:268`, and only when a non-empty `sender` is supplied. |
| Header extracted correctly? | For `XY-HEADER`, bare headers, and trimmed or lower-case input, yes. **Not for TRAI category suffixes (see F1).** |
| Does the sender verdict reach the response? | **Yes**: `sender_validation` plus `verdict.evidence` entries with source `registry:trai_sender`. |
| Does it affect risk scoring? | Yes: UNREGISTERED +20, PHONE_NUMBER +10, REGISTERED 0 (positive evidence only). The router and the adapter use equal constants, and a unit test compares them. |
| Warning retained? | Yes: the red flag, the `UNREGISTERED` detail ("could indicate a spoofed or fraudulent sender ID") and the `sender_not_registered` evidence. |
| Missing or malformed sender | Missing: skipped, with the limitation "No sender was supplied". Blank string via `/analyze`: `""` is skipped. `"   "` goes to `validate_sender` and returns UNKNOWN, giving the limitation "could not be verified". Over 50 characters: rejected (422). |
| Provider or database failure | **No fallback**: see F3. |

Executed lookups, read-only (verdict and parsed header):

| Input | Verdict |
|---|---|
| `AD-HDFCBK` | REGISTERED (header `HDFCBK`) |
| `VM-SBIBNK` | REGISTERED |
| `V-SBIBNK`, `-SBIBNK` | REGISTERED |
| `VKSBIBNK` (no hyphen) | UNREGISTERED (header `VKSBIBNK`) |
| `98765` | UNREGISTERED (short digits are looked up, not treated as a phone number) |
| `+91 98765 43210` | PHONE_NUMBER |
| `x' OR 1=1 --` | UNREGISTERED with no error, so the query is parameterised |
| Cyrillic-lookalike `СBIBNK` | UNREGISTERED (a spoofing lookalike is not accepted) |
| **`VM-SBIBNK-S`, `VM-SBIBNK-T`, `AD-HDFCBK-P`** | **UNREGISTERED** (headers `SBIBNK-S`, `SBIBNK-T`, `HDFCBK-P`) |

The registry holds no headers with a hyphen, so these suffixed forms can never match.

## 4. Flutter integration status
- **State management:** this screen is a plain `StatefulWidget` with a `Dio` API wrapper, not Riverpod. Riverpod is used elsewhere, for example `scam_hub_provider.dart`.
- **Request:** sender is optional and trimmed. The response is parsed as a raw `Map`.
- **Display:** `_SenderValidationCard` renders REGISTERED (green, "TRAI Registered"), UNREGISTERED (red, "Not in TRAI Registry"), PHONE_NUMBER (amber), and other cases as grey "Unknown Sender". It shows entity, network and the backend `verdict_detail`.
- **Gaps:**
  - The message screen **does not render the shared `verdict`** or its `limitations`, so "registered does not prove the message is genuine" never appears here. The Scam Hub does use `analyzeMessageWithVerdict`.
  - The headline is "Message Appears Safe" whenever `is_safe` is true. With AI off, that is simply pattern score below 40, which overstates what is known.
  - Errors show `'Error: $e'`, the raw exception text, in a snackbar.
  - There is no offline analysis fallback: the local `FraudKeywordEngine` result is used only to trigger a notification, not shown when the API fails.
  - The local fraud notification includes up to 100 characters of the message.
- **Tests:** none found for this screen or `_SenderValidationCard`. There are verdict contract tests in `test/core/verdict/`.

## 5. Security and correctness findings
| ID | Severity | Finding |
|---|---|---|
| **F1** | **High (correctness)** | TRAI category suffixes (`-S`, `-T`, `-P`, `-G`), commonly shown on Indian sender IDs, make legitimate senders `UNREGISTERED`: **+20 risk, a red flag and a spoofing warning on genuine bank SMS**. Whether real devices show these suffixes is not provable from this repo, but the parser splits only on the first hyphen and the registry has no suffixed headers. Needs a decision and a normalisation rule. |
| F2 | Medium (privacy) | An Alert row (risk at or above 50) stores the full `sender` and a 100-character message preview. Only URLs are redacted, so an OTP, an account number or a phone number in the first 100 characters would be stored, and alert e-mails may carry it (see `error_log_retention.py` notes). Add OTP and number redaction. No logging of message content was found in the router or validator. |
| F3 | Medium (resilience) | `validate_sender` is not wrapped. If the database is unavailable, `/analyze` returns 500 and loses the pattern analysis already computed. A safe fallback is to set `sender_verdict=UNKNOWN`. |
| F4 | Medium | The user-facing `UNREGISTERED` text says "could indicate a spoofed or fraudulent sender ID. Do not follow any instructions". It is a heuristic, and it also fires for wrong-format senders such as F1. It is not marked as inference, and no confirmed-fraud status is set, which is correct. |
| F5 | Low | `PHONE_NUMBER` needs 7 or more digits. Short numeric strings go to the registry (`8` is registered), as per TRAI data. |
| F6 | Low | The same boost constants are duplicated in the router and the adapter, kept equal by a test. The legacy `risk_score` can differ from `verdict.risk_score` once AI is on, by design. |
| F7 | Info | `Evidence` versus inference: the structured verdict separates evidence (registry match) from `limitations`. The legacy fields (`explanation`, `red_flags`) do not. |
| F8 | Info | AI output cannot override deterministic evidence in the shared verdict, which is built from pattern analysis only. In the legacy fields, AI can raise `risk_score` (`max`) and sets `is_safe`, `explanation` and `action`. AI is currently off. |
| F9 | Info | The registry query is parameterised (executed injection input returned UNREGISTERED), and uses the functional index. |

## 6. Test coverage and gaps
| Scenario | Existing | Gap |
|---|---|---|
| Registered sender through the full analyzer | `test_message_analyzer_api.py` posts `VK-SBIBNK`, but the integration database is empty, so no REGISTERED path | **No test** with a seeded registry |
| Unregistered through the analyzer | Adapter unit tests (+20, evidence) | No end-to-end test |
| Unknown / blank | Adapter test; `/validate-sender` blank returns 400 | No `/analyze` test with `"   "` |
| Phone-number sender | Sender `9876543210` used in the alert test | No assertion of the +10 or red flag |
| Missing sender | Adapter limitation test | OK at the unit level |
| Malformed input | Bounds tests (long text, 51-character sender) | None for suffixes (F1) |
| Database unavailable / lookup failure | None | **Missing** (F3) |
| Risk-score consistency, router versus adapter | `test_sender_registry_results_adjust_the_score_like_the_router_does` | Does not cover the combined AI path |
| Flutter rendering | None for the card or the screen | **Missing** |

I executed no integration tests. The unit suite was last run in Stage 1.6B-4 (1405 passed).

## 7. Prioritised remediation plan
1. **F1:** decide and implement suffix handling, and add tests: strip a trailing `-S/-T/-P/-G`, or look up both forms. Add registry-backed tests (`SBIBNK`, `IOCXRP`, the suffixed forms).
2. **F3:** catch lookup errors and fall back to UNKNOWN with a limitation, plus a failing-DB test.
3. **F2:** redact digits and OTP-like patterns in the stored preview and in `extra_data`, and review what is e-mailed.
4. **Flutter:** render `verdict.limitations`, and soften "Appears Safe". Show an offline or local fallback and a friendly error message. Add widget tests for the card.
5. Add integration tests that run against a seeded local test database (a separate `TEST_DATABASE_URL`, not `secureshield_dev`).

## 8. Recommended next milestone
**Stage 1.6D:** fix F1 and F3 with tests, as the smallest change that removes false fraud warnings and the outage mode. Then F2, then the Flutter display work.

## Conclusion
**READY WITH CONDITIONS.** The registry is wired end to end, parameterised, and the sender evidence reaches both the legacy response and the shared verdict, without ever labelling a sender as confirmed fraud or a registered sender as safe. The conditions are F1 (false UNREGISTERED on suffixed senders), F3 (no fallback), and the missing registry-backed and Flutter tests.
