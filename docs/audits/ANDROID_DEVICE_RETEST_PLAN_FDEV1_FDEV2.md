# Android Retest Plan: F-DEV-2 and F-DEV-1

Device: OnePlus CPH2767, Android 16 / API 36. Build: debug, pinned with `API_BASE_URL` to a laptop-local backend (`adb reverse tcp:8000 tcp:8000`). Synthetic accounts only; OTP/e-mail/SMS captured locally (same harness as `ANDROID_DEVICE_VALIDATION_REPORT.md`). No production or Neon access, no real SMS or e-mail.
Status: **NOT YET EXECUTED.** Automated tests pass; device behaviour is unverified until this plan is run.

## Risk policy implemented (F-DEV-2)
| Source | Condition | Notification |
|---|---|---|
| Server verdict | high or critical | Yes |
| Server verdict | medium, low, safe, unknown | No (in-app result only) |
| Older server, no verdict | `risk_score` >= 70 | Yes |
| Server unreachable | >= 3 distinct keyword hits | Yes (offline fallback) |
| Server unreachable | fewer hits | No |

Medium does not interrupt the user: a notification is reserved for high risk. Changing that is a product decision.

## Preconditions
1. Install the new debug build over the old one. Backend launcher running (providers blanked). Log in as the synthetic user.
2. Settings > Apps > SecureShield AI > Notifications: allowed. In-app notification preferences: "Scam messages" ON.
3. Phone unlocked, app in foreground for R1-R4, then lock-screen variants.

## F-DEV-2 tests
| ID | Steps | Expected |
|---|---|---|
| R1 | Analyze a synthetic message the backend scores >= 70 (the earlier 70/100 message). | Alert "Possible scam: <type>" appears; text has no message content or digits; result screen still shows. |
| R2 | Lock the phone, repeat R1. | Lock screen shows no private content (visibility private); unlock shows the safe summary. |
| R3 | Analyze a message scoring 40-69 (suspicious). | No notification; in-app result says SUSPICIOUS. |
| R4 | Analyze a benign message (low/safe). | No notification. |
| R5 | Turn "Scam messages" OFF, repeat R1. | No notification; in-app result still shown. |
| R6 | Deny the OS notification permission, repeat R1. | No crash; in-app result shown. |
| R7 | Run R1 twice in a row. | One notification slot per fraud type (same id), not a growing stack. |
| R8 | Airplane mode, analyze a message with >= 3 scam keywords. | Friendly error snackbar plus offline-fallback alert. |
| R9 | Airplane mode, analyze a message with 0-2 keywords. | Error snackbar only, no alert. |
| R10 | Check logcat during R1-R9. | No stack trace; no message text, token or URL logged. |

## F-DEV-1 tests
| ID | Steps | Expected |
|---|---|---|
| S1 | Fresh synthetic account, open dashboard. | Gauge shows NOT ASSESSED (no number, no 100); chip "NOT ASSESSED"; reason text explains no scans or alerts yet; Security Score card says "Not assessed". |
| S2 | Stop the backend, pull to refresh. | Same state with the "could not load" reason; never 100/100. |
| S3 | Run a device scan or app scan so activity is recorded, refresh. | Numeric score and label (PROTECTED/FAIR/AT RISK) return; value matches the server `security_score`. |
| S4 | Generate an alert on the account, refresh. | Score drops accordingly; threat count updates. |
| S5 | Set font scale 2.0 on the dashboard in the not-assessed state. | No RenderFlex overflow in logcat. |
| S6 | Light and dark theme. | Not-assessed gauge and text are legible. |

Record PASS/FAIL/BLOCKED per row with the logcat line or UI dump as evidence, as in the original report. Do not mark any row PASS without executing it.
