# Stage 1.6D-4 — Flutter Privacy and UI Validation

**Result: PASS WITH CONDITIONS**
- The Flutter changes are built and covered by automated tests.
- **No device validation was performed.** Section 6 gives the manual Android test plan, and the conditions are in section 7.

## 1. Git context first
The Flutter repository already had about 50 modified or untracked files from earlier stages (F1, consent, verdict work, Stage 1.6D-3). I changed only the files listed below. Nothing was staged, committed or pushed, and no backend, database or API contract was changed. The Stage 1.6D-3 files were extended, not replaced.

## 2. Files changed (all under `flutter_app`)
- **New:**
  - `lib/core/utils/safe_error.dart`
  - `lib/features/message_analyzer/widgets/message_result_view.dart`
  - `lib/core/services/notification_preferences.dart`
  - `lib/core/providers/notification_preferences_provider.dart`
  - `lib/features/settings/widgets/notification_preferences_section.dart`
  - Tests: `test/core/utils/safe_error_test.dart`, `test/features/message_analyzer/message_result_view_test.dart`, `test/features/settings/notification_preferences_test.dart`
- **Modified:**
  - `lib/features/message_analyzer/screens/message_analyzer_screen.dart`
  - `lib/core/services/notification_service.dart`
  - `lib/features/settings/screens/settings_screen.dart`
  - The 19 files listed in section 3.
  - `test/core/verdict/safe_defaults_test.dart`: see section 4.

## 3. Safe error handling
- **Problem:** about 20 screens showed `'Error: $e'`, `'Failed: $e'`, `${e.toString()}` and similar, straight from the exception. A Dio exception text contains the full request URL, including query parameters, and often a server reply.
- **Fix:** `safeErrorMessage(error, prefix:)` returns understandable text for the cases users meet (offline, timeout, signed out, forbidden, not found, too many attempts, server trouble, malformed reply, other). It never contains the exception text, URL, token or body. `safeErrorSummary` and `logSafeError` log only the exception type and HTTP status, and only in debug builds.
- **Replaced in:**
  - Alerts, community scam, evidence, family, clone detector, link scanner, Wi-Fi scanner, VPN monitor (screen and service), screen recorder, remote detector, payment verifier, FIR draft, profile (two sites), profile details, call recording (provider and emergency share), message analyzer.
  - `qr_safety_service.dart`: the reason text no longer echoes the parse exception.
  - Existing `debugPrint('... $e')` diagnostic lines in other files were left, since they write only to the developer console in debug builds. They could be moved to `logSafeError` later.
- **Guard:** a source test fails if any `Text(`, `SnackBar(`, `errorMessage:`, `_error =` or `_showSnack(` line interpolates a caught exception. It found three more sites that my first search had missed, and passes after the fix.

## 4. SMS analyzer screen
`MessageResultView` replaces the old result block, and the old sender card was removed from the screen file.
- **Headline:** never "Message Appears Safe". With the shared verdict: LOW RISK, SUSPICIOUS, HIGH RISK, CRITICAL RISK or UNABLE TO VERIFY. Without it (older server): "No warning signs found", or "Suspicious Message!" when `is_safe` is missing or false.
- **Shown:** risk score "N / 100", confidence ("not rated" because the contract carries none), the reasons, registry evidence, "What this check cannot tell you" (the verdict's limitations), and "What to do next" (the verdict's actions, or fallback advice).
- **Sender states, each with its own label and caveat:**

| State | Label | Caveat |
|---|---|---|
| REGISTERED | Registered sender name | does not prove the message is genuine |
| UNREGISTERED | Not found in the TRAI registry | a warning sign, not proof of fraud |
| Registry unavailable (`lookup_status=unavailable`) | Sender check unavailable | says nothing about whether the sender is genuine or fake |
| UNKNOWN, no lookup | Sender not verified | based on wording only |
| PHONE_NUMBER | Sent from a personal phone number | banks normally use registered names |

- The category suffix (for example `-S`) and the registered entity are shown when present.
- **Existing test changed:** `safe_defaults_test.dart` asserted the headline "Message Appears Safe" for `is_safe: true`. That is the headline the task bans, so the test now expects "No warning signs found", and it also asserts that a missing `is_safe` still never reads as safe.

## 5. Notification preferences
- **Design:** four categories. Two are optional and have switches in Settings, Notifications: **scam message alerts** and **general security notices**. Two are **essential** and always on, shown but not switchable: **fake app alerts** and **banking safety alerts**.
- **Implementation:** `NotificationCategory`, a `SharedPreferences`-backed store, a Riverpod `StateNotifier` (the existing pattern, like the theme provider), and `NotificationService` checks the preference in `showFraudAlert` and `showSecurityWarning`. Defaults are enabled, and a storage failure also means enabled, so failing quiet never hides a warning.
- **Permissions:** none requested. The code never calls a permission request, and a test asserts this. Android's own notification permission stays an OS-level setting, and the screen text says so. In-app analysis results are unaffected by turning notifications off.

## 6. Test results
- `flutter analyze`: **No issues found**.
- `flutter test`: **548 passed, 0 failed**. This is the whole suite, including earlier stages (it was 524 before this stage).
  - New: 24 tests (11 for the result view, 5 for safe errors, 8 for preferences), plus the updated safe-defaults test.
  - The new widget tests cover the registered, unregistered, registry-unavailable, not-verified and phone-number senders, the headline rules, the score, confidence, limitations and next actions.
- Backend: no backend code or contract changed, so I did not rerun backend tests this stage. The last results stand (1507 unit passed, 19 integration passed).

## 7. Manual Android device test plan (NOT performed)
No device or emulator was used, so none of the following is validated. Use a debug build and synthetic data only: OTP `482913`, account `123456789012`, phone `9876543210`.
1. **Private lock-screen notification.**
   - Set Android Settings, Lock screen, "Hide sensitive content", then lock the phone.
   - Analyse this message: `URGENT your account 123456789012 is blocked. Share OTP 482913 now, call 9876543210` (use the scam wording that triggers an alert).
   - Pass: the lock screen shows no message text and no digits. The shade, once unlocked, shows only "Possible scam: <category>" and generic advice. Repeat with "Show all notification content" and confirm the text never contains the message or numbers.
2. **Smartwatch.** If a watch is paired, repeat step 1. Pass: only the generic title and body appear. Mark "not tested" if there is no watch.
3. **Permission denied.** Deny the notification permission (Android 13+), then run an analysis. Pass: no crash, the in-app result still appears, and no notification is shown.
4. **Categories disabled.**
   - Turn off "Scam message alerts" and analyse a scam message. Pass: no notification, and the result still shows.
   - Turn off "General security notices" and trigger an app risk. Pass: no notice.
   - Confirm "Fake app alerts" and "Banking safety alerts" cannot be switched off and still notify.
   - Kill and reopen the app, and check the choices persist.
5. **Background and foreground.** Analyse, background the app, trigger an alert, and tap the notification. Pass: the app opens normally, with no crash and no message text in the payload shown.
6. **Result screen.** Analyse with the senders `VM-SBIBNK-S` (registered), `VM-ZZQQXX-S` (not found), and none. With the backend registry stopped or unreachable, confirm "Sender check unavailable". Pass: each state shows its own label and caveat, and the headline is never "Appears Safe".
7. **Error messages.** Switch on airplane mode and run a scan or analysis. Pass: "No internet connection…" with no URL or code.
Record device model, Android version, results and screenshots for each case.

## 8. Remaining limitations
- No device validation; Android visibility "private" depends on the user's lock-screen setting, and a smartwatch may show what the phone shows.
- Widget tests cover the result view and the settings section, not the whole analyzer screen against a live backend (the existing safe-defaults test does render the screen with fake responses).
- Confidence is always "not rated", because the shared contract carries none.
- About 40 `debugPrint` diagnostics still print the raw exception in debug builds only.
- Preferences are stored on the device only and are not synced.
- The four revisions `v7w8…`, `w8x9…`, `x9y0…`, `y0z1…` on the backend remain untracked.
