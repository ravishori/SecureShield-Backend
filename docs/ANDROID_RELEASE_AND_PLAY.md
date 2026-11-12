# Android release build and Google Play readiness

## Build configuration (done)

| Item | State |
|---|---|
| Release signing | `android/app/build.gradle.kts` reads `android/key.properties` (git-ignored, with `*.jks`/`*.keystore`). Since 2026-11-13 a release build **fails** without it (no debug-key fallback); see `flutter_app/docs/ANDROID_RELEASE.md`. |
| R8 / resource shrinking | `isMinifyEnabled = true`, `isShrinkResources = true`, rules in `android/app/proguard-rules.pro` |
| Cleartext HTTP | Release: HTTPS only (`network_security_config.xml`, `cleartextTrafficPermitted=false`). Debug/profile override it so LAN dev servers still work. `usesCleartextTraffic="true"` was removed from the main manifest. |
| Backups | `android:allowBackup="false"` (the app stores encrypted evidence keys / tokens) |
| Backend URL | Pin at build time: `--dart-define=API_BASE_URL=https://<host>/api/v1`. Pinned builds skip LAN probing entirely (no start-up delay, no manual http override). |
| Start-up | Notification and scan-history init are bounded (5 s) and failure-tolerant; a failing optional step no longer blocks `runApp`. |

## Create the upload keystore (owner action - never commit it)

```bash
keytool -genkey -v -keystore ~/secureshield-upload.jks -keyalg RSA -keysize 2048 -validity 10000 -alias upload
```

Create `android/key.properties` (ignored by git):

```properties
storePassword=<store password>
keyPassword=<key password>
keyAlias=upload
storeFile=C:/secure/secureshield-upload.jks
```

Enroll in **Play App Signing** so Google holds the app signing key and the keystore above is only an upload key
(recoverable by Play support if lost).

## Build

```bash
flutter build apk       --release --dart-define=API_BASE_URL=https://<host>/api/v1
flutter build appbundle --release --dart-define=API_BASE_URL=https://<host>/api/v1
```

On the development machine used for verification, the Flutter SDK cache lacks `const_finder.dart.snapshot`
(icon tree-shaking fails with `IconTreeShakerException`). `flutter precache --force` fixes it; otherwise add
`--no-tree-shake-icons` (larger APK, functionally identical).

Outputs: `build/app/outputs/flutter-apk/app-release.apk`, `build/app/outputs/bundle/release/app-release.aab`.
Upload the **.aab**.

## Play Console readiness - what Google will look at

These are **product/policy decisions**, not code gaps, and must be answered by the owner before submission.

| Area | Finding | Action |
|---|---|---|
| Restricted permissions | `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_CALL_LOG`, `PROCESS_OUTGOING_CALLS` need the **Permissions Declaration Form**. Play only allows SMS/Call-Log for apps whose *core* function is default SMS/phone handler or a narrow set of exceptions. | Decide whether SMS/call-log interception is essential; if not, remove them (the message analyzer and OTP-vault paste/share flows work without them). `SEND_SMS` is not used by any feature and should be removed. |
| `QUERY_ALL_PACKAGES` | Needs a declared core-purpose justification (the app scanner qualifies as "security/antivirus" - declare it). | Fill the declaration. |
| `REQUEST_INSTALL_PACKAGES` | Not used by any feature. | Remove. |
| Foreground services | `SYSTEM_EXEMPTED`, `DATA_SYNC`, `SPECIAL_USE`, `MEDIA_PROJECTION` types need a stated use and a demo video. | Declare in Play Console. |
| VPN service | `BIND_VPN_SERVICE` requires the VpnService declaration. | Declare (local VPN for network monitoring; no traffic leaves the device). |
| Data safety form | App collects phone/e-mail, location (panic), evidence files, recordings, installed-app list, SMS content. | Complete the form; state encryption in transit (HTTPS) and the deletion path. |
| Account deletion | In-app deletion exists (`DELETE /auth/me`, full erasure) - required by Play. | Provide the web URL for deletion requests too. |
| Privacy policy | Required URL. Must describe the items above. | Owner to publish. |
| Target API | `targetSdk = flutter.targetSdkVersion` (Flutter 3.41 default). | Re-check against Play's yearly minimum before each release. |

## Verification record

* `flutter analyze`: no issues. `flutter test`: 19 passed.
* `flutter build apk --release` / `appbundle --release`: see `docs/SECURESHIELD_FEATURE_COMPLETION_MATRIX.md`
  for the result and the exact command that was used.
* Not done (needs the owner's keystore / Play account): signed upload, internal-testing track install.
