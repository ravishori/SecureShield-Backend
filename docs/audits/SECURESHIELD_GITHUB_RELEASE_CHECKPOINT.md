# SecureShield — GitHub Release Checkpoint (Phase 2, approval gate)

**Status: commits created locally and approved for push to the staging candidate branches (execution record in section 12).**
This update covers the approved fixes (Ruff errors, formatting, registry file, logical commit groups) and the remote-branch assessment. `start.bat`, environment files, backups and generated artefacts are excluded.

## 1. Before and after Git state
| | Backend | Flutter |
|---|---|---|
| Repository | `ravishori/SecureShield-Backend` (private) | `ravishori/SecureShield-Frontend` (private) |
| Branch | `staging/candidate-2026-11-13` | `main` (local) |
| HEAD (unchanged) | `15f5ea6064e8977e6dcbaa9a51ada8192948561a` | `815cbd975a1e227c0733569ed3316c0e4d34887b` |
| Remote tip | `origin/staging/candidate-2026-11-13` = `15f5ea6` (local equals remote) | `origin/main` = `6a191b5` |
| Staged | 0 before, 0 after | 0 before, 0 after |
| Modified, tracked | 84 before, 84 after | 43 before, 43 after (**byte-identical**, patch checksum unchanged) |
| Untracked | 102 before, 102 after (same set) | 65 before, 65 after (same set) |
| Diff size (tracked) | +3783 / −819 before, +3866 / −818 after (formatting) | +1144 / −574, unchanged |

**Preserved pre-change state** (outside both repositories, in the session scratchpad `...\scratchpad\prechange\`): full binary patches of both tracked diffs, status and untracked lists of both repositories, the 50 backend files as they were before formatting (`backend_pre_format_files.zip`), and the same files after the lint fixes and before formatting (`backend_post_lint_pre_format.zip`). Nothing was reset, cleaned, stashed or overwritten.

## 2. What changed in this phase (backend only; Flutter untouched)
1. **Ruff errors fixed (3 reported, plus 1 exposed by formatting):**
   - `tests/unit/test_migration_guard.py`: two one-line `E701` statements split.
   - `tests/unit/test_model_schema_contract.py`: variable `l` renamed (`E741`).
   - `tests/integration/test_sender_registry_rollback.py`: a lambda that the formatter had separated from its `# noqa` became a `def` (`E731`).
2. **`ruff format` applied** to the 50 files CI would reformat: 20 in `app`, 3 in `scripts`, 27 in `tests`. 18 are tracked files with your earlier uncommitted work, and 32 are new files.
3. **Review of the 50 formatting changes:** each file was parsed before and after and the syntax trees compared (docstring whitespace normalised). **49 of 50 are identical in structure.** The one difference is the intended lambda→`def` edit in the rollback test.
4. **One test made robust to formatting:** `tests/unit/test_script_target_guards.py` searched script source for the literal text `assert_script_target(admin_url`. The formatter wrapped that call across lines, which broke two assertions (a real regression, caught by the unit run). The test now compares source with whitespace removed, so it asserts the same order (guard before first connection) and is immune to line wrapping. No script behaviour changed.

## 3. CI-equivalent results (executed in this phase)
| Check | Result |
|---|---|
| `ruff check app tests scripts` (CI gate, ruff 0.9.4) | **All checks passed** |
| `ruff format --check app tests scripts` | **258 files already formatted** |
| `ruff check app tests --select E9,F63,F7,F82` | passed |
| Backend unit suite | **1507 passed, 3 skipped, 0 failed**; 0 connection attempts by tests |
| Backend rollback integration module on local `secureshield_test` | **19 passed**; afterwards only `alembic_version` is non-empty and 0 fixture rows remain |
| Flutter `analyze` and `test` | **No re-run needed: no Flutter file changed** (byte-identical to the last run: analyze clean, **548 passed**) |
| `alembic heads` | single head `y0z1a2b3c4d5` |

**Not executed (limitations):**
- the broader backend integration suite (it migrates and truncates, not authorised), so many new or modified integration files are unverified here;
- Kotlin unit tests;
- any device test.

## 4. Secret and artefact findings
- No secret scanner is installed, so I used my own regex scan (keys, tokens, JWTs, database URLs with passwords, Neon hosts, assigned secrets, keystore passwords) over all added lines and untracked files. A pass after formatting found:
  - **Flutter: 0 hits.**
  - **Backend: 82 pattern hits, none a real secret.** All 46 database URLs with a password part use placeholders (`SENTINEL-PW`, `YOUR_..._PASSWORD`, `u:pw` and similar), and the classifier found 0 real-looking passwords. The only other hits are the literals `check-only` and `SENTINEL-PW` and the production endpoint identifier in test fixtures.
- **`config/production_endpoints.txt` (approved):** verified identifiers only. Its non-comment lines are two Neon endpoint ids (`ep-cool-silence-…`, `ep-small-tooth-…`) and one database-name line (`database:SecureShieldDB`). It has no URL, user, password, token or wildcard. A search of the file for `password`, `postgres`, `://`, `@`, `token` and `secret` finds only the explanatory comment that forbids them.
- **Excluded and confirmed ignored or held back:** `start.bat` (held back by your instruction, left untracked), `.env`, `.env.local`, `.env.test`, `.env.phase1b-backup`, ` - Copy.env`, `backups/` (the pre-seed dump), `.venv`, caches, `__pycache__`, `.railway/README.md`; Flutter `.dart_tool/`, `.idea/`, `android/.gradle/`, `.kotlin/`, `local.properties`. No keystore, `key.properties`, APK/AAB, dump or log is in either change set.
- Reminder: `D:\tmp\test_db_url.txt` (outside both repositories) holds the test database credential. It is never committed. Please delete it when finished.

## 5. Remote branch assessment (after `git fetch`; read-only)
### Backend
- `origin/main` = `8fcb5af`; `staging/candidate-2026-11-13` is **95 commits ahead** of main and has nothing main lacks (a clean fast-forward relationship). Local equals remote at `15f5ea6`, so the new commit pushes as a **fast-forward, with no force needed**.
- `staging/railway-snapshot`: local `a91c79a`, remote `976ce42` (the remote has moved). It is 18 commits ahead of main. This is the only branch the deploy workflow accepts, and it is **not** the candidate branch. I did not touch it.
- `cursor/fix-env-otp-delivery` (`ad07e27`): 4 commits ahead of main, unrelated.
### Flutter
- **Local `main` (`815cbd9`) is 23 commits ahead of `origin/main` (`6a191b5`), and the remote has nothing local lacks.** The remote still shows only the first two commits ("Initial frontend commit", "Updated SecureShield frontend"). Pushing any branch from here publishes those 23 earlier commits as well as the new one.

## 6. Do pushes trigger deployment?
- **Backend:** `backend-ci` runs on pushes to `main` and `staging/**` and on pull requests. It runs tests and lint only. `deploy-staging` runs only on `workflow_dispatch` (manual), only for the exact branch `staging/railway-snapshot`, behind a `staging` environment approval, and it refuses candidate branches. **Pushing `staging/candidate-2026-11-13` triggers CI only, with no deployment through GitHub Actions.**
- **Caveat I could not verify:** Railway may also auto-deploy from a GitHub-connected branch (configured in Railway, not in the repository). The repository shows no deploy hook (0 webhooks). Please confirm in Railway that the service is not linked to `staging/candidate-*` or `main` before pushing.
- **Flutter:** `flutter-ci` runs on pushes to `main` and `release/**`, and on pull requests. After tests, its `release` job runs for pushes to `main` or `release/**`. It builds a signed Android bundle, needs the `android-release` environment approval, and needs the signing secrets. **A direct push to `main` would therefore start the release pipeline** (it waits at the approval gate). Pull-request runs do not run `release`. A `staging/**` branch matches no push trigger, so it triggers nothing until a pull request is opened.

## 7. Proposed push targets
- **Backend:** the current branch `staging/candidate-2026-11-13` (fast-forward, CI only). No change to `main`.
- **Flutter:** do **not** push to `main`. Create **`staging/candidate-2026-11-16` from the current local `main` plus the new commits**, push it, then open a pull request into `main`. The pull request runs `analyze` and `test` without the release job. The 23 earlier local commits come with it, so the pull request will be large; review it before merging. Avoid names starting with `release/`, which would run the release job.

## 8. Logical commit groups (not created)
Each repository gets the groups below, in order. Because later groups depend on earlier ones, intermediate commits may not pass CI on their own; the tip of the push is what CI checks. If you want every commit green, merge groups instead.

Backend (185 files; `start.bat` excluded):
1. **Database identity safeguards, config precedence and operator scripts**: 36 files.
2. **Alembic revisions v7w8..y0z1 and ORM reconciliation**: 21 files. **All four revisions are in this single commit, in dependency order** (`v7w8` → `w8x9` → `x9y0` → `y0z1`, parent `u6v7`, already tracked).
3. **Identity binding, consent, privacy, guardian outbox, rate limits, AI gate and retention**: 77 files.
4. **Scam verdict contract, SMS registry/analyzer fixes and alert redaction**: 24 files.
5. **Audit reports, runbooks and release documentation**: 27 files (includes this report).

Flutter (108 files):
1. **Android app-monitor native store, lifecycle and policy (Kotlin plus JVM tests)**: 14 files.
2. **Shared scam-verdict model, Scam Hub and message-analysis result**: 28 files.
3. **Identity, consent, privacy and auth screens**: 37 files.
4. **Private notifications, preferences and safe error handling**: 24 files.
5. **App wiring and dependencies** (`main.dart`, router, constants, `pubspec.yaml`/`pubspec.lock`): 5 files.

Commit-message style: `feat(...)`/`fix(...)`/`docs(...)` with a short body, each ending with the attribution line required for this session. The exact file lists per group follow in section 11.

## 9. Outstanding risks
- **Unverified integration tests:** many new or modified backend integration files have not been executed. CI will run them on a blank database, so failures may show there first.
- **No Kotlin test run and no device validation** in this checkpoint.
- **Flutter history:** 23 commits have never been pushed, and the pull request will contain them all.
- **Staging migrations:** four new revisions (and the ones before them) have never run on staging, Neon or production. The Flutter app needs backend fields (`verdict`, `lookup_status`) that exist only once this backend is deployed, and deployment is a separate approved step.
- **Railway auto-deploy** from GitHub is unverified (section 6).
- **No real secret scanner:** my scan covers common patterns only. Run `gitleaks` before pushing if you can.
- **Line endings:** Git warns that some files change CRLF/LF on commit. Content is unchanged, but diffs may look larger.
- **Production endpoint ids** in tests and `config/production_endpoints.txt` are now in a private repository.
- **Reformatting of your earlier work:** 18 tracked files had formatting-only changes applied, verified structurally identical, but the diff for those files is larger than the edit itself.
- Earlier stage caveats (historical alert rows, notification behaviour on devices, the heuristics in redaction) still apply.

## 10. After your approval
I will stage only the approved groups, create the commits (no amend, no force), verify them locally (`git show --stat`, secret scan on the staged diff, rerun of the CI-equivalent checks), push the backend branch and the new Flutter staging branch, and record the remote hashes here. I will not open or merge a pull request unless you ask.

**Final status: READY FOR COMMIT APPROVAL.**

## 11. Exact file lists by commit group
### Backend

### 1. Database identity safeguards, config precedence and operator scripts (36)
```
.env.example
alembic/env.py
app/cli/check_rate_limit_config.py
app/cli/show_database_target.py
app/config.py
app/database.py
app/db_identity.py
app/db_url.py
app/migration_guard.py
app/startup_checks.py
config/production_endpoints.txt
docs/LOCAL_DEVELOPMENT.md
docs/database/STAGE_1_2_LOCAL_DATABASE_SETUP.sql
scripts/db_backup.py
scripts/db_restore_check.py
scripts/e2e_local_server.py
scripts/migration_rehearsal.py
scripts/premigration_report.py
scripts/seed_sms_registry.py
tests/unit/conftest.py
tests/unit/test_config_behaviour.py
tests/unit/test_database_engine.py
tests/unit/test_db_identity.py
tests/unit/test_db_identity_hardening.py
tests/unit/test_db_url_normalization.py
tests/unit/test_env_precedence.py
tests/unit/test_final_corrections.py
tests/unit/test_local_environment_setup.py
tests/unit/test_migration_guard.py
tests/unit/test_neon_migration_script_guards.py
tests/unit/test_production_database_name.py
tests/unit/test_production_registry.py
tests/unit/test_retention_gate.py
tests/unit/test_script_target_guards.py
tests/unit/test_seed_registry_guard.py
tests/unit/test_startup_checks.py
```

### 2. Alembic revisions v7w8..y0z1 and ORM reconciliation (21)
```
alembic/versions/v7w8x9y0z1a2_identity_binding.py
alembic/versions/w8x9y0z1a2b3_consent_records.py
alembic/versions/x9y0z1a2b3c4_app_monitor_sync_and_guardian_outbox.py
alembic/versions/y0z1a2b3c4d5_sms_header_upper_index_and_audit_comment.py
app/models/__init__.py
app/models/app_install_event.py
app/models/behavior_event.py
app/models/clone_report.py
app/models/community_scam.py
app/models/cyber_warrior.py
app/models/elderly_config.py
app/models/emergency_contact.py
app/models/guardian_outbox.py
app/models/pending_registration.py
app/models/sms_sender_registry.py
app/models/user.py
app/models/user_consent.py
docs/audit/f19_stage2a_review.sql
docs/audit/f1_identity_binding_review.sql
docs/audit/g_consent_review.sql
tests/unit/test_model_schema_contract.py
```

### 3. Identity binding, consent, privacy, guardian outbox, rate limits, AI gate and retention (77)
```
app/cli/admin_accounts.py
app/cli/bootstrap_admin.py
app/cli/purge_error_logs.py
app/cli/purge_link_scans.py
app/main.py
app/middleware/error_handler.py
app/routers/ai_coach.py
app/routers/app_monitor.py
app/routers/auth.py
app/routers/elderly_protection.py
app/routers/family.py
app/routers/identity.py
app/routers/link_scanner.py
app/routers/privacy.py
app/schemas/app_monitor.py
app/schemas/auth.py
app/schemas/elderly_protection.py
app/schemas/link_scan.py
app/schemas/security_report.py
app/services/account_erasure.py
app/services/ai_gate.py
app/services/ai_service.py
app/services/consent.py
app/services/device_service.py
app/services/error_log_retention.py
app/services/gsb_service.py
app/services/guardian_alerts.py
app/services/guardian_outbox.py
app/services/identity.py
app/services/link_scan_retention.py
app/services/log_scrubber.py
app/services/logger_service.py
app/services/notifications.py
app/services/otp_codes.py
app/services/otp_service.py
app/services/smtp_config.py
app/services/threat_analyzer.py
app/services/urlhaus_service.py
app/services/user_rate_limits.py
tests/conftest.py
tests/integration/conftest.py
tests/integration/test_account_deletion_api.py
tests/integration/test_admin_users_api.py
tests/integration/test_ai_coach_api.py
tests/integration/test_ai_containment_api.py
tests/integration/test_app_monitor_clone_api.py
tests/integration/test_app_monitor_sync_idempotency_api.py
tests/integration/test_auth_hardening_api.py
tests/integration/test_bootstrap_admin.py
tests/integration/test_check_user_enumeration_api.py
tests/integration/test_consent_and_deletion_api.py
tests/integration/test_device_scoped_data_api.py
tests/integration/test_elderly_protection_api.py
tests/integration/test_family_api.py
tests/integration/test_family_identity_api.py
tests/integration/test_google_signin_api.py
tests/integration/test_guardian_alert_logging.py
tests/integration/test_guardian_authorisation_api.py
tests/integration/test_guardian_outbox.py
tests/integration/test_identity_binding_api.py
tests/integration/test_link_scan_privacy_retention.py
tests/integration/test_message_analyzer_api.py
tests/integration/test_otp_auth_flow_api.py
tests/integration/test_otp_delivery_logging.py
tests/integration/test_otp_hardening_api.py
tests/integration/test_otp_logging_api.py
tests/integration/test_refresh_rotation_api.py
tests/integration/test_reports_api.py
tests/integration/test_response_compat_characterisation.py
tests/integration/test_startup_error_log_purge.py
tests/integration/test_user_rate_limit_endpoints.py
tests/unit/test_access_log_redaction.py
tests/unit/test_delete_account_schema.py
tests/unit/test_guardian_dispatch_gate.py
tests/unit/test_optional_providers.py
tests/unit/test_url_privacy.py
tests/unit/test_user_rate_limits.py
```

### 4. Scam verdict contract, SMS registry/analyzer fixes and alert redaction (24)
```
app/routers/community_scam.py
app/routers/message_analyzer.py
app/routers/scam_calls.py
app/routers/wifi.py
app/schemas/scam_verdict.py
app/services/alert_redaction.py
app/services/scam_verdict_adapters.py
app/services/sms_header_validator.py
app/services/url_privacy.py
docs/audit/SECURESHIELD_RELEASE_READINESS.md
docs/audit/architecture-and-integration.md
docs/audit/development-roadmap.md
docs/audit/infrastructure-setup.md
docs/audit/production-readiness.md
docs/audit/project-status.md
tests/integration/test_scam_verdict_contracts.py
tests/integration/test_sender_registry_rollback.py
tests/unit/data/threat_golden.json
tests/unit/test_alert_privacy_other_paths.py
tests/unit/test_alert_redaction.py
tests/unit/test_scam_verdict_adapters.py
tests/unit/test_scam_verdict_schema.py
tests/unit/test_sender_suffix_and_registry_failure.py
tests/unit/test_threat_signals_equivalence.py
```

### 5. Audit reports, runbooks and release documentation (27)
```
docs/RAILWAY_DEPLOYMENT.md
docs/audits/SECURESHIELD_GITHUB_RELEASE_CHECKPOINT.md
docs/audits/STAGE_1_2A_SQL_REVIEW_REPORT.md
docs/audits/STAGE_1_2B_LOCAL_DATABASE_ACTIVATION_RUNBOOK.md
docs/audits/STAGE_1_2C_DATABASE_ACTIVATION_REVIEW.md
docs/audits/STAGE_1_2C_EXISTING_DATABASE_INVENTORY.md
docs/audits/STAGE_1_2E_MIGRATION_SAFETY_REVIEW.md
docs/audits/STAGE_1_2_IMPLEMENTATION_REPORT.md
docs/audits/STAGE_1_3_LOCAL_DATABASE_MIGRATION_REPORT.md
docs/audits/STAGE_1_4_ORM_SCHEMA_DRIFT_REPORT.md
docs/audits/STAGE_1_5A_ORM_RECONCILIATION_IMPLEMENTATION_PLAN.md
docs/audits/STAGE_1_5B_ORM_RECONCILIATION_IMPLEMENTATION_REPORT.md
docs/audits/STAGE_1_5C_INDEPENDENT_CODE_REVIEW.md
docs/audits/STAGE_1_5D_EXPRESSION_INDEX_CORRECTION_REPORT.md
docs/audits/STAGE_1_5E_LOCAL_MIGRATION_REPORT.md
docs/audits/STAGE_1_5F_FINAL_EXPRESSION_ALIGNMENT_REPORT.md
docs/audits/STAGE_1_6A_SEED_DATA_READINESS_AUDIT.md
docs/audits/STAGE_1_6B_1_DEPENDENCY_INSTALLATION_REPORT.md
docs/audits/STAGE_1_6B_2_SMS_REGISTRY_DRY_RUN_REPORT.md
docs/audits/STAGE_1_6B_3_LOCAL_SMS_REGISTRY_SEED_REPORT.md
docs/audits/STAGE_1_6B_4_REGISTRY_FUNCTIONAL_VALIDATION_REPORT.md
docs/audits/STAGE_1_6C_SMS_ANALYZER_INTEGRATION_AUDIT.md
docs/audits/STAGE_1_6D_1A_BACKEND_INTEGRATION_TEST_REPORT.md
docs/audits/STAGE_1_6D_1_SUFFIX_AND_FAILURE_HANDLING_REPORT.md
docs/audits/STAGE_1_6D_2_ALERT_DATA_REDACTION_REPORT.md
docs/audits/STAGE_1_6D_3_CROSS_MODULE_PRIVACY_REPORT.md
docs/audits/STAGE_1_6D_4_FLUTTER_PRIVACY_VALIDATION_REPORT.md
```

### UNASSIGNED (0)
```

```

### EXCLUDED (1)
```
start.bat
```

### Flutter

### 1. Android app-monitor native store, lifecycle and policy (Kotlin + JVM tests) (14)
```
android/app/build.gradle.kts
android/app/src/main/AndroidManifest.xml
android/app/src/main/kotlin/com/secureshield/secureshield_app/AndroidSqlDb.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/AppMonitorService.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/MainActivity.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/MonitorDbSupport.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/MonitorEventStore.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/MonitorLifecycle.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/MonitorPolicy.kt
android/app/src/main/kotlin/com/secureshield/secureshield_app/PackageInstallReceiver.kt
android/app/src/test/kotlin/com/secureshield/secureshield_app/MonitorDbSafetyTest.kt
android/app/src/test/kotlin/com/secureshield/secureshield_app/MonitorEventStoreTest.kt
android/app/src/test/kotlin/com/secureshield/secureshield_app/MonitorLifecycleTest.kt
android/app/src/test/kotlin/com/secureshield/secureshield_app/MonitorPolicyTest.kt
```

### 2. Shared scam-verdict model, Scam Hub and message-analysis result (28)
```
lib/core/verdict/scam_verdict.dart
lib/core/verdict/verdict_adapters.dart
lib/core/verdict/verdict_headline.dart
lib/core/verdict/verdict_response.dart
lib/features/dashboard/dashboard_api.dart
lib/features/dashboard/screens/home_screen.dart
lib/features/link_scanner/link_scanner_api.dart
lib/features/link_scanner/screens/link_scanner_screen.dart
lib/features/message_analyzer/message_analyzer_api.dart
lib/features/message_analyzer/screens/message_analyzer_screen.dart
lib/features/message_analyzer/widgets/message_result_view.dart
lib/features/scam_hub/hub_input.dart
lib/features/scam_hub/hub_result.dart
lib/features/scam_hub/scam_hub_provider.dart
lib/features/scam_hub/screens/hub_qr_capture.dart
lib/features/scam_hub/screens/scam_hub_screen.dart
lib/features/scam_hub/sensitive_content.dart
lib/features/scam_hub/widgets/confirm_send_sheet.dart
test/core/verdict/consumer_contract_test.dart
test/core/verdict/safe_defaults_test.dart
test/core/verdict/scam_verdict_test.dart
test/core/verdict/server_verdict_fixtures.dart
test/core/verdict/verdict_adapters_test.dart
test/features/link_scanner/verdict_headline_test.dart
test/features/message_analyzer/message_result_view_test.dart
test/features/scam_hub/hub_flow_test.dart
test/features/scam_hub/hub_input_test.dart
test/features/scam_hub/sensitive_content_test.dart
```

### 3. Identity, consent, privacy and auth screens (37)
```
lib/features/ai_coach/screens/ai_coach_screen.dart
lib/features/app_monitor/app_monitor_service.dart
lib/features/app_monitor/monitor_sync_coordinator.dart
lib/features/app_monitor/screens/app_monitor_screen.dart
lib/features/auth/auth_provider.dart
lib/features/auth/identity_api.dart
lib/features/auth/screens/otp_screen.dart
lib/features/auth/screens/phone_screen.dart
lib/features/auth/screens/phone_verify_screen.dart
lib/features/auth/screens/profile_details_screen.dart
lib/features/auth/screens/register_screen.dart
lib/features/consent_manager/screens/consent_manager_screen.dart
lib/features/family/screens/family_screen.dart
lib/features/privacy/consent_choices.dart
lib/features/privacy/consent_gate.dart
lib/features/privacy/privacy_api.dart
lib/features/privacy/privacy_content.dart
lib/features/privacy/screens/consent_screen.dart
lib/features/privacy/screens/delete_account_screen.dart
lib/features/privacy/screens/privacy_notice_screen.dart
lib/features/privacy/screens/privacy_settings_screen.dart
lib/features/profile/screens/profile_screen.dart
lib/features/profile/widgets/email_change_dialog.dart
test/android_manifest_permissions_test.dart
test/features/app_monitor/app_monitor_test.dart
test/features/app_monitor/flaky_prefs.dart
test/features/app_monitor/monitor_sync_coordinator_test.dart
test/features/auth/auth_flows_test.dart
test/features/auth/fake_http.dart
test/features/auth/google_linking_test.dart
test/features/auth/identity_api_test.dart
test/features/auth/no_enumeration_guard_test.dart
test/features/auth/phone_verify_screen_test.dart
test/features/privacy/consent_screen_test.dart
test/features/privacy/delete_account_test.dart
test/features/privacy/privacy_settings_test.dart
test/features/profile/email_change_dialog_test.dart
```

### 4. Private notifications, notification preferences and safe error handling (24)
```
lib/core/providers/notification_preferences_provider.dart
lib/core/services/notification_content.dart
lib/core/services/notification_preferences.dart
lib/core/services/notification_service.dart
lib/core/utils/safe_error.dart
lib/features/alerts/screens/alerts_screen.dart
lib/features/call_recording/call_recording_provider.dart
lib/features/call_recording/screens/emergency_share_screen.dart
lib/features/clone_detector/screens/clone_detector_screen.dart
lib/features/community_scam/screens/community_scam_screen.dart
lib/features/evidence/screens/evidence_screen.dart
lib/features/payment_verifier/screens/payment_verifier_screen.dart
lib/features/qr_scanner/qr_safety_service.dart
lib/features/remote_detector/screens/remote_detector_screen.dart
lib/features/screen_recorder/screens/screen_recorder_screen.dart
lib/features/settings/screens/settings_screen.dart
lib/features/settings/widgets/notification_preferences_section.dart
lib/features/video_call/screens/fir_draft_screen.dart
lib/features/vpn_monitor/screens/vpn_monitor_screen.dart
lib/features/vpn_monitor/vpn_monitor_service.dart
lib/features/wifi_scanner/screens/wifi_scanner_screen.dart
test/core/services/notification_content_test.dart
test/core/utils/safe_error_test.dart
test/features/settings/notification_preferences_test.dart
```

### 5. App wiring and dependencies (5)
```
lib/core/constants.dart
lib/core/router.dart
lib/main.dart
pubspec.lock
pubspec.yaml
```

### UNASSIGNED (0)
```

```

### EXCLUDED (0)
```

```


## 12. Phase 3 execution record

### 12.1 Dedicated history scan (all refs, both repositories)
- Gitleaks is not installed, so an equivalent pattern scanner was run over every added line of every commit on all refs (backend 99 commits, Flutter 25). Secret values were never printed.
- **Flutter: 0 findings.** No sensitive filename was ever added.
- **Backend: PRE-EXISTING exposure in history already on origin/main and every remote branch.** The initial commits (6465d52e 2026-03-20, 8fcb5af5 2026-05-09) added a tracked .env (database URL, SECRET_KEY, a 108-character Anthropic API key), an app/config.py containing a Twilio account SID pattern, and logs/*.log; f775a3eb (2026-08-27) removed them from the tree but not from history. A vendored .venv with cacert.pem and library test fixtures is also in history (those private-key and JWT matches are library code, not secrets). Test files contain placeholder keys.
- **The new commits add no secrets** (staged-diff scan before commit and before push: no real-looking values). Pushing them does not add to the exposure, because the old commits are already on the remote. The remote repositories are private.
- **Action required (owner):** treat the credentials that were ever in that .env and config as exposed and rotate them (database, SECRET_KEY, Anthropic, Twilio and anything else it held). This is the rotation task already planned as the final remediation. Removing them from history would need a history rewrite plus force-push, which was not done and is not authorised.

### 12.2 Railway auto-deploy check (read-only, via the Railway integration)
- Project secureshield-staging, service secureshield-api, environment staging: **source repo ravishori/SecureShield-Backend, branch staging/railway-snapshot**, check suites off. Pre-deploy command: alembic upgrade head.
- The other four Railway projects contain only database or Redis services and unrelated apps; none deploys this repository.
- **Therefore a push to staging/candidate-2026-11-13 does not deploy.** A push to staging/railway-snapshot would (including running migrations), so that branch was not touched.

### 12.3 Flutter: review of the 23 commits ahead of origin/main
- All 23 are by the repository owner, linear (no merges), from 2026-10-06 to 2026-11-13: localization, Google sign-in client, evidence handling, screen-recorder fixes, release hardening, FLAG_SECURE, fail-closed signing, CI. They form a dependency chain on the work being committed now. 216 files, +31377/-4382.
- No keystore, key, dump or log file in the range (only android/key.properties.example, a template).
- All are intentional, so a clean cherry-picked candidate is not needed. The candidate branch staging/candidate-2026-11-16 is created from the current local main (815cbd9), and local main itself is not moved or pushed.
