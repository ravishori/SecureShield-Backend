# SecureShield AI — Google Play Readiness Checklist

**Baseline date:** 27 November 2026  
**Status:** Planning checklist; no Play Console submission was performed.

## A. Identity and store listing

- [ ] Confirm developer account type: personal or organisation.
- [ ] Confirm developer identity, legal entity and support contact.
- [ ] Confirm application ID/package name is final.
- [ ] Confirm app name, category and target audience.
- [ ] Write accurate short and full descriptions.
- [ ] Remove unsupported claims such as “100% protection”, “blocks every scam” or “guaranteed recovery”.
- [ ] Create 512×512 app icon.
- [ ] Create 1024×500 feature graphic.
- [ ] Capture genuine screenshots from the release candidate.
- [ ] Verify store assets meet current Play specifications.
- [ ] Prepare support website/email and public privacy-policy URL.

## B. Privacy and data declarations

- [ ] Complete data inventory from actual runtime/network behaviour.
- [ ] Review every SDK and third-party provider.
- [ ] Identify collection, sharing, processing, retention and deletion for each data type.
- [ ] Complete Data Safety accurately.
- [ ] Publish an app-specific public HTTPS privacy policy.
- [ ] Ensure privacy policy is accessible without login or geographic restrictions.
- [ ] Add in-app account deletion if accounts can be created.
- [ ] Publish an external account deletion request URL if required.
- [ ] Document retention exceptions and backup deletion timelines.
- [ ] Add prominent disclosure and consent before sensitive data collection/use where required.
- [ ] Review DPDP Act/Rules and obtain legal review.

## C. Android permissions and platform features

- [ ] Generate merged manifest from release build.
- [ ] Map every permission to a user-facing feature.
- [ ] Remove permissions not essential to launch.
- [ ] Resolve SMS/Call Log policy eligibility before requesting.
- [ ] Justify QUERY_ALL_PACKAGES or replace with narrower package visibility.
- [ ] Review usage access and notification listener disclosures.
- [ ] Review Accessibility API usage if any.
- [ ] Review VPNService declaration and allowed purpose.
- [ ] Review foreground service types and permissions.
- [ ] Provide user-visible start/stop and persistent notification where required.
- [ ] Verify camera, microphone and location are requested only when needed.
- [ ] Verify Android 14+ and newer behaviour.
- [ ] Test permission denial, revocation and restricted settings.

## D. Build and release

- [ ] Set target API 36 or higher for new app submissions as required at this baseline date; recheck current policy before release.
- [ ] Verify compile/target/min SDK values in the built artifact.
- [ ] Replace debug signing with secure production upload signing.
- [ ] Configure Play App Signing.
- [ ] Protect signing keys outside source control.
- [ ] Build release AAB.
- [ ] Verify AAB signature and package ID.
- [ ] Test release build, not just debug.
- [ ] Verify 16 KB page-size compatibility where applicable.
- [ ] Review R8/obfuscation and mapping-file handling.
- [ ] Review dependency vulnerabilities and SDK support.
- [ ] Verify HTTPS-only production networking.
- [ ] Verify app does not depend on a developer LAN IP.
- [ ] Verify crash/ANR reporting privacy and retention.

## E. Play Console declarations

- [ ] App access / reviewer instructions.
- [ ] Ads declaration.
- [ ] Content rating questionnaire.
- [ ] Target audience and content.
- [ ] Data Safety.
- [ ] Privacy policy.
- [ ] Account deletion.
- [ ] Sensitive permission declarations.
- [ ] Foreground service declarations and videos where required.
- [ ] VPNService declaration and listing disclosures where applicable.
- [ ] Accessibility declaration where applicable.
- [ ] Financial features declaration if applicable.
- [ ] App category and contact details.
- [ ] Countries/regions and pricing.
- [ ] Testing track requirements for account type and creation date.
- [ ] Review current policy and target API deadlines.

## F. Testing

- [ ] Internal test track.
- [ ] Closed test if required for the developer account.
- [ ] Fresh install and upgrade.
- [ ] Login, OTP, logout, refresh and account deletion.
- [ ] Offline/poor-network/provider outage.
- [ ] Permission denial/revocation.
- [ ] Device compatibility.
- [ ] Accessibility and senior-user usability.
- [ ] Battery and background execution.
- [ ] Cross-user data access tests.
- [ ] Upload abuse and file validation.
- [ ] Encryption and key lifecycle tests.
- [ ] VPN connectivity tests or VPN feature disabled.
- [ ] Billing purchase/restore/cancel/refund tests if applicable.
- [ ] Security regression report.
- [ ] UAT sign-off.

## G. Reviewer and support readiness

- [ ] Reviewer access instructions and test account, if needed.
- [ ] Explain optional permissions and how to enable/disable features.
- [ ] Provide demo video for applicable restricted service declarations.
- [ ] Support and grievance handling process.
- [ ] Incident response and security contact.
- [ ] Post-launch monitoring and rollback plan.
- [ ] Release notes and known limitations.

## Current baseline blockers

See findings `SS-AUD-001` through `SS-AUD-027`. The most significant release blockers are credential exposure, OTP and encryption weaknesses, restricted permissions, debug signing, network configuration and VPN functionality.
