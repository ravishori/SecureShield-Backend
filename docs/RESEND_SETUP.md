# Resend e-mail OTP: setup and safe verification

The application already contains the Resend integration (`app/services/otp_service.py::_send_email_resend`, settings `RESEND_API_KEY`, `RESEND_FROM_EMAIL`).
Delivery order for e-mail is **Resend (HTTPS) -> SMTP fallback -> generic 503**; phone OTP via Twilio is optional and is not needed for e-mail login. Nothing in this procedure sends a message until you explicitly run the last step.

## What the code already guarantees (verified by tests, see `docs/audit/testing-and-qa.md`)

* Code: 6 digits from the OS CSPRNG; only a keyed HMAC is stored; valid 10 minutes; a new code invalidates every older one; wrong guesses are counted per code and the code is burned after 5; atomic single use; constant-time compare; every failure returns the same response.
* Limits: 5 sends/hour per identifier, 20/hour per source address, 10 verifications per 15 minutes per identifier.
* Provider failure: 15 s timeout; Resend errors log only the HTTP status or exception class; SMTP is tried next; if everything fails the API answers a generic 503 and never returns or logs the code or the full address (masked in logs).
* Known trade-off: the subject line contains the code (`[123456] Your SecureShield AI Verification Code`), so it is visible in mail previews and in Resend's own logs. Remove it from the subject if you prefer stricter privacy (one-line change in `_send_email_resend`).

## 1. Resend dashboard (owner)

1. Create a Resend account and open **Domains -> Add Domain**. Use a sub-domain you control, e.g. `mail.<your-domain>`, region closest to your users.
2. Resend shows DNS records. Add them at your DNS host **exactly as displayed** (values below are the usual shape, not literal):
   * **SPF** - `TXT` on the `send.` sub-domain: `v=spf1 include:amazonses.com ~all`, plus the `MX` record Resend lists for bounce handling.
   * **DKIM** - `TXT` at `resend._domainkey.<sub-domain>` containing the public key Resend shows (do not edit it).
   * **DMARC** - `TXT` at `_dmarc.<your-domain>`: start with `v=DMARC1; p=none; rua=mailto:<mailbox you read>` and tighten to `p=quarantine` then `p=reject` after a few weeks of clean reports.
3. Click **Verify DNS Records**; wait until the domain shows *Verified* (minutes to 72 h).
4. **API Keys -> Create API Key**: permission **Sending access**, restricted to that domain, name it `secureshield-staging` (a separate key for production later). Copy it once; store it only in the platform secret store.
5. Staging variables: `RESEND_API_KEY=<key>`, `RESEND_FROM_EMAIL=SecureShield <no-reply@mail.<your-domain>>` (the address must be on the verified domain).

## 2. Safe verification procedure

1. Configure the two variables in the **staging** environment only (never commit them; `.env*` is git-ignored).
2. Offline check (reads configuration, sends nothing): `python scripts/otp_provider_check.py`.
3. Live authentication check (read-only): `python scripts/otp_provider_check.py --live`. A sending-only key may answer 401/403 to the domain listing; that is expected and then only a real send proves the key.
4. **Only with the owner's explicit approval:** send one dummy message to an address you own: `python scripts/otp_provider_check.py --send-test-email <your address>` (body code is `000000`, not a login code). Confirm it arrives, passes SPF/DKIM/DMARC in the message headers ("Authentication-Results"), and does not land in spam.
5. End-to-end: register a test account with that address in the staging app, receive the real OTP, log in; then request more than 5 codes in an hour and confirm the limit message; disable the key in the Resend dashboard and confirm login answers a generic failure (provider-failure test), then restore it.

## 3. Twilio

Twilio is **not** needed for e-mail login. The `twilio` package remains a dependency because the SMS/WhatsApp code path exists; with no valid credentials it fails closed ("not configured") and registration still succeeds through e-mail. Settings currently require the `TWILIO_*` variables to be present (non-empty), so on staging set them to harmless placeholders such as `disabled` (the code only calls Twilio when the SID starts with `AC`). Making these settings optional, or removing the SMS path, is a deliberate follow-up change (`app/config.py` currently carries uncommitted connection-fix edits, so it is not touched here).
