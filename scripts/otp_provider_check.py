"""Check the OTP delivery configuration without sending any message.

    python scripts/otp_provider_check.py            # offline: presence and shape of the settings only
    python scripts/otp_provider_check.py --live     # also authenticate to Twilio, Resend or SMTP (read-only, sends nothing)

What it does:
  * reports, by variable NAME only, whether each setting is present and plausibly formed;
  * with --live, calls Twilio's "fetch my account" endpoint (the same call the API makes at startup), Resend's "list domains"
    endpoint, or logs in to the SMTP server (no message is sent). None sends an SMS or an e-mail or incurs a charge. Only the HTTP status / Twilio error code is printed.

It never prints a credential, a phone number or an e-mail address. Settings are read exactly as the application reads them
(``backend/.env`` or ``SECURESHIELD_ENV_FILE``).

Exit code 0 = at least one channel for phones AND one for e-mail is usable (offline: configured), 1 = something is missing or rejected.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import load_settings  # noqa: E402

E164 = re.compile(r"^(whatsapp:)?\+\d{8,15}$")


def present(value: str | None) -> bool:
    return bool((value or "").strip())


def twilio_live(sid: str, token: str) -> str:
    try:
        from twilio.base.exceptions import TwilioRestException
        from twilio.rest import Client
    except ImportError:
        return "twilio package not installed"
    try:
        account = Client(sid, token).api.accounts(sid).fetch()
        return f"authenticated (account status: {account.status}, type: {getattr(account, 'type', 'unknown')})"
    except TwilioRestException as exc:
        hints = {
            20003: "authentication failed: the Account SID / Auth Token pair is not valid for this account (rotated token, token of another account, or a closed/suspended account). Compare both values with the Twilio Console > Account > API keys & tokens",
            20404: "account not found for this SID",
        }
        return f"REJECTED by Twilio: error {exc.code} - {hints.get(exc.code, 'see https://www.twilio.com/docs/api/errors/' + str(exc.code))}"
    except Exception as exc:  # network etc.
        return f"could not reach Twilio ({type(exc).__name__})"


def resend_live(api_key: str) -> str:
    import httpx

    try:
        r = httpx.get(
            "https://api.resend.com/domains",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15,
        )
    except Exception as exc:
        return f"could not reach Resend ({type(exc).__name__})"
    if r.status_code == 200:
        domains = r.json().get("data", [])
        verified = sum(1 for d in domains if d.get("status") == "verified")
        return f"authenticated ({len(domains)} domain(s), {verified} verified)"
    if r.status_code in (401, 403):
        return f"REJECTED by Resend: HTTP {r.status_code} (invalid or restricted API key; a send-only key cannot list domains - then test with a real send)"
    return f"unexpected HTTP {r.status_code}"


def smtp_live(host: str, port: int, user: str, password: str) -> str:
    import smtplib

    try:
        with smtplib.SMTP(host, port, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(user, password)
        return "authenticated (login only; no message sent)"
    except smtplib.SMTPAuthenticationError as exc:
        return f"REJECTED by the SMTP server: {exc.smtp_code} (wrong user/app password, or the app password was revoked)"
    except Exception as exc:  # blocked port, DNS, TLS ...
        return f"could not log in ({type(exc).__name__}); Railway and some hosts block outbound SMTP"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--live",
        action="store_true",
        help="authenticate to the providers (read-only, sends nothing)",
    )
    ap.add_argument(
        "--send-test-email",
        metavar="ADDRESS",
        help="SEND one real test e-mail (dummy code 000000) through the production delivery path to an address you own",
    )
    ap.add_argument(
        "--send-test-sms",
        metavar="E164",
        help="SEND one real test SMS (dummy code 000000) to a number you own; may incur a small provider charge",
    )
    args = ap.parse_args()
    s = load_settings()
    ok_phone = ok_mail = False

    print("== SMS / WhatsApp (Twilio)")
    sid, token = (
        (s.TWILIO_ACCOUNT_SID or "").strip(),
        (s.TWILIO_AUTH_TOKEN or "").strip(),
    )
    checks = {
        "TWILIO_ACCOUNT_SID": present(sid)
        and bool(re.fullmatch(r"AC[0-9a-f]{32}", sid)),
        "TWILIO_AUTH_TOKEN": present(token)
        and bool(re.fullmatch(r"[0-9a-f]{32}", token)),
        "TWILIO_SMS_NUMBER": bool(E164.match((s.TWILIO_SMS_NUMBER or "").strip())),
        "TWILIO_WHATSAPP_NUMBER": bool(
            E164.match((s.TWILIO_WHATSAPP_NUMBER or "").strip())
        ),
    }
    for name, good in checks.items():
        print(
            f"  {name:<24} {'present and well-formed' if good else 'MISSING or malformed'}"
        )
    twilio_cfg = (
        checks["TWILIO_ACCOUNT_SID"]
        and checks["TWILIO_AUTH_TOKEN"]
        and checks["TWILIO_SMS_NUMBER"]
    )
    if args.live and checks["TWILIO_ACCOUNT_SID"] and checks["TWILIO_AUTH_TOKEN"]:
        result = twilio_live(sid, token)
        print(f"  live check: {result}")
        ok_phone = twilio_cfg and result.startswith("authenticated")
    else:
        ok_phone = twilio_cfg
    print(
        "  note: a trial account can only SMS verified numbers; India needs DLT registration; the account needs balance to send."
    )

    print("== E-mail")
    resend_cfg = present(s.RESEND_API_KEY) and present(s.RESEND_FROM_EMAIL)
    smtp_cfg = (
        present(s.SMTP_HOST)
        and present(s.SMTP_USER)
        and present(s.SMTP_PASSWORD)
        and present(s.SMTP_FROM_EMAIL)
    )
    for name, good in {
        "RESEND_API_KEY": present(s.RESEND_API_KEY),
        "RESEND_FROM_EMAIL": present(s.RESEND_FROM_EMAIL),
        "SMTP_HOST/USER/PASSWORD/FROM": smtp_cfg,
    }.items():
        print(f"  {name:<28} {'present' if good else 'not set'}")
    if args.live and present(s.RESEND_API_KEY):
        result = resend_live(s.RESEND_API_KEY.strip())
        print(f"  Resend live check: {result}")
        ok_mail = resend_cfg and result.startswith("authenticated")
    elif args.live and smtp_cfg and not resend_cfg:
        result = smtp_live(
            s.SMTP_HOST.strip(),
            int(s.SMTP_PORT),
            s.SMTP_USER.strip(),
            s.SMTP_PASSWORD.strip(),
        )
        print(f"  SMTP live check: {result}")
        ok_mail = result.startswith("authenticated")
    else:
        ok_mail = resend_cfg or smtp_cfg
    print(
        "  note: Railway blocks outbound SMTP (587/465); use Resend (HTTPS) there. The sender domain must be verified in Resend."
    )

    if args.send_test_email or args.send_test_sms:
        import asyncio

        from app.services.otp_service import deliver_otp

        print("== Test delivery (dummy code 000000; this is NOT a login code)")
        for target in (args.send_test_email, args.send_test_sms):
            if target:
                res = asyncio.run(deliver_otp(target, "000000"))
                kind = "e-mail" if "@" in target else "sms/whatsapp"
                outcome = (
                    f"delivered via {res.method}"
                    if res.success
                    else f"FAILED ({res.error})"
                )
                print(f"  {kind}: {outcome}")

    print("== Result")
    print(f"  phone channel : {'usable' if ok_phone else 'NOT usable'}")
    print(f"  e-mail channel: {'usable' if ok_mail else 'NOT usable'}")
    return 0 if (ok_phone and ok_mail) else 1


if __name__ == "__main__":
    sys.exit(main())
