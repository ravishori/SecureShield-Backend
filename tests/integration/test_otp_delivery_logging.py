"""FG-165: OTP delivery logging privacy (same principles as FG-041).

The REAL ``deliver_otp`` / provider functions and the REAL auth endpoints run; only the network layer is faked
(Twilio client, smtplib, Resend/httpx). Real log records are captured (caplog + stdout/stderr + error_logs).
Never in a log: the OTP, the message/subject text, the full recipient, provider error text (which echoes the
recipient/body), credentials. Always in a log: channel, outcome, masked recipient, error class / Twilio code.
"""

from __future__ import annotations

import logging
import smtplib
from types import SimpleNamespace

import pytest
from sqlalchemy import text

import app.services.otp_service as otp
from app.services.log_scrubber import safe_error_text

pytestmark = [pytest.mark.integration, pytest.mark.security]

CODE = "739128"
PHONE = "+919876543210"
EMAIL = "victim.person@example.com"
LOCAL = EMAIL.split("@")[0]


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="secureshield")
    return caplog


def blob(caplog, capsys) -> str:
    out = capsys.readouterr()
    return "\n".join(r.getMessage() for r in caplog.records) + out.out + out.err


def assert_clean(text_: str, *extra: str) -> None:
    low = text_.lower()
    for bad in (CODE, PHONE, PHONE[3:], EMAIL, LOCAL, "auth-token-value", *extra):
        assert bad.lower() not in low, f"{bad!r} leaked into logs"


# ------------------------------------------------------------------ fakes
@pytest.fixture
def providers(monkeypatch):
    """Twilio + SMTP + Resend configured; behaviour chosen per test via the returned dict."""
    import twilio.rest
    from twilio.base.exceptions import TwilioRestException

    state = {"twilio": "fail-unmapped", "smtp": "refuse", "resend": "http422"}

    monkeypatch.setattr(
        otp,
        "load_settings",
        lambda: SimpleNamespace(
            TWILIO_ACCOUNT_SID="AC" + "0" * 32,
            TWILIO_AUTH_TOKEN="auth-token-value",
            TWILIO_SMS_NUMBER="+15550001111",
            TWILIO_WHATSAPP_NUMBER="whatsapp:+15550001111",
            SMTP_HOST="smtp.invalid",
            SMTP_PORT=587,
            SMTP_USER="u",
            SMTP_PASSWORD="p",
            SMTP_FROM_EMAIL="f@example.com",
            RESEND_API_KEY="re_" + "k" * 20,
            RESEND_FROM_EMAIL="f@example.com",
        ),
    )

    class Messages:
        def create(self, body, from_, to):
            mode = state["twilio"]
            if mode == "ok":
                return SimpleNamespace(sid="SM123")
            code = 21211 if mode == "fail-mapped" else 21614
            raise TwilioRestException(
                status=400,
                uri="/Messages",
                msg=f"Unable to create record: The 'To' number {to} is not valid. Body was: {body}",
                code=code,
            )

    class Client:
        def __init__(self, *a, **k):
            self.messages = Messages()

    monkeypatch.setattr(twilio.rest, "Client", Client)

    class SMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, *a):
            pass

        def sendmail(self, frm, to, msg):
            if state["smtp"] == "ok":
                return {}
            if state["smtp"] == "data":
                raise smtplib.SMTPDataError(
                    554, f"rejected: {msg[:200]!s} for {to}".encode()
                )
            raise smtplib.SMTPRecipientsRefused(
                {to: (550, f"no such user {to}".encode())}
            )

    monkeypatch.setattr(smtplib, "SMTP", SMTP)

    class Resp:
        def __init__(self, status):
            self.status_code = status
            self.text = f"invalid recipient {EMAIL} code {CODE}"

    class HttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            if state["resend"] == "ok":
                return Resp(200)
            if state["resend"] == "raise":
                import httpx

                raise httpx.ConnectError(f"cannot connect for {EMAIL}")
            return Resp(422)

    monkeypatch.setattr(otp, "_http_client", lambda: HttpClient())
    return state


# ------------------------------------------------------------------ helper unit
def test_safe_error_text_never_echoes_message_or_raises():
    from twilio.base.exceptions import TwilioRestException

    exc = TwilioRestException(400, "/x", msg=f"to {PHONE} body {CODE}", code=21614)
    assert safe_error_text(exc) == "TwilioRestException code 21614"
    assert safe_error_text(ValueError(f"{PHONE} {EMAIL}")) == "ValueError"
    assert safe_error_text(smtplib.SMTPDataError(554, f"x {EMAIL}".encode())) == (
        "SMTPDataError"
    )

    class Weird(Exception):
        @property
        def code(self):
            raise RuntimeError("boom")

    assert safe_error_text(Weird()) in ("Weird", "Exception")


def test_twilio_error_message_keeps_static_hints_and_drops_text():
    from twilio.base.exceptions import TwilioRestException

    mapped = TwilioRestException(400, "/x", msg=f"echo {PHONE}", code=21211)
    unmapped = TwilioRestException(400, "/x", msg=f"echo {PHONE}", code=21614)
    assert "invalid destination phone number" in otp._twilio_error_message(mapped)
    assert otp._twilio_error_message(unmapped) == "Twilio error 21614"
    assert PHONE not in otp._twilio_error_message(unmapped)
    assert otp._twilio_error_message(RuntimeError(f"x {PHONE}")) == "RuntimeError"


# ------------------------------------------------------------------ SMS / WhatsApp
async def test_sms_and_whatsapp_failure_logs_no_recipient_text_body_or_code(
    providers, logs, capsys
):
    r = await otp.deliver_otp(PHONE, CODE)
    assert r.success is False and r.method == "none"
    text_ = blob(logs, capsys)
    assert_clean(text_, "Body was", "not valid", "verification code")
    # the failure reason handed to callers is safe too
    assert PHONE not in (r.error or "") and CODE not in (r.error or "")
    # operational context remains
    assert "Twilio SMS failed" in text_ and "WhatsApp OTP failed" in text_
    assert "Twilio error 21614" in text_ and "[phone ...10]" in text_
    assert "tried: sms+whatsapp" in text_


async def test_mapped_twilio_code_keeps_its_static_hint(providers, logs, capsys):
    providers["twilio"] = "fail-mapped"
    r = await otp.deliver_otp(PHONE, CODE)
    text_ = blob(logs, capsys)
    assert "invalid destination phone number" in text_
    assert_clean(text_, "Body was")
    assert "invalid destination" in (r.error or "")


async def test_sms_success_logs_masked_recipient_and_sid_only(providers, logs, capsys):
    providers["twilio"] = "ok"
    r = await otp.deliver_otp(PHONE, CODE)
    assert r.success and r.method == "sms"
    text_ = blob(logs, capsys)
    assert_clean(text_, "verification code")
    assert "Twilio SMS sent to [phone ...10]" in text_ and "SM123" in text_


# ------------------------------------------------------------------ e-mail
async def test_smtp_recipient_refused_does_not_log_address_or_server_reply(
    providers, logs, capsys
):
    providers["resend"] = "http422"
    r = await otp.deliver_otp(EMAIL, CODE)
    assert r.success is False
    text_ = blob(logs, capsys)
    assert_clean(text_, "no such user", "invalid recipient")
    assert "SMTPRecipientsRefused" in text_ and "v***@example.com" in text_
    assert "Resend HTTP 422" in text_ and "tried: email" in text_
    assert EMAIL not in (r.error or "") and CODE not in (r.error or "")


async def test_smtp_data_error_echoing_the_message_is_not_logged(
    providers, logs, capsys
):
    providers["smtp"] = "data"
    providers["resend"] = "raise"
    r = await otp.deliver_otp(EMAIL, CODE)
    text_ = blob(logs, capsys)
    assert r.success is False
    assert_clean(text_, "rejected:", "cannot connect", "Verification Code")
    assert "SMTPDataError" in text_ and "ConnectError" in text_


async def test_email_success_logs_masked_recipient_only(providers, logs, capsys):
    providers["resend"] = "ok"
    r = await otp.deliver_otp(EMAIL, CODE)
    assert r.success
    text_ = blob(logs, capsys)
    assert_clean(text_, "Verification Code")
    assert "OTP email (resend) sent to v***@example.com" in text_


async def test_smtp_success_logs_masked_recipient_only(providers, logs, capsys):
    providers["resend"] = "http422"
    providers["smtp"] = "ok"
    r = await otp.deliver_otp(EMAIL, CODE)
    assert r.success
    text_ = blob(logs, capsys)
    assert_clean(text_, "Verification Code", "invalid recipient")
    assert "OTP email sent to v***@example.com" in text_


# ------------------------------------------------------------------ malformed recipients
@pytest.mark.parametrize(
    "identifier",
    ["", " ", "abc", "+", "1", "@", "a@", "@example.com", "a@b@c", "x" * 5000, "\x00"],
)
async def test_malformed_recipients_never_raise_or_leak(
    providers, logs, capsys, identifier
):
    r = await otp.deliver_otp(identifier, CODE)
    assert r.success is False
    text_ = blob(logs, capsys)
    assert CODE not in text_ and "Traceback" not in text_
    if len(identifier.strip()) > 3 and identifier.strip() not in ("x" * 5000,):
        assert identifier not in text_ or identifier in ("abc",)


# ------------------------------------------------------------------ through the auth endpoints
async def test_send_otp_endpoint_failure_logs_are_clean(
    client, db, make_user, providers, logs, capsys
):
    await make_user("otpfail", phone="9876543211", email="otp.fail@example.com")
    for ident in ("otp.fail@example.com", "9876543211"):
        r = await client.post("/api/v1/auth/send-otp", json={"identifier": ident})
        assert r.status_code in (200, 502, 503), r.text
    text_ = blob(logs, capsys)
    rows = (await db.execute(text("select t::text from error_logs t"))).scalars().all()
    text_ += "\n".join(rows)
    code = (
        await db.execute(
            text(
                "select code from otps where email=:e order by created_at desc limit 1"
            ),
            {"e": "otp.fail@example.com"},
        )
    ).scalar_one_or_none()
    for bad in ("otp.fail@example.com", "9876543211", "Body was", "no such user"):
        assert bad.lower() not in text_.lower(), bad
    if code:
        assert code not in text_
    assert "delivery failed" in text_.lower()
    assert "Twilio error 21614" in text_ or "SMTPRecipientsRefused" in text_


async def test_register_endpoint_failure_logs_are_clean(
    client, db, providers, logs, capsys
):
    email = "otp.register@example.com"
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "first_name": "Reg",
            "email": email,
            "phone": "9876543212",
            "consent": {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"},
        },
    )
    assert r.status_code == 200, r.text
    text_ = blob(logs, capsys)
    for bad in (email, "9876543212", "no such user", "Body was", "invalid recipient"):
        assert bad.lower() not in text_.lower(), bad
    code = (
        await db.execute(text("select code from otps where email=:e"), {"e": email})
    ).scalar_one()
    assert code not in text_
    assert "OTP delivery failed for o***@example.com (tried: email)" in text_
    assert "Registration code delivery failed for o***@example.com" in text_
    assert "SMTPRecipientsRefused" in text_
