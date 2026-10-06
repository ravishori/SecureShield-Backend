"""FG-041: guardian / panic alert delivery must never put contact details or message content in logs.

These tests run the REAL notification code (``app.services.notifications``) with only the network layer
faked (Twilio client, SMTP, Resend) and capture REAL log records, so the masking and error-text paths are
exercised end to end. Useful operational information (user id, channel outcome, error class/code) must
still be logged.
"""

from __future__ import annotations

import logging
import smtplib
from types import SimpleNamespace

import pytest

import app.routers.alerts as alerts_router
import app.services.notifications as n
from app.services.log_scrubber import mask_email_for_log, mask_phone_for_log

pytestmark = pytest.mark.integration

API = "/api/v1"
E = f"{API}/elderly"
PHONE = "+919800000000"
EMAIL = "asha.guardian@example.com"
CFG = {
    "enabled": True,
    "guardian_name": "Asha",
    "guardian_phone": PHONE,
    "guardian_email": EMAIL,
    "alert_threshold": 40,
}
ALERT = {
    "package_name": "com.bad.app",
    "app_name": "Bad App Name",
    "risk_score": 80,
    "risk_level": "high",
    "risk_tags": ["screen overlay", "sms read"],
    "clone_verdict": "likely_clone",
}
SECRET_BITS = ("Bad App Name", "screen overlay", "Asha", "likely clone")


# ------------------------------------------------------------------ helpers
@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG, logger="secureshield")
    caplog.set_level(logging.DEBUG)
    return caplog


def blob(caplog, capsys) -> str:
    out = capsys.readouterr()
    return "\n".join(r.getMessage() for r in caplog.records) + out.out + out.err


def assert_clean(text: str, *extra: str) -> None:
    low = text.lower()
    for bad in (PHONE, PHONE[3:], EMAIL, EMAIL.split("@")[0], *extra):
        assert bad.lower() not in low, f"{bad!r} leaked into logs"
    for bit in SECRET_BITS:
        assert bit.lower() not in low, f"{bit!r} (message content) leaked into logs"


@pytest.fixture
def twilio(monkeypatch):
    """Configured Twilio whose API rejects the number with an error text that echoes it (as the real API does)."""
    from twilio.base.exceptions import TwilioRestException
    import twilio.rest

    monkeypatch.setattr(
        n,
        "load_settings",
        lambda: SimpleNamespace(
            TWILIO_ACCOUNT_SID="AC" + "0" * 32,
            TWILIO_AUTH_TOKEN="auth-token-value",
            TWILIO_SMS_NUMBER="+15550001111",
            RESEND_API_KEY="",
            RESEND_FROM_EMAIL="",
            SMTP_HOST="smtp.invalid",
            SMTP_PORT=587,
            SMTP_USER="u",
            SMTP_PASSWORD="p",
            SMTP_FROM_EMAIL="f@example.com",
        ),
    )

    class Messages:
        def create(self, body, from_, to):
            raise TwilioRestException(
                status=400,
                uri="/Messages",
                msg=f"Unable to create record: The 'To' number {to} is not a valid mobile number. Body: {body[:30]}",
                code=21614,
            )

    class Client:
        def __init__(self, *a, **k):
            self.messages = Messages()

    monkeypatch.setattr(twilio.rest, "Client", Client)


@pytest.fixture
def smtp_rejects(monkeypatch):
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
            raise smtplib.SMTPRecipientsRefused(
                {to: (550, f"no such user {to}".encode())}
            )

    monkeypatch.setattr(smtplib, "SMTP", SMTP)


# ------------------------------------------------------------------ maskers
def test_phone_mask_keeps_at_most_the_last_two_digits_and_is_deterministic():
    assert mask_phone_for_log("+919800000012") == "[phone ...12]"
    assert mask_phone_for_log("98000 00012") == mask_phone_for_log("+91-9800000012")
    for short in ("1234", "12345", "", None, "abc", "+"):
        assert mask_phone_for_log(short) == "[phone]"
    assert "9800000" not in mask_phone_for_log(PHONE)


def test_email_mask_keeps_first_char_and_domain_only():
    assert mask_email_for_log("Asha.Guardian@Example.com") == "A***@example.com"
    for bad in ("", None, "no-at-sign", "@d.com", "a@", "a@b@c", 12345, "@"):
        assert mask_email_for_log(bad) in ("[email]",)  # never raises, never echoes


@pytest.mark.parametrize(
    "junk", [None, "", "x" * 10_000, "\x00\x01", "a@b@c", 123, b"bytes"]
)
def test_maskers_never_raise(junk):
    assert isinstance(mask_phone_for_log(junk), str)
    assert isinstance(mask_email_for_log(junk), str)


def test_safe_error_keeps_class_and_twilio_code_only():
    from twilio.base.exceptions import TwilioRestException

    exc = TwilioRestException(400, "/Messages", msg=f"bad number {PHONE}", code=21614)
    assert n._safe_error(exc) == "TwilioRestException code 21614"
    assert (
        n._safe_error(smtplib.SMTPRecipientsRefused({EMAIL: (550, b"x")}))
        == "SMTPRecipientsRefused"
    )
    assert PHONE not in n._safe_error(ValueError(f"bad {PHONE}"))


# ------------------------------------------------------------------ real transports
async def test_sms_failure_text_from_twilio_is_not_logged(twilio, logs, capsys):
    assert n._send_sms_sync(PHONE, "SECRET-BODY Bad App Name") is False
    text = blob(logs, capsys)
    assert_clean(text, "SECRET-BODY")
    assert "[phone ...00]" in text and "code 21614" in text  # still diagnosable


async def test_sms_with_a_malformed_number_fails_cleanly_without_raising(
    twilio, logs, capsys
):
    for bad in ("", "abc", None, "+", "1"):
        assert n._send_sms_sync(bad, "body") is False
    assert "Traceback" not in blob(logs, capsys)


async def test_smtp_failure_does_not_log_the_recipient_or_server_text(
    twilio, smtp_rejects, logs, capsys
):
    assert n._send_email_smtp_sync(EMAIL, "subject", "SECRET-BODY") is False
    text = blob(logs, capsys)
    assert_clean(text, "SECRET-BODY", "no such user")
    assert "a***@example.com" in text and "SMTPRecipientsRefused" in text


async def test_email_with_a_malformed_address_fails_cleanly_without_raising(
    twilio, smtp_rejects, logs, capsys
):
    for bad in ("", "no-at-sign", "@", "a@"):
        assert n._send_email_smtp_sync(bad, "s", "b") is False
    assert "Traceback" not in blob(logs, capsys)


async def test_resend_failure_logs_status_only(monkeypatch, logs, capsys):
    monkeypatch.setattr(
        n,
        "load_settings",
        lambda: SimpleNamespace(
            RESEND_API_KEY="re_key", RESEND_FROM_EMAIL="f@example.com"
        ),
    )

    class Resp:
        status_code = 422
        text = f"invalid recipient {EMAIL}"

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return Resp()

    monkeypatch.setattr(n.otp, "_http_client", lambda: Client())
    assert await n._send_email_resend(EMAIL, "s", "SECRET-BODY") is False
    text = blob(logs, capsys)
    assert_clean(text, "SECRET-BODY", "re_key")
    assert "HTTP 422" in text


# ------------------------------------------------------------------ through the guardian endpoint
@pytest.mark.security
async def test_guardian_alert_failure_end_to_end_logs_no_pii_but_keeps_diagnostics(
    client, make_user, auth_headers, twilio, smtp_rejects, logs, capsys
):
    u = await make_user("gl")
    h = auth_headers(u)
    assert (await client.put(f"{E}/config", headers=h, json=CFG)).status_code == 200
    r = await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)
    assert r.status_code == 202
    text = blob(logs, capsys)
    token = h["Authorization"].split()[-1]
    assert_clean(text, token)
    # operational information is still there
    assert f"user={u.id}" in text
    assert "sms=failed" in text and "email=failed" in text
    assert "could not be delivered" in text
    assert "code 21614" in text and "SMTPRecipientsRefused" in text
    assert "[phone ...00]" in text and "a***@example.com" in text


@pytest.mark.security
async def test_guardian_alert_success_logs_outcome_without_pii(
    client, make_user, auth_headers, monkeypatch, logs, capsys
):
    async def ok_sms(phone, body):
        n.logger.info(f"Notification SMS sent to {mask_phone_for_log(phone)}")
        return True

    async def ok_email(to, subject, body):
        n.logger.info(f"Notification e-mail (smtp) sent to {mask_email_for_log(to)}")
        return True

    monkeypatch.setattr(n, "send_sms", ok_sms)
    monkeypatch.setattr(n, "send_email", ok_email)
    u = await make_user("gs")
    h = auth_headers(u)
    await client.put(f"{E}/config", headers=h, json=CFG)
    assert (
        await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)
    ).status_code == 202
    text = blob(logs, capsys)
    assert_clean(text)
    assert f"user={u.id}" in text and "sms=ok" in text and "email=ok" in text
    assert "risk=high" in text and "score=80" in text


@pytest.mark.security
async def test_a_channel_that_raises_is_logged_by_class_only(
    client, make_user, auth_headers, monkeypatch, logs, capsys
):
    async def boom(*a, **k):
        raise RuntimeError(f"gateway rejected {PHONE} / {EMAIL} / SECRET-BODY")

    monkeypatch.setattr(n, "send_sms", boom)
    monkeypatch.setattr(n, "send_email", boom)
    u = await make_user("gb")
    h = auth_headers(u)
    await client.put(f"{E}/config", headers=h, json=CFG)
    assert (
        await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)
    ).status_code == 202
    text = blob(logs, capsys)
    assert_clean(text, "SECRET-BODY", "gateway rejected")
    assert "RuntimeError" in text and f"user={u.id}" in text


# ------------------------------------------------------------------ same pattern: panic fan-out
@pytest.mark.security
async def test_panic_notification_failure_logs_no_contact_details_or_message(
    client, make_user, auth_headers, twilio, smtp_rejects, logs, capsys
):
    u = await make_user("pl", full_name="Priya Sharma")
    h = auth_headers(u)
    r = await client.post(
        f"{API}/emergency-contacts",
        headers=h,
        json={"name": "Mum", "phone": PHONE, "email": EMAIL},
    )
    assert r.status_code in (200, 201), r.text
    r = await client.post(
        f"{API}/alerts/panic",
        headers=h,
        json={"latitude": 18.5204, "longitude": 73.8567, "message": "SECRET-HELP-TEXT"},
    )
    assert r.status_code == 200
    text = blob(logs, capsys)
    assert_clean(text, "SECRET-HELP-TEXT", "Priya", "18.5204", "73.8567")
    assert f"user={u.id}" in text
    assert "contacts=1" in text and "delivered=0" in text and "failed=2" in text
    assert "code 21614" in text and "SMTPRecipientsRefused" in text


@pytest.mark.security
async def test_panic_exception_is_logged_by_class_only(
    client, make_user, auth_headers, monkeypatch, logs, capsys
):
    async def boom(to, *a):
        raise RuntimeError(f"cannot reach {to}")

    monkeypatch.setattr(alerts_router.notifications, "send_sms", boom)
    monkeypatch.setattr(alerts_router.notifications, "send_email", boom)
    u = await make_user("pe")
    h = auth_headers(u)
    await client.post(
        f"{API}/emergency-contacts",
        headers=h,
        json={"name": "Mum", "phone": PHONE, "email": EMAIL},
    )
    await client.post(f"{API}/alerts/panic", headers=h, json={"message": "m"})
    text = blob(logs, capsys)
    assert_clean(text, "cannot reach")
    assert "RuntimeError" in text and "failed=2" in text
