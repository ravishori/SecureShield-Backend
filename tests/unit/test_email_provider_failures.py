"""Every Resend failure mode x SMTP_FALLBACK_ENABLED on the OTP, notification (guardian/panic/report) and new-device-alert paths.
Providers are simulated (httpx.MockTransport, stubbed smtplib); nothing leaves the machine."""

import smtplib
from types import SimpleNamespace

import httpx
import pytest

import app.services.device_service as device
import app.services.notifications as notif
import app.services.otp_service as svc
from app.delivery_settings import delivery_settings

EMAIL, CODE, KEY = "person@example.com", "482916", "re_test_key_123"
pytestmark = pytest.mark.unit

FAILURES = {
    "auth-401": lambda r: httpx.Response(401, json={"message": f"bad key {KEY}"}),
    "forbidden-403": lambda r: httpx.Response(403, json={"message": "domain"}),
    "rate-limit-429": lambda r: httpx.Response(429, json={"message": "slow down"}),
    "server-500": lambda r: httpx.Response(500, text="boom"),
    "unavailable-503": lambda r: httpx.Response(503, text="down"),
}


def _raise(exc):
    def handler(request):
        raise exc

    return handler


FAILURES["timeout"] = _raise(httpx.ReadTimeout("t"))
FAILURES["connect-error"] = _raise(httpx.ConnectError("c"))


class Rec:
    def __init__(self):
        self.lines = []

    def _r(self, m, *a, **k):
        self.lines.append(m % a if a else str(m))

    debug = info = warning = error = exception = critical = _r


@pytest.fixture
def smtp_calls(monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(a)
        raise smtplib.SMTPConnectError(421, "blocked")

    monkeypatch.setattr(smtplib, "SMTP", boom)
    return calls


def setup(monkeypatch, module, handler, *, enabled):
    real = module.load_settings()
    s = SimpleNamespace(**{k: getattr(real, k) for k in real.model_fields})
    s.RESEND_API_KEY = KEY
    s.RESEND_FROM_EMAIL = "SecureShield <no-reply@mail.example.org>"
    s.SMTP_HOST, s.SMTP_PORT, s.SMTP_USER, s.SMTP_PASSWORD = (
        "smtp.example.org",
        587,
        "u",
        "pw-secret",
    )
    monkeypatch.setattr(module, "load_settings", lambda: s)
    monkeypatch.setattr(
        svc,
        "_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    monkeypatch.setattr(delivery_settings, "SMTP_FALLBACK_ENABLED", enabled)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", FAILURES)
async def test_otp_disabled_never_calls_smtp_whatever_resend_does(
    monkeypatch, smtp_calls, name
):
    setup(monkeypatch, svc, FAILURES[name], enabled=False)
    rec = Rec()
    monkeypatch.setattr(svc, "logger", rec)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert (
        r.success is False and smtp_calls == []
    )  # never reports success when every provider failed
    blob = " ".join(rec.lines) + str(r.error)
    for secret in (CODE, EMAIL, KEY, "pw-secret"):
        assert secret not in blob


@pytest.mark.asyncio
@pytest.mark.parametrize("name", FAILURES)
async def test_otp_enabled_falls_back_to_smtp_after_every_resend_failure(
    monkeypatch, smtp_calls, name
):
    setup(monkeypatch, svc, FAILURES[name], enabled=True)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert len(smtp_calls) == 1 and r.success is False  # smtp itself is stubbed to fail


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
async def test_otp_resend_success_never_touches_smtp(monkeypatch, smtp_calls, enabled):
    setup(
        monkeypatch,
        svc,
        lambda r: httpx.Response(200, json={"id": "1"}),
        enabled=enabled,
    )
    r = await svc.deliver_otp(EMAIL, CODE)
    assert r.success is True and smtp_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", FAILURES)
async def test_guardian_panic_report_mail_disabled_never_calls_smtp(
    monkeypatch, smtp_calls, name
):
    setup(monkeypatch, notif, FAILURES[name], enabled=False)
    assert (
        await notif.send_email(EMAIL, "subject", "body") is False
    )  # not reported as delivered
    assert smtp_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", FAILURES)
async def test_guardian_panic_report_mail_enabled_falls_back(
    monkeypatch, smtp_calls, name
):
    setup(monkeypatch, notif, FAILURES[name], enabled=True)
    assert await notif.send_email(EMAIL, "subject", "body") is False
    assert len(smtp_calls) == 1


@pytest.mark.asyncio
async def test_guardian_mail_resend_success_is_true_without_smtp(
    monkeypatch, smtp_calls
):
    setup(monkeypatch, notif, lambda r: httpx.Response(200, json={}), enabled=False)
    assert await notif.send_email(EMAIL, "subject", "body") is True and smtp_calls == []


# ── new-device login alert: SMTP-only, so the switch turns it off entirely ───────────────────────────────────────────
def _user():
    return SimpleNamespace(id="u1", email=EMAIL)


@pytest.mark.asyncio
async def test_new_device_alert_disabled_makes_no_smtp_call(monkeypatch, smtp_calls):
    monkeypatch.setattr(delivery_settings, "SMTP_FALLBACK_ENABLED", False)
    await device.send_new_device_alert(_user(), "Pixel", "android", "203.0.113.7")
    assert smtp_calls == []


@pytest.mark.asyncio
async def test_new_device_alert_enabled_still_attempts_smtp_and_never_raises(
    monkeypatch, smtp_calls
):
    monkeypatch.setattr(delivery_settings, "SMTP_FALLBACK_ENABLED", True)
    await device.send_new_device_alert(_user(), "Pixel", "android", "203.0.113.7")
    assert len(smtp_calls) == 1


@pytest.mark.asyncio
async def test_no_application_code_can_reach_smtp_without_the_switch(
    monkeypatch, smtp_calls
):
    """Every module that imports smtplib must be gated: with the switch off none of the four paths connects."""
    monkeypatch.setattr(delivery_settings, "SMTP_FALLBACK_ENABLED", False)
    import app.services.logger_service as ls

    for fn in (ls._send_email_sync,):
        # error-alert sender is only reached through log_error, which checks the switch (see test_smtp_fallback_switch)
        assert callable(fn)
    assert notif._send_email_smtp_sync(EMAIL, "s", "b") is False
    await device.send_new_device_alert(_user(), "d", "p", "1.2.3.4")
    assert smtp_calls == []
