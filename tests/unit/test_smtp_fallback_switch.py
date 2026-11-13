"""SMTP_FALLBACK_ENABLED gates all three SMTP paths: OTP e-mail, guardian/panic/report notifications, error-alert e-mails.
Providers are simulated; nothing leaves the machine."""

import smtplib
from types import SimpleNamespace

import httpx
import pytest

import app.services.notifications as notif
import app.services.otp_service as svc
from app.delivery_settings import delivery_settings

EMAIL, CODE, KEY = "person@example.com", "482916", "re_test_key_123"
pytestmark = pytest.mark.unit


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


def configure(monkeypatch, module, *, resend: bool, resend_status=200):
    real = module.load_settings()
    s = SimpleNamespace(**{k: getattr(real, k) for k in real.model_fields})
    s.RESEND_API_KEY = KEY if resend else ""
    s.RESEND_FROM_EMAIL = "SecureShield <no-reply@mail.example.org>" if resend else ""
    s.SMTP_HOST, s.SMTP_PORT, s.SMTP_USER, s.SMTP_PASSWORD = (
        "smtp.example.org",
        587,
        "u",
        "pw-secret",
    )
    monkeypatch.setattr(module, "load_settings", lambda: s)

    def handler(req):
        if resend_status < 300:
            return httpx.Response(resend_status, json={"id": "x"})
        return httpx.Response(resend_status, json={"message": f"{EMAIL} {CODE} {KEY}"})

    monkeypatch.setattr(
        svc,
        "_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.fixture
def switch(monkeypatch):
    def _set(enabled: bool):
        monkeypatch.setattr(delivery_settings, "SMTP_FALLBACK_ENABLED", enabled)

    return _set


def test_default_preserves_existing_behaviour():
    assert delivery_settings.SMTP_FALLBACK_ENABLED is True
    assert delivery_settings.FILE_ENCRYPTION_REQUIRED is False


def test_environment_variable_names_are_the_documented_ones(monkeypatch):
    from app.delivery_settings import DeliverySettings

    monkeypatch.setenv("SMTP_FALLBACK_ENABLED", "false")
    monkeypatch.setenv("FILE_ENCRYPTION_REQUIRED", "true")
    s = DeliverySettings(_env_file=None)
    assert s.SMTP_FALLBACK_ENABLED is False and s.FILE_ENCRYPTION_REQUIRED is True


# ── OTP delivery ──────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_otp_enabled_resend_fails_smtp_is_tried(monkeypatch, switch, smtp_calls):
    switch(True)
    configure(monkeypatch, svc, resend=True, resend_status=500)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and len(smtp_calls) == 1


@pytest.mark.asyncio
async def test_otp_disabled_resend_fails_smtp_never_called_and_failure_is_clean(
    monkeypatch, switch, smtp_calls
):
    switch(False)
    configure(monkeypatch, svc, resend=True, resend_status=500)
    rec = Rec()
    monkeypatch.setattr(svc, "logger", rec)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and r.method == "none" and smtp_calls == []
    blob = " ".join(rec.lines) + str(r.error)
    for secret in (CODE, EMAIL, KEY, "pw-secret"):
        assert secret not in blob


@pytest.mark.asyncio
async def test_otp_disabled_without_resend_fails_without_touching_smtp(
    monkeypatch, switch, smtp_calls
):
    switch(False)
    configure(monkeypatch, svc, resend=False)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and smtp_calls == []


@pytest.mark.asyncio
async def test_otp_disabled_resend_success_is_unaffected(
    monkeypatch, switch, smtp_calls
):
    switch(False)
    configure(monkeypatch, svc, resend=True)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert r.success and r.method == "email" and smtp_calls == []


# ── guardian / panic / report notifications ───────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_notifications_enabled_fall_back_to_smtp(monkeypatch, switch, smtp_calls):
    switch(True)
    configure(monkeypatch, notif, resend=False)
    assert (
        await notif.send_email(EMAIL, "subject", "body") is False
    )  # smtp simulated as blocked
    assert len(smtp_calls) == 1


@pytest.mark.asyncio
async def test_notifications_disabled_never_touch_smtp(monkeypatch, switch, smtp_calls):
    switch(False)
    configure(monkeypatch, notif, resend=False)
    assert await notif.send_email(EMAIL, "subject", "body") is False
    assert smtp_calls == []


@pytest.mark.asyncio
async def test_notifications_disabled_still_use_resend(monkeypatch, switch, smtp_calls):
    switch(False)
    configure(monkeypatch, notif, resend=True)
    monkeypatch.setattr(
        notif.otp,
        "_http_client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ),
    )
    assert await notif.send_email(EMAIL, "subject", "body") is True
    assert smtp_calls == []


# ── error-alert e-mails (database write replaced; the alert decision is what is under test) ──────────────────────
async def _log_an_error(monkeypatch, notify="ops@example.org"):
    from concurrent.futures import ThreadPoolExecutor

    import app.services.logger_service as ls
    from app.config import settings

    sent = []

    async def no_db(**kw):
        return True

    pool = ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(ls, "_log_to_db", no_db)
    monkeypatch.setattr(ls, "_executor", pool)
    monkeypatch.setattr(ls, "_send_email_sync", lambda *a: sent.append(a))
    monkeypatch.setattr(settings, "ERROR_NOTIFY_EMAIL", notify)
    await ls.log_error("boom", RuntimeError("x"), endpoint="/t", method="GET")
    pool.shutdown(wait=True)
    return sent


@pytest.mark.asyncio
async def test_error_alert_enabled_is_sent(monkeypatch, switch):
    switch(True)
    assert len(await _log_an_error(monkeypatch)) == 1


@pytest.mark.asyncio
async def test_error_alert_disabled_is_not_sent(monkeypatch, switch):
    switch(False)
    assert await _log_an_error(monkeypatch) == []


@pytest.mark.asyncio
async def test_error_alert_without_recipient_is_not_sent_even_when_enabled(
    monkeypatch, switch
):
    switch(True)
    assert await _log_an_error(monkeypatch, notify="") == []
