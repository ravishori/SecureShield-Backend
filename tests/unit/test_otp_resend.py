"""Resend HTTPS adapter: request shape, failure handling, fallback order, no secret leakage.
The provider is simulated with httpx.MockTransport (no network)."""

import json
import smtplib
from types import SimpleNamespace

import httpx
import pytest

import app.services.otp_service as svc

EMAIL, CODE, KEY = "person@example.com", "482916", "re_test_key_123"
pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


class Rec:
    def __init__(self):
        self.lines = []

    def _r(self, m, *a, **k):
        self.lines.append(m % a if a else str(m))

    debug = info = warning = error = exception = critical = _r


def cfg(
    monkeypatch,
    key=KEY,
    sender="SecureShield <otp@example.org>",
    smtp="smtp.example.org",
):
    real = svc.load_settings()
    s = SimpleNamespace(**{k: getattr(real, k) for k in real.model_fields})
    s.RESEND_API_KEY, s.RESEND_FROM_EMAIL, s.SMTP_HOST = key, sender, smtp
    monkeypatch.setattr(svc, "load_settings", lambda: s)


def provider(monkeypatch, handler):
    monkeypatch.setattr(
        svc,
        "_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.fixture
def logs(monkeypatch):
    r = Rec()
    monkeypatch.setattr(svc, "logger", r)
    return r


@pytest.fixture
def smtp_calls(monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise smtplib.SMTPConnectError(421, "blocked")

    monkeypatch.setattr(smtplib, "SMTP", boom)
    return calls


async def test_success_sends_expected_request_and_skips_smtp(monkeypatch, smtp_calls):
    cfg(monkeypatch)
    seen = {}

    def h(req):
        seen["auth"], seen["body"], seen["url"] = (
            req.headers["authorization"],
            json.loads(req.content),
            str(req.url),
        )
        return httpx.Response(200, json={"id": "x"})

    provider(monkeypatch, h)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert r.success and r.method == "email" and smtp_calls == []
    assert seen["url"] == svc.RESEND_API_URL and seen["auth"] == f"Bearer {KEY}"
    assert (
        seen["body"]["to"] == [EMAIL]
        and CODE in seen["body"]["html"]
        and seen["body"]["from"].startswith("SecureShield")
    )


@pytest.mark.security
@pytest.mark.parametrize("status", [401, 422, 429, 500])
async def test_provider_errors_fail_cleanly_without_leaking(
    monkeypatch, logs, smtp_calls, capsys, status
):
    cfg(monkeypatch, smtp="")  # no SMTP fallback configured
    provider(
        monkeypatch,
        lambda req: httpx.Response(status, text=f"bad {EMAIL} {CODE} {KEY}"),
    )
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and r.method == "none" and str(status) in r.error
    out = capsys.readouterr()
    blob = "\n".join(logs.lines) + out.out + out.err + r.error
    assert logs.lines and CODE not in blob and EMAIL not in blob and KEY not in blob


@pytest.mark.security
async def test_network_error_does_not_leak_and_falls_back_to_smtp(
    monkeypatch, logs, smtp_calls
):
    cfg(monkeypatch)

    def h(req):
        raise httpx.ConnectError(f"cannot reach {KEY}")

    provider(monkeypatch, h)
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and smtp_calls == [1]  # SMTP attempted after Resend failed
    blob = "\n".join(logs.lines) + (r.error or "")
    assert KEY not in blob and CODE not in blob and EMAIL not in blob


async def test_unconfigured_resend_uses_smtp_only(monkeypatch, smtp_calls):
    cfg(monkeypatch, key="")
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and smtp_calls == [1]


async def test_no_provider_configured_reports_failure_not_exception(monkeypatch, logs):
    cfg(monkeypatch, key="", smtp="")
    r = await svc.deliver_otp(EMAIL, CODE)
    assert not r.success and r.method == "none" and "provider" in r.error
    assert CODE not in "\n".join(logs.lines)


async def test_missing_sender_counts_as_unconfigured(monkeypatch):
    cfg(monkeypatch, sender="", smtp="")
    r = await svc._send_email_resend(EMAIL, CODE)
    assert not r.success and "not configured" in r.error
