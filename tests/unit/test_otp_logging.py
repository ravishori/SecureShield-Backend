"""An OTP is a working credential: it must never reach stdout, logs or the
error_logs table, including on delivery-failure paths.

These tests drive the REAL ``deliver_otp`` fallback logic and fail only at the
network layer (``smtplib.SMTP`` / ``twilio.rest.Client``), so a regression that
re-adds a "dev console fallback" is caught.
"""

import smtplib

import pytest

import app.services.otp_service as otp_service

CODE = "739128"
EMAIL = "victim.person@example.com"
PHONE = "+919876543210"


class _Recorder:
    def __init__(self):
        self.lines: list[str] = []

    def _rec(self, msg, *args, **kwargs):
        self.lines.append(msg % args if args else str(msg))

    debug = info = warning = error = exception = critical = _rec


@pytest.fixture
def logs(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(otp_service, "logger", rec)
    return rec


@pytest.fixture
def broken_network(monkeypatch):
    def _smtp(*a, **k):
        raise smtplib.SMTPConnectError(421, "boom")

    monkeypatch.setattr(smtplib, "SMTP", _smtp)

    import twilio.rest

    class _Client:
        def __init__(self, *a, **k):
            raise RuntimeError("twilio down")

    monkeypatch.setattr(twilio.rest, "Client", _Client)


def _assert_clean(logs, capsys, *secrets):
    out = capsys.readouterr()
    blob = "\n".join(logs.lines) + out.out + out.err
    assert logs.lines, "expected a failure to be logged (test would be vacuous)"
    for s in secrets:
        assert s not in blob, f"{s!r} leaked into logs/stdout/stderr"


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.asyncio
async def test_email_delivery_failure_does_not_log_code(logs, broken_network, capsys):
    result = await otp_service.deliver_otp(EMAIL, CODE)
    assert result.success is False
    _assert_clean(logs, capsys, CODE, EMAIL)


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.asyncio
async def test_sms_and_whatsapp_failure_does_not_log_code(logs, broken_network, capsys):
    result = await otp_service.deliver_otp(PHONE, CODE)
    assert result.success is False
    _assert_clean(logs, capsys, CODE, PHONE)


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.asyncio
async def test_failure_logs_keep_useful_redacted_metadata(logs, broken_network):
    await otp_service.deliver_otp(EMAIL, CODE)
    joined = "\n".join(logs.lines)
    assert "OTP delivery failed" in joined and "tried: email" in joined
    assert "example.com" in joined  # masked identifier still identifies the domain


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.asyncio
async def test_success_path_does_not_log_code(logs, monkeypatch, capsys):
    class _Srv:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, *a, **k): ...
        def ehlo(self, *a, **k): ...
        def login(self, *a, **k): ...
        def sendmail(self, *a, **k): ...

    monkeypatch.setattr(smtplib, "SMTP", lambda *a, **k: _Srv())
    result = await otp_service.deliver_otp(EMAIL, CODE)
    assert result.success is True
    _assert_clean(logs, capsys, CODE, EMAIL)


@pytest.mark.unit
@pytest.mark.security
def test_no_console_fallback_symbol_or_print_of_codes():
    """Structural guard: the dev console fallback must stay gone."""
    import inspect

    src = inspect.getsource(otp_service)
    assert "_console_fallback" not in src
    assert "[DEV OTP]" not in src
    assert "print(" not in src
