"""Stage 1.2D: SMTP, Twilio and Resend are optional. The application runs (for example locally) with none of them configured, and no
path pretends to deliver, builds a message or opens a connection with missing credentials.

Every provider is simulated: ``smtplib.SMTP`` and ``twilio.rest.Client`` are in-memory fakes, Resend is an ``httpx.MockTransport``,
and nothing leaves the machine (tests/unit/conftest.py additionally blocks database connections).
"""

import logging
import os
import smtplib
import subprocess
import sys
import types
from concurrent.futures import Executor, Future
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from app import config
from app.config import Settings
from app.delivery_settings import delivery_settings
from app.services import device_service as device
from app.services import logger_service as lg
from app.services import notifications as notif
from app.services import otp_service as otp
from app.services.smtp_config import (
    REQUIRED_SMTP_SETTINGS,
    missing_smtp_settings,
    smtp_configured,
)

pytestmark = pytest.mark.unit

BACKEND = Path(__file__).resolve().parents[2]
OPTIONAL = (
    "SMTP_HOST",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_FROM_EMAIL",
    "ERROR_NOTIFY_EMAIL",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_SMS_NUMBER",
    "TWILIO_WHATSAPP_NUMBER",
)
EMAIL, CODE, PHONE = "person@example.com", "482916", "+919876543210"
SMTP_PW, RESEND_KEY = "SENTINEL-SMTP-PW", "re_SENTINEL_KEY"


# ------------------------------------------------------------------------------------------------------------------------------------
# helpers: settings, fake providers
# ------------------------------------------------------------------------------------------------------------------------------------
def provider_settings(**overrides):
    base = dict(
        SMTP_HOST="smtp.example.org",
        SMTP_PORT=587,
        SMTP_USER="mailer@example.org",
        SMTP_PASSWORD=SMTP_PW,
        SMTP_FROM_EMAIL="SecureShield <no-reply@example.org>",
        ERROR_NOTIFY_EMAIL="ops@example.org",
        TWILIO_ACCOUNT_SID="",
        TWILIO_AUTH_TOKEN="",
        TWILIO_SMS_NUMBER="",
        TWILIO_WHATSAPP_NUMBER="",
        RESEND_API_KEY="",
        RESEND_FROM_EMAIL="",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def apply_settings(monkeypatch, s, *, smtp_enabled=True):
    """Make ``s`` what every sending module sees (fresh ``load_settings()`` callers and the import-time ``settings`` object)."""
    for module in (notif, otp):
        monkeypatch.setattr(module, "load_settings", lambda s=s: s)
    for name, value in vars(s).items():
        if name in Settings.model_fields:
            monkeypatch.setattr(config.settings, name, value)
    monkeypatch.setattr(delivery_settings, "SMTP_FALLBACK_ENABLED", smtp_enabled)


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.logged_in, self.sent = host, port, None, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        return None

    def starttls(self):
        return None

    def login(self, user, password):
        self.logged_in = (user, password)

    def sendmail(self, sender, to, message):
        self.sent.append((sender, to, message))


@pytest.fixture
def smtp_attempts(monkeypatch):
    """smtplib.SMTP replaced by a recorder that FAILS the test's expectations if it is ever constructed."""
    calls = []

    def forbidden(*a, **k):
        calls.append((a, k))
        raise smtplib.SMTPConnectError(421, "blocked by the test")

    monkeypatch.setattr(smtplib, "SMTP", forbidden)
    return calls


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    return FakeSMTP.instances


@pytest.fixture
def twilio(monkeypatch):
    """A fake ``twilio.rest.Client``; records every construction and message."""
    record = SimpleNamespace(clients=[], messages=[])

    class Client:
        def __init__(self, sid, token):
            record.clients.append((sid, token))
            self.messages = SimpleNamespace(
                create=lambda **kw: (
                    record.messages.append(kw),
                    SimpleNamespace(sid="SMfake"),
                )[1]
            )

    package, rest = types.ModuleType("twilio"), types.ModuleType("twilio.rest")
    rest.Client = Client
    monkeypatch.setitem(sys.modules, "twilio", package)
    monkeypatch.setitem(sys.modules, "twilio.rest", rest)
    return record


def resend_transport(monkeypatch, status=200):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            status, json={"id": "x"} if status < 300 else {"message": "denied"}
        )

    monkeypatch.setattr(
        otp,
        "_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    return seen


# ------------------------------------------------------------------------------------------------------------------------------------
# 1. configuration
# ------------------------------------------------------------------------------------------------------------------------------------
def test_settings_load_with_no_smtp_or_twilio_credentials(monkeypatch):
    for name in OPTIONAL + ("RESEND_API_KEY", "RESEND_FROM_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    s = Settings(_env_file=None)
    assert all(getattr(s, name) == "" for name in OPTIONAL)
    assert s.SMTP_PORT == int(
        os.environ["SMTP_PORT"]
    )  # unchanged: still a required, validated integer


def test_blank_values_count_as_not_configured(monkeypatch):
    for name in OPTIONAL:
        monkeypatch.setenv(name, "")
    assert all(getattr(Settings(_env_file=None), name) == "" for name in OPTIONAL)


@pytest.mark.parametrize(
    "name", ["DATABASE_URL", "MIGRATOR_DATABASE_URL", "SECRET_KEY", "SMTP_PORT"]
)
def test_security_critical_and_port_settings_are_still_required(monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None)
    assert name in str(info.value)


@pytest.mark.parametrize("bad", ["abc", "25.5", "-"])
def test_smtp_port_is_still_validated(monkeypatch, bad):
    monkeypatch.setenv("SMTP_PORT", bad)
    with pytest.raises(ValidationError, match="SMTP_PORT"):
        Settings(_env_file=None)


def test_database_url_validation_is_untouched(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@localhost/d")
    assert Settings(_env_file=None).DATABASE_URL.startswith(
        "postgresql+asyncpg://"
    )  # still normalised


def test_fresh_process_with_no_provider_settings_imports_config_and_the_app():
    names = set(OPTIONAL) | {
        "RESEND_API_KEY",
        "RESEND_FROM_EMAIL",
        "SECURESHIELD_ENV_FILE",
    }
    env = {k: v for k, v in os.environ.items() if k not in names}
    code = (
        "import app.config as c, app.main;"
        "s = c.settings;"
        "print([getattr(s, n) for n in %r])" % (OPTIONAL,)
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr[-400:]
    assert out.stdout.strip().splitlines()[-1] == str([""] * len(OPTIONAL))


def test_smtp_helper_reports_names_only():
    s = provider_settings(SMTP_USER="  ", SMTP_PASSWORD="")
    assert missing_smtp_settings(s) == [
        "SMTP_USER",
        "SMTP_PASSWORD",
    ] and not smtp_configured(s)
    assert (
        smtp_configured(provider_settings())
        and missing_smtp_settings(provider_settings()) == []
    )
    assert REQUIRED_SMTP_SETTINGS == (
        "SMTP_HOST",
        "SMTP_USER",
        "SMTP_PASSWORD",
        "SMTP_FROM_EMAIL",
    )  # SMTP_PORT is not part of it


# ------------------------------------------------------------------------------------------------------------------------------------
# 2. SMTP is never attempted when it is not (fully) configured
# ------------------------------------------------------------------------------------------------------------------------------------
INCOMPLETE = [
    pytest.param(dict(SMTP_HOST=""), id="no-host"),
    pytest.param(dict(SMTP_USER=""), id="no-user"),
    pytest.param(dict(SMTP_PASSWORD=""), id="no-password"),
    pytest.param(dict(SMTP_FROM_EMAIL=""), id="no-sender"),
    pytest.param(dict(SMTP_HOST="  ", SMTP_USER="  "), id="blank"),
    pytest.param(
        dict(SMTP_HOST="", SMTP_USER="", SMTP_PASSWORD="", SMTP_FROM_EMAIL=""),
        id="nothing",
    ),
]


@pytest.mark.parametrize("missing", INCOMPLETE)
async def test_guardian_style_notification_email_is_skipped(
    monkeypatch, smtp_attempts, missing, caplog
):
    apply_settings(monkeypatch, provider_settings(**missing))
    caplog.set_level(logging.DEBUG)
    assert (
        await notif.send_email(EMAIL, "subject", "message body SENTINEL-BODY") is False
    )
    assert smtp_attempts == []
    assert (
        "SENTINEL-BODY" not in caplog.text
        and SMTP_PW not in caplog.text
        and EMAIL not in caplog.text
    )


@pytest.mark.parametrize("missing", INCOMPLETE)
async def test_otp_email_reports_not_configured_and_never_success(
    monkeypatch, smtp_attempts, missing, caplog
):
    apply_settings(monkeypatch, provider_settings(**missing))
    caplog.set_level(logging.DEBUG)
    direct = otp._send_email(EMAIL, CODE)
    assert (
        direct.success is False
        and direct.method == "email"
        and direct.error == "SMTP not configured"
    )
    routed = await otp.deliver_otp(EMAIL, CODE)
    assert routed.success is False and routed.method == "none" and routed.error
    assert smtp_attempts == []
    assert (
        CODE not in caplog.text
        and SMTP_PW not in caplog.text
        and EMAIL not in caplog.text
    )


async def test_otp_email_with_no_provider_at_all_is_a_clean_failure(
    monkeypatch, smtp_attempts
):
    apply_settings(
        monkeypatch,
        provider_settings(
            SMTP_HOST="", SMTP_USER="", SMTP_PASSWORD="", SMTP_FROM_EMAIL=""
        ),
    )
    seen = resend_transport(monkeypatch)
    result = await otp.deliver_otp(EMAIL, CODE)
    assert (result.success, result.method, result.error) == (
        False,
        "none",
        "no email provider configured",
    )
    assert smtp_attempts == [] and seen == []  # neither SMTP nor Resend was contacted


@pytest.mark.parametrize("missing", INCOMPLETE)
async def test_new_device_login_alert_does_not_attempt_smtp_and_never_raises(
    monkeypatch, smtp_attempts, missing, caplog
):
    apply_settings(monkeypatch, provider_settings(**missing))
    caplog.set_level(logging.DEBUG)
    user = SimpleNamespace(id="u-1", email=EMAIL)
    await device.send_new_device_alert(
        user, "Pixel", "android", "203.0.113.7"
    )  # login flow continues: no exception
    assert smtp_attempts == []
    assert SMTP_PW not in caplog.text and EMAIL not in caplog.text


@pytest.mark.parametrize("missing", INCOMPLETE)
def test_error_alert_sender_does_not_attempt_smtp(monkeypatch, smtp_attempts, missing):
    apply_settings(monkeypatch, provider_settings(**missing))
    lg._send_email_sync("subject", "<p>body</p>", "ops@example.org")
    assert smtp_attempts == []


class InlineExecutor(Executor):
    def submit(self, fn, *args, **kwargs):
        future = Future()
        future.set_result(fn(*args, **kwargs))
        return future


@pytest.mark.parametrize("missing", [None] + [p.values[0] for p in INCOMPLETE])
async def test_error_notification_is_only_scheduled_when_smtp_is_complete(
    monkeypatch, smtp_attempts, missing
):
    s = provider_settings(**(missing or {}))
    apply_settings(monkeypatch, s)
    sent = []

    async def no_database(**kw):
        return None

    monkeypatch.setattr(
        lg, "_log_to_db", no_database
    )  # the error logger would otherwise write a row
    monkeypatch.setattr(
        lg, "_send_email_sync", lambda subject, body, to: sent.append(to)
    )
    monkeypatch.setattr(lg, "_executor", InlineExecutor())
    await lg.log_error(
        "something failed", level="ERROR", endpoint="/x", send_email=True
    )
    assert smtp_attempts == []
    assert sent == (["ops@example.org"] if missing is None else [])


async def test_error_notification_without_a_recipient_is_not_scheduled(
    monkeypatch, smtp_attempts
):
    apply_settings(monkeypatch, provider_settings(ERROR_NOTIFY_EMAIL=""))
    sent = []

    async def no_database(**kw):
        return None

    monkeypatch.setattr(lg, "_log_to_db", no_database)
    monkeypatch.setattr(lg, "_send_email_sync", lambda *a: sent.append(a))
    monkeypatch.setattr(lg, "_executor", InlineExecutor())
    await lg.log_error("x", level="CRITICAL", send_email=True)
    assert sent == [] and smtp_attempts == []


def test_every_smtp_sender_checks_the_configuration_before_connecting():
    for module in (notif, otp, lg, device):
        source = Path(module.__file__).read_text(encoding="utf-8")
        connect = source.index("smtplib.SMTP(")
        guards = [
            i
            for i in (
                source.find("smtp_configured("),
                source.find("missing_smtp_settings("),
            )
            if i != -1
        ]
        # a CALL (the import lines carry no parenthesis) precedes the connection in the same module
        assert guards and min(guards) < connect, module.__name__


# ------------------------------------------------------------------------------------------------------------------------------------
# 3. a fully configured SMTP still works (mocked server)
# ------------------------------------------------------------------------------------------------------------------------------------
async def test_configured_smtp_notification_email_is_sent(monkeypatch, fake_smtp):
    apply_settings(monkeypatch, provider_settings())
    assert await notif.send_email(EMAIL, "subject", "body") is True
    (server,) = fake_smtp
    assert (server.host, server.port) == ("smtp.example.org", 587)
    assert (
        server.logged_in == ("mailer@example.org", SMTP_PW)
        and server.sent[0][1] == EMAIL
    )


async def test_configured_smtp_otp_email_is_delivered_as_the_fallback(
    monkeypatch, fake_smtp, caplog
):
    apply_settings(monkeypatch, provider_settings())
    caplog.set_level(logging.DEBUG)
    result = await otp.deliver_otp(EMAIL, CODE)
    assert (result.success, result.method) == (True, "email")
    assert fake_smtp[0].sent and fake_smtp[0].sent[0][1] == EMAIL
    assert (
        CODE not in caplog.text
        and SMTP_PW not in caplog.text
        and EMAIL not in caplog.text
    )


async def test_configured_smtp_device_alert_and_error_alert_are_sent(
    monkeypatch, fake_smtp
):
    apply_settings(monkeypatch, provider_settings())
    await device.send_new_device_alert(
        SimpleNamespace(id="u-1", email=EMAIL), "Pixel", "android", "203.0.113.7"
    )
    lg._send_email_sync("subject", "<p>b</p>", "ops@example.org")
    assert [i.sent[0][1] for i in fake_smtp] == [EMAIL, "ops@example.org"]
    assert all(i.logged_in == ("mailer@example.org", SMTP_PW) for i in fake_smtp)


async def test_smtp_fallback_switch_still_wins_over_a_complete_configuration(
    monkeypatch, smtp_attempts
):
    apply_settings(monkeypatch, provider_settings(), smtp_enabled=False)
    assert await notif.send_email(EMAIL, "s", "b") is False
    assert (await otp.deliver_otp(EMAIL, CODE)).success is False
    await device.send_new_device_alert(
        SimpleNamespace(id="u", email=EMAIL), "P", "android", "1.2.3.4"
    )
    assert smtp_attempts == []


# ------------------------------------------------------------------------------------------------------------------------------------
# 4. Twilio behaviour is intact
# ------------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "creds",
    [
        dict(),
        dict(TWILIO_ACCOUNT_SID="ACxxxx"),
        dict(TWILIO_ACCOUNT_SID="ACxxxx", TWILIO_AUTH_TOKEN="tok"),
        dict(TWILIO_AUTH_TOKEN="tok", TWILIO_SMS_NUMBER="+15550001111"),
        dict(
            TWILIO_ACCOUNT_SID="not-an-AC-sid",
            TWILIO_AUTH_TOKEN="tok",
            TWILIO_SMS_NUMBER="+15550001111",
        ),
    ],
)
async def test_unconfigured_or_partial_twilio_never_builds_a_client(
    monkeypatch, twilio, smtp_attempts, creds
):
    apply_settings(monkeypatch, provider_settings(**creds))
    sms = otp._send_sms(PHONE, CODE)
    assert (sms.success, sms.method, sms.error) == (
        False,
        "sms",
        "Twilio not configured",
    )
    wa = otp._send_whatsapp(PHONE, CODE)
    assert (wa.success, wa.error) == (False, "Twilio not configured")
    assert notif._send_sms_sync(PHONE, "body") is False
    routed = await otp.deliver_otp(PHONE, CODE)
    assert routed.success is False and routed.method == "none"
    assert twilio.clients == [] and twilio.messages == []


async def test_configured_twilio_still_sends(monkeypatch, twilio):
    apply_settings(
        monkeypatch,
        provider_settings(
            TWILIO_ACCOUNT_SID="ACfake",
            TWILIO_AUTH_TOKEN="tok",
            TWILIO_SMS_NUMBER="+15550001111",
            TWILIO_WHATSAPP_NUMBER="+15550002222",
        ),
    )
    sms = otp._send_sms(PHONE, CODE)
    assert (sms.success, sms.method) == (True, "sms")
    assert (
        twilio.clients == [("ACfake", "tok")]
        and twilio.messages[0]["from_"] == "+15550001111"
        and twilio.messages[0]["to"] == PHONE
    )
    assert notif._send_sms_sync(PHONE, "guardian message") is True
    wa = otp._send_whatsapp(PHONE, CODE)
    assert (wa.success, wa.method) == (True, "whatsapp") and twilio.messages[-1][
        "from_"
    ] == "whatsapp:+15550002222"
    assert (await otp.deliver_otp(PHONE, CODE)).success is True


def test_startup_twilio_message_survives_missing_settings(monkeypatch, caplog):
    from app import main

    for name in OPTIONAL:
        monkeypatch.delenv(name, raising=False)
    caplog.set_level(logging.DEBUG)
    main._log_twilio_configuration()  # no exception, no network, no credentials logged
    assert "not configured" in caplog.text.lower()


# ------------------------------------------------------------------------------------------------------------------------------------
# 5. Resend behaviour is intact, and missing credentials never cause an attempt
# ------------------------------------------------------------------------------------------------------------------------------------
async def test_resend_success_never_touches_smtp(monkeypatch, smtp_attempts):
    apply_settings(
        monkeypatch,
        provider_settings(
            RESEND_API_KEY=RESEND_KEY,
            RESEND_FROM_EMAIL="SecureShield <no-reply@mail.example.org>",
        ),
    )
    seen = resend_transport(monkeypatch, 200)
    assert (await otp.deliver_otp(EMAIL, CODE)).success is True
    assert await notif.send_email(EMAIL, "s", "b") is True
    assert len(seen) == 2 and smtp_attempts == []


async def test_resend_failure_falls_back_to_a_configured_smtp(monkeypatch, fake_smtp):
    apply_settings(
        monkeypatch,
        provider_settings(
            RESEND_API_KEY=RESEND_KEY,
            RESEND_FROM_EMAIL="SecureShield <no-reply@mail.example.org>",
        ),
    )
    resend_transport(monkeypatch, 500)
    assert (await otp.deliver_otp(EMAIL, CODE)).success is True
    assert await notif.send_email(EMAIL, "s", "b") is True
    assert len(fake_smtp) == 2


async def test_resend_failure_with_unconfigured_smtp_fails_cleanly(
    monkeypatch, smtp_attempts
):
    apply_settings(
        monkeypatch,
        provider_settings(
            RESEND_API_KEY=RESEND_KEY,
            RESEND_FROM_EMAIL="x <a@b.example>",
            SMTP_HOST="",
            SMTP_USER="",
            SMTP_PASSWORD="",
            SMTP_FROM_EMAIL="",
        ),
    )
    resend_transport(monkeypatch, 500)
    result = await otp.deliver_otp(EMAIL, CODE)
    assert (
        result.success is False
        and result.method == "none"
        and RESEND_KEY not in (result.error or "")
    )
    assert await notif.send_email(EMAIL, "s", "b") is False
    assert smtp_attempts == []


@pytest.mark.parametrize(
    "creds",
    [
        dict(RESEND_API_KEY=RESEND_KEY),
        dict(RESEND_FROM_EMAIL="x <a@b.example>"),
        dict(),
    ],
)
async def test_incomplete_resend_credentials_never_make_a_request(
    monkeypatch, smtp_attempts, creds
):
    apply_settings(
        monkeypatch,
        provider_settings(
            SMTP_HOST="", SMTP_USER="", SMTP_PASSWORD="", SMTP_FROM_EMAIL="", **creds
        ),
    )
    seen = resend_transport(monkeypatch, 200)
    assert (await otp.deliver_otp(EMAIL, CODE)).success is False
    assert await notif.send_email(EMAIL, "s", "b") is False
    assert seen == [] and smtp_attempts == []
