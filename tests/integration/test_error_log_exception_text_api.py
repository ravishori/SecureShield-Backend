"""Exception text / tracebacks reach file logs, ``error_logs`` and alert e-mails.
They can carry values the app never meant to log (driver DETAIL lines, pydantic
input echoes, URLs with API keys, tokens). Real exceptions go through the real
``log_error`` and the persisted row + e-mail are inspected."""

import time

import httpx
import pytest
from jose import jwt
from pydantic import BaseModel, EmailStr, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.user import User
from app.services.logger_service import log_error

pytestmark = pytest.mark.integration

EMAIL = "victim.person@example.com"
PHONE = "+919876501234"
API_KEY = "AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKE12345"
BEARER = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
OTP = "482910"
JWT = jwt.encode({"sub": "u1"}, "unit-test-signing-key-material", algorithm="HS256")


@pytest.fixture
def mailer(monkeypatch):
    import app.services.logger_service as ls

    sent = []
    monkeypatch.setattr(ls, "_send_email_sync", lambda s, h, to: sent.append((s, h)))
    return sent


async def _row(db):
    return (await db.execute(text("select message, traceback, extra::text ex, t::text raw from error_logs t"))).mappings().one()


def _wait(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end and not pred():
        time.sleep(0.05)
    return pred()


async def _log(exc_factory, **kw):
    try:
        raise exc_factory()
    except Exception as exc:  # noqa: BLE001 - the point of the test
        await log_error(message="op failed", exc=exc, level="ERROR", endpoint="/x", method="POST", **kw)


async def test_unique_violation_detail_does_not_persist_the_email(db, session_factory, make_user, mailer):
    await make_user("dup", email=EMAIL)
    try:
        async with session_factory() as s:
            s.add(User(email=EMAIL))
            await s.commit()
    except IntegrityError as exc:
        await log_error(message="insert failed", exc=exc, level="ERROR", endpoint="/x", method="POST")
    row = await _row(db)
    assert EMAIL not in row["raw"]
    assert "already exists" in row["raw"]  # useful diagnostics kept


async def test_pydantic_input_echo_is_scrubbed(db, mailer):
    class M(BaseModel):
        email: EmailStr

    def bad():
        try:
            M(email=f"not an email {EMAIL}")
        except ValidationError as e:
            return e

    await _log(bad)
    row = await _row(db)
    assert EMAIL not in row["raw"]


async def test_http_client_error_with_api_key_in_url_is_scrubbed(db, mailer):
    def bad():
        req = httpx.Request("POST", f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}")
        try:
            httpx.Response(403, request=req).raise_for_status()
        except httpx.HTTPStatusError as e:
            return e

    await _log(bad)
    row = await _row(db)
    assert API_KEY not in row["raw"]
    assert "safebrowsing.googleapis.com" in row["raw"]  # host/path still visible


async def test_tokens_and_codes_in_exception_text_are_scrubbed(db, mailer):
    await _log(lambda: RuntimeError(f"upstream said {BEARER} and jwt {JWT} for {PHONE}; otp={OTP}; password=hunter2hunter2"))
    row = await _row(db)
    for secret in (BEARER.split()[1], JWT, PHONE, OTP, "hunter2hunter2"):
        assert secret not in row["raw"], secret
    assert "upstream said" in row["raw"]


async def test_extra_payload_is_scrubbed_recursively(db, mailer):
    await log_error(message="ctx", level="ERROR", extra={"nested": {"who": EMAIL, "list": [f"call {PHONE}"]}, "n": 5})
    row = await _row(db)
    assert EMAIL not in row["raw"] and PHONE not in row["raw"]
    assert '"n": 5' in row["ex"]  # non-string data untouched


async def test_alert_email_is_scrubbed_too(db, mailer):
    await _log(lambda: RuntimeError(f"failed for {EMAIL} using {BEARER}"))
    assert _wait(lambda: len(mailer) == 1)
    subject, html = mailer[0]
    assert EMAIL not in subject + html and BEARER.split()[1] not in subject + html
    assert "RuntimeError" in subject


async def test_diagnostics_survive_for_ordinary_exceptions(db, mailer):
    await _log(lambda: KeyError("missing_field"))
    row = await _row(db)
    assert "KeyError" in row["raw"] and "missing_field" in row["raw"]
    assert "test_error_log_exception_text_api" in row["traceback"]  # traceback frames kept


async def test_huge_messages_are_truncated(db, mailer):
    await _log(lambda: RuntimeError("A" * 200_000))
    row = await _row(db)
    assert len(row["raw"]) < 60_000
