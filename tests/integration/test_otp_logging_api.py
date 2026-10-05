"""End-to-end: OTP codes never reach stdout, logs or the error_logs table,
even when delivery really fails (SMTP broken at the network layer)."""

from __future__ import annotations

import smtplib

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

CODE_WRONG = "654321"


class _Recorder:
    def __init__(self):
        self.lines: list[str] = []

    def _rec(self, msg, *args, **kwargs):
        self.lines.append(msg % args if args else str(msg))

    debug = info = warning = error = exception = critical = _rec


@pytest.fixture
def captured(monkeypatch):
    """Record every module logger on the OTP path; break SMTP for real."""
    import app.routers.auth as auth_router
    import app.services.otp_service as otp_service

    rec = _Recorder()
    monkeypatch.setattr(otp_service, "logger", rec)
    monkeypatch.setattr(auth_router, "logger", rec)

    def _smtp(*a, **k):
        raise smtplib.SMTPConnectError(421, "boom")

    monkeypatch.setattr(smtplib, "SMTP", _smtp)
    return rec


async def _error_log_blob(db) -> str:
    rows = (await db.execute(text("select t::text from error_logs t"))).scalars().all()
    return "\n".join(rows)


async def test_register_with_failing_delivery_never_logs_the_otp(client, db, captured, capsys):
    email = "otp-leak-check@example.com"
    r = await client.post("/api/v1/auth/register", json={"first_name": "Leak", "email": email})
    assert r.status_code == 200

    code = (await db.execute(text("select code from otps where email=:e"), {"e": email})).scalar_one()
    assert len(code) >= 4

    out = capsys.readouterr()
    blob = "\n".join(captured.lines) + out.out + out.err + await _error_log_blob(db)
    assert any("OTP delivery failed" in l for l in captured.lines), "failure path not exercised"
    assert code not in blob
    assert email not in blob


async def test_wrong_code_and_malformed_verify_do_not_log_submitted_code(client, db, captured, capsys):
    email = "otp-verify-check@example.com"
    await client.post("/api/v1/auth/register", json={"first_name": "V", "email": email})

    bad = await client.post("/api/v1/auth/verify-otp", json={"identifier": email, "code": CODE_WRONG})
    assert bad.status_code == 400
    # 422: body without identifier -> validation error echoing the input
    invalid = await client.post("/api/v1/auth/verify-otp", json={"code": CODE_WRONG})
    assert invalid.status_code == 422

    out = capsys.readouterr()
    blob = "\n".join(captured.lines) + out.out + out.err + await _error_log_blob(db)
    assert CODE_WRONG not in blob
