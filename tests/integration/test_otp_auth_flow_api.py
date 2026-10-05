"""OTP generation / verification / delivery failure, token refresh, health
and readiness — real PostgreSQL, real routes, real OTP validation logic.
Only the outbound delivery network call is stubbed."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from app.models.user import OTP

pytestmark = pytest.mark.integration

REGISTER = "/api/v1/auth/register"
VERIFY = "/api/v1/auth/verify-otp"
SEND = "/api/v1/auth/send-otp"
REFRESH = "/api/v1/auth/refresh"
ME = "/api/v1/auth/me"


@pytest.fixture
def delivered(monkeypatch):
    """Record what would be sent (identifier, code) without any network."""
    sent: list[tuple[str, str]] = []

    async def _fake(identifier, code):
        sent.append((identifier, code))
        return SimpleNamespace(success=True, error=None, method="email")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _fake)
    return sent


async def _otp_row(db, email):
    return (
        await db.execute(
            select(OTP).where(OTP.email == email).order_by(OTP.created_at.desc())
        )
    ).scalars().first()


async def _register(client, email):
    r = await client.post(REGISTER, json={"first_name": "Test", "email": email})
    assert r.status_code == 200, r.text


async def test_otp_generation_stores_code_with_ttl_and_delivers_same_code(client, db, delivered):
    await _register(client, "gen@example.com")
    row = await _otp_row(db, "gen@example.com")
    assert row.code.isdigit() and len(row.code) == 6 and not row.is_used
    assert timedelta(minutes=5) < row.expires_at - datetime.utcnow() <= timedelta(minutes=15)
    assert ("gen@example.com", row.code) in delivered


async def test_verify_success_returns_tokens_and_burns_otp(client, db, delivered):
    await _register(client, "ok@example.com")
    code = (await _otp_row(db, "ok@example.com")).code
    r = await client.post(VERIFY, json={"identifier": "ok@example.com", "code": code})
    assert r.status_code == 200 and r.json()["access_token"] and r.json()["refresh_token"]
    # single use
    again = await client.post(VERIFY, json={"identifier": "ok@example.com", "code": code})
    assert again.status_code == 400
    # token works and refresh issues a working access token
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.get(ME, headers=h)).status_code == 200
    rf = await client.post(REFRESH, json={"refresh_token": r.json()["refresh_token"]})
    assert rf.status_code == 200
    h2 = {"Authorization": f"Bearer {rf.json()['access_token']}"}
    assert (await client.get(ME, headers=h2)).json()["email"] == "ok@example.com"


async def test_wrong_and_expired_codes_rejected(client, db, delivered, session_factory):
    await _register(client, "bad@example.com")
    row = await _otp_row(db, "bad@example.com")
    wrong = "000000" if row.code != "000000" else "111111"
    assert (await client.post(VERIFY, json={"identifier": "bad@example.com", "code": wrong})).status_code == 400
    async with session_factory() as s:
        await s.execute(
            text("update otps set expires_at = (now() at time zone 'utc') - interval '1 minute' where email='bad@example.com'")
        )
        await s.commit()
    assert (await client.post(VERIFY, json={"identifier": "bad@example.com", "code": row.code})).status_code == 400


async def test_code_for_one_identifier_does_not_work_for_another(client, db, delivered):
    await _register(client, "a@example.com")
    await _register(client, "b@example.com")
    code_a = (await _otp_row(db, "a@example.com")).code
    code_b = (await _otp_row(db, "b@example.com")).code
    if code_a != code_b:  # random 6-digit codes: only meaningful when they differ
        r = await client.post(VERIFY, json={"identifier": "b@example.com", "code": code_a})
        assert r.status_code == 400


async def test_delivery_failure_on_login_returns_503_and_leaks_nothing(client, db, delivered, monkeypatch):
    await _register(client, "fail@example.com")

    async def _down(identifier, code):
        return SimpleNamespace(success=False, error="smtp down", method="none")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _down)
    r = await client.post(SEND, json={"identifier": "fail@example.com"})
    assert r.status_code == 503
    code = (await _otp_row(db, "fail@example.com")).code
    assert code not in r.text


async def test_health_and_ready_execute_a_real_query(client):
    assert (await client.get("/health")).json() == {"status": "healthy"}
    r = await client.get("/ready")
    assert r.status_code == 200 and r.json()["status"] == "ready"
    assert r.json()["database"]  # came from SELECT current_database()
