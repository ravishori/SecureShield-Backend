"""OTP hardening: one valid code at a time, per-code attempt limit, atomic single use, per-source send limit,
uniform failures. Real PostgreSQL and routes; only the outbound delivery call is replaced."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from app.models.user import OTP
from app.routers import auth as auth_router
from app.services.otp_codes import OTP_MAX_ATTEMPTS, hash_challenge

pytestmark = pytest.mark.integration

REGISTER = "/api/v1/auth/register"
SEND = "/api/v1/auth/send-otp"
VERIFY = "/api/v1/auth/verify-otp"
REG_VERIFY = "/api/v1/auth/register/verify"
GENERIC = "Invalid or expired OTP. Please request a new one."


@pytest.fixture
def delivered(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def _fake(identifier, code):
        sent.append((identifier, code))
        return SimpleNamespace(success=True, error=None, method="email")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _fake)
    return sent


def last_code(delivered, identifier):
    return [c for i, c in delivered if i == identifier][-1]


def wrong_code(real: str) -> str:
    return "000000" if real != "000000" else "111111"


async def verify(client, identifier, code):
    return await client.post(VERIFY, json={"identifier": identifier, "code": code})


async def test_a_new_code_invalidates_the_previous_one(client, delivered, make_user):
    ident = "resend@example.com"
    await make_user(email=ident)
    assert (await client.post(SEND, json={"identifier": ident})).status_code == 200
    first = last_code(delivered, ident)
    assert (await client.post(SEND, json={"identifier": ident})).status_code == 200
    second = last_code(delivered, ident)

    if first != second:
        assert (await verify(client, ident, first)).status_code == 400
    assert (await verify(client, ident, second)).status_code == 200


async def test_registering_again_does_not_leave_older_codes_valid(
    client, delivered, db
):
    ident = "reg-old@example.com"
    body = {
        "first_name": "Test",
        "email": ident,
        "consent": {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"},
    }
    assert (await client.post(REGISTER, json=body)).status_code == 200
    stale = last_code(delivered, ident)
    assert (await client.post(REGISTER, json=body)).status_code == 200
    fresh = last_code(delivered, ident)
    open_rows = (
        (
            await db.execute(
                select(OTP).where(OTP.email == ident, OTP.is_used.is_(False))
            )
        )
        .scalars()
        .all()
    )
    assert len(open_rows) == 1
    if stale != fresh:
        r = await client.post(REG_VERIFY, json={"identifier": ident, "code": stale})
        assert r.status_code == 400


async def test_resend_for_a_pending_registration_reissues_only_the_register_code(
    client, delivered, db
):
    ident = "pending-resend@example.com"
    await client.post(
        REGISTER,
        json={
            "first_name": "Test",
            "email": ident,
            "consent": {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"},
        },
    )
    first = last_code(delivered, ident)
    r = await client.post(SEND, json={"identifier": ident})
    assert r.status_code == 200
    second = last_code(delivered, ident)
    rows = (await db.execute(select(OTP).where(OTP.email == ident))).scalars().all()
    assert {o.purpose for o in rows} == {"register"}
    assert len([o for o in rows if not o.is_used]) == 1
    if first != second:
        stale = await client.post(REG_VERIFY, json={"identifier": ident, "code": first})
        assert stale.status_code == 400
    ok = await client.post(REG_VERIFY, json={"identifier": ident, "code": second})
    assert ok.status_code == 200


async def test_code_is_burned_after_the_attempt_limit(client, delivered, db, make_user):
    ident = "burn@example.com"
    await make_user(email=ident)
    await client.post(SEND, json={"identifier": ident})
    real = last_code(delivered, ident)
    bad = wrong_code(real)
    for i in range(OTP_MAX_ATTEMPTS):
        r = await verify(client, ident, bad)
        assert r.status_code == 400 and r.json()["detail"] == GENERIC, i
    # the correct code no longer works: the OTP was burned, not merely throttled
    r = await verify(client, ident, real)
    assert r.status_code == 400 and r.json()["detail"] == GENERIC
    row = (await db.execute(select(OTP).where(OTP.email == ident))).scalars().first()
    await db.refresh(row)
    assert row.is_used and row.attempts == OTP_MAX_ATTEMPTS


async def test_attempts_below_the_limit_do_not_block_the_right_code(
    client, delivered, make_user
):
    ident = "below@example.com"
    await make_user(email=ident)
    await client.post(SEND, json={"identifier": ident})
    real = last_code(delivered, ident)
    for _ in range(OTP_MAX_ATTEMPTS - 1):
        assert (await verify(client, ident, wrong_code(real))).status_code == 400
    assert (await verify(client, ident, real)).status_code == 200


async def test_attempts_are_counted_per_code_and_per_identifier(
    client, delivered, make_user
):
    a, b = "iso-a@example.com", "iso-b@example.com"
    await make_user(email=a)
    await make_user(email=b)
    await client.post(SEND, json={"identifier": a})
    await client.post(SEND, json={"identifier": b})
    real_b = last_code(delivered, b)
    for _ in range(OTP_MAX_ATTEMPTS):
        await verify(client, a, wrong_code(last_code(delivered, a)))
    assert (
        await verify(client, b, real_b)
    ).status_code == 200  # B is unaffected by A's failures


async def test_a_fresh_code_after_burning_works(client, delivered, make_user):
    ident = "again@example.com"
    await make_user(email=ident)
    await client.post(SEND, json={"identifier": ident})
    for _ in range(OTP_MAX_ATTEMPTS):
        await verify(client, ident, wrong_code(last_code(delivered, ident)))
    await client.post(SEND, json={"identifier": ident})
    assert (await verify(client, ident, last_code(delivered, ident))).status_code == 200


async def test_concurrent_verification_consumes_the_code_exactly_once(
    client, delivered, make_user
):
    ident = "race@example.com"
    await make_user(email=ident)
    await client.post(SEND, json={"identifier": ident})
    code = last_code(delivered, ident)
    results = await asyncio.gather(*[verify(client, ident, code) for _ in range(6)])
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 1, codes
    assert all(c in (200, 400) for c in codes)


async def test_expired_code_is_rejected_and_not_counted_as_open(
    client, delivered, session_factory, make_user
):
    ident = "late@example.com"
    await make_user(email=ident)
    await client.post(SEND, json={"identifier": ident})
    code = last_code(delivered, ident)
    async with session_factory() as s:
        await s.execute(
            text(
                "update otps set expires_at = (now() at time zone 'utc') - interval '1 second' where email = :e"
            ),
            {"e": ident},
        )
        await s.commit()
    r = await verify(client, ident, code)
    assert r.status_code == 400 and r.json()["detail"] == GENERIC


async def test_failures_look_identical_for_unknown_and_known_identifiers(
    client, delivered, make_user
):
    known = "known@example.com"
    await make_user(email=known)
    await client.post(SEND, json={"identifier": known})
    wrong = await verify(client, known, wrong_code(last_code(delivered, known)))
    unknown = await verify(client, "nobody-here@example.com", "123456")
    assert wrong.status_code == unknown.status_code == 400
    assert wrong.json() == unknown.json() and wrong.json()["detail"] == GENERIC


async def test_send_otp_answers_the_same_for_registered_and_unknown_identifiers(
    client, delivered, make_user
):
    u = await make_user("reg")
    a = await client.post(SEND, json={"identifier": u.email})
    b = await client.post(SEND, json={"identifier": "never-seen@example.com"})
    assert a.status_code == b.status_code == 200
    assert set(a.json()) == set(b.json())
    assert a.json()["message"] == b.json()["message"]


async def test_send_limit_per_source_applies_across_identifiers(
    client, delivered, monkeypatch, make_user
):
    monkeypatch.setattr(auth_router, "OTP_SEND_IP_LIMIT", 3)
    for i in range(5):
        await make_user(email=f"spray{i}@example.com")
    codes = []
    for i in range(5):
        r = await client.post(SEND, json={"identifier": f"spray{i}@example.com"})
        codes.append(r.status_code)
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]
    assert len(delivered) == 3  # nothing was sent once the source was capped


async def test_the_code_is_never_in_a_response_or_stored_in_clear(
    client, delivered, db, make_user
):
    ident = "secret@example.com"
    await make_user(email=ident)
    r = await client.post(SEND, json={"identifier": ident})
    code = last_code(delivered, ident)
    assert code not in r.text
    row = (await db.execute(select(OTP).where(OTP.email == ident))).scalars().first()
    assert (
        row.code == hash_challenge(code, "email", ident, "login") and row.code != code
    )
    assert row.attempts == 0 and row.expires_at > datetime.utcnow()
    assert row.expires_at - datetime.utcnow() <= timedelta(minutes=10, seconds=5)


async def test_burning_the_newest_code_does_not_bring_an_older_one_back(
    client, delivered, make_user
):
    """Needs the explicit invalidation on resend: without it, the older code becomes the newest *open* code again."""
    ident = "resurrect@example.com"
    await make_user(email=ident)
    await client.post(SEND, json={"identifier": ident})
    first = last_code(delivered, ident)
    await client.post(SEND, json={"identifier": ident})
    second = last_code(delivered, ident)
    for _ in range(OTP_MAX_ATTEMPTS):
        await verify(client, ident, wrong_code(second))
    r = await verify(client, ident, first)
    assert r.status_code == 400 and r.json()["detail"] == GENERIC
