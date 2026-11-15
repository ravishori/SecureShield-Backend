"""F1-C03: /auth/check-user no longer reveals whether an identifier has an account."""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.security]

URL = "/api/v1/auth/check-user"
SEND = "/api/v1/auth/send-otp"


async def test_known_and_unknown_identifiers_get_the_identical_response(
    client, make_user
):
    u = await make_user("kn", email="known@example.com", phone="+919822200001")
    cases = {
        "known email": u.email,
        "unknown email": "nobody@example.com",
        "known phone": u.phone,
        "unknown phone": "+919822299999",
    }
    bodies = {}
    for name, ident in cases.items():
        r = await client.get(URL, params={"identifier": ident})
        assert r.status_code == 200, name
        bodies[name] = r.json()
    assert len({tuple(sorted(b.items())) for b in bodies.values()}) == 1
    # nothing about the account is exposed
    assert set(bodies["known email"]) == {"exists", "has_profile"}
    assert str(u.id) not in str(bodies)


async def test_response_does_not_depend_on_account_state(client, make_user):
    legacy = await make_user(
        "lg", email="legacy-cu@example.com", email_verified_at=None
    )
    off = await make_user("off", email="off-cu@example.com", is_active=False)
    a = await client.get(URL, params={"identifier": legacy.email})
    b = await client.get(URL, params={"identifier": off.email})
    c = await client.get(URL, params={"identifier": "ghost@example.com"})
    assert a.json() == b.json() == c.json()


async def test_no_timing_channel_because_no_lookup_is_made(
    client, make_user, monkeypatch
):
    """The handler takes no database session at all, so existence cannot influence its running time."""
    import inspect

    from app.routers.auth import check_user

    assert "db" not in inspect.signature(check_user).parameters
    u = await make_user("tm", email="timing@example.com")
    t = []
    for ident in (u.email, "absent@example.com"):
        t0 = time.perf_counter()
        for _ in range(5):
            await client.get(URL, params={"identifier": ident})
        t.append(time.perf_counter() - t0)
    assert abs(t[0] - t[1]) < 0.5  # same code path; generous bound to avoid flakiness


async def test_rate_limit_still_applies(client):
    codes = [
        (await client.get(URL, params={"identifier": f"r{i}@example.com"})).status_code
        for i in range(32)
    ]
    assert codes[:30] == [200] * 30 and codes[30:] == [429, 429]


async def test_sign_in_still_works_without_the_existence_check(
    client, make_user, monkeypatch
):
    """Login needs only send-otp + verify-otp; send-otp answers the same for known and unknown identifiers."""
    from types import SimpleNamespace

    sent = []

    async def _fake(identifier, code):
        sent.append((identifier, code))
        return SimpleNamespace(success=True, error=None, method="x")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _fake)
    u = await make_user("lg2", email="login-ok@example.com")
    known = await client.post(SEND, json={"identifier": u.email})
    unknown = await client.post(SEND, json={"identifier": "unknown-login@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json()["message"] == unknown.json()["message"]
    assert [i for i, _ in sent] == [u.email]  # a code goes only to the real account
    r = await client.post(
        "/api/v1/auth/verify-otp", json={"identifier": u.email, "code": sent[0][1]}
    )
    assert r.status_code == 200
