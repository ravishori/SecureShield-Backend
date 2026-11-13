"""Endpoint-level per-IP limits use the SAME client identity as the global limiter (peer unless a trusted proxy vouches for the
forwarded address). Exercises the app's trust logic with a simulated peer address; no real proxy or socket is involved."""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

import app.middleware.rate_limiter as rl
from app.config import settings

pytestmark = [pytest.mark.integration, pytest.mark.security]
URL = "/api/v1/auth/check-user"  # 30 lookups / minute / client identity
PROXY = "100.64.0.9"


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(
        settings, "API_RATE_LIMIT", 10_000
    )  # isolate the endpoint limit from the global limiter
    yield
    for k in list(rl.rate_limiter._hits):
        if k.startswith("check_user_ip:"):
            rl.rate_limiter.reset(k)


@pytest_asyncio.fixture
async def from_peer(session_factory):
    from app.database import get_db
    from app.main import app

    async def _db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _db
    made = []

    def make(peer: str) -> httpx.AsyncClient:
        c = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(peer, 4000)),
            base_url="http://test",
        )
        made.append(c)
        return c

    try:
        yield make
    finally:
        for c in made:
            await c.aclose()
        app.dependency_overrides.pop(get_db, None)


async def lookup(c, **headers):
    return (
        await c.get(URL, params={"identifier": "nobody@example.com"}, headers=headers)
    ).status_code


async def test_rotating_forwarded_for_from_an_untrusted_peer_does_not_evade_the_endpoint_limit(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "")
    c = from_peer("198.51.100.4")
    codes = [await lookup(c, **{"X-Forwarded-For": f"10.0.0.{i}"}) for i in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429


async def test_naming_a_victim_in_the_header_cannot_exhaust_the_victims_budget(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "")
    attacker = from_peer("198.51.100.4")
    for _ in range(31):
        await lookup(attacker, **{"X-Forwarded-For": "203.0.113.7"})
    victim = from_peer("203.0.113.7")
    assert await lookup(victim) == 200


async def test_behind_a_trusted_proxy_each_forwarded_client_has_its_own_endpoint_budget(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", PROXY)
    proxy = from_peer(PROXY)
    for _ in range(31):
        last = await lookup(proxy, **{"X-Forwarded-For": "203.0.113.7"})
    assert last == 429
    assert await lookup(proxy, **{"X-Forwarded-For": "203.0.113.8"}) == 200


async def test_behind_a_trusted_proxy_a_client_prefix_cannot_evade_the_limit(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", PROXY)
    proxy = from_peer(PROXY)
    codes = [
        await lookup(proxy, **{"X-Forwarded-For": f"10.9.9.{i}, 203.0.113.7"})
        for i in range(31)
    ]
    assert codes[30] == 429


async def test_without_trusted_proxies_everyone_behind_the_proxy_shares_one_bucket(
    from_peer, monkeypatch
):
    """The documented cost of failing safe: with TRUSTED_PROXIES unset the proxy's address is the only identity."""
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "")
    proxy = from_peer(PROXY)
    for i in range(30):
        await lookup(proxy, **{"X-Forwarded-For": f"203.0.113.{i}"})
    assert await lookup(proxy, **{"X-Forwarded-For": "203.0.113.200"}) == 429
