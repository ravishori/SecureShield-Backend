"""FG-167 end to end through the REAL RateLimitMiddleware: the identity used for the per-IP limit is the TCP peer
unless that peer is an explicitly trusted proxy. The peer address is set on the ASGI transport; this exercises the
app's trust logic, NOT a real reverse proxy (no proxy/uvicorn socket is involved)."""

from __future__ import annotations

from typing import AsyncIterator, Callable

import httpx
import pytest
import pytest_asyncio

import app.middleware.rate_limiter as rl
from app.config import settings

pytestmark = [pytest.mark.integration, pytest.mark.security]

LIMIT = 3
PATH = "/api/v1/__no_such_route__"  # passes through the limiter; 404 when allowed


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(settings, "API_RATE_LIMIT", LIMIT)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "")
    yield
    for k in list(rl.rate_limiter._hits):
        if k.startswith("api_ip:"):
            rl.rate_limiter.reset(k)


@pytest_asyncio.fixture
async def from_peer(session_factory) -> AsyncIterator[Callable]:
    """Factory: an HTTP client whose TCP peer address is ``peer``."""
    from app.database import get_db
    from app.main import app

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    clients: list[httpx.AsyncClient] = []

    def make(peer: str) -> httpx.AsyncClient:
        c = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(peer, 40000)),
            base_url="http://test",
        )
        clients.append(c)
        return c

    try:
        yield make
    finally:
        for c in clients:
            await c.aclose()
        app.dependency_overrides.pop(get_db, None)


async def hit(c: httpx.AsyncClient, **headers) -> int:
    return (await c.get(PATH, headers=headers)).status_code


# ------------------------------------------------------------------ the attack
def legacy_identity(xff: str | None, peer: str) -> str:
    """The pre-FG-167 rule, kept here only to show what it allowed."""
    return xff.split(",")[0].strip() if xff else peer


def test_the_legacy_rule_gave_an_attacker_a_fresh_identity_per_request():
    ids = {legacy_identity(f"198.51.100.{i}", "203.0.113.7") for i in range(50)}
    assert len(ids) == 50  # 50 requests, 50 budgets: the limit never bit


async def test_rotating_x_forwarded_for_from_an_untrusted_peer_cannot_evade_the_limit(
    from_peer,
):
    c = from_peer("203.0.113.7")
    codes = [
        await hit(c, **{"X-Forwarded-For": f"198.51.100.{i}"}) for i in range(LIMIT + 7)
    ]
    assert codes[:LIMIT] == [404] * LIMIT  # allowed (route does not exist)
    assert (
        codes[LIMIT:] == [429] * 7
    )  # everything after the budget is limited, whatever the header says


async def test_same_for_every_spelling_and_shape_of_the_header(from_peer):
    c = from_peer("203.0.113.7")
    shapes = [
        "1.1.1.1",
        "2.2.2.2, 3.3.3.3",
        "::1",
        "[2001:db8::1]:443",
        "garbage",
        "",
        "10.0.0.1",
        "203.0.113.8",
    ]
    codes = [await hit(c, **{"X-Forwarded-For": s}) for s in shapes]
    assert codes[:LIMIT] == [404] * LIMIT and set(codes[LIMIT:]) == {429}


async def test_x_real_ip_and_other_forwarding_headers_are_ignored(from_peer):
    c = from_peer("203.0.113.7")
    codes = [
        await hit(
            c,
            **{
                "X-Real-IP": f"9.9.9.{i}",
                "Forwarded": f"for=8.8.8.{i}",
                "X-Client-IP": f"7.7.7.{i}",
            },
        )
        for i in range(LIMIT + 3)
    ]
    assert codes[:LIMIT] == [404] * LIMIT and set(codes[LIMIT:]) == {429}


async def test_a_victim_cannot_be_framed_by_naming_their_address(from_peer):
    attacker, victim = from_peer("203.0.113.7"), from_peer("198.51.100.99")
    for _ in range(LIMIT + 5):
        await hit(attacker, **{"X-Forwarded-For": "198.51.100.99"})
    assert await hit(attacker) == 429  # the attacker used up the attacker's budget
    assert await hit(victim) == 404  # the victim is untouched


async def test_clients_with_different_peers_have_independent_budgets(from_peer):
    a, b = from_peer("203.0.113.7"), from_peer("203.0.113.8")
    for _ in range(LIMIT):
        assert await hit(a) == 404
    assert await hit(a) == 429
    assert await hit(b) == 404


async def test_direct_requests_without_any_header_are_limited_by_peer(from_peer):
    c = from_peer("203.0.113.7")
    assert [await hit(c) for _ in range(LIMIT + 1)] == [404] * LIMIT + [429]


async def test_ipv6_peers_are_limited_and_isolated_from_ipv4(from_peer):
    v6 = from_peer("2001:db8::10")
    for _ in range(LIMIT):
        assert await hit(v6, **{"X-Forwarded-For": "1.2.3.4"}) == 404
    assert await hit(v6, **{"X-Forwarded-For": "5.6.7.8"}) == 429
    assert await hit(from_peer("203.0.113.7")) == 404


async def test_ipv4_mapped_ipv6_peer_shares_the_ipv4_budget(from_peer):
    for _ in range(LIMIT):
        assert await hit(from_peer("203.0.113.7")) == 404
    assert await hit(from_peer("::ffff:203.0.113.7")) == 429


async def test_localhost_peer_is_a_normal_identity(from_peer):
    c = from_peer("127.0.0.1")
    assert [
        await hit(c, **{"X-Forwarded-For": f"1.1.1.{i}"}) for i in range(LIMIT + 1)
    ] == [404] * LIMIT + [429]


# ------------------------------------------------------------------ trusted proxy configured
async def test_trusted_proxy_peer_lets_the_forwarded_client_be_limited_individually(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "10.0.0.0/8")
    proxy = from_peer("10.0.0.5")
    a, b = {"X-Forwarded-For": "203.0.113.7"}, {"X-Forwarded-For": "203.0.113.8"}
    for _ in range(LIMIT):
        assert await hit(proxy, **a) == 404
    assert await hit(proxy, **a) == 429  # client A exhausted ...
    assert (
        await hit(proxy, **b) == 404
    )  # ... client B behind the same proxy is not collateral damage


async def test_trusted_proxy_chain_client_prefix_cannot_be_used_to_evade(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "10.0.0.0/8")
    proxy = from_peer("10.0.0.5")
    # the attacker rotates what it writes; the proxy appends the real address it saw
    codes = [
        await hit(proxy, **{"X-Forwarded-For": f"6.6.6.{i}, 203.0.113.9"})
        for i in range(LIMIT + 4)
    ]
    assert codes[:LIMIT] == [404] * LIMIT and set(codes[LIMIT:]) == {429}


async def test_trusted_proxy_with_multiple_header_lines_is_joined_in_order(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "10.0.0.0/8")
    proxy = from_peer("10.0.0.5")
    two_lines = [("X-Forwarded-For", "6.6.6.6"), ("X-Forwarded-For", "203.0.113.9")]
    for _ in range(LIMIT):
        assert (await proxy.get(PATH, headers=two_lines)).status_code == 404
    assert (await proxy.get(PATH, headers=two_lines)).status_code == 429
    # the identity that was limited is the proxy-appended LAST line (203.0.113.9), not the first line (6.6.6.6)
    assert await hit(proxy, **{"X-Forwarded-For": "203.0.113.9"}) == 429
    assert await hit(proxy, **{"X-Forwarded-For": "6.6.6.6"}) == 404
    assert await hit(proxy, **{"X-Forwarded-For": "203.0.113.50"}) == 404


async def test_trusted_proxy_ipv6_clients(from_peer, monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "fd00::/8")
    proxy = from_peer("fd00::5")
    for _ in range(LIMIT):
        assert await hit(proxy, **{"X-Forwarded-For": "2001:db8::1"}) == 404
    assert (
        await hit(proxy, **{"X-Forwarded-For": "2001:0db8:0:0:0:0:0:1"}) == 429
    )  # same client, other spelling
    assert await hit(proxy, **{"X-Forwarded-For": "2001:db8::2"}) == 404


async def test_malformed_forwarded_value_from_a_trusted_proxy_falls_back_to_the_proxy_identity(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "10.0.0.0/8")
    proxy = from_peer("10.0.0.5")
    codes = [
        await hit(proxy, **{"X-Forwarded-For": f"junk-{i}"}) for i in range(LIMIT + 2)
    ]
    assert codes[:LIMIT] == [404] * LIMIT and set(codes[LIMIT:]) == {429}


async def test_an_untrusted_peer_gets_no_benefit_from_proxies_being_configured(
    from_peer, monkeypatch
):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "10.0.0.0/8")
    c = from_peer("203.0.113.7")  # not in the trusted range
    codes = [
        await hit(c, **{"X-Forwarded-For": f"198.51.100.{i}"}) for i in range(LIMIT + 4)
    ]
    assert codes[:LIMIT] == [404] * LIMIT and set(codes[LIMIT:]) == {429}


# ------------------------------------------------------------------ nothing else changed
async def test_the_limit_value_and_response_shape_are_unchanged(from_peer):
    c = from_peer("203.0.113.7")
    for _ in range(LIMIT):
        await hit(c)
    r = await c.get(PATH)
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    assert r.json()["error"] == "rate_limit_exceeded"
    assert "203.0.113.7" not in r.text


async def test_health_and_docs_remain_exempt(from_peer):
    c = from_peer("203.0.113.7")
    for _ in range(LIMIT + 3):
        assert (await c.get("/health")).status_code != 429
