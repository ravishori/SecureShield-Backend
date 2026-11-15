"""BH-1 endpoint behaviour: per-user limits on POST /message/analyze and POST /link-scanner/scan.

Real app, real authentication, real database. The limiter clock is replaced by a controllable one so minute and hour
windows can be crossed without sleeping.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from sqlalchemy import func, select

import app.services.user_rate_limits as url
from app.config import settings
from app.models.error_log import ErrorLog

pytestmark = [pytest.mark.integration, pytest.mark.security]

MSG = "/api/v1/message/analyze"
LINK = "/api/v1/link-scanner/scan"
BODY_MSG = {"message_text": "hello there, lunch at one?", "use_ai": False}
BODY_LINK = {"url": "https://example.com/page?token=SECRET-QUERY-VALUE"}


class Clock:
    def __init__(self) -> None:
        self.t = 5000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(url.default_limiter, "_clock", c)
    return c


@pytest.fixture(autouse=True)
def limits(monkeypatch):
    """Small limits: messages 3/min and 5/hour, links 2/min and 4/hour. The global per-IP limiter is moved out of the way."""
    for name, value in (
        ("MESSAGE_ANALYZE_PER_MINUTE", "3"),
        ("MESSAGE_ANALYZE_PER_HOUR", "5"),
        ("LINK_SCAN_PER_MINUTE", "2"),
        ("LINK_SCAN_PER_HOUR", "4"),
    ):
        monkeypatch.setattr(url.rate_limit_settings, name, value)
    monkeypatch.setattr(settings, "API_RATE_LIMIT", 10_000)
    url.default_limiter.clear()
    yield
    url.default_limiter.clear()


@pytest.fixture
def providers(monkeypatch):
    """Safe Browsing / URLhaus doubles that count their calls."""
    calls = {"gsb": 0, "urlhaus": 0}

    def env(name):
        return {
            "status": "safe",
            "safe": True,
            "threats": [],
            "provider": name,
            "reason": None,
            "http_status": None,
            "cached": False,
        }

    async def gsb(u):
        calls["gsb"] += 1
        return env("google_safe_browsing")

    async def uh(u):
        calls["urlhaus"] += 1
        return env("urlhaus")

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", gsb)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", uh)
    return calls


@pytest.fixture
async def user(make_user):
    return await make_user("limited")


async def post_msg(client, headers, **extra):
    return await client.post(MSG, headers=headers, json={**BODY_MSG, **extra})


async def count_error_logs(session_factory) -> int:
    async with session_factory() as s:
        return (
            await s.execute(select(func.count()).select_from(ErrorLog))
        ).scalar_one()


# ----------------------------------------------------------------------------------------------------------------------
async def test_requests_below_the_limit_are_unchanged(
    client, user, auth_headers, providers
):
    h = auth_headers(user)
    r = await post_msg(client, h)
    assert r.status_code == 200 and "verdict" in r.json()
    r = await client.post(LINK, headers=h, json=BODY_LINK)
    assert r.status_code == 200 and r.json()["verdict"] is not None


async def test_minute_limit_returns_a_429_with_the_full_contract(
    client, user, auth_headers, clock
):
    h = auth_headers(user)
    for _ in range(3):
        assert (await post_msg(client, h)).status_code == 200
    r = await post_msg(client, h)
    assert r.status_code == 429
    body = r.json()
    assert (
        body["error_code"] == "rate_limit_exceeded"
        and body["scope"] == "user"
        and body["code"] == 429
    )
    assert (
        body["window"] == "minute"
        and body["retry_after_seconds"] == 60
        and body["error"]
        and body["detail"]
    )
    assert r.headers["Retry-After"] == str(body["retry_after_seconds"])


async def test_hourly_limit_applies_after_the_minute_window_has_moved_on(
    client, user, auth_headers, clock
):
    h = auth_headers(user)
    for _ in range(3):
        assert (await post_msg(client, h)).status_code == 200
    clock.t += 61  # minute window empty again; five per hour allowed
    assert (await post_msg(client, h)).status_code == 200
    assert (await post_msg(client, h)).status_code == 200
    r = await post_msg(client, h)
    assert r.status_code == 429 and r.json()["window"] == "hour"
    assert r.json()["retry_after_seconds"] == 3600 - 61
    clock.t += 3600 - 61  # exactly the advertised wait
    assert (await post_msg(client, h)).status_code == 200


async def test_rejected_requests_consume_no_quota(client, user, auth_headers, clock):
    h = auth_headers(user)
    for _ in range(3):
        await post_msg(client, h)
    for _ in range(25):
        assert (
            await post_msg(client, h)
        ).status_code == 429  # hammering while locked out
    clock.t += 60  # the first three hits expire exactly now
    for _ in range(2):
        assert (
            (await post_msg(client, h)).status_code == 200
        )  # the rejections used up nothing (the hour allows two more)


async def test_users_have_independent_quotas(client, make_user, auth_headers):
    a, b = await make_user("a"), await make_user("b")
    for _ in range(3):
        assert (await post_msg(client, auth_headers(a))).status_code == 200
    assert (await post_msg(client, auth_headers(a))).status_code == 429
    for _ in range(3):
        assert (await post_msg(client, auth_headers(b))).status_code == 200


async def test_each_endpoint_has_its_own_quota(client, user, auth_headers, providers):
    h = auth_headers(user)
    for _ in range(3):
        await post_msg(client, h)
    assert (await post_msg(client, h)).status_code == 429
    assert (
        await client.post(LINK, headers=h, json=BODY_LINK)
    ).status_code == 200  # links unaffected by message use


async def test_unauthenticated_requests_cannot_bypass_authentication_or_create_limiter_state(
    client, user
):
    for headers in (
        {},
        {"Authorization": "Bearer not-a-token"},
        {"Authorization": "Basic abc"},
    ):
        for _ in range(8):
            r = await client.post(MSG, headers=headers, json=BODY_MSG)
            assert r.status_code in (401, 403)
    assert url.default_limiter.key_count() == 0


async def test_identity_comes_only_from_the_token_never_from_headers_or_body(
    client, make_user, auth_headers
):
    a, b = await make_user("a"), await make_user("b")
    for _ in range(3):
        await post_msg(client, auth_headers(a))
    spoof = {
        **auth_headers(a),
        "X-User-Id": str(b.id),
        "X-Forwarded-User": str(b.id),
        "X-Real-IP": "203.0.113.9",
    }
    r = await client.post(
        MSG, headers=spoof, json={**BODY_MSG, "user_id": str(b.id), "sub": str(b.id)}
    )
    assert r.status_code == 429  # still user A's bucket
    # and B's quota is untouched by A's spoof attempts: all three of B's requests succeed
    for _ in range(3):
        assert (await post_msg(client, auth_headers(b))).status_code == 200


async def test_an_inactive_or_unknown_user_never_reaches_the_limiter(
    client, make_user, auth_headers
):
    gone = await make_user("gone", is_active=False)
    r = await post_msg(client, auth_headers(gone))
    assert r.status_code == 401
    assert url.default_limiter.key_count() == 0


async def test_concurrent_requests_cannot_exceed_the_limit(
    client, user, auth_headers, monkeypatch
):
    monkeypatch.setattr(url.rate_limit_settings, "MESSAGE_ANALYZE_PER_MINUTE", "10")
    monkeypatch.setattr(url.rate_limit_settings, "MESSAGE_ANALYZE_PER_HOUR", "50")
    h = auth_headers(user)
    results = await asyncio.gather(*[post_msg(client, h) for _ in range(40)])
    codes = [r.status_code for r in results]
    assert (
        codes.count(200) == 10 and codes.count(429) == 30 and set(codes) == {200, 429}
    )


async def test_link_provider_is_not_called_after_a_rejected_request(
    client, user, auth_headers, providers
):
    h = auth_headers(user)
    for _ in range(2):
        assert (await client.post(LINK, headers=h, json=BODY_LINK)).status_code == 200
    assert providers == {"gsb": 2, "urlhaus": 2}
    for _ in range(5):
        assert (await client.post(LINK, headers=h, json=BODY_LINK)).status_code == 429
    assert providers == {
        "gsb": 2,
        "urlhaus": 2,
    }  # no third-party call, no database row for a rejected request


async def test_a_rejected_link_scan_writes_no_scan_row(
    client, user, auth_headers, providers, session_factory
):
    from app.models.link_scan import LinkScan

    h = auth_headers(user)
    for _ in range(2):
        await client.post(LINK, headers=h, json=BODY_LINK)
    for _ in range(3):
        await client.post(LINK, headers=h, json=BODY_LINK)
    async with session_factory() as s:
        n = (await s.execute(select(func.count()).select_from(LinkScan))).scalar_one()
    assert n == 2


async def test_rate_limit_rejections_are_not_written_to_the_error_log(
    client, user, auth_headers, session_factory
):
    h = auth_headers(user)
    for _ in range(3):
        await post_msg(client, h)
    before = await count_error_logs(session_factory)
    for _ in range(10):
        assert (await post_msg(client, h)).status_code == 429
    assert await count_error_logs(session_factory) == before


async def test_a_limiter_failure_is_a_safe_503_without_a_local_fallback(
    client, user, auth_headers, monkeypatch, session_factory
):
    def broken(*a, **k):
        raise RuntimeError("store down")

    monkeypatch.setattr(url.default_limiter, "check_and_record", broken)
    before = await count_error_logs(session_factory)
    r = await post_msg(client, auth_headers(user))
    assert r.status_code == 503 and r.headers["Retry-After"] == "5"
    body = r.json()
    assert (
        body["error_code"] == "rate_limit_unavailable"
        and body["retry_after_seconds"] == 5
        and "store down" not in r.text
    )
    assert await count_error_logs(session_factory) == before


async def test_an_invalid_or_unsupported_configuration_fails_closed_with_503(
    client, user, auth_headers, monkeypatch, providers
):
    h = auth_headers(user)
    monkeypatch.setattr(
        url.rate_limit_settings, "RATE_LIMIT_BACKEND", "redis"
    )  # not implemented in this release
    assert (await post_msg(client, h)).status_code == 503
    assert (await client.post(LINK, headers=h, json=BODY_LINK)).status_code == 503
    assert providers == {"gsb": 0, "urlhaus": 0}  # the analysis did not run
    monkeypatch.setattr(url.rate_limit_settings, "RATE_LIMIT_BACKEND", None)
    monkeypatch.setattr(
        url.rate_limit_settings, "MESSAGE_ANALYZE_PER_MINUTE", "not-a-number"
    )
    assert (await post_msg(client, h)).status_code == 503


async def test_more_than_one_worker_configuration_fails_closed(
    client, user, auth_headers, monkeypatch
):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    assert (await post_msg(client, auth_headers(user))).status_code == 503


async def test_the_disabled_flag_switches_only_the_user_limiter_off(
    client, user, auth_headers, monkeypatch
):
    monkeypatch.setattr(url.rate_limit_settings, "USER_RATE_LIMIT_ENABLED", "false")
    for _ in range(8):
        assert (await post_msg(client, auth_headers(user))).status_code == 200
    # the per-IP limiter is not part of this switch and still applies
    monkeypatch.setattr(settings, "API_RATE_LIMIT", 3)
    codes = [(await post_msg(client, auth_headers(user))).status_code for _ in range(5)]
    assert 429 in codes


async def test_the_existing_per_ip_limiter_still_works(client, monkeypatch):
    monkeypatch.setattr(settings, "API_RATE_LIMIT", 3)
    codes = []
    last = None
    for _ in range(5):
        last = await client.post(
            MSG, json=BODY_MSG
        )  # unauthenticated: counted by the global middleware
        codes.append(last.status_code)
    assert codes[:3] == [401, 401, 401] or all(c in (401, 403) for c in codes[:3])
    assert (
        codes[3] == 429 and last.json().get("error") == "rate_limit_exceeded"
    )  # the middleware's own body, not the user one
    assert last.headers["Retry-After"] == "60"


async def test_log_lines_contain_no_content_url_token_or_complete_user_id(
    client, user, auth_headers, caplog, monkeypatch
):
    monkeypatch.setattr(url, "_log", url._LogState())  # fresh throttle state
    h = auth_headers(user)
    token = h["Authorization"].split()[1]
    with caplog.at_level(logging.DEBUG):
        for _ in range(3):
            await post_msg(client, h)
        for _ in range(6):
            await post_msg(client, h)
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert "rate limit rejected" in blob and "user_ref=" in blob
    for forbidden in (
        str(user.id),
        str(user.id)[:8],
        user.email,
        user.phone,
        token,
        BODY_MSG["message_text"],
        "SECRET-QUERY-VALUE",
    ):
        assert forbidden not in blob
    assert (
        blob.count("rate limit rejected") == 1
    )  # throttled to one line per user and window


async def test_a_successful_request_adds_exactly_one_hit(client, user, auth_headers):
    await post_msg(client, auth_headers(user))
    key = f"rl:user:message_analyze:{user.id}"
    assert len(url.default_limiter._hits[key]) == 1
    assert url.default_limiter.key_count() == 1


async def test_the_limit_is_attached_once_per_route():
    from app.main import app

    seen = {}
    for route in app.routes:
        path = getattr(route, "path", "")
        if path in (MSG, LINK):
            deps = [
                d
                for d in route.dependant.dependencies
                if getattr(d.call, "__qualname__", "").startswith("user_limit")
            ]
            seen[path] = len(deps)
    assert seen == {MSG: 1, LINK: 1}
