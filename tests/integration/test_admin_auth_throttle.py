"""FG-166: failed-attempt throttle for the shared admin token.

Design under test (see app/routers/admin_errors.py): ONE global budget of failed, non-empty token guesses
(settings.ADMIN_AUTH_FAIL_LIMIT per ADMIN_AUTH_FAIL_WINDOW_SECONDS); when it is spent every admin
authentication gets the same 429 without the token being compared; only wrong non-empty tokens consume budget;
the window slides (no permanent lockout); limiter failure denies (fail closed). Time is faked, nothing sleeps.
The limiter under test is the in-memory, per-process one: nothing here proves distributed enforcement.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import app.middleware.rate_limiter as rl
import app.routers.admin_errors as admin_errors
from app.config import settings

pytestmark = [pytest.mark.integration, pytest.mark.security]

TOKEN = "unit-test-admin-token-xyz"  # test value only
BASE = "/api/v1/admin"
ROUTES = ("/stats", "/users", "/audit", "/errors", "/errors/stats/summary")
LIMIT = 4
WINDOW = 600


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", TOKEN)
    monkeypatch.setattr(settings, "ADMIN_AUTH_FAIL_LIMIT", LIMIT)
    monkeypatch.setattr(settings, "ADMIN_AUTH_FAIL_WINDOW_SECONDS", WINDOW)


@pytest.fixture
def clock(monkeypatch):
    """Deterministic time for the in-memory limiter (it reads time.monotonic through the module's `time`)."""
    now = {"t": 1000.0}
    monkeypatch.setattr(rl, "time", SimpleNamespace(monotonic=lambda: now["t"]))
    return now


def status_of(token) -> int:
    try:
        admin_errors._check_admin(token)
        return 200
    except HTTPException as exc:
        return exc.status_code


def burn(n: int, token="wrong") -> list[int]:
    return [status_of(f"{token}{i}") for i in range(n)]


# ------------------------------------------------------------------ boundary
def test_exactly_limit_failures_are_answered_401_then_429(clock):
    assert burn(LIMIT) == [401] * LIMIT  # the Nth failure is still a normal 401
    assert status_of("wrong-again") == 429  # budget spent
    assert status_of("wrong-again-2") == 429


def test_one_failure_below_the_limit_does_not_throttle(clock):
    assert burn(LIMIT - 1) == [401] * (LIMIT - 1)
    assert status_of(TOKEN) == 200  # still under budget: the right token works


def test_correct_token_is_also_refused_while_throttled_and_is_not_compared(
    clock, monkeypatch
):
    burn(LIMIT)
    calls = []
    monkeypatch.setattr(
        admin_errors.hmac, "compare_digest", lambda a, b: calls.append(1) or True
    )
    assert status_of(TOKEN) == 429
    assert status_of("anything") == 429
    assert status_of(None) == 429 and status_of("") == 429
    assert calls == []  # no comparison happens, so a guess gets no feedback at all


# ------------------------------------------------------------------ what consumes budget
def test_successful_authentication_never_consumes_the_budget(clock):
    for _ in range(LIMIT * 5):
        assert status_of(TOKEN) == 200
    assert rl.rate_limiter.current_count("admin_auth_fail", WINDOW) == 0
    assert burn(LIMIT - 1) == [401] * (LIMIT - 1)
    assert status_of(TOKEN) == 200


def test_missing_and_empty_tokens_do_not_consume_the_budget(clock):
    for _ in range(LIMIT * 5):
        assert status_of(None) == 401 and status_of("") == 401
    assert rl.rate_limiter.current_count("admin_auth_fail", WINDOW) == 0
    assert status_of(TOKEN) == 200


def test_success_does_not_refund_or_reset_failures(clock):
    burn(LIMIT - 1)
    assert status_of(TOKEN) == 200
    assert status_of("one-more") == 401  # budget used up by 4th failure
    assert status_of(TOKEN) == 429


@pytest.mark.parametrize(
    "bad", ["x" * 10_000, "\x00", "é" * 30, TOKEN + " ", TOKEN.upper(), TOKEN[:-1]]
)
def test_malformed_and_near_miss_tokens_count_like_any_wrong_token(clock, bad):
    assert status_of(bad) == 401
    assert rl.rate_limiter.current_count("admin_auth_fail", WINDOW) == 1


# ------------------------------------------------------------------ window / reset
def test_failures_age_out_so_access_returns_without_any_reset(clock):
    burn(LIMIT)
    assert status_of(TOKEN) == 429
    clock["t"] += WINDOW - 1
    assert status_of(TOKEN) == 429  # still inside the window
    clock["t"] += 2
    assert status_of(TOKEN) == 200  # oldest failures expired: no permanent lockout


def test_throttled_attempts_are_not_recorded_so_the_window_cannot_be_extended(clock):
    burn(LIMIT)
    for _ in range(50):
        clock["t"] += 1
        assert status_of("hammering") == 429
    assert rl.rate_limiter.current_count("admin_auth_fail", WINDOW) <= LIMIT
    clock["t"] += WINDOW
    assert status_of(TOKEN) == 200


def test_sliding_window_frees_budget_gradually(clock):
    for _ in range(LIMIT):
        assert status_of("w") == 401
        clock["t"] += 100
    assert status_of(TOKEN) == 429  # 4 failures within the 600 s window
    clock["t"] += 250  # the first failure (t=1000) is now older than the window
    assert status_of(TOKEN) == 200


# ------------------------------------------------------------------ unconfigured / fail closed
def test_unconfigured_admin_is_503_and_consumes_no_budget(clock, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    for _ in range(LIMIT * 3):
        assert status_of("guess") == 503
    assert rl.rate_limiter.current_count("admin_auth_fail", WINDOW) == 0


def test_limiter_failure_denies_and_never_fails_open(monkeypatch):
    class Broken:
        def current_count(self, *a):
            raise RuntimeError("redis down")

        def is_allowed(self, *a, **k):
            raise RuntimeError("redis down")

    monkeypatch.setattr(admin_errors, "rate_limiter", Broken())
    assert status_of(TOKEN) == 503  # even the right token: no limiter, no access
    assert status_of("wrong") == 503
    assert status_of(None) == 503


def test_failure_to_record_a_guess_denies_instead_of_returning_401(monkeypatch):
    class RecordFails:
        def current_count(self, *a):
            return 0

        def is_allowed(self, *a, **k):
            raise RuntimeError("redis down")

    monkeypatch.setattr(admin_errors, "rate_limiter", RecordFails())
    assert status_of("wrong") == 503
    assert status_of(TOKEN) == 200  # a correct token needs no recording


def test_a_zero_limit_denies_everything_fail_closed(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_AUTH_FAIL_LIMIT", 0)
    assert status_of(TOKEN) == 429


# ------------------------------------------------------------------ responses
def test_throttle_response_is_generic_and_identical_for_every_input(clock):
    burn(LIMIT)
    seen = set()
    for tok in (TOKEN, TOKEN[:-1], "x", None, "", "é" * 5):
        with pytest.raises(HTTPException) as e:
            admin_errors._check_admin(tok)
        seen.add((e.value.status_code, e.value.detail, tuple(e.value.headers.items())))
    assert len(seen) == 1
    ((status, detail, headers),) = seen
    assert status == 429
    for leak in (
        TOKEN,
        str(LIMIT),
        str(WINDOW),
        "remaining",
        "budget",
        "global",
        "limit",
    ):
        assert leak not in detail.lower()
    assert dict(headers)["Retry-After"] == str(WINDOW)


def test_401_is_identical_for_close_and_far_tokens(clock):
    details = set()
    for tok in (TOKEN[:-1], TOKEN + "x", "z" * 40):
        with pytest.raises(HTTPException) as e:
            admin_errors._check_admin(tok)
        details.add((e.value.status_code, e.value.detail))
    assert len(details) == 1


# ------------------------------------------------------------------ HTTP level
async def test_every_admin_route_family_shares_one_budget(client, clock):
    wrong = {"X-Admin-Token": "wrong-token"}
    codes = []
    for i in range(LIMIT):
        codes.append(
            (
                await client.get(BASE + ROUTES[i % len(ROUTES)], headers=wrong)
            ).status_code
        )
    assert codes == [401] * LIMIT  # failures spread over different route families
    for path in ROUTES:
        good = await client.get(BASE + path, headers={"X-Admin-Token": TOKEN})
        bad = await client.get(BASE + path, headers=wrong)
        none = await client.get(BASE + path)
        assert good.status_code == bad.status_code == none.status_code == 429, path
        assert good.headers["retry-after"] == str(WINDOW)
        assert TOKEN not in good.text and "wrong-token" not in bad.text


async def test_changing_superficial_request_fields_does_not_evade_the_throttle(
    client, clock
):
    for i in range(LIMIT):
        await client.get(
            BASE + "/stats",
            headers={
                "X-Admin-Token": f"w{i}",
                "X-Forwarded-For": f"203.0.113.{i}",
                "User-Agent": f"agent-{i}",
                "Origin": f"https://evil{i}.example",
            },
        )
    r = await client.get(
        BASE + "/stats",
        headers={
            "X-Admin-Token": "w-new",
            "X-Forwarded-For": "198.51.100.77",
            "User-Agent": "something-else",
        },
    )
    assert r.status_code == 429


async def test_http_success_does_not_trip_the_throttle(client, clock):
    for _ in range(LIMIT * 4):
        r = await client.get(BASE + "/stats", headers={"X-Admin-Token": TOKEN})
        assert r.status_code == 200


async def test_throttled_and_failed_attempts_never_log_the_token(
    client, clock, caplog, capsys
):
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="secureshield")
    for i in range(LIMIT + 2):
        await client.get(
            BASE + "/stats", headers={"X-Admin-Token": f"guess-secret-{i}"}
        )
    await client.get(BASE + "/stats", headers={"X-Admin-Token": TOKEN})
    out = capsys.readouterr()
    blob = "\n".join(r.getMessage() for r in caplog.records) + out.out + out.err
    assert TOKEN not in blob and "guess-secret-" not in blob


async def test_existing_global_ip_limiter_is_unchanged(client, monkeypatch):
    """The admin budget is additional: the app-wide per-IP limiter still applies to admin routes."""
    monkeypatch.setattr(settings, "API_RATE_LIMIT", 2)
    codes = [
        (
            await client.get(BASE + "/stats", headers={"X-Admin-Token": TOKEN})
        ).status_code
        for _ in range(4)
    ]
    assert codes[:2] == [200, 200] and codes[2:] == [429, 429]
    rl.rate_limiter.reset("api_ip:testclient")
    rl.rate_limiter.reset("api_ip:127.0.0.1")
    rl.rate_limiter.reset("api_ip:unknown")


# ------------------------------------------------------------------ concurrency
def test_concurrent_failures_cannot_exceed_the_budget():
    import threading

    results = []
    lock = threading.Lock()

    def worker(i):
        s = status_of(f"concurrent-wrong-{i}")
        with lock:
            results.append(s)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(60)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(401) == LIMIT  # never more than the budget evaluated
    assert results.count(429) == 60 - LIMIT


def test_the_check_and_the_record_are_atomic_under_a_widened_race_window(monkeypatch):
    """Without the lock every thread passes the check before any records its failure. The wrapper yields inside
    ``current_count`` to make that interleaving certain; with the lock the budget still holds exactly."""
    import threading
    import time as real_time

    inner = rl.rate_limiter

    class Slow:
        def current_count(self, key, window):
            n = inner.current_count(key, window)
            real_time.sleep(
                0.002
            )  # yield so other threads can run between check and record
            return n

        def is_allowed(self, *a, **k):
            return inner.is_allowed(*a, **k)

    monkeypatch.setattr(admin_errors, "rate_limiter", Slow())
    results, lock = [], threading.Lock()

    def worker(i):
        s = status_of(f"race-wrong-{i}")
        with lock:
            results.append(s)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(401) == LIMIT
    assert results.count(429) == 30 - LIMIT
