"""BH-1 per-user rate limiting: limiter engine, configuration validation, preflight CLI, logging and handlers.

No database is needed here; the endpoint-level behaviour is in tests/integration/test_user_rate_limit_endpoints.py.
"""

from __future__ import annotations

import io
import math
import threading
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.services.user_rate_limits as url
from app.cli import check_rate_limit_config as cli
from app.middleware import error_handler
from app.startup_checks import (
    StartupCheckError,
    check_rate_limit_configuration,
    run_startup_checks,
)
from app.services.user_rate_limits import (
    Decision,
    RateLimitExceeded,
    RateLimitUnavailable,
    UserRateLimiter,
    validate_rate_limit_config,
)

W = (("minute", 3, 60), ("hour", 5, 3600))  # small windows keep the arithmetic readable


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def limiter(clock):
    return UserRateLimiter(clock=clock)


def hit(limiter, clock, at, key="rl:user:x:u1", windows=W) -> Decision:
    clock.t = 1000.0 + at
    return limiter.check_and_record(key, windows)


# ----------------------------------------------------------------------------------------------------------------------
# Sliding windows, retry timing and boundaries
# ----------------------------------------------------------------------------------------------------------------------
def test_minute_limit_rejects_the_fourth_request_and_reports_the_wait(limiter, clock):
    assert [hit(limiter, clock, t).allowed for t in (0, 1, 2)] == [True] * 3
    d = hit(limiter, clock, 3)
    assert (d.allowed, d.window, d.retry_after_seconds) == (
        False,
        "minute",
        57,
    )  # oldest hit leaves at t=60


def test_boundary_exactly_at_retry_after_is_admitted_and_one_tick_before_is_not(
    limiter, clock
):
    for t in (0, 1, 2):
        hit(limiter, clock, t)
    assert hit(limiter, clock, 59.4).allowed is False  # 0.6 s remain
    assert hit(limiter, clock, 59.4).retry_after_seconds == 1  # rounded up, never zero
    assert (
        hit(limiter, clock, 60.0).allowed is True
    )  # the oldest hit is exactly one window old: expired


def test_hourly_limit_binds_when_the_minute_window_has_room(limiter, clock):
    for t in (
        0,
        1,
        2,
        61,
        62,
    ):  # five hits in total, never more than three in one minute
        assert hit(limiter, clock, t).allowed
    d = hit(limiter, clock, 63)
    assert (d.allowed, d.window) == (False, "hour")
    assert d.retry_after_seconds == math.ceil(0 + 3600 - 63)
    assert (
        hit(limiter, clock, 3600.0).allowed is True
    )  # the first hour-old hit has just expired


def test_both_windows_exceeded_reports_both_and_the_larger_wait(clock):
    lim = UserRateLimiter(clock=clock)
    windows = (("minute", 2, 60), ("hour", 2, 3600))
    hit(lim, clock, 0, windows=windows)
    hit(lim, clock, 1, windows=windows)
    d = hit(lim, clock, 2, windows=windows)
    assert (d.allowed, d.window) == (False, "both")
    assert (
        d.retry_after_seconds == 3598
    )  # the hour wait (3600 - 2), not the minute wait (58)


def test_waiting_exactly_the_reported_time_is_always_enough(limiter, clock):
    for t in (0, 5, 10):
        hit(limiter, clock, t)
    d = hit(limiter, clock, 11)
    assert d.allowed is False
    assert hit(limiter, clock, 11 + d.retry_after_seconds).allowed is True


# ----------------------------------------------------------------------------------------------------------------------
# Atomicity and "rejected requests consume no quota"
# ----------------------------------------------------------------------------------------------------------------------
def test_a_rejected_request_is_recorded_in_neither_window(limiter, clock):
    for t in (0, 1, 2, 61, 62):  # the hour window is now full, the minute window is not
        hit(limiter, clock, t)
    key = "rl:user:x:u1"
    before = list(limiter._hits[key])
    for t in (63, 64, 65, 66):
        assert hit(limiter, clock, t).allowed is False
    assert (
        list(limiter._hits[key]) == before
    )  # nothing was added by any rejection, in any window


def test_repeated_rejections_do_not_extend_the_lockout(limiter, clock):
    for t in (0, 1, 2):
        hit(limiter, clock, t)
    for t in range(3, 50):
        hit(limiter, clock, t)  # hammering while locked out
    assert (
        hit(limiter, clock, 60).allowed is True
    )  # unchanged: the first hit expired at t=60


def test_a_rejection_never_creates_a_key(limiter, clock):
    assert limiter.key_count() == 0
    # a rejection needs prior hits, so a brand-new key can only ever be created by an admitted request
    assert hit(limiter, clock, 0).allowed
    assert limiter.key_count() == 1


def test_users_and_endpoints_have_independent_quotas(limiter, clock):
    for t in (0, 1, 2):
        hit(limiter, clock, t, key="rl:user:message_analyze:A")
    assert hit(limiter, clock, 3, key="rl:user:message_analyze:A").allowed is False
    assert hit(limiter, clock, 3, key="rl:user:message_analyze:B").allowed is True
    assert hit(limiter, clock, 3, key="rl:user:link_scan:A").allowed is True


def test_two_hundred_threads_admit_exactly_the_limit():
    lim = UserRateLimiter()  # real clock
    windows = (("minute", 20, 60), ("hour", 200, 3600))
    barrier = threading.Barrier(200)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        d = lim.check_and_record("rl:user:message_analyze:U", windows)
        with lock:
            results.append(d.allowed)

    threads = [threading.Thread(target=worker) for _ in range(200)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(results) == 20 and len(results) == 200


def test_memory_is_bounded_by_the_key_cap_and_idle_keys_are_swept(clock):
    lim = UserRateLimiter(clock=clock, max_keys=50)
    for i in range(500):
        clock.t = 1000.0 + i
        lim.check_and_record(f"rl:user:x:{i}", W)
    assert lim.key_count() <= 50
    clock.t += 7200  # everything is idle for two hours
    for i in range(512):
        lim.check_and_record("rl:user:x:keepalive", W)
    assert lim.key_count() <= 2


# ----------------------------------------------------------------------------------------------------------------------
# Configuration validation (one function for startup, request time and the preflight)
# ----------------------------------------------------------------------------------------------------------------------
def v(**env):
    return validate_rate_limit_config({"ENVIRONMENT": "staging", **env})


def test_defaults_are_the_approved_limits():
    p = v().policy
    assert p.enabled and p.backend == "memory"
    assert p.windows["message_analyze"] == (("minute", 20, 60), ("hour", 200, 3600))
    assert p.windows["link_scan"] == (("minute", 10, 60), ("hour", 120, 3600))


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " 5",
        "5 ",
        "0",
        "-1",
        "1.5",
        "1e3",
        "0x10",
        "007",
        "100001",
        "five",
        "٣",
        "5\n",
    ],
)
def test_invalid_integers_are_fatal_in_every_environment(bad):
    for environment in ("staging", "production", "development"):
        r = validate_rate_limit_config(
            {"ENVIRONMENT": environment, "MESSAGE_ANALYZE_PER_MINUTE": bad}
        )
        assert not r.ok and r.policy is None
        assert any(i.variable == "MESSAGE_ANALYZE_PER_MINUTE" for i in r.fatal)


def test_hourly_below_minutely_is_fatal_and_equal_is_allowed():
    assert not v(LINK_SCAN_PER_MINUTE="50", LINK_SCAN_PER_HOUR="10").ok
    assert v(LINK_SCAN_PER_MINUTE="10", LINK_SCAN_PER_HOUR="10").ok


@pytest.mark.parametrize("bad", ["yes", "1", "0", "maybe", "", " true", "tru"])
def test_invalid_booleans_are_fatal(bad):
    assert not v(USER_RATE_LIMIT_ENABLED=bad).ok
    assert not v(RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED=bad).ok


@pytest.mark.parametrize("good", ["true", "TRUE", "False", "false"])
def test_valid_booleans_are_accepted_case_insensitively(good):
    assert v(USER_RATE_LIMIT_ENABLED=good).ok


@pytest.mark.parametrize("bad", ["", "Redi", "memory ", "local", "sqlite"])
def test_unknown_backend_is_fatal(bad):
    assert not v(RATE_LIMIT_BACKEND=bad).ok


def test_redis_backend_is_refused_because_it_is_not_implemented():
    for environment in ("development", "staging", "production"):
        r = validate_rate_limit_config(
            {
                "ENVIRONMENT": environment,
                "RATE_LIMIT_BACKEND": "redis",
                "REDIS_URL": "rediss://x",
            }
        )
        assert not r.ok
        assert any("not implemented" in i.rule for i in r.fatal)


def test_missing_or_malformed_redis_configuration_never_reads_as_valid():
    assert not v(RATE_LIMIT_BACKEND="redis").ok  # no URL
    assert not v(RATE_LIMIT_BACKEND="redis", REDIS_URL="not a url").ok


def test_production_memory_needs_the_attestation_but_staging_only_warns():
    prod = validate_rate_limit_config({"ENVIRONMENT": "production"})
    assert not prod.ok and any(
        i.variable == "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED" for i in prod.fatal
    )
    assert validate_rate_limit_config(
        {"ENVIRONMENT": "production", "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED": "true"}
    ).ok
    stg = v()
    assert stg.ok and any(
        i.variable == "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED" for i in stg.warnings
    )
    assert not validate_rate_limit_config(
        {"ENVIRONMENT": "production", "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED": "false"}
    ).ok


@pytest.mark.parametrize("workers", ["2", "4", "16"])
def test_more_than_one_worker_is_refused_even_when_attested(workers):
    for environment in ("staging", "production"):
        r = validate_rate_limit_config(
            {
                "ENVIRONMENT": environment,
                "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED": "true",
                "WEB_CONCURRENCY": workers,
            }
        )
        assert not r.ok and any(i.variable == "WEB_CONCURRENCY" for i in r.fatal)


def test_one_worker_and_garbage_worker_values():
    assert v(WEB_CONCURRENCY="1", RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED="true").ok
    assert not v(WEB_CONCURRENCY="many").ok


def test_environment_resolution_is_fail_safe():
    assert not validate_rate_limit_config({"ENVIRONMENT": "prod"}).ok  # unknown name
    assert (
        validate_rate_limit_config({"ENVIRONMENT": " Staging "}).environment
        == "staging"
    )
    unset_local = validate_rate_limit_config({})
    assert unset_local.ok and unset_local.environment == "development"
    deployed = validate_rate_limit_config(
        {"RAILWAY_SERVICE_ID": "x"}
    )  # a deployed service must say what it is
    assert not deployed.ok and deployed.environment == "production"
    assert not validate_rate_limit_config(
        {"ENVIRONMENT": "  ", "RAILWAY_ENVIRONMENT_NAME": "staging"}
    ).ok


def test_disabled_flag_skips_production_only_checks_but_not_type_errors():
    r = validate_rate_limit_config(
        {"ENVIRONMENT": "production", "USER_RATE_LIMIT_ENABLED": "false"}
    )
    assert r.ok and r.policy is not None and r.policy.enabled is False
    assert not validate_rate_limit_config(
        {
            "ENVIRONMENT": "production",
            "USER_RATE_LIMIT_ENABLED": "false",
            "LINK_SCAN_PER_MINUTE": "abc",
        }
    ).ok


def test_messages_name_variables_and_rules_but_never_values():
    secret = "S3CR3T-VALUE-123"
    r = validate_rate_limit_config(
        {
            "ENVIRONMENT": "production",
            "REDIS_URL": f"rediss://user:{secret}@host:6379",
            "RATE_LIMIT_BACKEND": "redis",
            "MESSAGE_ANALYZE_PER_MINUTE": secret,
        }
    )
    text = " | ".join(str(i) for i in r.issues)
    assert secret not in text and "user:" not in text


# ----------------------------------------------------------------------------------------------------------------------
# Preflight CLI and startup check share the validator
# ----------------------------------------------------------------------------------------------------------------------
def run_cli(env, *argv):
    buf = io.StringIO()
    code = cli.run(list(argv), env=env, out=buf)
    return code, buf.getvalue()


def test_cli_exit_codes_and_output():
    code, out = run_cli({"ENVIRONMENT": "staging"})
    assert (
        code == 0 and "OK" in out and "WARN" in out
    )  # staging without attestation only warns
    code, out = run_cli({"ENVIRONMENT": "production"})
    assert code == 1 and "FATAL RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED" in out
    code, _ = run_cli({"ENVIRONMENT": "staging"}, "--environment", "production")
    assert code == 1  # the manual production check overrides the resolved environment
    code, _ = run_cli(
        {"ENVIRONMENT": "production", "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED": "true"}
    )
    assert code == 0
    code, _ = run_cli({}, "--bogus")
    assert code == 2


def test_cli_internal_failure_exits_two(monkeypatch):
    monkeypatch.setattr(
        cli,
        "validate_rate_limit_config",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    code, out = run_cli({"ENVIRONMENT": "staging"})
    assert code == 2 and "RuntimeError" in out and "boom" not in out


@pytest.mark.parametrize(
    "env",
    [
        {"ENVIRONMENT": "staging"},
        {"ENVIRONMENT": "production"},
        {"ENVIRONMENT": "production", "RATE_LIMIT_SINGLE_INSTANCE_CONFIRMED": "true"},
        {"ENVIRONMENT": "staging", "WEB_CONCURRENCY": "3"},
        {"ENVIRONMENT": "staging", "RATE_LIMIT_BACKEND": "redis"},
        {"ENVIRONMENT": "nope"},
        {"RAILWAY_SERVICE_ID": "x"},
    ],
)
def test_startup_check_and_preflight_give_the_same_verdict(env, monkeypatch):
    for name in url.SETTING_NAMES:
        monkeypatch.setattr(url.rate_limit_settings, name, env.get(name))
    for k in ("ENVIRONMENT", "WEB_CONCURRENCY", "REDIS_URL", *url.RAILWAY_MARKERS):
        monkeypatch.delenv(k, raising=False)
    for k, val in env.items():
        if k not in url.SETTING_NAMES:
            monkeypatch.setenv(k, val)
    code, _ = run_cli(env)
    try:
        check_rate_limit_configuration(SimpleNamespace())
        startup_ok = True
    except StartupCheckError:
        startup_ok = False
    assert startup_ok == (code == 0)


def test_startup_check_is_part_of_the_standard_checks_and_is_secret_free(monkeypatch):
    monkeypatch.setattr(url.rate_limit_settings, "RATE_LIMIT_BACKEND", "redis")
    with pytest.raises(StartupCheckError) as exc:
        run_startup_checks(
            SimpleNamespace(is_production=lambda: False),
            checks=[check_rate_limit_configuration],
        )
    assert "RATE_LIMIT_BACKEND" in str(exc.value) and "redis" not in str(
        exc.value
    ).replace("'redis'", "")
    from app.startup_checks import _CHECKS

    assert check_rate_limit_configuration in _CHECKS


# ----------------------------------------------------------------------------------------------------------------------
# Enforcement, fail-closed behaviour, handlers and logging
# ----------------------------------------------------------------------------------------------------------------------
def test_enforce_raises_429_then_503_on_limiter_failure_and_invalid_configuration(
    monkeypatch, clock
):
    lim = UserRateLimiter(clock=clock)
    monkeypatch.setattr(url.rate_limit_settings, "MESSAGE_ANALYZE_PER_MINUTE", "1")
    monkeypatch.setattr(url.rate_limit_settings, "MESSAGE_ANALYZE_PER_HOUR", "1")
    uid = uuid.uuid4()
    url.enforce_user_limit("message_analyze", uid, lim)
    with pytest.raises(RateLimitExceeded) as e:
        url.enforce_user_limit("message_analyze", uid, lim)
    assert e.value.window == "both" and e.value.retry_after_seconds == 3600

    class Broken:
        def check_and_record(self, *a, **k):
            raise RuntimeError("store down")

    with pytest.raises(RateLimitUnavailable):
        url.enforce_user_limit(
            "link_scan", uid, Broken()
        )  # fail closed: no fallback to a weaker limiter
    monkeypatch.setattr(url.rate_limit_settings, "RATE_LIMIT_BACKEND", "redis")
    with pytest.raises(RateLimitUnavailable):
        url.enforce_user_limit("link_scan", uid, lim)


def test_disabled_policy_admits_everything(monkeypatch, clock):
    lim = UserRateLimiter(clock=clock)
    monkeypatch.setattr(url.rate_limit_settings, "USER_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setattr(url.rate_limit_settings, "MESSAGE_ANALYZE_PER_MINUTE", "1")
    for _ in range(50):
        url.enforce_user_limit("message_analyze", uuid.uuid4(), lim)
    assert lim.key_count() == 0


def test_the_handlers_render_the_contract_and_never_touch_the_error_log(monkeypatch):
    async def forbidden(*a, **k):
        raise AssertionError(
            "a rate-limit response must not be written to the error log"
        )

    monkeypatch.setattr(error_handler, "log_error", forbidden)
    app = FastAPI()
    error_handler.register_exception_handlers(app)

    @app.get("/limited")
    async def limited():
        raise RateLimitExceeded("hour", 1234)

    @app.get("/down")
    async def down():
        raise RateLimitUnavailable()

    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/limited")
    assert r.status_code == 429 and r.headers["Retry-After"] == "1234"
    body = r.json()
    assert (
        body["error_code"] == "rate_limit_exceeded"
        and body["scope"] == "user"
        and body["code"] == 429
    )
    assert (
        body["window"] == "hour"
        and body["retry_after_seconds"] == 1234
        and "1234" in body["detail"]
    )
    r = c.get("/down")
    assert r.status_code == 503 and r.headers["Retry-After"] == "5"
    body = r.json()
    assert (
        body["error_code"] == "rate_limit_unavailable"
        and body["retry_after_seconds"] == 5
        and "detail" in body
    )


def test_log_lines_are_bounded_throttled_and_free_of_identifiers(monkeypatch):
    clock = Clock(0.0)
    monkeypatch.setattr(url, "_log", url._LogState(clock=clock))
    lines = []
    monkeypatch.setattr(
        url.logger, "warning", lambda msg, *a: lines.append(msg % a if a else msg)
    )
    users = [uuid.uuid4() for _ in range(300)]
    for u in users:  # an attack from 300 distinct users within one minute
        url.log_event("rejected", "message_analyze", "minute", url.user_ref(u))
    assert len(lines) <= 30
    clock.t += 61
    url.log_event("rejected", "message_analyze", "minute", url.user_ref(users[0]))
    assert any(
        "summary" in line and "suppressed_lines=270" in line for line in lines
    )  # counts only, no per-request lines
    blob = "\n".join(lines)
    for u in users:
        assert str(u) not in blob and str(u)[:8] not in blob


def test_one_line_per_user_and_window_until_the_window_passes(monkeypatch):
    clock = Clock(0.0)
    monkeypatch.setattr(url, "_log", url._LogState(clock=clock))
    lines = []
    monkeypatch.setattr(url.logger, "warning", lambda msg, *a: lines.append(msg))
    ref = url.user_ref(uuid.uuid4())
    for _ in range(20):
        url.log_event("rejected", "link_scan", "minute", ref)
    assert len([x for x in lines if "rate limit rejected" in x]) == 1
    clock.t += 61
    url.log_event("rejected", "link_scan", "minute", ref)
    assert len([x for x in lines if "rate limit rejected" in x]) == 2


def test_the_log_throttle_table_is_capped(monkeypatch):
    clock = Clock(0.0)
    state = url._LogState(clock=clock, table_cap=10, per_minute_cap=10_000)
    monkeypatch.setattr(url, "_log", state)
    monkeypatch.setattr(url.logger, "warning", lambda *a: None)
    for i in range(200):
        url.log_event("rejected", "link_scan", "minute", f"u{i:07d}")
    assert len(state.seen) <= 10


def test_user_reference_is_a_keyed_hash_not_an_id_prefix():
    u = uuid.uuid4()
    ref = url.user_ref(u)
    assert (
        len(ref) == 8 and ref == url.user_ref(u) and ref != url.user_ref(uuid.uuid4())
    )
    assert ref not in str(u).replace("-", "")
