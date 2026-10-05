"""Factory + protocol tests for the rate limiter.

Phase 1B scaffolds the backend behind a protocol so a Redis-backed
limiter can swap in later without touching call sites. These tests
guard the swap boundary.
"""


import pytest

from app.middleware.rate_limiter import (
    RateLimiter,
    RateLimiterBackend,
    make_rate_limiter,
    rate_limiter,
)


class TestFactory:
    @pytest.mark.unit
    def test_default_backend_is_in_memory(self, monkeypatch):
        # No REDIS_URL set → in-memory
        monkeypatch.delenv("REDIS_URL", raising=False)
        instance = make_rate_limiter()
        assert isinstance(instance, RateLimiter)

    @staticmethod
    def _recording_logger(monkeypatch):
        """Replace the module logger with a stub that records formatted
        warnings. Independent of logging propagation/handler config, which
        the app reconfigures at import time (breaking ``caplog``)."""
        import app.middleware.rate_limiter as rl

        recorded: list[str] = []

        class _Stub:
            def warning(self, msg, *args, **kwargs):
                recorded.append(msg % args if args else msg)

            def __getattr__(self, name):  # info/error/etc. — ignore
                return lambda *a, **k: None

        monkeypatch.setattr(rl, "logger", _Stub())
        return recorded

    @pytest.mark.unit
    def test_redis_url_warns_but_falls_back(self, monkeypatch):
        # REDIS_URL set but backend not yet implemented → warn + in-memory
        monkeypatch.setenv("REDIS_URL",
                           "redis://user:password@redis.example.com:6379")
        recorded = self._recording_logger(monkeypatch)
        instance = make_rate_limiter()
        assert isinstance(instance, RateLimiter)
        assert any("REDIS_URL" in m for m in recorded), (
            "Setting REDIS_URL must log a warning that the Redis backend "
            "is not yet implemented — silent fallback is a trap"
        )

    @pytest.mark.unit
    @pytest.mark.security
    def test_redis_warning_does_not_leak_credentials(self, monkeypatch):
        # The log line must not contain the username:password portion
        monkeypatch.setenv("REDIS_URL",
                           "redis://admin:supersecret@redis.example.com:6379")
        recorded = self._recording_logger(monkeypatch)
        make_rate_limiter()
        assert recorded, "expected a warning to be logged (test would be vacuous)"
        for message in recorded:
            assert "supersecret" not in message
            assert "admin:" not in message
            assert "redis.example.com" in message  # host still useful for ops


class TestProtocolConformance:
    """The in-memory RateLimiter must satisfy RateLimiterBackend protocol."""

    @pytest.mark.unit
    def test_is_allowed_signature(self):
        rl: RateLimiterBackend = RateLimiter()
        assert rl.is_allowed("k", 5, 60) is True

    @pytest.mark.unit
    def test_reset_signature(self):
        rl: RateLimiterBackend = RateLimiter()
        rl.is_allowed("k", 5, 60)
        rl.reset("k")  # must not raise

    @pytest.mark.unit
    def test_current_count_signature(self):
        rl: RateLimiterBackend = RateLimiter()
        rl.is_allowed("k", 5, 60)
        assert rl.current_count("k", 60) == 1


class TestSingletonConsistency:
    @pytest.mark.unit
    def test_module_singleton_implements_backend(self):
        # The module-level `rate_limiter` must be usable as RateLimiterBackend
        assert hasattr(rate_limiter, "is_allowed")
        assert hasattr(rate_limiter, "reset")
        assert hasattr(rate_limiter, "current_count")
