"""Rate-limiter correctness tests.

The limiter protects every OTP endpoint. If the sliding-window logic breaks
quietly (e.g. forgets to prune, double-counts, locks up), attackers can burn
Twilio quota or enumerate accounts. These tests fail-closed.
"""

import time

import pytest

from app.middleware.rate_limiter import RateLimiter


class TestSlidingWindow:
    @pytest.mark.unit
    def test_allows_under_limit(self):
        rl = RateLimiter()
        for _ in range(5):
            assert rl.is_allowed("k", max_hits=5, window_seconds=60) is True

    @pytest.mark.unit
    @pytest.mark.security
    def test_blocks_at_limit(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.is_allowed("k", max_hits=5, window_seconds=60)
        assert rl.is_allowed("k", max_hits=5, window_seconds=60) is False, (
            "6th call within the window must be blocked"
        )

    @pytest.mark.unit
    def test_different_keys_are_independent(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.is_allowed("alice", max_hits=5, window_seconds=60)
        # bob should still be fresh
        assert rl.is_allowed("bob", max_hits=5, window_seconds=60) is True

    @pytest.mark.unit
    def test_reset_clears_hits(self):
        rl = RateLimiter()
        for _ in range(5):
            rl.is_allowed("k", max_hits=5, window_seconds=60)
        rl.reset("k")
        # After reset, limit should restart from zero
        assert rl.is_allowed("k", max_hits=5, window_seconds=60) is True

    @pytest.mark.unit
    def test_old_hits_are_evicted(self):
        # Window must slide: hits outside it stop counting.
        rl = RateLimiter()
        for _ in range(3):
            rl.is_allowed("k", max_hits=3, window_seconds=1)
        assert rl.is_allowed("k", max_hits=3, window_seconds=1) is False
        time.sleep(1.1)  # wait beyond the window
        assert rl.is_allowed("k", max_hits=3, window_seconds=1) is True, (
            "After the window passes, the key must be allowed again"
        )

    @pytest.mark.unit
    def test_current_count_reflects_window(self):
        rl = RateLimiter()
        for _ in range(3):
            rl.is_allowed("k", max_hits=10, window_seconds=60)
        assert rl.current_count("k", window_seconds=60) == 3


class TestConfigDrift:
    @pytest.mark.unit
    @pytest.mark.security
    def test_otp_send_limit_is_reasonable(self):
        from app.config import settings
        # Guardrail: should never go above 20 or below 3 without discussion.
        assert 3 <= settings.OTP_SEND_LIMIT <= 20

    @pytest.mark.unit
    @pytest.mark.security
    def test_api_rate_limit_is_set(self):
        from app.config import settings
        assert settings.API_RATE_LIMIT >= 30
