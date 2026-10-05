"""
Rate limiter
============
Pluggable sliding-window rate limiter.

**Current default: in-memory**. See `RateLimiter` below — same semantics as
the original implementation, backed by a threading.Lock'd defaultdict.

**Phase 1B scaffold for distributed deployments**. The limiter is now
exposed via the `RateLimiterBackend` protocol so swapping in a Redis
implementation later is a one-line config change. See
`make_rate_limiter()` for the factory.

Public API (unchanged):
  - rate_limiter                       — module-level singleton
  - check_otp_send_rate(identifier)   — 5 requests per hour, raises 429
  - check_otp_verify_rate(identifier) — 10 requests per 15 min, raises 429
  - RateLimitMiddleware               — 100 requests per minute per IP, returns 429 JSON
"""

import json
import os
import threading
import time
from collections import defaultdict
from typing import Callable, Protocol

from fastapi import HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings
from app.services.logger_service import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Backend protocol — anything implementing this is a valid rate limiter.
# ---------------------------------------------------------------------------
class RateLimiterBackend(Protocol):
    """Sliding-window rate limiter interface.

    Any class implementing these three methods can be used as the limiter.
    This indirection lets us swap in a Redis-backed implementation in
    Phase 1B/2 without touching every call site.
    """

    def is_allowed(self, key: str, max_hits: int, window_seconds: int) -> bool: ...
    def reset(self, key: str) -> None: ...
    def current_count(self, key: str, window_seconds: int) -> int: ...


# ---------------------------------------------------------------------------
# In-memory implementation (default)
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Sliding-window rate limiter backed by an in-memory dict.

    Thread-safe via threading.Lock.
    Automatically evicts old timestamps when checking to keep memory bounded.

    **Limitation**: single-process only. Each uvicorn worker has its own
    counters, so under -w > 1 the effective per-key limit is multiplied by
    worker count. Use the Redis backend (future) in multi-worker/replica
    deployments. See `make_rate_limiter()`.
    """

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_hits: int, window_seconds: int) -> bool:
        """
        Return True if the request is allowed.
        Return False if the rate limit has been exceeded.

        Args:
            key:            Unique identifier (IP, phone, email, etc.)
            max_hits:       Maximum number of requests allowed in the window.
            window_seconds: Length of the sliding window in seconds.
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            # Evict timestamps outside the window
            self._hits[key] = [t for t in self._hits[key] if t > cutoff]
            count = len(self._hits[key])

            if count >= max_hits:
                return False

            self._hits[key].append(now)
            return True

    def reset(self, key: str) -> None:
        """Clear all recorded hits for a key (e.g. after successful OTP verify)."""
        with self._lock:
            self._hits.pop(key, None)

    def current_count(self, key: str, window_seconds: int) -> int:
        """Return how many hits exist within the window (for debugging)."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            return sum(1 for t in self._hits.get(key, []) if t > cutoff)


# ---------------------------------------------------------------------------
# Factory — picks backend based on config
# ---------------------------------------------------------------------------
def make_rate_limiter() -> RateLimiterBackend:
    """Choose the correct backend for this deployment.

    Current logic:
      • REDIS_URL env var set → log a WARNING that Redis backend is not
        yet implemented but reserved for Phase 1B, fall back to in-memory.
      • Otherwise → in-memory.

    When the Redis backend lands (separate PR), only this function changes.
    Call sites keep using the module-level `rate_limiter` singleton.
    """
    redis_url = os.getenv("REDIS_URL", "").strip()
    if redis_url:
        # Guardrail for Phase 1B — intentional explicit log, not a silent fallback.
        logger.warning(
            "REDIS_URL is set (%s) but the Redis rate-limiter backend is not "
            "yet implemented. Falling back to in-memory limiter. In a "
            "multi-worker deployment this means per-key limits scale with "
            "worker count — treat as a known gap until Phase 1B lands.",
            redis_url.split("@")[-1],  # avoid logging credentials
        )
    return RateLimiter()


# ---------------------------------------------------------------------------
# Singleton instance — call sites use this directly.
# ---------------------------------------------------------------------------
rate_limiter: RateLimiterBackend = make_rate_limiter()


# ---------------------------------------------------------------------------
# OTP-specific helpers (raise HTTPException on limit exceeded)
# ---------------------------------------------------------------------------
def check_otp_send_rate(identifier: str) -> None:
    """
    Enforce OTP send rate limit: max 5 sends per identifier per hour.

    Raises:
        HTTPException 429 — if limit exceeded.
    """
    key = f"otp_send:{identifier}"
    if not rate_limiter.is_allowed(
        key, max_hits=settings.OTP_SEND_LIMIT, window_seconds=3600
    ):
        logger.warning(f"OTP send rate limit exceeded for: {identifier[:6]}***")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many OTP requests. "
                f"You can request at most {settings.OTP_SEND_LIMIT} codes per hour. "
                f"Please wait before trying again."
            ),
            headers={"Retry-After": "3600"},
        )


def check_otp_verify_rate(identifier: str) -> None:
    """
    Enforce OTP verify rate limit: max 10 attempts per identifier per 15 minutes.

    Raises:
        HTTPException 429 — if limit exceeded.
    """
    key = f"otp_verify:{identifier}"
    if not rate_limiter.is_allowed(
        key, max_hits=settings.OTP_VERIFY_LIMIT, window_seconds=900
    ):
        logger.warning(f"OTP verify rate limit exceeded for: {identifier[:6]}***")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many verification attempts. "
                f"You can attempt at most {settings.OTP_VERIFY_LIMIT} times per 15 minutes. "
                f"Please wait before trying again."
            ),
            headers={"Retry-After": "900"},
        )


# ---------------------------------------------------------------------------
# Middleware — global IP-level rate limit
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that limits requests to API_RATE_LIMIT per minute per IP.
    Returns a 429 JSON response when exceeded.

    Skips: /health, /docs, /openapi.json, /redoc
    """

    SKIP_PATHS = frozenset({"/health", "/", "/docs", "/openapi.json", "/redoc"})

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip health / docs endpoints
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        key = f"api_ip:{client_ip}"

        allowed = rate_limiter.is_allowed(
            key,
            max_hits=settings.API_RATE_LIMIT,
            window_seconds=60,
        )

        if not allowed:
            logger.warning(
                f"API rate limit hit for IP: {client_ip} on {request.url.path}"
            )
            body = json.dumps(
                {
                    "detail": (
                        f"Rate limit exceeded. Maximum {settings.API_RATE_LIMIT} requests "
                        f"per minute allowed per IP address."
                    ),
                    "error": "rate_limit_exceeded",
                }
            )
            return Response(
                content=body,
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        return await call_next(request)

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract real IP, respecting X-Forwarded-For for reverse proxies."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first (client) IP in the chain
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"
