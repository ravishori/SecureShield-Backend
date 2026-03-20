"""
In-Memory Rate Limiter
======================
No external dependencies — uses a threading.Lock + defaultdict of timestamps.

Provides:
  - RateLimiter class for generic sliding-window rate limiting
  - rate_limiter singleton
  - check_otp_send_rate(identifier)   — 5 requests per hour, raises 429
  - check_otp_verify_rate(identifier) — 10 requests per 15 min, raises 429
  - RateLimitMiddleware               — 100 requests per minute per IP, returns 429 JSON
"""

import json
import threading
import time
from collections import defaultdict
from typing import Callable

from fastapi import HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings
from app.services.logger_service import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Core rate-limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Sliding-window rate limiter backed by an in-memory dict.

    Thread-safe via threading.Lock.
    Automatically evicts old timestamps when checking to keep memory bounded.
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
# Singleton instance
# ---------------------------------------------------------------------------
rate_limiter = RateLimiter()


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
    if not rate_limiter.is_allowed(key, max_hits=settings.OTP_SEND_LIMIT, window_seconds=3600):
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
    if not rate_limiter.is_allowed(key, max_hits=settings.OTP_VERIFY_LIMIT, window_seconds=900):
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
            logger.warning(f"API rate limit hit for IP: {client_ip} on {request.url.path}")
            body = json.dumps({
                "detail": (
                    f"Rate limit exceeded. Maximum {settings.API_RATE_LIMIT} requests "
                    f"per minute allowed per IP address."
                ),
                "error": "rate_limit_exceeded",
            })
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
