"""Per-user cap on AI endpoints (each call costs money and seconds of model time)."""

from fastapi import HTTPException, status

from app.config import settings
from app.middleware.rate_limiter import rate_limiter
from app.models.user import User


def check_ai_rate(user: User) -> None:
    if not rate_limiter.is_allowed(
        f"ai:{user.id}", max_hits=settings.AI_REQUESTS_PER_MINUTE, window_seconds=60
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many AI requests. Please wait a minute and try again.",
            headers={"Retry-After": "60"},
        )
