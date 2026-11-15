"""Global kill switch for EXTERNAL AI processing (containment, Phase 0).

``AI_PROCESSING_ENABLED`` must be set to a true value to let any user content reach an external AI provider. It is
**fail-closed**: unset, empty, misspelt or unparsable all mean "disabled", and the presence of ``ANTHROPIC_API_KEY`` never
enables anything on its own. It is read on every call (environment first, then the backend ``.env`` resolved exactly like the
rest of the settings), so flipping it needs no code change and tests can control it.

This is containment only. It is NOT the per-user consent architecture: when the AI module is built, the user's recorded
``ai_processing`` consent must be checked as well, in addition to this switch (see section 12g of the release document).
"""

from __future__ import annotations

from fastapi import HTTPException, status
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import _resolve_env_files

_TRUE = {"1", "true", "yes", "on"}

UNAVAILABLE_DETAIL = "AI features are currently disabled. Local analysis still works; external AI processing is switched off."


class AIDisabledError(RuntimeError):
    """Raised at the provider boundary when external AI processing is switched off."""


class _Switch(BaseSettings):
    # a plain string, so a malformed value can never raise and can never enable the feature
    AI_PROCESSING_ENABLED: str = "false"

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files(), env_file_encoding="utf-8", extra="ignore"
    )


def ai_enabled() -> bool:
    try:
        return _Switch().AI_PROCESSING_ENABLED.strip().lower() in _TRUE
    except Exception:  # noqa: BLE001 - anything unreadable means "off"
        return False


def ensure_enabled() -> None:
    """The one check every provider call goes through."""
    if not ai_enabled():
        raise AIDisabledError("external AI processing is disabled")


def unavailable_error() -> HTTPException:
    """The clear, non-500 answer for an endpoint that cannot work without the AI provider."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=UNAVAILABLE_DETAIL,
        headers={"X-AI-Status": "disabled"},
    )


def require_enabled() -> None:
    """Endpoint-level guard: 503 + ``X-AI-Status: disabled`` instead of a misleading result."""
    if not ai_enabled():
        raise unavailable_error()
