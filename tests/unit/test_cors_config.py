"""Regression tests for the CORS fail-closed hardening (Phase 1).

If CORS silently reverts to wildcard in production, that's a cross-origin
exposure risk. Lock it down.
"""

import pytest

from app.config import Settings


def _make_settings(**overrides) -> Settings:
    """Build a Settings instance with the required env fixture + overrides."""
    base_env = {
        "DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "MIGRATOR_DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "SECRET_KEY": "test-only",
        "SMTP_HOST": "localhost",
        "SMTP_PORT": "1025",
        "SMTP_USER": "t",
        "SMTP_PASSWORD": "t",
        "SMTP_FROM_EMAIL": "t@example.com",
        "ERROR_NOTIFY_EMAIL": "t@example.com",
        "TWILIO_ACCOUNT_SID": "AC",
        "TWILIO_AUTH_TOKEN": "t",
        "TWILIO_SMS_NUMBER": "+15555555555",
        "TWILIO_WHATSAPP_NUMBER": "+15555555555",
    }
    base_env.update(overrides)
    return Settings(_env_file=None, **base_env)


class TestCorsFailClosed:
    @pytest.mark.unit
    @pytest.mark.security
    def test_empty_allowed_origins_in_production_returns_empty(self):
        s = _make_settings(ENVIRONMENT="production", CORS_ALLOWED_ORIGINS="")
        assert s.cors_allow_origins() == [], (
            "Production + empty CORS allowlist must fail CLOSED (no origins)"
        )

    @pytest.mark.unit
    def test_empty_allowed_origins_in_dev_returns_wildcard(self):
        s = _make_settings(ENVIRONMENT="development", CORS_ALLOWED_ORIGINS="")
        assert s.cors_allow_origins() == ["*"]

    @pytest.mark.unit
    def test_explicit_origins_always_used(self):
        s = _make_settings(
            ENVIRONMENT="production",
            CORS_ALLOWED_ORIGINS="https://admin.example.com,https://ops.example.com",
        )
        assert s.cors_allow_origins() == [
            "https://admin.example.com",
            "https://ops.example.com",
        ]

    @pytest.mark.unit
    @pytest.mark.security
    def test_credentials_never_paired_with_wildcard(self):
        s = _make_settings(ENVIRONMENT="development", CORS_ALLOWED_ORIGINS="")
        assert s.cors_allow_origins() == ["*"]
        assert s.cors_allow_credentials() is False, (
            "allow_origins=['*'] must never be paired with credentials=True "
            "(browsers reject it; FastAPI silently misbehaves)"
        )

    @pytest.mark.unit
    def test_credentials_enabled_with_explicit_origins(self):
        s = _make_settings(
            ENVIRONMENT="production",
            CORS_ALLOWED_ORIGINS="https://admin.example.com",
        )
        assert s.cors_allow_credentials() is True

    @pytest.mark.unit
    def test_credentials_disabled_when_empty_prod(self):
        s = _make_settings(ENVIRONMENT="production", CORS_ALLOWED_ORIGINS="")
        assert s.cors_allow_credentials() is False
