"""Startup-check regression tests.

The checks are the last line of defence between a misconfigured deployment
and real users. These lock in the fail-fast behaviour so a future refactor
can't silently loosen it.
"""

import pytest

from app.config import Settings
from app.startup_checks import (
    StartupCheckError,
    check_admin_token,
    check_cors_configuration,
    check_jwt_secret,
    check_tls_configuration,
    run_startup_checks,
)


def _settings(**overrides) -> Settings:
    base = {
        "DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "MIGRATOR_DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "SECRET_KEY": "something-long-and-random-that-isnt-the-default",
        "SMTP_HOST": "localhost",
        "SMTP_PORT": "1025",
        "SMTP_USER": "t",
        "SMTP_PASSWORD": "t",
        "SMTP_FROM_EMAIL": "t@e.com",
        "ERROR_NOTIFY_EMAIL": "t@e.com",
        "TWILIO_ACCOUNT_SID": "AC",
        "TWILIO_AUTH_TOKEN": "t",
        "TWILIO_SMS_NUMBER": "+15555555555",
        "TWILIO_WHATSAPP_NUMBER": "+15555555555",
        "ADMIN_TOKEN": "real-admin-token-12345",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


# ─── TLS ──────────────────────────────────────────────────────────────────


class TestTlsCheck:
    @pytest.mark.unit
    @pytest.mark.security
    def test_production_without_tls_raises(self):
        s = _settings(
            ENVIRONMENT="production", FORCE_HTTPS=False, TRUST_PROXY_TLS=False
        )
        with pytest.raises(StartupCheckError, match="TLS not configured"):
            check_tls_configuration(s)

    @pytest.mark.unit
    def test_production_with_force_https_passes(self):
        s = _settings(ENVIRONMENT="production", FORCE_HTTPS=True)
        check_tls_configuration(s)  # should not raise

    @pytest.mark.unit
    def test_production_with_trust_proxy_tls_passes(self):
        s = _settings(ENVIRONMENT="production", TRUST_PROXY_TLS=True)
        check_tls_configuration(s)

    @pytest.mark.unit
    def test_development_ignores_tls(self):
        s = _settings(
            ENVIRONMENT="development", FORCE_HTTPS=False, TRUST_PROXY_TLS=False
        )
        check_tls_configuration(s)  # no raise — dev convenience


# ─── JWT secret ───────────────────────────────────────────────────────────


class TestJwtSecret:
    @pytest.mark.unit
    @pytest.mark.security
    def test_production_rejects_default_secret(self):
        s = _settings(
            ENVIRONMENT="production",
            SECRET_KEY="secureshield-secret-key-change-in-prod",
        )
        with pytest.raises(StartupCheckError, match="SECRET_KEY in production"):
            check_jwt_secret(s)

    @pytest.mark.unit
    @pytest.mark.security
    def test_production_rejects_literal_secret(self):
        s = _settings(ENVIRONMENT="production", SECRET_KEY="secret")
        with pytest.raises(StartupCheckError):
            check_jwt_secret(s)

    @pytest.mark.unit
    def test_production_accepts_strong_secret(self):
        s = _settings(
            ENVIRONMENT="production",
            SECRET_KEY="k9-F2Jx7mZ.LpQw3-RVnTbU6Yx8Ag4Bc5De1Hi2JkMo7PqRsTvWxYz0A",
        )
        check_jwt_secret(s)

    @pytest.mark.unit
    def test_development_ignores_secret_strength(self):
        s = _settings(ENVIRONMENT="development", SECRET_KEY="secret")
        check_jwt_secret(s)


# ─── Admin token ──────────────────────────────────────────────────────────


class TestAdminToken:
    @pytest.mark.unit
    @pytest.mark.security
    def test_production_rejects_placeholder_admin_token(self):
        s = _settings(
            ENVIRONMENT="production", ADMIN_TOKEN="secureshield-admin-CHANGEME"
        )
        with pytest.raises(StartupCheckError, match="ADMIN_TOKEN"):
            check_admin_token(s)

    @pytest.mark.unit
    @pytest.mark.security
    def test_production_rejects_empty_admin_token(self):
        s = _settings(ENVIRONMENT="production", ADMIN_TOKEN="")
        with pytest.raises(StartupCheckError):
            check_admin_token(s)

    @pytest.mark.unit
    def test_production_accepts_real_admin_token(self):
        s = _settings(ENVIRONMENT="production", ADMIN_TOKEN="a-real-admin-token")
        check_admin_token(s)


# ─── CORS ─────────────────────────────────────────────────────────────────


class TestCorsCheck:
    @pytest.mark.unit
    @pytest.mark.security
    def test_production_rejects_wildcard_cors(self):
        s = _settings(ENVIRONMENT="production", CORS_ALLOWED_ORIGINS="*")
        with pytest.raises(StartupCheckError, match="CORS_ALLOWED_ORIGINS"):
            check_cors_configuration(s)

    @pytest.mark.unit
    def test_production_accepts_empty_cors(self):
        # Empty = fail-closed (zero origins), which is correct for API-only
        # backends with no browser clients.
        s = _settings(ENVIRONMENT="production", CORS_ALLOWED_ORIGINS="")
        check_cors_configuration(s)

    @pytest.mark.unit
    def test_production_accepts_explicit_list(self):
        s = _settings(
            ENVIRONMENT="production", CORS_ALLOWED_ORIGINS="https://admin.example.com"
        )
        check_cors_configuration(s)


# ─── Composite runner ────────────────────────────────────────────────────


class TestRunStartupChecks:
    @pytest.mark.unit
    def test_dev_passes_all_checks(self):
        s = _settings(ENVIRONMENT="development")
        run_startup_checks(s)  # no raise

    @pytest.mark.unit
    @pytest.mark.security
    def test_prod_with_safe_config_passes(self):
        s = _settings(
            ENVIRONMENT="production",
            TRUST_PROXY_TLS=True,
            TRUSTED_PROXIES="100.64.0.0/10",  # FG-167: required behind a proxy
            SECRET_KEY="k9-F2Jx7mZ.LpQw3-RVnTbU6Yx8Ag4Bc5De1Hi2JkMo7PqRsTvWxYz0A",
            ADMIN_TOKEN="a-real-admin-token",
            CORS_ALLOWED_ORIGINS="https://admin.example.com",
        )
        run_startup_checks(s)

    @pytest.mark.unit
    @pytest.mark.security
    def test_prod_fails_fast_on_first_problem(self):
        # Missing TLS — should raise before even looking at the secret
        s = _settings(
            ENVIRONMENT="production", FORCE_HTTPS=False, TRUST_PROXY_TLS=False
        )
        with pytest.raises(StartupCheckError, match="TLS"):
            run_startup_checks(s)
