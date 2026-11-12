"""Settings for individually authenticated admin accounts (see ``app/routers/admin_auth.py``).

Kept apart from ``app.config.Settings`` so the main settings file stays untouched; values come from the same
``.env`` / process environment (``SECURESHIELD_ENV_FILE`` is honoured). Every value has a safe default.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import _resolve_env_files


class AdminAuthSettings(BaseSettings):
    # Migration switch. While true the legacy shared ``X-Admin-Token`` keeps working (as an "admin"-role break-glass
    # credential that can never manage admin accounts). Set to false once the named admin accounts are enrolled.
    ADMIN_LEGACY_TOKEN_ENABLED: bool = True
    # Lifetime of one admin access token; /admin/auth/refresh extends it until the session's absolute limit.
    ADMIN_ACCESS_TOKEN_MINUTES: int = Field(default=30, ge=1, le=240)
    # Absolute session lifetime (hours) however often it is refreshed.
    ADMIN_SESSION_MAX_HOURS: int = Field(default=8, ge=1, le=72)
    # Wrong password / MFA attempts on one account before it is locked, and for how long.
    ADMIN_LOGIN_MAX_FAILURES: int = Field(default=5, ge=3, le=20)
    ADMIN_LOCKOUT_MINUTES: int = Field(default=15, ge=1, le=1440)
    # Failed or successful login requests per source address per 15 minutes.
    ADMIN_LOGIN_IP_LIMIT: int = Field(default=30, ge=5, le=1000)
    ADMIN_TOTP_ISSUER: str = "SecureShield AI"

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )


admin_settings = AdminAuthSettings()
