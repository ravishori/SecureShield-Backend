"""Settings for outbound e-mail fallback and mandatory file encryption.

Kept apart from ``app.config.Settings`` (project convention, see ``app/admin_settings.py``); values come from the same ``.env`` /
process environment (``SECURESHIELD_ENV_FILE`` is honoured). Defaults preserve the previous behaviour.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import _resolve_env_files


class DeliverySettings(BaseSettings):
    # When false, SMTP is never used: not as the OTP fallback after Resend, not for guardian/panic/report notifications and not
    # for error-alert e-mails (those are SMTP-only, so they are switched off). Resend stays the only e-mail provider. Use this on
    # staging while the old SMTP credentials are still deployed.
    SMTP_FALLBACK_ENABLED: bool = True
    # When true the application refuses to start without a valid FILE_ENCRYPTION_KEY and never stores an upload in plaintext.
    FILE_ENCRYPTION_REQUIRED: bool = False

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )


delivery_settings = DeliverySettings()
