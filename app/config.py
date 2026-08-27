from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent


def _resolve_env_files() -> tuple[str, ...]:
    """Always load backend/.env — the single secrets file for the API."""
    return (str(_BACKEND_DIR / ".env"),)


class Settings(BaseSettings):
    # ============================================================
    # Database
    # ============================================================
    DATABASE_URL: str
    MIGRATOR_DATABASE_URL: str = ""

    # ============================================================
    # Auth
    # ============================================================
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # ============================================================
    # AI
    # ============================================================
    ANTHROPIC_API_KEY: str = ""

    # ============================================================
    # Threat intelligence
    # ============================================================
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    # ============================================================
    # EMAIL (SMTP)
    # ============================================================
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASSWORD: str
    SMTP_FROM_EMAIL: str
    ERROR_NOTIFY_EMAIL: str

    # ============================================================
    # TWILIO (SMS + WhatsApp)
    # ============================================================
    TWILIO_ACCOUNT_SID: str
    TWILIO_AUTH_TOKEN: str
    TWILIO_SMS_NUMBER: str
    TWILIO_WHATSAPP_NUMBER: str

    # ============================================================
    # RATE LIMITING
    # ============================================================
    OTP_SEND_LIMIT: int = 5
    OTP_VERIFY_LIMIT: int = 10
    API_RATE_LIMIT: int = 100

    # ============================================================
    # SECURITY
    # ============================================================
    LOG_RETENTION_DAYS: int = 90

    # ============================================================
    # OBSERVABILITY
    # ============================================================
    ADMIN_TOKEN: str = ""
    SQL_ECHO: bool = False

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files() or (str(_PROJECT_ROOT / ".env"),),
        env_file_encoding="utf-8",
        extra="ignore",
        env_ignore_empty=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # .env must win over leftover shell/process variables so credential
        # updates apply without restarting the terminal session.
        return (init_settings, dotenv_settings, env_settings, file_secret_settings)

    @model_validator(mode="after")
    def _default_migrator_url(self) -> "Settings":
        if not self.MIGRATOR_DATABASE_URL:
            sync_url = self.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
            object.__setattr__(self, "MIGRATOR_DATABASE_URL", sync_url)
        return self


settings = Settings()


def load_settings() -> Settings:
    """Re-read .env on every call so SMTP/Twilio updates apply without a restart."""
    return Settings()
