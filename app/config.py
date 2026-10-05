import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent


def normalize_async_db_url(url: str) -> str:
    """Return a SQLAlchemy ``postgresql+asyncpg://`` URL.

    Railway (and most hosts) hand out ``postgresql://`` or ``postgres://``
    URLs. ``postgres://`` is not a valid SQLAlchemy dialect and bare
    ``postgresql://`` selects psycopg2, which is not installed. An already
    correct ``postgresql+asyncpg://`` URL is returned unchanged.

    asyncpg rejects the libpq ``sslmode`` parameter, so ``?sslmode=X`` is
    rewritten to ``?ssl=X`` (an explicit ``ssl`` wins). No other part of the
    URL is touched, and the URL is never logged here.
    """
    url = url.strip()
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            url = "postgresql+asyncpg://" + url[len(prefix):]
            break
    if not url.startswith("postgresql+asyncpg://"):
        return url
    parts = urlsplit(url)
    if "sslmode" not in parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    has_ssl = any(k == "ssl" for k, _ in pairs)
    out = []
    for k, v in pairs:
        if k == "sslmode":
            if has_ssl:
                continue
            k = "ssl"
        out.append((k, v))
    return urlunsplit(parts._replace(query=urlencode(out)))


def _resolve_env_files() -> tuple[str, ...]:
    """Load backend/.env — the single secrets file for the API.

    ``SECURESHIELD_ENV_FILE`` overrides the path. The test suite points it
    at a non-existent file so pytest can never pick up real credentials
    from backend/.env (dotenv values otherwise win over process env).
    """
    override = os.environ.get("SECURESHIELD_ENV_FILE")
    if override:
        return (override,)
    return (str(_BACKEND_DIR / ".env"),)


class Settings(BaseSettings):
    # ============================================================
    # Database
    # ============================================================
    # DATABASE_URL          → secureshield_app (FastAPI runtime only)
    # MIGRATOR_DATABASE_URL → secureshield_migrator (Alembic only)
    # Both required — no fallback between roles.
    DATABASE_URL: str
    MIGRATOR_DATABASE_URL: str

    @field_validator("DATABASE_URL", "MIGRATOR_DATABASE_URL", mode="before")
    @classmethod
    def _normalize_db_urls(cls, v):
        return normalize_async_db_url(v) if isinstance(v, str) else v

    # ============================================================
    # Auth
    # ============================================================
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    # Shortened from 24h → 1h as a security hardening measure. Mobile clients
    # should rely on the refresh token (30 days) for silent re-issuance. Can
    # be overridden via ACCESS_TOKEN_EXPIRE_MINUTES in .env if a specific
    # deployment needs a different value.
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
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

    # abuse.ch URLhaus requires an Auth-Key (free account) since 2025; without it the
    # provider reports `no_api_key` and the scanner falls back to the other tiers.
    URLHAUS_AUTH_KEY: str = ""

    # Per-user cap on AI endpoints (each call costs money and seconds of model time).
    AI_REQUESTS_PER_MINUTE: int = 10

    # ============================================================
    # CORS (browser clients only; native Android does not need CORS)
    # ============================================================
    # Comma-separated origins, e.g. "https://admin.example.com,http://localhost:3000"
    # Empty + ENVIRONMENT=development → wildcard (dev convenience)
    # Empty + ENVIRONMENT=production  → empty (fail-closed, no CORS at all)
    CORS_ALLOWED_ORIGINS: str = ""

    # ============================================================
    # ENVIRONMENT
    # ============================================================
    # "development" | "staging" | "production"
    # Controls fail-open vs fail-closed defaults (CORS, cleartext checks, etc.)
    ENVIRONMENT: str = "development"

    # ============================================================
    # TLS / HTTPS
    # ============================================================
    # When ENVIRONMENT=production, startup refuses to boot unless the
    # operator has explicitly confirmed TLS is terminated upstream (by a
    # trusted reverse proxy / cloud load balancer). This prevents a
    # cleartext backend being shipped by accident.
    #   • Hosts like Railway / Azure App Service / AWS ALB terminate TLS for us → set TRUST_PROXY_TLS=true
    #   • Running uvicorn with --ssl-keyfile → set FORCE_HTTPS=true
    #   • Local dev → leave both false
    FORCE_HTTPS: bool = False
    TRUST_PROXY_TLS: bool = False

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

    def cors_allow_origins(self) -> list[str]:
        """Resolve the CORS allowlist with fail-closed semantics in prod.

        Rules:
          • Explicit comma-separated list in CORS_ALLOWED_ORIGINS → use as-is.
          • Empty + ENVIRONMENT=production → return [] (NO origins allowed).
          • Empty + any other environment → wildcard [*] (dev convenience).

        The fail-closed path intentionally refuses browser access rather than
        reflecting any origin. Native Android clients do not use CORS so this
        does not affect them.
        """
        raw = (self.CORS_ALLOWED_ORIGINS or "").strip()
        if raw:
            return [origin.strip() for origin in raw.split(",") if origin.strip()]
        if self.ENVIRONMENT.lower() == "production":
            return []
        return ["*"]

    def cors_allow_credentials(self) -> bool:
        # Never pair allow_origins=["*"] with credentials=True.
        origins = self.cors_allow_origins()
        return bool(origins) and origins != ["*"]

    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


settings = Settings()


def load_settings() -> Settings:
    """Re-read .env on every call so SMTP/Twilio updates apply without a restart."""
    return Settings()
