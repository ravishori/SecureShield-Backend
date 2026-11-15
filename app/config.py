import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent


# URL helpers live in app.db_url (settings-free); re-exported here so existing imports keep working.
from app.db_url import (  # noqa: E402,F401
    _LIBPQ_ONLY_PARAMS,
    ASYNCPG_INT_OPTIONS,
    normalize_async_db_url,
    split_asyncpg_options,
)


ENV_FILE_VARIABLE = "SECURESHIELD_ENV_FILE"


class ConfigError(RuntimeError):
    """The configuration source selection is unusable. Messages never contain file contents or values."""


def _resolve_env_files() -> tuple[str, ...]:
    """Return the ONE environment file the operator selected, or ``()``.

    ``backend/.env`` is never loaded implicitly: a file is read only when ``SECURESHIELD_ENV_FILE`` names it. A selected
    file that does not exist is a configuration error (fail closed), not a silent fall-through to defaults.
    """
    selected = os.environ.get(ENV_FILE_VARIABLE, "").strip()
    if not selected:
        return ()
    if not Path(selected).is_file():
        raise ConfigError(
            f"{ENV_FILE_VARIABLE} is set but names a file that does not exist; "
            "fix the variable or unset it. No fallback file is read."
        )
    return (selected,)


def warn_if_unselected_env_file() -> bool:
    """Log (once, no values) that an existing ``backend/.env`` is not being read. Returns True when it warned."""
    if os.environ.get(ENV_FILE_VARIABLE, "").strip():
        return False
    if not (_BACKEND_DIR / ".env").exists():
        return False
    logging.getLogger(__name__).warning(
        "backend/.env exists but is NOT read (no implicit .env loading). "
        "Set %s to select an environment file explicitly.",
        ENV_FILE_VARIABLE,
    )
    return True


warn_if_unselected_env_file()


class Settings(BaseSettings):
    # ============================================================
    # Database
    # ============================================================
    # DATABASE_URL          → secureshield_app (FastAPI runtime only)
    # MIGRATOR_DATABASE_URL → secureshield_migrator (Alembic only)
    # Both required — no fallback between roles.
    DATABASE_URL: str
    MIGRATOR_DATABASE_URL: str

    @field_validator("TRUSTED_PROXIES")
    @classmethod
    def _validate_trusted_proxies(cls, v: str) -> str:
        from app.services.client_ip import parse_trusted_proxies

        parse_trusted_proxies(v)  # raises ValueError -> startup fails closed
        return v

    def trusted_proxy_networks(self):
        from app.services.client_ip import parse_trusted_proxies

        return parse_trusted_proxies(self.TRUSTED_PROXIES)

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
    # SMTP is OPTIONAL: with no provider configured the application still runs and every e-mail path reports "not configured"
    # (see app/services/smtp_config.py). Delivery needs ALL of host, user, password and sender. SMTP_PORT keeps its original
    # required, validated integer form.
    SMTP_HOST: str = ""
    SMTP_PORT: int
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    # HTTPS email provider (preferred where outbound SMTP is blocked, e.g. Railway)
    RESEND_API_KEY: str = ""
    RESEND_FROM_EMAIL: str = ""

    # Google Sign-In: comma-separated OAuth client IDs whose ID tokens are accepted (web + Android)
    GOOGLE_CLIENT_IDS: str = ""
    # Recipient of error-alert e-mails; empty = no alert e-mails.
    ERROR_NOTIFY_EMAIL: str = ""

    # ============================================================
    # TWILIO (SMS + WhatsApp)
    # ============================================================
    # Twilio is OPTIONAL: empty values mean "SMS/WhatsApp not configured" (the senders already check and report that).
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_SMS_NUMBER: str = ""
    TWILIO_WHATSAPP_NUMBER: str = ""

    # ============================================================
    # RATE LIMITING
    # ============================================================
    OTP_SEND_LIMIT: int = 5
    OTP_VERIFY_LIMIT: int = 10
    API_RATE_LIMIT: int = 100
    # Failed admin-token attempts allowed (across ALL sources) per window before every admin
    # authentication is answered 429. See app/routers/admin_errors.py and FG-166.
    ADMIN_AUTH_FAIL_LIMIT: int = 10
    ADMIN_AUTH_FAIL_WINDOW_SECONDS: int = 900

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

    # Upload size caps (MB). Uploads are streamed to disk and rejected with 413 beyond these.
    MAX_EVIDENCE_MB: int = 50
    # urlsafe-base64 of 32 random bytes. When set, uploaded files are AES-256-GCM encrypted at rest.
    FILE_ENCRYPTION_KEY: str = ""
    # Optional keyring for rotation, "1:<b64>,2:<b64>"; FILE_ENCRYPTION_ACTIVE_KEY_ID picks the key for new files.
    FILE_ENCRYPTION_KEYS: str = ""
    FILE_ENCRYPTION_ACTIVE_KEY_ID: str = ""
    MAX_RECORDING_MB: int = 200

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
    # DATABASE IDENTITY / RETENTION SAFETY (app/db_identity.py)
    # ============================================================
    # "local" | "test" | "staging" | "production". Must agree with ENVIRONMENT; checked at startup, not here.
    DATABASE_ENVIRONMENT: str = ""
    # Extra non-production hosts a development/test environment may use (comma-separated hostnames). Production-registry
    # endpoints are refused even when listed here.
    DEV_DATABASE_ALLOWED_HOSTS: str = ""
    # Additional production endpoint ids/hostnames, added to config/production_endpoints.txt (never removes entries).
    PRODUCTION_DATABASE_ENDPOINTS: str = ""
    # Additional production database NAMES (comma-separated), added to the "database:" lines of config/production_endpoints.txt.
    # Such a name is refused outside production on any host (localhost, an SSH tunnel and a port forward included).
    PRODUCTION_DATABASE_NAMES: str = ""
    # Only the exact value "true" (case-insensitive, trimmed) lets retention DELETE rows. Unset = off.
    RETENTION_CLEANUP_ENABLED: Optional[str] = None
    # Guardian-alert outbox worker (independent of Twilio). It can SEND real SMS/e-mail, so it is OFF unless explicitly enabled
    # outside production: None (unset) = on in production only; "true"/"false" overrides in any environment.
    GUARDIAN_WORKER_ENABLED: Optional[bool] = None
    # Worker poll interval in seconds (raw string so a malformed value is detected). Unset = 30; 0, negative or unparsable = off.
    GUARDIAN_OUTBOX_POLL_SECONDS: Optional[str] = None

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

    # ============================================================
    # TRUSTED PROXIES (client IP for rate limiting / attribution) - FG-167
    # ============================================================
    # Comma-separated IPs / CIDR ranges of the reverse proxies whose X-Forwarded-For header may be believed
    # (e.g. "100.64.0.0/10,10.0.0.5"). Empty (default) = trust NO forwarding header: the TCP peer address is the
    # client. Wildcards / "/0" and malformed entries refuse to start. Behind a proxy this MUST be set, otherwise
    # every user shares the proxy's address (production startup refuses to boot in that case when
    # TRUST_PROXY_TLS=true). The same value is passed to uvicorn as --forwarded-allow-ips (see Dockerfile).
    TRUSTED_PROXIES: str = ""

    model_config = SettingsConfigDict(
        env_file=_resolve_env_files() or None,
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
        # Precedence: explicit init values > process environment > the explicitly selected env file > defaults.
        # The process environment must win so a deliberate shell/CI override can never be silently undone by a file.
        return (init_settings, env_settings, dotenv_settings, file_secret_settings)

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

    def guardian_worker_enabled(self) -> bool:
        """Explicit setting wins; otherwise the worker runs in production only (it can send real notifications)."""
        if self.GUARDIAN_WORKER_ENABLED is not None:
            return self.GUARDIAN_WORKER_ENABLED
        return self.is_production()


settings = Settings()


def load_settings() -> Settings:
    """Re-read .env on every call so SMTP/Twilio updates apply without a restart."""
    return Settings()
