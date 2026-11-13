"""Production readiness checks run at app startup.

Each check returns None on pass or raises ``RuntimeError`` with a precise
message on fail. The goal is to make it impossible to accidentally ship
an insecure configuration to production:

  • TLS must be in front of the backend (either via a trusted proxy or
    the app's own uvicorn SSL)
  • CORS fail-closed must be configured
  • JWT secret must not be the development default
  • ADMIN_TOKEN must not be the placeholder
  • behind a TLS-terminating proxy, TRUSTED_PROXIES must be set (client IP / rate limiting)

In development the checks are permissive — they log warnings but don't
raise, so local work stays frictionless.
"""

from __future__ import annotations

import logging
from typing import Iterable

from app.config import Settings

logger = logging.getLogger(__name__)

# Known-bad values that must never ship to production.
_DEV_DEFAULT_SECRETS = frozenset(
    {
        "secureshield-secret-key-change-in-prod",
        "secret",
        "changeme",
        "",
    }
)
# NOTE: comparisons are case-insensitive via .lower() at call site;
# entries here MUST already be lowercase.
_DEV_DEFAULT_ADMIN_TOKENS = frozenset(
    {
        "secureshield-admin-changeme",
        "changeme",
        "admin",
        "",
    }
)


class StartupCheckError(RuntimeError):
    """Raised when a production readiness check fails."""


def check_tls_configuration(settings: Settings) -> None:
    """Reject production startup when neither FORCE_HTTPS nor TRUST_PROXY_TLS is set.

    One of them MUST be true in production — otherwise the backend is
    serving plaintext and the auth tokens it issues can be intercepted on
    the wire.
    """
    if not settings.is_production():
        return
    if settings.FORCE_HTTPS or settings.TRUST_PROXY_TLS:
        return
    raise StartupCheckError(
        "TLS not configured for production. Set TRUST_PROXY_TLS=true if a "
        "trusted reverse proxy (Azure App Service, AWS ALB, nginx, etc.) "
        "terminates TLS in front of this backend, OR set FORCE_HTTPS=true "
        "and run uvicorn with --ssl-keyfile/--ssl-certfile. Refusing to "
        "boot a cleartext backend in production."
    )


def check_jwt_secret(settings: Settings) -> None:
    """Reject production startup when SECRET_KEY is a known-dev default."""
    if not settings.is_production():
        return
    if settings.SECRET_KEY.strip().lower() in _DEV_DEFAULT_SECRETS:
        raise StartupCheckError(
            "SECRET_KEY in production is the development default. Generate a "
            "new 256-bit secret (e.g. `python -c 'import secrets; "
            "print(secrets.token_urlsafe(48))'`) and set it in the deployment "
            "environment. Refusing to issue JWTs signed with a public value."
        )


def check_admin_token(settings: Settings) -> None:
    """Reject production startup when ADMIN_TOKEN is the known placeholder."""
    if not settings.is_production():
        return
    if settings.ADMIN_TOKEN.strip().lower() in _DEV_DEFAULT_ADMIN_TOKENS:
        raise StartupCheckError(
            "ADMIN_TOKEN in production is a placeholder. The /admin/* "
            "endpoints are protected by this bearer; it must be a secret "
            "value. Refusing to boot."
        )


def check_cors_configuration(settings: Settings) -> None:
    """In production, empty CORS_ALLOWED_ORIGINS is correct (fail-closed),
    but wildcard ``*`` with explicit credentials is dangerous. Also warn
    when CORS is wide-open in production.
    """
    if not settings.is_production():
        return
    origins = settings.cors_allow_origins()
    if "*" in origins:
        raise StartupCheckError(
            "CORS_ALLOWED_ORIGINS=['*'] in production exposes the API to "
            "every browser origin. List explicit admin/console origins "
            "instead, or leave empty to disable browser access entirely."
        )


def check_trusted_proxies(settings: Settings) -> None:
    """Production behind a TLS-terminating proxy must say which proxies it trusts (FG-167).

    Without TRUSTED_PROXIES the app (correctly) ignores X-Forwarded-For, so behind a proxy every user would be
    rate-limited under the proxy's single address: one noisy client could lock everybody out. Fail loudly at boot
    instead of degrading silently."""
    if not settings.is_production():
        return
    if settings.TRUST_PROXY_TLS and not settings.TRUSTED_PROXIES.strip():
        raise StartupCheckError(
            "TRUST_PROXY_TLS=true but TRUSTED_PROXIES is empty. Behind a reverse proxy the client IP can only be "
            "recovered from X-Forwarded-For if the proxy's address/range is listed explicitly (e.g. "
            "TRUSTED_PROXIES=100.64.0.0/10). Without it all users share the proxy's address for rate limiting. "
            "Refusing to boot."
        )


def check_file_encryption(settings: Settings) -> None:
    """A configured encryption key must be valid (base64 of exactly 32 bytes; keyring ids consistent) in EVERY environment, and with
    FILE_ENCRYPTION_REQUIRED the application refuses to start without one. The message never contains key material."""
    from app.delivery_settings import delivery_settings
    from app.services import file_crypto

    try:
        active = file_crypto.active_key()
    except file_crypto.FileCryptoError as exc:
        raise StartupCheckError(
            f"File encryption key configuration is invalid: {exc}"
        ) from None
    if active is None and delivery_settings.FILE_ENCRYPTION_REQUIRED:
        raise StartupCheckError(
            "FILE_ENCRYPTION_REQUIRED=true but FILE_ENCRYPTION_KEY is not set. Provide a urlsafe-base64 key of 32 random bytes."
        )


_CHECKS = (
    check_file_encryption,
    check_tls_configuration,
    check_jwt_secret,
    check_admin_token,
    check_cors_configuration,
    check_trusted_proxies,
)


def run_startup_checks(settings: Settings, checks: Iterable | None = None) -> None:
    """Run every production readiness check. First failure raises.

    Each check is responsible for its own development skip. In dev mode
    this returns without doing anything useful; in production it fails
    loudly before any traffic is accepted.
    """
    for check in checks or _CHECKS:
        check(settings)
    if settings.is_production():
        logger.info("All startup checks passed — safe to serve production traffic")
