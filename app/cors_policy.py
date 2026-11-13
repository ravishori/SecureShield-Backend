"""CORS policy: explicit origin allowlist, validated at startup (fail closed).

* Only browsers send an ``Origin`` header and enforce CORS. The Flutter app is native (Android/iOS, no web target) and the admin
  console is served by this API itself (same origin), so **no cross-origin browser client exists today**: staging and production
  therefore default to an EMPTY allowlist. Add an origin to ``CORS_ALLOWED_ORIGINS`` only for a browser client that really exists.
* ``*`` is accepted only on its own and only in a development environment (``development``, ``dev``, ``local``, ``test``); it never
  enables credentials. Unknown environment names are NOT treated as development.
* Every entry must be ``scheme://host[:port]`` (http/https, no path, query, fragment, user-info or wildcard); production requires https.
  Anything malformed stops startup instead of being silently ignored.
* Methods and headers are restricted to what the API uses. Authentication is by bearer token (no cookies), so there is no ambient
  credential for a cross-site request to ride on.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})
ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
ALLOWED_HEADERS = [
    "Authorization",
    "Content-Type",
    "Accept",
    "Accept-Language",
    "X-Admin-Token",
]


class CorsConfigError(ValueError):
    """CORS_ALLOWED_ORIGINS is malformed or not permitted in this environment."""


@dataclass(frozen=True)
class CorsPolicy:
    origins: tuple[str, ...]
    allow_credentials: bool


def is_dev_environment(environment: str | None) -> bool:
    return (environment or "").strip().lower() in DEV_ENVIRONMENTS


def _normalise_origin(item: str, *, production: bool) -> str:
    bad = CorsConfigError(
        "CORS_ALLOWED_ORIGINS contains an entry that is not a plain origin "
        "(expected scheme://host[:port], e.g. https://app.example.com, no path or trailing slash)"
    )
    if not item or any(c in item for c in " \t\r\n*?#@\\"):
        raise bad
    try:
        parts = urlsplit(item)
        port = parts.port
    except ValueError:
        raise bad from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise bad
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise bad
    scheme = parts.scheme.lower()
    if production and scheme != "https":
        raise CorsConfigError(
            "CORS_ALLOWED_ORIGINS must use https:// origins in production"
        )
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def resolve_cors(environment: str | None, raw_origins: str | None) -> CorsPolicy:
    """Validated policy for this environment; raises :class:`CorsConfigError` for anything unsafe or malformed."""
    dev = is_dev_environment(environment)
    production = (environment or "").strip().lower() == "production"
    items = [i.strip() for i in (raw_origins or "").split(",") if i.strip()]
    if not items:
        return CorsPolicy(("*",), False) if dev else CorsPolicy((), False)
    if "*" in items:
        if len(items) > 1:
            raise CorsConfigError(
                "CORS_ALLOWED_ORIGINS: '*' cannot be combined with other origins"
            )
        if not dev:
            raise CorsConfigError(
                "CORS_ALLOWED_ORIGINS=* is only allowed in a development environment; list explicit origins "
                "or leave it empty to disable browser access"
            )
        return CorsPolicy(("*",), False)
    origins: list[str] = []
    for item in items:
        origin = _normalise_origin(item, production=production)
        if origin not in origins:
            origins.append(origin)
    return CorsPolicy(tuple(origins), True)
