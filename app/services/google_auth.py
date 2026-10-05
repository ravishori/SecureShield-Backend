"""Google Sign-In: verify a Google ID token server-side.

The client (Google Sign-In SDK) obtains an ID token; the backend never trusts anything the client
says about identity except what is cryptographically proven by that token:
  * RS256 signature against Google's published JWKS (fetched over HTTPS, cached, key rotation safe)
  * ``aud`` is one of our configured OAuth client IDs (GOOGLE_CLIENT_IDS, comma separated)
  * ``iss`` is Google, token not expired, ``email_verified`` is true
"""

import time
from dataclasses import dataclass

import httpx
from jose import JWTError, jwt

from app.config import settings

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
JWKS_TTL_SECONDS = 3600
HTTP_TIMEOUT_SECONDS = 10.0

_cache: dict = {"keys": None, "at": 0.0}


class GoogleAuthError(Exception):
    """Token rejected. ``reason`` is safe to log (never contains the token)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class GoogleNotConfigured(GoogleAuthError):
    pass


@dataclass
class GoogleIdentity:
    subject: str
    email: str
    name: str | None


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)


def allowed_audiences() -> list[str]:
    return [
        c.strip() for c in (settings.GOOGLE_CLIENT_IDS or "").split(",") if c.strip()
    ]


async def _jwks(force: bool = False) -> list[dict]:
    fresh = (
        _cache["keys"] is not None
        and time.monotonic() - _cache["at"] < JWKS_TTL_SECONDS
    )
    if fresh and not force:
        return _cache["keys"]
    try:
        async with _client() as client:
            resp = await client.get(GOOGLE_JWKS_URL)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
    except Exception as exc:
        if _cache["keys"] is not None:
            return _cache["keys"]  # serve the stale set rather than lock everybody out
        raise GoogleAuthError(
            f"could not fetch Google signing keys ({type(exc).__name__})"
        ) from exc
    _cache.update(keys=keys, at=time.monotonic())
    return keys


def reset_cache() -> None:
    _cache.update(keys=None, at=0.0)


async def verify_google_id_token(id_token: str) -> GoogleIdentity:
    audiences = allowed_audiences()
    if not audiences:
        raise GoogleNotConfigured("GOOGLE_CLIENT_IDS is not configured")
    try:
        header = jwt.get_unverified_header(id_token)
    except JWTError as exc:
        raise GoogleAuthError("malformed token") from exc
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise GoogleAuthError("unexpected token algorithm")

    key = next((k for k in await _jwks() if k.get("kid") == header["kid"]), None)
    if key is None:  # Google may have rotated keys since we cached them
        key = next(
            (k for k in await _jwks(force=True) if k.get("kid") == header["kid"]), None
        )
    if key is None:
        raise GoogleAuthError("unknown signing key")

    claims = None
    last_error = "audience mismatch"
    for aud in audiences:
        try:
            claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=aud)
            break
        except JWTError as exc:
            last_error = type(exc).__name__
    if claims is None:
        raise GoogleAuthError(f"token rejected ({last_error})")

    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise GoogleAuthError("wrong issuer")
    email = (claims.get("email") or "").strip().lower()
    if not email or claims.get("email_verified") not in (True, "true"):
        raise GoogleAuthError("email not verified")
    if not claims.get("sub"):
        raise GoogleAuthError("missing subject")
    return GoogleIdentity(
        subject=str(claims["sub"]), email=email, name=claims.get("name")
    )
