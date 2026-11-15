"""BH-2 URL privacy helpers: what may be stored, logged, cached or sent to a provider.

A full URL is processed in memory for scanning and detection. Everything that PERSISTS or is LOGGED uses the redacted form:

* user-info (``user:password@``) is removed,
* the fragment is removed,
* query VALUES are replaced by ``~`` (parameter names are kept: they explain a verdict, e.g. ``redirect=``); the value of a
  redirect-like parameter is reduced to ``scheme://host`` of its target,
* path segments that look like tokens (JWTs, UUIDs, long hex, long mixed letter/digit runs, e-mail addresses) become
  ``[redacted]``.

Providers need the query for exact matching (URLhaus compares the full URL), so they get ``provider_url``: only user-info, the
fragment and parameters whose NAME marks a credential are removed. Everything here is pure, idempotent
(``redact(redact(u)) == redact(u)``) and never raises.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, List, Optional
from urllib.parse import unquote_plus

MAX_STORED_URL = 512
MAX_QUERY_PARAMS = 10
_MAX_NAME = 40
REDACTED_SEGMENT = "[redacted]"
VALUE_MASK = "~"

_PARSE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://)?(?P<auth>[^/?#]*)(?P<path>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#.*)?$",
    re.S,
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f\s]+")
_HOST_OK = re.compile(r"[^A-Za-z0-9.\-_:\[\]%]")
_NAME_OK = re.compile(r"[A-Za-z0-9_.\-\[\]]{1,%d}" % _MAX_NAME)
_HEX = re.compile(r"[0-9A-Fa-f]{16,}")
_UUID = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
_LONG_RUN = re.compile(r"[A-Za-z0-9_]{20,}")
_REDIRECT_NAMES = frozenset(
    {
        "redirect",
        "redirect_uri",
        "redirect_url",
        "redirecturl",
        "return",
        "return_to",
        "returnto",
        "returnurl",
        "return_url",
        "next",
        "continue",
        "dest",
        "destination",
        "goto",
        "target",
        "url",
        "u",
        "link",
        "callback",
        "forward",
        "back",
        "backurl",
        "ref_url",
        "service",
    }
)
_SENSITIVE_NAMES = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "auth_token",
        "authtoken",
        "code",
        "otp",
        "pin",
        "password",
        "pwd",
        "passwd",
        "pass",
        "secret",
        "client_secret",
        "key",
        "apikey",
        "api_key",
        "api-key",
        "sig",
        "signature",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "sessid",
        "auth",
        "authorization",
        "jwt",
        "bearer",
        "ticket",
        "creds",
        "credential",
        "credentials",
        "csrf",
        "xsrf",
        "nonce",
        "state",
        "email",
        "phone",
        "mobile",
    }
)
_SENSITIVE_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "session",
    "signature",
    "apikey",
    "api_key",
)
_TEXT_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)


def _clean(url: object) -> str:
    return _CONTROL.sub("", str(url or ""))


def _split(url: str):
    m = _PARSE.match(url)
    if not m:
        return None
    auth = m.group("auth") or ""
    hostport = auth.rsplit("@", 1)[
        -1
    ]  # user-info is dropped, even when it contains '@'
    host = _HOST_OK.sub("", hostport)[:255]
    return (
        m.group("scheme"),
        host,
        m.group("path") or "",
        m.group("query"),
        m.group("auth") != hostport,
    )


def _token_like(segment: str) -> bool:
    if "@" in segment:
        return True
    if segment == REDACTED_SEGMENT:
        return False
    if _UUID.fullmatch(segment) or _HEX.fullmatch(segment):
        return True
    if segment.startswith("eyJ") and "." in segment:
        return True
    for run in _LONG_RUN.findall(segment):
        if (any(c.isdigit() for c in run) and any(c.isalpha() for c in run)) or len(
            run
        ) >= 32:
            return True
    return False


def _redact_path(path: str) -> str:
    if not path:
        return ""
    return "/".join(
        REDACTED_SEGMENT if _token_like(seg) else seg for seg in path.split("/")
    )


def _target_host(value: str) -> Optional[str]:
    """scheme://host of a redirect-like value, or None when the value is not a URL."""
    v = _clean(unquote_plus(value))
    if not re.match(r"(?i)^(https?:)?//", v):
        return None
    parts = _split(v if "://" in v else "https:" + v)
    if not parts or not parts[1]:
        return None
    scheme = parts[0] or "https"
    return f"{scheme.lower()}://{parts[1]}"


def _redact_query(query: Optional[str]) -> str:
    if not query:
        return ""
    out: List[str] = []
    pairs = [p for p in re.split(r"[&;]", query) if p != ""]
    for raw in pairs[:MAX_QUERY_PARAMS]:
        name, eq, value = raw.partition("=")
        name = (
            name
            if _NAME_OK.fullmatch(name) and not _LONG_RUN.search(name)
            else VALUE_MASK
        )
        if not eq:
            out.append(name)
        elif name.lower() in _REDIRECT_NAMES and (target := _target_host(value)):
            out.append(f"{name}={target}")
        else:
            out.append(f"{name}={VALUE_MASK}")
    if len(pairs) > MAX_QUERY_PARAMS:
        out.append("...")
    return "?" + "&".join(out) if out else ""


def redact_url_for_storage(url: object, limit: int = MAX_STORED_URL) -> str:
    """The privacy-safe form that may be persisted, logged and returned. Never raises, idempotent, bounded."""
    try:
        parts = _split(_clean(url))
        if parts is None or not parts[1]:
            return "[invalid-url]"
        scheme, host, path, query, _ = parts
        text = (
            (f"{scheme}://" if scheme else "")
            + host
            + _redact_path(path)
            + _redact_query(query)
        )
        return text if len(text) <= limit else text[: limit - 3] + "..."
    except Exception:  # noqa: BLE001 - redaction must never fail a request
        return "[invalid-url]"


def _is_sensitive_name(name: str) -> bool:
    n = name.lower()
    return n in _SENSITIVE_NAMES or any(p in n for p in _SENSITIVE_PARTS)


def provider_url(url: str) -> str:
    """What may be sent to a reputation provider: user-info, fragment and credential-named parameters are removed; the rest
    (host, path, other query parameters) stays because exact-match feeds need it. Returns the input unchanged when nothing
    needs removing. On a parse failure the text is returned with only user-info and fragment cut off."""
    try:
        text = _clean(url)
        m = _PARSE.match(text)
        if not m:
            return text.split("#", 1)[0]
        auth = m.group("auth") or ""
        hostport = auth.rsplit("@", 1)[-1]
        query = m.group("query")
        kept = None
        if query:
            pairs = query.split("&")
            kept_pairs = []
            for p in pairs:
                name, eq, value = p.partition("=")
                if _is_sensitive_name(name):
                    continue
                target = (
                    _target_host(value)
                    if eq and name.lower() in _REDIRECT_NAMES
                    else None
                )
                kept_pairs.append(
                    f"{name}={target}" if target else p
                )  # a redirect target is reduced to its host
            kept = "&".join(kept_pairs) if kept_pairs != pairs else query
        same = hostport == auth and kept == query and "#" not in text
        if same:
            return text
        scheme = m.group("scheme")
        rebuilt = (
            (f"{scheme}://" if scheme else "") + hostport + (m.group("path") or "")
        )
        if kept:
            rebuilt += "?" + kept
        return rebuilt
    except Exception:  # noqa: BLE001
        return _clean(url).split("#", 1)[0]


def cache_key(url: str) -> str:
    """In-memory cache key that does not keep the URL itself."""
    return hashlib.sha256(str(url).encode("utf-8", "replace")).hexdigest()


def sanitize_threats(threats: Any) -> Any:
    """Provider threat entries echo the matched URL; keep their type/label fields and redact any ``url`` value."""
    if not isinstance(threats, list):
        return threats
    clean = []
    for t in threats:
        if isinstance(t, dict):
            t = dict(t)
            if isinstance(t.get("url"), str):
                t["url"] = redact_url_for_storage(t["url"])
        clean.append(t)
    return clean


def redact_urls_in_text(text: Optional[str], mode: str = "host") -> Optional[str]:
    """Replace every http(s) URL inside free text. ``host`` -> ``[link: host]`` (previews, alerts); ``path`` -> the stored form
    (log lines keep the path for diagnostics)."""
    if text is None:
        return None

    def _sub(m: "re.Match[str]") -> str:
        raw = m.group(0).rstrip(".,;:!?")
        tail = m.group(0)[len(raw) :]
        if mode == "host":
            parts = _split(raw)
            host = parts[1] if parts else ""
            return f"[link: {host or 'redacted'}]" + tail
        return redact_url_for_storage(raw, limit=2000) + tail

    try:
        return _TEXT_URL.sub(_sub, str(text))
    except Exception:  # noqa: BLE001
        return "[unredactable text omitted]"
