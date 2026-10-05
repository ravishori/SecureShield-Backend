"""Redact sensitive URL parts from uvicorn's access log.

uvicorn writes one line per request to stdout (``uvicorn.access``), which the hosting
platform stores. That line contains the *full* request target, so it exposed:

  * query-string VALUES (``/auth/check-user?identifier=<e-mail or phone>``),
  * share tokens in paths (``/recordings/share/<token>`` is a capability URL),
  * phone numbers / e-mail addresses used as path parameters.

``install_access_log_redaction()`` attaches a logging filter that rewrites the target
before any handler formats it: query parameter NAMES are kept, values become
``[redacted]``, and token-like / identifier-like path segments are masked. Route shape,
method and status stay visible for diagnostics.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import unquote

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_\-\.~]{24,}$")
_EMAILISH = re.compile(r"@|%40", re.I)
_PHONEISH = re.compile(r"^\+?\d[\d\-\s%B]{7,}$")
# Path segments that are ALWAYS followed by a secret/identifier value, whatever it looks like.
_SECRET_AFTER = {"share", "block", "token", "verify", "reset"}
REDACTED = "[redacted]"


def redact_target(target: str) -> str:
    """Return ``target`` (path + optional query) with secrets masked."""
    if not isinstance(target, str):
        return target
    path, sep, query = target.partition("?")
    segments = path.split("/")
    out, mask_next = [], False
    for seg in segments:
        if mask_next and seg:
            out.append(REDACTED)
            mask_next = False
            continue
        decoded = unquote(seg)
        if (
            seg
            and not _UUID.match(seg)
            and (
                _LONG_TOKEN.match(seg)
                or _EMAILISH.search(seg)
                or _PHONEISH.match(decoded)
            )
        ):
            out.append(REDACTED)
        else:
            out.append(seg)
        mask_next = seg.lower() in _SECRET_AFTER
    redacted_path = "/".join(out)
    if not sep:
        return redacted_path
    names = []
    for pair in query.split("&"):
        if not pair:
            continue
        names.append(pair.split("=", 1)[0] + "=" + REDACTED)
    return redacted_path + ("?" + "&".join(names) if names else "")


class AccessLogRedactor(logging.Filter):
    """uvicorn access records carry ``args = (client, method, target, http_version, status)``."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], redact_target(args[2]), *args[3:])
        return True


def install_access_log_redaction() -> None:
    """Idempotently attach the redactor to ``uvicorn.access`` (and its handlers)."""
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, AccessLogRedactor) for f in logger.filters):
        logger.addFilter(AccessLogRedactor())
