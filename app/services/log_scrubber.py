"""Scrub secrets and personal data out of text that is about to be logged.

Exception messages and tracebacks are free text produced by libraries (asyncpg DETAIL
lines, pydantic input echoes, httpx errors that include the full request URL, upstream
API error bodies...). They are written to the file log, the ``error_logs`` table and
alert e-mails, so anything sensitive in them is stored and shipped.

Design rules: conservative (keep error types, messages, hosts, paths, frames - the
diagnostics), redact only values that are credentials or personal identifiers, never raise,
and always bound the output size.
"""

from __future__ import annotations

import re
from typing import Any

MAX_MESSAGE = 4_000
MAX_TRACEBACK = 20_000
MAX_EXTRA_STRING = 2_000

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{6,4096}\.[A-Za-z0-9_-]{6,4096}\.[A-Za-z0-9_-]{0,4096}")
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s{1,8}[A-Za-z0-9._~+/=-]{8,4096}")
# key=VALUE style secrets in URLs, form bodies and messages
_KV = re.compile(
    r"(?i)(?P<k>\b(?:api[_-]?key|apikey|key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
    r"secret|client[_-]?secret|password|passwd|pwd|authorization|signature|sig|otp)\b)"
    r"(?P<sep>\s*[=:]\s*)(?P<q>[\"']?)(?P<v>[^&\s\"'<>,;)}\]]+)"
)
_KNOWN_KEYS = re.compile(r"\b(?:sk-ant-[A-Za-z0-9_-]{10,}|AIza[0-9A-Za-z_-]{20,}|AC[0-9a-f]{32}|SG\.[A-Za-z0-9_-]{16,}|re_[A-Za-z0-9]{16,})\b")
_URL_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]{0,19}://)(?P<user>[^:/\s@]{1,128}):(?P<pw>[^@\s/]{1,256})@")
# asyncpg/psycopg: ``Key (email)=(a@b.com) already exists.``
_PG_DETAIL = re.compile(r"(?i)(Key\s*\([^)]*\)\s*=\s*\()[^)]*(\))")
# pydantic v2: ``input_value='...'`` / ``[input_value=..., input_type=str]``
_PYDANTIC_INPUT = re.compile(r"(input_value\s*=\s*)(?:'[^']*'|\"[^\"]*\"|[^,\]\s]+)")
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{0,63}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8})(?![A-Za-z0-9-])")
_PHONE = re.compile(r"(?<![\w.:/-])\+?\d[\d \-]{8,16}\d(?![\w.-])")
_OTP_WORDS = re.compile(r"(?i)\b(otp|verification code|passcode|pin)\b([^0-9\n]{0,12})(\d{4,8})\b")


def _mask_phone(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) < 10:  # too short to be a phone number: leave (ids, counters)
        return m.group(0)
    return "[PHONE …" + digits[-2:] + "]"


def scrub_text(value: str | None, limit: int = MAX_MESSAGE) -> str | None:
    """Return ``value`` with credentials/PII redacted and length bounded. Never raises."""
    if value is None:
        return None
    try:
        s = str(value)
        pre_cut = len(s) - limit * 4
        if pre_cut > 0:  # bound regex work: never scan megabytes of text
            s = s[: limit * 4]
        s = _URL_USERINFO.sub(lambda m: f"{m['scheme']}{m['user']}:[REDACTED]@", s)
        s = _JWT.sub("[JWT]", s)
        s = _AUTH_SCHEME.sub(lambda m: f"{m.group(1)} [REDACTED]", s)
        s = _KNOWN_KEYS.sub("[API_KEY]", s)
        s = _PG_DETAIL.sub(r"\1[REDACTED]\2", s)
        s = _PYDANTIC_INPUT.sub(r"\1[REDACTED]", s)
        s = _KV.sub(lambda m: f"{m['k']}{m['sep']}{m['q']}[REDACTED]", s)
        s = _OTP_WORDS.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", s)
        s = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", s)
        s = _PHONE.sub(_mask_phone, s)
        if pre_cut > 0 or len(s) > limit:
            s = s[:limit] + f"… [truncated {max(pre_cut, 0) + max(len(s) - limit, 0)} chars]"
        return s
    except Exception:  # noqa: BLE001 - logging must never fail because of scrubbing
        return "[unscrubbable text omitted]"


def scrub_obj(obj: Any, _depth: int = 0) -> Any:
    """Recursively scrub strings inside dict/list/tuple structures (JSON-able ``extra``)."""
    if _depth > 8:
        return "[max depth]"
    if isinstance(obj, str):
        return scrub_text(obj, MAX_EXTRA_STRING)
    if isinstance(obj, dict):
        return {k: scrub_obj(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_obj(v, _depth + 1) for v in obj]
    return obj
