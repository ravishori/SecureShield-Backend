"""Privacy-safe text for SMS-analysis alerts (Stage 1.6D-2).

An alert row is stored, listed to the user, and may be mailed. It needs enough to explain WHY a message was flagged, not the
message itself. Everything written to ``alerts.message`` / ``alerts.extra_data`` from an analysed SMS goes through here BEFORE it
reaches the database, so Flutter never has to be trusted to hide it.

Redacted (replaced by a short label):
  * OTPs and codes next to a keyword (``OTP 482913``, ``482913 is your OTP``), and standalone 5-8 digit codes in a message that
    talks about OTP / code / PIN / password / login;
  * card numbers, account numbers next to ``a/c`` / ``account``, Aadhaar-shaped numbers, other long digit runs (9-18 digits);
  * mobile and international phone numbers (kept as ``[PHONE ...NN]``, the last two digits, like the log scrubber);
  * e-mail addresses (``a***@domain``), UPI ids, IFSC and PAN codes;
  * link values (only ``[link: host]`` is kept, see ``url_privacy``).
Kept: the wording of the message (which is what makes it recognisable as a scam), alphabetic sender headers, amounts written
with ``Rs``/``INR``/``₹`` and short numbers (bank-masked ``XX1234``), and the link host.

Pure, idempotent and never raises; on an unexpected error the result is ``[redacted]``, never the raw text.
"""

from __future__ import annotations

import re
from typing import Optional

from app.services.url_privacy import redact_urls_in_text

MAX_PREVIEW = 100
MAX_NOTE = 200
MAX_SENDER = 50
_SCAN_LIMIT = 2_000  # bound regex work on a 5,000-character message

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]+")

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{0,63}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8})(?![A-Za-z0-9-])"
)
_UPI = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._-]{2,64}@[A-Za-z]{2,20}\b(?![.\w-])"
)
_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_OTP_KEYWORD_FIRST = re.compile(
    r"(?i)\b(otp|one[- ]time[- ](?:password|code)|verification code|passcode|pin|cvv|cvc|code)\b([^0-9\n]{0,20}?)(\d{4,8})\b"
)
_OTP_NUMBER_FIRST = re.compile(
    r"(?i)\b(\d{4,8})(\s+(?:is|as)\s+(?:your|the)\s+(?:otp|one[- ]time|verification code|passcode|pin|code)\b)"
)
_OTP_CONTEXT = re.compile(
    r"(?i)\b(otp|one[- ]time|verification|passcode|pin|cvv|password|login|log in|verify|code)\b"
)
_CODE_NUMBER = re.compile(
    r"(?i)(?<![\d.,])(?<!rs )(?<!rs\.)(?<!inr )(?<!₹)\b(\d{5,8})\b(?![\d.,]\d|%)"
)
_CARD = re.compile(r"(?<!\d)(?:\d{4}[ -]){3}\d{1,7}(?!\d)|(?<!\d)\d{13,19}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)\d{4}[ -]\d{4}[ -]\d{4}(?!\d)")
_ACCOUNT_KEYWORD = re.compile(
    r"(?i)\b(a/c|a\.c\.|acct?|account)(\s*(?:no\.?|number|num|#)?\s*[:\-]?\s*)(?:[xX*]{2,}\s*)?(\d{5,18})\b"
)
_PHONE_IN = re.compile(r"(?<![\w.:/-])(?:\+?\d{1,3}[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
_PHONE_INTL = re.compile(r"(?<![\w.:/-])\+\d[\d \-]{8,16}\d(?![\w.-])")
_LONG_DIGITS = re.compile(r"(?<![\d.])\d{9,18}(?![\d])")


def _phone_label(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return f"[PHONE ...{digits[-2:]}]" if len(digits) >= 6 else "[PHONE]"


def redact_sensitive_text(value: object, limit: Optional[int] = None) -> str:
    """Return ``value`` with the identifiers listed in the module docstring redacted, then cut to ``limit`` characters.

    Redaction runs on the whole (bounded) text BEFORE the cut, so a value can never survive by being split across the limit.
    """
    try:
        if value is None:
            return ""
        s = _CONTROL.sub(" ", str(value))[:_SCAN_LIMIT]
        s = redact_urls_in_text(s, mode="host") or s
        s = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", s)
        s = _UPI.sub("[UPI ID]", s)
        has_otp_words = bool(_OTP_CONTEXT.search(s))
        s = _IFSC.sub("[IFSC]", s)
        s = _PAN.sub("[PAN]", s)
        s = _OTP_KEYWORD_FIRST.sub(lambda m: f"{m.group(1)}{m.group(2)}[OTP]", s)
        s = _OTP_NUMBER_FIRST.sub(lambda m: f"[OTP]{m.group(2)}", s)
        s = _ACCOUNT_KEYWORD.sub(lambda m: f"{m.group(1)}{m.group(2)}[ACCOUNT]", s)
        s = _CARD.sub("[CARD]", s)
        s = _AADHAAR.sub("[AADHAAR]", s)
        s = _PHONE_IN.sub(lambda m: _phone_label(m.group(0)), s)
        s = _PHONE_INTL.sub(lambda m: _phone_label(m.group(0)), s)
        s = _LONG_DIGITS.sub("[NUMBER]", s)
        if has_otp_words:
            s = _CODE_NUMBER.sub("[CODE]", s)
        s = re.sub(r"\s+", " ", s).strip()
        return s[:limit] if limit else s
    except Exception:  # noqa: BLE001 - never fall back to the raw text
        return "[redacted]"


def redact_message_preview(text: object) -> str:
    """The stored preview of an analysed message: redacted, then at most ``MAX_PREVIEW`` characters."""
    return redact_sensitive_text(text, MAX_PREVIEW)


def redact_note(text: object) -> str:
    """Free text typed by the user next to a report (e.g. ``reporter_note``)."""
    return redact_sensitive_text(text, MAX_NOTE)


def redact_sender(sender: object) -> Optional[str]:
    """The sender as stored on an alert: ``None`` if blank; a personal phone number becomes ``[PHONE ...NN]``; an alphabetic
    sender header (a public registry value such as ``VM-SBIBNK-S``) is kept, after the same redaction as any other text."""
    try:
        if sender is None:
            return None
        raw = _CONTROL.sub(" ", str(sender)).strip()
        if not raw:
            return None
        cleaned = raw.replace("+", "").replace(" ", "").replace("-", "")
        if cleaned.isdigit() and len(cleaned) >= 7:
            return _phone_label(raw)
        return redact_sensitive_text(raw, MAX_SENDER) or None
    except Exception:  # noqa: BLE001
        return "[redacted]"
