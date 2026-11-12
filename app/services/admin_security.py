"""Credential primitives for individually authenticated admin accounts.

* Passwords: salted scrypt (stdlib, memory-hard), constant-time verification, strength policy.
* TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) implemented with the standard library; a code can be used once
  (the last accepted time step is stored) and a +/- 1 step window absorbs clock drift.
* The TOTP secret is stored encrypted (Fernet, key derived from SECRET_KEY with HKDF); recovery codes are stored only
  as keyed hashes and each can be used once.

Nothing here logs or returns a secret. Pure functions, no database access.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import settings

# ── passwords ────────────────────────────────────────────────────────────────────────────────────────────────────
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
MIN_PASSWORD_LENGTH = 12
_COMMON = {
    "password1234",
    "123456789012",
    "qwertyuiop12",
    "administrator",
    "secureshield",
    "secureshield1",
    "changeme1234",
}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except Exception:
        return False
    return hmac.compare_digest(actual, expected)


# Verified against when the account does not exist, so "unknown e-mail" costs the same time as "wrong password".
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problems(password: str, email: str | None = None) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if len(set(password)) < 5:
        problems.append("is too repetitive")
    low = password.lower()
    if low in _COMMON:
        problems.append("is too common")
    if email and (low == email.lower() or email.lower().split("@")[0] in low):
        problems.append("must not contain the e-mail address")
    if not (
        any(c.isalpha() for c in password)
        and any(c.isdigit() or not c.isalnum() for c in password)
    ):
        problems.append("must mix letters with digits or symbols")
    return problems


# ── TOTP ─────────────────────────────────────────────────────────────────────────────────────────────────────────
TOTP_PERIOD = 30
TOTP_DIGITS = 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % (
        10**TOTP_DIGITS
    )
    return f"{value:0{TOTP_DIGITS}d}"


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def totp_code(secret: str, step: int) -> str:
    return _hotp(secret, step)


def verify_totp(
    secret: str, code: str, last_step: int, now: float | None = None
) -> int | None:
    """Return the matched time step, or None. Steps at or before ``last_step`` are refused (no code reuse)."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    matched: int | None = None
    step_now = current_step(now)
    for step in (
        step_now - 1,
        step_now,
        step_now + 1,
    ):  # evaluate all three: constant work, no early exit
        if hmac.compare_digest(_hotp(secret, step), code) and step > last_step:
            matched = step if matched is None else max(matched, step)
    return matched


# ── secret encryption + recovery codes ───────────────────────────────────────────────────────────────────────────
def _derived(info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
        settings.SECRET_KEY.encode()
    )


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_derived(b"secureshield-admin-totp-v1")))


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None


RECOVERY_CODE_COUNT = 8


def _recovery_hash(code: str) -> str:
    key = _derived(b"secureshield-admin-recovery-v1")
    return hmac.new(
        key, code.strip().lower().replace("-", "").encode(), hashlib.sha256
    ).hexdigest()


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> tuple[list[str], list[str]]:
    """Return (codes to show the user once, hashes to store)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike characters
    codes = ["".join(secrets.choice(alphabet) for _ in range(10)) for _ in range(count)]
    shown = [f"{c[:5]}-{c[5:]}" for c in codes]
    return shown, [_recovery_hash(c) for c in codes]


def consume_recovery_code(hashes_: list[str], code: str) -> list[str] | None:
    """Return the remaining hashes if ``code`` matched one (which is removed), else None."""
    presented = _recovery_hash(code)
    remaining = []
    found = False
    for h in hashes_ or []:
        if hmac.compare_digest(h, presented) and not found:
            found = True
        else:
            remaining.append(h)
    return remaining if found else None
