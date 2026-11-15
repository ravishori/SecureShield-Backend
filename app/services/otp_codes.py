"""One-time-code generation and at-rest protection.

Codes come from the OS CSPRNG (``secrets``), never ``random``. Only an HMAC of the code is stored, so
a database leak or backup does not expose usable codes; the plaintext exists only in the message sent
to the user. The HMAC key is derived from SECRET_KEY, so stored hashes cannot be brute-forced offline
without it (a bare SHA-256 of a 6-digit code would fall in microseconds).
"""

import hashlib
import hmac
import secrets

from app.config import settings

OTP_TTL_MINUTES = 10  # keep in sync with the "Valid for 10 minutes" text of the SMS / e-mail templates
OTP_MAX_ATTEMPTS = 5  # wrong guesses against one code before it is burned


def generate_code() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def hash_code(code: str) -> str:
    key = hashlib.sha256(f"otp-key:{settings.SECRET_KEY}".encode()).digest()
    return hmac.new(key, code.encode(), hashlib.sha256).hexdigest()


def codes_match(stored_hash: str, presented_code: str) -> bool:
    """Constant-time comparison of the stored HMAC with the HMAC of the presented code."""
    return hmac.compare_digest(stored_hash, hash_code(presented_code))


def hash_challenge(code: str, kind: str, identifier: str, purpose: str) -> str:
    """HMAC of a code BOUND to one identifier, one channel and one purpose: the same digits issued for another identifier or
    purpose hash differently, so a code can never verify anything but the exact challenge it was issued for."""
    key = hashlib.sha256(f"otp-key:{settings.SECRET_KEY}".encode()).digest()
    msg = f"v2|{purpose}|{kind}|{identifier}|{code}"
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def challenge_matches(
    stored_hash: str, code: str, kind: str, identifier: str, purpose: str
) -> bool:
    return hmac.compare_digest(
        stored_hash, hash_challenge(code, kind, identifier, purpose)
    )
