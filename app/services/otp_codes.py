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


def generate_code() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def hash_code(code: str) -> str:
    key = hashlib.sha256(f"otp-key:{settings.SECRET_KEY}".encode()).digest()
    return hmac.new(key, code.encode(), hashlib.sha256).hexdigest()
