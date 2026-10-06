"""Shared pytest bootstrap for the SecureShield backend test suite.

Hermetic by construction:
  * ``SECURESHIELD_ENV_FILE`` points at a file that does not exist, so
    ``backend/.env`` (real credentials) is never loaded — dotenv values
    would otherwise override process env in ``app.config``.
  * Every setting is FORCED (assignment, not ``setdefault``) so a stray
    shell variable such as a production ``DATABASE_URL`` cannot leak in.
  * ``DATABASE_URL`` is the dummy below unless ``TEST_DATABASE_URL`` is
    supplied. Integration fixtures (tests/integration/conftest.py) then
    validate that URL fails-closed before any connection is made.
"""

import os
from pathlib import Path

_NO_ENV_FILE = str(Path(__file__).parent / "_no_such_env_file")

_DUMMY_DB = "postgresql+asyncpg://test:test@localhost/test"
_test_db_url = os.environ.get("TEST_DATABASE_URL", "").strip() or _DUMMY_DB

_FORCED = {
    "SECURESHIELD_ENV_FILE": _NO_ENV_FILE,
    "DATABASE_URL": _test_db_url,
    "MIGRATOR_DATABASE_URL": _test_db_url,
    "SECRET_KEY": "test-secret-key-for-pytest-only-do-not-use-in-prod",
    "SMTP_HOST": "localhost",
    "SMTP_PORT": "1025",
    "SMTP_USER": "test@example.com",
    "SMTP_PASSWORD": "test-password",
    "SMTP_FROM_EMAIL": "test@example.com",
    "ERROR_NOTIFY_EMAIL": "errors@example.com",
    "TWILIO_ACCOUNT_SID": "ACtest",
    "TWILIO_AUTH_TOKEN": "test-token",
    "TWILIO_SMS_NUMBER": "+15555555555",
    "TWILIO_WHATSAPP_NUMBER": "+15555555555",
    "ENVIRONMENT": "test",
    "ADMIN_TOKEN": "test-admin-token",
}
for _k, _v in _FORCED.items():
    os.environ[_k] = _v
# Never allow integration/unit runs to talk to Redis-backed limiter config.
os.environ.pop("REDIS_URL", None)


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_admin_failure_budget():
    """FG-166: the admin failed-attempt budget lives in the process-wide limiter; every test starts with it empty."""
    from app.middleware.rate_limiter import rate_limiter

    rate_limiter.reset("admin_auth_fail")
    yield
    rate_limiter.reset("admin_auth_fail")
