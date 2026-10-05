"""Credentials in request headers must never be persisted by the error logger.

Drives a REAL unhandled exception through GlobalErrorHandlerMiddleware, then
inspects (a) the actual ``error_logs`` row written to PostgreSQL and (b) the
actual alert e-mail payload handed to the mailer. Nothing about the sanitiser
is mocked.
"""

import time

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.sig-SENTINEL-AUTH"
COOKIE = "session=SENTINEL-COOKIE-VALUE; csrftoken=SENTINEL-CSRF"
ADMIN = "SENTINEL-ADMIN-TOKEN"
BODY_MARKER = "SENTINEL-BODY-OTP-482910"
QUERY_PATH = "/__boom"

SECRETS = (JWT, "sig-SENTINEL-AUTH", "SENTINEL-COOKIE-VALUE", "SENTINEL-CSRF", ADMIN)


@pytest.fixture
def boom_route():
    """Temporarily mount a route that raises an unhandled exception."""
    from fastapi import Request

    from app.main import app

    async def _boom(request: Request):
        raise RuntimeError("deliberate failure for header-leak test")

    app.add_api_route(QUERY_PATH, _boom, methods=["GET", "POST"])
    added = app.router.routes[-1]
    try:
        yield
    finally:
        app.router.routes.remove(added)


@pytest.fixture
def mailer(monkeypatch):
    """Capture what would be e-mailed (subject + html) instead of sending."""
    import app.services.logger_service as ls

    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(ls, "_send_email_sync", lambda subject, html, to: sent.append((subject, html)))
    return sent


async def _rows(db):
    return (
        await db.execute(
            text("select level, endpoint, method, exception_type, extra, t::text as raw from error_logs t")
        )
    ).mappings().all()


def _wait_for(predicate, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


async def test_500_persists_metadata_but_never_credentials(client, db, boom_route, mailer):
    r = await client.get(
        QUERY_PATH,
        headers={
            "Authorization": f"Bearer {JWT}",
            "Cookie": COOKIE,
            "X-Admin-Token": ADMIN,
            "Proxy-Authorization": "Basic SENTINEL-PROXY",
            "X-Request-ID": "req-abc123",
            "User-Agent": "SecureShieldTest/1.0",
            "Content-Type": "application/json",
        },
    )
    # existing behaviour preserved: generic 500 body, nothing internal leaked
    assert r.status_code == 500
    assert r.json() == {
        "error": "An unexpected error occurred. Our team has been notified.",
        "code": "INTERNAL_SERVER_ERROR",
    }

    rows = await _rows(db)
    assert len(rows) == 1
    row = rows[0]

    # expected error metadata is still recorded
    assert row["level"] == "CRITICAL"
    assert row["endpoint"] == QUERY_PATH
    assert row["method"] == "GET"
    assert row["exception_type"] == "RuntimeError"

    # safe headers + request id survive...
    headers = row["extra"]["headers"]
    assert headers["user-agent"] == "SecureShieldTest/1.0"
    assert headers["content-type"] == "application/json"
    assert headers["x-request-id"] == "req-abc123"

    # ...and no credential header exists at all, by name or by value
    assert not {"authorization", "cookie", "x-admin-token", "proxy-authorization"} & set(headers)
    for secret in (*SECRETS, "SENTINEL-PROXY"):
        assert secret not in row["raw"], f"{secret!r} was persisted to error_logs"


async def test_alert_email_is_sent_without_any_credentials(client, db, boom_route, mailer):
    await client.get(
        QUERY_PATH,
        headers={"Authorization": f"Bearer {JWT}", "Cookie": COOKIE, "X-Admin-Token": ADMIN},
    )
    assert _wait_for(lambda: len(mailer) == 1), "alert e-mail was not generated"
    subject, html = mailer[0]
    assert "CRITICAL" in subject and "RuntimeError" in subject and QUERY_PATH in subject
    assert "deliberate failure" in html
    for secret in SECRETS:
        assert secret not in subject + html


async def test_request_body_is_not_captured(client, db, boom_route, mailer):
    await client.post(QUERY_PATH, json={"code": BODY_MARKER, "password": BODY_MARKER})
    assert _wait_for(lambda: len(mailer) == 1)
    rows = await _rows(db)
    assert len(rows) == 1
    assert BODY_MARKER not in rows[0]["raw"]
    assert BODY_MARKER not in mailer[0][0] + mailer[0][1]


async def test_unlisted_headers_are_dropped_even_if_new(client, db, boom_route, mailer):
    """Allowlist, not denylist: a header nobody anticipated is never stored."""
    await client.get(QUERY_PATH, headers={"X-Brand-New-Secret": "SENTINEL-NEW", "Referer": "https://x/?t=SENTINEL-REF"})
    row = (await _rows(db))[0]
    assert "SENTINEL-NEW" not in row["raw"] and "SENTINEL-REF" not in row["raw"]
