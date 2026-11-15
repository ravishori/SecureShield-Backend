"""uvicorn's access log must not carry query values, share tokens or identifiers."""

import logging
import socket
import threading
import time

import httpx
import pytest

from app.middleware.access_log import (
    AccessLogRedactor,
    install_access_log_redaction,
    redact_target,
)

EMAIL = "victim.person@example.com"
SHARE = "Zx9Qm4Rt7Lp2Vb6Nc8Wd3Hs5Jf1Gk0Ya"


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    "target,must_not_contain",
    [
        (f"/api/v1/auth/check-user?identifier={EMAIL}", EMAIL),
        ("/api/v1/auth/check-user?identifier=%2B919876501234", "919876501234"),
        (f"/api/v1/recordings/share/{SHARE}", SHARE),
        ("/api/v1/recordings/share/short-but-secret", "short-but-secret"),
        ("/api/v1/scam-calls/block/+919876501234", "919876501234"),
        ("/api/v1/scam-calls/block/9876501234", "9876501234"),
        (f"/x/{EMAIL}/y", EMAIL),
        ("/x?token=abc&code=123456&key=AIzaSyD", "123456"),
    ],
)
def test_sensitive_parts_are_removed(target, must_not_contain):
    assert must_not_contain not in redact_target(target)


@pytest.mark.unit
@pytest.mark.parametrize(
    "target",
    [
        "/health",
        "/ready",
        "/",
        "/api/v1/auth/me",
        "/api/v1/alerts/",
        "/api/v1/evidence/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        "/api/v1/warriors/admin/applications/3f2504e0-4f89-11d3-9a0c-0305e82c3301/reject",
    ],
)
def test_ordinary_routes_and_uuids_are_untouched(target):
    assert redact_target(target) == target


@pytest.mark.unit
def test_query_names_are_kept_values_masked():
    assert (
        redact_target("/a?identifier=x&page=2")
        == "/a?identifier=[redacted]&page=[redacted]"
    )
    assert redact_target("/a?") == "/a"


@pytest.mark.unit
def test_filter_rewrites_uvicorn_record_args_and_is_installed_once():
    rec = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "",
        0,
        '%s - "%s %s HTTP/%s" %d',
        ("1.2.3.4:5", "GET", f"/api/v1/auth/check-user?identifier={EMAIL}", "1.1", 200),
        None,
    )
    assert AccessLogRedactor().filter(rec) is True
    assert (
        EMAIL not in rec.getMessage()
        and "check-user?identifier=[redacted]" in rec.getMessage()
    )
    assert (
        rec.args[0] == "1.2.3.4:5" and rec.args[-1] == 200
    )  # client, method, status intact
    install_access_log_redaction()
    install_access_log_redaction()
    assert (
        sum(
            isinstance(f, AccessLogRedactor)
            for f in logging.getLogger("uvicorn.access").filters
        )
        == 1
    )


@pytest.mark.unit
@pytest.mark.security
def test_real_uvicorn_access_log_is_redacted(no_database):
    """Run a REAL uvicorn server serving the real app and read what it actually logs.

    The share-link route queries the database; ``no_database`` (tests/unit/conftest.py) answers every query from an in-memory fake, so
    the test never opens a database connection. Every assertion below is unchanged."""
    import uvicorn

    from app.main import app

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    lines: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    cap = Capture()
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="info", lifespan="off"
        )
    )
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "uvicorn did not start"
    access = logging.getLogger("uvicorn.access")
    access.addHandler(cap)
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}") as c:
            c.get(f"/health?identifier={EMAIL}&token=SENTINEL-QTOKEN")
            c.get(f"/api/v1/recordings/share/{SHARE}")
            c.get("/definitely/not/a/route?x=SENTINEL-Q2")
        time.sleep(0.5)
    finally:
        access.removeHandler(cap)
        server.should_exit = True
        t.join(timeout=10)
    blob = "\n".join(lines)
    assert len(lines) >= 3, lines
    for secret in (EMAIL, SHARE, "SENTINEL-QTOKEN", "SENTINEL-Q2"):
        assert secret not in blob, f"{secret!r} reached the access log"
    assert (
        "GET /health?identifier=[redacted]&token=[redacted]" in blob
    )  # shape kept for diagnostics
