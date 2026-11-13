"""One client identity everywhere: the request-level helper, its consistency with the rate limiter, and a guard that no module reads
``request.client.host`` directly (which behind a proxy is the proxy, and which X-Forwarded-For could not be trusted for)."""

import logging
import pathlib
import re

import pytest
from starlette.requests import Request

from app.config import Settings, settings
from app.middleware.rate_limiter import RateLimitMiddleware
from app.services.client_ip import client_ip_for
from app.startup_checks import StartupCheckError, check_trusted_proxies

pytestmark = pytest.mark.unit
PROXY = "100.64.0.9"  # documentation-style example value used only in these tests, not a claim about any host


def req(peer, xff=(), client=True):
    headers = [(b"x-forwarded-for", v.encode()) for v in xff]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
            "client": (peer, 5555) if client else None,
        }
    )


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", PROXY)


@pytest.fixture
def untrusted(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "")


def test_trusted_proxy_gives_the_forwarded_client(trusted):
    assert client_ip_for(req(PROXY, ["203.0.113.7"])) == "203.0.113.7"


def test_untrusted_direct_client_cannot_choose_its_identity(trusted):
    assert client_ip_for(req("198.51.100.4", ["203.0.113.7"])) == "198.51.100.4"


def test_spoofed_header_is_ignored_when_nothing_is_trusted(untrusted):
    assert client_ip_for(req("198.51.100.4", ["1.2.3.4"])) == "198.51.100.4"


def test_client_supplied_prefix_cannot_override_the_proxy_appended_hop(trusted):
    assert client_ip_for(req(PROXY, ["6.6.6.6, 203.0.113.7"])) == "203.0.113.7"


def test_multiple_header_lines_and_hops_are_read_right_to_left(trusted):
    assert (
        client_ip_for(req(PROXY, ["6.6.6.6", "203.0.113.7, " + PROXY])) == "203.0.113.7"
    )


def test_malformed_forwarded_value_falls_back_to_the_peer(trusted):
    assert client_ip_for(req(PROXY, ["not-an-ip"])) == PROXY


def test_no_peer_returns_the_default(untrusted):
    assert client_ip_for(req("x", client=False)) == "unknown"
    assert client_ip_for(req("x", client=False), None) is None


def test_missing_configuration_means_trust_nobody(untrusted):
    assert client_ip_for(req(PROXY, ["203.0.113.7"])) == PROXY


@pytest.mark.parametrize(
    "bad", ["*", "0.0.0.0/0", "::/0", "10.0.0.0/0", "nonsense", "1.2.3.4/33"]
)
def test_invalid_proxy_configuration_stops_startup(bad):
    with pytest.raises(ValueError):
        Settings(
            _env_file=None,
            DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
            MIGRATOR_DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
            SECRET_KEY="x" * 40,
            SMTP_HOST="",
            SMTP_PORT="25",
            SMTP_USER="t",
            SMTP_PASSWORD="t",
            SMTP_FROM_EMAIL="t@e.com",
            ERROR_NOTIFY_EMAIL="t@e.com",
            TWILIO_ACCOUNT_SID="AC",
            TWILIO_AUTH_TOKEN="t",
            TWILIO_SMS_NUMBER="+15555555555",
            TWILIO_WHATSAPP_NUMBER="+15555555555",
            TRUSTED_PROXIES=bad,
        )


@pytest.mark.parametrize(
    "peer,xff",
    [
        (PROXY, ["203.0.113.7"]),
        ("198.51.100.4", ["203.0.113.7"]),
        (PROXY, ["6.6.6.6, 203.0.113.7"]),
        (PROXY, ["garbage"]),
        ("::ffff:198.51.100.4", []),
    ],
)
def test_rate_limiter_and_every_other_consumer_see_the_same_identity(
    trusted, peer, xff
):
    r = req(peer, xff)
    assert RateLimitMiddleware._get_client_ip(r) == client_ip_for(r)


# ── regression guard: nobody reads the raw peer for an identity any more ─────────────────────────────────────────────
def test_no_application_module_reads_request_client_host_directly():
    root = pathlib.Path(__file__).resolve().parents[2] / "app"
    pattern = re.compile(r"\b(?:http_)?request\.client\.host\b")
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "client_ip.py":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(root.parent)}:{n}")
    assert offenders == [], offenders


# ── startup policy for the proxy settings ────────────────────────────────────────────────────────────────────────────
def _s(**kw):
    return Settings(
        _env_file=None,
        DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
        MIGRATOR_DATABASE_URL="postgresql+asyncpg://t:t@localhost/t",
        SECRET_KEY="x" * 40,
        SMTP_HOST="",
        SMTP_PORT="25",
        SMTP_USER="t",
        SMTP_PASSWORD="t",
        SMTP_FROM_EMAIL="t@e.com",
        ERROR_NOTIFY_EMAIL="t@e.com",
        TWILIO_ACCOUNT_SID="AC",
        TWILIO_AUTH_TOKEN="t",
        TWILIO_SMS_NUMBER="+15555555555",
        TWILIO_WHATSAPP_NUMBER="+15555555555",
        **kw,
    )


def test_staging_behind_a_proxy_without_a_range_warns_but_still_starts(caplog):
    with caplog.at_level(logging.WARNING, logger="app.startup_checks"):
        check_trusted_proxies(_s(ENVIRONMENT="staging", TRUST_PROXY_TLS=True))
    assert any("TRUSTED_PROXIES is empty" in m for m in caplog.messages)


def test_production_behind_a_proxy_without_a_range_still_refuses_to_boot():
    with pytest.raises(StartupCheckError):
        check_trusted_proxies(_s(ENVIRONMENT="production", TRUST_PROXY_TLS=True))


def test_staging_with_a_range_or_without_a_proxy_is_silent(caplog):
    with caplog.at_level(logging.WARNING, logger="app.startup_checks"):
        check_trusted_proxies(
            _s(ENVIRONMENT="staging", TRUST_PROXY_TLS=True, TRUSTED_PROXIES=PROXY)
        )
        check_trusted_proxies(_s(ENVIRONMENT="staging"))
    assert caplog.messages == []
