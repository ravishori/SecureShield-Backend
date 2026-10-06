"""FG-167: client-IP trust policy (pure functions, config validation, startup check, uvicorn flags)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from app.config import Settings
from app.services.client_ip import (
    normalize_ip,
    parse_trusted_proxies,
    resolve_client_ip,
)
from app.startup_checks import StartupCheckError, check_trusted_proxies

pytestmark = [pytest.mark.unit, pytest.mark.security]

TRUSTED = parse_trusted_proxies("10.0.0.0/8, 100.64.0.0/10, fd00::/8, 192.0.2.1")


def r(peer, xff=None, trusted=TRUSTED):
    return resolve_client_ip(peer, xff, trusted)


# ------------------------------------------------------------------ parsing / validation
def test_empty_trusts_nobody():
    assert parse_trusted_proxies("") == ()
    assert parse_trusted_proxies(None) == ()
    assert parse_trusted_proxies(" , ,") == ()


def test_valid_entries_parse_ipv4_ipv6_and_ranges():
    nets = parse_trusted_proxies("10.1.2.3, 100.64.0.0/10 ,::1, 2001:db8::/32")
    assert ipaddress.ip_network("10.1.2.3/32") in nets
    assert ipaddress.ip_network("100.64.0.0/10") in nets
    assert ipaddress.ip_network("2001:db8::/32") in nets and len(nets) == 4


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/0",
        "not-an-ip",
        "10.0.0.1, banana",
        "1.2.3",
        "10.0.0.0/33",
        "a:b:c",
    ],
)
def test_wildcards_and_garbage_are_rejected_not_ignored(bad):
    with pytest.raises(ValueError) as e:
        parse_trusted_proxies(bad)
    assert "TRUSTED_PROXIES" in str(e.value)


def _settings(**kw):
    base = {
        "DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "MIGRATOR_DATABASE_URL": "postgresql+asyncpg://t:t@localhost/t",
        "SECRET_KEY": "something-long-and-random-that-isnt-the-default",
        "SMTP_HOST": "localhost",
        "SMTP_PORT": "1025",
        "SMTP_USER": "t",
        "SMTP_PASSWORD": "t",
        "SMTP_FROM_EMAIL": "t@e.com",
        "ERROR_NOTIFY_EMAIL": "t@e.com",
        "TWILIO_ACCOUNT_SID": "AC",
        "TWILIO_AUTH_TOKEN": "t",
        "TWILIO_SMS_NUMBER": "+15555555555",
        "TWILIO_WHATSAPP_NUMBER": "+15555555555",
        "ADMIN_TOKEN": "real-admin-token-12345",
    }
    base.update(kw)
    return Settings(_env_file=None, **base)


def test_settings_default_trusts_nobody_and_invalid_values_stop_startup():
    assert _settings().trusted_proxy_networks() == ()
    assert (
        len(_settings(TRUSTED_PROXIES="10.0.0.0/8,::1").trusted_proxy_networks()) == 2
    )
    for bad in ("*", "0.0.0.0/0", "oops"):
        with pytest.raises(ValueError):
            _settings(TRUSTED_PROXIES=bad)


# ------------------------------------------------------------------ normalisation
@pytest.mark.parametrize(
    "text,expected",
    [
        ("203.0.113.7", "203.0.113.7"),
        ("203.0.113.7:51234", "203.0.113.7"),
        (" 203.0.113.7 ", "203.0.113.7"),
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("::ffff:203.0.113.7", "203.0.113.7"),
        ("fe80::1%eth0", "fe80::1"),
        ("::1", "::1"),
    ],
)
def test_normalize_accepts_the_common_spellings(text, expected):
    assert normalize_ip(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "unknown",
        "garbage",
        "999.1.1.1",
        "1.2.3",
        "[::1",
        "1.2.3.4.5",
        "a" * 100,
        None,
        "1.2.3.4:5:6",
    ],
)
def test_normalize_rejects_non_addresses(text):
    assert normalize_ip(text) is None


# ------------------------------------------------------------------ resolution: untrusted peers
def test_direct_request_uses_the_peer():
    assert r("203.0.113.7") == "203.0.113.7"
    assert r("203.0.113.7", None, ()) == "203.0.113.7"
    assert r("2001:db8::9") == "2001:db8::9"


@pytest.mark.parametrize(
    "xff",
    [
        "1.1.1.1",
        "1.1.1.1, 2.2.2.2",
        "10.0.0.5",  # claiming to be a trusted proxy does not help either
        "garbage",
        "",
        "::1",
        "203.0.113.7, 198.51.100.1, 10.0.0.1",
    ],
)
def test_untrusted_peer_cannot_choose_its_identity(xff):
    assert r("203.0.113.7", xff) == "203.0.113.7"
    assert r("2001:db8::9", xff) == "2001:db8::9"


def test_no_trusted_proxies_configured_ignores_forwarding_entirely():
    assert r("10.0.0.5", "1.1.1.1", ()) == "10.0.0.5"


def test_non_ip_peer_is_kept_verbatim_and_never_overridden():
    assert resolve_client_ip("testclient", "1.1.1.1", TRUSTED) == "testclient"
    assert resolve_client_ip(None, "1.1.1.1", TRUSTED) == "unknown"
    assert resolve_client_ip("", "1.1.1.1", TRUSTED) == "unknown"


def test_ipv4_mapped_peer_is_the_same_identity_as_plain_ipv4():
    assert r("::ffff:203.0.113.7") == r("203.0.113.7") == "203.0.113.7"


# ------------------------------------------------------------------ resolution: trusted peers
def test_trusted_proxy_single_hop_gives_the_client():
    assert r("10.0.0.5", "203.0.113.7") == "203.0.113.7"
    assert r("100.64.1.1", "2001:db8::77") == "2001:db8::77"
    assert r("192.0.2.1", "198.51.100.4") == "198.51.100.4"  # single-address entry
    assert r("fd00::5", "203.0.113.7") == "203.0.113.7"


def test_rightmost_untrusted_hop_wins_so_a_client_supplied_prefix_is_ignored():
    # the client wrote "6.6.6.6"; the proxy appended the address it actually saw
    assert r("10.0.0.5", "6.6.6.6, 203.0.113.9") == "203.0.113.9"
    assert r("10.0.0.5", "6.6.6.6, 7.7.7.7, 203.0.113.9") == "203.0.113.9"


def test_chain_of_trusted_proxies_is_walked_past():
    assert r("10.0.0.5", "203.0.113.9, 10.0.0.9, 100.64.0.3") == "203.0.113.9"
    assert r("10.0.0.5", "198.51.100.1, 203.0.113.9, 10.0.0.9") == "203.0.113.9"


def test_all_hops_trusted_or_missing_header_falls_back_to_the_peer():
    assert r("10.0.0.5", "10.0.0.9, 100.64.0.3") == "10.0.0.5"
    assert r("10.0.0.5", None) == "10.0.0.5"
    assert r("10.0.0.5", "") == "10.0.0.5"


@pytest.mark.parametrize(
    "xff",
    [
        "garbage",
        "203.0.113.9, garbage",
        "unknown",
        ",",
        "203.0.113.9,,",
        "[::1",
        "999.9.9.9",
    ],
)
def test_malformed_forwarded_values_fall_back_to_the_peer(xff):
    assert r("10.0.0.5", xff) == "10.0.0.5"


def test_junk_to_the_left_of_a_valid_untrusted_hop_is_just_client_supplied_prefix():
    # right-to-left: the proxy-appended hop decides; whatever the client wrote before it cannot change the outcome
    assert r("10.0.0.5", "garbage, 203.0.113.9") == "203.0.113.9"
    assert r("10.0.0.5", "999.9.9.9, 203.0.113.9") == "203.0.113.9"


def test_oversized_or_overlong_chains_fall_back_to_the_peer():
    assert r("10.0.0.5", ", ".join(["203.0.113.9"] * 100)) == "10.0.0.5"
    assert r("10.0.0.5", "203.0.113.9," + " " * 3000) == "10.0.0.5"


def test_spelling_variants_of_one_client_collapse_to_one_identity():
    ids = {
        r("10.0.0.5", s)
        for s in (
            "2001:db8::1",
            "2001:0db8:0:0:0:0:0:1",
            "[2001:db8::1]:443",
            "[2001:DB8::1]",
        )
    }
    assert ids == {"2001:db8::1"}
    assert (
        r("10.0.0.5", "::ffff:203.0.113.9")
        == r("10.0.0.5", "203.0.113.9:80")
        == "203.0.113.9"
    )


def test_ipv6_trusted_proxy_and_mixed_families():
    t = parse_trusted_proxies("2001:db8:ffff::/48")
    assert resolve_client_ip("2001:db8:ffff::10", "203.0.113.9", t) == "203.0.113.9"
    assert (
        resolve_client_ip("2001:db8:eeee::10", "203.0.113.9", t) == "2001:db8:eeee::10"
    )
    # an IPv4 hop is never matched against an IPv6 range and vice versa
    assert (
        resolve_client_ip(
            "2001:db8:ffff::10", "10.0.0.1", parse_trusted_proxies("2001:db8:ffff::/48")
        )
        == "10.0.0.1"
    )


# ------------------------------------------------------------------ startup check
def test_production_behind_proxy_without_trusted_proxies_refuses_to_boot():
    s = _settings(ENVIRONMENT="production", TRUST_PROXY_TLS=True)
    with pytest.raises(StartupCheckError) as e:
        check_trusted_proxies(s)
    assert "TRUSTED_PROXIES" in str(e.value)


def test_production_with_trusted_proxies_passes():
    check_trusted_proxies(
        _settings(
            ENVIRONMENT="production",
            TRUST_PROXY_TLS=True,
            TRUSTED_PROXIES="100.64.0.0/10",
        )
    )


def test_production_without_a_proxy_and_development_are_not_blocked():
    check_trusted_proxies(_settings(ENVIRONMENT="production", FORCE_HTTPS=True))
    check_trusted_proxies(_settings(ENVIRONMENT="development", TRUST_PROXY_TLS=True))
    check_trusted_proxies(_settings(ENVIRONMENT="staging", TRUST_PROXY_TLS=True))


def test_check_is_part_of_the_standard_startup_checks():
    from app.startup_checks import _CHECKS

    assert check_trusted_proxies in _CHECKS


# ------------------------------------------------------------------ uvicorn / deployment files
def test_dockerfile_passes_the_same_allow_list_to_uvicorn_and_never_a_wildcard():
    text = (Path(__file__).parents[2] / "Dockerfile").read_text(encoding="utf-8")
    cmd = [ln for ln in text.splitlines() if ln.startswith("CMD")][0]
    assert "--forwarded-allow-ips" in cmd and "TRUSTED_PROXIES" in cmd
    assert '"*"' not in cmd and "forwarded-allow-ips *" not in cmd
    assert "127.0.0.1" in cmd  # safe default when unset
