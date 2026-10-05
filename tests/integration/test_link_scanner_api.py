"""Link scanner endpoint: provider combination logic, persistence, alerts, validation and auth.

The two provider clients are replaced at the router boundary with envelopes shaped exactly like
the real clients return (their own behaviour is covered in tests/unit/test_threat_intel_clients.py)."""

import pytest
from sqlalchemy import select

from app.models.alert import Alert
from app.models.link_scan import LinkScan

pytestmark = pytest.mark.integration

SCAN = "/api/v1/link-scanner/scan"
HIST = "/api/v1/link-scanner/history"
STATUS = "/api/v1/link-scanner/providers/status"


def env(provider, status, threats=None, reason=None):
    return {
        "status": status,
        "safe": status == "safe",
        "threats": threats or [],
        "provider": provider,
        "reason": reason,
        "http_status": None,
        "cached": False,
    }


def gsb_hit():
    return env(
        "google_safe_browsing",
        "malicious",
        [
            {
                "threat_type": "SOCIAL_ENGINEERING",
                "threat_label": "Phishing",
                "platform_type": "ANY_PLATFORM",
                "threat_entry_type": "URL",
                "url": "x",
            }
        ],
    )


def uh_hit():
    return env(
        "urlhaus",
        "malicious",
        [
            {
                "threat_type": "MALWARE_DOWNLOAD",
                "threat_label": "Malware Download",
                "platform_type": "ANY_PLATFORM",
                "threat_entry_type": "URL",
                "url": "x",
            }
        ],
    )


def set_providers(monkeypatch, gsb, uh):
    async def _g(url):
        return gsb

    async def _u(url):
        return uh

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", _g)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", _u)


@pytest.fixture
async def user(make_user):
    return await make_user("scan")


async def test_safe_browsing_hit_wins_and_raises_a_critical_alert(
    client, db, user, auth_headers, monkeypatch
):
    set_providers(monkeypatch, gsb_hit(), env("urlhaus", "safe"))
    r = await client.post(
        SCAN, headers=auth_headers(user), json={"url": "http://phish.example/login"}
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert (
        j["is_malicious"],
        j["is_phishing"],
        j["scan_provider"],
        j["risk_score"],
    ) == (True, True, "google_safe_browsing", 95.0)
    alert = (
        (await db.execute(select(Alert).where(Alert.user_id == user.id)))
        .scalars()
        .one()
    )
    assert (
        alert.severity.value == "critical" and alert.title == "Dangerous Link Detected"
    )


async def test_urlhaus_catches_what_safe_browsing_misses(
    client, db, user, auth_headers, monkeypatch
):
    """Regression: a 'safe' Safe Browsing answer used to short-circuit URLhaus entirely."""
    set_providers(monkeypatch, env("google_safe_browsing", "safe"), uh_hit())
    r = await client.post(
        SCAN, headers=auth_headers(user), json={"url": "http://files.example/m.exe"}
    )
    j = r.json()
    assert (j["is_malicious"], j["scan_provider"], j["risk_score"]) == (
        True,
        "urlhaus",
        90.0,
    )
    assert (
        j["threat_category"] == "malware"
        and j["gsb_threats"][0]["threat_type"] == "MALWARE_DOWNLOAD"
    )


async def test_both_clean_uses_internal_score_and_credits_both(
    client, user, auth_headers, monkeypatch
):
    set_providers(
        monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "safe")
    )
    j = (
        await client.post(
            SCAN, headers=auth_headers(user), json={"url": "https://example.org/about"}
        )
    ).json()
    assert (
        j["scan_provider"] == "google_safe_browsing+urlhaus"
        and j["is_malicious"] is False
        and j["gsb_threats"] == []
    )


async def test_internal_engine_still_flags_structurally_risky_urls_even_when_providers_say_clean(
    client, user, auth_headers, monkeypatch
):
    set_providers(
        monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "safe")
    )
    j = (
        await client.post(
            SCAN,
            headers=auth_headers(user),
            json={"url": "http://secure-login-paypal-verify.xyz/account"},
        )
    ).json()
    assert j["risk_score"] > 0


@pytest.mark.parametrize(
    "gsb_status,uh_status",
    [
        ("no_api_key", "no_api_key"),
        ("rate_limited", "network_error"),
        ("http_error", "http_error"),
        ("unknown_error", "no_api_key"),
    ],
)
async def test_both_providers_unavailable_falls_back_to_internal_only(
    client, user, auth_headers, monkeypatch, gsb_status, uh_status
):
    set_providers(
        monkeypatch,
        env("google_safe_browsing", gsb_status, reason="x"),
        env("urlhaus", uh_status, reason="y"),
    )
    r = await client.post(
        SCAN, headers=auth_headers(user), json={"url": "https://example.org/"}
    )
    assert (
        r.status_code == 200
        and r.json()["scan_provider"] == "internal_fallback"
        and r.json()["gsb_threats"] is None
    )


async def test_one_provider_down_other_clean_is_attributed_to_the_one_that_answered(
    client, user, auth_headers, monkeypatch
):
    set_providers(
        monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "no_api_key")
    )
    assert (
        await client.post(
            SCAN, headers=auth_headers(user), json={"url": "https://example.org/"}
        )
    ).json()["scan_provider"] == "google_safe_browsing"
    set_providers(
        monkeypatch, env("google_safe_browsing", "rate_limited"), env("urlhaus", "safe")
    )
    assert (
        await client.post(
            SCAN, headers=auth_headers(user), json={"url": "https://example.org/2"}
        )
    ).json()["scan_provider"] == "urlhaus_clean_internal_score"


async def test_history_is_per_user_newest_first_and_persisted(
    client, db, make_user, auth_headers, monkeypatch
):
    a, b = await make_user("a"), await make_user("b")
    set_providers(
        monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "safe")
    )
    for i in range(3):
        await client.post(
            SCAN, headers=auth_headers(a), json={"url": f"https://example.org/{i}"}
        )
    await client.post(
        SCAN, headers=auth_headers(b), json={"url": "https://other.example/"}
    )
    h = (await client.get(HIST, headers=auth_headers(a))).json()
    assert [x["url"] for x in h] == [
        "https://example.org/2",
        "https://example.org/1",
        "https://example.org/0",
    ]
    assert (await db.execute(select(LinkScan))).scalars().all().__len__() == 4


@pytest.mark.parametrize(
    "body",
    [
        {"url": ""},
        {"url": "  "},
        {"url": "ab"},
        {"url": "http://x.example/" + "a" * 2100},
        {"url": "http://x\n.example/"},
        {},
    ],
)
async def test_invalid_urls_are_rejected_with_422(client, user, auth_headers, body):
    assert (
        await client.post(SCAN, headers=auth_headers(user), json=body)
    ).status_code == 422


async def test_requires_authentication(client):
    assert (
        await client.post(SCAN, json={"url": "https://example.org/"})
    ).status_code in (401, 403)
    assert (await client.get(HIST)).status_code in (401, 403)


async def test_providers_status_reflects_configuration(
    client, user, auth_headers, monkeypatch
):
    from app.config import settings

    monkeypatch.setattr("app.routers.link_scanner.gsb_is_configured", lambda: True)
    monkeypatch.setattr(settings, "URLHAUS_AUTH_KEY", "", raising=False)
    j = (await client.get(STATUS, headers=auth_headers(user))).json()
    assert (
        j["gsb"]["configured"] is True
        and j["urlhaus"]["configured"] is False
        and j["internal"]["configured"] is True
    )
    monkeypatch.setattr(settings, "URLHAUS_AUTH_KEY", "k" * 12, raising=False)
    assert (await client.get(STATUS, headers=auth_headers(user))).json()["urlhaus"][
        "configured"
    ] is True
