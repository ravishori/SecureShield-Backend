"""X-1 consumer contracts: link scan, link history, message, job offer and the daily report each carry a valid additive
`verdict`, built from the detector's own result, never from an AI result, never `safe` from absence, and with no submitted
content in it. The legacy fields are pinned separately in test_response_compat_characterisation.py."""

import json

import pytest
from sqlalchemy import select

import app.routers.message_analyzer as ma
from app.models.alert import Alert, AlertSeverity, AlertType
from app.models.link_scan import LinkScan
from app.schemas.scam_verdict import RiskLevel, ScamVerdict

pytestmark = pytest.mark.integration

LINK = "/api/v1/link-scanner"
MSG = "/api/v1/message"
REP = "/api/v1/reports"
SCAM = "URGENT: your SBI KYC has expired. Click http://bit.ly/abc123 now and share your OTP or account will be blocked"


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


def providers(monkeypatch, gsb, uh):
    async def g(url):
        return gsb

    async def u(url):
        return uh

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", g)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", u)


def verdict(j):
    assert "verdict" in j and j["verdict"] is not None, j
    return ScamVerdict.model_validate(
        j["verdict"]
    )  # the response is valid against the strict contract


def codes(v, attr):
    return {x.code for x in getattr(v, attr)}


@pytest.fixture
async def user(make_user):
    return await make_user("verdict")


# ------------------------------------------------------------------------------------------------ link scan
async def scan(client, user, auth_headers, url="http://192.168.4.4/login/verify"):
    r = await client.post(f"{LINK}/scan", headers=auth_headers(user), json={"url": url})
    assert r.status_code == 200, r.text
    return r.json()


async def test_provider_hit_gives_a_critical_verdict_and_keeps_the_legacy_fields(
    client, user, auth_headers, monkeypatch
):
    providers(
        monkeypatch,
        env(
            "google_safe_browsing",
            "malicious",
            [{"threat_type": "SOCIAL_ENGINEERING", "threat_label": "x"}],
        ),
        env("urlhaus", "safe"),
    )
    j = await scan(client, user, auth_headers, "http://phish.example/login")
    v = verdict(j)
    assert (j["is_malicious"], j["scan_provider"], j["risk_score"]) == (
        True,
        "google_safe_browsing",
        95.0,
    )
    assert v.risk_level is RiskLevel.CRITICAL and {
        "listed_malicious",
        "threat_phishing",
        "not_listed",
    } <= codes(v, "evidence")


@pytest.mark.parametrize(
    "status",
    [
        "no_api_key",
        "rate_limited",
        "network_error",
        "http_error",
        "unknown_error",
        "garbage",
    ],
)
async def test_every_provider_failure_is_an_outage_verdict_never_safe(
    client, user, auth_headers, monkeypatch, status
):
    providers(monkeypatch, env("google_safe_browsing", status), env("urlhaus", status))
    j = await scan(client, user, auth_headers, "https://example.com/about")
    v = verdict(j)
    assert j["scan_provider"] == "internal_fallback" and j["risk_score"] == 0.0
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)
    assert codes(v, "reasons") == {"reputation_unavailable"}
    assert "no_signals_found" not in codes(v, "reasons")
    assert "provider_unavailable" in codes(v, "evidence")
    assert any("legitimacy could not be established" in x for x in v.limitations)


async def test_a_timeout_is_an_outage_and_not_a_clean_scan(
    client, user, auth_headers, monkeypatch
):
    t = env("google_safe_browsing", "network_error", reason="timeout")
    providers(monkeypatch, t, {**t, "provider": "urlhaus"})
    v = verdict(await scan(client, user, auth_headers, "https://example.com"))
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)
    assert "reputation_unavailable" in codes(v, "reasons")


async def test_one_provider_down_and_the_other_not_listed_is_low_not_unknown(
    client, user, auth_headers, monkeypatch
):
    providers(
        monkeypatch,
        env("google_safe_browsing", "network_error"),
        env("urlhaus", "safe"),
    )
    v = verdict(await scan(client, user, auth_headers, "https://example.com/about"))
    assert v.risk_level is RiskLevel.LOW and "no_signals_found" in codes(v, "reasons")
    assert "reputation_unavailable" not in codes(v, "reasons")


async def test_outage_plus_an_independent_adverse_heuristic_is_not_unknown(
    client, user, auth_headers, monkeypatch
):
    providers(
        monkeypatch,
        env("google_safe_browsing", "network_error"),
        env("urlhaus", "network_error"),
    )
    v = verdict(
        await scan(client, user, auth_headers, "http://192.168.4.4/login/verify")
    )
    assert v.risk_level is RiskLevel.MEDIUM
    assert {"reputation_unavailable", "ip_based_url"} <= codes(v, "reasons")
    assert "no_signals_found" not in codes(v, "reasons")


async def test_not_listed_is_neutral_and_still_not_safe(
    client, user, auth_headers, monkeypatch
):
    providers(monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "safe"))
    v = verdict(await scan(client, user, auth_headers, "https://example.com/about"))
    assert v.risk_level is RiskLevel.LOW and "reputation_unavailable" not in codes(
        v, "reasons"
    )
    assert all(e.polarity.value == "neutral" for e in v.evidence)


async def test_contradictory_providers_one_malicious_one_not_listed(
    client, user, auth_headers, monkeypatch
):
    providers(
        monkeypatch,
        env("google_safe_browsing", "safe"),
        env("urlhaus", "malicious", [{"threat_type": "MALWARE_DOWNLOAD"}]),
    )
    j = await scan(client, user, auth_headers, "https://example.com/file.exe")
    v = verdict(j)
    assert j["scan_provider"] == "urlhaus" and v.risk_level is RiskLevel.CRITICAL
    assert {"listed_malicious", "not_listed", "threat_malware"} <= codes(v, "evidence")


async def test_not_listed_does_not_hide_strong_heuristics(
    client, user, auth_headers, monkeypatch
):
    providers(monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "safe"))
    v = verdict(
        await scan(client, user, auth_headers, "http://192.168.4.4/login/verify")
    )
    assert v.risk_level is RiskLevel.MEDIUM and {
        "ip_based_url",
        "insecure_http",
    } <= codes(v, "reasons")


async def test_a_negative_example_known_good_looking_https_link_is_low_with_no_adverse_signal(
    client, user, auth_headers, monkeypatch
):
    providers(monkeypatch, env("google_safe_browsing", "safe"), env("urlhaus", "safe"))
    v = verdict(await scan(client, user, auth_headers, "https://www.example.com/"))
    assert v.risk_level is RiskLevel.LOW and "no_signals_found" in codes(v, "reasons")


async def test_the_link_verdict_contains_no_part_of_the_submitted_url(
    client, user, auth_headers, monkeypatch
):
    providers(
        monkeypatch,
        env("google_safe_browsing", "network_error"),
        env("urlhaus", "network_error"),
    )
    j = await scan(
        client,
        user,
        auth_headers,
        "http://192.168.77.12/login/verify?token=TOPSECRET123&acct=9876543210",
    )
    blob = json.dumps(j["verdict"])
    for leak in ("TOPSECRET123", "192.168", "9876543210", "login", "http://"):
        assert leak not in blob


async def test_history_items_carry_a_verdict_and_say_details_were_not_stored(
    client, user, auth_headers, monkeypatch
):
    providers(
        monkeypatch,
        env("google_safe_browsing", "network_error"),
        env("urlhaus", "network_error"),
    )
    await scan(client, user, auth_headers, "http://192.168.4.4/login/verify")
    h = (await client.get(f"{LINK}/history", headers=auth_headers(user))).json()
    assert len(h) == 1
    v = verdict(h[0])
    assert v.risk_level is RiskLevel.MEDIUM and any(
        "not stored" in x for x in v.limitations
    )


async def test_a_corrupt_history_row_degrades_to_unknown_without_breaking_the_list(
    client, user, auth_headers, session_factory
):
    async with session_factory() as s:
        s.add(
            LinkScan(
                user_id=user.id,
                url="http://x.example",
                is_phishing=False,
                is_malicious=False,
                risk_score=-5.0,
                threat_category=None,
                scan_provider="internal_fallback",
                gsb_threats=None,
            )
        )
        await s.commit()
    r = await client.get(f"{LINK}/history", headers=auth_headers(user))
    assert r.status_code == 200
    v = verdict(r.json()[0])
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)


# ------------------------------------------------------------------------------------------------ message
async def analyze(client, user, auth_headers, text, **extra):
    r = await client.post(
        f"{MSG}/analyze",
        headers=auth_headers(user),
        json={"message_text": text, "use_ai": False, **extra},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_a_scam_message_has_high_risk_with_pattern_evidence_and_no_content(
    client, user, auth_headers
):
    j = await analyze(client, user, auth_headers, SCAM + " 9876543210 TOPSECRETPHRASE")
    v = verdict(j)
    assert v.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert {
        "scam_message_pattern",
        "risky_link_in_message",
        "urgency_language",
    } & codes(v, "evidence")
    blob = json.dumps(j["verdict"])
    for leak in ("TOPSECRETPHRASE", "9876543210", "bit.ly", "KYC", "SBI", "expired"):
        assert leak not in blob


async def test_a_harmless_message_is_low_not_safe(client, user, auth_headers):
    v = verdict(await analyze(client, user, auth_headers, "See you at lunch tomorrow"))
    assert v.risk_level is RiskLevel.LOW and "no_signals_found" in codes(v, "reasons")
    assert any("No sender was supplied" in x for x in v.limitations)


async def test_sender_registry_boost_is_in_the_verdict_and_matches_the_router(
    client, user, auth_headers
):
    j = await analyze(
        client, user, auth_headers, "See you at lunch tomorrow", sender="9876543210"
    )
    v = verdict(j)
    assert j["sender_validation"]["verdict"] == "PHONE_NUMBER"
    assert "sender_is_phone_number" in codes(v, "evidence") and v.risk_score == 10
    assert j["risk_score"] == 10.0  # the router's own +10, same as the verdict adapter


async def test_the_verdict_never_comes_from_an_ai_result(
    client, user, auth_headers, monkeypatch
):
    monkeypatch.setenv("AI_PROCESSING_ENABLED", "true")

    async def fake_ai(text):
        return {
            "is_safe": False,
            "risk_level": "high",
            "scam_type": "phishing",
            "explanation": "e",
            "action": "a",
            "red_flags": ["ai-flag"],
        }

    monkeypatch.setattr(ma, "analyze_message_safety", fake_ai)
    r = await client.post(
        f"{MSG}/analyze",
        headers=auth_headers(user),
        json={"message_text": "See you at lunch tomorrow", "use_ai": True},
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert (
        j["risk_level"] == "high"
    )  # the legacy field reflects the (faked) AI result, unchanged
    v = verdict(j)
    assert v.risk_level is RiskLevel.LOW and "no_signals_found" in codes(
        v, "reasons"
    )  # the verdict reflects only the pattern analysis
    assert "ai-flag" not in json.dumps(j["verdict"])


# ------------------------------------------------------------------------------------------------ job offer
async def test_job_offer_verdict_uses_the_detectors_fake_flag(
    client, user, auth_headers
):
    r = await client.post(
        f"{MSG}/check-job-offer",
        headers=auth_headers(user),
        json={
            "job_text": "Earn 50000 per month from home. Pay registration fee 500 and apply on whatsapp today only",
            "use_ai": False,
        },
    )
    j = r.json()
    v = verdict(j)
    assert j["is_fake"] is True and v.risk_level is RiskLevel.HIGH
    assert "job_upfront_payment" in codes(v, "evidence")
    assert (
        j["confidence"] == j["risk_score"] and v.confidence is None
    )  # legacy semantics kept; the verdict does not repeat the claim


async def test_a_genuine_looking_job_offer_is_low_not_safe(client, user, auth_headers):
    r = await client.post(
        f"{MSG}/check-job-offer",
        headers=auth_headers(user),
        json={
            "job_text": "Acme Pvt Ltd is hiring a software engineer. Apply on our company careers page. Salary disclosed.",
            "use_ai": False,
        },
    )
    v = verdict(r.json())
    assert v.risk_level is RiskLevel.LOW and v.risk_level is not RiskLevel.SAFE


# ------------------------------------------------------------------------------------------------ daily report (API-only aggregate)
async def test_a_day_with_no_activity_is_unknown_while_the_legacy_fields_are_unchanged(
    client, user, auth_headers
):
    j = (await client.get(f"{REP}/daily", headers=auth_headers(user))).json()
    v = verdict(j)
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)
    assert (
        j["security_score"] == 100 and j["overall_risk_score"] == 0.0
    )  # the dashboard's own (misleading) semantics are untouched


async def test_scan_activity_is_never_risk_evidence(
    client, user, auth_headers, session_factory
):
    async with session_factory() as s:
        s.add(
            Alert(
                user_id=user.id,
                alert_type=AlertType.phishing,
                title="t",
                message="m",
                severity=AlertSeverity.warning,
            )
        )
        for i in range(30):
            s.add(
                LinkScan(
                    user_id=user.id,
                    url=f"https://example.com/{i}",
                    is_phishing=False,
                    is_malicious=False,
                    risk_score=0.0,
                    threat_category=None,
                    scan_provider="internal_fallback",
                    gsb_threats=None,
                )
            )
        await s.commit()
    j = (await client.get(f"{REP}/daily", headers=auth_headers(user))).json()
    v = verdict(j)
    # the legacy score is inflated by 30 clean link scans (links * 2); the verdict is not
    assert (
        j["overall_risk_score"] >= 60
        and v.risk_score == 10
        and v.risk_level is RiskLevel.LOW
    )
    assert codes(v, "evidence") == {"alerts_recorded"}
    assert any("F05-1" in x for x in v.limitations)


async def test_history_reports_also_carry_a_verdict(client, user, auth_headers):
    await client.get(f"{REP}/daily", headers=auth_headers(user))
    h = (await client.get(f"{REP}/history", headers=auth_headers(user))).json()
    assert h and all(verdict(x) for x in h)


# ------------------------------------------------------------------------------------------------ nothing is persisted or blocked
async def test_no_verdict_is_stored_and_nothing_extra_is_written(
    client, user, auth_headers, session_factory, monkeypatch
):
    providers(
        monkeypatch,
        env("google_safe_browsing", "network_error"),
        env("urlhaus", "network_error"),
    )
    await scan(client, user, auth_headers, "https://example.com")
    async with session_factory() as s:
        row = (await s.execute(select(LinkScan))).scalar_one()
    assert not hasattr(
        row, "verdict"
    )  # the model/table is unchanged: no migration, no stored verdict
