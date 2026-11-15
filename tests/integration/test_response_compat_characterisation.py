"""X-1 characterisation: the response contracts of the verdict consumers as they were BEFORE the additive `verdict` field.

Every key listed here must keep its name and meaning. The tests tolerate the new optional `verdict` key (and nothing else
new), so they pass on the unchanged code and must keep passing once the verdict is attached."""

import pytest

pytestmark = pytest.mark.integration

LINK = "/api/v1/link-scanner"
MSG = "/api/v1/message"
REP = "/api/v1/reports"

LINK_KEYS = {
    "id",
    "user_id",
    "url",
    "is_phishing",
    "is_malicious",
    "risk_score",
    "threat_category",
    "scan_provider",
    "gsb_threats",
    "scanned_at",
}
MESSAGE_KEYS = {
    "is_safe",
    "risk_level",
    "risk_score",
    "scam_type",
    "explanation",
    "action",
    "red_flags",
    "detected_patterns",
    "sender_validation",
    "analyzed_at",
}
JOB_KEYS = {
    "is_fake",
    "confidence",
    "risk_score",
    "red_flags",
    "explanation",
    "action",
    "analyzed_at",
}
REPORT_KEYS = {
    "id",
    "user_id",
    "report_date",
    "threats_detected",
    "apps_scanned",
    "links_scanned",
    "calls_analyzed",
    "overall_risk_score",
    "top_threats",
    "recommendations",
    "created_at",
    "security_score",
    "risk_level",
}
SCAM = "URGENT: your SBI KYC has expired. Click http://bit.ly/abc123 now and share your OTP or account will be blocked"


def only_old(j, old):
    assert old <= set(j), f"missing old keys: {old - set(j)}"
    assert set(j) - old <= {"verdict"}, (
        f"unexpected new keys: {set(j) - old - {'verdict'}}"
    )


async def inconclusive(url):
    return {
        "status": "network_error",
        "safe": False,
        "threats": [],
        "provider": "x",
        "reason": "boom",
        "http_status": None,
        "cached": False,
    }


@pytest.fixture(autouse=True)
def _providers_down(monkeypatch):
    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", inconclusive)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", inconclusive)


@pytest.fixture
async def user(make_user):
    return await make_user("compat")


async def test_link_scan_and_history_keep_every_old_key_and_value(
    client, user, auth_headers
):
    r = await client.post(
        f"{LINK}/scan",
        headers=auth_headers(user),
        json={"url": "http://192.168.4.4/login/verify"},
    )
    assert r.status_code == 200, r.text
    j = r.json()
    only_old(j, LINK_KEYS)
    assert (
        j["scan_provider"],
        j["gsb_threats"],
        j["is_phishing"],
        j["is_malicious"],
    ) == ("internal_fallback", None, True, False)
    assert j["risk_score"] == 55.0 and j["threat_category"] == "ip_based_url"
    h = (await client.get(f"{LINK}/history", headers=auth_headers(user))).json()
    assert len(h) == 1
    only_old(h[0], LINK_KEYS)
    assert h[0]["risk_score"] == 55.0


async def test_message_analysis_keeps_every_old_key_and_value(
    client, user, auth_headers
):
    r = await client.post(
        f"{MSG}/analyze",
        headers=auth_headers(user),
        json={"message_text": SCAM, "use_ai": False},
    )
    assert r.status_code == 200, r.text
    j = r.json()
    only_old(j, MESSAGE_KEYS)
    # the router maps the pattern category back to a score (suspicious_message -> 60); kept as-is
    assert (j["risk_score"], j["risk_level"], j["is_safe"]) == (
        60.0,
        "suspicious_message",
        False,
    )
    clean = (
        await client.post(
            f"{MSG}/analyze",
            headers=auth_headers(user),
            json={"message_text": "See you at lunch", "use_ai": False},
        )
    ).json()
    only_old(clean, MESSAGE_KEYS)
    assert (clean["risk_score"], clean["risk_level"], clean["is_safe"]) == (
        0.0,
        "safe",
        True,
    )


async def test_job_offer_keeps_every_old_key_and_value(client, user, auth_headers):
    r = await client.post(
        f"{MSG}/check-job-offer",
        headers=auth_headers(user),
        json={
            "job_text": "Earn 50000 per month from home. Pay registration fee 500 and send your Aadhaar and OTP today",
            "use_ai": False,
        },
    )
    assert r.status_code == 200, r.text
    j = r.json()
    only_old(j, JOB_KEYS)
    assert (
        j["confidence"] == j["risk_score"]
    )  # today's (non-)confidence semantics, unchanged


async def test_daily_report_keeps_every_old_key_and_value(client, user, auth_headers):
    r = await client.get(f"{REP}/daily", headers=auth_headers(user))
    assert r.status_code == 200, r.text
    j = r.json()
    only_old(j, REPORT_KEYS)
    assert j["security_score"] == 100 - round(j["overall_risk_score"])
    assert j["risk_level"] in {"low", "moderate", "high", "critical"}
