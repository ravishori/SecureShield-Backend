"""Message analyzer: pattern analysis, AI path (faked), alerts, screenshot upload safety."""

import json
from types import SimpleNamespace

import pytest

import app.routers.message_analyzer as ma

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _external_ai_on_with_a_fake_provider(monkeypatch):
    """These tests exercise the AI paths against a RECORDING FAKE provider only (no network); containment tests live in
    test_ai_containment_api.py."""
    monkeypatch.setenv("AI_PROCESSING_ENABLED", "true")


M = "/api/v1/message"
PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 64
SCAM = "URGENT: your SBI KYC has expired. Click http://bit.ly/abc123 now and share your OTP or account will be blocked"


@pytest.fixture
def ai(monkeypatch):
    calls = {"msg": 0, "job": 0, "vision": []}

    async def safety(text):
        calls["msg"] += 1
        return {
            "is_safe": False,
            "risk_level": "high",
            "scam_type": "phishing",
            "explanation": "e",
            "action": "a",
            "red_flags": ["ai-flag"],
        }

    async def job(text):
        calls["job"] += 1
        return {
            "is_fake": True,
            "confidence": 90,
            "red_flags": ["fee"],
            "explanation": "e",
            "action": "a",
        }

    async def vision(**kw):
        calls["vision"].append(kw)
        text = json.dumps(
            {
                "sender": "VK-SBIBNK",
                "message_text": "hello",
                "phone_number": None,
                "timestamp": None,
            }
        )
        return SimpleNamespace(content=[SimpleNamespace(text=text)])

    monkeypatch.setattr(ma, "analyze_message_safety", safety)
    monkeypatch.setattr(ma, "analyze_job_offer_ai", job)
    monkeypatch.setattr(ma, "_create_message", vision)
    return calls


async def test_requires_auth(client):
    for path in (
        "/analyze",
        "/validate-sender",
        "/check-job-offer",
        "/check-bullying",
        "/extract-screenshot",
    ):
        assert (await client.post(M + path, json={})).status_code in (401, 403, 422)
        assert (await client.post(M + path)).status_code in (401, 403)


async def test_pattern_only_analysis_does_not_call_the_model(
    client, make_user, auth_headers, ai
):
    h = auth_headers(await make_user("p"))
    r = await client.post(
        f"{M}/analyze", headers=h, json={"message_text": SCAM, "use_ai": False}
    )
    assert r.status_code == 200, r.text
    assert r.json()["risk_score"] >= 40 and ai["msg"] == 0


async def test_risky_message_creates_an_alert_and_uses_ai(
    client, make_user, auth_headers, ai
):
    h = auth_headers(await make_user("risk"))
    r = await client.post(
        f"{M}/analyze", headers=h, json={"message_text": SCAM, "sender": "9876543210"}
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["risk_level"] == "high" and "ai-flag" in j["red_flags"] and ai["msg"] == 1
    alerts = (await client.get("/api/v1/alerts/", headers=h)).json()
    assert (
        alerts["total"] == 1
        and alerts["items"][0]["alert_type"] == "suspicious_message"
    )


async def test_benign_message_creates_no_alert(
    client, make_user, auth_headers, ai, monkeypatch
):
    async def safe(text):
        return {
            "is_safe": True,
            "risk_level": "safe",
            "scam_type": "none",
            "explanation": "",
            "action": "",
            "red_flags": [],
        }

    monkeypatch.setattr(ma, "analyze_message_safety", safe)
    h = auth_headers(await make_user("ok"))
    r = await client.post(
        f"{M}/analyze",
        headers=h,
        json={"message_text": "See you at lunch tomorrow", "use_ai": True},
    )
    assert (
        r.status_code == 200
        and (await client.get("/api/v1/alerts/", headers=h)).json()["total"] == 0
    )


@pytest.mark.parametrize(
    "body",
    [
        {"message_text": ""},
        {"message_text": "x" * 5001},
        {"message_text": "x", "sender": "s" * 51},
        {},
    ],
)
async def test_analyze_input_bounds(client, make_user, auth_headers, ai, body):
    assert (
        await client.post(
            f"{M}/analyze", headers=auth_headers(await make_user("b")), json=body
        )
    ).status_code == 422


@pytest.mark.security
async def test_ai_calls_are_rate_limited_but_pattern_only_is_not(
    client, make_user, auth_headers, ai
):
    h = auth_headers(await make_user("rl"))
    for _ in range(10):
        assert (
            await client.post(f"{M}/analyze", headers=h, json={"message_text": "hi"})
        ).status_code == 200
    assert (
        await client.post(f"{M}/analyze", headers=h, json={"message_text": "hi"})
    ).status_code == 429
    assert (
        await client.post(
            f"{M}/analyze", headers=h, json={"message_text": "hi", "use_ai": False}
        )
    ).status_code == 200


async def test_job_offer_flow(client, make_user, auth_headers, ai):
    h = auth_headers(await make_user("job"))
    r = await client.post(
        f"{M}/check-job-offer",
        headers=h,
        json={"job_text": "Earn 5000/day pay registration fee"},
    )
    assert r.status_code == 200 and r.json()["is_fake"] is True and ai["job"] == 1
    assert (await client.get("/api/v1/alerts/", headers=h)).json()["items"][0][
        "alert_type"
    ] == "job_fraud"
    assert (
        await client.post(f"{M}/check-job-offer", headers=h, json={"job_text": ""})
    ).status_code == 422


async def test_bullying_check_and_bounds(client, make_user, auth_headers):
    h = auth_headers(await make_user("bu"))
    r = await client.post(
        f"{M}/check-bullying",
        headers=h,
        json={"message_text": "you are worthless nobody likes you, go die"},
    )
    assert r.status_code == 200 and "helpline" in r.json()
    assert (
        await client.post(
            f"{M}/check-bullying",
            headers=h,
            json={"message_text": "x", "reporter_note": "n" * 501},
        )
    ).status_code == 422


async def test_validate_sender_typed_body(client, make_user, auth_headers):
    h = auth_headers(await make_user("vs"))
    ok = await client.post(
        f"{M}/validate-sender", headers=h, json={"sender": "VK-SBIBNK"}
    )
    assert ok.status_code == 200 and "verdict" in ok.json()
    for bad in ({"sender": ""}, {"sender": 5}, {"sender": "x" * 51}, {}):
        assert (
            await client.post(f"{M}/validate-sender", headers=h, json=bad)
        ).status_code in (400, 422)
    assert (
        await client.post(f"{M}/validate-sender", headers=h, json={"sender": "   "})
    ).status_code == 400


def shot(client, h, data=PNG, ctype="image/png"):
    return client.post(
        f"{M}/extract-screenshot", headers=h, files={"file": ("s.png", data, ctype)}
    )


async def test_screenshot_extraction_uses_the_async_model_call(
    client, make_user, auth_headers, ai
):
    r = await shot(client, auth_headers(await make_user("ss")))
    assert (
        r.status_code == 200
        and r.json()["sender"] == "VK-SBIBNK"
        and len(ai["vision"]) == 1
    )
    assert (
        ai["vision"][0]["messages"][0]["content"][0]["source"]["media_type"]
        == "image/png"
    )


@pytest.mark.security
async def test_screenshot_upload_validation(client, make_user, auth_headers, ai):
    h = auth_headers(await make_user("sv"))
    assert (await shot(client, h, ctype="application/pdf")).status_code == 400
    assert (await shot(client, h, data=b"")).status_code == 400
    assert (
        await shot(client, h, data=b"not really a png at all")
    ).status_code == 400  # signature mismatch
    assert (
        await shot(client, h, data=PNG + b"x" * (5 * 1024 * 1024))
    ).status_code == 400
    assert ai["vision"] == []  # nothing reached the model


@pytest.mark.security
async def test_screenshot_failures_do_not_leak_exception_text(
    client, make_user, auth_headers, monkeypatch
):
    async def boom(**kw):
        raise RuntimeError("sk-ant-SECRET internal host 10.0.0.5")

    monkeypatch.setattr(ma, "_create_message", boom)
    r = await shot(client, auth_headers(await make_user("leak")))
    assert r.status_code == 200 and "SECRET" not in r.text and "10.0.0.5" not in r.text
    assert r.json()["extraction_note"]
