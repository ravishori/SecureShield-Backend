"""Phase 0 containment: external AI processing is behind a fail-closed global switch (AI_PROCESSING_ENABLED).

Only recording fakes are used: no test here can reach a real provider. The per-user consent architecture is NOT tested
here because it is not built yet (it belongs to the AI module)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models.ai_conversation import AiConversation
from app.services import ai_gate, ai_service

pytestmark = pytest.mark.integration

API = "/api/v1"


class FakeSDK:
    """Stands in for ``anthropic.AsyncAnthropic``: records constructions and calls, never touches a network."""

    constructed: list[str] = []
    calls: list[dict] = []

    def __init__(self, api_key=None, **kw):
        if not api_key:
            raise RuntimeError("no credential configured")
        FakeSDK.constructed.append(api_key)
        self.messages = self

    async def create(self, **kw):
        FakeSDK.calls.append(kw)
        return SimpleNamespace(content=[SimpleNamespace(text="mock reply")])


@pytest.fixture
def sdk(monkeypatch):
    FakeSDK.constructed, FakeSDK.calls = [], []
    monkeypatch.setattr(ai_service.anthropic, "AsyncAnthropic", FakeSDK)
    monkeypatch.setattr(ai_service, "_async_client_singleton", None)
    return FakeSDK


def set_switch(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("AI_PROCESSING_ENABLED", raising=False)
    else:
        monkeypatch.setenv("AI_PROCESSING_ENABLED", value)


def set_key(monkeypatch, key):
    monkeypatch.setattr(ai_service.settings, "ANTHROPIC_API_KEY", key)


# ------------------------------------------------------------------------------------------------ the switch itself
@pytest.mark.parametrize(
    "value", [None, "", "false", "FALSE", "0", "no", "off", "enabled!", "tru", " ", "2"]
)
def test_every_value_except_an_explicit_true_means_disabled(monkeypatch, value):
    set_switch(monkeypatch, value)
    assert ai_gate.ai_enabled() is False
    with pytest.raises(ai_gate.AIDisabledError):
        ai_gate.ensure_enabled()


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "on", " true "])
def test_only_explicit_true_values_enable_it(monkeypatch, value):
    set_switch(monkeypatch, value)
    assert ai_gate.ai_enabled() is True
    ai_gate.ensure_enabled()


def test_default_is_off_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv("AI_PROCESSING_ENABLED", raising=False)
    assert ai_gate.ai_enabled() is False


def test_an_api_key_never_enables_ai(monkeypatch, sdk):
    set_switch(monkeypatch, None)
    set_key(monkeypatch, "sk-test-key-not-real")
    assert ai_gate.ai_enabled() is False
    with pytest.raises(ai_gate.AIDisabledError):
        ai_service.get_async_client()
    with pytest.raises(ai_gate.AIDisabledError):
        ai_service.get_client()
    assert sdk.constructed == []  # not even a client object was built


# ------------------------------------------------------------------------------------- the provider boundary
async def test_the_central_boundary_refuses_when_disabled(monkeypatch, sdk):
    set_switch(monkeypatch, "false")
    set_key(monkeypatch, "sk-test-key-not-real")
    with pytest.raises(ai_gate.AIDisabledError):
        await ai_service._create_message(
            model="m", max_tokens=1, messages=[{"role": "user", "content": "private"}]
        )
    assert sdk.calls == [] and sdk.constructed == []


async def test_boundary_is_enforced_even_if_a_caller_swaps_the_client(monkeypatch):
    """A patched/injected client (as tests and future code might do) still cannot be reached while disabled."""
    set_switch(monkeypatch, "false")
    seen = []

    class Spy:
        messages = None

        async def create(self, **kw):
            seen.append(kw)

    spy = Spy()
    spy.messages = spy
    monkeypatch.setattr(ai_service, "get_async_client", lambda: spy)
    with pytest.raises(ai_gate.AIDisabledError):
        await ai_service._create_message(model="m", max_tokens=1, messages=[])
    assert seen == []


async def test_enabled_without_a_credential_fails_safely_with_no_call(monkeypatch, sdk):
    set_switch(monkeypatch, "true")
    set_key(monkeypatch, "")
    r = await ai_service.generate_ai_security_tips(1, 50.0, ["x"], [])
    assert isinstance(r, list) and r  # the deterministic default tips
    assert sdk.calls == []


async def test_enabled_with_a_credential_uses_only_the_mock(monkeypatch, sdk):
    set_switch(monkeypatch, "true")
    set_key(monkeypatch, "sk-test-key-not-real")
    reply = await ai_service.chat_with_coach([{"role": "user", "content": "hi"}])
    assert reply == "mock reply"
    assert len(sdk.calls) == 1 and sdk.constructed == ["sk-test-key-not-real"]


# --------------------------------------------------------------------------------------------- every endpoint
CHAT = f"{API}/ai/chat"
EMAIL = f"{API}/ai/generate-complaint-email"
ANALYZE = f"{API}/message/analyze"
JOB = f"{API}/message/check-job-offer"
SHOT = f"{API}/message/extract-screenshot"
FIR = f"{API}/video-call/generate-fir"
FIR_STREAM = f"{API}/video-call/generate-fir-stream"
DAILY = f"{API}/reports/daily"
FIR_BODY = {
    "incident_type": "fraud",
    "description": "private details",
    "incident_date": "2026-11-01",
    "incident_location": "Pune",
    "complainant_name": "Rae",
    "complainant_phone": "+919800000000",
}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


@pytest.fixture
def disabled(monkeypatch, sdk):
    set_switch(monkeypatch, "false")
    set_key(monkeypatch, "sk-test-key-not-real")  # a configured key must change nothing
    return sdk


async def test_coach_chat_is_unavailable_not_faked_and_stores_nothing(
    client, make_user, auth_headers, disabled, db
):
    u = await make_user("c")
    r = await client.post(
        CHAT, json={"message": "private question"}, headers=auth_headers(u)
    )
    assert r.status_code == 503
    assert r.headers.get("x-ai-status") == "disabled"
    assert "disabled" in r.json()["detail"].lower()
    assert disabled.calls == [] and disabled.constructed == []
    assert (
        await db.execute(select(func.count()).select_from(AiConversation))
    ).scalar_one() == 0


async def test_complaint_email_falls_back_to_the_local_template(
    client, make_user, auth_headers, disabled
):
    u = await make_user("e")
    r = await client.post(
        EMAIL,
        json={"incident_type": "fraud", "description": "private"},
        headers=auth_headers(u),
    )
    assert r.status_code == 200
    assert (
        "Dear Cybercrime Authority" in r.json()["body"]
    )  # deterministic template, not model output
    assert disabled.calls == [] and disabled.constructed == []


async def test_message_analysis_keeps_working_locally(
    client, make_user, auth_headers, disabled
):
    u = await make_user("m")
    body = {
        "message_text": "URGENT: your account is blocked, share your OTP now http://bit.ly/x",
        "use_ai": True,
    }
    r = await client.post(ANALYZE, json=body, headers=auth_headers(u))
    assert r.status_code == 200
    j = r.json()
    assert (
        j["risk_score"] > 0 and j["detected_patterns"]
    )  # the local pattern engine produced the verdict
    assert j["explanation"].startswith(
        "Pattern analysis"
    )  # not the canned "AI analysis unavailable"
    assert disabled.calls == [] and disabled.constructed == []
    off = await client.post(
        ANALYZE, json={**body, "use_ai": False}, headers=auth_headers(u)
    )
    assert off.status_code == 200 and off.json()["risk_score"] == j["risk_score"]


async def test_job_offer_check_keeps_working_locally(
    client, make_user, auth_headers, disabled
):
    u = await make_user("j")
    r = await client.post(
        JOB,
        json={
            "job_text": "Earn 50000 daily from home! Pay registration fee Rs 999 to confirm your job",
            "use_ai": True,
        },
        headers=auth_headers(u),
    )
    assert r.status_code == 200
    assert r.json()["red_flags"]
    assert disabled.calls == [] and disabled.constructed == []


async def test_screenshot_extraction_is_unavailable_not_a_500(
    client, make_user, auth_headers, disabled
):
    u = await make_user("s")
    r = await client.post(
        SHOT, files={"file": ("s.png", PNG, "image/png")}, headers=auth_headers(u)
    )
    assert r.status_code == 503 and r.headers.get("x-ai-status") == "disabled"
    assert disabled.calls == [] and disabled.constructed == []


async def test_fir_draft_uses_the_local_template(
    client, make_user, auth_headers, disabled
):
    u = await make_user("f")
    r = await client.post(FIR, json=FIR_BODY, headers=auth_headers(u))
    assert r.status_code == 200
    assert r.json().get("fir_draft")
    assert "disabled" in (r.json().get("note") or "").lower()  # says why, plainly
    assert disabled.calls == [] and disabled.constructed == []


async def test_fir_stream_never_reaches_the_provider(
    client, make_user, auth_headers, disabled
):
    u = await make_user("fs")
    r = await client.post(FIR_STREAM, json=FIR_BODY, headers=auth_headers(u))
    assert r.status_code == 200
    assert "disabled" in r.text.lower()
    assert disabled.calls == [] and disabled.constructed == []


async def test_daily_report_uses_default_tips(
    client, make_user, auth_headers, disabled
):
    u = await make_user("r")
    r = await client.get(DAILY, headers=auth_headers(u))
    assert r.status_code == 200
    assert disabled.calls == [] and disabled.constructed == []


async def test_a_declared_consent_does_not_open_the_switch(
    client, make_user, auth_headers, disabled
):
    """Interim rule: while the switch is off nothing is sent even for a user who granted the optional consent."""
    from app.database import AsyncSessionLocal
    from app.services import consent as cns

    u = await make_user("granted")
    async with AsyncSessionLocal() as s:
        cns.add_decision(s, u.id, cns.AI_PROCESSING, True, cns.SETTINGS)
        await s.commit()
    r = await client.post(CHAT, json={"message": "hello"}, headers=auth_headers(u))
    assert r.status_code == 503
    assert disabled.calls == []


async def test_enabled_chat_reaches_only_the_mock(
    client, make_user, auth_headers, monkeypatch, sdk
):
    set_switch(monkeypatch, "true")
    set_key(monkeypatch, "sk-test-key-not-real")
    u = await make_user("on")
    r = await client.post(CHAT, json={"message": "hello"}, headers=auth_headers(u))
    assert r.status_code == 200
    assert len(sdk.calls) == 1


def test_no_module_other_than_the_gateway_builds_a_provider_client():
    """Static guard: a new file that imports the SDK directly would bypass the switch."""
    import pathlib
    import re

    offenders = []
    root = pathlib.Path(__file__).resolve().parents[2] / "app"
    for f in root.rglob("*.py"):
        if f.name == "ai_service.py":
            continue
        if re.search(
            r"^\s*(import anthropic|from anthropic)",
            f.read_text(encoding="utf-8"),
            re.M,
        ):
            offenders.append(str(f))
    assert offenders == []
