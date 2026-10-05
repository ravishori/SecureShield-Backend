"""AI Coach: ownership of conversations, history window, non-blocking calls, safe errors,
per-user rate limit and input bounds. The Anthropic client is a recording fake (no network);
what the service WOULD send to the model is inspected."""

import asyncio
import time
import uuid
from types import SimpleNamespace

import pytest

from app.models.ai_conversation import AiConversation, ConversationRole

pytestmark = pytest.mark.integration

CHAT = "/api/v1/ai/chat"
HIST = "/api/v1/ai/history/{}"
EMAIL = "/api/v1/ai/generate-complaint-email"


class FakeAnthropic:
    def __init__(self, text="Stay safe: never share OTPs.", delay=0.0, error=None):
        self.calls, self.text, self.delay, self.error = [], text, delay, error
        self.messages = self

    async def create(self, **kw):
        self.calls.append(kw)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return SimpleNamespace(content=[SimpleNamespace(text=self.text)])


@pytest.fixture
def fake(monkeypatch):
    f = FakeAnthropic()
    monkeypatch.setattr("app.services.ai_service.get_async_client", lambda: f)
    return f


def sent_texts(fake_client):
    return [m["content"] for call in fake_client.calls for m in call["messages"]]


async def test_chat_persists_both_turns_and_history_returns_them_to_the_owner(
    client, db, make_user, auth_headers, fake
):
    u = await make_user("coach")
    r = await client.post(
        CHAT,
        headers=auth_headers(u),
        json={"message": "Is this SMS a scam?", "topic_category": "sms"},
    )
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]
    assert r.json()["reply"] == fake.text
    h = (await client.get(HIST.format(sid), headers=auth_headers(u))).json()
    assert [(m["role"], m["content"]) for m in h] == [
        ("user", "Is this SMS a scam?"),
        ("assistant", fake.text),
    ]


async def test_another_users_session_id_grants_no_access(
    client, db, make_user, auth_headers, fake
):
    """Regression (IDOR): history used to be loaded by session_id alone."""
    alice, mallory = await make_user("alice"), await make_user("mallory")
    a = await client.post(
        CHAT,
        headers=auth_headers(alice),
        json={"message": "My bank PIN story ALICE-SECRET-123"},
    )
    sid = a.json()["session_id"]
    fake.calls.clear()
    m = await client.post(
        CHAT,
        headers=auth_headers(mallory),
        json={"session_id": sid, "message": "hello"},
    )
    assert m.status_code == 200
    assert not any("ALICE-SECRET-123" in t for t in sent_texts(fake)), (
        "another user's turns reached the model"
    )
    # reading the foreign session returns nothing, and Alice's history is untouched by Mallory
    assert (
        await client.get(HIST.format(sid), headers=auth_headers(mallory))
    ).json() == [] or all(
        x["content"] != "My bank PIN story ALICE-SECRET-123"
        for x in (
            await client.get(HIST.format(sid), headers=auth_headers(mallory))
        ).json()
    )
    alice_hist = (
        await client.get(HIST.format(sid), headers=auth_headers(alice))
    ).json()
    assert [x["content"] for x in alice_hist if x["role"] == "user"] == [
        "My bank PIN story ALICE-SECRET-123"
    ]


async def test_history_endpoint_rejects_invalid_ids_without_a_500(
    client, make_user, auth_headers, fake
):
    u = await make_user("badid")
    assert (
        await client.get(HIST.format("not-a-uuid"), headers=auth_headers(u))
    ).status_code == 404
    assert (
        await client.get(HIST.format(uuid.uuid4()), headers=auth_headers(u))
    ).json() == []


async def test_model_context_is_the_latest_20_turns_not_the_oldest(
    client, db, make_user, auth_headers, fake, session_factory
):
    u = await make_user("long")
    sid = uuid.uuid4()
    base = time.time() - 3600
    import datetime as dt

    async with session_factory() as s:
        for i in range(30):
            s.add(
                AiConversation(
                    user_id=u.id,
                    session_id=sid,
                    role=ConversationRole.user
                    if i % 2 == 0
                    else ConversationRole.assistant,
                    content=f"turn-{i:02d}",
                    created_at=dt.datetime.utcfromtimestamp(base + i),
                )
            )
        await s.commit()
    await client.post(
        CHAT,
        headers=auth_headers(u),
        json={"session_id": str(sid), "message": "newest"},
    )
    sent = sent_texts(fake)
    assert (
        "turn-29" in sent
        and "turn-10" in sent
        and "turn-09" not in sent
        and "turn-00" not in sent
    )
    assert sent[-1] == "newest" and len(sent) == 21


async def test_ai_calls_do_not_block_the_event_loop(
    client, make_user, auth_headers, monkeypatch
):
    """Five concurrent chats of 0.4 s each must overlap (the old sync client serialised them and
    froze every other request while waiting)."""
    f = FakeAnthropic(delay=0.4)
    monkeypatch.setattr("app.services.ai_service.get_async_client", lambda: f)
    users = [await make_user(f"c{i}") for i in range(5)]
    t0 = time.perf_counter()
    rs = await asyncio.gather(
        *[
            client.post(CHAT, headers=auth_headers(u), json={"message": "hi"})
            for u in users
        ]
    )
    elapsed = time.perf_counter() - t0
    assert all(r.status_code == 200 for r in rs)
    assert elapsed < 1.4, f"calls were serialised ({elapsed:.2f}s for 5 x 0.4s)"


@pytest.mark.security
async def test_provider_failures_show_users_a_generic_message_only(
    client, make_user, auth_headers, monkeypatch, caplog
):
    secret_error = RuntimeError(
        "Your credit balance is too low. Invalid x-api-key sk-ant-api03-LEAKYLEAKYLEAKY1234 "
        "see console.anthropic.com ANTHROPIC_API_KEY"
    )
    f = FakeAnthropic(error=secret_error)
    monkeypatch.setattr("app.services.ai_service.get_async_client", lambda: f)
    u = await make_user("err")
    r = await client.post(
        CHAT, headers=auth_headers(u), json={"message": "help", "language": "hi"}
    )
    assert r.status_code == 200
    reply = r.json()["reply"]
    for leak in (
        "ANTHROPIC_API_KEY",
        "console.anthropic.com",
        "credit",
        "sk-ant",
        "x-api-key",
        "RuntimeError",
    ):
        assert leak.lower() not in reply.lower(), f"{leak!r} reached the end user"
    assert "unavailable" in reply.lower() or "उपलब्ध" in reply
    assert "LEAKYLEAKY" not in caplog.text  # nor the logs
    assert "RuntimeError" in caplog.text  # but the failure TYPE is logged for operators


async def test_per_user_rate_limit_with_retry_after(
    client, make_user, auth_headers, fake, monkeypatch
):
    from app.config import settings

    monkeypatch.setattr(settings, "AI_REQUESTS_PER_MINUTE", 3)
    a, b = await make_user("rl-a"), await make_user("rl-b")
    codes = [
        (
            await client.post(CHAT, headers=auth_headers(a), json={"message": "q"})
        ).status_code
        for _ in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]
    r = await client.post(CHAT, headers=auth_headers(a), json={"message": "q"})
    assert r.headers.get("retry-after") == "60"
    assert (
        await client.post(CHAT, headers=auth_headers(b), json={"message": "q"})
    ).status_code == 200  # per user, not global
    assert len(fake.calls) == 4  # throttled requests never reached the model


@pytest.mark.parametrize(
    "body",
    [
        {"message": ""},
        {"message": "   "},
        {"message": "x" * 4001},
        {},
        {"message": "ok", "language": "english-us-long"},
        {"message": "ok", "language": "h!"},
        {"message": "ok", "topic_category": "t" * 65},
    ],
)
async def test_chat_input_is_bounded(client, make_user, auth_headers, fake, body):
    u = await make_user("val")
    assert (
        await client.post(CHAT, headers=auth_headers(u), json=body)
    ).status_code == 422
    assert fake.calls == []


async def test_valid_inputs_at_the_limits_are_accepted(
    client, make_user, auth_headers, fake
):
    u = await make_user("lim")
    for body in (
        {"message": "x" * 4000},
        {"message": "ok", "language": "hi"},
        {"message": "ok", "language": "pt-BR"},
        {"message": "ok", "topic_category": "t" * 64},
    ):
        assert (
            await client.post(CHAT, headers=auth_headers(u), json=body)
        ).status_code == 200


async def test_complaint_email_inputs_bounded_rate_limited_and_authenticated(
    client, make_user, auth_headers, monkeypatch
):
    from app.config import settings

    async def fake_email(**kw):
        return {"subject": "s", "body": "b", "email": "b", "to_addresses": []}

    monkeypatch.setattr("app.routers.ai_coach.generate_complaint_email", fake_email)
    u = await make_user("mail")
    ok = {"incident_type": "upi_fraud", "description": "I was tricked"}
    assert (
        await client.post(EMAIL, headers=auth_headers(u), json=ok)
    ).status_code == 200
    assert (
        await client.post(
            EMAIL, headers=auth_headers(u), json={**ok, "description": "x" * 4001}
        )
    ).status_code == 422
    assert (
        await client.post(
            EMAIL, headers=auth_headers(u), json={**ok, "incident_type": ""}
        )
    ).status_code == 422
    assert (await client.post(EMAIL, json=ok)).status_code in (401, 403)
    monkeypatch.setattr(settings, "AI_REQUESTS_PER_MINUTE", 1)
    assert (
        await client.post(EMAIL, headers=auth_headers(u), json=ok)
    ).status_code == 429


async def test_chat_requires_authentication(client, fake):
    assert (await client.post(CHAT, json={"message": "hi"})).status_code in (401, 403)
    assert fake.calls == []
