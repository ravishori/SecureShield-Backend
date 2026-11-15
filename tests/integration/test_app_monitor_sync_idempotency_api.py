"""F19 Stage 2A: idempotent, race-safe, per-event-outcome sync (old clients keep working)."""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from sqlalchemy import func, select

from app.models.app_install_event import AppInstallEvent
from app.models.guardian_outbox import GuardianAlertOutbox
from app.services import guardian_outbox
from tests.integration.conftest import delete_body, verified_guardian_fields

pytestmark = pytest.mark.integration

URL = "/api/v1/app-monitor/sync"


@pytest.fixture(autouse=True)
def _no_immediate_worker(monkeypatch):
    """The immediate best-effort worker run would race the assertions; the outbox is exercised explicitly elsewhere."""

    async def _noop():
        return None

    monkeypatch.setattr(guardian_outbox, "run_once_safe", _noop)


def now_ms(offset_s: int = 0) -> int:
    return int((time.time() + offset_s) * 1000)


def ev(pkg="com.example.app", name="Example", **over):
    d = {
        "package_name": pkg,
        "app_name": name,
        "event_type": "installed",
        "local_risk_score": 10,
    }
    d.update(over)
    return d


async def sync(client, headers, *events):
    return await client.post(URL, json={"events": list(events)}, headers=headers)


async def count_events(db, user_id=None):
    q = select(func.count()).select_from(AppInstallEvent)
    if user_id is not None:
        q = q.where(AppInstallEvent.user_id == user_id)
    return (await db.execute(q)).scalar_one()


async def test_a_retry_with_the_same_client_event_id_stores_one_event(
    client, db, make_user, auth_headers
):
    u = await make_user("a")
    h = auth_headers(u)
    cid = str(uuid.uuid4())
    first = await sync(client, h, ev(client_event_id=cid, occurred_at=now_ms()))
    again = await sync(client, h, ev(client_event_id=cid, occurred_at=now_ms()))
    assert first.json()["outcomes"][0]["status"] == "created"
    d = again.json()["outcomes"][0]
    assert d["status"] == "duplicate" and d["id"] == first.json()["outcomes"][0]["id"]
    assert again.json()["synced"] == 0 and again.json()["results"] == []
    assert await count_events(db, u.id) == 1


async def test_outcomes_are_ordered_per_event_and_a_bad_event_does_not_fail_the_batch(
    client, db, make_user, auth_headers
):
    h = auth_headers(await make_user("m"))
    dup = str(uuid.uuid4())
    await sync(client, h, ev("com.dup", "Dup", client_event_id=dup))
    r = await sync(
        client,
        h,
        ev("com.one", "One", client_event_id=str(uuid.uuid4())),
        ev("com.dup", "Dup", client_event_id=dup),
        {
            "package_name": "",
            "app_name": "x",
            "client_event_id": str(uuid.uuid4()),
        },  # invalid
        ev("com.two", "Two", client_event_id=str(uuid.uuid4())),
    )
    assert r.status_code == 200
    out = r.json()["outcomes"]
    assert [o["index"] for o in out] == [0, 1, 2, 3]
    assert [o["status"] for o in out] == ["created", "duplicate", "rejected", "created"]
    assert out[2]["reason"] == "invalid_payload" and out[2]["fields"] == [
        "package_name"
    ]
    assert (
        r.json()["synced"] == 2 and len(r.json()["results"]) == 2
    )  # old fields: created only


async def test_an_implausible_timestamp_is_rejected_alone(
    client, db, make_user, auth_headers
):
    h = auth_headers(await make_user("t"))
    r = await sync(
        client,
        h,
        ev("com.bad", "Bad", occurred_at=5),
        ev("com.ok", "Ok", occurred_at=now_ms()),
    )
    out = r.json()["outcomes"]
    assert (out[0]["status"], out[0]["reason"]) == ("rejected", "bad_timestamp")
    assert out[1]["status"] == "created"


async def test_concurrent_identical_syncs_create_exactly_one_event(
    client, db, make_user, auth_headers
):
    u = await make_user("race")
    h = auth_headers(u)
    cid = str(uuid.uuid4())
    body = ev(client_event_id=cid, occurred_at=now_ms())
    rs = await asyncio.gather(*[sync(client, h, body) for _ in range(10)])
    statuses = sorted(r.json()["outcomes"][0]["status"] for r in rs)
    assert statuses.count("created") == 1 and statuses.count("duplicate") == 9, statuses
    assert await count_events(db, u.id) == 1


async def test_two_updates_of_the_same_app_are_both_kept(
    client, db, make_user, auth_headers
):
    """Regression: the old rule keyed on first_install_time, so a second update was silently dropped."""
    u = await make_user("up")
    h = auth_headers(u)
    base = dict(event_type="updated", first_install_time=1_700_000_000_000)
    r = await sync(
        client,
        h,
        ev(**base, client_event_id=str(uuid.uuid4()), occurred_at=now_ms(-100)),
        ev(**base, client_event_id=str(uuid.uuid4()), occurred_at=now_ms(-50)),
    )
    assert [o["status"] for o in r.json()["outcomes"]] == ["created", "created"]
    assert await count_events(db, u.id) == 2


async def test_legacy_clients_without_ids_keep_working(
    client, db, make_user, auth_headers
):
    u = await make_user("leg")
    h = auth_headers(u)
    # a fresh install is still de-duplicated by first_install_time (old behaviour, kept)
    a = await sync(client, h, ev("com.l", "L", first_install_time=1_700_000_000_000))
    b = await sync(client, h, ev("com.l", "L", first_install_time=1_700_000_000_000))
    assert a.json()["synced"] == 1 and b.json()["synced"] == 0
    assert b.json()["outcomes"][0]["status"] == "duplicate"
    # legacy updates: distinct observation times are distinct events, the same time is a retry
    t1, t2 = now_ms(-200), now_ms(-100)
    base = dict(event_type="updated", first_install_time=1_700_000_000_000)
    r1 = await sync(client, h, ev("com.l", "L", **base, client_timestamp=t1))
    r2 = await sync(client, h, ev("com.l", "L", **base, client_timestamp=t2))
    r3 = await sync(
        client, h, ev("com.l", "L", **base, client_timestamp=t1)
    )  # retry of the first
    assert [r.json()["synced"] for r in (r1, r2, r3)] == [1, 1, 0]
    assert r3.json()["outcomes"][0]["status"] == "duplicate"
    # legacy updates with neither id nor time cannot be matched, so real events are never dropped
    r4 = await sync(client, h, ev("com.l", "L", **base))
    r5 = await sync(client, h, ev("com.l", "L", **base))
    assert r4.json()["synced"] == 1 and r5.json()["synced"] == 1


async def test_legacy_retries_are_race_safe_too(client, db, make_user, auth_headers):
    u = await make_user("legrace")
    h = auth_headers(u)
    body = ev("com.r", "R", event_type="updated", client_timestamp=now_ms(-10))
    rs = await asyncio.gather(*[sync(client, h, body) for _ in range(8)])
    assert sum(r.json()["synced"] for r in rs) == 1
    assert await count_events(db, u.id) == 1


async def test_the_same_client_event_id_for_two_users_is_two_events(
    client, db, make_user, auth_headers
):
    a, b = await make_user("ua"), await make_user("ub")
    cid = str(uuid.uuid4())
    ra = await sync(client, auth_headers(a), ev(client_event_id=cid))
    rb = await sync(client, auth_headers(b), ev(client_event_id=cid))
    assert (
        ra.json()["outcomes"][0]["status"]
        == rb.json()["outcomes"][0]["status"]
        == "created"
    )
    assert await count_events(db) == 2


async def test_old_response_fields_keep_their_meaning(client, make_user, auth_headers):
    h = auth_headers(await make_user("old"))
    r = await sync(client, h, ev("com.x", "X"))
    j = r.json()
    assert {"synced", "results", "outcomes"} <= set(j)
    assert j["synced"] == 1 and j["results"][0]["package_name"] == "com.x"
    assert {"id", "risk_level", "server_risk_score", "synced_at"} <= set(
        j["results"][0]
    )


# ---------------------------------------------------------------------------------------------- 401 / 422 / 429 / 5xx
async def test_unauthenticated_sync_is_401_and_stores_nothing(client, db):
    r = await client.post(URL, json={"events": [ev()]})
    assert r.status_code in (401, 403)
    assert await count_events(db) == 0


async def test_structural_errors_are_422(client, make_user, auth_headers):
    h = auth_headers(await make_user("s"))
    assert (
        await client.post(URL, json={"events": "nope"}, headers=h)
    ).status_code == 422
    assert (await client.post(URL, json={}, headers=h)).status_code == 422
    assert (
        await sync(client, h, *[ev(f"com.p{i}", "n") for i in range(51)])
    ).status_code == 422


async def test_sync_is_rate_limited_with_retry_after(client, make_user, auth_headers):
    h = auth_headers(await make_user("rl"))
    codes = [(await sync(client, h)).status_code for _ in range(62)]
    assert codes[:60] == [200] * 60 and codes[60] == 429
    r = await sync(client, h)
    assert r.status_code == 429 and r.headers.get("retry-after") == "60"


async def test_a_server_error_rolls_the_whole_batch_back_and_the_retry_is_safe(
    client, db, make_user, auth_headers, monkeypatch
):
    u = await make_user("boom")
    h = auth_headers(u)
    cfg_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    batch = [
        ev("com.a", "A", client_event_id=cfg_ids[0]),
        ev("com.b", "B", client_event_id=cfg_ids[1]),
    ]
    import app.routers.app_monitor as router

    calls = {"n": 0}
    real = router.analyze_clone

    def flaky(**kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated failure on the second event")
        return real(**kw)

    monkeypatch.setattr(router, "analyze_clone", flaky)
    r = await sync(client, h, *batch)
    assert r.status_code == 500
    assert (
        await count_events(db, u.id) == 0
    )  # the first event was rolled back with the rest
    monkeypatch.setattr(router, "analyze_clone", real)
    ok = await sync(client, h, *batch)
    assert [o["status"] for o in ok.json()["outcomes"]] == ["created", "created"]
    again = await sync(client, h, *batch)
    assert [o["status"] for o in again.json()["outcomes"]] == ["duplicate", "duplicate"]
    assert await count_events(db, u.id) == 2


# ---------------------------------------------------------------------------------------------- account erasure
async def test_account_erasure_removes_events_outbox_and_delivery_audit(
    client, db, make_user, auth_headers, session_factory
):
    from app.models.elderly_config import ElderlyConfig
    from app.models.guardian_outbox import GuardianAlertDelivery

    u = await make_user("gone", email="gone-sync@example.com")
    h = auth_headers(u)
    async with session_factory() as s:
        s.add(
            ElderlyConfig(
                user_id=u.id,
                enabled=True,
                guardian_email="g@example.com",
                alert_threshold=0,
                **verified_guardian_fields("g@example.com"),
            )
        )
        await s.commit()
    r = await sync(
        client,
        h,
        ev(
            "com.risky", "Risky", client_event_id=str(uuid.uuid4()), local_risk_score=90
        ),
    )
    assert r.json()["outcomes"][0]["guardian"]["status"] == "queued"
    async with session_factory() as s:
        row = (await s.execute(select(GuardianAlertOutbox))).scalar_one()
        from app.models.guardian_outbox import GuardianAlertDelivery as D

        s.add(D(outbox_id=row.id, attempt_no=1, channel="email", result="ok"))
        await s.commit()
    d = await client.request(
        "DELETE", "/api/v1/auth/me", headers=h, json=await delete_body(h)
    )
    assert d.status_code == 200, d.text
    for model in (AppInstallEvent, GuardianAlertOutbox, GuardianAlertDelivery):
        assert (
            await db.execute(select(func.count()).select_from(model))
        ).scalar_one() == 0


async def test_deleting_an_event_keeps_its_alert(
    client, db, make_user, auth_headers, session_factory
):
    from app.models.elderly_config import ElderlyConfig

    u = await make_user("keep")
    h = auth_headers(u)
    async with session_factory() as s:
        s.add(
            ElderlyConfig(
                user_id=u.id,
                enabled=True,
                guardian_email="g@example.com",
                alert_threshold=0,
                **verified_guardian_fields("g@example.com"),
            )
        )
        await s.commit()
    r = await sync(
        client,
        h,
        ev("com.k", "K", client_event_id=str(uuid.uuid4()), local_risk_score=80),
    )
    event_id = r.json()["outcomes"][0]["id"]
    assert (
        await client.delete(f"/api/v1/app-monitor/{event_id}", headers=h)
    ).status_code == 204
    row = (await db.execute(select(GuardianAlertOutbox))).scalar_one()
    await db.refresh(row)
    assert (
        row.event_id is None and row.status == "pending"
    )  # the alert survives the history record
