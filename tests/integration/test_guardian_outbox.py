"""F19 Stage 2A: durable guardian-alert outbox (enqueue, lease, retry, expiry, audit, independence from history)."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, update

from app.models.app_install_event import AppInstallEvent
from app.models.elderly_config import ElderlyConfig
from app.models.guardian_outbox import (
    EXPIRED,
    FAILED,
    LEASED,
    PENDING,
    SENT,
    SKIPPED,
    GuardianAlertDelivery,
    GuardianAlertOutbox,
)
from app.services import guardian_alerts as rules
from tests.integration.conftest import verified_guardian_fields
from app.services import guardian_outbox as ob

pytestmark = pytest.mark.integration

URL = "/api/v1/app-monitor/sync"


@pytest.fixture(autouse=True)
def _quiet_worker(monkeypatch):
    async def _noop():
        return None

    monkeypatch.setattr(ob, "run_once_safe", _noop)


class Provider:
    """Recording stand-in for SMS/e-mail delivery (no network)."""

    def __init__(self, monkeypatch):
        self.sms: list[tuple[str, str]] = []
        self.email: list[tuple[str, str, str]] = []
        self.sms_ok = True
        self.email_ok = True
        self.raise_email = False

        async def send_sms(phone, body):
            self.sms.append((phone, body))
            return self.sms_ok

        async def send_email(to, subject, body):
            self.email.append((to, subject, body))
            if self.raise_email:
                raise RuntimeError("provider exploded")
            return self.email_ok

        from app.services import notifications

        monkeypatch.setattr(notifications, "send_sms", send_sms)
        monkeypatch.setattr(notifications, "send_email", send_email)


@pytest.fixture
def provider(monkeypatch):
    return Provider(monkeypatch)


async def setup_config(session_factory, user, **over):
    cfg = dict(
        enabled=True,
        guardian_email="guardian@example.com",
        guardian_phone="+919811100000",
        auto_alert_guardian=True,
        alert_threshold=0,
    )
    cfg.update(over)
    for k, v in verified_guardian_fields(
        cfg.get("guardian_email"), cfg.get("guardian_phone")
    ).items():
        cfg.setdefault(k, v)
    async with session_factory() as s:
        s.add(ElderlyConfig(user_id=user.id, **cfg))
        await s.commit()


def ev(pkg="com.risky", name="Risky", score=90, **over):
    d = {
        "package_name": pkg,
        "app_name": name,
        "event_type": "installed",
        "local_risk_score": score,
        "client_event_id": str(uuid.uuid4()),
        "occurred_at": int(time.time() * 1000),
    }
    d.update(over)
    return d


async def sync(client, h, *events):
    return await client.post(URL, json={"events": list(events)}, headers=h)


async def only_row(session_factory):
    async with session_factory() as s:
        return (await s.execute(select(GuardianAlertOutbox))).scalar_one()


async def run(session_factory, now=None, limit=10):
    async with session_factory() as s:
        return await ob.run_once(s, now=now, limit=limit)


async def setup_alert(client, make_user, auth_headers, session_factory, **cfg):
    u = await make_user("g")
    await setup_config(session_factory, u, **cfg)
    r = await sync(client, auth_headers(u), ev())
    assert r.json()["outcomes"][0]["guardian"]["status"] == "queued"
    return u


# ------------------------------------------------------------------------------------------------- shared rules
AUTH = dict(
    guardian_authorised_at=datetime(2026, 1, 1),
    guardian_notice_version="2026-11-14",
    guardian_email_verified_at=datetime(2026, 1, 1),
    guardian_email_verified_value="e",
    guardian_phone_verified_at=datetime(2026, 1, 1),
    guardian_phone_verified_value="x",
)


@pytest.mark.parametrize(
    "cfg, score, expected",
    [
        (None, 90, rules.SKIP_DISABLED),
        (
            SimpleNamespace(
                **AUTH,
                enabled=False,
                auto_alert_guardian=True,
                guardian_phone="x",
                guardian_email=None,
                alert_threshold=0,
            ),
            90,
            rules.SKIP_DISABLED,
        ),
        (
            SimpleNamespace(
                **AUTH,
                enabled=True,
                auto_alert_guardian=False,
                guardian_phone="x",
                guardian_email=None,
                alert_threshold=0,
            ),
            90,
            rules.SKIP_DISABLED,
        ),
        (
            SimpleNamespace(
                **AUTH,
                enabled=True,
                auto_alert_guardian=True,
                guardian_phone=None,
                guardian_email=None,
                alert_threshold=0,
            ),
            90,
            rules.SKIP_NO_CONTACT,
        ),
        (
            SimpleNamespace(
                **AUTH,
                enabled=True,
                auto_alert_guardian=True,
                guardian_phone=None,
                guardian_email="e",
                alert_threshold=50,
            ),
            49,
            rules.SKIP_BELOW_THRESHOLD,
        ),
        (
            SimpleNamespace(
                **AUTH,
                enabled=True,
                auto_alert_guardian=True,
                guardian_phone=None,
                guardian_email="e",
                alert_threshold=50,
            ),
            50,
            None,
        ),
    ],
)
def test_eligibility_rules(cfg, score, expected):
    assert rules.check_eligibility(cfg, score) == expected


def test_message_text_is_sanitised_and_states_the_time_when_known():
    m = rules.build_message(
        user_name="A\nB",
        guardian_name="G",
        app_name="x\x00y",
        risk_score=80,
        risk_level="danger",
        risk_tags=["t1", "t2"],
        clone_verdict="likely_clone",
        occurred_at=datetime(2026, 11, 1, 10, 30),
    )
    assert (
        "\x00" not in m
        and "A B" in m
        and "(at 2026-11-01 10:30 UTC)" in m
        and "Likely Clone" in m
    )
    assert "just installed" in rules.build_message(
        user_name="A",
        guardian_name=None,
        app_name="x",
        risk_score=1,
        risk_level="warning",
        risk_tags=[],
        clone_verdict=None,
    )


def test_backoff_grows_and_is_capped():
    s = [ob.backoff_seconds(n, jitter=0) for n in range(1, 9)]
    assert s[:4] == [60, 120, 240, 480] and max(s) == 3600


def test_worker_poll_setting(monkeypatch):
    monkeypatch.delenv("GUARDIAN_OUTBOX_POLL_SECONDS", raising=False)
    assert ob.poll_seconds_from_env() == 30
    monkeypatch.setenv("GUARDIAN_OUTBOX_POLL_SECONDS", "0")
    assert ob.poll_seconds_from_env() == 0
    monkeypatch.setenv("GUARDIAN_OUTBOX_POLL_SECONDS", "garbage")
    assert ob.poll_seconds_from_env() == 0  # unparsable disables rather than guessing


# ------------------------------------------------------------------------------------------------- enqueue at sync
async def test_sync_queues_one_alert_and_a_retry_does_not_queue_another(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("q")
    await setup_config(session_factory, u)
    h = auth_headers(u)
    e = ev()
    a = await sync(client, h, e)
    b = await sync(client, h, e)  # the device retried the same event
    assert a.json()["outcomes"][0]["guardian"]["status"] == "queued"
    assert b.json()["outcomes"][0]["status"] == "duplicate"
    assert (
        b.json()["outcomes"][0]["guardian"]["status"] == "pending"
    )  # the existing alert, not a new one
    async with session_factory() as s:
        assert (
            await s.execute(select(func.count()).select_from(GuardianAlertOutbox))
        ).scalar_one() == 1


@pytest.mark.parametrize(
    "cfg, reason",
    [
        ({"enabled": False}, "disabled"),
        ({"auto_alert_guardian": False}, "disabled"),
        ({"guardian_email": None, "guardian_phone": None}, "no_contact"),
        ({"alert_threshold": 100}, "below_threshold"),
    ],
)
async def test_ineligible_events_are_skipped_with_a_reason_and_queue_nothing(
    client, make_user, auth_headers, session_factory, cfg, reason
):
    u = await make_user("sk")
    await setup_config(session_factory, u, **cfg)
    r = await sync(client, auth_headers(u), ev(score=60))
    assert r.json()["outcomes"][0]["status"] == "created"  # history is unaffected
    assert r.json()["outcomes"][0]["guardian"] == {
        "status": "skipped",
        "reason": reason,
    }
    async with session_factory() as s:
        assert (
            await s.execute(select(func.count()).select_from(GuardianAlertOutbox))
        ).scalar_one() == 0


async def test_no_config_at_all_is_skipped(
    client, make_user, auth_headers, session_factory
):
    r = await sync(client, auth_headers(await make_user("nc")), ev())
    assert r.json()["outcomes"][0]["guardian"]["reason"] == "disabled"


async def test_removals_are_never_alerted(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("rm")
    await setup_config(session_factory, u)
    r = await sync(client, auth_headers(u), ev(event_type="removed"))
    assert r.json()["outcomes"][0]["guardian"]["status"] == "skipped"


async def test_events_older_than_the_ttl_are_not_alerted(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("old")
    await setup_config(session_factory, u)
    old = int((time.time() - 8 * 86400) * 1000)
    r = await sync(client, auth_headers(u), ev(occurred_at=old))
    assert r.json()["outcomes"][0]["status"] == "created"
    assert r.json()["outcomes"][0]["guardian"] == {
        "status": "expired",
        "reason": "too_old",
    }


# ------------------------------------------------------------------------------------------------- delivery
async def test_delivery_sends_once_audits_each_channel_and_is_not_repeated(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    out = await run(session_factory)
    assert out == {SENT: 1}
    assert len(provider.sms) == 1 and len(provider.email) == 1
    assert "(at " in provider.email[0][2]  # the message states when it happened
    row = await only_row(session_factory)
    assert (
        row.status == SENT
        and row.sent_at
        and row.channels_done == {"sms": True, "email": True}
    )
    assert row.lease_token is None
    async with session_factory() as s:
        audit = (await s.execute(select(GuardianAlertDelivery))).scalars().all()
    assert sorted((a.channel, a.result) for a in audit) == [
        ("email", "ok"),
        ("sms", "ok"),
    ]
    assert await run(session_factory) == {}  # nothing left to do
    assert len(provider.sms) == 1 and len(provider.email) == 1


async def test_the_audit_and_outbox_hold_no_contact_details(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    await run(session_factory)
    row = await only_row(session_factory)
    blob = str(row.payload) + str(row.last_error_code)
    assert "guardian@example.com" not in blob and "+919811100000" not in blob
    async with session_factory() as s:
        for a in (await s.execute(select(GuardianAlertDelivery))).scalars():
            assert "@" not in str(a.error_code) and "+91" not in str(a.error_code)


async def test_a_retry_only_resends_the_channel_that_failed(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    provider.email_ok = False
    now = datetime.utcnow()
    assert await run(session_factory, now=now) == {PENDING: 1}
    row = await only_row(session_factory)
    assert (
        row.channels_done == {"sms": True}
        and row.attempts == 1
        and row.last_error_code == "provider_failed"
    )
    assert row.next_attempt_at > now  # backed off
    provider.email_ok = True
    assert await run(
        session_factory, now=row.next_attempt_at + timedelta(seconds=1)
    ) == {SENT: 1}
    assert len(provider.sms) == 1, (
        "the channel that already succeeded must not be sent again"
    )
    assert len(provider.email) == 2


async def test_not_yet_due_rows_are_left_alone(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    provider.sms_ok = provider.email_ok = False
    now = datetime.utcnow()
    await run(session_factory, now=now)
    assert (
        await run(session_factory, now=now + timedelta(seconds=5)) == {}
    )  # still inside the backoff


async def test_attempts_are_exhausted_into_failed_with_a_full_audit(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    provider.sms_ok = provider.email_ok = False
    t = datetime.utcnow()
    for _ in range(ob.MAX_ATTEMPTS):
        await run(session_factory, now=t)
        t += timedelta(hours=2)
    row = await only_row(session_factory)
    assert (
        row.status == FAILED
        and row.attempts == ob.MAX_ATTEMPTS
        and row.last_error_code == "attempts_exhausted"
    )
    async with session_factory() as s:
        assert (
            await s.execute(select(func.count()).select_from(GuardianAlertDelivery))
        ).scalar_one() == 2 * ob.MAX_ATTEMPTS
    assert (
        await run(session_factory, now=t) == {}
    )  # a failed alert is never retried again


async def test_a_provider_exception_is_contained_and_recorded_by_type_only(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    provider.raise_email = True
    out = await run(session_factory)
    assert out == {PENDING: 1}  # sms succeeded, e-mail raised: no crash, retry later
    async with session_factory() as s:
        errs = [
            a.error_code
            for a in (await s.execute(select(GuardianAlertDelivery))).scalars()
            if a.result == "error"
        ]
    assert errs == ["RuntimeError"]


async def test_old_alerts_expire_instead_of_being_sent_late(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    out = await run(
        session_factory, now=datetime.utcnow() + ob.TTL + timedelta(hours=1)
    )
    assert out == {} and (await only_row(session_factory)).status == EXPIRED
    assert provider.sms == [] and provider.email == []


async def test_a_config_disabled_after_enqueue_is_respected_at_delivery(
    client, make_user, auth_headers, session_factory, provider
):
    u = await setup_alert(client, make_user, auth_headers, session_factory)
    async with session_factory() as s:
        await s.execute(
            update(ElderlyConfig)
            .where(ElderlyConfig.user_id == u.id)
            .values(enabled=False)
        )
        await s.commit()
    assert await run(session_factory) == {SKIPPED: 1}
    assert provider.sms == [] and provider.email == []
    assert (await only_row(session_factory)).last_error_code == "disabled"


async def test_the_durable_hourly_cap_defers_without_burning_an_attempt(
    client, make_user, auth_headers, session_factory, provider
):
    u = await setup_alert(client, make_user, auth_headers, session_factory)
    async with session_factory() as s:
        for i in range(ob.HOURLY_CAP):
            s.add(
                GuardianAlertOutbox(
                    user_id=u.id,
                    dedupe_key=f"x{i}",
                    payload={},
                    status=SENT,
                    attempts=1,
                    next_attempt_at=datetime.utcnow(),
                    channels_done={},
                    sent_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=1),
                )
            )
        await s.commit()
    assert await run(session_factory) == {PENDING: 1}
    async with session_factory() as s:
        row = (
            await s.execute(
                select(GuardianAlertOutbox).where(
                    GuardianAlertOutbox.dedupe_key.like("evt:%")
                )
            )
        ).scalar_one()
    assert (
        row.last_error_code == "rate_limited"
        and row.attempts == 0
        and provider.sms == []
    )


# ------------------------------------------------------------------------------------------------- leases and concurrency
async def seed(session_factory, user_id, n):
    async with session_factory() as s:
        for i in range(n):
            s.add(
                GuardianAlertOutbox(
                    user_id=user_id,
                    dedupe_key=f"d{i}",
                    payload={"app_name": "A", "risk_score": 90},
                    status=PENDING,
                    attempts=0,
                    next_attempt_at=datetime.utcnow() - timedelta(seconds=1),
                    channels_done={},
                    expires_at=datetime.utcnow() + timedelta(days=1),
                )
            )
        await s.commit()


async def test_concurrent_workers_never_claim_the_same_row(make_user, session_factory):
    u = await make_user("cc")
    await seed(session_factory, u.id, 12)

    async def worker():
        async with session_factory() as s:
            return [r.id for r in await ob.claim_due(s, limit=8)]

    a, b = await asyncio.gather(worker(), worker())
    assert not set(a) & set(b), "two workers leased the same alert"
    assert len(set(a) | set(b)) == 12 and len(a) + len(b) == 12


async def test_claimed_rows_carry_a_lease_and_count_the_attempt(
    make_user, session_factory
):
    u = await make_user("ls")
    await seed(session_factory, u.id, 1)
    async with session_factory() as s:
        (row,) = await ob.claim_due(s)
    assert (
        row.status == LEASED
        and row.lease_token
        and row.lease_expires_at > datetime.utcnow()
        and row.attempts == 1
    )


async def test_an_expired_lease_is_reclaimed_and_a_live_one_is_not(
    make_user, session_factory
):
    u = await make_user("lx")
    await seed(session_factory, u.id, 1)
    async with session_factory() as s:
        await ob.claim_due(s)
    async with session_factory() as s:
        assert await ob.claim_due(s) == []  # lease still valid: nobody else may take it
    async with session_factory() as s:
        again = await ob.claim_due(
            s, now=datetime.utcnow() + ob.LEASE + timedelta(seconds=5)
        )
    assert len(again) == 1 and again[0].attempts == 2


async def test_a_worker_that_lost_its_lease_cannot_overwrite_the_new_holder(
    make_user, session_factory
):
    u = await make_user("st")
    await seed(session_factory, u.id, 1)
    async with session_factory() as s:
        (first,) = await ob.claim_due(s)
    stale_token = first.lease_token
    async with session_factory() as s:
        (second,) = await ob.claim_due(
            s, now=datetime.utcnow() + ob.LEASE + timedelta(seconds=5)
        )
    assert second.lease_token != stale_token
    async with session_factory() as s:
        wrote = await ob._finalise(
            s, first, stale_token, status=SENT, now=datetime.utcnow()
        )
    assert wrote is False
    assert (
        await only_row(session_factory)
    ).status == LEASED  # the new holder's lease is intact


async def test_a_worker_that_dies_after_leasing_loses_nothing(
    client, make_user, auth_headers, session_factory, provider
):
    await setup_alert(client, make_user, auth_headers, session_factory)
    async with session_factory() as s:
        await ob.claim_due(s)  # leased, then "the process died": no send, no finalise
    assert await run(session_factory) == {}  # still leased: not stolen early
    out = await run(
        session_factory, now=datetime.utcnow() + ob.LEASE + timedelta(seconds=5)
    )
    assert out == {SENT: 1} and len(provider.email) == 1


async def test_concurrent_run_once_sends_each_alert_once(
    client, make_user, auth_headers, session_factory, provider
):
    u = await make_user("two")
    await setup_config(session_factory, u)
    h = auth_headers(u)
    await sync(client, h, *[ev(f"com.p{i}", f"P{i}") for i in range(6)])
    await asyncio.gather(run(session_factory), run(session_factory))
    assert len(provider.email) == 6 and len(provider.sms) == 6


# ------------------------------------------------------------------------------------------------- independence
async def test_guardian_failure_does_not_touch_history_and_history_retry_does_not_requeue(
    client, db, make_user, auth_headers, session_factory, provider
):
    u = await make_user("ind")
    await setup_config(session_factory, u)
    h = auth_headers(u)
    e = ev()
    await sync(client, h, e)
    provider.sms_ok = provider.email_ok = False
    await run(session_factory)
    assert (
        await db.execute(select(func.count()).select_from(AppInstallEvent))
    ).scalar_one() == 1
    again = await sync(client, h, e)
    assert again.json()["outcomes"][0]["status"] == "duplicate"
    async with session_factory() as s:
        assert (
            await s.execute(select(func.count()).select_from(GuardianAlertOutbox))
        ).scalar_one() == 1


async def test_cross_user_isolation_of_alerts(
    client, make_user, auth_headers, session_factory, provider
):
    a, b = await make_user("ia"), await make_user("ib")
    await setup_config(session_factory, a)
    await setup_config(
        session_factory, b, guardian_email="other@example.com", guardian_phone=None
    )
    await sync(client, auth_headers(a), ev())
    await sync(client, auth_headers(b), ev())
    await run(session_factory)
    assert sorted(e[0] for e in provider.email) == [
        "guardian@example.com",
        "other@example.com",
    ]
    assert [p[0] for p in provider.sms] == ["+919811100000"]  # only user a had a phone


async def test_the_legacy_guardian_endpoint_still_works_with_the_shared_rules(
    client, make_user, auth_headers, session_factory, provider
):
    u = await make_user("lg")
    await setup_config(session_factory, u)
    r = await client.post(
        "/api/v1/elderly/guardian-alert",
        headers=auth_headers(u),
        json={
            "package_name": "com.x",
            "app_name": "X",
            "risk_score": 90,
            "risk_level": "danger",
        },
    )
    assert r.status_code == 202 and r.json()["status"] == "queued"
    off = await client.post(
        "/api/v1/elderly/guardian-alert",
        headers=auth_headers(u),
        json={
            "package_name": "com.x",
            "app_name": "X",
            "risk_score": 90,
            "risk_level": "danger",
        },
    )
    assert off.status_code == 202


@pytest.fixture(autouse=True)
def _retention_enabled(monkeypatch):
    """Stage 1.1: retention deletes only when RETENTION_CLEANUP_ENABLED=true (and the identity is valid). These tests exercise
    the delete behaviour itself, so they enable it explicitly; the blocked paths are covered in tests/unit/test_retention_gate.py."""
    from app import config

    monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", "true")
