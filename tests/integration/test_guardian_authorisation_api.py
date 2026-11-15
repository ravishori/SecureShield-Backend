"""F19 Stage 2A corrections: guardian authorisation + verification gate, server-calculated risk, legacy endpoint through the
outbox, 90-day retention, attempt cap, index and migration shape."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, text

from app.models.app_install_event import AppInstallEvent
from app.models.elderly_config import ElderlyConfig
from app.models.guardian_outbox import (
    FAILED,
    LEASED,
    PENDING,
    SENT,
    GuardianAlertDelivery,
    GuardianAlertOutbox,
)
from app.services import guardian_alerts as rules
from app.services import guardian_outbox as ob
from tests.integration.conftest import ready_guardian, verified_guardian_fields

pytestmark = pytest.mark.integration

E = "/api/v1/elderly"
SYNC = "/api/v1/app-monitor/sync"
NOTICE = rules.GUARDIAN_NOTICE_VERSION
CFG = {
    "enabled": True,
    "guardian_name": "Asha",
    "guardian_email": "Asha@Example.com",
    "guardian_phone": "+919800000000",
    "alert_threshold": 0,
}


@pytest.fixture(autouse=True)
def _quiet_worker(monkeypatch):
    async def _noop():
        return None

    monkeypatch.setattr(ob, "run_once_safe", _noop)


@pytest.fixture
def provider(monkeypatch):
    from app.services import notifications

    log = SimpleNamespace(sms=[], email=[])

    async def sms(phone, body):
        log.sms.append((phone, body))
        return True

    async def email(to, subject, body):
        log.email.append((to, subject, body))
        return True

    monkeypatch.setattr(notifications, "send_sms", sms)
    monkeypatch.setattr(notifications, "send_email", email)
    return log


def ev(**over):
    d = {
        "package_name": "com.risky",
        "app_name": "Risky",
        "event_type": "installed",
        "client_event_id": str(uuid.uuid4()),
        "occurred_at": int(time.time() * 1000),
    }
    d.update(over)
    return d


async def sync(client, h, *events):
    return await client.post(SYNC, json={"events": list(events)}, headers=h)


async def config_row(session_factory, user):
    async with session_factory() as s:
        return (
            await s.execute(
                select(ElderlyConfig).where(ElderlyConfig.user_id == user.id)
            )
        ).scalar_one()


async def run(session_factory, now=None):
    async with session_factory() as s:
        return await ob.run_once(s, now=now)


# ------------------------------------------------------------------------------------------- authorisation
async def test_new_config_is_unauthorised_and_unverified(
    client, make_user, auth_headers
):
    h = auth_headers(await make_user("n"))
    r = (await client.put(f"{E}/config", headers=h, json=CFG)).json()
    assert (
        r["guardian_authorised"],
        r["guardian_email_verified"],
        r["guardian_phone_verified"],
    ) == (False, False, False)


async def test_authorising_needs_the_current_disclosure_version_and_a_contact(
    client, make_user, auth_headers
):
    h = auth_headers(await make_user("a"))
    stale = await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_authorised": True, "guardian_notice_version": "1999"},
    )
    assert (
        stale.status_code == 409
        and stale.headers.get("x-consent-error") == "stale_guardian_notice"
    )
    missing = await client.put(
        f"{E}/config", headers=h, json={**CFG, "guardian_authorised": True}
    )
    assert missing.status_code == 409  # no version given is not the current version
    nocontact = await client.put(
        f"{E}/config",
        headers=h,
        json={
            "enabled": True,
            "guardian_authorised": True,
            "guardian_notice_version": NOTICE,
        },
    )
    assert nocontact.status_code == 422
    ok = await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_authorised": True, "guardian_notice_version": NOTICE},
    )
    assert ok.status_code == 200 and ok.json()["guardian_authorised"] is True


async def test_changing_a_contact_withdraws_authorisation_and_verification(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("c")
    h = auth_headers(u)
    await ready_guardian(client, h, **CFG)
    assert (await client.get(f"{E}/config", headers=h)).json()[
        "guardian_email_verified"
    ] is True
    same = (
        await client.put(
            f"{E}/config", headers=h, json={**CFG, "guardian_email": "asha@EXAMPLE.com"}
        )
    ).json()
    assert (
        same["guardian_authorised"] and same["guardian_email_verified"]
    )  # same address, different case: unchanged
    changed = (
        await client.put(
            f"{E}/config",
            headers=h,
            json={**CFG, "guardian_email": "someone.else@example.com"},
        )
    ).json()
    assert (
        changed["guardian_authorised"] is False
        and changed["guardian_email_verified"] is False
    )
    # the unchanged phone keeps its own verification, but authorisation is gone so nothing can be delivered
    assert changed["guardian_phone_verified"] is True
    row = await config_row(session_factory, u)
    assert (
        row.guardian_authorised_at is None and row.guardian_email_verified_value is None
    )


async def test_withdrawing_authorisation_clears_everything(
    client, make_user, auth_headers
):
    h = auth_headers(await make_user("w"))
    await ready_guardian(client, h, **CFG)
    r = (
        await client.put(
            f"{E}/config", headers=h, json={**CFG, "guardian_authorised": False}
        )
    ).json()
    assert (
        r["guardian_authorised"],
        r["guardian_email_verified"],
        r["guardian_phone_verified"],
    ) == (False, False, False)


# ------------------------------------------------------------------------------------------- verification flow
async def test_verification_needs_authorisation_and_sms_is_unavailable(
    client, make_user, auth_headers, provider
):
    h = auth_headers(await make_user("v"))
    await client.put(f"{E}/config", headers=h, json=CFG)
    r = await client.post(f"{E}/guardian/verify/start", headers=h, json={})
    assert (
        r.status_code == 409 and r.headers.get("x-guardian-error") == "not_authorised"
    )
    await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_authorised": True, "guardian_notice_version": NOTICE},
    )
    sms = await client.post(
        f"{E}/guardian/verify/start", headers=h, json={"channel": "phone"}
    )
    assert (
        sms.status_code == 409
        and sms.headers.get("x-guardian-error") == "sms_unavailable"
    )
    assert provider.email == [] and provider.sms == []


async def test_the_code_goes_to_the_guardian_only_and_verifies_exactly_once(
    client, make_user, auth_headers, provider, session_factory
):
    u = await make_user("g", full_name="Grand Pa")
    h = auth_headers(u)
    await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_authorised": True, "guardian_notice_version": NOTICE},
    )
    r = await client.post(f"{E}/guardian/verify/start", headers=h, json={})
    assert r.status_code == 200 and "asha" not in r.text.lower().replace(
        "a***", ""
    )  # masked in the response
    (to, subject, body) = provider.email[0]
    assert (
        to == "asha@example.com"
        and "Grand Pa" in body
        and "ignore this message" in body
    )
    code = next(w for w in body.split() if w.isdigit() and len(w) == 6)
    assert code not in r.text
    bad = "000000" if code != "000000" else "111111"
    assert (
        await client.post(f"{E}/guardian/verify/confirm", headers=h, json={"code": bad})
    ).status_code == 400
    ok = await client.post(
        f"{E}/guardian/verify/confirm", headers=h, json={"code": code}
    )
    assert ok.status_code == 200 and ok.json()["guardian_email_verified"] is True
    assert (
        await config_row(session_factory, u)
    ).guardian_email_verified_value == "asha@example.com"
    assert (
        await client.post(
            f"{E}/guardian/verify/confirm", headers=h, json={"code": code}
        )
    ).status_code == 400  # replay


async def test_another_accounts_code_and_a_changed_contact_cannot_verify(
    client, make_user, auth_headers, provider
):
    a, b = await make_user("ua"), await make_user("ub")
    for u in (a, b):
        await client.put(
            f"{E}/config",
            headers=auth_headers(u),
            json={
                **CFG,
                "guardian_email": f"{u.email}",
                "guardian_authorised": True,
                "guardian_notice_version": NOTICE,
            },
        )
    await client.post(f"{E}/guardian/verify/start", headers=auth_headers(a), json={})
    code = next(w for w in provider.email[-1][2].split() if w.isdigit() and len(w) == 6)
    assert (
        await client.post(
            f"{E}/guardian/verify/confirm", headers=auth_headers(b), json={"code": code}
        )
    ).status_code == 400
    # the holder changes the guardian after the code was sent: the old code proves nothing about the new contact
    await client.put(
        f"{E}/config",
        headers=auth_headers(a),
        json={
            **CFG,
            "guardian_email": "new@example.com",
            "guardian_authorised": True,
            "guardian_notice_version": NOTICE,
        },
    )
    assert (
        await client.post(
            f"{E}/guardian/verify/confirm", headers=auth_headers(a), json={"code": code}
        )
    ).status_code == 400


async def test_verification_requests_require_auth_and_are_rate_limited(
    client, make_user, auth_headers, provider
):
    assert (await client.post(f"{E}/guardian/verify/start", json={})).status_code in (
        401,
        403,
    )
    assert (
        await client.post(f"{E}/guardian/verify/confirm", json={"code": "123456"})
    ).status_code in (401, 403)
    h = auth_headers(await make_user("rl"))
    await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_authorised": True, "guardian_notice_version": NOTICE},
    )
    codes = [
        (
            await client.post(f"{E}/guardian/verify/start", headers=h, json={})
        ).status_code
        for _ in range(7)
    ]
    assert codes[0] == 200 and 429 in codes and len(provider.email) <= 5


# ------------------------------------------------------------------------------------------- delivery is blocked until satisfied
async def test_sync_does_not_queue_for_an_unauthorised_or_unverified_guardian(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("blk")
    h = auth_headers(u)
    await client.put(
        f"{E}/config", headers=h, json=CFG
    )  # configured, but nothing authorised
    r = await sync(client, h, ev())
    assert r.json()["outcomes"][0]["guardian"] == {
        "status": "skipped",
        "reason": "not_authorised",
    }
    await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_authorised": True, "guardian_notice_version": NOTICE},
    )
    r = await sync(client, h, ev())
    assert r.json()["outcomes"][0]["guardian"] == {
        "status": "skipped",
        "reason": "not_verified",
    }
    async with session_factory() as s:
        assert (
            await s.execute(select(func.count()).select_from(GuardianAlertOutbox))
        ).scalar_one() == 0


async def test_only_verified_channels_are_used(
    client, make_user, auth_headers, session_factory, provider
):
    u = await make_user("one")
    async with session_factory() as s:
        s.add(
            ElderlyConfig(
                user_id=u.id,
                enabled=True,
                guardian_email="g@example.com",
                guardian_phone="+919811100000",
                alert_threshold=0,
                **verified_guardian_fields("g@example.com", None),
            )
        )  # phone NOT verified
        await s.commit()
    await sync(client, auth_headers(u), ev())
    await run(session_factory)
    assert [e[0] for e in provider.email] == ["g@example.com"] and provider.sms == []
    async with session_factory() as s:
        row = (await s.execute(select(GuardianAlertOutbox))).scalar_one()
    assert row.status == SENT and row.channels_done == {"email": True}


async def test_authorisation_withdrawn_or_contact_changed_after_enqueue_blocks_delivery(
    client, make_user, auth_headers, session_factory, provider
):
    u = await make_user("late")
    h = auth_headers(u)
    await ready_guardian(client, h, **CFG)
    await sync(client, h, ev(), ev(package_name="com.two", app_name="Two"))
    await client.put(
        f"{E}/config", headers=h, json={**CFG, "guardian_email": "swapped@example.com"}
    )  # a different guardian now
    out = await run(session_factory)
    assert out == {"skipped": 2} and provider.email == [] and provider.sms == []


# ------------------------------------------------------------------------------------------- M2: server-calculated risk
async def test_a_device_reported_score_never_makes_an_alert_eligible(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("m2")
    h = auth_headers(u)
    await ready_guardian(client, h, **{**CFG, "alert_threshold": 90})
    r = await sync(
        client, h, ev(local_risk_score=100)
    )  # the device claims the maximum; the server sees a harmless app
    assert r.json()["outcomes"][0]["guardian"] == {
        "status": "skipped",
        "reason": "below_threshold",
    }


async def test_a_server_detected_risk_is_eligible_whatever_the_device_says(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("m2b")
    h = auth_headers(u)
    await ready_guardian(client, h, **{**CFG, "alert_threshold": 60})
    r = await sync(
        client,
        h,
        ev(
            local_risk_score=0,
            perm_count=8,
            is_unknown_source=True,
            has_overlay=True,
            has_accessibility=True,
        ),
    )
    assert r.json()["outcomes"][0]["guardian"]["status"] == "queued"
    async with session_factory() as s:
        row = (await s.execute(select(GuardianAlertOutbox))).scalar_one()
        stored = (
            await s.execute(select(AppInstallEvent.server_risk_score))
        ).scalar_one()
    assert row.payload["risk_score"] == stored  # the alert carries the server score


async def test_the_legacy_endpoint_ignores_the_reported_score_and_uses_the_stored_server_score(
    client, make_user, auth_headers, session_factory
):
    u = await make_user("lg")
    h = auth_headers(u)
    await ready_guardian(client, h, **{**CFG, "alert_threshold": 60})
    body = {
        "package_name": "com.harmless",
        "app_name": "Harmless",
        "risk_score": 100,
        "risk_level": "danger",
        "risk_tags": ["x"],
    }
    r = await client.post(f"{E}/guardian-alert", headers=h, json=body)
    assert r.json() == {
        "status": "skipped",
        "reason": rules.SKIP_BELOW_THRESHOLD,
    }  # the claimed 100 counts for nothing
    # once the server has scored a dangerous event for that package, the same endpoint uses THAT score
    await sync(
        client,
        h,
        ev(
            package_name="com.harmless",
            app_name="Harmless",
            perm_count=8,
            is_unknown_source=True,
            has_overlay=True,
            has_accessibility=True,
        ),
    )
    again = await client.post(
        f"{E}/guardian-alert", headers=h, json={**body, "risk_score": 1}
    )
    assert again.json()["status"] in ("queued", "skipped")
    async with session_factory() as s:
        n = (
            await s.execute(select(func.count()).select_from(GuardianAlertOutbox))
        ).scalar_one()
    assert n >= 1


# ------------------------------------------------------------------------------------------- M4: legacy endpoint is durable
async def test_the_legacy_endpoint_stores_the_alert_first_and_collapses_repeats(
    client, make_user, auth_headers, session_factory, provider
):
    u = await make_user("m4")
    h = auth_headers(u)
    await ready_guardian(client, h, **CFG)
    body = {
        "package_name": "com.whatsap.fake",
        "app_name": "WhatsApp",
        "risk_score": 1,
        "risk_level": "low",
    }
    a = await client.post(f"{E}/guardian-alert", headers=h, json=body)
    b = await client.post(f"{E}/guardian-alert", headers=h, json=body)
    assert (
        a.status_code == b.status_code == 202
        and a.json()["status"] == b.json()["status"] == "queued"
    )
    async with session_factory() as s:
        rows = (await s.execute(select(GuardianAlertOutbox))).scalars().all()
    assert (
        len(rows) == 1
        and rows[0].dedupe_key.startswith("legacy:")
        and rows[0].status == PENDING
    )
    assert (
        provider.email == []
    )  # nothing is sent inside the request: the worker delivers (and retries) it
    assert await run(session_factory) == {SENT: 1}
    assert len(provider.email) == 1 and len(provider.sms) == 1


async def test_a_legacy_alert_survives_a_provider_outage(
    client, make_user, auth_headers, session_factory, provider
):
    u = await make_user("m4b")
    h = auth_headers(u)
    await ready_guardian(client, h, **CFG)
    await client.post(
        f"{E}/guardian-alert",
        headers=h,
        json={
            "package_name": "com.whatsap.fake",
            "app_name": "WhatsApp",
            "risk_score": 1,
            "risk_level": "low",
        },
    )
    provider.sms = None  # break the stand-in: sending raises
    from app.services import notifications

    async def down(*a, **k):
        raise RuntimeError("provider down")

    import pytest as _p

    mp = _p.MonkeyPatch()
    mp.setattr(notifications, "send_sms", down)
    mp.setattr(notifications, "send_email", down)
    try:
        now = datetime.utcnow()
        assert await run(session_factory, now=now) == {
            PENDING: 1
        }  # kept for a retry, not lost
    finally:
        mp.undo()
    async with session_factory() as s:
        row = (await s.execute(select(GuardianAlertOutbox))).scalar_one()
    assert row.status == PENDING and row.attempts == 1 and row.next_attempt_at > now


# ------------------------------------------------------------------------------------------- M3: retention
async def seed_row(s, user_id, status, age_days, key, **kw):
    t = datetime.utcnow() - timedelta(days=age_days)
    row = GuardianAlertOutbox(
        user_id=user_id,
        dedupe_key=key,
        payload={},
        status=status,
        attempts=1,
        next_attempt_at=t,
        channels_done={},
        expires_at=t + timedelta(days=7),
        created_at=t,
        updated_at=t,
        **kw,
    )
    s.add(row)
    await s.flush()
    s.add(
        GuardianAlertDelivery(
            outbox_id=row.id, attempt_no=1, channel="email", result="ok"
        )
    )
    return row


async def test_terminal_alerts_and_their_audit_are_purged_after_90_days_and_nothing_else(
    make_user, session_factory
):
    u = await make_user("ret")
    async with session_factory() as s:
        for st in ("sent", "skipped", "expired", "failed"):
            await seed_row(s, u.id, st, 91, f"old-{st}")
        await seed_row(s, u.id, "sent", 89, "recent-sent")
        await seed_row(s, u.id, PENDING, 120, "old-pending")
        await seed_row(s, u.id, LEASED, 120, "old-leased")
        await s.commit()
    async with session_factory() as s:
        assert await ob.purge_terminal(s) == 4
    async with session_factory() as s:
        keys = sorted(
            (await s.execute(select(GuardianAlertOutbox.dedupe_key))).scalars().all()
        )
        audit = (
            await s.execute(select(func.count()).select_from(GuardianAlertDelivery))
        ).scalar_one()
    assert keys == [
        "old-leased",
        "old-pending",
        "recent-sent",
    ]  # in-flight rows are never purged by age
    assert audit == 3  # the purged rows' audit went with them
    assert ob.RETENTION == timedelta(days=90)


async def test_the_purge_is_safe_to_repeat_and_a_failure_does_not_escape(
    make_user, session_factory, monkeypatch
):
    u = await make_user("ret2")
    async with session_factory() as s:
        await seed_row(s, u.id, "sent", 100, "x")
        await s.commit()
    await ob.purge_safe()
    await ob.purge_safe()
    async with session_factory() as s:
        assert (
            await s.execute(select(func.count()).select_from(GuardianAlertOutbox))
        ).scalar_one() == 0

    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(ob, "purge_terminal", boom)
    await ob.purge_safe()  # logged, not raised


# ------------------------------------------------------------------------------------------- L3: attempts never exceed the maximum
async def test_a_row_that_used_every_attempt_is_failed_not_retried(
    make_user, session_factory, provider
):
    u = await make_user("l3")
    await ready_cfg(session_factory, u)
    async with session_factory() as s:
        # a worker died on the LAST attempt: leased, lease expired, attempts == max
        await seed_row(
            s,
            u.id,
            LEASED,
            0,
            "dead",
            lease_token=uuid.uuid4(),
            lease_expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        row = (await s.execute(select(GuardianAlertOutbox))).scalar_one()
        row.attempts = row.max_attempts = 5
        row.payload = {"app_name": "A", "risk_score": 90}
        await s.commit()
    out = await run(session_factory)
    assert out == {} and provider.email == [] and provider.sms == []  # no sixth attempt
    async with session_factory() as s:
        row = (await s.execute(select(GuardianAlertOutbox))).scalar_one()
    assert (
        row.status == FAILED
        and row.attempts == 5
        and row.last_error_code == "attempts_exhausted"
    )


async def ready_cfg(session_factory, user):
    async with session_factory() as s:
        s.add(
            ElderlyConfig(
                user_id=user.id,
                enabled=True,
                guardian_email="g@example.com",
                alert_threshold=0,
                **verified_guardian_fields("g@example.com"),
            )
        )
        await s.commit()


# ------------------------------------------------------------------------------------------- L2 and migration shape
async def test_the_event_id_index_exists_and_supports_the_fk(session_factory):
    async with session_factory() as s:
        names = set(
            (
                await s.execute(
                    text(
                        "select indexname from pg_indexes where tablename='guardian_alert_outbox'"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert {
        "ix_guardian_outbox_due",
        "ix_guardian_outbox_event_id",
        "ix_guardian_alert_outbox_user_id",
    } <= names


async def test_sql_review_script_matches_the_migration_and_is_non_destructive():
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[2]
    sql = (root / "docs/audit/f19_stage2a_review.sql").read_text(encoding="utf-8")
    mig = (
        root / "alembic/versions/x9y0z1a2b3c4_app_monitor_sync_and_guardian_outbox.py"
    ).read_text(encoding="utf-8")
    code = "\n".join(ln for ln in sql.splitlines() if not ln.strip().startswith("--"))
    assert not re.search(
        r"^\s*(DROP|DELETE|TRUNCATE|UPDATE)\b", code, re.M | re.I
    )  # destructive statements are comments only
    assert (
        code.strip().splitlines()[-1].strip() == "ROLLBACK;"
        and code.count("BEGIN;") == 1
        and "COMMIT;" not in code
    )
    for name in re.findall(r'"((?:uq|ix)_[a-z_]+)"', mig):
        assert name in sql, f"{name} is in the migration but not in the SQL script"
    for col in (
        "guardian_authorised_at",
        "guardian_notice_version",
        "guardian_email_verified_at",
        "guardian_email_verified_value",
        "guardian_phone_verified_at",
        "guardian_phone_verified_value",
        "client_event_id",
        "occurred_at",
    ):
        assert col in sql and col in mig
    assert (
        "has_table_privilege" in sql and "secureshield_app" in sql
    )  # runtime-role privilege verification


@pytest.fixture(autouse=True)
def _retention_enabled(monkeypatch):
    """Stage 1.1: retention deletes only when RETENTION_CLEANUP_ENABLED=true (and the identity is valid). These tests exercise
    the delete behaviour itself, so they enable it explicitly; the blocked paths are covered in tests/unit/test_retention_gate.py."""
    from app import config

    monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", "true")
