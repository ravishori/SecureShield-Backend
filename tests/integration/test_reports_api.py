"""Daily security report / score: scoping, freshness, AI-cost control, behavior logging."""

import pytest
from sqlalchemy import select

import app.routers.reports as reports
from app.models.alert import Alert, AlertSeverity, AlertType
from app.models.app_scan import AppScan
from app.models.behavior_event import BehaviorEvent
from app.models.device import Device
from app.models.security_report import SecurityReport

pytestmark = pytest.mark.integration
R = "/api/v1/reports"


@pytest.fixture
def tips(monkeypatch):
    calls = []

    async def fake(**kw):
        calls.append(kw)
        return [f"tip-{len(calls)}"]

    monkeypatch.setattr(reports, "generate_ai_security_tips", fake)
    return calls


async def add_alert(session_factory, user):
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
        await s.commit()


async def add_device_scans(session_factory, user, n, token):
    async with session_factory() as s:
        d = Device(
            user_id=user.id, device_token=token, device_name="d", platform="android"
        )
        s.add(d)
        await s.flush()
        for i in range(n):
            s.add(
                AppScan(
                    user_id=user.id,
                    device_id=d.id,
                    package_name=f"p{i}",
                    app_name=f"a{i}",
                )
            )
        await s.commit()


async def test_requires_auth(client):
    for p in ("/daily", "/history", "/weekly-insights"):
        assert (await client.get(R + p)).status_code in (401, 403)


async def test_empty_day_is_a_perfect_score(client, make_user, auth_headers, tips):
    j = (
        await client.get(f"{R}/daily", headers=auth_headers(await make_user("e")))
    ).json()
    assert (
        j["overall_risk_score"] == 0
        and j["security_score"] == 100
        and j["risk_level"] == "low"
    )
    assert j["threats_detected"] == 0 and j["recommendations"] == ["tip-1"]


@pytest.mark.security
async def test_app_scan_counts_are_per_user_not_global(
    client, make_user, auth_headers, session_factory, tips
):
    a, b = await make_user("a"), await make_user("b")
    await add_device_scans(session_factory, a, 4, "tok-a")
    await add_device_scans(session_factory, b, 7, "tok-b")
    assert (await client.get(f"{R}/daily", headers=auth_headers(a))).json()[
        "apps_scanned"
    ] == 4
    assert (await client.get(f"{R}/daily", headers=auth_headers(b))).json()[
        "apps_scanned"
    ] == 7


async def test_report_refreshes_during_the_day_and_stays_one_row(
    client, make_user, auth_headers, session_factory, tips, db
):
    u = await make_user("fresh")
    h = auth_headers(u)
    first = (await client.get(f"{R}/daily", headers=h)).json()
    await add_alert(session_factory, u)
    second = (await client.get(f"{R}/daily", headers=h)).json()
    assert first["id"] == second["id"]
    assert second["threats_detected"] == 1 and second["overall_risk_score"] == 10
    assert second["security_score"] == 90 and second["risk_level"] == "low"
    assert len((await db.execute(select(SecurityReport))).scalars().all()) == 1


async def test_ai_tips_only_regenerated_when_the_picture_changes(
    client, make_user, auth_headers, session_factory, tips
):
    u = await make_user("cost")
    h = auth_headers(u)
    for _ in range(3):
        await client.get(f"{R}/daily", headers=h)
    assert len(tips) == 1  # identical data: tips reused
    await add_alert(session_factory, u)
    j = (await client.get(f"{R}/daily", headers=h)).json()
    assert len(tips) == 2 and j["recommendations"] == ["tip-2"]


async def test_ai_failure_falls_back_to_default_tips(
    client, make_user, auth_headers, monkeypatch
):
    import app.services.ai_service as ai

    async def boom(**kw):
        raise RuntimeError("model down")

    monkeypatch.setattr(ai, "_create_message", boom)
    j = (
        await client.get(f"{R}/daily", headers=auth_headers(await make_user("fb")))
    ).json()
    assert len(j["recommendations"]) >= 3


async def test_score_levels_and_clamping(
    client, make_user, auth_headers, session_factory, tips
):
    u = await make_user("risky")
    h = auth_headers(u)
    for kind in ("shared_otp", "shared_otp", "shared_otp", "shared_otp"):
        assert (
            await client.post(
                f"{R}/log-behavior", headers=h, params={"event_type": kind}
            )
        ).status_code == 200
    j = (await client.get(f"{R}/daily", headers=h)).json()
    assert (
        j["overall_risk_score"] == 100
        and j["security_score"] == 0
        and j["risk_level"] == "critical"
    )
    assert j["top_threats"][0]["type"] == "risky_behaviors"


async def test_behavior_logging_validates_and_is_user_scoped(
    client, make_user, auth_headers, db
):
    a, b = await make_user("a"), await make_user("b")
    ok = await client.post(
        f"{R}/log-behavior",
        headers=auth_headers(a),
        params={"event_type": "connected_open_wifi"},
    )
    assert ok.status_code == 200 and ok.json()["risk_contribution"] == 10.0
    bad = await client.post(
        f"{R}/log-behavior", headers=auth_headers(a), params={"event_type": "nonsense"}
    )
    assert bad.status_code == 422  # used to be silently stored as clicked_unknown_link
    long = await client.post(
        f"{R}/log-behavior",
        headers=auth_headers(a),
        params={"event_type": "shared_otp", "details": "x" * 501},
    )
    assert long.status_code == 422
    rows = (await db.execute(select(BehaviorEvent))).scalars().all()
    assert len(rows) == 1 and rows[0].user_id == a.id
    assert (await client.get(f"{R}/daily", headers=auth_headers(b))).json()[
        "overall_risk_score"
    ] == 0


async def test_history_and_weekly_insights_are_own_data_only(
    client, make_user, auth_headers, tips
):
    a, b = await make_user("a"), await make_user("b")
    await client.get(f"{R}/daily", headers=auth_headers(a))
    assert len((await client.get(f"{R}/history", headers=auth_headers(a))).json()) == 1
    assert (await client.get(f"{R}/history", headers=auth_headers(b))).json() == []
    assert (await client.get(f"{R}/weekly-insights", headers=auth_headers(b))).json()[
        "trend"
    ] == "unknown"
    wk = (await client.get(f"{R}/weekly-insights", headers=auth_headers(a))).json()
    assert wk["daily_scores"] and wk["average_risk_score"] == 0


async def test_unique_constraint_blocks_duplicate_daily_rows(
    make_user, session_factory
):
    from datetime import date

    from sqlalchemy.exc import IntegrityError

    u = await make_user("dup")
    async with session_factory() as s:
        s.add(SecurityReport(user_id=u.id, report_date=date.today()))
        await s.commit()
    async with session_factory() as s:
        s.add(SecurityReport(user_id=u.id, report_date=date.today()))
        with pytest.raises(IntegrityError):
            await s.commit()


# -------------------------------------------------------------- e-mail delivery
async def test_daily_report_email_goes_to_the_account_address_only(
    client, make_user, auth_headers, tips, monkeypatch
):
    sent = []

    async def fake_send(to, subject, body):
        sent.append((to, subject, body))
        return True

    monkeypatch.setattr(reports.notifications, "send_email", fake_send)
    u = await make_user("mail", email="me@example.com")
    r = await client.post(f"{R}/daily/email", headers=auth_headers(u))
    assert r.status_code == 200 and r.json()["security_score"] == 100
    assert (
        sent[0][0] == "me@example.com"
        and "Security score: 100/100" in sent[0][2]
        and "tip-1" in sent[0][2]
    )


async def test_daily_report_email_errors(
    client, make_user, auth_headers, tips, monkeypatch
):
    async def down(to, subject, body):
        return False

    monkeypatch.setattr(reports.notifications, "send_email", down)
    no_mail = await make_user("nomail", email=None)
    assert (
        await client.post(f"{R}/daily/email", headers=auth_headers(no_mail))
    ).status_code == 400
    u = await make_user("fail", email="f@example.com")
    assert (
        await client.post(f"{R}/daily/email", headers=auth_headers(u))
    ).status_code == 502
    assert (await client.post(f"{R}/daily/email")).status_code in (401, 403)


async def test_daily_report_email_is_rate_limited(
    client, make_user, auth_headers, tips, monkeypatch
):
    async def ok(to, subject, body):
        return True

    monkeypatch.setattr(reports.notifications, "send_email", ok)
    h = auth_headers(await make_user("rl", email="rl@example.com"))
    codes = [
        (await client.post(f"{R}/daily/email", headers=h)).status_code for _ in range(4)
    ]
    assert codes == [200, 200, 200, 429]
