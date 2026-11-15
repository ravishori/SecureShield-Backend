"""BH-2: sensitive URL data is minimised in storage, alerts, logs and provider requests; link-scan history has a retention
period; the existing history API stays compatible. Real app, real database."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

import app.services.link_scan_retention as ret
from app.cli import purge_link_scans as purge_cli
from app.config import settings
from app.models.alert import Alert
from app.models.error_log import ErrorLog
from app.models.link_scan import LinkScan
from tests.integration.conftest import delete_body

pytestmark = [pytest.mark.integration, pytest.mark.security]

SCAN = "/api/v1/link-scanner/scan"
HIST = "/api/v1/link-scanner/history"
MSG = "/api/v1/message/analyze"
SECRET = "S3cr3tT0kenV4lue"
SENSITIVE = f"http://admin:{SECRET}@192.168.4.4/login/verify?access_token={SECRET}&id=7&next=https://evil.example/x?k={SECRET}#frag={SECRET}"
NO_USERINFO = f"http://192.168.4.4/login/verify?access_token={SECRET}&id=7&next=https://evil.example/x?k={SECRET}#frag={SECRET}"


def env(name, status="safe", threats=None):
    return {
        "status": status,
        "safe": status == "safe",
        "threats": threats or [],
        "provider": name,
        "reason": None,
        "http_status": None,
        "cached": False,
    }


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    monkeypatch.setattr(settings, "API_RATE_LIMIT", 10_000)
    import app.services.user_rate_limits as url

    url.default_limiter.clear()
    for k in (
        "LINK_SCAN_RETENTION_DAYS",
        "LINK_SCAN_PURGE_BATCH",
        "LINK_SCAN_PURGE_MAX_BATCHES",
    ):
        monkeypatch.setattr(ret.retention_settings, k, None)
    ret._gate["next"] = (
        1e18  # the opportunistic purge stays off unless a test turns it on
    )
    yield
    ret._gate["next"] = 0.0


@pytest.fixture
def seen(monkeypatch):
    """Providers that record exactly what they were asked about."""
    calls = {"gsb": [], "uh": []}

    async def gsb(u):
        calls["gsb"].append(u)
        return env("google_safe_browsing")

    async def uh(u):
        calls["uh"].append(u)
        return env("urlhaus")

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", gsb)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", uh)
    return calls


@pytest.fixture
async def user(make_user):
    return await make_user("priv")


async def rows(session_factory):
    async with session_factory() as s:
        return (await s.execute(select(LinkScan))).scalars().all()


async def everything_stored(session_factory) -> str:
    """All text that could hold a URL: scans, alerts and error logs, as one searchable string."""
    out = []
    async with session_factory() as s:
        for r in (await s.execute(select(LinkScan))).scalars():
            out.append(
                json.dumps(
                    [r.url, r.gsb_threats, r.threat_category, r.scan_provider],
                    default=str,
                )
            )
        for a in (await s.execute(select(Alert))).scalars():
            out.append(json.dumps([a.title, a.message, a.extra_data], default=str))
        for e in (await s.execute(select(ErrorLog))).scalars():
            out.append(
                json.dumps([e.message, e.traceback, e.endpoint, e.extra], default=str)
            )
    return "\n".join(out)


# ----------------------------------------------------------------------------------------------------------------------
# Storage, response, alerts
# ----------------------------------------------------------------------------------------------------------------------
async def test_a_url_full_of_secrets_is_never_persisted(
    client, user, auth_headers, seen, session_factory
):
    r = await client.post(SCAN, headers=auth_headers(user), json={"url": SENSITIVE})
    assert r.status_code == 200
    stored = (await rows(session_factory))[0].url
    assert (
        stored
        == "http://192.168.4.4/login/verify?access_token=~&id=~&next=https://evil.example"
    )
    assert r.json()["url"] == stored  # the response shows the same redacted form
    blob = await everything_stored(session_factory)
    assert SECRET not in blob and "frag" not in blob and "admin:" not in blob


async def test_detection_still_uses_the_full_url_exactly_as_before(
    client, user, auth_headers, seen
):
    from app.services.threat_analyzer import analyze_url

    for submitted in ("http://192.168.4.4/login/verify", NO_USERINFO, SENSITIVE):
        body = (
            await client.post(SCAN, headers=auth_headers(user), json={"url": submitted})
        ).json()
        is_phishing, _, score, category = analyze_url(
            submitted
        )  # the detector on the ORIGINAL, unredacted text
        assert (body["is_phishing"], body["risk_score"], body["threat_category"]) == (
            is_phishing,
            score,
            category,
        )
    assert (
        body["is_phishing"] is False or body["risk_score"] >= 40
    )  # sanity: the detector result is what was returned


async def test_providers_receive_no_user_info_fragment_or_credential_parameters(
    client, user, auth_headers, seen
):
    await client.post(SCAN, headers=auth_headers(user), json={"url": SENSITIVE})
    # the credential-named parameter is dropped and the redirect target is reduced to its host; 'id' stays because
    # exact-match feeds compare the whole URL
    assert seen["gsb"] == [
        "http://192.168.4.4/login/verify?id=7&next=https://evil.example"
    ]
    assert seen["gsb"] == seen["uh"]
    assert (
        SECRET not in seen["gsb"][0]
        and "admin:" not in seen["gsb"][0]
        and "#" not in seen["gsb"][0]
    )


async def test_a_risky_url_creates_an_alert_without_secrets(
    client, user, auth_headers, seen, session_factory
):
    await client.post(SCAN, headers=auth_headers(user), json={"url": NO_USERINFO})
    async with session_factory() as s:
        alerts = (await s.execute(select(Alert))).scalars().all()
    assert alerts, "the risky link should raise an alert"
    assert (
        alerts[0].extra_data["url"]
        == "http://192.168.4.4/login/verify?access_token=~&id=~&next=https://evil.example"
    )
    assert (
        SECRET
        not in json.dumps(alerts[0].extra_data) + alerts[0].message + alerts[0].title
    )


async def test_provider_threat_urls_are_redacted_before_storage_and_in_the_response(
    client, user, auth_headers, monkeypatch, session_factory
):
    threat = {
        "threat_type": "MALWARE",
        "threat_label": "Malware",
        "url": f"https://evil.example/dl?token={SECRET}#x",
    }

    async def gsb(u):
        return env("google_safe_browsing", "malicious", [threat])

    async def uh(u):
        return env("urlhaus")

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", gsb)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", uh)
    r = await client.post(
        SCAN,
        headers=auth_headers(user),
        json={"url": f"https://evil.example/dl?token={SECRET}"},
    )
    body = r.json()
    assert body["is_malicious"] is True and body["verdict"]["risk_level"] == "critical"
    assert body["gsb_threats"][0]["threat_type"] == "MALWARE"
    assert SECRET not in json.dumps(body) and SECRET not in await everything_stored(
        session_factory
    )


async def test_provider_failure_is_unknown_never_safe_and_still_redacted(
    client, user, auth_headers, monkeypatch, session_factory
):
    async def down(u):
        return env("x", "network_error")

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", down)
    monkeypatch.setattr("app.routers.link_scanner.check_url_urlhaus", down)
    r = await client.post(
        SCAN,
        headers=auth_headers(user),
        json={"url": f"https://example.com/about?session={SECRET}"},
    )
    v = r.json()["verdict"]
    assert (
        v["risk_level"] == "unknown"
        and v["risk_score"] is None
        and v["risk_level"] != "safe"
    )
    assert (await rows(session_factory))[0].url == "https://example.com/about?session=~"


async def test_bare_hosts_typed_by_the_app_are_stored_as_typed_without_secrets(
    client, user, auth_headers, seen, session_factory
):
    await client.post(
        SCAN,
        headers=auth_headers(user),
        json={"url": f"example.com/login?pin={SECRET}"},
    )
    assert (await rows(session_factory))[0].url == "example.com/login?pin=~"


# ----------------------------------------------------------------------------------------------------------------------
# History API compatibility and legacy rows
# ----------------------------------------------------------------------------------------------------------------------
async def test_history_keeps_its_shape_and_never_returns_a_legacy_full_url(
    client, user, auth_headers, session_factory
):
    async with session_factory() as s:  # a row written before BH-2
        s.add(
            LinkScan(
                user_id=user.id,
                url=f"https://old.example/p?token={SECRET}#f",
                is_phishing=False,
                is_malicious=True,
                risk_score=95.0,
                threat_category="phishing",
                scan_provider="google_safe_browsing",
                gsb_threats=[
                    {
                        "threat_type": "SOCIAL_ENGINEERING",
                        "url": f"https://old.example/p?token={SECRET}",
                    }
                ],
            )
        )
        await s.commit()
    r = await client.get(HIST, headers=auth_headers(user))
    assert r.status_code == 200
    item = r.json()[0]
    assert set(item) >= {
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
        "verdict",
    }
    assert item["url"] == "https://old.example/p?token=~" and SECRET not in json.dumps(
        item
    )
    assert item["verdict"]["risk_level"] == "critical"


async def test_history_order_and_plain_urls_are_unchanged(
    client, make_user, auth_headers, seen
):
    u = await make_user("h")
    for i in range(3):
        await client.post(
            SCAN, headers=auth_headers(u), json={"url": f"https://example.org/{i}"}
        )
    h = (await client.get(HIST, headers=auth_headers(u))).json()
    assert [x["url"] for x in h] == [
        "https://example.org/2",
        "https://example.org/1",
        "https://example.org/0",
    ]


# ----------------------------------------------------------------------------------------------------------------------
# Message analysis and community reports
# ----------------------------------------------------------------------------------------------------------------------
async def test_message_alert_previews_contain_no_link_values(
    client, user, auth_headers, session_factory
):
    text = f"URGENT your SBI KYC has expired. Click http://bit.ly/abc123?otp={SECRET}#x now and share your OTP or account will be blocked"
    r = await client.post(
        MSG, headers=auth_headers(user), json={"message_text": text, "use_ai": False}
    )
    assert r.status_code == 200
    async with session_factory() as s:
        alerts = (await s.execute(select(Alert))).scalars().all()
    preview = alerts[0].extra_data["message_preview"]
    assert (
        alerts
        and "[link: bit.ly]" in preview
        and SECRET not in json.dumps(alerts[0].extra_data)
        and len(preview) <= 100
    )


async def test_community_report_urls_are_redacted_on_write(
    client, user, auth_headers, session_factory
):
    payload = {
        "scam_type": "phishing_link",
        "title": "Fake bank page",
        "description": "A page asked for my PIN and card number",
        "url": f"https://fake.example/b?session={SECRET}#x",
    }
    r = await client.post(
        "/api/v1/community-scams/report", headers=auth_headers(user), json=payload
    )
    assert r.status_code in (200, 201), r.text
    assert (
        SECRET not in r.text and r.json()["url"] == "https://fake.example/b?session=~"
    )


# ----------------------------------------------------------------------------------------------------------------------
# Logging and exception handling
# ----------------------------------------------------------------------------------------------------------------------
async def test_an_unexpected_failure_does_not_put_the_url_in_the_error_log(
    client, user, auth_headers, monkeypatch, session_factory
):
    async def boom(u):
        raise RuntimeError(f"provider exploded for {u}")

    monkeypatch.setattr("app.routers.link_scanner.check_url_gsb", boom)
    r = await client.post(
        SCAN,
        headers=auth_headers(user),
        json={"url": f"https://example.com/p?token={SECRET}&id=5#frag"},
    )
    assert (
        r.status_code == 500 and SECRET not in r.text
    )  # the generic handler answers; nothing about the URL is returned
    blob = await everything_stored(session_factory)
    assert "RuntimeError" in blob  # the failure is still logged ...
    assert (
        SECRET not in blob and "id=5" not in blob and "frag" not in blob
    )  # ... without the URL's values


async def test_application_logs_never_contain_the_submitted_url(
    client, user, auth_headers, seen, caplog
):
    with caplog.at_level(logging.DEBUG):
        await client.post(SCAN, headers=auth_headers(user), json={"url": SENSITIVE})
    assert SECRET not in "\n".join(r.getMessage() for r in caplog.records)


# ----------------------------------------------------------------------------------------------------------------------
# Retention
# ----------------------------------------------------------------------------------------------------------------------
NOW = datetime(2026, 11, 15, 12, 0, 0)


async def add_scan(
    session_factory, user, age: timedelta, url="https://example.org/x"
) -> uuid.UUID:
    async with session_factory() as s:
        row = LinkScan(
            user_id=user.id,
            url=url,
            is_phishing=False,
            is_malicious=False,
            risk_score=0.0,
            scan_provider="internal_fallback",
            scanned_at=NOW - age,
        )
        s.add(row)
        await s.commit()
        return row.id


async def count_scans(session_factory) -> int:
    async with session_factory() as s:
        return (
            await s.execute(select(func.count()).select_from(LinkScan))
        ).scalar_one()


async def test_expiry_boundary_is_strictly_older_than_the_retention_period(
    user, session_factory
):
    old = await add_scan(session_factory, user, timedelta(days=30, seconds=1))
    edge = await add_scan(
        session_factory, user, timedelta(days=30)
    )  # exactly 30 days old: kept
    young = await add_scan(session_factory, user, timedelta(days=29, hours=23))
    res = await ret.purge_expired(session_factory, now=NOW)
    assert (res.deleted, res.error, res.days) == (1, None, 30)
    async with session_factory() as s:
        left = {r for (r,) in (await s.execute(select(LinkScan.id))).all()}
    assert left == {edge, young} and old not in left


async def test_cleanup_is_repeatable_and_a_second_run_changes_nothing(
    user, session_factory
):
    for d in (31, 40, 90):
        await add_scan(session_factory, user, timedelta(days=d))
    first = await ret.purge_expired(session_factory, now=NOW)
    second = await ret.purge_expired(session_factory, now=NOW)
    assert (first.deleted, second.deleted, second.batches) == (
        3,
        0,
        1,
    ) and await count_scans(session_factory) == 0


async def test_cleanup_is_bounded_per_run_and_continues_on_the_next(
    user, session_factory, monkeypatch
):
    monkeypatch.setattr(ret.retention_settings, "LINK_SCAN_PURGE_BATCH", "2")
    monkeypatch.setattr(ret.retention_settings, "LINK_SCAN_PURGE_MAX_BATCHES", "2")
    for i in range(7):
        await add_scan(session_factory, user, timedelta(days=31 + i))
    keep = await add_scan(session_factory, user, timedelta(days=1))
    r1 = await ret.purge_expired(session_factory, now=NOW)
    assert (r1.deleted, r1.batches, r1.more_remaining) == (4, 2, True)
    r2 = await ret.purge_expired(session_factory, now=NOW)
    assert (r2.deleted, r2.more_remaining) == (
        3,
        False,
    )  # 3 left: the last batch is not full
    async with session_factory() as s:
        assert [r for (r,) in (await s.execute(select(LinkScan.id))).all()] == [keep]


@pytest.mark.parametrize("bad", ["", "0", "-5", "abc", "1.5", "99999", " 30"])
async def test_an_invalid_retention_setting_never_disables_or_lengthens_retention(
    bad, user, session_factory, monkeypatch, caplog
):
    monkeypatch.setattr(ret.retention_settings, "LINK_SCAN_RETENTION_DAYS", bad)
    await add_scan(session_factory, user, timedelta(days=31))
    with caplog.at_level(logging.WARNING):
        res = await ret.purge_expired(session_factory, now=NOW)
    assert res.days == 30 and res.deleted == 1
    assert any(
        "LINK_SCAN_RETENTION_DAYS is invalid" in r.getMessage() for r in caplog.records
    )
    assert bad.strip() == "" or bad not in "\n".join(
        r.getMessage() for r in caplog.records
    )


async def test_a_custom_retention_period_is_honoured(
    user, session_factory, monkeypatch
):
    monkeypatch.setattr(ret.retention_settings, "LINK_SCAN_RETENTION_DAYS", "7")
    await add_scan(session_factory, user, timedelta(days=8))
    await add_scan(session_factory, user, timedelta(days=6))
    assert (await ret.purge_expired(session_factory, now=NOW)).deleted == 1


async def test_cleanup_failure_is_observable_without_leaking_anything(
    user, session_factory, caplog
):
    await add_scan(
        session_factory,
        user,
        timedelta(days=40),
        url=f"https://example.org/p?token={SECRET}",
    )

    class Broken:
        def __call__(self):
            raise ConnectionError(
                f"cannot reach db with https://example.org/p?token={SECRET}"
            )

    with caplog.at_level(logging.DEBUG):
        res = await ret.purge_expired(Broken(), now=NOW)
    assert res.error == "ConnectionError" and res.deleted == 0
    assert ret.last_run["error"] == "ConnectionError"
    assert SECRET not in "\n".join(r.getMessage() for r in caplog.records)
    assert await count_scans(session_factory) == 1  # nothing was lost by the failure


async def test_the_opportunistic_purge_runs_after_a_scan_once_per_hour(
    client, user, auth_headers, seen, session_factory
):
    ret._gate["next"] = 0.0
    await add_scan(
        session_factory, user, timedelta(days=45)
    )  # NOW is a fixed date in 2026; real "now" makes this far older
    await client.post(
        SCAN, headers=auth_headers(user), json={"url": "https://example.org/fresh"}
    )
    stored = [r.url for r in await rows(session_factory)]
    assert stored == [
        "https://example.org/fresh"
    ]  # the old row was purged in the background, the new one kept
    assert ret._gate["next"] > 0  # and the hourly gate is now closed
    await add_scan(session_factory, user, timedelta(days=45))
    await client.post(
        SCAN, headers=auth_headers(user), json={"url": "https://example.org/fresh2"}
    )
    assert (
        await count_scans(session_factory) == 3
    )  # gate closed: no second purge within the hour


async def test_account_deletion_still_removes_all_of_a_users_scans_at_any_age(
    client, make_user, auth_headers, seen, session_factory
):
    u = await make_user("gone")
    h = auth_headers(u)
    await client.post(
        SCAN, headers=h, json={"url": f"https://example.org/a?t={SECRET}"}
    )
    await add_scan(session_factory, u, timedelta(days=1))
    other = await make_user("stay")
    await client.post(
        SCAN, headers=auth_headers(other), json={"url": "https://example.org/b"}
    )
    resp = await client.request(
        "DELETE", "/api/v1/auth/me", headers=h, json=await delete_body(h)
    )
    assert resp.status_code == 200, resp.text
    left = await rows(session_factory)
    assert [r.user_id for r in left] == [other.id]


# ----------------------------------------------------------------------------------------------------------------------
# The command line tool
# ----------------------------------------------------------------------------------------------------------------------
async def test_the_cli_dry_run_counts_and_changes_nothing(
    user, session_factory, capsys
):
    await add_scan(
        session_factory, user, timedelta(days=400)
    )  # relative to the real clock: expired
    assert await purge_cli._dry_run() == 0
    assert "eligible for deletion (older than 30 days): 1" in capsys.readouterr().out
    assert await count_scans(session_factory) == 1


async def test_redact_existing_rewrites_legacy_rows_and_is_idempotent(
    user, session_factory, capsys
):
    await add_scan(
        session_factory,
        user,
        timedelta(days=1),
        url=f"https://x.example/p?token={SECRET}#f",
    )
    assert await purge_cli._redact_existing() == 0
    assert "rows rewritten to the redacted form: 1" in capsys.readouterr().out
    assert (await rows(session_factory))[0].url == "https://x.example/p?token=~"
    await purge_cli._redact_existing()
    assert "rows rewritten to the redacted form: 0" in capsys.readouterr().out
    assert await count_scans(session_factory) == 1  # nothing deleted


def test_the_cli_reports_usage_errors_with_exit_code_two():
    assert purge_cli.run(["--nope"]) == 2
    assert purge_cli.run(["--dry-run", "--redact-existing"]) == 2


@pytest.fixture(autouse=True)
def _retention_enabled(monkeypatch):
    """Stage 1.1: retention deletes only when RETENTION_CLEANUP_ENABLED=true (and the identity is valid). These tests exercise
    the delete behaviour itself, so they enable it explicitly; the blocked paths are covered in tests/unit/test_retention_gate.py."""
    from app import config

    monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", "true")
