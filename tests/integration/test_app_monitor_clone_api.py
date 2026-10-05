"""App install monitor (offline-first sync) and clone detection."""

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


def ev(pkg="com.example.tool", name="Example Tool", **kw):
    return {"package_name": pkg, "app_name": name, **kw}


async def sync(client, h, *events):
    return await client.post(
        f"{API}/app-monitor/sync", headers=h, json={"events": list(events)}
    )


async def test_requires_auth(client):
    for method, path in (
        ("POST", "/app-monitor/sync"),
        ("GET", "/app-monitor/history"),
        ("GET", "/app-monitor/summary"),
        ("POST", "/clone-detection/scan"),
        ("GET", "/clone-detection/history"),
        ("GET", "/clone-detection/catalogue"),
    ):
        assert (await client.request(method, API + path)).status_code in (401, 403), (
            path
        )


async def test_sync_scores_events_and_lists_history(client, make_user, auth_headers):
    h = auth_headers(await make_user("m"))
    r = await sync(
        client,
        h,
        ev(first_install_time=111),
        ev("com.other", "Other", first_install_time=222),
    )
    assert r.status_code == 200, r.text
    assert r.json()["synced"] == 2 and all(x["risk_level"] for x in r.json()["results"])
    hist = (await client.get(f"{API}/app-monitor/history", headers=h)).json()
    assert hist["total"] == 2 and len(hist["events"]) == 2
    s = (await client.get(f"{API}/app-monitor/summary", headers=h)).json()
    assert (
        s["total_monitored"] == 2
        and s["safe_count"] + s["warning_count"] + s["danger_count"] == 2
    )


async def test_resyncing_the_same_queue_is_idempotent(client, make_user, auth_headers):
    h = auth_headers(await make_user("idem"))
    batch = [ev(first_install_time=1000), ev("com.b", "B", first_install_time=2000)]
    assert (await sync(client, h, *batch)).json()["synced"] == 2
    assert (await sync(client, h, *batch)).json()["synced"] == 0
    assert (await client.get(f"{API}/app-monitor/summary", headers=h)).json()[
        "total_monitored"
    ] == 2


async def test_dangerous_install_creates_an_alert_instead_of_crashing(
    client, make_user, auth_headers
):
    """Regression: the alert used non-existent enum members/columns, so every dangerous sync was a 500."""
    h = auth_headers(await make_user("danger"))
    risky = ev(
        "com.whatsapp.fake",
        "WhatsApp",
        is_unknown_source=True,
        has_overlay=True,
        has_accessibility=True,
        perm_count=12,
        dangerous_perms=["SMS", "CAMERA"],
        local_risk_score=90,
        first_install_time=5,
    )
    r = await sync(client, h, risky)
    assert r.status_code == 200, r.text
    row = r.json()["results"][0]
    assert row["flagged_as_clone"] is True
    alerts = (await client.get(f"{API}/alerts/", headers=h)).json()
    assert alerts["total"] == 1 and alerts["items"][0]["alert_type"] == "app_risk"
    assert alerts["items"][0]["extra_data"]["packageName"] == "com.whatsapp.fake"


@pytest.mark.security
async def test_monitor_data_is_private_and_delete_is_owner_only(
    client, make_user, auth_headers
):
    a, b = await make_user("a"), await make_user("b")
    await sync(client, auth_headers(a), ev(first_install_time=1))
    assert (
        await client.get(f"{API}/app-monitor/history", headers=auth_headers(b))
    ).json()["total"] == 0
    assert (
        await client.get(f"{API}/app-monitor/summary", headers=auth_headers(b))
    ).json()["total_monitored"] == 0
    eid = (
        await client.get(f"{API}/app-monitor/history", headers=auth_headers(a))
    ).json()["events"][0]["id"]
    assert (
        await client.delete(f"{API}/app-monitor/{eid}", headers=auth_headers(b))
    ).status_code == 404
    assert (
        await client.delete(f"{API}/app-monitor/{eid}", headers=auth_headers(a))
    ).status_code == 204
    assert (
        await client.delete(f"{API}/app-monitor/not-a-uuid", headers=auth_headers(a))
    ).status_code == 422


async def test_sync_validation(client, make_user, auth_headers):
    h = auth_headers(await make_user("val"))
    for bad in (
        ev(event_type="exploded"),
        ev(local_risk_score=101),
        ev(perm_count=-1),
        ev(pkg="p" * 256),
        ev(name=""),
    ):
        assert (await sync(client, h, bad)).status_code == 422
    assert (
        await sync(client, h, *[ev(f"com.p{i}", "n") for i in range(51)])
    ).status_code == 422


async def test_history_filters_and_pagination_bounds(client, make_user, auth_headers):
    h = auth_headers(await make_user("pg"))
    await sync(
        client, h, *[ev(f"com.p{i}", f"n{i}", first_install_time=i) for i in range(5)]
    )
    page = (
        await client.get(
            f"{API}/app-monitor/history", headers=h, params={"limit": 2, "page": 3}
        )
    ).json()
    assert page["total"] == 5 and len(page["events"]) == 1
    assert (
        await client.get(f"{API}/app-monitor/history", headers=h, params={"limit": 101})
    ).status_code == 422
    assert (
        await client.get(f"{API}/app-monitor/history", headers=h, params={"page": 0})
    ).status_code == 422


# ----------------------------------------------------------- clone detection
async def test_clone_scan_verdicts_and_history(client, make_user, auth_headers):
    h = auth_headers(await make_user("c"))
    real = (
        await client.post(
            f"{API}/clone-detection/scan",
            headers=h,
            json={"package_name": "com.whatsapp", "app_name": "WhatsApp"},
        )
    ).json()
    assert real["verdict"] == "safe" and real["action_recommended"] == "none"
    fake = (
        await client.post(
            f"{API}/clone-detection/scan",
            headers=h,
            json={"package_name": "com.whatsapp.fake", "app_name": "WhatsApp"},
        )
    ).json()
    assert (
        fake["verdict"] != "safe"
        and fake["target_package"] == "com.whatsapp"
        and fake["signals"]
    )
    hist = (await client.get(f"{API}/clone-detection/history", headers=h)).json()
    assert hist["total"] == 2
    only = (
        await client.get(
            f"{API}/clone-detection/history", headers=h, params={"verdict": "safe"}
        )
    ).json()
    assert only["total"] == 1


@pytest.mark.security
async def test_clone_feedback_and_history_are_owner_scoped(
    client, make_user, auth_headers
):
    a, b = await make_user("a"), await make_user("b")
    rid = (
        await client.post(
            f"{API}/clone-detection/scan",
            headers=auth_headers(a),
            json={"package_name": "x.y", "app_name": "Z"},
        )
    ).json()["id"]
    assert (
        await client.get(f"{API}/clone-detection/history", headers=auth_headers(b))
    ).json()["total"] == 0
    fb = {"report_id": rid, "user_confirmed": True, "action_taken": "uninstalled"}
    assert (
        await client.post(
            f"{API}/clone-detection/feedback", headers=auth_headers(b), json=fb
        )
    ).status_code == 404
    assert (
        await client.post(
            f"{API}/clone-detection/feedback", headers=auth_headers(a), json=fb
        )
    ).status_code == 200
    assert (
        await client.post(
            f"{API}/clone-detection/feedback",
            headers=auth_headers(a),
            json={**fb, "report_id": "zzz"},
        )
    ).status_code == 422


async def test_clone_scan_bounds_and_catalogue(client, make_user, auth_headers):
    h = auth_headers(await make_user("b"))
    for bad in (
        {"package_name": "", "app_name": "x"},
        {"package_name": "p" * 256, "app_name": "x"},
        {"package_name": "p", "app_name": "x", "cert_hash": "h" * 201},
    ):
        assert (
            await client.post(f"{API}/clone-detection/scan", headers=h, json=bad)
        ).status_code == 422
    cat = (await client.get(f"{API}/clone-detection/catalogue", headers=h)).json()
    assert cat["count"] == len(cat["apps"]) > 5
