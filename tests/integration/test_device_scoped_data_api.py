"""Tenant isolation for app scans, Wi-Fi scans, network activity and scam calls.

Regression: these endpoints used to return EVERY user's rows (scans were stored with no owner)."""

import pytest
from sqlalchemy import select

from app.models.app_scan import AppScan
from app.models.device import Device
from app.models.wifi_scan import WifiScan

pytestmark = pytest.mark.integration
API = "/api/v1"


def apps(*names, perms=None):
    return {
        "apps": [
            {"package_name": f"com.{n}", "app_name": n, "permissions": perms or []}
            for n in names
        ]
    }


async def test_all_endpoints_require_auth(client):
    for method, path in (
        ("GET", "/app-scanner/results"),
        ("GET", "/app-scanner/spyware-check"),
        ("GET", "/wifi/history"),
        ("GET", "/network/suspicious"),
        ("GET", "/scam-calls/history"),
        ("POST", "/scam-calls/block/123"),
    ):
        r = await client.request(method, API + path)
        assert r.status_code in (401, 403), path


@pytest.mark.security
async def test_app_scan_results_are_private(client, make_user, auth_headers):
    a, b = await make_user("a"), await make_user("b")
    spy = [
        "android.permission.READ_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
    ]
    await client.post(
        f"{API}/app-scanner/scan",
        headers=auth_headers(a),
        json=apps("alpha", perms=spy),
    )
    await client.post(
        f"{API}/app-scanner/scan", headers=auth_headers(b), json=apps("bravo")
    )
    mine = (
        await client.get(f"{API}/app-scanner/results", headers=auth_headers(a))
    ).json()
    assert [x["package_name"] for x in mine] == ["com.alpha"]
    their = (
        await client.get(f"{API}/app-scanner/results", headers=auth_headers(b))
    ).json()
    assert [x["package_name"] for x in their] == ["com.bravo"]
    # fetching someone else's scan by id looks like it does not exist
    assert (
        await client.get(
            f"{API}/app-scanner/results/{mine[0]['id']}", headers=auth_headers(b)
        )
    ).status_code == 404
    assert (
        await client.get(
            f"{API}/app-scanner/results/{mine[0]['id']}", headers=auth_headers(a)
        )
    ).status_code == 200
    assert (
        await client.get(
            f"{API}/app-scanner/results/not-a-uuid", headers=auth_headers(a)
        )
    ).status_code == 404
    bad_device = await client.get(
        f"{API}/app-scanner/results",
        headers=auth_headers(a),
        params={"device_id": "zzz"},
    )
    assert bad_device.status_code == 404


@pytest.mark.security
async def test_spyware_check_only_shows_own_apps(
    client, make_user, auth_headers, session_factory
):
    a, b = await make_user("a"), await make_user("b")
    async with session_factory() as s:
        s.add(
            AppScan(
                user_id=a.id, package_name="com.spy", app_name="Spy", is_malicious=True
            )
        )
        s.add(
            AppScan(
                user_id=b.id,
                package_name="com.other",
                app_name="Other",
                is_malicious=True,
            )
        )
        s.add(
            AppScan(
                user_id=None,
                package_name="com.legacy",
                app_name="Legacy",
                is_malicious=True,
            )
        )
        await s.commit()
    j = (
        await client.get(f"{API}/app-scanner/spyware-check", headers=auth_headers(a))
    ).json()
    assert [x["package_name"] for x in j["spyware_apps"]] == [
        "com.spy"
    ]  # no other user's, no orphan rows


@pytest.mark.security
async def test_wifi_history_is_private(client, make_user, auth_headers):
    a, b = await make_user("a"), await make_user("b")
    await client.post(
        f"{API}/wifi/scan",
        headers=auth_headers(a),
        json={"ssid": "HomeNet-A", "encryption_type": "WPA2"},
    )
    await client.post(
        f"{API}/wifi/scan",
        headers=auth_headers(b),
        json={"ssid": "HomeNet-B", "encryption_type": "OPEN"},
    )
    ha = (await client.get(f"{API}/wifi/history", headers=auth_headers(a))).json()
    hb = (await client.get(f"{API}/wifi/history", headers=auth_headers(b))).json()
    assert [x["ssid"] for x in ha] == ["HomeNet-A"] and [x["ssid"] for x in hb] == [
        "HomeNet-B"
    ]
    assert (
        await client.get(
            f"{API}/wifi/history", headers=auth_headers(a), params={"device_id": "x"}
        )
    ).status_code == 404


async def test_wifi_and_scan_inputs_are_bounded(client, make_user, auth_headers):
    h = auth_headers(await make_user("v"))
    assert (
        await client.post(f"{API}/wifi/scan", headers=h, json={"ssid": "s" * 256})
    ).status_code == 422
    empty_pkg = {"apps": [{"package_name": "", "app_name": "x"}]}
    assert (
        await client.post(f"{API}/app-scanner/scan", headers=h, json=empty_pkg)
    ).status_code == 422
    too_many = {
        "apps": [{"package_name": f"p{i}", "app_name": "a"} for i in range(501)]
    }
    assert (
        await client.post(f"{API}/app-scanner/scan", headers=h, json=too_many)
    ).status_code == 422


async def _device(session_factory, user, token):
    async with session_factory() as s:
        d = Device(
            user_id=user.id, device_token=token, device_name="d", platform="android"
        )
        s.add(d)
        await s.commit()
        return str(d.id)


@pytest.mark.security
async def test_network_activity_requires_an_owned_device_and_is_private(
    client, make_user, auth_headers, session_factory
):
    a, b = await make_user("a"), await make_user("b")
    da, db_ = (
        await _device(session_factory, a, "tok-a"),
        await _device(session_factory, b, "tok-b"),
    )
    act = [{"app_package": "p", "destination_domain": "spynet.ru", "bytes_sent": 5}]
    # A cannot write into B's device
    r = await client.post(
        f"{API}/network/activity",
        headers=auth_headers(a),
        json={"device_id": db_, "activities": act},
    )
    assert r.status_code == 404
    r = await client.post(
        f"{API}/network/activity",
        headers=auth_headers(a),
        json={"device_id": da, "activities": act},
    )
    assert r.status_code == 200
    r = await client.post(
        f"{API}/network/activity",
        headers=auth_headers(b),
        json={"device_id": db_, "activities": act},
    )
    assert r.status_code == 200
    ra = (await client.get(f"{API}/network/suspicious", headers=auth_headers(a))).json()
    assert len(ra) == 1 and ra[0]["device_id"] == da
    # B cannot read A's device by passing its id either
    leak = await client.get(
        f"{API}/network/suspicious", headers=auth_headers(b), params={"device_id": da}
    )
    assert leak.json() == []
    bad_id = await client.get(
        f"{API}/network/suspicious",
        headers=auth_headers(a),
        params={"device_id": "nope"},
    )
    assert bad_id.status_code == 404
    neg = [{"bytes_sent": -1}]
    r = await client.post(
        f"{API}/network/activity",
        headers=auth_headers(a),
        json={"device_id": da, "activities": neg},
    )
    assert r.status_code == 422


async def test_scam_call_history_is_private_and_block_is_idempotent(
    client, make_user, auth_headers
):
    a, b = await make_user("a"), await make_user("b")
    h = auth_headers(a)
    for secs in (30, 40):
        await client.post(
            f"{API}/scam-calls/report",
            headers=h,
            json={"caller_number": "+919811111111", "call_duration_seconds": secs},
        )
    assert len((await client.get(f"{API}/scam-calls/history", headers=h)).json()) == 2
    assert (
        await client.get(f"{API}/scam-calls/history", headers=auth_headers(b))
    ).json() == []
    # two rows for the same number used to make this endpoint crash (MultipleResultsFound -> 500)
    for _ in range(2):
        assert (
            await client.post(f"{API}/scam-calls/block/%2B919811111111", headers=h)
        ).status_code == 200
    assert (
        await client.post(f"{API}/scam-calls/block/{'9' * 21}", headers=h)
    ).status_code == 422


async def test_scam_call_input_bounds(client, make_user, auth_headers):
    h = auth_headers(await make_user("c"))
    for bad in (
        {"caller_number": "1" * 21},
        {"caller_number": ""},
        {"caller_number": "1", "call_duration_seconds": -1},
        {"caller_number": "1", "detection_reason": "x" * 1001},
    ):
        assert (
            await client.post(f"{API}/scam-calls/report", headers=h, json=bad)
        ).status_code == 422


async def test_erasure_removes_owned_scans(client, make_user, auth_headers, db):
    u = await make_user("gone")
    h = auth_headers(u)
    await client.post(f"{API}/app-scanner/scan", headers=h, json=apps("zed"))
    await client.post(f"{API}/wifi/scan", headers=h, json={"ssid": "gone-net"})
    r = await client.request(
        "DELETE", f"{API}/auth/me", headers=h, json={"confirm": "DELETE"}
    )
    assert r.status_code == 200, r.text
    assert (await db.execute(select(AppScan))).scalars().all() == []
    assert (await db.execute(select(WifiScan))).scalars().all() == []
