"""Devices + alerts + panic fan-out to emergency contacts."""

import pytest

import app.routers.alerts as alerts_router
from app.models.alert import Alert, AlertSeverity, AlertType

pytestmark = pytest.mark.integration
API = "/api/v1"


async def add_alert(session_factory, user, **kw):
    async with session_factory() as s:
        a = Alert(
            user_id=user.id,
            alert_type=kw.get("t", AlertType.phishing),
            title=kw.get("title", "t"),
            message="m",
            severity=kw.get("sev", AlertSeverity.info),
        )
        s.add(a)
        await s.commit()
        return str(a.id)


# ----------------------------------------------------------------- devices
async def test_register_update_list_roundtrip(client, make_user, auth_headers):
    h = auth_headers(await make_user("d"))
    r = await client.post(
        f"{API}/devices/register",
        headers=h,
        json={"device_token": "token-0001", "device_name": "Pixel"},
    )
    assert r.status_code == 200, r.text
    dev = r.json()
    again = await client.post(
        f"{API}/devices/register",
        headers=h,
        json={"device_token": "token-0001", "os_version": "14"},
    )
    assert again.json()["id"] == dev["id"] and again.json()["os_version"] == "14"
    assert len((await client.get(f"{API}/devices/", headers=h)).json()) == 1
    up = await client.patch(
        f"{API}/devices/{dev['id']}", headers=h, json={"device_name": "Renamed"}
    )
    assert up.json()["device_name"] == "Renamed"


@pytest.mark.security
async def test_a_device_token_registered_to_another_account_is_not_handed_out(
    client, make_user, auth_headers
):
    a, b = await make_user("a"), await make_user("b")
    mine = (
        await client.post(
            f"{API}/devices/register",
            headers=auth_headers(a),
            json={"device_token": "shared-token-1"},
        )
    ).json()
    r = await client.post(
        f"{API}/devices/register",
        headers=auth_headers(b),
        json={"device_token": "shared-token-1"},
    )
    assert (
        r.status_code == 409
        and mine["id"] not in r.text
        and "shared-token-1" not in r.text
    )
    assert (await client.get(f"{API}/devices/", headers=auth_headers(b))).json() == []
    assert (
        await client.patch(
            f"{API}/devices/{mine['id']}",
            headers=auth_headers(b),
            json={"device_name": "x"},
        )
    ).status_code == 404


async def test_device_validation_and_bad_ids(client, make_user, auth_headers):
    h = auth_headers(await make_user("v"))
    for bad in (
        {"device_token": "x"},
        {"device_token": "t" * 513},
        {"device_token": "token-0002", "device_name": "n" * 256},
    ):
        assert (
            await client.post(f"{API}/devices/register", headers=h, json=bad)
        ).status_code == 422
    assert (
        await client.patch(f"{API}/devices/not-a-uuid", headers=h, json={})
    ).status_code == 404
    assert (await client.get(f"{API}/devices/")).status_code in (401, 403)


# ------------------------------------------------------------------ alerts
async def test_alert_lifecycle_is_owner_only(
    client, make_user, auth_headers, session_factory
):
    a, b = await make_user("a"), await make_user("b")
    aid = await add_alert(session_factory, a)
    ha, hb = auth_headers(a), auth_headers(b)
    listed = (await client.get(f"{API}/alerts/", headers=ha)).json()
    assert (
        listed["total"] == 1
        and (await client.get(f"{API}/alerts/", headers=hb)).json()["total"] == 0
    )
    for verb, path in (
        ("PATCH", f"/alerts/{aid}/read"),
        ("PATCH", f"/alerts/{aid}/dismiss"),
        ("DELETE", f"/alerts/{aid}"),
    ):
        assert (await client.request(verb, API + path, headers=hb)).status_code == 404
    assert (await client.patch(f"{API}/alerts/{aid}/read", headers=ha)).json()[
        "is_read"
    ] is True
    assert (await client.patch(f"{API}/alerts/{aid}/dismiss", headers=ha)).json()[
        "is_dismissed"
    ] is True
    assert (await client.delete(f"{API}/alerts/{aid}", headers=ha)).status_code == 200


async def test_alert_malformed_ids_are_404_not_500(client, make_user, auth_headers):
    h = auth_headers(await make_user("m"))
    for verb, path in (
        ("PATCH", "/alerts/zzz/read"),
        ("PATCH", "/alerts/zzz/dismiss"),
        ("DELETE", "/alerts/zzz"),
    ):
        assert (await client.request(verb, API + path, headers=h)).status_code == 404


# ------------------------------------------------------------------- panic
@pytest.fixture
def sent(monkeypatch):
    log = {"sms": [], "email": []}

    async def sms(to, body):
        log["sms"].append((to, body))
        return True

    async def email(to, subject, body):
        log["email"].append((to, subject, body))
        return True

    monkeypatch.setattr(alerts_router.notifications, "send_sms", sms)
    monkeypatch.setattr(alerts_router.notifications, "send_email", email)
    return log


async def contact(client, h, **body):
    r = await client.post(
        f"{API}/emergency-contacts", headers=h, json={"name": "Mum", **body}
    )
    assert r.status_code in (200, 201), r.text


async def test_panic_notifies_only_the_users_own_contacts_with_location(
    client, make_user, auth_headers, sent
):
    u, other = await make_user("p", full_name="Priya"), await make_user("o")
    await contact(
        client, auth_headers(u), phone="+919811111111", email="mum@example.com"
    )
    await contact(client, auth_headers(u), phone="+919822222222")
    await contact(client, auth_headers(other), phone="+919833333333")
    r = await client.post(
        f"{API}/alerts/panic",
        headers=auth_headers(u),
        json={"latitude": 18.5204, "longitude": 73.8567, "message": "Help me"},
    )
    assert r.status_code == 200 and r.json()["severity"] == "critical"
    assert sorted(p for p, _ in sent["sms"]) == ["+919811111111", "+919822222222"]
    assert [e[0] for e in sent["email"]] == ["mum@example.com"]
    body = sent["sms"][0][1]
    assert (
        "Priya" in body
        and "Help me" in body
        and "18.52040,73.85670" in body
        and "112" in body
    )


async def test_panic_with_no_contacts_still_records_the_alert(
    client, make_user, auth_headers, sent
):
    h = auth_headers(await make_user("alone"))
    assert (
        await client.post(f"{API}/alerts/panic", headers=h, json={})
    ).status_code == 200
    assert sent == {"sms": [], "email": []}
    assert (await client.get(f"{API}/alerts/", headers=h)).json()["total"] == 1


async def test_zero_coordinates_are_kept_and_bounds_are_enforced(
    client, make_user, auth_headers, sent
):
    h = auth_headers(await make_user("z"))
    r = await client.post(
        f"{API}/alerts/panic", headers=h, json={"latitude": 0, "longitude": 0}
    )
    assert r.json()["extra_data"]["latitude"] == 0
    for bad in ({"latitude": 91}, {"longitude": -181}, {"message": "x" * 501}):
        assert (
            await client.post(f"{API}/alerts/panic", headers=h, json=bad)
        ).status_code == 422


async def test_one_failing_channel_does_not_stop_the_rest_or_the_request(
    client, make_user, auth_headers, monkeypatch
):
    calls = []

    async def sms(to, body):
        calls.append(("sms", to))
        raise RuntimeError("twilio down")

    async def email(to, subject, body):
        calls.append(("email", to))
        return True

    monkeypatch.setattr(alerts_router.notifications, "send_sms", sms)
    monkeypatch.setattr(alerts_router.notifications, "send_email", email)
    h = auth_headers(await make_user("f"))
    await contact(client, h, phone="+919811111111", email="a@example.com")
    await contact(client, h, phone="+919822222222", email="b@example.com")
    assert (
        await client.post(f"{API}/alerts/panic", headers=h, json={})
    ).status_code == 200
    assert [c for c in calls if c[0] == "email"] == [
        ("email", "a@example.com"),
        ("email", "b@example.com"),
    ]
    assert len([c for c in calls if c[0] == "sms"]) == 2


@pytest.mark.security
async def test_panic_is_rate_limited_per_user_and_text_is_sanitised(
    client, make_user, auth_headers, sent
):
    h = auth_headers(await make_user("rl", full_name="Eve\r\nBCC: x"))
    await contact(client, h, phone="+919811111111")
    codes = [
        (
            await client.post(
                f"{API}/alerts/panic", headers=h, json={"message": "a\r\nb"}
            )
        ).status_code
        for _ in range(11)
    ]
    assert codes[:10] == [200] * 10 and codes[10] == 429
    assert (
        all("\r" not in body for _, body in sent["sms"])
        and "Eve BCC: x" in sent["sms"][0][1]
    )
