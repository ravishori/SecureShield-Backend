"""Senior Citizen / guardian protection: config persistence, validation, guardian alert delivery."""

import pytest

import app.routers.elderly_protection as elderly

pytestmark = pytest.mark.integration
E = "/api/v1/elderly"

CFG = {
    "enabled": True,
    "guardian_name": "Asha",
    "guardian_phone": "+919800000000",
    "guardian_email": "Asha@Example.com",
    "alert_threshold": 40,
}
ALERT = {
    "package_name": "com.bad.app",
    "app_name": "Bad App",
    "risk_score": 80,
    "risk_level": "high",
    "risk_tags": ["screen overlay", "sms read"],
    "clone_verdict": "likely_clone",
}


@pytest.fixture
def sent(monkeypatch):
    log = {"sms": [], "email": []}

    async def sms(phone, body):
        log["sms"].append((phone, body))
        return True

    async def email(to, subject, body):
        log["email"].append((to, subject, body))
        return True

    monkeypatch.setattr(elderly.notifications, "send_sms", sms)
    monkeypatch.setattr(elderly.notifications, "send_email", email)
    return log


async def test_requires_auth(client):
    assert (await client.get(f"{E}/config")).status_code in (401, 403)
    assert (await client.post(f"{E}/guardian-alert", json=ALERT)).status_code in (
        401,
        403,
    )


async def test_defaults_then_update_roundtrip_and_normalisation(
    client, make_user, auth_headers
):
    h = auth_headers(await make_user("sr"))
    d = (await client.get(f"{E}/config", headers=h)).json()
    assert (
        d["enabled"] is False and d["simplified_ui"] is True and d["large_text"] is True
    )
    r = await client.put(f"{E}/config", headers=h, json=CFG)
    assert r.status_code == 200
    got = (await client.get(f"{E}/config", headers=h)).json()
    assert (
        got["enabled"]
        and got["guardian_email"] == "asha@example.com"
        and got["guardian_phone"] == "+919800000000"
    )
    # blank contacts clear the field
    await client.put(
        f"{E}/config",
        headers=h,
        json={**CFG, "guardian_phone": "  ", "guardian_email": ""},
    )
    got = (await client.get(f"{E}/config", headers=h)).json()
    assert got["guardian_phone"] is None and got["guardian_email"] is None


async def test_config_is_per_user(client, make_user, auth_headers):
    a, b = await make_user("a"), await make_user("b")
    await client.put(f"{E}/config", headers=auth_headers(a), json=CFG)
    assert (await client.get(f"{E}/config", headers=auth_headers(b))).json()[
        "enabled"
    ] is False


@pytest.mark.parametrize(
    "patch",
    [
        {"guardian_phone": "abc"},
        {"guardian_phone": "1"},
        {"guardian_email": "not-an-email"},
        {"guardian_email": "a@b"},
        {"alert_threshold": 101},
        {"alert_threshold": -1},
        {"guardian_name": "x" * 101},
    ],
)
async def test_config_validation(client, make_user, auth_headers, patch):
    h = auth_headers(await make_user("v"))
    assert (
        await client.put(f"{E}/config", headers=h, json={**CFG, **patch})
    ).status_code == 422


async def test_alert_is_delivered_by_sms_and_email_with_sanitised_content(
    client, make_user, auth_headers, sent
):
    u = await make_user("grandpa", full_name="Grand\npa")
    h = auth_headers(u)
    await client.put(f"{E}/config", headers=h, json=CFG)
    r = await client.post(
        f"{E}/guardian-alert", headers=h, json={**ALERT, "app_name": "Bad\r\nApp"}
    )
    assert r.status_code == 202 and r.json()["status"] == "queued"
    (phone, body), (to, subject, ebody) = sent["sms"][0], sent["email"][0]
    assert (
        phone == "+919800000000"
        and to == "asha@example.com"
        and subject == "SecureShield Guardian Alert"
    )
    assert (
        "Dear Asha," in body
        and "'Bad App'" in body
        and "80/100" in body
        and "HIGH" in body
    )
    assert "Likely Clone" in body and "Grand pa" in body and "\r" not in body
    assert body == ebody


async def test_channels_are_independent_and_failures_do_not_break_the_request(
    client, make_user, auth_headers, monkeypatch
):
    calls = []

    async def sms(phone, body):
        calls.append("sms")
        return False

    async def email(to, subject, body):
        calls.append("email")
        raise RuntimeError("provider down")

    monkeypatch.setattr(elderly.notifications, "send_sms", sms)
    monkeypatch.setattr(elderly.notifications, "send_email", email)
    h = auth_headers(await make_user("f"))
    await client.put(f"{E}/config", headers=h, json=CFG)
    assert (
        await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)
    ).status_code == 202
    assert calls == ["sms", "email"]  # the email channel still ran after SMS failed


@pytest.mark.parametrize(
    "setup, expect",
    [
        ({"enabled": False}, "disabled"),
        ({"auto_alert_guardian": False}, "auto-alert off"),
        ({"guardian_phone": None, "guardian_email": None}, "no guardian"),
        ({"alert_threshold": 90}, "threshold"),
    ],
)
async def test_alert_is_skipped_when_policy_says_so(
    client, make_user, auth_headers, sent, setup, expect
):
    h = auth_headers(await make_user("p"))
    await client.put(f"{E}/config", headers=h, json={**CFG, **setup})
    r = await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)
    assert (
        r.status_code == 202
        and r.json()["status"] == "skipped"
        and expect in r.json()["reason"]
    )
    assert sent == {"sms": [], "email": []}


async def test_alert_input_bounds(client, make_user, auth_headers, sent):
    h = auth_headers(await make_user("b"))
    await client.put(f"{E}/config", headers=h, json=CFG)
    for bad in (
        {"risk_score": 101},
        {"risk_score": -1},
        {"risk_level": "extreme"},
        {"app_name": ""},
        {"app_name": "x" * 101},
        {"risk_tags": ["t"] * 11},
        {"package_name": ""},
    ):
        assert (
            await client.post(f"{E}/guardian-alert", headers=h, json={**ALERT, **bad})
        ).status_code == 422
    assert sent == {"sms": [], "email": []}


@pytest.mark.security
async def test_guardian_alerts_are_rate_limited_per_user(
    client, make_user, auth_headers, sent
):
    h = auth_headers(await make_user("spam"))
    await client.put(f"{E}/config", headers=h, json=CFG)
    codes = [
        (await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)).status_code
        for _ in range(12)
    ]
    assert codes[:10] == [202] * 10 and codes[10:] == [429, 429]
    assert len(sent["sms"]) == 10
    other = auth_headers(await make_user("other"))
    await client.put(f"{E}/config", headers=other, json=CFG)
    assert (
        await client.post(f"{E}/guardian-alert", headers=other, json=ALERT)
    ).status_code == 202


@pytest.mark.security
async def test_delivery_logs_never_contain_guardian_contact_or_message(
    client, make_user, auth_headers, monkeypatch, capsys
):
    import app.services.notifications as n

    lines = []

    class Rec:
        def _r(self, m, *a, **k):
            lines.append(m % a if a else str(m))

        debug = info = warning = error = exception = critical = _r

    monkeypatch.setattr(n, "logger", Rec())
    monkeypatch.setattr(elderly, "logger", Rec())
    monkeypatch.setattr(
        n, "_send_sms_sync", lambda phone, body: n.logger.error("sms failed") or False
    )

    async def no_email(*a, **k):
        return False

    monkeypatch.setattr(n, "_send_email_resend", no_email)
    monkeypatch.setattr(n, "_send_email_smtp_sync", lambda *a: False)
    h = auth_headers(await make_user("l"))
    await client.put(f"{E}/config", headers=h, json=CFG)
    await client.post(f"{E}/guardian-alert", headers=h, json=ALERT)
    out = capsys.readouterr()
    blob = "\n".join(lines) + out.out + out.err
    assert (
        "+919800000000" not in blob
        and "asha@example.com" not in blob.lower()
        and "Bad App" not in blob
    )
