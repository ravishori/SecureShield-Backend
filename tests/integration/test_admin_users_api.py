"""Admin stats + user control (static X-Admin-Token)."""

import pytest
from sqlalchemy import select

from app.models.user import User

pytestmark = pytest.mark.integration
ADMIN = {"X-Admin-Token": "test-admin-token"}
BASE = "/api/v1/admin"


@pytest.mark.security
@pytest.mark.parametrize("path", ["/stats", "/users"])
async def test_requires_the_admin_token(client, make_user, auth_headers, path):
    assert (await client.get(BASE + path)).status_code == 401
    assert (
        await client.get(BASE + path, headers={"X-Admin-Token": "wrong"})
    ).status_code == 401
    assert (
        await client.get(BASE + path, headers={"X-Admin-Token": "test-admin-token "})
    ).status_code == 401
    user_jwt = auth_headers(
        await make_user("plain")
    )  # an ordinary user's JWT is not admin
    assert (await client.get(BASE + path, headers=user_jwt)).status_code == 401


@pytest.mark.security
async def test_status_change_requires_admin_and_unconfigured_token_is_503(
    client, make_user, monkeypatch
):
    u = await make_user("t")
    assert (
        await client.patch(f"{BASE}/users/{u.id}/status", json={"is_active": False})
    ).status_code == 401
    from app.config import settings

    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    assert (
        await client.get(BASE + "/stats", headers={"X-Admin-Token": ""})
    ).status_code == 503


async def test_stats_counts(client, make_user):
    await make_user("a")
    await make_user("b", is_active=False)
    await make_user("c", senior_mode=True)
    j = (await client.get(BASE + "/stats", headers=ADMIN)).json()
    assert (
        j["users_total"],
        j["users_active"],
        j["users_disabled"],
        j["users_senior_mode"],
    ) == (3, 2, 1, 1)


async def test_list_search_filter_and_pagination_never_leak_secrets(client, make_user):
    for i in range(5):
        await make_user(f"u{i}", email=f"person{i}@example.com")
    await make_user("off", email="off@example.com", is_active=False)
    r = (await client.get(BASE + "/users", headers=ADMIN, params={"limit": 2})).json()
    assert r["total"] == 6 and len(r["items"]) == 2
    assert not {"hashed_password", "password"} & set(r["items"][0])
    assert (
        await client.get(BASE + "/users", headers=ADMIN, params={"q": "off@"})
    ).json()["total"] == 1
    assert (
        await client.get(BASE + "/users", headers=ADMIN, params={"is_active": "false"})
    ).json()["total"] == 1
    page2 = (
        await client.get(
            BASE + "/users", headers=ADMIN, params={"limit": 4, "offset": 4}
        )
    ).json()
    assert len(page2["items"]) == 2


@pytest.mark.security
async def test_search_wildcards_are_literal_and_bounds_enforced(client, make_user):
    await make_user("w", email="plain@example.com")
    assert (await client.get(BASE + "/users", headers=ADMIN, params={"q": "%"})).json()[
        "total"
    ] == 0
    assert (
        await client.get(BASE + "/users", headers=ADMIN, params={"limit": 101})
    ).status_code == 422
    assert (
        await client.get(BASE + "/users", headers=ADMIN, params={"q": "x" * 101})
    ).status_code == 422


async def test_disable_blocks_the_user_immediately_and_enable_restores(
    client, make_user, auth_headers, db
):
    u = await make_user("victim")
    h = auth_headers(u)
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 200
    r = await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": False}
    )
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 401
    r = await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": True}
    )
    assert r.status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 200
    assert (
        await db.execute(select(User).where(User.id == u.id))
    ).scalar_one().is_active is True


async def test_status_unknown_or_malformed_id_is_404_and_bad_body_422(
    client, make_user
):
    for uid in ("not-a-uuid", "00000000-0000-0000-0000-000000000000"):
        assert (
            await client.patch(
                f"{BASE}/users/{uid}/status", headers=ADMIN, json={"is_active": False}
            )
        ).status_code == 404
    u = await make_user("b")
    assert (
        await client.patch(f"{BASE}/users/{u.id}/status", headers=ADMIN, json={})
    ).status_code == 422


async def test_status_changes_are_audited_and_the_audit_is_admin_only(
    client, make_user, db
):
    from sqlalchemy import select

    from app.models.admin_audit import AdminAuditLog

    u = await make_user("aud")
    assert (await client.get(f"{BASE}/audit")).status_code == 401
    await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": False}
    )
    await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": False}
    )  # no-op: not logged
    await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": True}
    )
    j = (await client.get(f"{BASE}/audit", headers=ADMIN)).json()
    assert [i["action"] for i in j["items"]] == ["user.enable", "user.disable"] and j[
        "total"
    ] == 2
    assert all(i["target_user_id"] == str(u.id) and i["client_ip"] for i in j["items"])
    only = (
        await client.get(
            f"{BASE}/audit", headers=ADMIN, params={"action": "user.disable"}
        )
    ).json()
    assert only["total"] == 1
    assert (
        await client.get(
            f"{BASE}/audit", headers=ADMIN, params={"target_user_id": "zzz"}
        )
    ).status_code == 422
    assert (
        await client.get(f"{BASE}/audit", headers=ADMIN, params={"limit": 201})
    ).status_code == 422
    assert "ADMIN" not in str(
        (await db.execute(select(AdminAuditLog.detail))).scalars().all()
    ).upper().replace("ADMIN_", "")


async def test_audit_rows_survive_account_erasure(client, make_user, auth_headers, db):
    from sqlalchemy import select

    from app.models.admin_audit import AdminAuditLog

    u = await make_user("gone")
    await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": True}
    )  # no change -> nothing
    await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": False}
    )
    await client.patch(
        f"{BASE}/users/{u.id}/status", headers=ADMIN, json={"is_active": True}
    )
    r = await client.request(
        "DELETE", "/api/v1/auth/me", headers=auth_headers(u), json={"confirm": "DELETE"}
    )
    assert r.status_code == 200, r.text
    assert (
        len((await db.execute(select(AdminAuditLog))).scalars().all()) == 2
    )  # history is kept


async def test_console_page_is_public_secret_free_and_locked_down(client):
    r = await client.get(f"{BASE}/console")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    assert (
        "default-src 'none'" in csp
        and "frame-ancestors 'none'" in csp
        and "connect-src 'self'" in csp
    )
    assert (
        r.headers["cache-control"] == "no-store"
        and r.headers["x-content-type-options"] == "nosniff"
    )
    body = r.text
    assert (
        "test-admin-token" not in body
        and "localStorage" not in body
        and "sessionStorage" not in body
    )
    assert (
        "innerHTML" not in body and "document.write" not in body and "eval(" not in body
    )  # data goes in via textContent
    assert (
        "<script src" not in body.lower()
        and "http://" not in body
        and "https://" not in body
    )
    # the page is only a shell: the data endpoints behind it still need the token
    assert (await client.get(f"{BASE}/users")).status_code == 401
