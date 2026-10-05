"""Family: consent-gated linking, invitations, dashboard, ownership and bounds."""

import pytest
from sqlalchemy import select

from app.models.alert import Alert, AlertSeverity, AlertType
from app.models.family import FamilyMember

pytestmark = pytest.mark.integration
F = "/api/v1/family"


async def alert(
    session_factory,
    user,
    sev=AlertSeverity.info,
    read=False,
    dismissed=False,
    title="a",
):
    async with session_factory() as s:
        s.add(
            Alert(
                user_id=user.id,
                alert_type=AlertType.phishing,
                title=title,
                message="m",
                severity=sev,
                is_read=read,
                is_dismissed=dismissed,
            )
        )
        await s.commit()


async def invite(client, h, phone, **kw):
    return await client.post(
        f"{F}/members",
        headers=h,
        json={"member_phone": phone, "can_view_alerts": True, **kw},
    )


async def link(client, make_user, auth_headers):
    parent = await make_user("parent")
    kid = await make_user("kid")
    r = await invite(client, auth_headers(parent), kid.phone, relationship="son")
    assert r.status_code == 200, r.text
    return parent, kid, r.json()


@pytest.mark.security
async def test_cannot_read_anyones_alerts_without_their_consent(
    client, make_user, auth_headers, session_factory
):
    parent, kid, m = await link(client, make_user, auth_headers)
    await alert(session_factory, kid, title="secret bank alert")
    assert m["consent_status"] == "pending"
    r = await client.get(f"{F}/members/{m['id']}/alerts", headers=auth_headers(parent))
    assert (
        r.status_code == 404
    )  # regression: this used to return the other person's alerts
    dash = (await client.get(f"{F}/dashboard", headers=auth_headers(parent))).json()
    assert (
        dash["members"][0]["alerts_visible"] is False
        and dash["members"][0]["latest_alert_title"] is None
    )
    assert dash["pending_invitations_sent"] == 1


async def test_accept_enables_alerts_and_dashboard_counts(
    client, make_user, auth_headers, session_factory
):
    parent, kid, m = await link(client, make_user, auth_headers)
    await alert(session_factory, kid, AlertSeverity.critical, title="crit")
    await alert(session_factory, kid, AlertSeverity.info, read=True, title="old")
    await alert(
        session_factory, kid, AlertSeverity.warning, dismissed=True, title="gone"
    )
    inv = (await client.get(f"{F}/invitations", headers=auth_headers(kid))).json()
    assert (
        len(inv) == 1
        and inv[0]["id"] == m["id"]
        and inv[0]["inviter_name"] == parent.full_name
    )
    assert (
        await client.post(
            f"{F}/invitations/{m['id']}/accept", headers=auth_headers(kid)
        )
    ).status_code == 200
    assert (
        await client.get(f"{F}/invitations", headers=auth_headers(kid))
    ).json() == []
    got = (
        await client.get(f"{F}/members/{m['id']}/alerts", headers=auth_headers(parent))
    ).json()
    assert {a["title"] for a in got} == {
        "crit",
        "old",
    }  # dismissed alerts are not shown
    d = (await client.get(f"{F}/dashboard", headers=auth_headers(parent))).json()
    row = d["members"][0]
    assert (
        row["alerts_visible"]
        and row["unread_alerts"] == 1
        and row["critical_alerts"] == 1
    )
    assert (
        d["total_unread_alerts"] == 1
        and d["total_critical_alerts"] == 1
        and row["latest_alert_title"]
    )


async def test_decline_and_later_revocation_cut_access(
    client, make_user, auth_headers, session_factory
):
    parent, kid, m = await link(client, make_user, auth_headers)
    await alert(session_factory, kid)
    assert (
        await client.post(
            f"{F}/invitations/{m['id']}/decline", headers=auth_headers(kid)
        )
    ).status_code == 200
    assert (
        await client.get(f"{F}/members/{m['id']}/alerts", headers=auth_headers(parent))
    ).status_code == 404
    await client.post(f"{F}/invitations/{m['id']}/accept", headers=auth_headers(kid))
    assert (
        await client.get(f"{F}/members/{m['id']}/alerts", headers=auth_headers(parent))
    ).status_code == 200
    assert (
        await client.post(f"{F}/links/{m['id']}/revoke", headers=auth_headers(kid))
    ).status_code == 200
    assert (
        await client.get(f"{F}/members/{m['id']}/alerts", headers=auth_headers(parent))
    ).status_code == 404


@pytest.mark.security
async def test_only_the_invitee_can_answer_an_invitation(
    client, make_user, auth_headers
):
    parent, kid, m = await link(client, make_user, auth_headers)
    stranger = await make_user("stranger")
    for who in (parent, stranger):  # the inviter cannot consent on the invitee's behalf
        assert (
            await client.post(
                f"{F}/invitations/{m['id']}/accept", headers=auth_headers(who)
            )
        ).status_code == 404
        assert (
            await client.post(f"{F}/links/{m['id']}/revoke", headers=auth_headers(who))
        ).status_code == 404
    assert (
        await client.get(f"{F}/invitations", headers=auth_headers(stranger))
    ).json() == []


async def test_invite_to_unregistered_phone_is_claimed_when_that_person_joins(
    client, make_user, auth_headers, session_factory
):
    parent = await make_user("p")
    r = await invite(client, auth_headers(parent), "9876543210")  # normalised to +91...
    assert r.status_code == 200 and r.json()["member_user_id"] is None
    newbie = await make_user("new", phone="+919876543210")
    inv = (await client.get(f"{F}/invitations", headers=auth_headers(newbie))).json()
    assert len(inv) == 1
    await client.post(
        f"{F}/invitations/{inv[0]['id']}/accept", headers=auth_headers(newbie)
    )
    await alert(session_factory, newbie, title="hello")
    got = await client.get(
        f"{F}/members/{r.json()['id']}/alerts", headers=auth_headers(parent)
    )
    assert [a["title"] for a in got.json()] == ["hello"]


async def test_validation_duplicates_self_and_limits(client, make_user, auth_headers):
    p = await make_user("v")
    h = auth_headers(p)
    assert (await invite(client, h, "abc")).status_code == 422
    assert (await invite(client, h, p.phone)).status_code == 422
    assert (await client.post(f"{F}/members", headers=h, json={})).status_code == 422
    assert (
        await client.post(f"{F}/members", headers=h, json={"nickname": "Mum"})
    ).status_code == 200
    assert (await invite(client, h, "+919000000001")).status_code == 200
    assert (
        await invite(client, h, "9000000001")
    ).status_code == 409  # same number, other spelling
    for i in range(18):
        assert (
            await client.post(f"{F}/members", headers=h, json={"nickname": f"n{i}"})
        ).status_code == 200
    assert (
        await client.post(f"{F}/members", headers=h, json={"nickname": "one too many"})
    ).status_code == 409


async def test_member_crud_is_owner_scoped_and_ids_are_validated(
    client, make_user, auth_headers
):
    parent, kid, m = await link(client, make_user, auth_headers)
    other = await make_user("o")
    assert (await client.get(f"{F}/members", headers=auth_headers(other))).json() == []
    assert (
        await client.delete(f"{F}/members/{m['id']}", headers=auth_headers(other))
    ).status_code == 404
    assert (
        await client.delete(f"{F}/members/not-a-uuid", headers=auth_headers(parent))
    ).status_code == 404
    assert (
        await client.get(f"{F}/members/not-a-uuid/alerts", headers=auth_headers(parent))
    ).status_code == 404
    assert (await client.get(f"{F}/members")).status_code in (401, 403)
    assert (
        await client.delete(f"{F}/members/{m['id']}", headers=auth_headers(parent))
    ).status_code == 200


@pytest.mark.security
async def test_erasing_the_invitee_leaves_no_claimable_or_accepted_link(
    client, make_user, auth_headers, db
):
    parent, kid, m = await link(client, make_user, auth_headers)
    await client.post(f"{F}/invitations/{m['id']}/accept", headers=auth_headers(kid))
    r = await client.request(
        "DELETE",
        "/api/v1/auth/me",
        headers=auth_headers(kid),
        json={"confirm": "DELETE"},
    )
    assert r.status_code == 200, r.text
    row = (await db.execute(select(FamilyMember))).scalar_one()
    assert (
        row.member_user_id is None
        and row.invited_phone is None
        and row.consent_status == "declined"
    )
