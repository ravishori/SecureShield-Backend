"""F1-C01: a family invitation is matched to a person only through a VERIFIED phone number."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.family import FamilyMember

pytestmark = pytest.mark.integration

API = "/api/v1/family"
PHONE = "+919811100001"


async def _invite(client, inviter_headers, phone=PHONE):
    r = await client.post(
        f"{API}/members",
        json={"member_phone": phone, "relationship": "parent", "can_view_alerts": True},
        headers=inviter_headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _link(db, member_id):
    return (
        await db.execute(
            select(FamilyMember)
            .where(FamilyMember.id == member_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _invitations(client, headers):
    r = await client.get(f"{API}/invitations", headers=headers)
    assert r.status_code == 200
    return r.json()


async def test_verified_phone_is_linked_and_can_accept(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    invitee = await make_user("ver", phone=PHONE)  # verified by default
    m = await _invite(client, auth_headers(inviter))
    assert (await _link(db, m["id"])).member_user_id == invitee.id
    assert len(await _invitations(client, auth_headers(invitee))) == 1
    r = await client.post(
        f"{API}/invitations/{m['id']}/accept", headers=auth_headers(invitee)
    )
    assert r.status_code == 200
    assert (await _link(db, m["id"])).consent_status == "accepted"


async def test_legacy_account_with_unverified_phone_is_not_linked_and_cannot_accept(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    squatter = await make_user("sq", phone=PHONE, phone_verified_at=None)
    m = await _invite(client, auth_headers(inviter))
    link = await _link(db, m["id"])
    assert link.member_user_id is None and link.consent_status == "pending"
    assert await _invitations(client, auth_headers(squatter)) == []
    for verb in ("accept", "decline"):
        r = await client.post(
            f"{API}/invitations/{m['id']}/{verb}", headers=auth_headers(squatter)
        )
        assert (
            r.status_code == 404
        )  # same answer as for an invitation that does not exist
    assert (await _link(db, m["id"])).consent_status == "pending"


async def test_inviter_sees_nothing_of_an_unconsented_link(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    await make_user("sq", phone=PHONE, phone_verified_at=None)
    m = await _invite(client, auth_headers(inviter))
    r = await client.get(
        f"{API}/members/{m['id']}/alerts", headers=auth_headers(inviter)
    )
    assert r.status_code == 404


async def test_the_real_owner_can_accept_after_verifying_the_number(
    client, db, make_user, auth_headers
):
    from datetime import datetime
    from sqlalchemy import update
    from app.models.user import User

    inviter = await make_user("inv")
    owner = await make_user("own", phone=PHONE, phone_verified_at=None)
    m = await _invite(client, auth_headers(inviter))
    assert await _invitations(client, auth_headers(owner)) == []
    async with (
        db.bind.connect() as c
    ):  # the owner proves the number (what /auth/phone/add/confirm does)
        await c.execute(
            update(User)
            .where(User.id == owner.id)
            .values(phone_verified_at=datetime.utcnow())
        )
        await c.commit()
    assert len(await _invitations(client, auth_headers(owner))) == 1
    r = await client.post(
        f"{API}/invitations/{m['id']}/accept", headers=auth_headers(owner)
    )
    assert r.status_code == 200
    assert (await _link(db, m["id"])).member_user_id == owner.id


async def test_another_account_cannot_answer_the_invitation(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    await make_user("ver", phone=PHONE)
    other = await make_user("oth", phone="+919811100002")
    m = await _invite(client, auth_headers(inviter))
    for verb in ("accept", "decline"):
        r = await client.post(
            f"{API}/invitations/{m['id']}/{verb}", headers=auth_headers(other)
        )
        assert r.status_code == 404
    assert (await _link(db, m["id"])).consent_status == "pending"


async def test_a_link_bound_to_one_account_is_not_reassigned_by_phone(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    first = await make_user("first", phone=PHONE)
    m = await _invite(client, auth_headers(inviter))
    # the number later appears on a different verified account (e.g. it was released and re-registered)
    link = await _link(db, m["id"])
    assert link.member_user_id == first.id
    second = await make_user("second", phone="+919811100003")
    # same invited_phone text, but the link is bound to `first`: `second` is not addressed
    from sqlalchemy import update

    async with db.bind.connect() as c:
        await c.execute(
            update(FamilyMember)
            .where(FamilyMember.id == link.id)
            .values(invited_phone="+919811100003")
        )
        await c.commit()
    r = await client.post(
        f"{API}/invitations/{m['id']}/accept", headers=auth_headers(second)
    )
    assert r.status_code == 404
    assert (await _link(db, m["id"])).member_user_id == first.id


async def test_consent_is_required_before_any_data_access(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    invitee = await make_user("ver", phone=PHONE)
    m = await _invite(client, auth_headers(inviter))
    r = await client.get(
        f"{API}/members/{m['id']}/alerts", headers=auth_headers(inviter)
    )
    assert r.status_code == 404  # pending: nothing is shared
    await client.post(
        f"{API}/invitations/{m['id']}/accept", headers=auth_headers(invitee)
    )
    r = await client.get(
        f"{API}/members/{m['id']}/alerts", headers=auth_headers(inviter)
    )
    assert r.status_code == 200


async def test_answered_invitations_are_not_offered_again_and_a_decline_can_be_revoked_only_by_the_member(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    invitee = await make_user("ver", phone=PHONE)
    other = await make_user("oth", phone="+919811100004")
    m = await _invite(client, auth_headers(inviter))
    await client.post(
        f"{API}/invitations/{m['id']}/accept", headers=auth_headers(invitee)
    )
    assert await _invitations(client, auth_headers(invitee)) == []  # no longer pending
    again = await client.post(
        f"{API}/invitations/{m['id']}/accept", headers=auth_headers(invitee)
    )
    assert again.status_code == 200  # idempotent for the same person
    assert (
        await client.post(f"{API}/links/{m['id']}/revoke", headers=auth_headers(other))
    ).status_code == 404
    assert (
        await client.post(
            f"{API}/links/{m['id']}/revoke", headers=auth_headers(invitee)
        )
    ).status_code == 200
    assert (await _link(db, m["id"])).consent_status == "declined"


async def test_existing_relationship_survives_for_an_account_with_an_unverified_phone(
    client, db, make_user, auth_headers
):
    """A relationship the member already accepted is preserved and can still be revoked, whatever the phone state."""
    inviter = await make_user("inv")
    member = await make_user("mem", phone=PHONE, phone_verified_at=None)
    link = FamilyMember(
        user_id=inviter.id,
        member_user_id=member.id,
        invited_phone=PHONE,
        consent_status="accepted",
    )
    db.add(link)
    await db.commit()
    r = await client.post(f"{API}/links/{link.id}/revoke", headers=auth_headers(member))
    assert r.status_code == 200
    assert (await _link(db, link.id)).consent_status == "declined"


async def test_a_pending_link_matched_before_the_fix_needs_verification_to_be_answered(
    client, db, make_user, auth_headers
):
    inviter = await make_user("inv")
    legacy = await make_user("leg", phone=PHONE, phone_verified_at=None)
    link = FamilyMember(
        user_id=inviter.id,
        member_user_id=legacy.id,  # bound earlier by an unverified phone match
        invited_phone=PHONE,
        consent_status="pending",
    )
    db.add(link)
    await db.commit()
    assert await _invitations(client, auth_headers(legacy)) == []
    r = await client.post(
        f"{API}/invitations/{link.id}/accept", headers=auth_headers(legacy)
    )
    assert r.status_code == 404
    row = await _link(db, link.id)
    assert (
        row.member_user_id == legacy.id and row.consent_status == "pending"
    )  # preserved, not reassigned
