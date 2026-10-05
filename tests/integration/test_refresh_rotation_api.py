"""Refresh-token rotation: one use per token, replay revokes the whole login lineage."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models.refresh_token import RefreshTokenUse, RevokedTokenFamily
from app.routers.auth import create_token, create_tokens

pytestmark = pytest.mark.integration
REFRESH = "/api/v1/auth/refresh"
ME = "/api/v1/auth/me"


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


async def refresh(client, token):
    return await client.post(REFRESH, json={"refresh_token": token})


async def test_each_refresh_token_works_exactly_once_and_chain_continues(
    client, make_user
):
    u = await make_user("rot")
    t0 = create_tokens(str(u.id), u.email)
    r1 = await refresh(client, t0["refresh_token"])
    assert r1.status_code == 200
    assert r1.json()["refresh_token"] != t0["refresh_token"]
    r2 = await refresh(client, r1.json()["refresh_token"])
    assert r2.status_code == 200
    assert (
        await client.get(ME, headers=bearer(r2.json()["access_token"]))
    ).status_code == 200


@pytest.mark.security
async def test_replaying_a_used_token_is_rejected_and_revokes_the_family(
    client, make_user, db
):
    u = await make_user("replay")
    t0 = create_tokens(str(u.id), u.email)
    legit = await refresh(client, t0["refresh_token"])
    assert legit.status_code == 200
    # attacker (or a buggy client) presents the already-used token
    assert (await refresh(client, t0["refresh_token"])).status_code == 401
    # ...which also kills the newer token of the same login: the user must sign in again
    assert (await refresh(client, legit.json()["refresh_token"])).status_code == 401
    fams = (await db.execute(select(RevokedTokenFamily))).scalars().all()
    assert len(fams) == 1 and fams[0].user_id == u.id


async def test_a_separate_login_is_unaffected_by_another_familys_revocation(
    client, make_user
):
    u = await make_user("fams")
    phone = create_tokens(str(u.id), u.email)
    laptop = create_tokens(str(u.id), u.email)
    await refresh(client, phone["refresh_token"])
    await refresh(
        client, phone["refresh_token"]
    )  # replay -> only the phone family dies
    assert (await refresh(client, laptop["refresh_token"])).status_code == 200


@pytest.mark.security
async def test_tokens_without_jti_or_family_cannot_be_exchanged(client, make_user):
    u = await make_user("legacy")
    legacy = create_token(
        {"sub": str(u.id), "type": "refresh", "identifier": u.email}, timedelta(days=1)
    )
    assert (await refresh(client, legacy)).status_code == 401
    half = create_token(
        {"sub": str(u.id), "type": "refresh", "jti": "not-a-uuid", "fam": "x"},
        timedelta(days=1),
    )
    assert (await refresh(client, half)).status_code == 401


async def test_concurrent_exchange_of_one_token_succeeds_at_most_once(
    client, make_user
):
    import asyncio

    u = await make_user("race")
    t0 = create_tokens(str(u.id), u.email)
    rs = await asyncio.gather(*[refresh(client, t0["refresh_token"]) for _ in range(5)])
    assert sorted(r.status_code for r in rs).count(200) == 1


async def test_expired_bookkeeping_rows_are_pruned(client, make_user, session_factory):
    from datetime import datetime
    import uuid

    u = await make_user("prune")
    async with session_factory() as s:
        s.add(
            RefreshTokenUse(
                jti=uuid.uuid4(),
                family_id=uuid.uuid4(),
                user_id=u.id,
                expires_at=datetime.utcnow() - timedelta(days=1),
            )
        )
        await s.commit()
    await refresh(client, create_tokens(str(u.id), u.email)["refresh_token"])
    async with session_factory() as s:
        rows = (await s.execute(select(RefreshTokenUse))).scalars().all()
    assert len(rows) == 1  # only the fresh exchange remains


async def test_deleted_account_cannot_rotate_and_erasure_removes_bookkeeping(
    client, make_user, auth_headers, db
):
    u = await make_user("erase")
    t0 = create_tokens(str(u.id), u.email)
    assert (await refresh(client, t0["refresh_token"])).status_code == 200
    r = await client.request(
        "DELETE", "/api/v1/auth/me", headers=auth_headers(u), json={"confirm": "DELETE"}
    )
    assert r.status_code == 200, r.text
    assert (await db.execute(select(RefreshTokenUse))).scalars().all() == []
    assert (
        await refresh(client, create_tokens(str(u.id), u.email)["refresh_token"])
    ).status_code == 401
