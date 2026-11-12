"""Access vs refresh token separation (regression for: refresh token accepted as bearer).

Real routes, real PostgreSQL, tokens minted with the application's own functions."""

from datetime import timedelta

import pytest
import jwt

from app.config import settings
from app.routers.auth import create_token, create_tokens

pytestmark = pytest.mark.integration

ME = "/api/v1/auth/me"
REFRESH = "/api/v1/auth/refresh"
PROTECTED = [
    "/api/v1/auth/me",
    "/api/v1/evidence/",
    "/api/v1/recordings/",
    "/api/v1/alerts/",
    "/api/v1/warriors/me/application",
    "/api/v1/devices/",
]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def pair(make_user):
    user = await make_user("tok")
    return user, create_tokens(str(user.id), user.email)


async def test_access_token_authenticates(client, pair):
    user, tokens = pair
    r = await client.get(ME, headers=_bearer(tokens["access_token"]))
    assert r.status_code == 200 and r.json()["email"] == user.email


async def test_access_token_carries_type_claim_and_refresh_differs(pair):
    _, tokens = pair
    key, alg = settings.SECRET_KEY, settings.ALGORITHM
    assert jwt.decode(tokens["access_token"], key, algorithms=[alg])["type"] == "access"
    assert (
        jwt.decode(tokens["refresh_token"], key, algorithms=[alg])["type"] == "refresh"
    )


@pytest.mark.parametrize("path", PROTECTED)
async def test_refresh_token_is_rejected_on_protected_routes(client, pair, path):
    _, tokens = pair
    r = await client.get(path, headers=_bearer(tokens["refresh_token"]))
    assert r.status_code == 401, f"{path} accepted a refresh token"
    # ...while the access token is not rejected as unauthenticated
    ok = await client.get(path, headers=_bearer(tokens["access_token"]))
    assert ok.status_code != 401


async def test_expired_access_token_rejected(client, make_user):
    user = await make_user("exp")
    expired = create_token(
        {"sub": str(user.id), "type": "access"}, timedelta(seconds=-5)
    )
    assert (await client.get(ME, headers=_bearer(expired))).status_code == 401


async def test_expired_refresh_token_rejected(client, make_user):
    user = await make_user("exp2")
    expired = create_token(
        {"sub": str(user.id), "type": "refresh"}, timedelta(seconds=-5)
    )
    assert (
        await client.post(REFRESH, json={"refresh_token": expired})
    ).status_code == 401


async def test_refresh_endpoint_still_works_and_new_access_token_is_usable(
    client, pair
):
    user, tokens = pair
    r = await client.post(REFRESH, json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert (await client.get(ME, headers=_bearer(new["access_token"]))).json()[
        "email"
    ] == user.email
    # the NEW refresh token is itself refreshable, and again not a bearer token
    assert (
        await client.post(REFRESH, json={"refresh_token": new["refresh_token"]})
    ).status_code == 200
    assert (
        await client.get(ME, headers=_bearer(new["refresh_token"]))
    ).status_code == 401


async def test_access_token_cannot_be_used_to_refresh(client, pair):
    _, tokens = pair
    r = await client.post(REFRESH, json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 400


async def test_rotation_rule_is_single_use_with_replay_rejection(client, pair):
    """Rotation was added deliberately (see test_refresh_rotation_api.py): this test used to pin the
    old 'used refresh tokens stay valid' behaviour; it now pins the replacement."""
    _, tokens = pair
    assert (
        await client.post(REFRESH, json={"refresh_token": tokens["refresh_token"]})
    ).status_code == 200
    assert (
        await client.post(REFRESH, json={"refresh_token": tokens["refresh_token"]})
    ).status_code == 401


async def test_token_without_type_claim_is_rejected(client, make_user):
    user = await make_user("legacy")
    legacy = create_token({"sub": str(user.id)}, timedelta(minutes=5))
    assert (await client.get(ME, headers=_bearer(legacy))).status_code == 401


async def test_tampered_or_foreign_signature_rejected(client, make_user):
    user = await make_user("sig")
    forged = jwt.encode(
        {"sub": str(user.id), "type": "access", "exp": 9999999999},
        "not-the-real-secret",
        algorithm=settings.ALGORITHM,
    )
    assert (await client.get(ME, headers=_bearer(forged))).status_code == 401
    good = create_token({"sub": str(user.id), "type": "access"}, timedelta(minutes=5))
    assert (await client.get(ME, headers=_bearer(good[:-3] + "AAA"))).status_code == 401


async def test_non_uuid_subject_is_401_not_500(client):
    bad = create_token({"sub": "not-a-uuid", "type": "access"}, timedelta(minutes=5))
    assert (await client.get(ME, headers=_bearer(bad))).status_code == 401
    badr = create_token({"sub": "not-a-uuid", "type": "refresh"}, timedelta(minutes=5))
    assert (await client.post(REFRESH, json={"refresh_token": badr})).status_code == 401


async def test_refresh_denied_for_inactive_or_missing_user(client, make_user):
    inactive = await make_user("off", is_active=False)
    t = create_tokens(str(inactive.id), inactive.email)
    assert (
        await client.post(REFRESH, json={"refresh_token": t["refresh_token"]})
    ).status_code == 401
    ghost = create_token(
        {"sub": "00000000-0000-0000-0000-000000000001", "type": "refresh"},
        timedelta(days=1),
    )
    assert (
        await client.post(REFRESH, json={"refresh_token": ghost})
    ).status_code == 401
