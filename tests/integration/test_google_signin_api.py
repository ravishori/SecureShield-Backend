"""Google Sign-In: ID tokens are signed locally with a throw-away RSA key and Google's JWKS endpoint
is simulated with httpx.MockTransport. Nothing here talks to Google."""

import base64
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from sqlalchemy import select

import app.services.google_auth as ga
from app.config import settings
from app.models.user import User

pytestmark = pytest.mark.integration
URL = "/api/v1/auth/google"
CLIENT_ID = "1234-web.apps.googleusercontent.com"
ANDROID_ID = "1234-android.apps.googleusercontent.com"


def _b64(n: int) -> str:
    return (
        base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
        .rstrip(b"=")
        .decode()
    )


class Signer:
    def __init__(self, kid="k1"):
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        n = self.key.public_key().public_numbers()
        self.jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": kid,
            "n": _b64(n.n),
            "e": _b64(n.e),
        }

    def token(self, **over):
        claims = {
            "iss": "https://accounts.google.com",
            "aud": CLIENT_ID,
            "sub": "g-123",
            "email": "g.user@example.com",
            "email_verified": True,
            "name": "Gee User",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        }
        claims.update(over)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(
            claims, self.pem, algorithm="RS256", headers={"kid": self.kid}
        )


@pytest.fixture
def signer():
    return Signer()


@pytest.fixture(autouse=True)
def google(monkeypatch, signer):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_IDS", f"{CLIENT_ID}, {ANDROID_ID}")
    ga.reset_cache()
    state = {"jwks": [signer.jwk], "calls": 0, "fail": False}

    def handler(req):
        state["calls"] += 1
        if state["fail"]:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json={"keys": state["jwks"]})

    monkeypatch.setattr(
        ga, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    yield state
    ga.reset_cache()


async def login(client, token, **extra):
    consent = {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"}
    return await client.post(URL, json={"id_token": token, "consent": consent, **extra})


async def test_new_user_is_created_and_gets_working_tokens(client, signer, db):
    r = await login(client, signer.token())
    assert r.status_code == 200, r.text
    tokens = r.json()
    me = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert me.status_code == 200 and me.json()["email"] == "g.user@example.com"
    user = (
        await db.execute(select(User).where(User.email == "g.user@example.com"))
    ).scalar_one()
    assert user.full_name == "Gee User"
    assert (
        await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
    ).status_code == 200


async def test_existing_account_is_reused_not_duplicated(client, signer, make_user, db):
    u = await make_user("ex", email="g.user@example.com", full_name="Kept Name")
    r = await login(client, signer.token())
    assert r.status_code == 200
    rows = (
        (await db.execute(select(User).where(User.email == "g.user@example.com")))
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].id == u.id and rows[0].full_name == "Kept Name"


async def test_second_configured_client_id_is_accepted(client, signer):
    assert (await login(client, signer.token(aud=ANDROID_ID))).status_code == 200


@pytest.mark.security
async def test_bad_tokens_are_rejected_with_a_generic_401(client, signer, google):
    other = Signer("k1")  # same kid, different key => bad signature
    cases = {
        "wrong audience": signer.token(aud="evil.apps.googleusercontent.com"),
        "wrong issuer": signer.token(iss="https://evil.example"),
        "expired": signer.token(exp=int(time.time()) - 10),
        "unverified email": signer.token(email_verified=False),
        "no email": signer.token(email=None),
        "forged signature": other.token(),
        "garbage": "not.a.jwt-but-long-enough-xxxx",
    }
    for name, tok in cases.items():
        r = await login(client, tok)
        assert r.status_code == 401, name
        assert r.json()["detail"] == "Google sign-in could not be verified.", name
        assert tok not in r.text


@pytest.mark.security
async def test_alg_none_and_hs256_confusion_are_rejected(client, signer):
    # PyJWT refuses to *encode* these (alg=none, empty HMAC key), so the attacker's tokens are built by hand.
    import hashlib
    import hmac as _hmac
    import json

    def _seg(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    claims = {"aud": CLIENT_ID, "email": "x@example.com"}
    unsigned = f"{_seg({'alg': 'none', 'kid': 'k1'})}.{_seg(claims)}."
    assert (await login(client, unsigned)).status_code == 401
    head = f"{_seg({'alg': 'HS256', 'kid': 'k1'})}.{_seg(claims)}"
    sig = (
        base64.urlsafe_b64encode(_hmac.new(b"", head.encode(), hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    assert (
        await login(client, f"{head}.{sig}")
    ).status_code == 401  # HS256 signed with an empty secret
    # HS256 signed with the public modulus as the secret (classic algorithm confusion)
    confused = jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "aud": CLIENT_ID,
            "sub": "1",
            "email": "x@example.com",
            "email_verified": True,
            "exp": int(time.time()) + 60,
        },
        signer.jwk["n"],
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    assert (await login(client, confused)).status_code == 401


async def test_unverified_email_never_creates_an_account(client, signer, db):
    await login(client, signer.token(email_verified=False, email="nope@example.com"))
    assert (
        await db.execute(select(User).where(User.email == "nope@example.com"))
    ).scalar_one_or_none() is None


async def test_disabled_account_is_blocked(client, signer, make_user):
    await make_user("off", email="g.user@example.com", is_active=False)
    r = await login(client, signer.token())
    assert r.status_code == 403


async def test_not_configured_returns_503_without_trusting_anything(
    client, signer, monkeypatch, db
):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_IDS", "")
    assert (await login(client, signer.token())).status_code == 503
    assert (await db.execute(select(User))).scalars().all() == []


async def test_key_rotation_refetches_jwks_once(client, google):
    old, new = Signer("old"), Signer("new")
    google["jwks"] = [old.jwk]
    assert (await login(client, old.token())).status_code == 200
    google["jwks"] = [new.jwk]  # Google rotated; cache still holds only "old"
    assert (
        await login(client, new.token(sub="g-2", email="rot@example.com"))
    ).status_code == 200
    google["jwks"] = [new.jwk]
    assert (await login(client, Signer("unknown").token())).status_code == 401


async def test_jwks_is_cached_and_stale_cache_survives_an_outage(
    client, signer, google
):
    assert (await login(client, signer.token())).status_code == 200
    assert (await login(client, signer.token())).status_code == 200
    assert google["calls"] == 1
    google["fail"] = True
    assert (await login(client, signer.token())).status_code == 200  # served from cache


async def test_jwks_outage_without_cache_is_a_safe_401(client, signer, google):
    google["fail"] = True
    r = await login(client, signer.token())
    assert r.status_code == 401 and "down" not in r.text


async def test_input_bounds_and_rate_limit(client, signer):
    assert (await client.post(URL, json={"id_token": "short"})).status_code == 422
    assert (await client.post(URL, json={"id_token": "x" * 5000})).status_code == 422
    codes = [
        (await login(client, "bad.token.value-long-enough-aa")).status_code
        for _ in range(25)
    ]
    assert 429 in codes


# --------------------------------------------------------------------------- account-linking safeguards (F-01)
async def _reload(db, user):
    return (
        await db.execute(
            select(User)
            .where(User.id == user.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def test_google_links_to_an_account_whose_email_is_verified(
    client, signer, make_user, db
):
    u = await make_user("v", email="g.user@example.com")
    r = await login(client, signer.token(sub="g-link-1"))
    assert r.status_code == 200 and r.json()["email_verified"] is True
    assert (await _reload(db, u)).google_sub == "g-link-1"


async def test_google_never_links_to_a_legacy_account_that_has_another_verified_identifier(
    client, signer, make_user, db
):
    # e-mail claim is unverified but the phone is verified: Google must not take over this row
    u = await make_user("lg", email="g.user@example.com", email_verified_at=None)
    r = await login(client, signer.token(sub="g-link-2"))
    assert r.status_code == 409 and "access_token" not in r.text
    fresh = await _reload(db, u)
    assert fresh.google_sub is None and fresh.email_verified_at is None


async def test_google_proves_the_only_identifier_of_a_legacy_account(
    client, signer, make_user, db
):
    u = await make_user(
        "ls",
        email="g.user@example.com",
        phone=None,
        email_verified_at=None,
        phone_verified_at=None,
    )
    r = await login(client, signer.token(sub="g-link-3"))
    assert r.status_code == 200
    fresh = await _reload(db, u)
    assert fresh.google_sub == "g-link-3" and fresh.email_verified_at is not None


async def test_google_will_not_rebind_an_account_to_a_different_google_subject(
    client, signer, make_user, db
):
    u = await make_user("bound", email="g.user@example.com", google_sub="g-original")
    r = await login(client, signer.token(sub="g-attacker"))
    assert r.status_code == 409
    assert (await _reload(db, u)).google_sub == "g-original"


async def test_known_google_subject_wins_over_a_changed_email(
    client, signer, make_user, db
):
    u = await make_user("moved", email="moved-to@example.com", google_sub="g-stable")
    r = await login(
        client, signer.token(sub="g-stable", email="old-address@example.com")
    )
    assert r.status_code == 200
    rows = (
        (await db.execute(select(User).where(User.google_sub == "g-stable")))
        .scalars()
        .all()
    )
    assert [x.id for x in rows] == [u.id]
    assert (
        await db.execute(select(User).where(User.email == "old-address@example.com"))
    ).first() is None


async def test_google_subject_is_unique_per_account(client, signer, make_user, db):
    from sqlalchemy.exc import IntegrityError

    await make_user("one", google_sub="g-dup")
    with pytest.raises(IntegrityError):
        await make_user("two", google_sub="g-dup")
