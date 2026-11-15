"""Identity binding (F-01 / F-02): an e-mail address or phone number can authenticate an account only after its owner proved it.

Real PostgreSQL and real routes; only outbound delivery (OTP + notice e-mail) is replaced."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models.pending_registration import PendingRegistration
from app.models.user import OTP, User

pytestmark = pytest.mark.integration

API = "/api/v1/auth"
REGISTER = f"{API}/register"
REG_VERIFY = f"{API}/register/verify"
SEND = f"{API}/send-otp"
VERIFY = f"{API}/verify-otp"
ME = f"{API}/me"
PHONE_START = f"{API}/phone/add/start"
PHONE_CONFIRM = f"{API}/phone/add/confirm"
EMAIL_START = f"{API}/email/change/start"
EMAIL_CONFIRM = f"{API}/email/change/confirm"
REL_START = f"{API}/identifier/release/start"
REL_CONFIRM = f"{API}/identifier/release/confirm"
GENERIC = "Invalid or expired OTP. Please request a new one."


@pytest.fixture
def delivered(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def _fake(identifier, code):
        sent.append((identifier, code))
        return SimpleNamespace(success=True, error=None, method="x")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _fake)
    monkeypatch.setattr("app.routers.identity.deliver_otp", _fake)
    return sent


@pytest.fixture
def notices(monkeypatch):
    sent: list[tuple[str, str, str]] = []

    async def _fake(to, subject, body):
        sent.append((to, subject, body))
        return True

    monkeypatch.setattr("app.services.notifications.send_email", _fake)
    return sent


def code_for(delivered, identifier):
    return [c for i, c in delivered if i == identifier][-1]


def wrong(real):
    return "000000" if real != "000000" else "111111"


async def register(client, email, phone=None, **extra):
    body = {
        "first_name": "Rae",
        "email": email,
        "consent": {"terms_version": "2026-11-14", "privacy_version": "2026-11-14"},
        **extra,
    }
    if phone:
        body["phone"] = phone
    return await client.post(REGISTER, json=body)


async def register_verified(client, delivered, email, phone=None):
    r = await register(client, email, phone)
    assert r.status_code == 200, r.text
    v = await client.post(
        REG_VERIFY, json={"identifier": email, "code": code_for(delivered, email)}
    )
    assert v.status_code == 200, v.text
    return v.json()


def bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def reload(db, user):
    """Fresh copy from the database (``make_user`` returns detached rows; the app wrote through its own session)."""
    return (
        await db.execute(
            select(User)
            .where(User.id == user.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def count(db, model, *where):
    return (
        await db.execute(select(func.count()).select_from(model).where(*where))
    ).scalar_one()


# --------------------------------------------------------------------------- F-01 registration binding
async def test_registration_creates_no_account_until_the_email_is_verified(
    client, db, delivered
):
    r = await register(client, "new@example.com", "+919800000001")
    assert r.status_code == 200 and r.json()["next_step"] == "verify_email"
    assert await count(db, User, User.email == "new@example.com") == 0
    assert (
        await count(
            db, PendingRegistration, PendingRegistration.email == "new@example.com"
        )
        == 1
    )
    # the code went to the e-mail address only: nothing was sent to the phone
    assert [i for i, _ in delivered] == ["new@example.com"]


async def test_account_is_usable_after_email_verification_and_phone_is_pending(
    client, db, delivered
):
    tokens = await register_verified(
        client, delivered, "ok2@example.com", "+919800000002"
    )
    assert tokens["email_verified"] is True and tokens["phone_verified"] is False
    assert tokens["next_step"] == "verify_phone"
    me = await client.get(ME, headers=bearer(tokens))
    assert me.status_code == 200 and me.json()["phone_verified"] is False
    user = (
        await db.execute(select(User).where(User.email == "ok2@example.com"))
    ).scalar_one()
    assert user.phone is None  # the phone was only a hint; it is not bound until proven
    assert (
        await count(
            db, PendingRegistration, PendingRegistration.email == "ok2@example.com"
        )
        == 0
    )


async def test_phone_squatting_is_impossible_and_the_real_owner_can_still_verify(
    client, db, delivered
):
    victim_phone = "+919800000003"
    attacker = await register_verified(
        client, delivered, "attacker@example.com", victim_phone
    )
    # the attacker holds no phone; the victim's number never resolves to anyone
    sent_before = len(delivered)
    s = await client.post(SEND, json={"identifier": victim_phone})
    assert (
        s.status_code == 200 and len(delivered) == sent_before
    )  # nothing sent, nobody to log in
    # the real owner registers with the same number and verifies it with a code sent to that number
    victim = await register_verified(client, delivered, "victim@example.com")
    st = await client.post(
        PHONE_START, json={"phone": victim_phone}, headers=bearer(victim)
    )
    assert st.status_code == 200
    cf = await client.post(
        PHONE_CONFIRM,
        json={"phone": victim_phone, "code": code_for(delivered, victim_phone)},
        headers=bearer(victim),
    )
    assert cf.status_code == 200 and cf.json()["phone_verified"] is True
    me = await client.get(ME, headers=bearer(victim))
    assert me.json()["phone_verified"] is True
    assert (await client.get(ME, headers=bearer(attacker))).json()[
        "phone_verified"
    ] is False


async def test_unverified_phone_cannot_log_in_or_resolve_an_account(
    client, db, make_user, delivered
):
    # legacy row: verified e-mail, phone claimed but never proven
    u = await make_user("leg", phone="+919800000004", phone_verified_at=None)
    assert (
        await client.post(SEND, json={"identifier": "+919800000004"})
    ).status_code == 200
    code = code_for(delivered, "+919800000004")  # a code is sent to that number only...
    r = await client.post(VERIFY, json={"identifier": "+919800000004", "code": code})
    # ...but proving the OTHER identifier of an account whose e-mail is verified signs nobody in and merges nothing
    assert r.status_code == 409
    assert r.headers.get("x-identity-error")
    assert "access_token" not in r.text
    u = await reload(db, u)
    assert u.phone_verified_at is None


async def test_email_and_phone_codes_are_independent_and_not_interchangeable(
    client, db, delivered
):
    tokens = await register_verified(client, delivered, "ind@example.com")
    phone = "+919800000005"
    await client.post(PHONE_START, json={"phone": phone}, headers=bearer(tokens))
    phone_code = code_for(delivered, phone)
    # a phone code cannot confirm another number, and an e-mail code cannot confirm the phone
    other = await client.post(
        PHONE_CONFIRM,
        json={"phone": "+919800000099", "code": phone_code},
        headers=bearer(tokens),
    )
    assert other.status_code == 400 and other.json()["detail"] == GENERIC
    await client.post(
        EMAIL_START, json={"new_email": "ind2@example.com"}, headers=bearer(tokens)
    )
    email_code = code_for(delivered, "ind2@example.com")
    cross = await client.post(
        PHONE_CONFIRM, json={"phone": phone, "code": email_code}, headers=bearer(tokens)
    )
    if email_code != phone_code:
        assert cross.status_code == 400
    ok = await client.post(
        PHONE_CONFIRM, json={"phone": phone, "code": phone_code}, headers=bearer(tokens)
    )
    assert ok.status_code == 200


async def test_a_code_is_bound_to_its_purpose(client, db, make_user, delivered):
    await make_user("pur", email="pur@example.com")
    await client.post(SEND, json={"identifier": "pur@example.com"})
    login_code = code_for(delivered, "pur@example.com")
    # a LOGIN code cannot complete a registration, an e-mail change or a phone addition
    r1 = await client.post(
        REG_VERIFY, json={"identifier": "pur@example.com", "code": login_code}
    )
    assert r1.status_code == 400
    tokens = (
        await client.post(
            VERIFY, json={"identifier": "pur@example.com", "code": login_code}
        )
    ).json()
    await client.post(
        PHONE_START, json={"phone": "+919800000006"}, headers=bearer(tokens)
    )
    add_code = code_for(delivered, "+919800000006")
    # an ADD_PHONE code cannot sign anyone in
    r2 = await client.post(
        VERIFY, json={"identifier": "+919800000006", "code": add_code}
    )
    assert r2.status_code == 400 and r2.json()["detail"] == GENERIC


async def test_phone_code_replay_is_rejected(client, delivered):
    tokens = await register_verified(client, delivered, "rep@example.com")
    phone = "+919800000007"
    await client.post(PHONE_START, json={"phone": phone}, headers=bearer(tokens))
    code = code_for(delivered, phone)
    body = {"phone": phone, "code": code}
    assert (
        await client.post(PHONE_CONFIRM, json=body, headers=bearer(tokens))
    ).status_code == 200
    assert (
        await client.post(PHONE_CONFIRM, json=body, headers=bearer(tokens))
    ).status_code == 400


async def test_concurrent_verification_creates_exactly_one_account(
    client, db, delivered
):
    await register(client, "race2@example.com")
    code = code_for(delivered, "race2@example.com")
    rs = await asyncio.gather(
        *[
            client.post(
                REG_VERIFY, json={"identifier": "race2@example.com", "code": code}
            )
            for _ in range(6)
        ]
    )
    codes = sorted(r.status_code for r in rs)
    assert codes.count(200) == 1 and all(c in (200, 400, 409) for c in codes), codes
    assert await count(db, User, User.email == "race2@example.com") == 1


async def test_concurrent_registrations_for_one_email_leave_one_pending_row(
    client, db, delivered
):
    rs = await asyncio.gather(*[register(client, "same@example.com") for _ in range(4)])
    assert all(r.status_code == 200 for r in rs), [r.status_code for r in rs]
    assert (
        await count(
            db, PendingRegistration, PendingRegistration.email == "same@example.com"
        )
        == 1
    )
    assert (
        await count(db, OTP, OTP.email == "same@example.com", OTP.is_used.is_(False))
        == 1
    )


async def test_registering_an_existing_email_or_phone_is_a_409(
    client, make_user, delivered
):
    await make_user("dup", email="dup@example.com", phone="+919800000008")
    assert (await register(client, "dup@example.com")).status_code == 409
    assert (
        await register(client, "fresh@example.com", "+919800000008")
    ).status_code == 409


async def test_pending_registration_expires_and_can_not_be_verified(
    client, db, delivered, session_factory
):
    from sqlalchemy import text

    await register(client, "exp@example.com")
    code = code_for(delivered, "exp@example.com")
    async with session_factory() as s:
        await s.execute(
            text(
                "update pending_registrations set expires_at=(now() at time zone 'utc') - interval '1 minute'"
            )
        )
        await s.commit()
    r = await client.post(
        REG_VERIFY, json={"identifier": "exp@example.com", "code": code}
    )
    assert r.status_code == 400
    assert await count(db, User, User.email == "exp@example.com") == 0


async def test_resend_answers_the_same_for_pending_known_and_unknown(
    client, make_user, delivered
):
    await register(client, "pend@example.com")
    await make_user("kn", email="kn@example.com")
    a = await client.post(SEND, json={"identifier": "pend@example.com"})
    b = await client.post(SEND, json={"identifier": "kn@example.com"})
    c = await client.post(SEND, json={"identifier": "ghost@example.com"})
    assert a.status_code == b.status_code == c.status_code == 200
    assert set(a.json()) == set(b.json()) == set(c.json())
    assert a.json()["message"] == b.json()["message"] == c.json()["message"]


# --------------------------------------------------------------------------- F-02 e-mail change
async def test_patch_me_rejects_email_changes(client, make_user, auth_headers, db):
    u = await make_user("pm", email="pm@example.com")
    h = auth_headers(u)
    r = await client.patch(ME, json={"email": "other@example.com"}, headers=h)
    assert r.status_code == 400
    assert r.headers.get("x-identity-error") == "email_change_requires_verification"
    u = await reload(db, u)
    assert u.email == "pm@example.com"
    same = await client.patch(
        ME, json={"email": "pm@example.com", "full_name": "Pat M"}, headers=h
    )
    assert same.status_code == 200 and same.json()["full_name"] == "Pat M"


async def test_email_change_needs_proof_and_keeps_the_old_email_active_until_then(
    client, db, make_user, auth_headers, delivered, notices
):
    u = await make_user("chg", email="old@example.com")
    h = auth_headers(u)
    s = await client.post(
        EMAIL_START, json={"new_email": "new2@example.com"}, headers=h
    )
    assert s.status_code == 200
    assert [i for i, _ in delivered] == [
        "new2@example.com"
    ]  # the code goes to the NEW address only
    u = await reload(db, u)
    assert u.email == "old@example.com"  # unchanged before confirmation
    # the old address still signs in
    await client.post(SEND, json={"identifier": "old@example.com"})
    assert (
        await client.post(
            VERIFY,
            json={
                "identifier": "old@example.com",
                "code": code_for(delivered, "old@example.com"),
            },
        )
    ).status_code == 200
    # wrong code: still unchanged
    bad = await client.post(
        EMAIL_CONFIRM,
        json={
            "new_email": "new2@example.com",
            "code": wrong(code_for(delivered, "new2@example.com")),
        },
        headers=h,
    )
    assert bad.status_code == 400
    ok = await client.post(
        EMAIL_CONFIRM,
        json={
            "new_email": "new2@example.com",
            "code": code_for(delivered, "new2@example.com"),
        },
        headers=h,
    )
    assert ok.status_code == 200 and ok.json()["email_verified"] is True
    u = await reload(db, u)
    assert u.email == "new2@example.com" and u.email_verified
    assert any(
        to == "old@example.com" for to, _, _ in notices
    )  # the old address was told


async def test_email_change_to_a_claimed_address_is_a_409_with_nothing_sent(
    client, make_user, auth_headers, delivered
):
    a = await make_user("a", email="a-own@example.com")
    await make_user("b", email="b-own@example.com")
    r = await client.post(
        EMAIL_START, json={"new_email": "b-own@example.com"}, headers=auth_headers(a)
    )
    assert r.status_code == 409
    assert delivered == []


async def test_email_change_code_cannot_be_used_by_another_account(
    client, make_user, auth_headers, delivered
):
    a = await make_user("iso1", email="iso1@example.com")
    b = await make_user("iso2", email="iso2@example.com")
    await client.post(
        EMAIL_START, json={"new_email": "target@example.com"}, headers=auth_headers(a)
    )
    code = code_for(delivered, "target@example.com")
    r = await client.post(
        EMAIL_CONFIRM,
        json={"new_email": "target@example.com", "code": code},
        headers=auth_headers(b),
    )
    assert r.status_code == 400 and r.json()["detail"] == GENERIC


async def test_google_binding_survives_an_email_change(
    client, db, make_user, auth_headers, delivered, notices
):
    u = await make_user("gs", email="gs@example.com", google_sub="sub-keep-1")
    h = auth_headers(u)
    await client.post(EMAIL_START, json={"new_email": "gs2@example.com"}, headers=h)
    await client.post(
        EMAIL_CONFIRM,
        json={
            "new_email": "gs2@example.com",
            "code": code_for(delivered, "gs2@example.com"),
        },
        headers=h,
    )
    u = await reload(db, u)
    assert u.email == "gs2@example.com" and u.google_sub == "sub-keep-1"


# --------------------------------------------------------------------------- legacy accounts
async def test_legacy_account_signs_in_by_proving_its_only_identifier_and_keeps_its_data(
    client, db, make_user, delivered
):
    u = await make_user(
        "old",
        email="legacy@example.com",
        full_name="Kept Name",
        phone=None,
        email_verified_at=None,
        phone_verified_at=None,
    )
    await client.post(SEND, json={"identifier": "legacy@example.com"})
    r = await client.post(
        VERIFY,
        json={
            "identifier": "legacy@example.com",
            "code": code_for(delivered, "legacy@example.com"),
        },
    )
    assert r.status_code == 200 and r.json()["email_verified"] is True
    u = await reload(db, u)
    assert (
        u.email_verified_at is not None and u.full_name == "Kept Name"
    )  # nothing merged, nothing lost


async def test_legacy_rows_are_never_auto_verified(client, db, make_user):
    u = await make_user("nv", email_verified_at=None, phone_verified_at=None)
    u = await reload(db, u)
    assert u.email_verified is False and u.phone_verified is False


async def test_releasing_an_unverified_phone_claim_moves_no_data_and_notifies_the_holder(
    client, db, make_user, delivered, notices
):
    holder = await make_user(
        "holder",
        email="holder@example.com",
        phone="+919800000010",
        phone_verified_at=None,
        full_name="Holder",
    )
    rs = await client.post(REL_START, json={"identifier": "+919800000010"})
    assert rs.status_code == 200
    code = code_for(delivered, "+919800000010")
    bad = await client.post(
        REL_CONFIRM, json={"identifier": "+919800000010", "code": wrong(code)}
    )
    assert bad.status_code == 400
    ok = await client.post(
        REL_CONFIRM, json={"identifier": "+919800000010", "code": code}
    )
    assert ok.status_code == 200
    holder = await reload(db, holder)
    assert (
        holder.phone is None
        and holder.email == "holder@example.com"
        and holder.full_name == "Holder"
    )
    assert any(to == "holder@example.com" for to, _, _ in notices)
    # the number is now free: the real owner can verify it on a new account
    tokens = await register_verified(client, delivered, "newowner@example.com")
    await client.post(
        PHONE_START, json={"phone": "+919800000010"}, headers=bearer(tokens)
    )
    cf = await client.post(
        PHONE_CONFIRM,
        json={"phone": "+919800000010", "code": code_for(delivered, "+919800000010")},
        headers=bearer(tokens),
    )
    assert cf.status_code == 200


async def test_release_never_applies_to_a_verified_identifier_and_answers_uniformly(
    client, make_user, delivered
):
    await make_user("ver", email="ver@example.com", phone="+919800000011")
    a = await client.post(REL_START, json={"identifier": "+919800000011"})
    b = await client.post(REL_START, json={"identifier": "+919800000012"})
    assert (
        a.status_code == b.status_code == 200
        and a.json()["message"] == b.json()["message"]
    )
    assert (
        delivered == []
    )  # nothing is released or sent for a verified or unknown identifier


async def test_verified_phone_added_elsewhere_evicts_only_the_unverified_claim(
    client, db, make_user, auth_headers, delivered, notices
):
    claimant = await make_user(
        "claim",
        email="claim@example.com",
        phone="+919800000013",
        phone_verified_at=None,
    )
    owner = await make_user(
        "owner", email="owner2@example.com", phone=None, phone_verified_at=None
    )
    h = auth_headers(owner)
    await client.post(PHONE_START, json={"phone": "+919800000013"}, headers=h)
    r = await client.post(
        PHONE_CONFIRM,
        json={"phone": "+919800000013", "code": code_for(delivered, "+919800000013")},
        headers=h,
    )
    assert r.status_code == 200
    claimant = await reload(db, claimant)
    owner = await reload(db, owner)
    assert (
        claimant.phone is None
        and owner.phone == "+919800000013"
        and owner.phone_verified
    )
    assert any(to == "claim@example.com" for to, _, _ in notices)


async def test_a_verified_phone_cannot_be_taken_by_another_account(
    client, make_user, auth_headers, delivered
):
    await make_user("hold", email="hold@example.com", phone="+919800000014")
    other = await make_user(
        "oth", email="oth@example.com", phone=None, phone_verified_at=None
    )
    r = await client.post(
        PHONE_START, json={"phone": "+919800000014"}, headers=auth_headers(other)
    )
    assert r.status_code == 409 and delivered == []


# --------------------------------------------------------------------------- anti-enumeration / rate limits
async def test_phone_start_is_rate_limited_per_number(
    client, make_user, auth_headers, delivered
):
    u = await make_user(
        "rl", email="rl@example.com", phone=None, phone_verified_at=None
    )
    codes = [
        (
            await client.post(
                PHONE_START, json={"phone": "+919800000015"}, headers=auth_headers(u)
            )
        ).status_code
        for _ in range(7)
    ]
    assert 429 in codes and codes[0] == 200
    assert len(delivered) <= 5


async def test_identity_endpoints_require_authentication(client):
    for path, body in (
        (PHONE_START, {"phone": "+919800000016"}),
        (PHONE_CONFIRM, {"phone": "+919800000016", "code": "123456"}),
        (EMAIL_START, {"new_email": "x@example.com"}),
        (EMAIL_CONFIRM, {"new_email": "x@example.com", "code": "123456"}),
    ):
        assert (await client.post(path, json=body)).status_code in (401, 403), path
