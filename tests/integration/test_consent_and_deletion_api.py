"""Phase G: consent capture / versioning / withdrawal, and re-authenticated account deletion."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models.user import User
from app.models.user_consent import UserConsent
from app.services import consent as cns
from tests.integration.conftest import delete_body

pytestmark = pytest.mark.integration

API = "/api/v1/auth"
REGISTER = f"{API}/register"
REG_VERIFY = f"{API}/register/verify"
CONSENTS = f"{API}/consents"
DEL_START = f"{API}/me/delete/start"
ME = f"{API}/me"
V = cns.VERSIONS[cns.TERMS]


@pytest.fixture
def delivered(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def _fake(identifier, code):
        sent.append((identifier, code))
        return SimpleNamespace(success=True, error=None, method="x")

    monkeypatch.setattr("app.routers.auth.deliver_otp", _fake)
    monkeypatch.setattr("app.routers.identity.deliver_otp", _fake)
    monkeypatch.setattr("app.routers.privacy.deliver_otp", _fake)
    return sent


def code_for(delivered, identifier):
    return [c for i, c in delivered if i == identifier][-1]


def body(email, consent="ok", **extra):
    b = {"first_name": "Rae", "email": email, **extra}
    if consent == "ok":
        b["consent"] = {"terms_version": V, "privacy_version": V}
    elif consent is not None:
        b["consent"] = consent
    return b


async def rows(db, user_id):
    return (
        (
            await db.execute(
                select(UserConsent)
                .where(UserConsent.user_id == user_id)
                .order_by(UserConsent.created_at)
            )
        )
        .scalars()
        .all()
    )


async def register_verified(client, delivered, email, **extra):
    r = await client.post(REGISTER, json=body(email, **extra))
    assert r.status_code == 200, r.text
    v = await client.post(
        REG_VERIFY, json={"identifier": email, "code": code_for(delivered, email)}
    )
    assert v.status_code == 200, v.text
    return v.json()


def bearer(t):
    return {"Authorization": f"Bearer {t['access_token']}"}


# ----------------------------------------------------------------------------------------------- registration consent
async def test_registration_without_consent_is_refused_and_creates_nothing(
    client, db, delivered
):
    r = await client.post(REGISTER, json=body("noc@example.com", consent=None))
    assert r.status_code == 422
    assert r.headers.get("x-consent-error") == "consent_required"
    assert delivered == []  # no code was sent
    assert (await db.execute(select(func.count()).select_from(User))).scalar_one() == 0


async def test_stale_notice_version_is_refused(client, delivered):
    old = {"terms_version": "2000-01-01", "privacy_version": V}
    r = await client.post(REGISTER, json=body("old@example.com", consent=old))
    assert r.status_code == 409 and r.headers.get("x-consent-error") == "stale_version"
    old = {"terms_version": V, "privacy_version": "1999"}
    assert (
        await client.post(REGISTER, json=body("old2@example.com", consent=old))
    ).status_code == 409


async def test_consent_is_persisted_per_purpose_with_version_user_and_time(
    client, db, delivered
):
    tokens = await register_verified(client, delivered, "rec@example.com")
    user = (
        await db.execute(select(User).where(User.email == "rec@example.com"))
    ).scalar_one()
    got = {c.purpose: c for c in await rows(db, user.id)}
    assert set(got) == {cns.TERMS, cns.PRIVACY}  # nothing optional was recorded
    for c in got.values():
        assert c.granted is True and c.version == V and c.source == "register"
        assert c.user_id == user.id and c.created_at is not None
    state = (await client.get(CONSENTS, headers=bearer(tokens))).json()
    assert state["required_up_to_date"] is True
    ai = next(i for i in state["items"] if i["purpose"] == cns.AI_PROCESSING)
    assert ai["granted"] is None and ai["required"] is False  # never decided


async def test_optional_choice_at_registration_is_recorded_separately_and_defaults_to_nothing(
    client, db, delivered
):
    consent = {"terms_version": V, "privacy_version": V, "ai_processing": True}
    await register_verified(client, delivered, "ai@example.com", consent=consent)
    user = (
        await db.execute(select(User).where(User.email == "ai@example.com"))
    ).scalar_one()
    got = {c.purpose: c for c in await rows(db, user.id)}
    assert got[cns.AI_PROCESSING].granted is True


async def test_declining_the_optional_choice_never_blocks_signup(client, db, delivered):
    consent = {"terms_version": V, "privacy_version": V, "ai_processing": False}
    await register_verified(client, delivered, "noai@example.com", consent=consent)
    user = (
        await db.execute(select(User).where(User.email == "noai@example.com"))
    ).scalar_one()
    got = {c.purpose: c for c in await rows(db, user.id)}
    assert got[cns.AI_PROCESSING].granted is False


# ------------------------------------------------------------------------------------------- change and withdrawal
async def test_optional_consent_can_be_granted_then_withdrawn_and_history_is_kept(
    client, db, delivered
):
    t = await register_verified(client, delivered, "tog@example.com")
    h = bearer(t)
    put = lambda g: client.put(  # noqa: E731
        CONSENTS,
        headers=h,
        json={"purpose": cns.AI_PROCESSING, "granted": g, "version": V},
    )
    assert (await put(True)).status_code == 200
    r = await put(False)
    ai = next(i for i in r.json()["items"] if i["purpose"] == cns.AI_PROCESSING)
    assert ai["granted"] is False
    user = (
        await db.execute(select(User).where(User.email == "tog@example.com"))
    ).scalar_one()
    history = [
        c.granted for c in await rows(db, user.id) if c.purpose == cns.AI_PROCESSING
    ]
    assert history == [True, False]  # append-only: the grant is still on record


async def test_mandatory_acknowledgements_cannot_be_withdrawn(client, delivered):
    t = await register_verified(client, delivered, "mand@example.com")
    for purpose in (cns.TERMS, cns.PRIVACY):
        r = await client.put(
            CONSENTS,
            headers=bearer(t),
            json={"purpose": purpose, "granted": False, "version": V},
        )
        assert r.status_code == 422 and "delete your account" in r.json()["detail"]


async def test_unknown_purpose_and_stale_version_are_rejected(client, delivered):
    t = await register_verified(client, delivered, "bad@example.com")
    r = await client.put(
        CONSENTS,
        headers=bearer(t),
        json={"purpose": "marketing", "granted": True, "version": V},
    )
    assert r.status_code == 422
    r = await client.put(
        CONSENTS,
        headers=bearer(t),
        json={"purpose": cns.AI_PROCESSING, "granted": True, "version": "1999"},
    )
    assert r.status_code == 409


async def test_legacy_user_without_records_is_reported_as_not_up_to_date_then_can_accept(
    client, make_user, auth_headers
):
    u = await make_user("legacy")
    h = auth_headers(u)
    state = (await client.get(CONSENTS, headers=h)).json()
    assert state["required_up_to_date"] is False
    assert all(i["granted"] is None for i in state["items"])
    for purpose in (cns.TERMS, cns.PRIVACY):
        r = await client.put(
            CONSENTS,
            headers=h,
            json={"purpose": purpose, "granted": True, "version": V},
        )
        assert r.status_code == 200
    assert r.json()["required_up_to_date"] is True


async def test_consent_state_is_per_user_and_requires_authentication(
    client, make_user, auth_headers
):
    a, b = await make_user("a"), await make_user("b")
    await client.put(
        CONSENTS,
        headers=auth_headers(a),
        json={"purpose": cns.AI_PROCESSING, "granted": True, "version": V},
    )
    sb = (await client.get(CONSENTS, headers=auth_headers(b))).json()
    ai = next(i for i in sb["items"] if i["purpose"] == cns.AI_PROCESSING)
    assert ai["granted"] is None  # b did not inherit a's choice
    assert (await client.get(CONSENTS)).status_code in (401, 403)
    assert (
        await client.put(
            CONSENTS, json={"purpose": cns.AI_PROCESSING, "granted": True, "version": V}
        )
    ).status_code in (401, 403)


# ------------------------------------------------------------------------------------------------- Google sign-up
async def test_google_signup_requires_consent_and_records_it(client, monkeypatch, db):
    import app.routers.auth as auth_router

    async def _fake_verify(token):
        return SimpleNamespace(email="g.new@example.com", subject="g-new-1", name="Gee")

    monkeypatch.setattr(auth_router, "verify_google_id_token", _fake_verify)
    url = f"{API}/google"
    tok = "x" * 40
    r = await client.post(url, json={"id_token": tok})
    assert (
        r.status_code == 422 and r.headers.get("x-consent-error") == "consent_required"
    )
    assert (
        await db.execute(select(User).where(User.email == "g.new@example.com"))
    ).scalar_one_or_none() is None
    r = await client.post(
        url,
        json={"id_token": tok, "consent": {"terms_version": V, "privacy_version": V}},
    )
    assert r.status_code == 200, r.text
    user = (
        await db.execute(select(User).where(User.email == "g.new@example.com"))
    ).scalar_one()
    got = {c.purpose: c for c in await rows(db, user.id)}
    assert got[cns.TERMS].source == "google" and got[cns.PRIVACY].granted


async def test_google_signin_of_an_existing_account_needs_no_new_consent(
    client, monkeypatch, make_user
):
    import app.routers.auth as auth_router

    u = await make_user("ex", email="g.ex@example.com")

    async def _fake_verify(token):
        return SimpleNamespace(email=u.email, subject="g-ex-1", name="Ex")

    monkeypatch.setattr(auth_router, "verify_google_id_token", _fake_verify)
    r = await client.post(f"{API}/google", json={"id_token": "y" * 40})
    assert r.status_code == 200


# ---------------------------------------------------------------------------------- deletion: re-authentication
async def test_delete_without_a_code_is_rejected_and_nothing_is_deleted(
    client, make_user, auth_headers, db
):
    u = await make_user("nocode")
    r = await client.request(
        "DELETE", ME, headers=auth_headers(u), json={"confirm": "DELETE"}
    )
    assert r.status_code == 422
    assert (
        (await db.execute(select(User).where(User.id == u.id))).scalar_one().is_active
    )


async def test_delete_start_sends_the_code_to_the_verified_email_only(
    client, make_user, auth_headers, delivered
):
    u = await make_user("own", email="owner-del@example.com", phone="+919833300001")
    r = await client.post(DEL_START, headers=auth_headers(u))
    assert r.status_code == 200 and "Nothing has been deleted" in r.json()["message"]
    assert [i for i, _ in delivered] == ["owner-del@example.com"]
    assert delivered[0][1] not in r.text


async def test_full_two_step_deletion_and_replay_is_refused(
    client, make_user, auth_headers, delivered, db
):
    u = await make_user("full", email="full-del@example.com")
    h = auth_headers(u)
    await client.post(DEL_START, headers=h)
    code = code_for(delivered, "full-del@example.com")
    r = await client.request(
        "DELETE", ME, headers=h, json={"confirm": "DELETE", "code": code}
    )
    assert r.status_code == 200, r.text
    fresh = (
        await db.execute(
            select(User)
            .where(User.id == u.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert fresh.is_active is False and fresh.email is None
    assert (await rows(db, u.id)) == []  # consent records are erased with the account
    again = await client.request(
        "DELETE", ME, headers=h, json={"confirm": "DELETE", "code": code}
    )
    assert again.status_code in (400, 401, 403)


async def test_wrong_code_does_not_delete_and_correct_code_still_works_afterwards(
    client, make_user, auth_headers, delivered, db
):
    u = await make_user("wrong", email="wrong-del@example.com")
    h = auth_headers(u)
    await client.post(DEL_START, headers=h)
    code = code_for(delivered, "wrong-del@example.com")
    bad = "000000" if code != "000000" else "111111"
    r = await client.request(
        "DELETE", ME, headers=h, json={"confirm": "DELETE", "code": bad}
    )
    assert r.status_code == 400
    assert (
        (await db.execute(select(User).where(User.id == u.id))).scalar_one().is_active
    )
    ok = await client.request(
        "DELETE", ME, headers=h, json={"confirm": "DELETE", "code": code}
    )
    assert ok.status_code == 200


async def test_another_accounts_code_cannot_delete_this_account(
    client, make_user, auth_headers, delivered, db
):
    victim = await make_user("victim", email="victim-del@example.com")
    attacker = await make_user("attacker", email="attacker-del@example.com")
    await client.post(DEL_START, headers=auth_headers(attacker))
    attacker_code = code_for(delivered, "attacker-del@example.com")
    r = await client.request(
        "DELETE",
        ME,
        headers=auth_headers(victim),
        json={"confirm": "DELETE", "code": attacker_code},
    )
    assert r.status_code == 400
    assert (
        (await db.execute(select(User).where(User.id == victim.id)))
        .scalar_one()
        .is_active
    )
    # and the attacker's own account is untouched by the failed attempt
    assert (
        (await db.execute(select(User).where(User.id == attacker.id)))
        .scalar_one()
        .is_active
    )


async def test_a_login_code_cannot_be_used_to_delete(
    client, make_user, auth_headers, delivered, db
):
    u = await make_user("lg", email="login-del@example.com")
    await client.post(f"{API}/send-otp", json={"identifier": u.email})
    login_code = code_for(delivered, u.email)
    r = await client.request(
        "DELETE",
        ME,
        headers=auth_headers(u),
        json={"confirm": "DELETE", "code": login_code},
    )
    assert r.status_code == 400  # purpose-bound: a login code is not a deletion code
    assert (
        (await db.execute(select(User).where(User.id == u.id))).scalar_one().is_active
    )


async def test_account_with_no_verified_identifier_cannot_delete_in_app(
    client, make_user, auth_headers
):
    u = await make_user("unv", email_verified_at=None, phone_verified_at=None)
    assert (await client.post(DEL_START, headers=auth_headers(u))).status_code == 409
    r = await client.request(
        "DELETE",
        ME,
        headers=auth_headers(u),
        json={"confirm": "DELETE", "code": "123456"},
    )
    assert (
        r.status_code == 409
        and r.headers.get("x-identity-error") == "no_verified_identifier"
    )


async def test_delete_requires_authentication(client):
    assert (await client.post(DEL_START)).status_code in (401, 403)
    r = await client.request("DELETE", ME, json={"confirm": "DELETE", "code": "123456"})
    assert r.status_code in (401, 403)


async def test_failed_erasure_rolls_back_and_the_same_code_can_be_retried(
    client, make_user, auth_headers, delivered, db, monkeypatch
):
    import app.services.account_erasure as ae

    u = await make_user("boom", email="boom-del@example.com")
    h = auth_headers(u)
    await client.post(DEL_START, headers=h)
    code = code_for(delivered, "boom-del@example.com")
    real = ae._del

    async def _boom(db_, name, stmt, result):
        if name == "link_scans":
            raise RuntimeError("simulated failure")
        return await real(db_, name, stmt, result)

    monkeypatch.setattr(ae, "_del", _boom)
    r = await client.request(
        "DELETE", ME, headers=h, json={"confirm": "DELETE", "code": code}
    )
    assert r.status_code == 500
    assert (
        (await db.execute(select(User).where(User.id == u.id))).scalar_one().is_active
    )
    monkeypatch.setattr(ae, "_del", real)
    r = await client.request(
        "DELETE", ME, headers=h, json={"confirm": "DELETE", "code": code}
    )
    assert r.status_code == 200, r.text  # the failed attempt did not burn the code


async def test_delete_start_is_rate_limited(client, make_user, auth_headers, delivered):
    u = await make_user("rl", email="rl-del@example.com")
    codes = [
        (await client.post(DEL_START, headers=auth_headers(u))).status_code
        for _ in range(7)
    ]
    assert codes[0] == 200 and 429 in codes
    assert len(delivered) <= 5


async def test_delete_body_helper_matches_the_endpoint_contract(
    make_user, auth_headers
):
    u = await make_user("h", email="helper@example.com")
    b = await delete_body(auth_headers(u))
    assert set(b) == {"confirm", "code"} and b["confirm"] == "DELETE"
