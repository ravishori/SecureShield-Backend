"""Named admin accounts: password + TOTP login, setup flow, sessions, RBAC, privilege escalation, MFA bypass attempts,
recovery, lockout, audit and the legacy-token migration path. Real PostgreSQL and routes; the TOTP clock is controlled."""

from __future__ import annotations

import calendar
import uuid
from datetime import datetime, timedelta

import jwt
import pytest
from sqlalchemy import select, text

from app.admin_settings import admin_settings
from app.config import settings
from app.models.admin_account import AdminAccount, AdminSession
from app.models.admin_audit import AdminAuditLog
from app.services import admin_security as sec

pytestmark = pytest.mark.integration

AUTH = "/api/v1/admin/auth"
ADMIN = "/api/v1/admin"
PASSWORD = "Correct-Horse-9-battery"
LEGACY = {"X-Admin-Token": "test-admin-token"}
# The app-wide error handler reshapes error bodies, so "uniform" means: every failure produces the same body.


class Clock:
    """Controls the TOTP time step so several logins in one test each get a fresh, valid code."""

    def __init__(self):
        self.step = 50_000_000

    def tick(self, n: int = 3):
        self.step += n


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(sec, "current_step", lambda now=None: c.step)
    return c


@pytest.fixture
def make_admin(session_factory):
    async def _make(
        role="superadmin",
        *,
        email=None,
        password=PASSWORD,
        mfa=True,
        must_change=False,
        active=True,
    ):
        secret = sec.new_totp_secret()
        shown, stored = sec.new_recovery_codes()
        async with session_factory() as s:
            a = AdminAccount(
                email=(email or f"{role}.{uuid.uuid4().hex[:6]}@example.org").lower(),
                role=role,
                password_hash=sec.hash_password(password),
                must_change_password=must_change,
                is_active=active,
                totp_secret_enc=sec.encrypt_secret(secret) if mfa else None,
                totp_enabled=mfa,
                recovery_hashes=stored if mfa else [],
            )
            s.add(a)
            await s.commit()
            await s.refresh(a)
        a.secret, a.recovery = secret, shown  # test-only conveniences (not columns)
        return a

    return _make


async def login(client, clock, acct, *, password=PASSWORD, code="auto", recovery=None):
    clock.tick()
    body = {"email": acct.email, "password": password}
    if recovery:
        body["recovery_code"] = recovery
    elif code == "auto":
        body["totp_code"] = sec.totp_code(acct.secret, clock.step)
    elif code is not None:
        body["totp_code"] = code
    return await client.post(f"{AUTH}/login", json=body)


def bearer(res):
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


async def signed_in(client, clock, acct):
    r = await login(client, clock, acct)
    assert r.status_code == 200, r.text
    return bearer(r)


async def audit_rows(session_factory, action=None):
    async with session_factory() as s:
        q = select(AdminAuditLog).order_by(AdminAuditLog.created_at)
        if action:
            q = q.where(AdminAuditLog.action == action)
        return (await s.execute(q)).scalars().all()


# ── login ────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_login_with_password_and_totp_gives_a_working_full_session(
    client, clock, make_admin
):
    a = await make_admin("admin")
    r = await login(client, clock, a)
    assert r.status_code == 200
    j = r.json()
    assert (
        j["scope"] == "full"
        and j["role"] == "admin"
        and j["setup_required"] == []
        and j["token_type"] == "bearer"
    )
    assert (await client.get(f"{ADMIN}/stats", headers=bearer(r))).status_code == 200
    me = (await client.get(f"{AUTH}/me", headers=bearer(r))).json()
    assert me["kind"] == "account" and me["email"] == a.email and me["role"] == "admin"
    assert "password" not in r.text.lower().replace("setup_required", "")


@pytest.mark.security
async def test_every_failure_is_the_same_401(
    client, clock, make_admin, session_factory
):
    ok = await make_admin("admin")
    off = await make_admin("admin", active=False)
    cases = {
        "unknown e-mail": await client.post(
            f"{AUTH}/login", json={"email": "nobody@example.org", "password": PASSWORD}
        ),
        "wrong password": await login(
            client, clock, ok, password="Wrong-Password-1234"
        ),
        "wrong code": await login(client, clock, ok, code="000000"),
        "missing code": await login(client, clock, ok, code=None),
        "malformed code": await login(client, clock, ok, code="12ab"),
        "disabled account": await login(client, clock, off),
    }
    bodies = {r.text for r in cases.values()}
    for name, r in cases.items():
        assert r.status_code == 401, name
        assert r.headers.get("www-authenticate") == "Bearer"
    assert len(bodies) == 1, (
        bodies
    )  # unknown e-mail, wrong password, wrong/missing code, disabled: indistinguishable
    # a correct password alone (no second factor) never yields a token
    assert "access_token" not in cases["missing code"].text


@pytest.mark.security
async def test_totp_code_cannot_be_replayed(client, clock, make_admin):
    a = await make_admin("admin")
    clock.tick()
    code = sec.totp_code(a.secret, clock.step)
    body = {"email": a.email, "password": PASSWORD, "totp_code": code}
    assert (await client.post(f"{AUTH}/login", json=body)).status_code == 200
    assert (await client.post(f"{AUTH}/login", json=body)).status_code == 401
    # an older code from the previous step is not accepted either
    body["totp_code"] = sec.totp_code(a.secret, clock.step - 1)
    assert (await client.post(f"{AUTH}/login", json=body)).status_code == 401


@pytest.mark.security
async def test_repeated_failures_lock_the_account_even_for_the_right_credentials(
    client, clock, make_admin, session_factory, monkeypatch
):
    monkeypatch.setattr(admin_settings, "ADMIN_LOGIN_MAX_FAILURES", 3)
    a = await make_admin("admin")
    for _ in range(3):
        assert (
            await login(client, clock, a, password="Wrong-Password-1234")
        ).status_code == 401
    assert (await login(client, clock, a)).status_code == 401  # locked
    async with session_factory() as s:
        row = (
            await s.execute(select(AdminAccount).where(AdminAccount.id == a.id))
        ).scalar_one()
        assert row.locked_until and row.locked_until > datetime.utcnow()
        row.locked_until = datetime.utcnow() - timedelta(seconds=1)  # lockout elapsed
        await s.commit()
    assert (await login(client, clock, a)).status_code == 200
    actions = [r.action for r in await audit_rows(session_factory)]
    assert (
        actions.count("admin.login_failed") == 3 and "admin.account_locked" in actions
    )


@pytest.mark.security
async def test_per_source_limit_applies_to_unknown_accounts_too(client, monkeypatch):
    monkeypatch.setattr(admin_settings, "ADMIN_LOGIN_IP_LIMIT", 5)
    codes = [
        (
            await client.post(
                f"{AUTH}/login",
                json={"email": f"x{i}@example.org", "password": PASSWORD},
            )
        ).status_code
        for i in range(7)
    ]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]


async def test_recovery_code_replaces_totp_once(
    client, clock, make_admin, session_factory
):
    a = await make_admin("admin")
    first = a.recovery[0]
    r = await login(client, clock, a, recovery=first)
    assert r.status_code == 200
    again = await login(client, clock, a, recovery=first)
    assert again.status_code == 401
    assert (await login(client, clock, a, recovery=a.recovery[1])).status_code == 200
    async with session_factory() as s:
        row = (
            await s.execute(select(AdminAccount).where(AdminAccount.id == a.id))
        ).scalar_one()
        assert len(row.recovery_hashes) == len(a.recovery) - 2
    assert len(await audit_rows(session_factory, "admin.recovery_code_used")) == 2


# ── setup flow (temporary password + MFA enrolment) ──────────────────────────────────────────────────────────────
async def test_first_login_requires_password_change_and_mfa_enrolment(
    client, clock, make_admin, session_factory
):
    a = await make_admin(
        "admin", mfa=False, must_change=True, password="Temp-Passw0rd-xyz"
    )
    r = await client.post(
        f"{AUTH}/login", json={"email": a.email, "password": "Temp-Passw0rd-xyz"}
    )
    j = r.json()
    assert (
        r.status_code == 200
        and j["scope"] == "setup"
        and set(j["setup_required"]) == {"password", "mfa"}
    )
    h = bearer(r)

    # a setup token is useless for everything except finishing setup
    for path in (
        "/stats",
        "/users",
        "/audit",
        "/errors",
        "/auth/accounts",
        "/auth/sessions",
    ):
        resp = await client.get(ADMIN + path, headers=h)
        assert resp.status_code == 403, path

    weak = await client.post(
        f"{AUTH}/password/change",
        json={"current_password": "Temp-Passw0rd-xyz", "new_password": "short"},
        headers=h,
    )
    assert weak.status_code == 422
    same = await client.post(
        f"{AUTH}/password/change",
        json={
            "current_password": "Temp-Passw0rd-xyz",
            "new_password": "Temp-Passw0rd-xyz",
        },
        headers=h,
    )
    assert same.status_code == 422
    ch = await client.post(
        f"{AUTH}/password/change",
        json={
            "current_password": "Temp-Passw0rd-xyz",
            "new_password": "Brand-New-Passw0rd!",
        },
        headers=h,
    )
    assert (
        ch.status_code == 200
        and ch.json()["setup_required"] == ["mfa"]
        and ch.json()["scope"] == "setup"
    )

    start = await client.post(f"{AUTH}/mfa/enroll/start", headers=h)
    assert start.status_code == 200
    secret = start.json()["secret"]
    assert (
        start.json()["otpauth_uri"].startswith("otpauth://totp/")
        and secret in start.json()["otpauth_uri"]
    )
    clock.tick()
    bad = await client.post(
        f"{AUTH}/mfa/enroll/confirm", json={"code": "000000"}, headers=h
    )
    assert bad.status_code == 400
    done = await client.post(
        f"{AUTH}/mfa/enroll/confirm",
        json={"code": sec.totp_code(secret, clock.step)},
        headers=h,
    )
    assert done.status_code == 200
    d = done.json()
    assert (
        d["scope"] == "full"
        and d["setup_required"] == []
        and len(d["recovery_codes"]) == sec.RECOVERY_CODE_COUNT
    )
    assert (await client.get(f"{ADMIN}/stats", headers=bearer(done))).status_code == 200
    assert (
        await client.get(f"{ADMIN}/stats", headers=h)
    ).status_code == 401  # the setup session was retired

    # from now on MFA is mandatory
    a.secret = secret
    assert (
        await login(client, clock, a, password="Brand-New-Passw0rd!", code=None)
    ).status_code == 401
    assert (
        await login(client, clock, a, password="Brand-New-Passw0rd!")
    ).status_code == 200
    assert (
        await client.post(f"{AUTH}/mfa/enroll/start", headers=bearer(done))
    ).status_code in (401, 403)
    for action in ("admin.password_changed", "admin.mfa_enrolled", "admin.login"):
        assert await audit_rows(session_factory, action), action


async def test_mfa_can_be_enrolled_only_once_without_a_superadmin_reset(
    client, clock, make_admin
):
    a = await make_admin("admin", mfa=True)
    r = await login(client, clock, a)
    # a full session cannot restart enrolment (setup scope only)
    assert (
        await client.post(f"{AUTH}/mfa/enroll/start", headers=bearer(r))
    ).status_code == 403


# ── tokens: MFA bypass, forgery, cross-use ───────────────────────────────────────────────────────────────────────
@pytest.mark.security
async def test_tokens_are_not_interchangeable_with_end_user_tokens(
    client, clock, make_admin, make_user, auth_headers
):
    a = await make_admin("superadmin")
    h = await signed_in(client, clock, a)
    # admin token on the end-user API
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 401
    # end-user token on the admin API
    u = auth_headers(await make_user("plain"))
    assert (await client.get(f"{ADMIN}/stats", headers=u)).status_code == 401
    assert (await client.get(f"{AUTH}/accounts", headers=u)).status_code == 401


@pytest.mark.security
async def test_forged_expired_and_foreign_tokens_are_rejected(
    client, clock, make_admin, session_factory
):
    a = await make_admin("admin")
    r = await login(client, clock, a)
    token = r.json()["access_token"]
    claims = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    def forge(**over):
        c = {**claims, **over}
        return {
            "Authorization": "Bearer "
            + jwt.encode(c, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        }

    wrong_key = {
        "Authorization": "Bearer "
        + jwt.encode(
            claims, "another-secret-of-sufficient-length-1234", algorithm="HS256"
        )
    }
    cases = {
        "wrong signing key": wrong_key,
        "elevated scope claim": forge(scope="setup"),
        "unknown session": forge(sid=str(uuid.uuid4())),
        "other admin id": forge(sub=str(uuid.uuid4())),
        "wrong type": forge(type="access"),
        "expired": forge(
            exp=calendar.timegm(
                (datetime.utcnow() - timedelta(minutes=1)).utctimetuple()
            )
        ),
        "garbage": {"Authorization": "Bearer not.a.jwt"},
        "wrong scheme": {"Authorization": "Basic abc"},
        "empty bearer": {"Authorization": "Bearer "},
    }
    for name, h in cases.items():
        assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 401, name
    assert (
        await client.get(f"{ADMIN}/stats", headers=bearer(r))
    ).status_code == 200  # the real one still works


@pytest.mark.security
async def test_a_bad_bearer_never_falls_back_to_the_legacy_token(client):
    r = await client.get(
        f"{ADMIN}/stats", headers={"Authorization": "Bearer nope", **LEGACY}
    )
    assert r.status_code == 401


# ── sessions ─────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.security
async def test_logout_revokes_the_session_immediately(client, clock, make_admin):
    a = await make_admin("admin")
    h = await signed_in(client, clock, a)
    assert (await client.post(f"{AUTH}/logout", headers=h)).status_code == 200
    assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 401
    assert (await client.post(f"{AUTH}/refresh", headers=h)).status_code == 401


@pytest.mark.security
async def test_deactivating_the_account_kills_live_tokens(
    client, clock, make_admin, session_factory
):
    boss = await make_admin("superadmin")
    victim = await make_admin("admin")
    vh = await signed_in(client, clock, victim)
    bh = await signed_in(client, clock, boss)
    assert (
        await client.post(f"{AUTH}/accounts/{victim.id}/disable", headers=bh)
    ).status_code == 200
    assert (await client.get(f"{ADMIN}/stats", headers=vh)).status_code == 401
    assert (await login(client, clock, victim)).status_code == 401
    assert (
        await client.post(f"{AUTH}/accounts/{victim.id}/enable", headers=bh)
    ).status_code == 200
    assert (await login(client, clock, victim)).status_code == 200


@pytest.mark.security
async def test_expired_session_row_is_refused_even_with_a_valid_signature(
    client, clock, make_admin, session_factory
):
    a = await make_admin("admin")
    h = await signed_in(client, clock, a)
    async with session_factory() as s:
        await s.execute(
            text(
                "update admin_sessions set expires_at = (now() at time zone 'utc') - interval '1 second'"
            )
        )
        await s.commit()
    assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 401


async def test_sessions_can_be_listed_and_revoked_but_only_your_own(
    client, clock, make_admin
):
    a, b = await make_admin("admin"), await make_admin("admin")
    h1 = await signed_in(client, clock, a)
    h2 = await signed_in(client, clock, a)
    hb = await signed_in(client, clock, b)
    items = (await client.get(f"{AUTH}/sessions", headers=h1)).json()["items"]
    assert len(items) == 2 and sum(i["current"] for i in items) == 1
    other = (await client.get(f"{AUTH}/sessions", headers=hb)).json()["items"][0]["id"]
    assert (
        await client.post(f"{AUTH}/sessions/{other}/revoke", headers=h1)
    ).status_code == 404  # not yours
    assert (
        await client.post(f"{AUTH}/sessions/{uuid.uuid4()}/revoke", headers=h1)
    ).status_code == 404
    assert (
        await client.post(f"{AUTH}/sessions/not-a-uuid/revoke", headers=h1)
    ).status_code == 404
    assert (
        await client.get(f"{ADMIN}/stats", headers=hb)
    ).status_code == 200  # B untouched
    assert (
        await client.post(f"{AUTH}/sessions/revoke-others", headers=h1)
    ).status_code == 200
    assert (await client.get(f"{ADMIN}/stats", headers=h2)).status_code == 401
    assert (await client.get(f"{ADMIN}/stats", headers=h1)).status_code == 200


async def test_password_change_revokes_other_sessions_and_refresh_keeps_the_session(
    client, clock, make_admin
):
    a = await make_admin("admin")
    h1 = await signed_in(client, clock, a)
    h2 = await signed_in(client, clock, a)
    ch = await client.post(
        f"{AUTH}/password/change",
        json={"current_password": PASSWORD, "new_password": "Another-Strong-Passw0rd"},
        headers=h1,
    )
    assert ch.status_code == 200
    assert (await client.get(f"{ADMIN}/stats", headers=h2)).status_code == 401
    wrong = await client.post(
        f"{AUTH}/password/change",
        json={
            "current_password": "nope-nope-nope-1",
            "new_password": "Yet-Another-Passw0rd",
        },
        headers=h1,
    )
    assert wrong.status_code == 400
    ref = await client.post(f"{AUTH}/refresh", headers=h1)
    assert (
        ref.status_code == 200
        and (await client.get(f"{ADMIN}/stats", headers=bearer(ref))).status_code == 200
    )


# ── RBAC and privilege escalation ────────────────────────────────────────────────────────────────────────────────
@pytest.mark.security
async def test_roles_are_enforced_on_the_server(client, clock, make_admin, make_user):
    support = await signed_in(client, clock, await make_admin("support"))
    admin = await signed_in(client, clock, await make_admin("admin"))
    boss = await signed_in(client, clock, await make_admin("superadmin"))
    u = await make_user("target")
    status = f"{ADMIN}/users/{u.id}/status"
    for h in (support, admin, boss):
        assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 200
        assert (await client.get(f"{ADMIN}/audit", headers=h)).status_code == 200
        assert (await client.get(f"{ADMIN}/errors", headers=h)).status_code == 200
    assert (
        await client.patch(status, json={"is_active": False}, headers=support)
    ).status_code == 403
    assert (
        await client.patch(status, json={"is_active": False}, headers=admin)
    ).status_code == 200
    for h in (support, admin):
        assert (await client.get(f"{AUTH}/accounts", headers=h)).status_code == 403
        assert (
            await client.post(
                f"{AUTH}/accounts",
                json={
                    "email": "x@example.org",
                    "role": "superadmin",
                    "temporary_password": "Temp-Passw0rd-xyz",
                },
                headers=h,
            )
        ).status_code == 403
    assert (await client.get(f"{AUTH}/accounts", headers=boss)).status_code == 200


@pytest.mark.security
async def test_an_admin_cannot_promote_or_modify_accounts(client, clock, make_admin):
    admin_acct = await make_admin("admin")
    h = await signed_in(client, clock, admin_acct)
    for path, body in (
        (f"{AUTH}/accounts/{admin_acct.id}/role", {"role": "superadmin"}),
        (f"{AUTH}/accounts/{admin_acct.id}/reset-mfa", None),
        (f"{AUTH}/accounts/{admin_acct.id}/unlock", None),
        (f"{AUTH}/accounts/{admin_acct.id}/disable", None),
        (
            f"{AUTH}/accounts/{admin_acct.id}/reset-password",
            {"temporary_password": "Temp-Passw0rd-xyz"},
        ),
    ):
        r = (
            await client.post(path, json=body, headers=h)
            if body
            else await client.post(path, headers=h)
        )
        assert r.status_code == 403, path
    assert (
        await login(client, clock, admin_acct)
    ).status_code == 200  # nothing changed


@pytest.mark.security
async def test_the_last_superadmin_cannot_be_locked_out_or_demoted(
    client, clock, make_admin
):
    only = await make_admin("superadmin")
    h = await signed_in(client, clock, only)
    assert (
        await client.post(f"{AUTH}/accounts/{only.id}/disable", headers=h)
    ).status_code == 409
    assert (
        await client.post(
            f"{AUTH}/accounts/{only.id}/role", json={"role": "admin"}, headers=h
        )
    ).status_code == 409
    assert (
        await client.post(f"{AUTH}/accounts/{only.id}/reset-mfa", headers=h)
    ).status_code == 409
    assert (
        await client.post(
            f"{AUTH}/accounts/{only.id}/reset-password",
            json={"temporary_password": "Temp-Passw0rd-xyz"},
            headers=h,
        )
    ).status_code == 409


async def test_account_lifecycle_by_a_superadmin(
    client, clock, make_admin, session_factory
):
    boss = await make_admin("superadmin")
    other = await make_admin("superadmin")
    h = await signed_in(client, clock, boss)

    created = await client.post(
        f"{AUTH}/accounts",
        json={
            "email": "New.Person@Example.org",
            "role": "support",
            "temporary_password": "Temp-Passw0rd-xyz",
        },
        headers=h,
    )
    assert created.status_code == 201
    c = created.json()
    assert (
        c["email"] == "new.person@example.org"
        and c["must_change_password"]
        and not c["mfa_enabled"]
    )
    assert not {"password_hash", "totp_secret_enc", "recovery_hashes"} & set(c)
    dup = await client.post(
        f"{AUTH}/accounts",
        json={
            "email": "new.person@example.org",
            "role": "admin",
            "temporary_password": "Temp-Passw0rd-xyz",
        },
        headers=h,
    )
    assert dup.status_code == 409
    for body in (
        {
            "email": "not-an-email",
            "role": "support",
            "temporary_password": "Temp-Passw0rd-xyz",
        },
        {
            "email": "ok@example.org",
            "role": "root",
            "temporary_password": "Temp-Passw0rd-xyz",
        },
        {"email": "ok@example.org", "role": "support", "temporary_password": "weak"},
    ):
        assert (
            await client.post(f"{AUTH}/accounts", json=body, headers=h)
        ).status_code == 422, body

    # role change forces a new sign-in; demoting another superadmin is allowed while one remains
    oh = await signed_in(client, clock, other)
    assert (
        await client.post(
            f"{AUTH}/accounts/{other.id}/role", json={"role": "admin"}, headers=h
        )
    ).status_code == 200
    assert (await client.get(f"{ADMIN}/stats", headers=oh)).status_code == 401
    assert (
        await client.post(
            f"{AUTH}/accounts/{other.id}/role", json={"role": "root"}, headers=h
        )
    ).status_code == 422
    listing = (await client.get(f"{AUTH}/accounts", headers=h)).json()["items"]
    assert {i["email"] for i in listing} >= {
        boss.email,
        other.email,
        "new.person@example.org",
    }
    assert (
        await client.post(f"{AUTH}/accounts/not-a-uuid/disable", headers=h)
    ).status_code == 404

    actions = {r.action for r in await audit_rows(session_factory)}
    assert {"admin.account_created", "admin.role_changed"} <= actions


# ── recovery ─────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.security
async def test_superadmin_can_reset_mfa_and_password_for_a_locked_out_admin(
    client, clock, make_admin, session_factory
):
    boss = await make_admin("superadmin")
    lost = await make_admin("admin")
    old_session = await signed_in(client, clock, lost)
    h = await signed_in(client, clock, boss)

    assert (
        await client.post(f"{AUTH}/accounts/{lost.id}/reset-mfa", headers=h)
    ).status_code == 200
    assert (await client.get(f"{ADMIN}/stats", headers=old_session)).status_code == 401
    # the lost authenticator no longer works; the password alone only reaches the setup scope
    r = await client.post(
        f"{AUTH}/login", json={"email": lost.email, "password": PASSWORD}
    )
    assert (
        r.status_code == 200
        and r.json()["scope"] == "setup"
        and r.json()["setup_required"] == ["mfa"]
    )
    assert (await client.get(f"{ADMIN}/stats", headers=bearer(r))).status_code == 403

    assert (
        await client.post(
            f"{AUTH}/accounts/{lost.id}/reset-password",
            json={"temporary_password": "Fresh-Temp-Passw0rd"},
            headers=h,
        )
    ).status_code == 200
    assert (
        await client.post(
            f"{AUTH}/login", json={"email": lost.email, "password": PASSWORD}
        )
    ).status_code == 401
    r2 = await client.post(
        f"{AUTH}/login", json={"email": lost.email, "password": "Fresh-Temp-Passw0rd"}
    )
    assert r2.status_code == 200 and set(r2.json()["setup_required"]) == {
        "password",
        "mfa",
    }
    actions = {r.action for r in await audit_rows(session_factory)}
    assert {"admin.mfa_reset", "admin.password_reset"} <= actions


async def test_superadmin_can_unlock_a_locked_account(
    client, clock, make_admin, monkeypatch
):
    monkeypatch.setattr(admin_settings, "ADMIN_LOGIN_MAX_FAILURES", 3)
    boss, victim = await make_admin("superadmin"), await make_admin("admin")
    h = await signed_in(client, clock, boss)
    for _ in range(3):
        await login(client, clock, victim, password="Wrong-Password-1234")
    assert (await login(client, clock, victim)).status_code == 401
    assert (
        await client.post(f"{AUTH}/accounts/{victim.id}/unlock", headers=h)
    ).status_code == 200
    assert (await login(client, clock, victim)).status_code == 200


# ── audit ────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.security
async def test_privileged_actions_are_attributed_and_the_log_holds_no_secrets(
    client, clock, make_admin, make_user, session_factory
):
    a = await make_admin("admin")
    h = await signed_in(client, clock, a)
    u = await make_user("tgt")
    await client.patch(
        f"{ADMIN}/users/{u.id}/status", json={"is_active": False}, headers=h
    )
    await client.patch(
        f"{ADMIN}/users/{u.id}/status", json={"is_active": True}, headers=LEGACY
    )

    rows = await audit_rows(session_factory)
    by_action = {}
    for r in rows:
        by_action.setdefault((r.action, r.actor_label), r)
    assert ("user.disable", f"admin:{a.id}") in by_action
    assert by_action[("user.disable", f"admin:{a.id}")].actor_admin_id == a.id
    assert ("user.enable", "legacy-token") in by_action and by_action[
        ("user.enable", "legacy-token")
    ].actor_admin_id is None

    blob = " ".join(
        f"{r.action} {r.detail} {r.client_ip} {r.actor_label}" for r in rows
    ).lower()
    for secret in (PASSWORD.lower(), a.secret.lower(), "password_hash", "totp"):
        assert secret not in blob, secret
    api = (await client.get(f"{ADMIN}/audit", headers=h)).json()["items"]
    assert any(
        i["actor"] == f"admin:{a.id}" and i["actor_admin_id"] == str(a.id) for i in api
    )
    assert any(i["actor"] == "legacy-token" for i in api)


# ── legacy token migration path ──────────────────────────────────────────────────────────────────────────────────
@pytest.mark.security
async def test_legacy_token_keeps_working_but_cannot_manage_admins_or_touch_sessions(
    client, make_user
):
    u = await make_user("t")
    assert (await client.get(f"{ADMIN}/stats", headers=LEGACY)).status_code == 200
    assert (
        await client.patch(
            f"{ADMIN}/users/{u.id}/status", json={"is_active": False}, headers=LEGACY
        )
    ).status_code == 200
    for method, path in (
        ("get", f"{AUTH}/accounts"),
        ("get", f"{AUTH}/sessions"),
        ("post", f"{AUTH}/logout"),
        ("post", f"{AUTH}/mfa/enroll/start"),
        ("post", f"{AUTH}/accounts/{uuid.uuid4()}/disable"),
    ):
        r = await getattr(client, method)(path, headers=LEGACY)
        assert r.status_code in (401, 403), (path, r.status_code)
    me = await client.get(f"{AUTH}/me", headers=LEGACY)
    assert me.status_code == 200 and me.json() == {
        "kind": "legacy",
        "role": "admin",
        "email": None,
    }


@pytest.mark.security
async def test_legacy_token_can_be_switched_off_without_affecting_named_admins(
    client, clock, make_admin, monkeypatch
):
    a = await make_admin("admin")
    h = await signed_in(client, clock, a)
    monkeypatch.setattr(admin_settings, "ADMIN_LEGACY_TOKEN_ENABLED", False)
    r = await client.get(f"{ADMIN}/stats", headers=LEGACY)
    assert r.status_code == 401
    assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 200
    # even the correct legacy token consumes no failed-attempt budget while disabled
    assert (
        await client.get(f"{ADMIN}/stats", headers={"X-Admin-Token": "wrong"})
    ).status_code == 401


@pytest.mark.security
async def test_wrong_legacy_tokens_are_still_throttled_while_enabled(
    client, monkeypatch
):
    monkeypatch.setattr(settings, "ADMIN_AUTH_FAIL_LIMIT", 3)
    codes = [
        (
            await client.get(f"{ADMIN}/stats", headers={"X-Admin-Token": f"bad{i}"})
        ).status_code
        for i in range(5)
    ]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


async def test_console_page_is_served_with_a_strict_csp_and_no_embedded_secret(client):
    r = await client.get(f"{ADMIN}/console")
    assert (
        r.status_code == 200
        and "default-src 'none'" in r.headers["content-security-policy"]
    )
    assert r.headers["cache-control"] == "no-store"
    assert (
        "Authorization" in r.text
        and "localStorage" not in r.text
        and "sessionStorage" not in r.text
    )
    assert "test-admin-token" not in r.text


async def test_sessions_table_is_cleaned_with_the_account(session_factory, make_admin):
    a = await make_admin("admin")
    async with session_factory() as s:
        s.add(
            AdminSession(
                admin_id=a.id,
                scope="full",
                expires_at=datetime.utcnow() + timedelta(hours=1),
            )
        )
        await s.commit()
        await s.execute(text("delete from admin_accounts where id = :i"), {"i": a.id})
        await s.commit()
        assert (await s.execute(select(AdminSession))).scalars().all() == []


@pytest.mark.security
async def test_a_token_dies_when_the_account_is_deactivated_directly_in_the_database(
    client, clock, make_admin, session_factory
):
    """Account state is read from the database on every request, not only through the API that revokes sessions."""
    a = await make_admin("admin")
    h = await signed_in(client, clock, a)
    assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 200
    async with session_factory() as s:
        await s.execute(
            text("update admin_accounts set is_active = false where id = :i"),
            {"i": a.id},
        )
        await s.commit()
    assert (await client.get(f"{ADMIN}/stats", headers=h)).status_code == 401


@pytest.mark.security
async def test_an_admin_token_never_authenticates_an_end_user_even_with_the_same_id(
    client, clock, make_admin, session_factory
):
    from app.models.user import User

    a = await make_admin("admin")
    h = await signed_in(client, clock, a)
    async with session_factory() as s:
        s.add(User(id=a.id, email="twin@example.com", full_name="Twin"))
        await s.commit()
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 401


@pytest.mark.security
async def test_two_superadmins_cannot_remove_each_other_concurrently(
    client, clock, make_admin, session_factory
):
    """Both checks would see the other as active; only the serialised account changes keep one superadmin standing."""
    import asyncio

    a, b = await make_admin("superadmin"), await make_admin("superadmin")
    ha = await signed_in(client, clock, a)
    hb = await signed_in(client, clock, b)
    ra, rb = await asyncio.gather(
        client.post(f"{AUTH}/accounts/{b.id}/disable", headers=ha),
        client.post(f"{AUTH}/accounts/{a.id}/disable", headers=hb),
    )
    assert sorted([ra.status_code, rb.status_code]) != [200, 200], (
        ra.status_code,
        rb.status_code,
    )
    async with session_factory() as s:
        active = (
            await s.execute(
                text(
                    "select count(*) from admin_accounts where role = 'superadmin' and is_active"
                )
            )
        ).scalar_one()
    assert active >= 1
