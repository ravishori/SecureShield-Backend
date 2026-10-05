"""Database-backed regression tests for Phase 1A/1B hardening:
rate limiting on enumeration/OTP endpoints, account deletion, and the
422-not-500 validation handler."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.models.cyber_warrior import WarriorApplication, WarriorProfile
from app.models.user import User
from tests.integration.conftest import application_payload

pytestmark = pytest.mark.integration

REGISTER = "/api/v1/auth/register"
CHECK_USER = "/api/v1/auth/check-user"
ME = "/api/v1/auth/me"


@pytest.fixture(autouse=True)
def _stub_otp_delivery(monkeypatch):
    """Never send real email/SMS from tests."""

    async def _fake(identifier, code):  # noqa: ARG001
        return SimpleNamespace(success=True, error=None)

    monkeypatch.setattr("app.routers.auth.deliver_otp", _fake)


def _register_body(n: int, **over) -> dict:
    body = {"first_name": "Test", "last_name": "User", "email": f"reg{n}@example.com"}
    body.update(over)
    return body


# ═══════════════════════════════════════════════════════════════════════════
# 422-not-500 regression (custom validators)
# ═══════════════════════════════════════════════════════════════════════════


class TestValidationErrorsAre422:
    async def test_register_with_bad_email_is_422_not_500(self, client):
        r = await client.post(REGISTER, json=_register_body(1, email="nope"))
        assert r.status_code == 422
        assert r.json()["code"] == 422

    async def test_register_with_short_first_name_is_422(self, client):
        r = await client.post(REGISTER, json=_register_body(2, first_name="A"))
        assert r.status_code == 422

    async def test_register_with_bad_pin_is_422(self, client):
        r = await client.post(REGISTER, json=_register_body(3, pin_code="12"))
        assert r.status_code == 422

    async def test_422_body_is_json_safe_and_hides_input(self, client):
        r = await client.post(REGISTER, json=_register_body(4, email="nope"))
        details = r.json()["details"]
        assert details, "expected validation details"
        assert all("input" not in d for d in details)


# ═══════════════════════════════════════════════════════════════════════════
# Rate limiting
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckUserRateLimit:
    async def test_enumeration_is_throttled_per_ip(self, client):
        statuses = []
        for i in range(32):
            r = await client.get(CHECK_USER, params={"identifier": f"x{i}@example.com"})
            statuses.append(r.status_code)
        assert statuses[:30] == [200] * 30
        assert statuses[30] == 429
        assert statuses[31] == 429

    async def test_429_carries_retry_after(self, client):
        for i in range(30):
            await client.get(CHECK_USER, params={"identifier": f"y{i}@example.com"})
        r = await client.get(CHECK_USER, params={"identifier": "z@example.com"})
        assert r.status_code == 429
        assert r.headers.get("retry-after") == "60"


class TestRegisterRateLimit:
    async def test_per_ip_limit_blocks_eleventh_registration(self, client):
        results = []
        for i in range(11):
            r = await client.post(REGISTER, json=_register_body(100 + i))
            results.append(r.status_code)
        assert results[:10] == [200] * 10, results
        assert results[10] == 429

    async def test_repeated_registration_of_same_email_is_throttled(self, client):
        body = _register_body(500)
        codes = [(await client.post(REGISTER, json=body)).status_code for _ in range(6)]
        # 1st creates the account; 2nd-5th hit the uniqueness check (409);
        # 6th exceeds the per-identifier OTP limit (5/hour) → 429 *before*
        # any account-existence information is returned.
        assert codes == [200, 409, 409, 409, 409, 429]

    async def test_throttled_registration_creates_no_user(self, client, db):
        body = _register_body(600)
        for _ in range(6):
            await client.post(REGISTER, json=body)
        users = (
            (await db.execute(select(User).where(User.email == "reg600@example.com")))
            .scalars()
            .all()
        )
        assert len(users) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Account deletion
# ═══════════════════════════════════════════════════════════════════════════


async def _delete_me(client, headers, confirm="DELETE"):
    return await client.request(
        "DELETE", ME, json={"confirm": confirm}, headers=headers
    )


async def _reload(db, user) -> User:
    """Fresh copy of ``user`` from the DB (fixture objects belong to another
    session, so ``db.refresh`` cannot be used on them)."""
    db.expire_all()
    return (await db.execute(select(User).where(User.id == user.id))).scalar_one()


class TestAccountDeletion:
    async def test_requires_authentication(self, client):
        r = await client.request("DELETE", ME, json={"confirm": "DELETE"})
        assert r.status_code in (401, 403)

    @pytest.mark.parametrize("confirm", ["delete", "DELETE ", "yes", ""])
    async def test_wrong_confirmation_rejected_and_nothing_deleted(
        self, client, db, make_user, auth_headers, confirm
    ):
        user = await make_user("keep")
        r = await _delete_me(client, auth_headers(user), confirm)
        assert r.status_code == 422
        fresh = await _reload(db, user)
        assert fresh.is_active is True and fresh.email is not None

    async def test_scrubs_pii_and_deactivates(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user(
            "leaver", first_name="Lee", last_name="Ver", city="Pune", pin_code="411001"
        )
        r = await _delete_me(client, auth_headers(user))
        assert r.status_code == 200, r.text
        assert r.json()["user_id"] == str(user.id)

        row = (await db.execute(select(User).where(User.id == user.id))).scalar_one()
        await db.refresh(row)
        for field in (
            "email",
            "phone",
            "alt_phone",
            "first_name",
            "last_name",
            "full_name",
            "flat_no",
            "building",
            "street",
            "city",
            "state",
            "pin_code",
            "country",
        ):
            assert getattr(row, field) is None, f"{field} was not scrubbed"
        assert row.is_active is False

    async def test_old_token_is_rejected_after_deletion(
        self, client, make_user, auth_headers
    ):
        user = await make_user("leaver")
        headers = auth_headers(user)
        assert (await _delete_me(client, headers)).status_code == 200
        assert (await client.get(ME, headers=headers)).status_code == 401

    async def test_double_deletion_second_call_unauthorized(
        self, client, make_user, auth_headers
    ):
        user = await make_user("leaver")
        headers = auth_headers(user)
        await _delete_me(client, headers)
        assert (await _delete_me(client, headers)).status_code == 401

    async def test_same_email_can_register_again_after_deletion(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user("leaver", email="comeback@example.com")
        await _delete_me(client, auth_headers(user))
        r = await client.post(
            REGISTER, json=_register_body(700, email="comeback@example.com")
        )
        assert r.status_code == 200, r.text
        rows = (
            (await db.execute(select(User).where(User.email == "comeback@example.com")))
            .scalars()
            .all()
        )
        assert len(rows) == 1 and rows[0].id != user.id

    async def test_deleting_one_account_does_not_touch_another(
        self, client, db, make_user, auth_headers
    ):
        a = await make_user("a")
        b = await make_user("b")
        await _delete_me(client, auth_headers(a))
        fresh_b = await _reload(db, b)
        assert fresh_b.is_active is True and fresh_b.email is not None

    async def test_cyber_warrior_data_is_erased_with_the_account(
        self, client, db, make_user, make_warrior, auth_headers
    ):
        """Volunteer application + profile hold name, DOB, phone, email and a
        free-text motivation — all PII that must not outlive the account."""
        user = await make_user("warrior")
        await make_warrior(user, "verified_warrior")
        applied = await client.post(
            "/api/v1/warriors/apply",
            json=application_payload(),
            headers=auth_headers(user),
        )
        # active warriors can't apply (409) — insert the application directly
        assert applied.status_code == 409
        db.add(
            WarriorApplication(
                user_id=user.id,
                full_name="Warrior Name",
                date_of_birth=__import__("datetime").date(1990, 1, 1),
                phone="+919800000000",
                email="warrior@example.com",
                motivation="m" * 50,
                consent_bgcheck=True,
                consent_pii=True,
                consent_safeguarding=True,
            )
        )
        await db.commit()

        assert (await _delete_me(client, auth_headers(user))).status_code == 200

        apps = (
            (
                await db.execute(
                    select(WarriorApplication).where(
                        WarriorApplication.user_id == user.id
                    )
                )
            )
            .scalars()
            .all()
        )
        profiles = (
            (
                await db.execute(
                    select(WarriorProfile).where(WarriorProfile.user_id == user.id)
                )
            )
            .scalars()
            .all()
        )
        assert apps == [], "warrior application PII survived account deletion"
        assert profiles == [], "warrior profile PII survived account deletion"
