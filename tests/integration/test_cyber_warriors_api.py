"""Database-backed API tests for the Cyber Warriors volunteer + admin workflow.

Every test runs against a real PostgreSQL schema (alembic head) via the
fail-closed harness in conftest.py. Covers: submission, validation/consent,
duplicates, profile access, approval, rejection, RBAC, unauthenticated
access, audit logging, DB constraints and transaction rollback.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError

from app.models.cyber_warrior import (
    ApplicationStatus,
    AuditAction,
    WarriorApplication,
    WarriorAuditLog,
    WarriorProfile,
    WarriorRole,
)
from app.models.user import User
from tests.integration.conftest import adult_dob, application_payload, minor_dob

pytestmark = pytest.mark.integration

APPLY = "/api/v1/warriors/apply"
MY_APP = "/api/v1/warriors/me/application"
MY_PROFILE = "/api/v1/warriors/me"
ADMIN_LIST = "/api/v1/warriors/admin/applications"


def approve_url(app_id) -> str:
    return f"/api/v1/warriors/admin/applications/{app_id}/approve"


def reject_url(app_id) -> str:
    return f"/api/v1/warriors/admin/applications/{app_id}/reject"


async def _count(db, model, *where) -> int:
    stmt = select(func.count()).select_from(model)
    for clause in where:
        stmt = stmt.where(clause)
    return (await db.execute(stmt)).scalar_one()


# ═══════════════════════════════════════════════════════════════════════════
# Submission
# ═══════════════════════════════════════════════════════════════════════════

class TestSubmitApplication:
    async def test_valid_submission_creates_pending_application(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user("applicant")
        r = await client.post(APPLY, json=application_payload(),
                              headers=auth_headers(user))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "pending"
        assert body["user_id"] == str(user.id)
        assert body["preferred_role"] == "trainee"

        row = (await db.execute(select(WarriorApplication))).scalar_one()
        assert row.user_id == user.id
        assert row.status == ApplicationStatus.pending
        assert row.consent_bgcheck and row.consent_pii and row.consent_safeguarding
        assert row.email == "priya.volunteer@example.com"

    async def test_submission_writes_audit_log(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user("applicant")
        await client.post(APPLY, json=application_payload(),
                          headers=auth_headers(user))
        log = (await db.execute(select(WarriorAuditLog))).scalar_one()
        assert log.action == AuditAction.application_submitted
        assert log.actor_user_id == user.id
        assert log.subject_user_id == user.id
        assert log.extra["preferred_role"] == "trainee"

    async def test_unauthenticated_submission_rejected(self, client, db):
        r = await client.post(APPLY, json=application_payload())
        assert r.status_code in (401, 403)
        assert await _count(db, WarriorApplication) == 0

    async def test_garbage_token_rejected(self, client, db):
        r = await client.post(
            APPLY, json=application_payload(),
            headers={"Authorization": "Bearer not.a.jwt"},
        )
        assert r.status_code == 401
        assert await _count(db, WarriorApplication) == 0

    async def test_token_for_unknown_user_rejected(self, client, db, auth_headers):
        ghost = User(id=uuid.uuid4(), email="ghost@example.com", is_active=True)
        r = await client.post(APPLY, json=application_payload(),
                              headers=auth_headers(ghost))
        assert r.status_code == 401
        assert await _count(db, WarriorApplication) == 0

    async def test_inactive_user_cannot_apply(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user("gone", is_active=False)
        r = await client.post(APPLY, json=application_payload(),
                              headers=auth_headers(user))
        assert r.status_code == 401
        assert await _count(db, WarriorApplication) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Validation + safeguarding
# ═══════════════════════════════════════════════════════════════════════════

class TestSafeguardingValidation:
    async def test_minor_applicant_rejected_and_nothing_persisted(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user("kid")
        r = await client.post(
            APPLY,
            json=application_payload(date_of_birth=minor_dob().isoformat()),
            headers=auth_headers(user),
        )
        assert r.status_code == 422
        assert await _count(db, WarriorApplication) == 0
        assert await _count(db, WarriorAuditLog) == 0

    @pytest.mark.parametrize(
        "flag", ["consent_bgcheck", "consent_pii", "consent_safeguarding"]
    )
    async def test_each_consent_flag_is_mandatory(
        self, client, db, make_user, auth_headers, flag
    ):
        user = await make_user("consent")
        r = await client.post(APPLY, json=application_payload(**{flag: False}),
                              headers=auth_headers(user))
        assert r.status_code == 422
        assert await _count(db, WarriorApplication) == 0

    @pytest.mark.parametrize("flag", ["consent_bgcheck", "consent_pii",
                                      "consent_safeguarding"])
    async def test_missing_consent_field_rejected(
        self, client, db, make_user, auth_headers, flag
    ):
        user = await make_user("consent")
        payload = application_payload()
        payload.pop(flag)
        r = await client.post(APPLY, json=payload, headers=auth_headers(user))
        assert r.status_code == 422
        assert await _count(db, WarriorApplication) == 0

    @pytest.mark.parametrize("role", ["admin", "moderator", "mentor"])
    async def test_self_escalation_to_privileged_role_rejected(
        self, client, db, make_user, auth_headers, role
    ):
        user = await make_user("climber")
        r = await client.post(APPLY, json=application_payload(preferred_role=role),
                              headers=auth_headers(user))
        assert r.status_code == 422
        assert await _count(db, WarriorApplication) == 0

    async def test_short_motivation_rejected(
        self, client, make_user, auth_headers
    ):
        user = await make_user("terse")
        r = await client.post(APPLY, json=application_payload(motivation="help"),
                              headers=auth_headers(user))
        assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
# Duplicates
# ═══════════════════════════════════════════════════════════════════════════

class TestDuplicateApplications:
    async def test_second_pending_application_conflicts(
        self, client, db, make_user, auth_headers
    ):
        user = await make_user("dup")
        first = await client.post(APPLY, json=application_payload(),
                                  headers=auth_headers(user))
        second = await client.post(APPLY, json=application_payload(),
                                   headers=auth_headers(user))
        assert first.status_code == 201
        assert second.status_code == 409
        assert await _count(db, WarriorApplication) == 1
        # Only the first submission is audited
        assert await _count(db, WarriorAuditLog) == 1

    async def test_active_warrior_cannot_reapply(
        self, client, db, make_user, make_warrior, auth_headers
    ):
        user = await make_user("already")
        await make_warrior(user, "trainee")
        r = await client.post(APPLY, json=application_payload(),
                              headers=auth_headers(user))
        assert r.status_code == 409
        assert await _count(db, WarriorApplication) == 0

    async def test_can_reapply_after_rejection(
        self, client, db, make_user, make_warrior, auth_headers
    ):
        admin = await make_user("admin")
        await make_warrior(admin, "admin")
        user = await make_user("retry")
        first = await client.post(APPLY, json=application_payload(),
                                  headers=auth_headers(user))
        rej = await client.post(
            reject_url(first.json()["id"]),
            json={"reviewer_notes": "Please add references"},
            headers=auth_headers(admin),
        )
        assert rej.status_code == 204
        again = await client.post(APPLY, json=application_payload(),
                                  headers=auth_headers(user))
        assert again.status_code == 201
        assert await _count(
            db, WarriorApplication, WarriorApplication.user_id == user.id
        ) == 2


# ═══════════════════════════════════════════════════════════════════════════
# Profile + own-application access
# ═══════════════════════════════════════════════════════════════════════════

class TestOwnApplicationAndProfile:
    async def test_my_application_none_before_applying(
        self, client, make_user, auth_headers
    ):
        user = await make_user("fresh")
        r = await client.get(MY_APP, headers=auth_headers(user))
        assert r.status_code == 200
        assert r.json() is None

    async def test_my_application_is_scoped_to_caller(
        self, client, make_user, auth_headers
    ):
        alice = await make_user("alice")
        bob = await make_user("bob")
        applied = await client.post(APPLY, json=application_payload(),
                                    headers=auth_headers(alice))
        mine = await client.get(MY_APP, headers=auth_headers(alice))
        theirs = await client.get(MY_APP, headers=auth_headers(bob))
        assert mine.json()["id"] == applied.json()["id"]
        assert theirs.json() is None  # no IDOR: bob never sees alice's row

    async def test_profile_denied_until_approved(
        self, client, make_user, auth_headers
    ):
        user = await make_user("pending")
        await client.post(APPLY, json=application_payload(),
                          headers=auth_headers(user))
        r = await client.get(MY_PROFILE, headers=auth_headers(user))
        assert r.status_code == 403

    async def test_non_warrior_and_pending_get_identical_denial(
        self, client, make_user, auth_headers
    ):
        """No information leak: pending applicants and strangers look alike."""
        stranger = await make_user("stranger")
        pending = await make_user("pending")
        await client.post(APPLY, json=application_payload(),
                          headers=auth_headers(pending))
        a = await client.get(MY_PROFILE, headers=auth_headers(stranger))
        b = await client.get(MY_PROFILE, headers=auth_headers(pending))
        assert a.status_code == b.status_code == 403
        # Bodies are identical apart from the per-request correlation id.
        def strip(body):
            return {k: v for k, v in body.items() if k != "request_id"}

        assert strip(a.json()) == strip(b.json())

    async def test_suspended_warrior_denied(
        self, client, make_user, make_warrior, auth_headers
    ):
        user = await make_user("suspended")
        await make_warrior(user, "verified_warrior", is_active=False)
        r = await client.get(MY_PROFILE, headers=auth_headers(user))
        assert r.status_code == 403

    async def test_unauthenticated_profile_denied(self, client):
        r = await client.get(MY_PROFILE)
        assert r.status_code in (401, 403)


# ═══════════════════════════════════════════════════════════════════════════
# Admin: RBAC + approve / reject + audit
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
async def pending_application(client, make_user, auth_headers):
    """(applicant, application_id) with one pending application."""
    applicant = await make_user("candidate")
    r = await client.post(APPLY, json=application_payload(),
                          headers=auth_headers(applicant))
    assert r.status_code == 201
    return applicant, r.json()["id"]


@pytest.fixture
async def admin_user(make_user, make_warrior):
    admin = await make_user("admin")
    await make_warrior(admin, "admin")
    return admin


class TestAdminRbac:
    @pytest.mark.parametrize("method,builder", [
        ("get", lambda i: ADMIN_LIST),
        ("post", lambda i: approve_url(i)),
        ("post", lambda i: reject_url(i)),
    ])
    async def test_unauthenticated_denied(
        self, client, pending_application, method, builder
    ):
        _, app_id = pending_application
        kwargs = {"json": {"reviewer_notes": "no way"}} if method == "post" else {}
        r = await getattr(client, method)(builder(app_id), **kwargs)
        assert r.status_code in (401, 403)

    @pytest.mark.parametrize("method,builder", [
        ("get", lambda i: ADMIN_LIST),
        ("post", lambda i: approve_url(i)),
        ("post", lambda i: reject_url(i)),
    ])
    async def test_plain_user_denied(
        self, client, make_user, auth_headers, pending_application,
        method, builder,
    ):
        _, app_id = pending_application
        rando = await make_user("rando")
        kwargs = {"json": {"reviewer_notes": "let me in"}} if method == "post" else {}
        r = await getattr(client, method)(
            builder(app_id), headers=auth_headers(rando), **kwargs
        )
        assert r.status_code == 403

    @pytest.mark.parametrize("role", ["trainee", "verified_warrior", "mentor",
                                      "moderator"])
    async def test_non_admin_warrior_roles_denied(
        self, client, make_user, make_warrior, auth_headers,
        pending_application, role,
    ):
        _, app_id = pending_application
        warrior = await make_user(role)
        await make_warrior(warrior, role)
        for call in (
            client.get(ADMIN_LIST, headers=auth_headers(warrior)),
            client.post(approve_url(app_id), json={},
                        headers=auth_headers(warrior)),
            client.post(reject_url(app_id),
                        json={"reviewer_notes": "nope nope"},
                        headers=auth_headers(warrior)),
        ):
            assert (await call).status_code == 403

    async def test_denied_attempts_do_not_change_state(
        self, client, db, make_user, make_warrior, auth_headers,
        pending_application,
    ):
        _, app_id = pending_application
        mentor = await make_user("mentor")
        await make_warrior(mentor, "mentor")
        await client.post(approve_url(app_id), json={},
                          headers=auth_headers(mentor))
        row = await db.get(WarriorApplication, uuid.UUID(app_id))
        assert row.status == ApplicationStatus.pending
        assert await _count(db, WarriorProfile) == 1  # only the mentor's own

    async def test_suspended_admin_denied(
        self, client, make_user, make_warrior, auth_headers
    ):
        admin = await make_user("exadmin")
        await make_warrior(admin, "admin", is_active=False)
        r = await client.get(ADMIN_LIST, headers=auth_headers(admin))
        assert r.status_code == 403


class TestApproval:
    async def test_admin_lists_pending_oldest_first(
        self, client, make_user, auth_headers, admin_user
    ):
        ids = []
        for label in ("a", "b", "c"):
            u = await make_user(label)
            r = await client.post(
                APPLY,
                json=application_payload(email=f"{label}@example.com"),
                headers=auth_headers(u),
            )
            ids.append(r.json()["id"])
        r = await client.get(ADMIN_LIST, headers=auth_headers(admin_user))
        assert r.status_code == 200
        assert [a["id"] for a in r.json()] == ids

    async def test_approval_creates_profile_and_updates_application(
        self, client, db, auth_headers, admin_user, pending_application
    ):
        applicant, app_id = pending_application
        r = await client.post(
            approve_url(app_id),
            json={"reviewer_notes": "Strong references"},
            headers=auth_headers(admin_user),
        )
        assert r.status_code == 200, r.text
        assert r.json()["role"] == "trainee"
        assert r.json()["user_id"] == str(applicant.id)

        app_row = await db.get(WarriorApplication, uuid.UUID(app_id))
        await db.refresh(app_row)
        assert app_row.status == ApplicationStatus.approved
        assert app_row.reviewer_user_id == admin_user.id
        assert app_row.reviewer_notes == "Strong references"
        assert app_row.reviewed_at is not None

        profile = (await db.execute(
            select(WarriorProfile).where(WarriorProfile.user_id == applicant.id)
        )).scalar_one()
        assert profile.is_active and profile.role == WarriorRole.trainee
        assert profile.application_id == app_row.id

    async def test_approved_applicant_can_now_access_profile(
        self, client, auth_headers, admin_user, pending_application
    ):
        applicant, app_id = pending_application
        await client.post(approve_url(app_id), json={},
                          headers=auth_headers(admin_user))
        r = await client.get(MY_PROFILE, headers=auth_headers(applicant))
        assert r.status_code == 200
        assert r.json()["role"] == "trainee"

    async def test_approval_audit_log(
        self, client, db, auth_headers, admin_user, pending_application
    ):
        applicant, app_id = pending_application
        await client.post(
            approve_url(app_id),
            json={"reviewer_notes": "ok", "assigned_role": "verified_warrior"},
            headers=auth_headers(admin_user),
        )
        log = (await db.execute(
            select(WarriorAuditLog).where(
                WarriorAuditLog.action == AuditAction.application_approved
            )
        )).scalar_one()
        assert log.actor_user_id == admin_user.id
        assert log.subject_user_id == applicant.id
        assert log.extra == {"application_id": app_id,
                             "assigned_role": "verified_warrior"}
        assert log.reason == "ok"

    @pytest.mark.parametrize("role", ["admin", "moderator", "mentor"])
    async def test_cannot_approve_directly_into_privileged_role(
        self, client, db, auth_headers, admin_user, pending_application, role
    ):
        _, app_id = pending_application
        r = await client.post(approve_url(app_id),
                              json={"assigned_role": role},
                              headers=auth_headers(admin_user))
        assert r.status_code == 422
        row = await db.get(WarriorApplication, uuid.UUID(app_id))
        assert row.status == ApplicationStatus.pending

    async def test_double_approval_conflicts(
        self, client, db, auth_headers, admin_user, pending_application
    ):
        _, app_id = pending_application
        first = await client.post(approve_url(app_id), json={},
                                  headers=auth_headers(admin_user))
        second = await client.post(approve_url(app_id), json={},
                                   headers=auth_headers(admin_user))
        assert first.status_code == 200
        assert second.status_code == 409
        # admin's own profile + the new warrior's
        assert await _count(db, WarriorProfile) == 2

    async def test_unknown_application_is_404(
        self, client, auth_headers, admin_user
    ):
        r = await client.post(approve_url(uuid.uuid4()), json={},
                              headers=auth_headers(admin_user))
        assert r.status_code == 404

    async def test_malformed_application_id_is_422(
        self, client, auth_headers, admin_user
    ):
        r = await client.post("/api/v1/warriors/admin/applications/not-a-uuid/approve",
                              json={}, headers=auth_headers(admin_user))
        assert r.status_code == 422

    async def test_existing_inactive_profile_blocks_reapproval(
        self, client, db, make_user, make_warrior, auth_headers, admin_user
    ):
        user = await make_user("returning")
        await make_warrior(user, "trainee", is_active=False)
        # A pending application can be inserted directly (API blocks only
        # *active* profiles at submit time).
        app_row = WarriorApplication(
            user_id=user.id, full_name="Return Ee", date_of_birth=adult_dob(),
            phone="+919876500000", email="return@example.com",
            motivation="x" * 50, consent_bgcheck=True, consent_pii=True,
            consent_safeguarding=True,
        )
        db.add(app_row)
        await db.commit()
        r = await client.post(approve_url(app_row.id), json={},
                              headers=auth_headers(admin_user))
        assert r.status_code == 409


class TestRejection:
    async def test_rejection_updates_state_and_audits(
        self, client, db, auth_headers, admin_user, pending_application
    ):
        applicant, app_id = pending_application
        r = await client.post(
            reject_url(app_id),
            json={"reviewer_notes": "Insufficient experience"},
            headers=auth_headers(admin_user),
        )
        assert r.status_code == 204

        row = await db.get(WarriorApplication, uuid.UUID(app_id))
        await db.refresh(row)
        assert row.status == ApplicationStatus.rejected
        assert row.reviewer_user_id == admin_user.id
        assert row.reviewer_notes == "Insufficient experience"
        assert row.reviewed_at is not None
        # No profile was created for the applicant
        assert await _count(
            db, WarriorProfile, WarriorProfile.user_id == applicant.id
        ) == 0

        log = (await db.execute(
            select(WarriorAuditLog).where(
                WarriorAuditLog.action == AuditAction.application_rejected
            )
        )).scalar_one()
        assert log.actor_user_id == admin_user.id
        assert log.subject_user_id == applicant.id
        assert log.reason == "Insufficient experience"

    @pytest.mark.parametrize("payload", [{}, {"reviewer_notes": "no"}])
    async def test_reason_is_mandatory(
        self, client, db, auth_headers, admin_user, pending_application, payload
    ):
        _, app_id = pending_application
        r = await client.post(reject_url(app_id), json=payload,
                              headers=auth_headers(admin_user))
        assert r.status_code == 422
        row = await db.get(WarriorApplication, uuid.UUID(app_id))
        assert row.status == ApplicationStatus.pending

    async def test_rejected_application_cannot_then_be_approved(
        self, client, db, auth_headers, admin_user, pending_application
    ):
        applicant, app_id = pending_application
        await client.post(reject_url(app_id),
                          json={"reviewer_notes": "Not a fit"},
                          headers=auth_headers(admin_user))
        r = await client.post(approve_url(app_id), json={},
                              headers=auth_headers(admin_user))
        assert r.status_code == 409
        assert await _count(
            db, WarriorProfile, WarriorProfile.user_id == applicant.id
        ) == 0

    async def test_double_rejection_conflicts(
        self, client, auth_headers, admin_user, pending_application
    ):
        _, app_id = pending_application
        body = {"reviewer_notes": "Not a fit"}
        first = await client.post(reject_url(app_id), json=body,
                                  headers=auth_headers(admin_user))
        second = await client.post(reject_url(app_id), json=body,
                                   headers=auth_headers(admin_user))
        assert (first.status_code, second.status_code) == (204, 409)

    async def test_rejected_applicant_still_denied_profile(
        self, client, auth_headers, admin_user, pending_application
    ):
        applicant, app_id = pending_application
        await client.post(reject_url(app_id),
                          json={"reviewer_notes": "Not a fit"},
                          headers=auth_headers(admin_user))
        r = await client.get(MY_PROFILE, headers=auth_headers(applicant))
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# Transaction rollback
# ═══════════════════════════════════════════════════════════════════════════

class TestTransactionalIntegrity:
    async def test_failed_audit_write_rolls_back_the_approval(
        self, lenient_client, db, monkeypatch, auth_headers, admin_user,
        pending_application,
    ):
        """If the audit row cannot be committed, the profile + status change
        must NOT persist (single transaction)."""
        import app.routers.cyber_warrior as cw

        real = cw.WarriorAuditLog

        def audit_with_bad_actor(**kwargs):
            kwargs["actor_user_id"] = uuid.uuid4()  # FK violation on commit
            return real(**kwargs)

        monkeypatch.setattr(cw, "WarriorAuditLog", audit_with_bad_actor)

        applicant, app_id = pending_application
        r = await lenient_client.post(
            approve_url(app_id), json={}, headers=auth_headers(admin_user)
        )
        assert r.status_code == 500

        row = await db.get(WarriorApplication, uuid.UUID(app_id))
        await db.refresh(row)
        assert row.status == ApplicationStatus.pending
        assert row.reviewer_user_id is None
        assert await _count(
            db, WarriorProfile, WarriorProfile.user_id == applicant.id
        ) == 0
        assert await _count(
            db, WarriorAuditLog,
            WarriorAuditLog.action == AuditAction.application_approved,
        ) == 0

    async def test_failed_audit_write_rolls_back_the_submission(
        self, lenient_client, db, monkeypatch, make_user, auth_headers
    ):
        import app.routers.cyber_warrior as cw

        real = cw.WarriorAuditLog

        def bad(**kwargs):
            kwargs["actor_user_id"] = uuid.uuid4()
            return real(**kwargs)

        monkeypatch.setattr(cw, "WarriorAuditLog", bad)
        user = await make_user("unlucky")
        r = await lenient_client.post(APPLY, json=application_payload(),
                                      headers=auth_headers(user))
        assert r.status_code == 500
        assert await _count(db, WarriorApplication) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Database constraints (independent of the API layer)
# ═══════════════════════════════════════════════════════════════════════════

def _application(user_id, **kw) -> WarriorApplication:
    base = dict(
        user_id=user_id, full_name="Db Test", date_of_birth=adult_dob(),
        phone="+919876500001", email="db@example.com", motivation="y" * 50,
        consent_bgcheck=True, consent_pii=True, consent_safeguarding=True,
    )
    base.update(kw)
    return WarriorApplication(**base)


class TestDatabaseConstraints:
    async def test_partial_unique_index_blocks_second_pending(self, db, make_user):
        user = await make_user("u")
        db.add(_application(user.id))
        await db.commit()
        db.add(_application(user.id))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()

    async def test_partial_unique_index_allows_pending_plus_closed(
        self, db, make_user
    ):
        user = await make_user("u")
        db.add_all([
            _application(user.id, status=ApplicationStatus.rejected),
            _application(user.id, status=ApplicationStatus.withdrawn),
            _application(user.id, status=ApplicationStatus.pending),
        ])
        await db.commit()
        assert await _count(db, WarriorApplication) == 3

    async def test_one_profile_per_user(self, db, make_user, make_warrior):
        user = await make_user("u")
        await make_warrior(user, "trainee")
        db.add(WarriorProfile(user_id=user.id, role=WarriorRole.mentor,
                              display_name="Dup", date_of_birth=adult_dob()))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()

    @pytest.mark.parametrize("flag", ["consent_bgcheck", "consent_pii",
                                      "consent_safeguarding"])
    async def test_consent_columns_are_not_null(self, db, make_user, flag):
        user = await make_user("u")
        db.add(_application(user.id, **{flag: None}))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()

    async def test_date_of_birth_is_not_null(self, db, make_user):
        user = await make_user("u")
        db.add(_application(user.id, date_of_birth=None))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()

    async def test_application_requires_existing_user(self, db):
        db.add(_application(uuid.uuid4()))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()

    async def test_deleting_user_cascades_to_applications_and_profile(
        self, db, make_user, make_warrior
    ):
        user = await make_user("u")
        db.add(_application(user.id))
        await db.commit()
        await make_warrior(user, "trainee")
        await db.execute(delete(User).where(User.id == user.id))
        await db.commit()
        assert await _count(db, WarriorApplication) == 0
        assert await _count(db, WarriorProfile) == 0

    async def test_audit_log_blocks_hard_delete_of_referenced_user(
        self, db, make_user
    ):
        """Audit rows have no ON DELETE CASCADE: hard-deleting a user that
        appears in the trail is refused (the trail is append-only). Account
        deletion therefore scrubs PII instead of deleting the row."""
        user = await make_user("actor")
        db.add(WarriorAuditLog(actor_user_id=user.id,
                               action=AuditAction.application_submitted))
        await db.commit()
        with pytest.raises(IntegrityError):
            await db.execute(delete(User).where(User.id == user.id))
            await db.commit()
        await db.rollback()

    async def test_invalid_enum_value_rejected_by_database(self, db, make_user):
        user = await make_user("u")
        with pytest.raises(Exception):
            await db.execute(text(
                "INSERT INTO warrior_profiles (user_id, role, display_name, "
                "date_of_birth) VALUES (:u, 'superuser', 'x', '1990-01-01')"
            ), {"u": user.id})
            await db.commit()
        await db.rollback()
