"""One-time first-admin bootstrap CLI (app.cli.bootstrap_admin), against real
PostgreSQL."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.cli.bootstrap_admin import BootstrapError, bootstrap_first_admin
from app.models.cyber_warrior import (
    AuditAction,
    WarriorAuditLog,
    WarriorProfile,
    WarriorRole,
)
from tests.integration.conftest import adult_dob, minor_dob

pytestmark = pytest.mark.integration


async def _run(session_factory, **kw):
    async with session_factory() as s:
        return await bootstrap_first_admin(s, **kw)


async def _count(session_factory, model):
    async with session_factory() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar_one()


async def test_dry_run_changes_nothing(session_factory, make_user):
    user = await make_user("boot")
    out = await _run(
        session_factory, email=user.email, date_of_birth=adult_dob(), execute=False
    )
    assert out.startswith("DRY RUN")
    assert user.email not in out  # masked
    assert await _count(session_factory, WarriorProfile) == 0
    assert await _count(session_factory, WarriorAuditLog) == 0


async def test_execute_creates_admin_profile_and_audit_row(session_factory, make_user):
    user = await make_user("boot")
    out = await _run(
        session_factory,
        email=user.email.upper(),
        date_of_birth=adult_dob(),
        execute=True,
    )
    assert out.startswith("APPLIED")
    async with session_factory() as s:
        profile = (await s.execute(select(WarriorProfile))).scalar_one()
        assert (
            profile.user_id == user.id
            and profile.role == WarriorRole.admin
            and profile.is_active
        )
        log = (await s.execute(select(WarriorAuditLog))).scalar_one()
        assert log.action == AuditAction.role_promoted
        assert log.actor_user_id == log.subject_user_id == user.id
        assert log.extra["method"] == "cli_bootstrap"


async def test_second_run_is_refused_even_for_another_user(session_factory, make_user):
    first, second = await make_user("first"), await make_user("second")
    await _run(
        session_factory, email=first.email, date_of_birth=adult_dob(), execute=True
    )
    with pytest.raises(BootstrapError, match="already exists"):
        await _run(
            session_factory, email=second.email, date_of_birth=adult_dob(), execute=True
        )
    assert await _count(session_factory, WarriorProfile) == 1


async def test_refused_even_if_existing_admin_is_deactivated(
    session_factory, make_user
):
    first, second = await make_user("first"), await make_user("second")
    await _run(
        session_factory, email=first.email, date_of_birth=adult_dob(), execute=True
    )
    async with session_factory() as s:
        p = (await s.execute(select(WarriorProfile))).scalar_one()
        p.is_active = False
        await s.commit()
    with pytest.raises(BootstrapError):
        await _run(
            session_factory, email=second.email, date_of_birth=adult_dob(), execute=True
        )


@pytest.mark.parametrize("case", ["unknown", "inactive", "minor"])
async def test_precondition_failures_write_nothing(session_factory, make_user, case):
    if case == "unknown":
        email, dob = "nobody@example.com", adult_dob()
    elif case == "inactive":
        email, dob = (await make_user("off", is_active=False)).email, adult_dob()
    else:
        email, dob = (await make_user("kid")).email, minor_dob()
    with pytest.raises(BootstrapError):
        await _run(session_factory, email=email, date_of_birth=dob, execute=True)
    assert await _count(session_factory, WarriorProfile) == 0
    assert await _count(session_factory, WarriorAuditLog) == 0


async def test_bootstrapped_admin_passes_real_admin_rbac(
    client, session_factory, make_user, auth_headers
):
    user = await make_user("boot")
    other = await make_user("plain")
    assert (
        await client.get(
            "/api/v1/warriors/admin/applications", headers=auth_headers(user)
        )
    ).status_code == 403
    await _run(
        session_factory, email=user.email, date_of_birth=adult_dob(), execute=True
    )
    assert (
        await client.get(
            "/api/v1/warriors/admin/applications", headers=auth_headers(user)
        )
    ).status_code == 200
    assert (
        await client.get(
            "/api/v1/warriors/admin/applications", headers=auth_headers(other)
        )
    ).status_code == 403


def test_cli_confirm_must_match_email(capsys):
    from app.cli.bootstrap_admin import main

    rc = main(
        [
            "--email",
            "a@example.com",
            "--date-of-birth",
            "1990-01-01",
            "--confirm",
            "b@example.com",
        ]
    )
    assert rc == 2
    assert "does not match" in capsys.readouterr().err


# --- F1-C02: verified e-mail ownership is required -------------------------------------------------------------
@pytest.mark.parametrize("execute", [False, True])
async def test_unverified_email_is_refused_and_writes_nothing(
    session_factory, make_user, execute
):
    """A legacy row (NULL ``email_verified_at``) must not become an admin, not even as a dry-run plan."""
    user = await make_user("legacy", email_verified_at=None)
    with pytest.raises(BootstrapError, match="verified"):
        await _run(
            session_factory,
            email=user.email,
            date_of_birth=adult_dob(),
            execute=execute,
        )
    assert await _count(session_factory, WarriorProfile) == 0
    assert await _count(session_factory, WarriorAuditLog) == 0


async def test_phone_verification_alone_is_not_enough(session_factory, make_user):
    user = await make_user(
        "phoneonly", email_verified_at=None
    )  # phone verified by default
    assert user.phone_verified_at is not None
    with pytest.raises(BootstrapError, match="verified"):
        await _run(
            session_factory, email=user.email, date_of_birth=adult_dob(), execute=True
        )
    assert await _count(session_factory, WarriorProfile) == 0


async def test_unknown_and_unverified_emails_get_the_same_message(
    session_factory, make_user
):
    legacy = await make_user("legacy", email_verified_at=None)
    msgs = []
    for email in ("nobody@example.com", legacy.email):
        with pytest.raises(BootstrapError) as e:
            await _run(
                session_factory, email=email, date_of_birth=adult_dob(), execute=False
            )
        msgs.append(str(e.value))
    assert msgs[0] == msgs[1]  # no enumeration through the operator-facing error


async def test_verified_email_is_accepted_and_only_that_user_gains_the_role(
    session_factory, make_user
):
    target, bystander = await make_user("t"), await make_user("b")
    unverified = await make_user("u", email_verified_at=None)
    await _run(
        session_factory, email=target.email, date_of_birth=adult_dob(), execute=True
    )
    async with session_factory() as s:
        ids = {p.user_id for p in (await s.execute(select(WarriorProfile))).scalars()}
    assert ids == {target.id}
    assert bystander.id not in ids and unverified.id not in ids


async def test_rerun_is_idempotent_and_never_promotes_a_second_user(
    session_factory, make_user
):
    target, other = await make_user("t"), await make_user("o")
    await _run(
        session_factory, email=target.email, date_of_birth=adult_dob(), execute=True
    )
    for who in (target, other):
        with pytest.raises(BootstrapError):
            await _run(
                session_factory,
                email=who.email,
                date_of_birth=adult_dob(),
                execute=True,
            )
    assert await _count(session_factory, WarriorProfile) == 1
    assert await _count(session_factory, WarriorAuditLog) == 1


async def test_a_duplicate_address_cannot_exist_so_a_claim_cannot_shadow_a_verified_owner(
    session_factory, make_user
):
    from sqlalchemy.exc import IntegrityError

    owner = await make_user("owner", email="dup-admin@example.com")
    with pytest.raises(IntegrityError):
        await make_user(
            "claimant", email="dup-admin@example.com", email_verified_at=None
        )
    await _run(
        session_factory, email=owner.email, date_of_birth=adult_dob(), execute=True
    )
    async with session_factory() as s:
        assert (
            await s.execute(select(WarriorProfile))
        ).scalar_one().user_id == owner.id
