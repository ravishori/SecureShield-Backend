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
