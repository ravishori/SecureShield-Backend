"""python -m app.cli.admin_accounts: bootstrap and last-resort recovery. The CLI runs against the test database."""

from __future__ import annotations

from argparse import Namespace
from datetime import datetime

import pytest
from sqlalchemy import select

from app.cli import admin_accounts as cli
from app.models.admin_account import AdminAccount
from app.models.admin_audit import AdminAuditLog
from app.services import admin_security as sec

pytestmark = pytest.mark.integration
PW = "Zebra-Quartz-Passw0rd-123"


@pytest.fixture(autouse=True)
def _cli_env(monkeypatch, session_factory):
    monkeypatch.setattr(cli, "AsyncSessionLocal", session_factory)
    monkeypatch.setenv("ADMIN_CLI_PASSWORD", PW)


def args(command, email="boot@example.org", role="superadmin"):
    return Namespace(command=command, email=email, role=role)


async def account(session_factory, email="boot@example.org"):
    async with session_factory() as s:
        return (
            await s.execute(select(AdminAccount).where(AdminAccount.email == email))
        ).scalar_one_or_none()


async def test_create_makes_a_superadmin_that_must_set_up_and_never_prints_the_password(
    session_factory, capsys
):
    assert await cli.run(args("create")) == 0
    out = capsys.readouterr().out
    assert PW not in out and "must change the password" in out
    a = await account(session_factory)
    assert (
        a.role == "superadmin"
        and a.must_change_password
        and not a.totp_enabled
        and a.is_active
    )
    assert a.password_hash != PW and sec.verify_password(PW, a.password_hash)
    assert await cli.run(args("create")) == 1  # duplicate refused
    async with session_factory() as s:
        row = (await s.execute(select(AdminAuditLog))).scalars().one()
    assert (
        row.action == "admin.account_created"
        and row.actor_label == "cli"
        and PW not in str(row.detail)
    )


async def test_weak_password_and_bad_role_are_rejected(session_factory, monkeypatch):
    monkeypatch.setenv("ADMIN_CLI_PASSWORD", "short")
    with pytest.raises(SystemExit):
        await cli.run(args("create"))
    assert await account(session_factory) is None
    monkeypatch.setenv("ADMIN_CLI_PASSWORD", PW)
    assert await cli.run(args("create", role="root")) == 2


async def test_recovery_commands_reset_mfa_password_lock_and_state(
    session_factory, capsys
):
    assert await cli.run(args("create", role="admin")) == 0
    a = await account(session_factory)
    async with session_factory() as s:
        row = (
            await s.execute(select(AdminAccount).where(AdminAccount.id == a.id))
        ).scalar_one()
        row.failed_logins, row.locked_until = 4, datetime.utcnow()
        await s.commit()

    # give it an enrolled authenticator so the reset has something to clear
    async with session_factory() as s:
        row = (
            await s.execute(select(AdminAccount).where(AdminAccount.id == a.id))
        ).scalar_one()
        row.totp_secret_enc, row.totp_enabled, row.recovery_hashes = (
            sec.encrypt_secret("JBSWY3DPEHPK3PXP"),
            True,
            ["x"],
        )
        await s.commit()
    assert await cli.run(args("reset-mfa")) == 0
    row = await account(session_factory)
    assert (
        not row.totp_enabled
        and row.totp_secret_enc is None
        and row.recovery_hashes == []
    )

    assert await cli.run(args("set-password")) == 0
    row = await account(session_factory)
    assert (
        row.must_change_password
        and sec.verify_password(PW, row.password_hash)
        and row.locked_until is None
    )

    assert await cli.run(args("disable")) == 0
    assert not (await account(session_factory)).is_active
    assert await cli.run(args("enable")) == 0
    assert (await account(session_factory)).is_active
    assert await cli.run(args("unlock")) == 0
    assert await cli.run(args("list")) == 0
    assert "boot@example.org" in capsys.readouterr().out
    assert await cli.run(args("reset-mfa", email="nobody@example.org")) == 1

    async with session_factory() as s:
        actions = {r.action for r in (await s.execute(select(AdminAuditLog))).scalars()}
    assert {
        "admin.mfa_reset",
        "admin.password_reset",
        "admin.account_disabled",
        "admin.account_enabled",
        "admin.account_unlocked",
    } <= actions
