"""Command-line management of admin accounts - the bootstrap and last-resort recovery path.

    python -m app.cli.admin_accounts create --email ops@example.org --role superadmin
    python -m app.cli.admin_accounts list
    python -m app.cli.admin_accounts reset-mfa --email ops@example.org
    python -m app.cli.admin_accounts set-password --email ops@example.org
    python -m app.cli.admin_accounts unlock --email ops@example.org
    python -m app.cli.admin_accounts disable|enable --email ops@example.org

Needs database access (the same ``DATABASE_URL`` the API uses), which is why it is trusted for recovery when no
superadmin can sign in. Passwords are read with a hidden prompt (or the ``ADMIN_CLI_PASSWORD`` environment variable for
scripted use) and are never echoed or logged. A new or reset password is temporary: the account must change it and
enrol (or re-enrol) an authenticator app at its next sign-in. Every action is written to the admin audit log with the
actor label ``cli``. Nothing is deleted.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.admin_account import ADMIN_ROLES, AdminAccount
from app.models.admin_audit import AdminAuditLog
from app.services.admin_access import revoke_sessions
from app.services.admin_security import hash_password, password_problems


def _password(email: str) -> str:
    pw = os.environ.get("ADMIN_CLI_PASSWORD")
    if not pw:
        pw = getpass.getpass("Temporary password (hidden): ")
        if pw != getpass.getpass("Repeat password: "):
            raise SystemExit("Passwords do not match.")
    problems = password_problems(pw, email)
    if problems:
        raise SystemExit("Password " + "; ".join(problems))
    return pw


def _audit(db, action: str, acct_id, detail: dict | None = None) -> None:
    info = dict(detail or {})
    if acct_id is not None:
        info["account"] = str(acct_id)
    db.add(AdminAuditLog(action=action, detail=info, actor_label="cli"))


async def run(args: argparse.Namespace) -> int:
    email = (getattr(args, "email", None) or "").strip().lower()
    async with AsyncSessionLocal() as db:
        if args.command == "list":
            rows = (
                (
                    await db.execute(
                        select(AdminAccount).order_by(AdminAccount.created_at)
                    )
                )
                .scalars()
                .all()
            )
            for a in rows:
                print(
                    f"{a.email}\t{a.role}\tactive={a.is_active}\tmfa={a.totp_enabled}\tmust_change_password={a.must_change_password}"
                )
            print(f"{len(rows)} admin account(s)")
            return 0

        acct = (
            await db.execute(select(AdminAccount).where(AdminAccount.email == email))
        ).scalar_one_or_none()
        if args.command == "create":
            if acct is not None:
                print("An admin account with this e-mail already exists.")
                return 1
            if args.role not in ADMIN_ROLES:
                print("role must be one of: " + ", ".join(ADMIN_ROLES))
                return 2
            acct = AdminAccount(
                email=email,
                role=args.role,
                password_hash=hash_password(_password(email)),
                must_change_password=True,
                recovery_hashes=[],
            )
            db.add(acct)
            await db.flush()
            _audit(
                db, "admin.account_created", acct.id, {"role": args.role, "via": "cli"}
            )
            await db.commit()
            print(
                f"Created {args.role} account {email}. It must change the password and enrol MFA at first sign-in."
            )
            return 0

        if acct is None:
            print("No admin account with this e-mail.")
            return 1
        if args.command == "reset-mfa":
            (
                acct.totp_secret_enc,
                acct.totp_enabled,
                acct.totp_last_step,
                acct.recovery_hashes,
            ) = None, False, 0, []
            await revoke_sessions(db, acct.id)
            _audit(db, "admin.mfa_reset", acct.id, {"via": "cli"})
            msg = "MFA reset; sessions revoked. The account must enrol again at next sign-in."
        elif args.command == "set-password":
            acct.password_hash = hash_password(_password(email))
            acct.must_change_password, acct.failed_logins, acct.locked_until = (
                True,
                0,
                None,
            )
            await revoke_sessions(db, acct.id)
            _audit(db, "admin.password_reset", acct.id, {"via": "cli"})
            msg = "Temporary password set; sessions revoked; the account must change it at next sign-in."
        elif args.command == "unlock":
            acct.failed_logins, acct.locked_until = 0, None
            _audit(db, "admin.account_unlocked", acct.id, {"via": "cli"})
            msg = "Account unlocked."
        elif args.command in ("disable", "enable"):
            acct.is_active = args.command == "enable"
            if not acct.is_active:
                await revoke_sessions(db, acct.id)
            _audit(db, f"admin.account_{args.command}d", acct.id, {"via": "cli"})
            msg = f"Account {args.command}d."
        else:
            return 2
        await db.commit()
        print(msg)
        return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    c.add_argument("--email", required=True)
    c.add_argument("--role", choices=ADMIN_ROLES, default="superadmin")
    sub.add_parser("list")
    for name in ("reset-mfa", "set-password", "unlock", "disable", "enable"):
        sub.add_parser(name).add_argument("--email", required=True)
    return asyncio.run(run(ap.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
