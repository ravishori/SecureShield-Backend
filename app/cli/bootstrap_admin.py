"""One-time bootstrap of the FIRST Cyber Warriors admin.

Why this exists: every admin route requires an ``admin`` WarriorProfile, and
profiles are only created by an admin approving an application — so a fresh
database has no way to get its first admin. This is intentionally NOT an HTTP
endpoint: the trust boundary is shell access to the deployed service.

Usage (Railway; the container already has DATABASE_URL on the private network)::

    railway ssh -s secureshield-api -- \
        python -m app.cli.bootstrap_admin --email you@example.com \
        --date-of-birth 1990-01-31                 # prints the plan only
    railway ssh -s secureshield-api -- \
        python -m app.cli.bootstrap_admin --email you@example.com \
        --date-of-birth 1990-01-31 --confirm you@example.com

Safety properties
  * The person must already exist (registered + OTP-verified through the normal
    flow). No password, token or OTP is created, read or printed.
  * Refuses to run if ANY admin profile already exists (active or not), so it
    cannot be reused as a backdoor once the first admin is in place. Further
    admins come from the existing, audited approve flow.
  * Dry-run by default; executing requires ``--confirm`` to repeat the email.
  * Serialised with a Postgres advisory lock (two simultaneous runs cannot
    both create an admin).
  * Writes a ``warrior_audit_logs`` row (role_promoted, method=cli_bootstrap).
  * Uses the least-privilege runtime role (DML only).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import date

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cyber_warrior import (
    AuditAction,
    WarriorAuditLog,
    WarriorProfile,
    WarriorRole,
)
from app.models.user import User
from app.schemas.cyber_warrior import MIN_WARRIOR_AGE_YEARS, _age_in_years

# Arbitrary constant key for pg_advisory_xact_lock.
_LOCK_KEY = 7_300_240_001


class BootstrapError(Exception):
    """A precondition failed; message is safe to show."""


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


async def bootstrap_first_admin(
    db: AsyncSession,
    *,
    email: str,
    date_of_birth: date,
    execute: bool,
    today: date | None = None,
) -> str:
    """Validate (and, if ``execute``, perform) the bootstrap. Returns a
    human-readable, secret-free summary. Raises ``BootstrapError``."""
    email = email.strip().lower()
    if _age_in_years(date_of_birth, today) < MIN_WARRIOR_AGE_YEARS:
        raise BootstrapError(f"Date of birth must make the person at least {MIN_WARRIOR_AGE_YEARS}.")

    # Serialise concurrent runs for the duration of this transaction.
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})

    existing_admin = (
        await db.execute(
            select(WarriorProfile.id).where(WarriorProfile.role == WarriorRole.admin).limit(1)
        )
    ).first()
    if existing_admin is not None:
        raise BootstrapError(
            "An admin profile already exists. Bootstrap is one-time only; "
            "create further admins through the audited approve flow."
        )

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        raise BootstrapError("No registered user with that email. Register through the app first.")
    if not user.is_active:
        raise BootstrapError("That user account is not active.")

    has_profile = (
        await db.execute(select(WarriorProfile.id).where(WarriorProfile.user_id == user.id))
    ).first()
    if has_profile is not None:
        raise BootstrapError("That user already has a warrior profile.")

    display_name = (
        user.full_name or " ".join(p for p in (user.first_name, user.last_name) if p) or "Admin"
    )
    plan = f"Grant role 'admin' to user {_mask_email(email)} (display name: {display_name!r})."
    if not execute:
        return "DRY RUN — " + plan + " Re-run with --confirm <email> to apply."

    profile = WarriorProfile(
        user_id=user.id,
        application_id=None,
        role=WarriorRole.admin,
        is_active=True,
        display_name=display_name,
        date_of_birth=date_of_birth,
    )
    db.add(profile)
    db.add(
        WarriorAuditLog(
            actor_user_id=user.id,
            subject_user_id=user.id,
            action=AuditAction.role_promoted,
            extra={"from_role": None, "to_role": "admin", "method": "cli_bootstrap"},
            reason="Initial admin bootstrap via app.cli.bootstrap_admin",
        )
    )
    await db.commit()
    return "APPLIED — " + plan


def _parse(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="One-time bootstrap of the first Cyber Warriors admin")
    ap.add_argument("--email", required=True)
    ap.add_argument("--date-of-birth", required=True, type=date.fromisoformat, metavar="YYYY-MM-DD")
    ap.add_argument("--confirm", metavar="EMAIL", help="repeat the email to actually apply")
    return ap.parse_args(argv)


async def _run(args: argparse.Namespace) -> int:
    from app.database import AsyncSessionLocal

    execute = args.confirm is not None
    if execute and args.confirm.strip().lower() != args.email.strip().lower():
        print("ERROR: --confirm does not match --email; nothing done.", file=sys.stderr)
        return 2
    async with AsyncSessionLocal() as db:
        try:
            print(await bootstrap_first_admin(db, email=args.email, date_of_birth=args.date_of_birth, execute=execute))
            return 0
        except BootstrapError as exc:
            await db.rollback()
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_run(_parse(argv)))


if __name__ == "__main__":
    sys.exit(main())
