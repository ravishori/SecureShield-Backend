"""Read-only pre-/post-deployment row-count report for the four data-affecting migrations.

    PREMIGRATION_DATABASE_URL=postgresql://... python scripts/premigration_report.py > before.txt
    ... run the migrations ...
    PREMIGRATION_DATABASE_URL=postgresql://... python scripts/premigration_report.py > after.txt

It opens the connection READ ONLY (the session cannot write) and prints only counts, never row contents.
Tables that do not exist yet (before the migration) are reported as "absent", not as an error.
See docs/MIGRATION_SAFETY_REVIEW.md "Pre-deployment checks" for what to expect.
"""

from __future__ import annotations

import asyncio
import os
import sys

import asyncpg

CHECKS: list[tuple[str, str]] = [
    ("users (total)", "select count(*) from users"),
    (
        "users (active) = upper bound of people who must sign in again",
        "select count(*) from users where is_active",
    ),
    (
        "family_members (all) - all become 'pending'",
        "select count(*) from family_members",
    ),
    (
        "family_members consent_status='pending' (after m8n9)",
        "select count(*) from family_members where consent_status = 'pending'",
    ),
    (
        "family_members consent_status<>'pending' (must be 0 after m8n9)",
        "select count(*) from family_members where consent_status <> 'pending'",
    ),
    ("security_reports (all)", "select count(*) from security_reports"),
    (
        "security_reports duplicate rows that n9o0 will delete",
        "select coalesce(sum(c - 1), 0) from (select count(*) c from security_reports group by user_id, report_date having count(*) > 1) t",
    ),
    ("otps (all) - q2r3 deletes every row", "select count(*) from otps"),
    (
        "otps still valid (unused, unexpired) = codes users lose",
        "select count(*) from otps where not is_used and expires_at > (now() at time zone 'utc')",
    ),
    (
        "app_scans without owner (stay unowned, never shown)",
        "select count(*) from app_scans where user_id is null",
    ),
    (
        "wifi_scans without owner (stay unowned, never shown)",
        "select count(*) from wifi_scans where user_id is null",
    ),
    ("refresh_token_uses (after r3s4)", "select count(*) from refresh_token_uses"),
    (
        "revoked_token_families (after r3s4)",
        "select count(*) from revoked_token_families",
    ),
    ("admin_audit_logs (after s4t5)", "select count(*) from admin_audit_logs"),
    ("alembic_version", "select version_num from alembic_version"),
]


async def main() -> int:
    url = os.environ.get("PREMIGRATION_DATABASE_URL")
    if not url:
        print(
            "Set PREMIGRATION_DATABASE_URL (a read-only role is best).", file=sys.stderr
        )
        return 1
    conn = await asyncpg.connect(
        url.replace("+asyncpg", ""),
        server_settings={"default_transaction_read_only": "on"},
    )
    try:
        for label, sql in CHECKS:
            try:
                value = await conn.fetchval(sql)
            except (asyncpg.UndefinedTableError, asyncpg.UndefinedColumnError):
                value = "absent"
            print(f"{label}: {value}")
    finally:
        await conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
