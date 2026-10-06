"""Rehearse the newest Alembic migrations on a throw-away LOCAL database that contains seeded data.

    python scripts/migration_rehearsal.py            # uses RESTORE_ADMIN_URL (loopback only)

Creates ``secureshield_migration_review_<rand>``, upgrades to the pre-change revision, seeds rows that
exercise every destructive path (duplicate daily reports, OTP rows, family links, unowned scans),
then applies each of the seven revisions one at a time printing before/after row counts, tries each
downgrade, and re-upgrades. Always drops the scratch database. Refuses non-loopback servers.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

import asyncpg
from sqlalchemy.engine import make_url

BACKEND = Path(__file__).resolve().parents[1]
BASE = "l7m8n9o0p1q2"
STEPS = [
    "m8n9o0p1q2r3",
    "n9o0p1q2r3s4",
    "o0p1q2r3s4t5",
    "p1q2r3s4t5u6",
    "q2r3s4t5u6v7",
    "r3s4t5u6v7w8",
    "s4t5u6v7w8x9",
]
TABLES = [
    "users",
    "otps",
    "family_members",
    "security_reports",
    "app_scans",
    "wifi_scans",
    "alerts",
]


def pg(url: str) -> str:
    return url.replace("+asyncpg", "")


def alembic(url: str, *args: str) -> None:
    env = dict(os.environ)
    env["DATABASE_URL"] = url
    env["MIGRATOR_DATABASE_URL"] = url
    subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND,
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


async def counts(url: str) -> dict[str, int | None]:
    conn = await asyncpg.connect(pg(url))
    try:
        out = {}
        for t in TABLES:
            try:
                out[t] = await conn.fetchval(f'select count(*) from "{t}"')
            except asyncpg.UndefinedTableError:
                out[t] = None
        return out
    finally:
        await conn.close()


async def seed(url: str) -> None:
    conn = await asyncpg.connect(pg(url))
    try:
        u1, u2 = uuid.uuid4(), uuid.uuid4()
        for u, n in ((u1, "a"), (u2, "b")):
            await conn.execute(
                "insert into users (id, email, phone, is_active, senior_mode, subscription_tier, created_at, updated_at, country)"
                " values ($1,$2,$3,true,false,'free',now(),now(),'India')",
                u,
                f"{n}@example.com",
                f"+9190000000{ord(n)}",
            )
        for code in ("123456", "654321", "111111"):
            await conn.execute(
                "insert into otps (email, code, expires_at, is_used, created_at) values ('a@example.com',$1,now()+interval '10 minutes',false,now())",
                code,
            )
        await conn.execute(
            "insert into family_members (id,user_id,member_user_id,relationship,nickname,can_view_alerts,can_trigger_panic,is_child_profile,content_filter_enabled,cyberbullying_alerts,created_at)"
            " values ($1,$2,$3,'son','kid',true,false,false,false,false,now())",
            uuid.uuid4(),
            u1,
            u2,
        )
        for i, ts in enumerate(
            (datetime(2026, 10, 1, 8), datetime(2026, 10, 1, 20))
        ):  # two reports for one user/day
            await conn.execute(
                "insert into security_reports (id,user_id,report_date,threats_detected,apps_scanned,links_scanned,calls_analyzed,overall_risk_score,top_threats,recommendations,created_at)"
                " values ($1,$2,'2026-10-01'::date,$3,0,0,0,0,'[]','[]',$4)",
                uuid.uuid4(),
                u1,
                i,
                ts,
            )
        await conn.execute(
            "insert into security_reports (id,user_id,report_date,threats_detected,apps_scanned,links_scanned,calls_analyzed,overall_risk_score,top_threats,recommendations,created_at)"
            " values ($1,$2,'2026-10-01'::date,0,0,0,0,0,'[]','[]',now())",
            uuid.uuid4(),
            u2,
        )
        await conn.execute(
            "insert into app_scans (id,package_name,app_name,risk_score,risk_level,permissions,is_system_app,is_malicious,threat_tags,scanned_at)"
            " values ($1,'com.x','X',0,'safe','[]',false,false,'[]',now())",
            uuid.uuid4(),
        )
        await conn.execute(
            "insert into wifi_scans (id,ssid,is_open,is_suspicious,risk_reasons,scanned_at) values ($1,'net',false,false,'[]',now())",
            uuid.uuid4(),
        )
        await conn.execute(
            "insert into alerts (id,user_id,alert_type,title,message,severity,is_read,is_dismissed,extra_data,created_at)"
            " values ($1,$2,'phishing','t','m','info',false,false,'{}',now())",
            uuid.uuid4(),
            u1,
        )
    finally:
        await conn.close()


async def admin(url: str, sql: str) -> None:
    conn = await asyncpg.connect(pg(url))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def show(label: str, c: dict) -> None:
    print(f"  {label:<22}" + "  ".join(f"{k}={v}" for k, v in c.items()))


def main() -> None:
    admin_url = os.environ.get("RESTORE_ADMIN_URL")
    if not admin_url:
        sys.exit("Set RESTORE_ADMIN_URL (local PostgreSQL).")
    a = make_url(pg(admin_url))
    if (a.host or "").lower() not in {"localhost", "127.0.0.1", "::1"}:
        sys.exit("Refusing: RESTORE_ADMIN_URL must be loopback.")
    name = f"secureshield_migration_review_{secrets.token_hex(3)}"
    url = (
        a.set(database=name)
        .render_as_string(hide_password=False)
        .replace("postgresql://", "postgresql+asyncpg://")
    )
    asyncio.run(admin(admin_url, f'create database "{name}"'))
    try:
        alembic(url, "upgrade", BASE)
        asyncio.run(seed(url))
        print("seeded at", BASE)
        show("before", asyncio.run(counts(url)))
        for rev in STEPS:
            alembic(url, "upgrade", rev)
            show(f"after {rev[:4]}", asyncio.run(counts(url)))
        print("downgrades:")
        for rev in reversed(STEPS):
            try:
                alembic(url, "downgrade", "-1")
                print(f"  {rev}: downgrade OK")
            except subprocess.CalledProcessError:
                print(f"  {rev}: downgrade FAILED")
                break
        alembic(url, "upgrade", "head")
        print("re-upgrade to head OK")
    finally:
        asyncio.run(admin(admin_url, f'drop database if exists "{name}" with (force)'))


if __name__ == "__main__":
    main()
