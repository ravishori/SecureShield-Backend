"""
Seed Script: TRAI SMS Sender Registry
=======================================
Loads TSP codes, LSA codes, and 23K+ SMS headers from:
  - Detail_Header_Prefixes_16062020_0.pdf (embedded in code below)
  - List_SMS_Headers_16062020_0.xlsx (must be present in SecureShieldApp/ root)

Run from the backend directory:
  python scripts/seed_sms_registry.py --dry-run          # parse only, no DB
  python scripts/seed_sms_registry.py                    # seed EMPTY tables
  python scripts/seed_sms_registry.py --replace          # wipe + reseed

Needs (not in requirements.txt):  pip install -r requirements-seed.txt
Connects with MIGRATOR_DATABASE_URL: TRUNCATE requires table ownership, which
the runtime role (secureshield_app) deliberately does not have.
"""

import argparse
import sys
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Add backend root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.db_identity import validate_identity

# TRUNCATE with the migrator role: refuse a target that does not match the declared environment (no connection is made).
validate_identity(settings)


# ── Connection ─────────────────────────────────────────────────────────────────
# TRUNCATE needs ownership -> use the migrator role (MIGRATOR_DATABASE_URL).
def _libpq_dsn(url: str) -> str:
    """SQLAlchemy asyncpg URL -> libpq DSN (asyncpg ``ssl`` -> libpq ``sslmode``)."""
    parts = urlsplit(url.replace("postgresql+asyncpg://", "postgresql://", 1))
    q = [("sslmode" if k == "ssl" else k, v) for k, v in parse_qsl(parts.query)]
    return urlunsplit(parts._replace(query=urlencode(q)))


DSN = _libpq_dsn(settings.MIGRATOR_DATABASE_URL)

# This seed is for the local development database only (Stage 1.6B-3).
EXPECTED_DATABASE = "secureshield_dev"
EXPECTED_PORT = 5432
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def assert_seed_target(actual_database: str, cfg=None) -> None:
    """Refuse unless the connected database is the local development one. ``actual_database`` is ``SELECT current_database()``.

    Raises ``SystemExit`` with a credential-free message. No connection is made here; call it before the first write.
    """
    from app.db_identity import (
        DatabaseIdentityError,
        check_connected_database_name,
        parse_endpoint,
    )

    cfg = cfg or settings
    try:
        ep = parse_endpoint(cfg.MIGRATOR_DATABASE_URL)
        check_connected_database_name(actual_database, cfg)
    except DatabaseIdentityError as exc:
        sys.exit(f"Refusing to seed: {exc}")
    env = (getattr(cfg, "ENVIRONMENT", "") or "").strip().lower()
    if env != "development":
        sys.exit(f"Refusing to seed: ENVIRONMENT is {env!r}, expected 'development'.")
    if ep.host not in _LOOPBACK or (ep.port or 5432) != EXPECTED_PORT:
        sys.exit("Refusing to seed: the target is not localhost:5432.")
    if actual_database != EXPECTED_DATABASE:
        sys.exit(
            f"Refusing to seed: connected to {actual_database!r}, expected {EXPECTED_DATABASE!r}."
        )


# ── TSP Codes (from TRAI PDF) ─────────────────────────────────────────────────
TSP_CODES = [
    ("D", "Aircel Ltd / Dishnet Wireless Ltd"),
    ("A", "Bharti Airtel Ltd / Bharti Hexacom Ltd"),
    ("B", "Bharat Sanchar Nigam Ltd (BSNL)"),
    ("Q", "Quadrant Televentures Limited"),
    ("M", "Mahanagar Telephone Nigam Ltd (MTNL)"),
    ("R", "Reliance Communications Ltd"),
    ("J", "Reliance Jio Infocomm Ltd"),
    ("E", "Reliance Telecom Ltd"),
    ("T", "Tata Teleservices Ltd / Tata Teleservices (Maharashtra) Ltd"),
    ("V", "Vodafone Idea Ltd"),
    ("C", "V-CON Mobile & Infra Private Ltd"),
]

# ── LSA Codes (from TRAI PDF) ─────────────────────────────────────────────────
LSA_CODES = [
    ("A", "Andhra Pradesh"),
    ("S", "Assam"),
    ("B", "Bihar"),
    ("D", "Delhi"),
    ("G", "Gujarat"),
    ("H", "Haryana"),
    ("I", "Himachal Pradesh"),
    ("J", "Jammu & Kashmir"),
    ("X", "Karnataka"),
    ("L", "Kerala"),
    ("K", "Kolkata"),
    ("Y", "Madhya Pradesh"),
    ("Z", "Maharashtra"),
    ("M", "Mumbai"),
    ("N", "North East"),
    ("O", "Orissa"),
    ("P", "Punjab"),
    ("R", "Rajasthan"),
    ("T", "Tamil Nadu (including Chennai)"),
    ("E", "UP-East"),
    ("W", "UP-West"),
    ("V", "West Bengal"),
]


def load_sms_headers(xlsx_path: str):
    """Load SMS headers from the TRAI XLSX file."""
    try:
        import openpyxl
    except ImportError:
        print("openpyxl not found. Install: pip install openpyxl")
        sys.exit(1)

    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        wb = openpyxl.load_workbook(xlsx_path)

    ws = wb.active
    rows = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        header_raw = row[0]
        entity_name = row[1]
        if header_raw is None or entity_name is None:
            continue
        header = str(header_raw).strip()
        entity = str(entity_name).strip()
        if header and entity:
            rows.append((header, entity))
    print(f"  Loaded {len(rows):,} SMS headers from XLSX")
    return rows


def seed(dry_run: bool = False, replace: bool = False, xlsx: str | None = None):
    xlsx_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "..",
        "List_SMS_Headers_16062020_0.xlsx",
    )
    xlsx_path = os.path.normpath(xlsx or xlsx_path)

    if not os.path.exists(xlsx_path):
        print(f"ERROR: XLSX not found at {xlsx_path}")
        print(
            "Place 'List_SMS_Headers_16062020_0.xlsx' in D:/ravishori/SecureShieldApp/"
        )
        sys.exit(1)

    if dry_run:
        rows = load_sms_headers(xlsx_path)
        print(
            f"DRY RUN: would seed {len(TSP_CODES)} TSP codes, {len(LSA_CODES)} LSA codes, "
            f"{len(rows):,} SMS headers. No database contact."
        )
        return

    import psycopg2
    from psycopg2.extras import execute_values

    print("Connecting to database...")
    conn = psycopg2.connect(DSN)
    cur = conn.cursor()

    # Identity before ANY other statement, and in particular before any write.
    cur.execute("SELECT current_database()")
    try:
        assert_seed_target(cur.fetchone()[0])
    except SystemExit:
        conn.close()
        raise

    cur.execute(
        "SELECT (SELECT count(*) FROM tsp_codes), (SELECT count(*) FROM lsa_codes), "
        "(SELECT count(*) FROM sms_sender_registry)"
    )
    existing = cur.fetchone()
    if any(existing) and not replace:
        print(
            f"ABORT: tables already hold data (tsp={existing[0]}, lsa={existing[1]}, "
            f"sms={existing[2]}). Re-run with --replace to wipe and reseed."
        )
        conn.close()
        sys.exit(2)

    # ── Seed TSP codes ──────────────────────────────────────────────────────────
    print("Seeding TSP codes...")
    cur.execute("TRUNCATE TABLE tsp_codes RESTART IDENTITY CASCADE")
    execute_values(
        cur,
        "INSERT INTO tsp_codes (code, provider_name) VALUES %s ON CONFLICT DO NOTHING",
        TSP_CODES,
    )
    print(f"  {len(TSP_CODES)} TSP codes inserted")

    # ── Seed LSA codes ──────────────────────────────────────────────────────────
    print("Seeding LSA codes...")
    cur.execute("TRUNCATE TABLE lsa_codes RESTART IDENTITY CASCADE")
    execute_values(
        cur,
        "INSERT INTO lsa_codes (code, service_area) VALUES %s ON CONFLICT DO NOTHING",
        LSA_CODES,
    )
    print(f"  {len(LSA_CODES)} LSA codes inserted")

    # ── Seed SMS headers ────────────────────────────────────────────────────────
    print("Loading SMS headers from XLSX...")
    sms_rows = load_sms_headers(xlsx_path)

    print("Seeding sms_sender_registry (bulk insert)...")
    cur.execute("TRUNCATE TABLE sms_sender_registry RESTART IDENTITY")

    BATCH = 2000
    total = 0
    for i in range(0, len(sms_rows), BATCH):
        batch = sms_rows[i : i + BATCH]
        execute_values(
            cur,
            "INSERT INTO sms_sender_registry (header, principal_entity_name) VALUES %s",
            batch,
        )
        total += len(batch)
        print(f"  Inserted {total:,}/{len(sms_rows):,}", end="\r")

    conn.commit()
    cur.close()
    conn.close()

    print(f"\nDone! {total:,} SMS headers seeded.")
    print("   TSP codes:", len(TSP_CODES))
    print("   LSA codes:", len(LSA_CODES))
    print("   SMS headers:", total)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Seed TRAI SMS sender registry")
    ap.add_argument(
        "--dry-run", action="store_true", help="parse inputs only; no database"
    )
    ap.add_argument(
        "--replace", action="store_true", help="TRUNCATE and reseed populated tables"
    )
    ap.add_argument("--xlsx", help="path to List_SMS_Headers_16062020_0.xlsx")
    a = ap.parse_args()
    seed(dry_run=a.dry_run, replace=a.replace, xlsx=a.xlsx)
