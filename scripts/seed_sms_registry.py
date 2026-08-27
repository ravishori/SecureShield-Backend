"""
Seed Script: TRAI SMS Sender Registry
=======================================
Loads TSP codes, LSA codes, and 23K+ SMS headers from:
  - Detail_Header_Prefixes_16062020_0.pdf (embedded in code below)
  - List_SMS_Headers_16062020_0.xlsx (must be present in SecureShieldApp/ root)

Run from: D:/ravishori/SecureShieldApp/backend/
  python scripts/seed_sms_registry.py
"""
import sys
import os

# Add backend root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
from psycopg2.extras import execute_values

from app.config import settings

# ── Connection ─────────────────────────────────────────────────────────────────
# Seed data is DML (INSERT) into existing tables, not DDL. Use the FastAPI
# runtime role (DATABASE_URL / secureshield_app), not the migrator or admin.
# Convert SQLAlchemy asyncpg URL to a libpq DSN for psycopg2.
DSN = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)

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


def seed():
    xlsx_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "..", "List_SMS_Headers_16062020_0.xlsx"
    )
    xlsx_path = os.path.normpath(xlsx_path)

    if not os.path.exists(xlsx_path):
        print(f"ERROR: XLSX not found at {xlsx_path}")
        print("Place 'List_SMS_Headers_16062020_0.xlsx' in D:/ravishori/SecureShieldApp/")
        sys.exit(1)

    print("Connecting to database...")
    conn = psycopg2.connect(DSN)
    cur = conn.cursor()

    # ── Seed TSP codes ──────────────────────────────────────────────────────────
    print("Seeding TSP codes...")
    cur.execute("TRUNCATE TABLE tsp_codes RESTART IDENTITY CASCADE")
    execute_values(cur, "INSERT INTO tsp_codes (code, provider_name) VALUES %s ON CONFLICT DO NOTHING", TSP_CODES)
    print(f"  {len(TSP_CODES)} TSP codes inserted")

    # ── Seed LSA codes ──────────────────────────────────────────────────────────
    print("Seeding LSA codes...")
    cur.execute("TRUNCATE TABLE lsa_codes RESTART IDENTITY CASCADE")
    execute_values(cur, "INSERT INTO lsa_codes (code, service_area) VALUES %s ON CONFLICT DO NOTHING", LSA_CODES)
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

    print(f"\n✅ Done! {total:,} SMS headers seeded.")
    print("   TSP codes:", len(TSP_CODES))
    print("   LSA codes:", len(LSA_CODES))
    print("   SMS headers:", total)


if __name__ == "__main__":
    seed()
