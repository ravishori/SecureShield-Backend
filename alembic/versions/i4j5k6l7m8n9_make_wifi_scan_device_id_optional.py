"""make wifi_scan device_id optional

Revision ID: i4j5k6l7m8n9
Revises: h3i4j5k6l7m8
Create Date: 2026-04-29

"""
from alembic import op
import sqlalchemy as sa

revision = 'i4j5k6l7m8n9'
down_revision = 'h3i4j5k6l7m8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the foreign key constraint on wifi_scans.device_id
    # (constraint name may vary; use IF EXISTS via raw SQL to be safe)
    op.execute("""
        DO $$
        DECLARE
            cname TEXT;
        BEGIN
            SELECT conname INTO cname
            FROM pg_constraint
            WHERE conrelid = 'wifi_scans'::regclass
              AND confrelid = 'devices'::regclass
              AND contype = 'f';
            IF cname IS NOT NULL THEN
                EXECUTE 'ALTER TABLE wifi_scans DROP CONSTRAINT ' || quote_ident(cname);
            END IF;
        END $$;
    """)

    # Make device_id nullable
    op.alter_column('wifi_scans', 'device_id', nullable=True)


def downgrade() -> None:
    # Restore NOT NULL (rows with NULL will prevent this unless cleared first)
    op.alter_column('wifi_scans', 'device_id', nullable=False)
    op.create_foreign_key(
        'wifi_scans_device_id_fkey',
        'wifi_scans', 'devices',
        ['device_id'], ['id'],
    )
