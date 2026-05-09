"""make app_scan device_id optional

Revision ID: j5k6l7m8n9o0
Revises: i4j5k6l7m8n9
Create Date: 2026-04-29

"""
from alembic import op
import sqlalchemy as sa

revision = 'j5k6l7m8n9o0'
down_revision = 'i4j5k6l7m8n9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop FK from app_scans.device_id → devices.id (dynamic name)
    op.execute("""
        DO $$
        DECLARE
            cname TEXT;
        BEGIN
            SELECT conname INTO cname
            FROM pg_constraint
            WHERE conrelid = 'app_scans'::regclass
              AND confrelid = 'devices'::regclass
              AND contype = 'f';
            IF cname IS NOT NULL THEN
                EXECUTE 'ALTER TABLE app_scans DROP CONSTRAINT ' || quote_ident(cname);
            END IF;
        END $$;
    """)
    op.alter_column('app_scans', 'device_id', nullable=True)


def downgrade() -> None:
    op.alter_column('app_scans', 'device_id', nullable=False)
    op.create_foreign_key(
        'app_scans_device_id_fkey',
        'app_scans', 'devices',
        ['device_id'], ['id'],
    )
