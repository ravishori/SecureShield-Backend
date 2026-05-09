"""add gsb_threats to link_scans

Revision ID: g2h3i4j5k6l7
Revises: f1a2b3c4d5e6
Create Date: 2026-04-05

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers
revision = 'g2h3i4j5k6l7'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('link_scans', sa.Column('gsb_threats', JSONB, nullable=True))


def downgrade():
    op.drop_column('link_scans', 'gsb_threats')
