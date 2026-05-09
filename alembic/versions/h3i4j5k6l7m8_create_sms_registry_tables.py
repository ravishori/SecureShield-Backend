"""create sms registry tables (tsp_codes, lsa_codes, sms_sender_registry)

Revision ID: h3i4j5k6l7m8
Revises: g2h3i4j5k6l7
Create Date: 2026-04-29

"""
from alembic import op
import sqlalchemy as sa

revision = 'h3i4j5k6l7m8'
down_revision = 'g2h3i4j5k6l7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'tsp_codes',
        sa.Column('code', sa.String(1), primary_key=True),
        sa.Column('provider_name', sa.Text, nullable=False),
    )

    op.create_table(
        'lsa_codes',
        sa.Column('code', sa.String(1), primary_key=True),
        sa.Column('service_area', sa.Text, nullable=False),
    )

    op.create_table(
        'sms_sender_registry',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('header', sa.String(30), nullable=False),
        sa.Column('principal_entity_name', sa.Text, nullable=False),
    )
    op.create_index('ix_sms_sender_registry_header', 'sms_sender_registry', ['header'])


def downgrade():
    op.drop_index('ix_sms_sender_registry_header', 'sms_sender_registry')
    op.drop_table('sms_sender_registry')
    op.drop_table('lsa_codes')
    op.drop_table('tsp_codes')
