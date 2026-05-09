"""add recordings table

Revision ID: a1b2c3d4e5f6
Revises: 519e8e8aa0ae
Create Date: 2026-03-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'a1b2c3d4e5f6'
down_revision = '519e8e8aa0ae'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'recordings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('file_path', sa.String(512), nullable=False),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False, default=0),
        sa.Column('duration_seconds', sa.Integer(), nullable=False, default=0),
        sa.Column('is_encrypted', sa.Boolean(), nullable=False, default=True),
        sa.Column('share_token', sa.String(128), nullable=True, unique=True),
        sa.Column('share_expires_at', sa.DateTime(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_recordings_share_token', 'recordings', ['share_token'])


def downgrade() -> None:
    op.drop_index('ix_recordings_share_token', table_name='recordings')
    op.drop_table('recordings')
