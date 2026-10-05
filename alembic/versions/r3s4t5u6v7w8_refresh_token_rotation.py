"""refresh token rotation: consumed-token and revoked-family tables

Revision ID: r3s4t5u6v7w8
Revises: q2r3s4t5u6v7
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from alembic import op

revision = "r3s4t5u6v7w8"
down_revision = "q2r3s4t5u6v7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "refresh_token_uses",
        sa.Column("jti", sa.UUID(), primary_key=True),
        sa.Column("family_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_refresh_token_uses_family_id", "refresh_token_uses", ["family_id"])
    op.create_index("ix_refresh_token_uses_user_id", "refresh_token_uses", ["user_id"])
    op.create_index("ix_refresh_token_uses_expires_at", "refresh_token_uses", ["expires_at"])
    op.create_table(
        "revoked_token_families",
        sa.Column("family_id", sa.UUID(), primary_key=True),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_revoked_token_families_user_id", "revoked_token_families", ["user_id"])
    op.create_index("ix_revoked_token_families_expires_at", "revoked_token_families", ["expires_at"])


def downgrade():
    op.drop_table("revoked_token_families")
    op.drop_table("refresh_token_uses")
