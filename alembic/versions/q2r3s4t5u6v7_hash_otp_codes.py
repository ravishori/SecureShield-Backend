"""otps.code: widen to hold an HMAC and drop any plaintext codes

Codes are now stored as HMAC-SHA256 hex digests (64 chars). Existing rows hold plaintext six-digit
codes that expire within 10 minutes; they are deleted so no usable code remains at rest.

Revision ID: q2r3s4t5u6v7
Revises: p1q2r3s4t5u6
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from alembic import op

revision = "q2r3s4t5u6v7"
down_revision = "p1q2r3s4t5u6"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("DELETE FROM otps")
    op.alter_column("otps", "code", existing_type=sa.String(10), type_=sa.String(64), existing_nullable=False)


def downgrade():
    op.execute("DELETE FROM otps")
    op.alter_column("otps", "code", existing_type=sa.String(64), type_=sa.String(10), existing_nullable=False)
