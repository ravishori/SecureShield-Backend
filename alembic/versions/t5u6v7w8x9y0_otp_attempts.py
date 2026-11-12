"""per-OTP failed-attempt counter

Adds ``otps.attempts`` (default 0). Additive and non-destructive: existing rows keep their data and
start at 0. The application burns an OTP after OTP_MAX_ATTEMPTS wrong guesses, so brute-forcing a
six-digit code no longer depends on the (per-process) rate limiter alone.

Revision ID: t5u6v7w8x9y0
Revises: s4t5u6v7w8x9
Create Date: 2026-11-12
"""

import sqlalchemy as sa
from alembic import op

revision = "t5u6v7w8x9y0"
down_revision = "s4t5u6v7w8x9"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "otps",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade():
    op.drop_column("otps", "attempts")
