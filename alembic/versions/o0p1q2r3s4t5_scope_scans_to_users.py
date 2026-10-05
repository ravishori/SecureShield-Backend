"""app_scans / wifi_scans: add user_id

App and Wi-Fi scans were stored with device_id NULL, so there was no owner at all and the history
endpoints returned every user's rows. Rows now carry user_id. Pre-existing rows cannot be
attributed and stay NULL (they are never returned to anyone).

Revision ID: o0p1q2r3s4t5
Revises: n9o0p1q2r3s4
Create Date: 2026-10-05
"""

import sqlalchemy as sa
from alembic import op

revision = "o0p1q2r3s4t5"
down_revision = "n9o0p1q2r3s4"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("app_scans", "wifi_scans"):
        op.add_column(table, sa.Column("user_id", sa.UUID(), nullable=True))
        op.create_foreign_key(f"fk_{table}_user_id", table, "users", ["user_id"], ["id"])
        op.create_index(f"ix_{table}_user_id", table, ["user_id"])


def downgrade():
    for table in ("app_scans", "wifi_scans"):
        op.drop_index(f"ix_{table}_user_id", table)
        op.drop_constraint(f"fk_{table}_user_id", table, type_="foreignkey")
        op.drop_column(table, "user_id")
