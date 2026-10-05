"""security_reports: one report per user per day

Concurrent first requests could create duplicate daily reports. De-duplicate (keep the newest)
and enforce uniqueness.

Revision ID: n9o0p1q2r3s4
Revises: m8n9o0p1q2r3
Create Date: 2026-10-05
"""

import sqlalchemy as sa
from alembic import op

revision = "n9o0p1q2r3s4"
down_revision = "m8n9o0p1q2r3"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        sa.text(
            """
            DELETE FROM security_reports a
            USING security_reports b
            WHERE a.user_id = b.user_id AND a.report_date = b.report_date
              AND (a.created_at, a.id) < (b.created_at, b.id)
            """
        )
    )
    op.create_unique_constraint(
        "uq_security_reports_user_day", "security_reports", ["user_id", "report_date"]
    )


def downgrade():
    op.drop_constraint("uq_security_reports_user_day", "security_reports", type_="unique")
