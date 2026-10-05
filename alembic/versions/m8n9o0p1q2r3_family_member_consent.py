"""family members: consent workflow (consent_status, invited_phone)

Before this, anyone could add another person's phone number as a family member with
can_view_alerts=true and read that person's alerts without their knowledge. Links now start
as 'pending' and only grant access once the invited person accepts. Existing links are set to
'pending' on purpose (they were never consented to).

Revision ID: m8n9o0p1q2r3
Revises: l7m8n9o0p1q2
Create Date: 2026-10-05
"""

import sqlalchemy as sa
from alembic import op

revision = "m8n9o0p1q2r3"
down_revision = "l7m8n9o0p1q2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "family_members",
        sa.Column("consent_status", sa.String(16), nullable=False, server_default="pending"),
    )
    op.add_column("family_members", sa.Column("invited_phone", sa.String(20), nullable=True))
    op.create_index("ix_family_members_member_user_id", "family_members", ["member_user_id"])
    op.create_index("ix_family_members_invited_phone", "family_members", ["invited_phone"])


def downgrade():
    op.drop_index("ix_family_members_invited_phone", "family_members")
    op.drop_index("ix_family_members_member_user_id", "family_members")
    op.drop_column("family_members", "invited_phone")
    op.drop_column("family_members", "consent_status")
