"""alerttype: add the members the application already uses

The initial migration created the enum with 9 values; the model later gained community_scam,
identity_breach, sim_swap, job_fraud, suspicious_message, cyberbullying and dark_web_leak without a
migration, so creating those alerts (message analysis, job-offer check, bullying check...) failed
with "invalid input value for enum alerttype" (HTTP 500).

Revision ID: p1q2r3s4t5u6
Revises: o0p1q2r3s4t5
Create Date: 2026-10-05
"""

from alembic import op

revision = "p1q2r3s4t5u6"
down_revision = "o0p1q2r3s4t5"
branch_labels = None
depends_on = None

NEW_VALUES = (
    "community_scam",
    "identity_breach",
    "sim_swap",
    "job_fraud",
    "suspicious_message",
    "cyberbullying",
    "dark_web_leak",
)


def upgrade():
    # ADD VALUE must be committed before it can be used; run outside the migration transaction.
    with op.get_context().autocommit_block():
        for value in NEW_VALUES:
            op.execute(f"ALTER TYPE alerttype ADD VALUE IF NOT EXISTS '{value}'")


def downgrade():
    # PostgreSQL cannot drop enum values; leaving them is harmless.
    pass
