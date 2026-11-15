"""consent records: user_consents + consent captured with a pending registration

Revision ID: w8x9y0z1a2b3
Revises: v7w8x9y0z1a2

Additive only. Nothing is deleted or updated and no consent is assumed for existing users:

* ``user_consents``: append-only decisions (user, purpose, notice version, granted, source, time). Existing users simply have no
  rows until they accept the current notice in the app.
* ``pending_registrations`` gains the consent fields (all NULL on rows that already exist; such a row cannot be verified and the
  person registers again - pending rows live at most 24 hours anyway).

Rollback: ``downgrade`` drops the table and the columns, which discards every recorded consent. Use it only on a database that
has not been used with the new code.
"""

import sqlalchemy as sa
from alembic import op

revision = "w8x9y0z1a2b3"
down_revision = "v7w8x9y0z1a2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_consents",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(40), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("granted", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_user_consents_user_purpose", "user_consents", ["user_id", "purpose"]
    )
    op.add_column(
        "pending_registrations",
        sa.Column("terms_version", sa.String(20), nullable=True),
    )
    op.add_column(
        "pending_registrations",
        sa.Column("privacy_version", sa.String(20), nullable=True),
    )
    op.add_column(
        "pending_registrations", sa.Column("consented_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "pending_registrations",
        sa.Column("ai_processing_consent", sa.Boolean(), nullable=True),
    )


def downgrade():
    for col in (
        "ai_processing_consent",
        "consented_at",
        "privacy_version",
        "terms_version",
    ):
        op.drop_column("pending_registrations", col)
    op.drop_index("ix_user_consents_user_purpose", table_name="user_consents")
    op.drop_table("user_consents")
