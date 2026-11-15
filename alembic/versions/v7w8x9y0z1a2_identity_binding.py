"""identity binding: verified identifiers, pending registrations, single-identifier OTP challenges, google_sub

Revision ID: v7w8x9y0z1a2
Revises: u6v7w8x9y0z1

Additive only; NOTHING is deleted and NO existing record is marked verified:

* ``users.email_verified_at`` / ``phone_verified_at`` start NULL for every existing row. A historical identifier becomes
  verified only when its owner proves it with a code sent to that identifier alone (see app.services.identity).
* ``users.google_sub`` (unique, nullable): Google's stable subject, so an e-mail change never moves the link.
* ``pending_registrations``: unverified sign-ups live here, never on ``users``.
* ``otps`` gains ``identifier`` / ``identifier_type`` / ``purpose`` / ``user_id`` / ``pending_registration_id``. Existing OTP rows
  keep NULLs and are ignored by the new code (they expire on their own within minutes). A CHECK constraint requires every
  new-style row to carry exactly one identifier.

Rollback limitation: ``downgrade`` drops the verification state and the pending registrations, and restores the old
dual-identifier behaviour, which re-opens the account-takeover weakness this revision closes. Use it only on a database that
has not been used with the new code.
"""

import sqlalchemy as sa
from alembic import op

revision = "v7w8x9y0z1a2"
down_revision = "u6v7w8x9y0z1"
branch_labels = None
depends_on = None


def upgrade():
    # users
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("phone_verified_at", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("google_sub", sa.String(64), nullable=True))
    op.create_index("ix_users_google_sub", "users", ["google_sub"], unique=True)

    # pending registrations
    op.create_table(
        "pending_registrations",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("phone", sa.String(20), nullable=True),
        sa.Column("first_name", sa.String(100), nullable=False),
        sa.Column("last_name", sa.String(100), nullable=True),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("flat_no", sa.String(50), nullable=True),
        sa.Column("building", sa.String(255), nullable=True),
        sa.Column("street", sa.String(255), nullable=True),
        sa.Column("city", sa.String(100), nullable=True),
        sa.Column("state", sa.String(100), nullable=True),
        sa.Column("country", sa.String(100), nullable=True),
        sa.Column("pin_code", sa.String(10), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_pending_registrations_email",
        "pending_registrations",
        ["email"],
        unique=True,
    )
    op.create_index(
        "ix_pending_registrations_expires_at", "pending_registrations", ["expires_at"]
    )

    # otps: challenge binding
    op.add_column("otps", sa.Column("identifier", sa.String(255), nullable=True))
    op.add_column("otps", sa.Column("identifier_type", sa.String(8), nullable=True))
    op.add_column("otps", sa.Column("purpose", sa.String(32), nullable=True))
    op.add_column("otps", sa.Column("user_id", sa.UUID(), nullable=True))
    op.add_column(
        "otps", sa.Column("pending_registration_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        "fk_otps_user_id", "otps", "users", ["user_id"], ["id"], ondelete="CASCADE"
    )
    op.create_foreign_key(
        "fk_otps_pending_registration_id",
        "otps",
        "pending_registrations",
        ["pending_registration_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_otps_challenge", "otps", ["identifier_type", "identifier", "purpose"]
    )
    op.create_check_constraint(
        "ck_otps_single_identifier",
        "otps",
        "identifier IS NULL OR (purpose IS NOT NULL AND ("
        "(identifier_type = 'email' AND email = identifier AND phone IS NULL) OR "
        "(identifier_type = 'phone' AND phone = identifier AND email IS NULL)))",
    )


def downgrade():
    op.drop_constraint("ck_otps_single_identifier", "otps", type_="check")
    op.drop_index("ix_otps_challenge", table_name="otps")
    op.drop_constraint("fk_otps_pending_registration_id", "otps", type_="foreignkey")
    op.drop_constraint("fk_otps_user_id", "otps", type_="foreignkey")
    for col in (
        "pending_registration_id",
        "user_id",
        "purpose",
        "identifier_type",
        "identifier",
    ):
        op.drop_column("otps", col)
    op.drop_index(
        "ix_pending_registrations_expires_at", table_name="pending_registrations"
    )
    op.drop_index("ix_pending_registrations_email", table_name="pending_registrations")
    op.drop_table("pending_registrations")
    op.drop_index("ix_users_google_sub", table_name="users")
    for col in ("google_sub", "phone_verified_at", "email_verified_at"):
        op.drop_column("users", col)
