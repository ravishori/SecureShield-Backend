"""individual admin accounts, MFA sessions, audit actor columns

Additive only: two new tables (``admin_accounts``, ``admin_sessions``) and two NULLABLE columns on
``admin_audit_logs`` (``actor_admin_id``, ``actor_label``). Existing audit rows are untouched (their actor stays
NULL = recorded before individual identities existed). No data is read, rewritten or deleted.

Revision ID: u6v7w8x9y0z1
Revises: t5u6v7w8x9y0
Create Date: 2026-11-12
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "u6v7w8x9y0z1"
down_revision = "t5u6v7w8x9y0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admin_accounts",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("totp_secret_enc", sa.Text(), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False),
        sa.Column("totp_last_step", sa.Integer(), nullable=False),
        sa.Column("recovery_hashes", postgresql.JSONB(), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(), nullable=True),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("role in ('support','admin','superadmin')", name="ck_admin_accounts_role"),
    )
    op.create_index("ix_admin_accounts_email", "admin_accounts", ["email"], unique=True)

    op.create_table(
        "admin_sessions",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("admin_id", sa.UUID(), sa.ForeignKey("admin_accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("client_ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(200), nullable=True),
    )
    op.create_index("ix_admin_sessions_admin_id", "admin_sessions", ["admin_id"])

    op.add_column("admin_audit_logs", sa.Column("actor_admin_id", sa.UUID(), nullable=True))
    op.add_column("admin_audit_logs", sa.Column("actor_label", sa.String(64), nullable=True))
    op.create_index("ix_admin_audit_logs_actor_admin_id", "admin_audit_logs", ["actor_admin_id"])


def downgrade():
    op.drop_index("ix_admin_audit_logs_actor_admin_id", table_name="admin_audit_logs")
    op.drop_column("admin_audit_logs", "actor_label")
    op.drop_column("admin_audit_logs", "actor_admin_id")
    op.drop_table("admin_sessions")
    op.drop_table("admin_accounts")
