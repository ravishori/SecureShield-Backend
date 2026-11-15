"""app monitor: idempotent sync identity and a durable guardian-alert outbox

Revision ID: x9y0z1a2b3c4
Revises: w8x9y0z1a2b3

Additive only; nothing is deleted or rewritten and old clients keep working:

* ``app_install_events.client_event_id`` / ``occurred_at`` (both nullable) plus two PARTIAL unique indexes that make sync
  idempotent and race-safe: per user by client event id, and - for old clients that send no id - per user by
  (package, event type, observation time). Existing rows have NULLs and are outside both indexes.
* ``guardian_alert_outbox``: one durable row per alert (status, attempts, lease, per-channel progress, expiry) with a unique
  (user_id, dedupe_key). ``event_id`` references the event with ON DELETE SET NULL, so deleting an event never removes an alert.
* ``guardian_alert_deliveries``: send-attempt audit (no contact details, no message text), cascades with its outbox row.
* ``elderly_configs`` gains nullable guardian authorisation and per-channel verification columns. Existing guardian
  settings therefore start UNAUTHORISED and UNVERIFIED, and no alert is sent for them until the account holder authorises the
  guardian and the guardian confirms the channel (behaviour change, by design).
* An index on ``guardian_alert_outbox.event_id`` (the FK is ON DELETE SET NULL; deleting an event and the per-event status
  lookup both search by it).

Rollback: ``downgrade`` drops the two tables and the new columns/indexes. That discards queued and historical guardian alerts,
the client event ids and every guardian authorisation/verification (events and the rest of the elderly settings are kept).
Use it only before the new code has been used.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "x9y0z1a2b3c4"
down_revision = "w8x9y0z1a2b3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "app_install_events", sa.Column("client_event_id", sa.UUID(), nullable=True)
    )
    op.add_column(
        "app_install_events", sa.Column("occurred_at", sa.DateTime(), nullable=True)
    )
    op.create_index(
        "uq_app_events_client_event",
        "app_install_events",
        ["user_id", "client_event_id"],
        unique=True,
        postgresql_where=sa.text("client_event_id IS NOT NULL"),
    )
    op.create_index(
        "uq_app_events_legacy_occurrence",
        "app_install_events",
        ["user_id", "package_name", "event_type", "occurred_at"],
        unique=True,
        postgresql_where=sa.text("client_event_id IS NULL AND occurred_at IS NOT NULL"),
    )

    op.create_table(
        "guardian_alert_outbox",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "event_id",
            sa.UUID(),
            sa.ForeignKey("app_install_events.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("dedupe_key", sa.String(80), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("lease_token", sa.UUID(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
        sa.Column("channels_done", postgresql.JSONB(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("last_error_code", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "user_id", "dedupe_key", name="uq_guardian_outbox_user_dedupe"
        ),
    )
    op.create_index(
        "ix_guardian_alert_outbox_user_id", "guardian_alert_outbox", ["user_id"]
    )
    op.create_index(
        "ix_guardian_outbox_due", "guardian_alert_outbox", ["status", "next_attempt_at"]
    )

    op.create_index(
        "ix_guardian_outbox_event_id", "guardian_alert_outbox", ["event_id"]
    )

    op.create_table(
        "guardian_alert_deliveries",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "outbox_id",
            sa.UUID(),
            sa.ForeignKey("guardian_alert_outbox.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(8), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_guardian_alert_deliveries_outbox_id",
        "guardian_alert_deliveries",
        ["outbox_id"],
    )

    # guardian authorisation + verification (all nullable: existing rows are unauthorised and unverified)
    for name, typ in (
        ("guardian_authorised_at", sa.DateTime()),
        ("guardian_notice_version", sa.String(20)),
        ("guardian_email_verified_at", sa.DateTime()),
        ("guardian_email_verified_value", sa.String(255)),
        ("guardian_phone_verified_at", sa.DateTime()),
        ("guardian_phone_verified_value", sa.String(20)),
    ):
        op.add_column("elderly_configs", sa.Column(name, typ, nullable=True))


def downgrade():
    for col in (
        "guardian_phone_verified_value",
        "guardian_phone_verified_at",
        "guardian_email_verified_value",
        "guardian_email_verified_at",
        "guardian_notice_version",
        "guardian_authorised_at",
    ):
        op.drop_column("elderly_configs", col)
    op.drop_index("ix_guardian_outbox_event_id", table_name="guardian_alert_outbox")
    op.drop_index(
        "ix_guardian_alert_deliveries_outbox_id", table_name="guardian_alert_deliveries"
    )
    op.drop_table("guardian_alert_deliveries")
    op.drop_index("ix_guardian_outbox_due", table_name="guardian_alert_outbox")
    op.drop_index(
        "ix_guardian_alert_outbox_user_id", table_name="guardian_alert_outbox"
    )
    op.drop_table("guardian_alert_outbox")
    op.drop_index("uq_app_events_legacy_occurrence", table_name="app_install_events")
    op.drop_index("uq_app_events_client_event", table_name="app_install_events")
    op.drop_column("app_install_events", "occurred_at")
    op.drop_column("app_install_events", "client_event_id")
