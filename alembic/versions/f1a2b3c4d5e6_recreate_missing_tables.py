"""recreate behavior_events, community_scam_reports and create emergency_contacts

The previous migration (d845ea331d7d) was auto-generated incorrectly:
its upgrade() dropped behavior_events + community_scam_reports instead of
creating emergency_contacts. This migration is the corrective fix.

Revision ID: f1a2b3c4d5e6
Revises: d845ea331d7d
Create Date: 2026-04-04 22:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'd845ea331d7d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # ── 1. Create enum types safely (IF NOT EXISTS equivalent) ──────────────
    conn.execute(sa.text("""
        DO $$ BEGIN
            CREATE TYPE behavioreventtype AS ENUM (
                'clicked_unknown_link',
                'installed_suspicious_app',
                'shared_otp',
                'connected_open_wifi',
                'received_scam_call',
                'submitted_form_on_suspicious_site',
                'opened_scam_message',
                'granted_excessive_permissions',
                'disabled_security_feature'
            );
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
    """))

    conn.execute(sa.text("""
        DO $$ BEGIN
            CREATE TYPE scamtype AS ENUM (
                'phishing_link',
                'fake_job',
                'lottery_fraud',
                'investment_scam',
                'bank_fraud',
                'otp_fraud',
                'romance_scam',
                'tech_support_scam',
                'parcel_scam',
                'other'
            );
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
    """))

    # ── 2. behavior_events ───────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS behavior_events (
            id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            event_type  behavioreventtype NOT NULL,
            risk_contribution DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            details     TEXT,
            extra_data  JSONB       NOT NULL DEFAULT '{}',
            occurred_at TIMESTAMP   NOT NULL DEFAULT now()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_behavior_events_user_id
            ON behavior_events(user_id);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_behavior_events_occurred_at
            ON behavior_events(occurred_at DESC);
    """))

    # ── 3. community_scam_reports ────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS community_scam_reports (
            id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            scam_type    scamtype    NOT NULL,
            title        VARCHAR(255) NOT NULL,
            description  TEXT        NOT NULL,
            phone_number VARCHAR(20),
            url          TEXT,
            city         VARCHAR(100),
            pincode      VARCHAR(10),
            upvotes      INTEGER     NOT NULL DEFAULT 0,
            is_verified  BOOLEAN     NOT NULL DEFAULT false,
            is_active    BOOLEAN     NOT NULL DEFAULT true,
            extra_data   JSONB       NOT NULL DEFAULT '{}',
            created_at   TIMESTAMP   NOT NULL DEFAULT now()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_community_scam_user_id
            ON community_scam_reports(user_id);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_community_scam_city
            ON community_scam_reports(city);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_community_scam_pincode
            ON community_scam_reports(pincode);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_community_scam_created_at
            ON community_scam_reports(created_at DESC);
    """))

    # ── 4. emergency_contacts ────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS emergency_contacts (
            id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name         VARCHAR(150) NOT NULL,
            relationship VARCHAR(100),
            phone        VARCHAR(30),
            email        VARCHAR(255),
            created_at   TIMESTAMP   NOT NULL DEFAULT now()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_emergency_contacts_user_id
            ON emergency_contacts(user_id);
    """))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("DROP TABLE IF EXISTS emergency_contacts CASCADE;"))
    conn.execute(sa.text("DROP TABLE IF EXISTS community_scam_reports CASCADE;"))
    conn.execute(sa.text("DROP TABLE IF EXISTS behavior_events CASCADE;"))
    conn.execute(sa.text("DROP TYPE IF EXISTS scamtype;"))
    conn.execute(sa.text("DROP TYPE IF EXISTS behavioreventtype;"))
