"""create app_install_events, clone_reports, elderly_configs

The models in app/models/{app_install_event,clone_report,elderly_config}.py
were added to the codebase but their tables were never migrated. The
/api/v1/app-monitor/summary endpoint blows up at runtime with
"relation 'app_install_events' does not exist".

This migration creates all three tables idempotently
(CREATE TABLE IF NOT EXISTS) so it's safe to run on databases that may
already have some of them.

Revision ID: k6l7m8n9o0p1
Revises: j5k6l7m8n9o0
Create Date: 2026-05-12 08:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = 'k6l7m8n9o0p1'
down_revision: Union[str, None] = 'j5k6l7m8n9o0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # ── 1. app_install_events ───────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS app_install_events (
            id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id             UUID         NOT NULL,

            package_name        VARCHAR(255) NOT NULL,
            app_name            VARCHAR(255) NOT NULL,
            version_name        VARCHAR(100),
            event_type          VARCHAR(20)  NOT NULL DEFAULT 'installed',

            installer_package   VARCHAR(255),
            is_unknown_source   BOOLEAN      NOT NULL DEFAULT FALSE,
            is_system_app       BOOLEAN      NOT NULL DEFAULT FALSE,

            dangerous_perms     JSONB        NOT NULL DEFAULT '[]'::jsonb,
            perm_count          INTEGER      NOT NULL DEFAULT 0,

            local_risk_score    INTEGER      NOT NULL DEFAULT 0,
            server_risk_score   INTEGER      NOT NULL DEFAULT 0,
            risk_level          VARCHAR(10)  NOT NULL DEFAULT 'safe',
            risk_tags           JSONB        NOT NULL DEFAULT '[]'::jsonb,

            clone_probability   INTEGER      NOT NULL DEFAULT 0,
            flagged_as_clone    BOOLEAN      NOT NULL DEFAULT FALSE,
            clone_target_pkg    VARCHAR(255),

            has_overlay         BOOLEAN      NOT NULL DEFAULT FALSE,
            has_accessibility   BOOLEAN      NOT NULL DEFAULT FALSE,

            first_install_time  BIGINT,
            synced_at           TIMESTAMP    NOT NULL DEFAULT now(),
            created_at          TIMESTAMP    NOT NULL DEFAULT now()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_app_install_events_user_id
            ON app_install_events(user_id);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_app_install_events_package_name
            ON app_install_events(package_name);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_app_install_events_created_at
            ON app_install_events(created_at DESC);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_app_install_events_risk_level
            ON app_install_events(risk_level);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_app_install_events_flagged_as_clone
            ON app_install_events(flagged_as_clone);
    """))

    # ── 2. clone_reports ────────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS clone_reports (
            id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id             UUID         NOT NULL,

            package_name        VARCHAR(255) NOT NULL,
            app_name            VARCHAR(255) NOT NULL,

            target_package      VARCHAR(255),
            target_name         VARCHAR(255),

            name_similarity     INTEGER      NOT NULL DEFAULT 0,
            package_similarity  INTEGER      NOT NULL DEFAULT 0,
            icon_hash_match     BOOLEAN      NOT NULL DEFAULT FALSE,
            cert_hash_match     BOOLEAN      NOT NULL DEFAULT FALSE,

            overall_score       INTEGER      NOT NULL DEFAULT 0,
            verdict             VARCHAR(20)  NOT NULL DEFAULT 'safe',

            signals             JSONB        NOT NULL DEFAULT '[]'::jsonb,

            action_taken        VARCHAR(50),
            user_confirmed      BOOLEAN,

            created_at          TIMESTAMP    NOT NULL DEFAULT now()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_clone_reports_user_id
            ON clone_reports(user_id);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_clone_reports_package_name
            ON clone_reports(package_name);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_clone_reports_created_at
            ON clone_reports(created_at DESC);
    """))

    # ── 3. elderly_configs ──────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS elderly_configs (
            id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id               UUID         NOT NULL UNIQUE,

            enabled               BOOLEAN      NOT NULL DEFAULT FALSE,

            guardian_name         VARCHAR(100),
            guardian_phone        VARCHAR(20),
            guardian_email        VARCHAR(255),

            block_risky_installs  BOOLEAN      NOT NULL DEFAULT TRUE,
            alert_threshold       INTEGER      NOT NULL DEFAULT 40,
            auto_alert_guardian   BOOLEAN      NOT NULL DEFAULT TRUE,
            require_approval      BOOLEAN      NOT NULL DEFAULT FALSE,

            simplified_ui         BOOLEAN      NOT NULL DEFAULT TRUE,
            large_text            BOOLEAN      NOT NULL DEFAULT TRUE,

            updated_at            TIMESTAMP    NOT NULL DEFAULT now(),
            created_at            TIMESTAMP    NOT NULL DEFAULT now()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_elderly_configs_user_id
            ON elderly_configs(user_id);
    """))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("DROP TABLE IF EXISTS elderly_configs CASCADE;"))
    conn.execute(sa.text("DROP TABLE IF EXISTS clone_reports CASCADE;"))
    conn.execute(sa.text("DROP TABLE IF EXISTS app_install_events CASCADE;"))
