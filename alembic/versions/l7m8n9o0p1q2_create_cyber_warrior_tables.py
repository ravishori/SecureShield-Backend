"""create warrior_applications, warrior_profiles, warrior_audit_logs

Cyber Warriors Network — Phase 1B foundation slice. Introduces three
tables + two enum types + a partial unique index that enforces "one open
application per user".

Scope: adult volunteer applications, approved warrior profiles, and the
immutable audit trail. Case/messaging/credential tables land in a later
migration once safeguarding + consent controls are implemented.

Deliberate design:
  • Enum values are strings on purpose — easier to grep and extend.
  • CREATE TYPE IF NOT EXISTS so re-runs are safe.
  • warrior_profiles.user_id is UNIQUE — one profile per user max.
  • Partial index enforces "at most one pending application per user"
    without blocking a user from reapplying after a rejection.

Revision ID: l7m8n9o0p1q2
Revises: k6l7m8n9o0p1
Create Date: 2026-10-04 00:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = 'l7m8n9o0p1q2'
down_revision: Union[str, None] = 'k6l7m8n9o0p1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # ── Enums (idempotent) ─────────────────────────────────────────────────
    conn.execute(sa.text("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'warriorrole') THEN
                CREATE TYPE warriorrole AS ENUM (
                    'trainee', 'verified_warrior', 'mentor', 'moderator', 'admin'
                );
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'warriorapplicationstatus') THEN
                CREATE TYPE warriorapplicationstatus AS ENUM (
                    'pending', 'approved', 'rejected', 'withdrawn'
                );
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'warriorauditaction') THEN
                CREATE TYPE warriorauditaction AS ENUM (
                    'application_submitted',
                    'application_approved',
                    'application_rejected',
                    'application_withdrawn',
                    'role_promoted',
                    'role_demoted',
                    'profile_suspended',
                    'profile_reactivated'
                );
            END IF;
        END$$;
    """))

    # ── warrior_applications ──────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS warrior_applications (
            id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

            full_name          VARCHAR(255) NOT NULL,
            date_of_birth      DATE         NOT NULL,
            phone              VARCHAR(20)  NOT NULL,
            email              VARCHAR(255) NOT NULL,
            city               VARCHAR(100),
            state              VARCHAR(100),

            preferred_role     warriorrole  NOT NULL DEFAULT 'trainee',
            motivation         TEXT         NOT NULL,
            skills             TEXT,
            languages          VARCHAR(200),
            availability_hours_per_week INTEGER,

            consent_bgcheck       BOOLEAN NOT NULL,
            consent_pii           BOOLEAN NOT NULL,
            consent_safeguarding  BOOLEAN NOT NULL,

            status             warriorapplicationstatus NOT NULL DEFAULT 'pending',
            reviewer_user_id   UUID REFERENCES users(id),
            reviewer_notes     TEXT,

            created_at         TIMESTAMP NOT NULL DEFAULT NOW(),
            reviewed_at        TIMESTAMP
        );
    """))
    # Fast "pending apps for user X" lookup
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_warrior_applications_user_id
          ON warrior_applications(user_id);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_warrior_applications_status
          ON warrior_applications(status);
    """))
    # One OPEN application per user — partial unique index
    conn.execute(sa.text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_warrior_app_user_pending
          ON warrior_applications(user_id)
          WHERE status = 'pending';
    """))

    # ── warrior_profiles ──────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS warrior_profiles (
            id              UUID       PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         UUID       NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            application_id  UUID       REFERENCES warrior_applications(id) ON DELETE SET NULL,

            role            warriorrole NOT NULL DEFAULT 'trainee',
            is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
            display_name    VARCHAR(255) NOT NULL,
            date_of_birth   DATE         NOT NULL,

            created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMP   NOT NULL DEFAULT NOW()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_warrior_profiles_role
          ON warrior_profiles(role);
    """))

    # ── warrior_audit_logs ────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS warrior_audit_logs (
            id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            actor_user_id    UUID        NOT NULL REFERENCES users(id),
            subject_user_id  UUID        REFERENCES users(id),
            action           warriorauditaction NOT NULL,
            extra            JSONB,
            reason           TEXT,
            created_at       TIMESTAMP   NOT NULL DEFAULT NOW()
        );
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_warrior_audit_actor
          ON warrior_audit_logs(actor_user_id, created_at DESC);
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_warrior_audit_subject
          ON warrior_audit_logs(subject_user_id, created_at DESC);
    """))


def downgrade() -> None:
    # Drop in reverse dependency order; CASCADE handles any residual refs.
    op.execute("DROP TABLE IF EXISTS warrior_audit_logs CASCADE;")
    op.execute("DROP TABLE IF EXISTS warrior_profiles CASCADE;")
    op.execute("DROP TABLE IF EXISTS warrior_applications CASCADE;")
    op.execute("DROP TYPE IF EXISTS warriorauditaction;")
    op.execute("DROP TYPE IF EXISTS warriorapplicationstatus;")
    op.execute("DROP TYPE IF EXISTS warriorrole;")
