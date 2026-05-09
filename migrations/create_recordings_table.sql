-- =============================================================================
--  SecureShield AI — Create recordings table
--  Run against: SecureShieldDB
--  Command:  psql -U postgres -d SecureShieldDB -f create_recordings_table.sql
-- =============================================================================

CREATE TABLE IF NOT EXISTS recordings (
    id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title             VARCHAR(255)  NOT NULL,
    file_path         VARCHAR(512)  NOT NULL,
    file_size_bytes   BIGINT        NOT NULL DEFAULT 0,
    duration_seconds  INTEGER       NOT NULL DEFAULT 0,
    is_encrypted      BOOLEAN       NOT NULL DEFAULT TRUE,
    share_token       VARCHAR(128)  UNIQUE,
    share_expires_at  TIMESTAMP     NULL,
    notes             TEXT          NULL,
    created_at        TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_recordings_user_id     ON recordings (user_id);
CREATE INDEX IF NOT EXISTS ix_recordings_share_token ON recordings (share_token);
