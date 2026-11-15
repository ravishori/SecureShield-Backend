-- =====================================================================================================================
-- SecureShield AI - Phase G consent records: STANDALONE SQL REVIEW SCRIPT
-- Alembic revision  : w8x9y0z1a2b3  (down revision v7w8x9y0z1a2 - the F1 identity-binding revision must be applied first)
-- Source of truth   : backend/alembic/versions/w8x9y0z1a2b3_consent_records.py (this file mirrors it; Alembic is the supported
--                     way to apply the change - use this script for REVIEW, a DBA dry run, or a manual apply)
-- Status            : PREPARED FOR REVIEW. NOT EXECUTED on any application database.
--
-- WHAT IT DOES      : additive only. Creates user_consents (append-only consent decisions) and adds four nullable consent
--                     columns to pending_registrations.
-- WHAT IT NEVER DOES: delete or update any row; record a consent on anyone's behalf; touch users, otps or backups.
--
-- HOW TO REVIEW SAFELY: run the whole file as-is against a COPY of the data. It ends with ROLLBACK, so a review run keeps
-- nothing (PostgreSQL DDL is transactional). To really apply it (only after owner approval and a verified backup) change the
-- final ROLLBACK to COMMIT and run the optional alembic_version statement - or run `alembic upgrade head` instead.
-- LOCKS: CREATE TABLE is instant; ADD COLUMN (nullable, no default) is metadata-only; the new index is on an empty table.
-- =====================================================================================================================

\set ON_ERROR_STOP on

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- 1. Preconditions ----------------------------------------------------------------------------------------------------
DO $$
DECLARE
    current_rev text;
BEGIN
    SELECT version_num INTO current_rev FROM alembic_version;
    IF current_rev IS DISTINCT FROM 'v7w8x9y0z1a2' THEN
        RAISE EXCEPTION 'Expected alembic_version v7w8x9y0z1a2 but found %. Do not apply this script.', current_rev;
    END IF;
    IF to_regclass('public.user_consents') IS NOT NULL THEN
        RAISE EXCEPTION 'user_consents already exists.';
    END IF;
    IF to_regclass('public.pending_registrations') IS NULL THEN
        RAISE EXCEPTION 'pending_registrations is missing: apply the F1 identity-binding revision first.';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'pending_registrations'
                 AND column_name IN ('terms_version', 'privacy_version', 'consented_at', 'ai_processing_consent')) THEN
        RAISE EXCEPTION 'pending_registrations already has a consent column.';
    END IF;
END
$$;

CREATE TEMP TABLE _g_before ON COMMIT DROP AS
SELECT (SELECT count(*) FROM users) AS users_rows,
       (SELECT count(*) FROM pending_registrations) AS pending_rows;

-- 2. APPLY (additive only) ---------------------------------------------------------------------------------------------
CREATE TABLE user_consents (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    varchar(40) NOT NULL,        -- terms | privacy_notice | ai_processing
    version    varchar(20) NOT NULL,        -- the notice version the person was shown
    granted    boolean NOT NULL,            -- false = withdrawn (optional purposes only)
    source     varchar(16) NOT NULL,        -- register | google | settings | update
    created_at timestamp without time zone NOT NULL
);
CREATE INDEX ix_user_consents_user_purpose ON user_consents (user_id, purpose);

ALTER TABLE pending_registrations ADD COLUMN terms_version          varchar(20);
ALTER TABLE pending_registrations ADD COLUMN privacy_version        varchar(20);
ALTER TABLE pending_registrations ADD COLUMN consented_at           timestamp without time zone;
ALTER TABLE pending_registrations ADD COLUMN ai_processing_consent  boolean;

-- 3. Optional: keep Alembic in step when applying by hand (leave commented for a review run) -------------------------------
-- UPDATE alembic_version SET version_num = 'w8x9y0z1a2b3' WHERE version_num = 'v7w8x9y0z1a2';

-- 4. VERIFICATION (the DO block aborts the transaction on any anomaly) ---------------------------------------------------
DO $$
DECLARE
    b record;
    n bigint;
BEGIN
    SELECT * INTO b FROM _g_before;
    IF (SELECT count(*) FROM users) <> b.users_rows OR (SELECT count(*) FROM pending_registrations) <> b.pending_rows THEN
        RAISE EXCEPTION 'Row counts changed: the migration must not add or remove rows.';
    END IF;
    IF (SELECT count(*) FROM user_consents) <> 0 THEN
        RAISE EXCEPTION 'user_consents must start empty (no consent is assumed for existing users).';
    END IF;
    SELECT count(*) INTO n FROM pending_registrations
     WHERE terms_version IS NOT NULL OR privacy_version IS NOT NULL OR consented_at IS NOT NULL OR ai_processing_consent IS NOT NULL;
    IF n <> 0 THEN
        RAISE EXCEPTION '% existing pending registrations were given consent data.', n;
    END IF;
    IF to_regclass('public.ix_user_consents_user_purpose') IS NULL THEN
        RAISE EXCEPTION 'Expected index is missing.';
    END IF;
    RAISE NOTICE 'Consent migration: all verification checks passed.';
END
$$;

-- The foreign key must cascade on user delete (read from the catalogue; no test rows are inserted because users has several
-- NOT NULL columns without database defaults).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'user_consents'::regclass AND contype = 'f' AND confdeltype = 'c') THEN
        RAISE EXCEPTION 'user_consents.user_id must be ON DELETE CASCADE.';
    END IF;
    RAISE NOTICE 'OK: consent rows follow their user on delete (FK is ON DELETE CASCADE).';
END
$$;

-- 5. READ-ONLY REPORT (safe any time): how many accounts still have no recorded acceptance of the current notice ---------------
-- Run after applying. Existing users show here until they accept the notice in the app; this is expected.
SELECT count(*) AS users_total,
       count(*) FILTER (WHERE NOT EXISTS (
           SELECT 1 FROM user_consents c WHERE c.user_id = u.id AND c.purpose = 'terms' AND c.granted)) AS users_without_terms_record
FROM users u
WHERE u.is_active;

-- 6. END OF TRANSACTION: review run = ROLLBACK (default). Real apply = COMMIT after owner approval and a verified backup. ----
ROLLBACK;

-- =====================================================================================================================
-- ROLLBACK NOTES (reference only - COMMENTED OUT, never run by this file)
-- Before COMMIT: nothing to undo. After COMMIT and before use: reversible with the statements below. After the app has been
-- used with it, dropping these objects DISCARDS every recorded consent (the evidence of what each person accepted); prefer
-- fixing forward, and restore into an isolated database first if data was lost (see docs/BACKUP_AND_RECOVERY.md).
--
-- BEGIN;
--   ALTER TABLE pending_registrations DROP COLUMN ai_processing_consent, DROP COLUMN consented_at,
--                                     DROP COLUMN privacy_version, DROP COLUMN terms_version;
--   DROP INDEX ix_user_consents_user_purpose;
--   DROP TABLE user_consents;
--   UPDATE alembic_version SET version_num = 'v7w8x9y0z1a2' WHERE version_num = 'w8x9y0z1a2b3';
-- COMMIT;
