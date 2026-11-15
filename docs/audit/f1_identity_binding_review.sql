-- =====================================================================================================================
-- SecureShield AI - F1 identity binding: STANDALONE SQL REVIEW SCRIPT
-- Alembic revision  : v7w8x9y0z1a2  (down revision u6v7w8x9y0z1)
-- Source of truth   : backend/alembic/versions/v7w8x9y0z1a2_identity_binding.py  (this file mirrors it; Alembic is the
--                     supported way to apply the change - use this script for REVIEW, a DBA dry run, or a manual apply)
-- Status            : PREPARED FOR REVIEW. NOT EXECUTED anywhere (no local, staging, Neon or production database).
--
-- WHAT IT DOES   : additive only. Adds verification timestamps and google_sub to users, creates pending_registrations,
--                  and adds single-identifier challenge columns to otps.
-- WHAT IT NEVER DOES : delete or update any existing row; mark any identifier verified; move or merge any data;
--                  reassign any identifier; touch backups. No DROP, DELETE, TRUNCATE or UPDATE appears in the apply section.
--
-- HOW TO REVIEW SAFELY
--   1. Run this whole file as-is against a COPY of the data. It ends with ROLLBACK, so a review run changes nothing
--      (PostgreSQL DDL is transactional).
--   2. To really apply it (only after owner approval, on the intended database, after a verified backup), change the
--      final `ROLLBACK;` to `COMMIT;` AND run the optional alembic_version statement so Alembic stays in step.
--      Preferred alternative: run `alembic upgrade head` instead of this file.
--   3. Run section 5 (read-only impact report) before and after to see how many legacy identifiers are unverified.
--
-- LOCKS: ADD COLUMN (nullable, no default) and CREATE TABLE are metadata-only / instant. CREATE UNIQUE INDEX on
-- users.google_sub (all NULL) and CREATE INDEX on otps take a short SHARE lock on those tables; both tables are small.
-- Run in a quiet window anyway. The migration adds no table rewrite.
-- =====================================================================================================================

\set ON_ERROR_STOP on

BEGIN;

-- ---------------------------------------------------------------------------------------------------------------------
-- 0. Safety rails for this transaction
-- ---------------------------------------------------------------------------------------------------------------------
SET LOCAL lock_timeout = '5s';          -- fail fast instead of queueing behind long transactions
SET LOCAL statement_timeout = '60s';

-- ---------------------------------------------------------------------------------------------------------------------
-- 1. Preconditions: abort (with a clear message) unless the database is exactly at the expected previous revision
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    current_rev text;
BEGIN
    SELECT version_num INTO current_rev FROM alembic_version;
    IF current_rev IS DISTINCT FROM 'u6v7w8x9y0z1' THEN
        RAISE EXCEPTION 'Expected alembic_version u6v7w8x9y0z1 but found %. Do not apply this script.', current_rev;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'users' AND column_name IN ('email_verified_at', 'phone_verified_at', 'google_sub')) THEN
        RAISE EXCEPTION 'users already has one of the new columns: the change looks partly or fully applied.';
    END IF;

    IF to_regclass('public.pending_registrations') IS NOT NULL THEN
        RAISE EXCEPTION 'pending_registrations already exists.';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'otps' AND column_name IN ('identifier', 'identifier_type', 'purpose', 'user_id', 'pending_registration_id')) THEN
        RAISE EXCEPTION 'otps already has one of the new columns.';
    END IF;
END
$$;

-- Snapshot row counts so section 4 can prove nothing was lost or added (no existing row may change count).
CREATE TEMP TABLE _f1_before ON COMMIT DROP AS
SELECT (SELECT count(*) FROM users) AS users_rows,
       (SELECT count(*) FROM otps)  AS otps_rows,
       (SELECT count(*) FROM users WHERE email IS NOT NULL) AS users_with_email,
       (SELECT count(*) FROM users WHERE phone IS NOT NULL) AS users_with_phone;

-- ---------------------------------------------------------------------------------------------------------------------
-- 2. APPLY (additive only)
-- ---------------------------------------------------------------------------------------------------------------------

-- 2a. users: verification state + stable Google subject. Every existing row gets NULL = "not verified".
ALTER TABLE users ADD COLUMN email_verified_at timestamp without time zone;
ALTER TABLE users ADD COLUMN phone_verified_at timestamp without time zone;
ALTER TABLE users ADD COLUMN google_sub varchar(64);
CREATE UNIQUE INDEX ix_users_google_sub ON users (google_sub);   -- NULLs do not collide; one Google subject, one account

-- 2b. pending_registrations: unverified sign-ups live here and never on users.
CREATE TABLE pending_registrations (
    id          uuid PRIMARY KEY,
    email       varchar(255) NOT NULL,
    phone       varchar(20),                 -- a hint only; it is NOT bound to any account until verified separately
    first_name  varchar(100) NOT NULL,
    last_name   varchar(100),
    full_name   varchar(255),
    flat_no     varchar(50),
    building    varchar(255),
    street      varchar(255),
    city        varchar(100),
    state       varchar(100),
    country     varchar(100),
    pin_code    varchar(10),
    created_at  timestamp without time zone NOT NULL,
    expires_at  timestamp without time zone NOT NULL
);
CREATE UNIQUE INDEX ix_pending_registrations_email ON pending_registrations (email);   -- concurrent sign-ups collapse to one row
CREATE INDEX ix_pending_registrations_expires_at ON pending_registrations (expires_at);

-- 2c. otps: one challenge = one identifier = one channel = one purpose.
ALTER TABLE otps ADD COLUMN identifier              varchar(255);
ALTER TABLE otps ADD COLUMN identifier_type         varchar(8);
ALTER TABLE otps ADD COLUMN purpose                 varchar(32);
ALTER TABLE otps ADD COLUMN user_id                 uuid;
ALTER TABLE otps ADD COLUMN pending_registration_id uuid;

ALTER TABLE otps ADD CONSTRAINT fk_otps_user_id
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE otps ADD CONSTRAINT fk_otps_pending_registration_id
    FOREIGN KEY (pending_registration_id) REFERENCES pending_registrations (id) ON DELETE CASCADE;

CREATE INDEX ix_otps_challenge ON otps (identifier_type, identifier, purpose);

-- Existing OTP rows have identifier IS NULL, so the constraint accepts them unchanged. Every NEW row must carry exactly one
-- identifier, in the column that matches its type, and a purpose. NOT VALID is unnecessary: existing rows already satisfy it.
ALTER TABLE otps ADD CONSTRAINT ck_otps_single_identifier CHECK (
    identifier IS NULL OR (purpose IS NOT NULL AND (
        (identifier_type = 'email' AND email = identifier AND phone IS NULL) OR
        (identifier_type = 'phone' AND phone = identifier AND email IS NULL)))
);

-- ---------------------------------------------------------------------------------------------------------------------
-- 3. Optional: keep Alembic in step when applying by hand (leave commented for a review run)
-- ---------------------------------------------------------------------------------------------------------------------
-- UPDATE alembic_version SET version_num = 'v7w8x9y0z1a2' WHERE version_num = 'u6v7w8x9y0z1';

-- ---------------------------------------------------------------------------------------------------------------------
-- 4. VERIFICATION (each query must return the stated result; the DO block aborts the transaction otherwise)
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    b record;
    n bigint;
BEGIN
    SELECT * INTO b FROM _f1_before;

    -- no row was added or removed
    IF (SELECT count(*) FROM users) <> b.users_rows OR (SELECT count(*) FROM otps) <> b.otps_rows THEN
        RAISE EXCEPTION 'Row counts changed: the migration must not add or remove rows.';
    END IF;

    -- nothing was marked verified, and no Google subject was assigned
    SELECT count(*) INTO n FROM users
     WHERE email_verified_at IS NOT NULL OR phone_verified_at IS NOT NULL OR google_sub IS NOT NULL;
    IF n <> 0 THEN
        RAISE EXCEPTION '% existing users were marked verified / given a google_sub: the migration must not do that.', n;
    END IF;

    -- identifiers are untouched
    IF (SELECT count(*) FROM users WHERE email IS NOT NULL) <> b.users_with_email
       OR (SELECT count(*) FROM users WHERE phone IS NOT NULL) <> b.users_with_phone THEN
        RAISE EXCEPTION 'User identifiers changed.';
    END IF;

    -- every existing OTP row has no challenge binding yet (the new code ignores them; they expire on their own)
    SELECT count(*) INTO n FROM otps
     WHERE identifier IS NOT NULL OR identifier_type IS NOT NULL OR purpose IS NOT NULL
        OR user_id IS NOT NULL OR pending_registration_id IS NOT NULL;
    IF n <> 0 THEN
        RAISE EXCEPTION '% existing OTP rows were given challenge data.', n;
    END IF;

    -- the new table starts empty
    IF (SELECT count(*) FROM pending_registrations) <> 0 THEN
        RAISE EXCEPTION 'pending_registrations must start empty.';
    END IF;

    -- the objects exist
    IF to_regclass('public.ix_users_google_sub') IS NULL
       OR to_regclass('public.ix_pending_registrations_email') IS NULL
       OR to_regclass('public.ix_pending_registrations_expires_at') IS NULL
       OR to_regclass('public.ix_otps_challenge') IS NULL THEN
        RAISE EXCEPTION 'An expected index is missing.';
    END IF;

    SELECT count(*) INTO n FROM pg_constraint
     WHERE conname IN ('ck_otps_single_identifier', 'fk_otps_user_id', 'fk_otps_pending_registration_id');
    IF n <> 3 THEN
        RAISE EXCEPTION 'Expected 3 new constraints on otps, found %.', n;
    END IF;

    RAISE NOTICE 'F1 identity binding: all verification checks passed (%-% rows unchanged).', b.users_rows, b.otps_rows;
END
$$;

-- Constraint behaviour, proved inside the transaction (rolled back with everything else):
--   expected: a two-identifier OTP row is REJECTED by ck_otps_single_identifier
SAVEPOINT chk;
DO $$
BEGIN
    BEGIN
        INSERT INTO otps (email, phone, identifier, identifier_type, purpose, code, expires_at, created_at, is_used, attempts)
        VALUES ('a@example.com', '+911234567890', 'a@example.com', 'email', 'login', 'x', now(), now(), false, 0);
        RAISE EXCEPTION 'The single-identifier CHECK did not reject a two-identifier challenge.';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE 'OK: a challenge carrying both an e-mail and a phone is rejected.';
    END;
END
$$;
ROLLBACK TO SAVEPOINT chk;

-- ---------------------------------------------------------------------------------------------------------------------
-- 5. READ-ONLY IMPACT REPORT (legacy accounts). Safe to run any time, before or after the change. Shows counts only.
--    Legacy = existed before verification state; their identifiers are NOT verified until the owner proves them.
-- ---------------------------------------------------------------------------------------------------------------------
SELECT
    count(*)                                                                  AS users_total,
    count(*) FILTER (WHERE email IS NOT NULL AND email_verified_at IS NULL)   AS emails_unverified,
    count(*) FILTER (WHERE phone IS NOT NULL AND phone_verified_at IS NULL)   AS phones_unverified,
    count(*) FILTER (WHERE email_verified_at IS NULL AND phone_verified_at IS NULL) AS legacy_no_verified_identifier,
    count(*) FILTER (WHERE (email_verified_at IS NULL) <> (phone_verified_at IS NULL)) AS legacy_one_verified_identifier,
    count(*) FILTER (WHERE google_sub IS NOT NULL)                            AS google_linked
FROM users;

-- Identifiers claimed by more than one row can never exist (unique constraints), so list near-duplicates a human may want
-- to review: same phone digits in a different format. Informational only: nothing is changed or merged.
SELECT regexp_replace(phone, '[^0-9]', '', 'g') AS phone_digits, count(*) AS accounts
FROM users
WHERE phone IS NOT NULL
GROUP BY 1
HAVING count(*) > 1;

-- ---------------------------------------------------------------------------------------------------------------------
-- 6. END OF TRANSACTION
--    Review run  : ROLLBACK  (default - nothing is kept)
--    Real apply  : replace with COMMIT after owner approval, a verified backup, and (optionally) section 3.
-- ---------------------------------------------------------------------------------------------------------------------
ROLLBACK;

-- =====================================================================================================================
-- ROLLBACK / RECOVERY NOTES (reference only - the statements below are COMMENTED OUT and are never run by this file)
-- =====================================================================================================================
-- Before COMMIT : nothing to undo, the ROLLBACK above discards everything.
-- After COMMIT, before any user touches the new code: the change can be reversed with the statements below, in a transaction.
-- After COMMIT, once the new code has been used: do NOT reverse it casually. Dropping these columns discards verification
-- state (every identifier would look unverified again), the Google bindings and any pending registrations, and the old
-- application code it would require re-opens the dual-identifier registration weakness (F-01 / F-02). Prefer fixing forward.
-- Preferred recovery for real data loss: restore from the verified encrypted backup into an isolated database first
-- (see docs/BACKUP_AND_RECOVERY.md), compare, and only then decide.
--
-- BEGIN;
--   ALTER TABLE otps DROP CONSTRAINT ck_otps_single_identifier;
--   DROP INDEX ix_otps_challenge;
--   ALTER TABLE otps DROP CONSTRAINT fk_otps_pending_registration_id;
--   ALTER TABLE otps DROP CONSTRAINT fk_otps_user_id;
--   ALTER TABLE otps DROP COLUMN pending_registration_id, DROP COLUMN user_id, DROP COLUMN purpose,
--                    DROP COLUMN identifier_type, DROP COLUMN identifier;
--   DROP INDEX ix_pending_registrations_expires_at;
--   DROP INDEX ix_pending_registrations_email;
--   DROP TABLE pending_registrations;
--   DROP INDEX ix_users_google_sub;
--   ALTER TABLE users DROP COLUMN google_sub, DROP COLUMN phone_verified_at, DROP COLUMN email_verified_at;
--   UPDATE alembic_version SET version_num = 'u6v7w8x9y0z1' WHERE version_num = 'v7w8x9y0z1a2';
-- COMMIT;
