-- =====================================================================================================================
-- SecureShield AI - F19 Stage 2A (idempotent app-monitor sync + durable guardian-alert outbox): SQL REVIEW SCRIPT
-- Alembic revision  : x9y0z1a2b3c4  (down revision w8x9y0z1a2b3 - the consent revision must be applied first)
-- Source of truth   : backend/alembic/versions/x9y0z1a2b3c4_app_monitor_sync_and_guardian_outbox.py (this file mirrors it;
--                     Alembic is the supported way to apply the change; use this script for REVIEW or a manual apply)
-- Status            : PREPARED FOR REVIEW. NOT EXECUTED on any application database.
--
-- WHAT IT DOES      : additive only. Two nullable columns and two PARTIAL unique indexes on app_install_events; two new tables
--                     (guardian_alert_outbox, guardian_alert_deliveries); six nullable guardian authorisation/verification
--                     columns on elderly_configs; an index on guardian_alert_outbox.event_id.
-- BEHAVIOUR CHANGE  : existing guardian settings start UNAUTHORISED and UNVERIFIED, so no guardian alert is sent for them until
--                     the account holder authorises the guardian and the guardian confirms the channel.
-- WHAT IT NEVER DOES: delete, update or rewrite any existing row; touch users, backups or other tables.
--
-- HOW TO REVIEW SAFELY: run the whole file against a COPY of the data. It ends with ROLLBACK, so a review run keeps nothing
-- (PostgreSQL DDL is transactional). To really apply it (only after owner approval and a verified backup) change the final
-- ROLLBACK to COMMIT and run the optional alembic_version statement - or run `alembic upgrade head` instead.
--
-- LOCKS AND RISK: ADD COLUMN (nullable, no default) is metadata-only. CREATE UNIQUE INDEX takes a SHARE lock on
-- app_install_events for the duration of the build (writes wait; reads continue). The table is small today (it was empty at the
-- last staging probe), so building inside this transaction is acceptable. This is a deliberate limit of this script: for a
-- LARGE table the indexes must instead be built with CREATE INDEX CONCURRENTLY, which cannot run inside BEGIN/COMMIT, so that
-- would be a separate, manual procedure (build the two indexes concurrently first, then run the rest of this script without
-- the two CREATE UNIQUE INDEX statements). Both indexes are PARTIAL and every existing row has NULLs in the new columns, so
-- they cannot conflict with existing data. gen_random_uuid() (used by the worker, not by this script) needs PostgreSQL 13+.
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
    IF current_rev IS DISTINCT FROM 'w8x9y0z1a2b3' THEN
        RAISE EXCEPTION 'Expected alembic_version w8x9y0z1a2b3 but found %. Do not apply this script.', current_rev;
    END IF;
    IF to_regclass('public.app_install_events') IS NULL THEN
        RAISE EXCEPTION 'app_install_events is missing.';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'app_install_events' AND column_name IN ('client_event_id', 'occurred_at')) THEN
        RAISE EXCEPTION 'app_install_events already has one of the new columns.';
    END IF;
    IF to_regclass('public.guardian_alert_outbox') IS NOT NULL OR to_regclass('public.guardian_alert_deliveries') IS NOT NULL THEN
        RAISE EXCEPTION 'A guardian alert table already exists.';
    END IF;
    IF to_regclass('public.elderly_configs') IS NULL THEN
        RAISE EXCEPTION 'elderly_configs is missing.';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'elderly_configs'
                 AND column_name IN ('guardian_authorised_at', 'guardian_notice_version', 'guardian_email_verified_at',
                                     'guardian_email_verified_value', 'guardian_phone_verified_at', 'guardian_phone_verified_value')) THEN
        RAISE EXCEPTION 'elderly_configs already has a guardian authorisation column.';
    END IF;
END
$$;

CREATE TEMP TABLE _f19_before ON COMMIT DROP AS
SELECT (SELECT count(*) FROM app_install_events) AS events_rows,
       (SELECT count(*) FROM elderly_configs)    AS config_rows;

-- 2. APPLY (additive only) ---------------------------------------------------------------------------------------------
ALTER TABLE app_install_events ADD COLUMN client_event_id uuid;
ALTER TABLE app_install_events ADD COLUMN occurred_at timestamp without time zone;

-- Race-safe idempotency. (1) the device-generated event id, per user.
CREATE UNIQUE INDEX uq_app_events_client_event
    ON app_install_events (user_id, client_event_id)
    WHERE client_event_id IS NOT NULL;
-- (2) old clients that send no id: the event's own observation time identifies it.
CREATE UNIQUE INDEX uq_app_events_legacy_occurrence
    ON app_install_events (user_id, package_name, event_type, occurred_at)
    WHERE client_event_id IS NULL AND occurred_at IS NOT NULL;

CREATE TABLE guardian_alert_outbox (
    id               uuid PRIMARY KEY,
    user_id          uuid NOT NULL,
    event_id         uuid REFERENCES app_install_events (id) ON DELETE SET NULL,   -- deleting an event keeps its alert
    dedupe_key       varchar(80) NOT NULL,                                          -- 'evt:<event id>' or 'legacy:<hash>'
    payload          jsonb NOT NULL,                                                -- message inputs only; NO contact details
    status           varchar(10) NOT NULL,                                          -- pending|leased|sent|skipped|expired|failed
    attempts         integer NOT NULL,
    max_attempts     integer NOT NULL,
    next_attempt_at  timestamp without time zone NOT NULL,
    lease_token      uuid,
    lease_expires_at timestamp without time zone,
    channels_done    jsonb NOT NULL,                                                -- {"sms": true, "email": false}
    expires_at       timestamp without time zone NOT NULL,
    sent_at          timestamp without time zone,
    last_error_code  varchar(40),
    created_at       timestamp without time zone NOT NULL,
    updated_at       timestamp without time zone NOT NULL,
    CONSTRAINT uq_guardian_outbox_user_dedupe UNIQUE (user_id, dedupe_key)
);
CREATE INDEX ix_guardian_alert_outbox_user_id ON guardian_alert_outbox (user_id);
CREATE INDEX ix_guardian_outbox_due           ON guardian_alert_outbox (status, next_attempt_at);
CREATE INDEX ix_guardian_outbox_event_id      ON guardian_alert_outbox (event_id);

CREATE TABLE guardian_alert_deliveries (
    id         uuid PRIMARY KEY,
    outbox_id  uuid NOT NULL REFERENCES guardian_alert_outbox (id) ON DELETE CASCADE,
    attempt_no integer NOT NULL,
    channel    varchar(8) NOT NULL,      -- sms | email
    result     varchar(16) NOT NULL,     -- ok | failed | error
    error_code varchar(40),              -- an exception TYPE or a fixed code; never a message, contact or content
    created_at timestamp without time zone NOT NULL
);
CREATE INDEX ix_guardian_alert_deliveries_outbox_id ON guardian_alert_deliveries (outbox_id);

-- Guardian authorisation + verification (nullable: existing rows are unauthorised and unverified)
ALTER TABLE elderly_configs ADD COLUMN guardian_authorised_at          timestamp without time zone;
ALTER TABLE elderly_configs ADD COLUMN guardian_notice_version         varchar(20);
ALTER TABLE elderly_configs ADD COLUMN guardian_email_verified_at      timestamp without time zone;
ALTER TABLE elderly_configs ADD COLUMN guardian_email_verified_value   varchar(255);
ALTER TABLE elderly_configs ADD COLUMN guardian_phone_verified_at      timestamp without time zone;
ALTER TABLE elderly_configs ADD COLUMN guardian_phone_verified_value   varchar(20);

-- 3. Optional: keep Alembic in step when applying by hand (leave commented for a review run) -------------------------------
-- UPDATE alembic_version SET version_num = 'x9y0z1a2b3c4' WHERE version_num = 'w8x9y0z1a2b3';

-- 4. VERIFICATION (the DO block aborts the transaction on any anomaly) ---------------------------------------------------
DO $$
DECLARE
    b record;
    n bigint;
BEGIN
    SELECT * INTO b FROM _f19_before;
    IF (SELECT count(*) FROM app_install_events) <> b.events_rows OR (SELECT count(*) FROM elderly_configs) <> b.config_rows THEN
        RAISE EXCEPTION 'Row counts changed: the migration must not add or remove rows.';
    END IF;
    SELECT count(*) INTO n FROM app_install_events WHERE client_event_id IS NOT NULL OR occurred_at IS NOT NULL;
    IF n <> 0 THEN
        RAISE EXCEPTION '% existing events were given sync identity data.', n;
    END IF;
    IF (SELECT count(*) FROM guardian_alert_outbox) <> 0 OR (SELECT count(*) FROM guardian_alert_deliveries) <> 0 THEN
        RAISE EXCEPTION 'The new tables must start empty.';
    END IF;
    SELECT count(*) INTO n FROM elderly_configs
     WHERE guardian_authorised_at IS NOT NULL OR guardian_notice_version IS NOT NULL
        OR guardian_email_verified_at IS NOT NULL OR guardian_phone_verified_at IS NOT NULL;
    IF n <> 0 THEN
        RAISE EXCEPTION '% existing guardian settings were marked authorised or verified.', n;
    END IF;
    IF to_regclass('public.ix_guardian_outbox_event_id') IS NULL THEN
        RAISE EXCEPTION 'The event_id index is missing.';
    END IF;

    -- both indexes exist, are UNIQUE and are PARTIAL (read from the catalogue; no test rows are inserted because
    -- app_install_events has several NOT NULL columns without database defaults)
    SELECT count(*) INTO n
      FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
     WHERE c.relname IN ('uq_app_events_client_event', 'uq_app_events_legacy_occurrence')
       AND i.indisunique AND i.indpred IS NOT NULL;
    IF n <> 2 THEN
        RAISE EXCEPTION 'Expected 2 partial unique indexes, found %.', n;
    END IF;

    -- the outbox FK clears (not cascades) on event delete; the audit FK cascades with its outbox row
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'guardian_alert_outbox'::regclass AND contype = 'f' AND confdeltype = 'n') THEN
        RAISE EXCEPTION 'guardian_alert_outbox.event_id must be ON DELETE SET NULL.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'guardian_alert_deliveries'::regclass AND contype = 'f' AND confdeltype = 'c') THEN
        RAISE EXCEPTION 'guardian_alert_deliveries.outbox_id must be ON DELETE CASCADE.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'guardian_alert_outbox'::regclass AND conname = 'uq_guardian_outbox_user_dedupe') THEN
        RAISE EXCEPTION 'The per-user dedupe constraint is missing.';
    END IF;
    RAISE NOTICE 'F19 stage 2A migration: all verification checks passed.';
END
$$;

-- 4b. RUNTIME ROLE PRIVILEGES. The tables are created by the migrator role; the application connects as the least-privilege
-- runtime role (secureshield_app: DML only, docs/RAILWAY_DEPLOYMENT.md). Without privileges on the new tables the sync
-- endpoint and the guardian worker fail with "permission denied". This block FAILS the transaction if the runtime role exists
-- but cannot read/write the new tables (for example ALTER DEFAULT PRIVILEGES was not set for the migrator role), and only
-- NOTICEs when the role does not exist (a review copy without roles). Evaluated inside this transaction, so it sees the
-- privileges a COMMIT would leave behind.
DO $$
DECLARE
    runtime_role constant text := 'secureshield_app';
    t text;
    missing text := '';
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = runtime_role) THEN
        RAISE NOTICE 'Role % does not exist on this database: privilege check skipped (review copy).', runtime_role;
        RETURN;
    END IF;
    FOREACH t IN ARRAY ARRAY['guardian_alert_outbox', 'guardian_alert_deliveries'] LOOP
        IF NOT has_table_privilege(runtime_role, 'public.' || t, 'SELECT,INSERT,UPDATE,DELETE') THEN
            missing := missing || ' ' || t;
        END IF;
    END LOOP;
    -- existing tables only gain columns, which inherit the table-level privileges the role already holds
    IF NOT has_table_privilege(runtime_role, 'public.app_install_events', 'SELECT,INSERT') THEN
        missing := missing || ' app_install_events';
    END IF;
    IF NOT has_table_privilege(runtime_role, 'public.elderly_configs', 'SELECT,INSERT,UPDATE') THEN
        missing := missing || ' elderly_configs';
    END IF;
    IF missing <> '' THEN
        RAISE EXCEPTION 'Runtime role % lacks DML on:%. Fix with ALTER DEFAULT PRIVILEGES FOR ROLE <migrator> IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %, or GRANT on these tables (see the commented block below). Do not COMMIT before it passes.', runtime_role, missing, runtime_role;
    END IF;
    RAISE NOTICE 'Runtime role % has the required privileges on the new tables.', runtime_role;
END
$$;

-- Read-only: which default privileges exist for tables created in schema public (empty = grants must be applied by hand).
SELECT pg_get_userbyid(defaclrole) AS creating_role, defaclacl AS default_acl
FROM pg_default_acl
WHERE defaclobjtype = 'r';

-- Manual fix, ONLY if the check above failed and the owner approves (kept commented; it is never run by this file):
-- GRANT SELECT, INSERT, UPDATE, DELETE ON guardian_alert_outbox, guardian_alert_deliveries TO secureshield_app;

-- 5. READ-ONLY REPORT (safe any time): outbox health once the code is live ----------------------------------------------
SELECT status, count(*) AS alerts, min(created_at) AS oldest, max(attempts) AS max_attempts_used
FROM guardian_alert_outbox
GROUP BY status
ORDER BY status;

-- Alerts stuck leased past their lease (a worker died; they are reclaimed automatically):
SELECT count(*) AS stale_leases FROM guardian_alert_outbox WHERE status = 'leased' AND lease_expires_at < now() AT TIME ZONE 'utc';

-- 6. END OF TRANSACTION: review run = ROLLBACK (default). Real apply = COMMIT after owner approval and a verified backup. ----
ROLLBACK;

-- =====================================================================================================================
-- ROLLBACK NOTES (reference only - COMMENTED OUT, never run by this file)
-- Before COMMIT: nothing to undo. After COMMIT and before the new code is used: reversible with the statements below. After
-- use, dropping discards queued/sent/failed guardian alerts and their delivery audit, the client event ids and every guardian
-- authorisation and verification (events and the other elderly settings are kept); prefer fixing forward. Old application versions ignore the new columns and tables, so a code rollback does NOT need
-- a schema rollback. Deploy order: migration first, then the backend, then the app.
--
-- BEGIN;
--   DROP INDEX ix_guardian_alert_deliveries_outbox_id;
--   DROP TABLE guardian_alert_deliveries;
--   ALTER TABLE elderly_configs DROP COLUMN guardian_phone_verified_value, DROP COLUMN guardian_phone_verified_at,
--                               DROP COLUMN guardian_email_verified_value, DROP COLUMN guardian_email_verified_at,
--                               DROP COLUMN guardian_notice_version, DROP COLUMN guardian_authorised_at;
--   DROP INDEX ix_guardian_outbox_event_id;
--   DROP INDEX ix_guardian_outbox_due;
--   DROP INDEX ix_guardian_alert_outbox_user_id;
--   DROP TABLE guardian_alert_outbox;
--   DROP INDEX uq_app_events_legacy_occurrence;
--   DROP INDEX uq_app_events_client_event;
--   ALTER TABLE app_install_events DROP COLUMN occurred_at, DROP COLUMN client_event_id;
--   UPDATE alembic_version SET version_num = 'w8x9y0z1a2b3' WHERE version_num = 'x9y0z1a2b3c4';
-- COMMIT;
