-- =====================================================================================================================
-- SecureShield AI - Stage 1.2: isolated LOCAL development and test databases
-- =====================================================================================================================
-- STATUS: reviewed, NOT executed. Nothing in the repository runs this file. It is meant to be run ONCE, BY HAND, by the
-- machine owner, against the LOCAL PostgreSQL server only, after the owner has approved it.
--
-- WHAT IT CREATES (all names are fixed; none of them is, or resembles, a production/recovery target)
--   roles      secureshield_dev_owner   migrations for the development database (Alembic, MIGRATOR_DATABASE_URL); owns it
--              secureshield_dev_app     the running application in development (DATABASE_URL); data access only (DML)
--              secureshield_test_owner  the integration-test database only (TEST_DATABASE_URL); migrations + TRUNCATE between tests
--   databases  secureshield_dev         development data
--              secureshield_test        disposable integration-test data (the harness requires the "_test" suffix)
--
-- WHAT IT DELIBERATELY DOES NOT DO
--   * no password is created, stored or suggested here: the roles are created with LOGIN but WITHOUT a password, so nobody can
--     authenticate with a password until the owner sets one by hand (see "PASSWORDS" below);
--   * no superuser, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS attribute is ever granted; no role is a member of another;
--   * no extension, no ALTER SYSTEM, no pg_hba.conf / postgresql.conf change, no data statement of any kind;
--   * no destructive statement: it never removes, truncates, resets or overwrites anything. Existing roles/databases of the
--     same names are reused (and checked); a mismatch aborts the script instead of being "fixed".
--   * it never creates or mentions the production database name or any Neon / Railway / recovery endpoint.
--
-- HOW TO RUN (later, manually, after approval). Connect to the maintenance database as an administrative role (for example the
-- local "postgres" role), over loopback, with the psql that ships with the server:
--
--     psql -X -h localhost -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -f STAGE_1_2_LOCAL_DATABASE_SETUP.sql
--
--   -X                 ignore any ~/.psqlrc
--   ON_ERROR_STOP=1    stop at the first error (the script also sets it)
--   DO NOT use --single-transaction / -1: CREATE DATABASE cannot run inside a transaction block (see "TRANSACTIONS").
--
-- TRANSACTIONS (PostgreSQL cannot create a database inside a transaction block)
--   Part 0  precheck          one DO block (its own implicit transaction); aborts on any non-local server
--   Part 1  roles             ONE explicit transaction: BEGIN ... COMMIT (all three roles or none; a pre-existing role that holds
--                             more than least privilege aborts and rolls back the whole part; existing roles are never altered)
--   Part 2  databases         one statement each, in AUTOCOMMIT, generated with \gexec so it is skipped if the database exists.
--                             These two statements must NOT be wrapped in BEGIN/COMMIT. Each is its own atomic statement; if
--                             the first succeeds and the second fails, re-running the script completes the missing part.
--                             CREATE DATABASE copies "template1": it fails with "source database ... is being accessed by other
--                             users" if another session is connected to template1; close that session and re-run.
--   Part 3  connect privileges ONE explicit transaction (cluster catalog changes)
--   Part 4  schema privileges  one explicit transaction PER DATABASE (after \connect)
--   Part 5  verification       SELECT only
--   The script is idempotent: running it again changes nothing that is already correct.
--
-- PASSWORDS (not part of this file)
--   After Part 1, set each role's password interactively, so that it never appears in a file, a shell history or a log:
--       psql -h localhost -U postgres -d postgres
--       \password secureshield_dev_owner
--       \password secureshield_dev_app
--       \password secureshield_test_owner
--   (psql hashes the password on the client with SCRAM before sending it.) Put the passwords only in the git-ignored env file
--   or in your shell, never in a committed file. See docs/LOCAL_DEVELOPMENT.md.
--
-- ROLLBACK
--   This file contains no destructive statement, so there is nothing to "undo" automatically, and no rollback step requires a
--   destructive operation. To switch the environment off without losing data, an administrator disables the three logins
--   (ALTER ROLE <name> NOLOGIN) and, to switch it back on, re-enables them (ALTER ROLE <name> LOGIN). Re-running this script
--   after that is safe: it never alters an existing role. Removing the databases or roles is a separate, optional, manual
--   administrator decision documented in docs/LOCAL_DEVELOPMENT.md ("Manual removal"); it is intentionally not scripted here.
--   If the script stops part-way (an error, Ctrl-C or a lost connection) nothing needs cleaning up: fix the cause and run it again.
--
-- PREREQUISITES: PostgreSQL 15 or newer (this machine runs 18; the "public" schema is owned by pg_database_owner), and the
-- local administrative superuser role (for example "postgres"). No extension is needed: the Alembic revisions create none.
-- =====================================================================================================================

\set ON_ERROR_STOP on
-- CREATE DATABASE (Part 2) needs autocommit; make that independent of any psqlrc or -v AUTOCOMMIT=off.
\set AUTOCOMMIT on

-- ---------------------------------------------------------------------------------------------------------------------
-- Part 0 - precheck: refuse to run anywhere except a local server, from the maintenance database
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
BEGIN
    IF inet_server_addr() IS NOT NULL
       AND NOT (inet_server_addr() <<= '127.0.0.0/8'::inet OR inet_server_addr() = '::1'::inet) THEN
        RAISE EXCEPTION 'refusing to run: this PostgreSQL server is not reached over loopback or a local socket';
    END IF;
    IF current_database() <> 'postgres' THEN
        RAISE EXCEPTION 'refusing to run: connect to the maintenance database "postgres" (found %)', current_database();
    END IF;
    IF current_setting('server_version_num')::int < 150000 THEN
        RAISE EXCEPTION 'refusing to run: PostgreSQL 15 or newer is required';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_settings WHERE name LIKE 'neon.%')
       OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('neon_superuser', 'cloud_admin', 'neondb_owner', 'rds_superuser', 'azure_pg_admin', 'cloudsqlsuperuser')) THEN
        -- A loopback address does not prove the server is local (an SSH tunnel or port forward looks identical); a hosted
        -- service leaves its fingerprint in the settings and roles it provides.
        RAISE EXCEPTION 'refusing to run: this looks like a hosted PostgreSQL service (Neon/RDS/Azure/Cloud SQL), not the local server';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper) THEN
        -- Parts 3 and 4 connect to the new databases and change their schema privileges, which only a superuser may do after
        -- CONNECT has been revoked from PUBLIC.
        RAISE EXCEPTION 'refusing to run: connect as the local administrative (superuser) role';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Part 1 - roles (one transaction). LOGIN but no password; every dangerous attribute explicitly off.
-- ---------------------------------------------------------------------------------------------------------------------
BEGIN;

-- A missing role is created. A role that already exists is NEVER altered: it is only checked (next block) and the script stops
-- if it holds more than least privilege. Connection limits leave room for a development server with auto-reload (two processes
-- briefly overlap, each with a pool of up to 15 connections); the owner roles only run migrations or the test harness.
DO $$
DECLARE
    spec record;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES ('secureshield_dev_owner', 20), ('secureshield_dev_app', 50), ('secureshield_test_owner', 20))
            AS v(role_name, conn_limit)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = spec.role_name) THEN
            EXECUTE format(
                'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s',
                spec.role_name, spec.conn_limit
            );
        END IF;
    END LOOP;
END
$$;

-- Whether the roles were just created or pre-existed, none may hold more than least privilege. A violation aborts the whole
-- transaction (so nothing from Part 1 is kept) and asks for a manual review; existing roles are not modified here.
DO $$
DECLARE
    offending text;
BEGIN
    SELECT string_agg(r.rolname, ', ' ORDER BY r.rolname) INTO offending
    FROM pg_roles r
    WHERE r.rolname IN ('secureshield_dev_owner', 'secureshield_dev_app', 'secureshield_test_owner')
      AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
           OR EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid));
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'existing role(s) % hold more than least privilege (superuser, createdb, createrole, replication, bypassrls or membership of another role): review by hand; this script does not modify existing roles', offending;
    END IF;
END
$$;

COMMIT;

-- ---------------------------------------------------------------------------------------------------------------------
-- Part 2 - databases. NOT in a transaction block (CREATE DATABASE is not allowed in one). Each statement is generated only
-- if the database does not exist yet, then executed by \gexec in autocommit mode.
-- ---------------------------------------------------------------------------------------------------------------------
SELECT format('CREATE DATABASE %I OWNER %I', 'secureshield_dev', 'secureshield_dev_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'secureshield_dev')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I', 'secureshield_test', 'secureshield_test_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'secureshield_test')
\gexec

-- A database that already existed must belong to the intended owner (otherwise stop; never "repair" ownership here).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
                   WHERE d.datname = 'secureshield_dev' AND r.rolname = 'secureshield_dev_owner') THEN
        RAISE EXCEPTION 'secureshield_dev exists but is not owned by secureshield_dev_owner: stop and review by hand';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
                   WHERE d.datname = 'secureshield_test' AND r.rolname = 'secureshield_test_owner') THEN
        RAISE EXCEPTION 'secureshield_test exists but is not owned by secureshield_test_owner: stop and review by hand';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Part 3 - who may connect to what (one transaction). PUBLIC loses every database privilege; the development roles cannot
-- reach the test database and the test role cannot reach the development database.
-- ---------------------------------------------------------------------------------------------------------------------
BEGIN;

REVOKE ALL ON DATABASE secureshield_dev  FROM PUBLIC;
REVOKE ALL ON DATABASE secureshield_test FROM PUBLIC;

GRANT CONNECT ON DATABASE secureshield_dev  TO secureshield_dev_owner, secureshield_dev_app;
GRANT CONNECT ON DATABASE secureshield_test TO secureshield_test_owner;

REVOKE ALL ON DATABASE secureshield_dev  FROM secureshield_test_owner;
REVOKE ALL ON DATABASE secureshield_test FROM secureshield_dev_owner, secureshield_dev_app;

COMMIT;

-- ---------------------------------------------------------------------------------------------------------------------
-- Part 4 - schema privileges, inside each database (one transaction per database)
--   * the owner role owns the database, so it owns what it creates (Alembic runs as the owner);
--   * the application role may only read and write rows of tables the owner creates later (default privileges), plus use their
--     sequences: no CREATE, no TRUNCATE, no REFERENCES, no TRIGGER, no DDL.
-- ---------------------------------------------------------------------------------------------------------------------
\connect secureshield_dev

BEGIN;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO secureshield_dev_app;

ALTER DEFAULT PRIVILEGES FOR ROLE secureshield_dev_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secureshield_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE secureshield_dev_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO secureshield_dev_app;

COMMIT;

\connect secureshield_test

BEGIN;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- No application role exists for the test database: the integration harness runs the application AND the migrations as the
-- single owner role (it requires DATABASE_URL == MIGRATOR_DATABASE_URL == TEST_DATABASE_URL).

COMMIT;

\connect postgres

-- ---------------------------------------------------------------------------------------------------------------------
-- Part 5 - verification (SELECT only; read the results, they are the acceptance check for this script)
-- ---------------------------------------------------------------------------------------------------------------------

-- 5.1 EXPECT exactly 3 rows; every flag column false; can_login true; connection_limit 20 / 50 / 20 for roles created by this
--     script; has_password false until you set one. (pg_authid, readable because the script runs as a superuser, is used because
--     the pg_roles view masks every password as '********'. Only "is a password set" is selected, never the hash.)
SELECT r.rolname,
       r.rolcanlogin      AS can_login,
       r.rolsuper         AS superuser,
       r.rolcreatedb      AS create_db,
       r.rolcreaterole    AS create_role,
       r.rolreplication   AS replication,
       r.rolbypassrls     AS bypass_rls,
       r.rolinherit       AS inherit,
       r.rolconnlimit     AS connection_limit,
       (r.rolpassword IS NOT NULL) AS has_password
FROM pg_authid r
WHERE r.rolname IN ('secureshield_dev_owner', 'secureshield_dev_app', 'secureshield_test_owner')
ORDER BY r.rolname;

-- 5.1b EXPECT 0 rows: no authentication rule lets a client in without a password. The three roles have no password until you set
--      one, so a "trust" rule on a TCP or local-socket line would let anyone who can reach the server log in as them.
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'trust';

-- 5.2 EXPECT 0 rows: none of the three roles is a member of any other role (so none inherits extra privileges).
SELECT m.roleid::regrole AS member_of, m.member::regrole AS role
FROM pg_auth_members m
WHERE m.member::regrole::text IN ('secureshield_dev_owner', 'secureshield_dev_app', 'secureshield_test_owner');

-- 5.3 EXPECT 2 rows: secureshield_dev -> secureshield_dev_owner, secureshield_test -> secureshield_test_owner; encoding UTF8.
SELECT d.datname, r.rolname AS owner, pg_encoding_to_char(d.encoding) AS encoding, d.datallowconn AS allow_connections
FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
WHERE d.datname IN ('secureshield_dev', 'secureshield_test')
ORDER BY d.datname;

-- 5.4 EXPECT the connect matrix below (database x role -> can_connect):
--       secureshield_dev  : dev_owner true,  dev_app true,  test_owner false
--       secureshield_test : dev_owner false, dev_app false, test_owner true
SELECT d.datname, r.rolname,
       has_database_privilege(r.rolname, d.datname, 'CONNECT') AS can_connect
FROM (VALUES ('secureshield_dev'), ('secureshield_test')) AS d(datname)
CROSS JOIN (VALUES ('secureshield_dev_owner'), ('secureshield_dev_app'), ('secureshield_test_owner')) AS r(rolname)
ORDER BY d.datname, r.rolname;

-- 5.5 Every privilege on the two databases held by anyone other than the database owner (PUBLIC shows as 'PUBLIC').
--     EXPECT exactly ONE row: secureshield_dev | secureshield_dev_app | CONNECT. No PUBLIC row, no row for secureshield_test, and
--     no row for any other role (an unexpected grantee means someone granted access before this script ran: review it).
SELECT d.datname,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee,
       a.privilege_type
FROM pg_database d, aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
WHERE d.datname IN ('secureshield_dev', 'secureshield_test') AND a.grantee <> d.datdba
ORDER BY d.datname, grantee, a.privilege_type;

-- 5.6 INFORMATION ONLY. A row here is the LEGACY local source database of the Neon migration (the production database name).
--     This script never touches it, and the backend refuses that name outside production, so it can stay but must not be used
--     as a development database. 0 rows is also fine.
SELECT datname FROM pg_database WHERE lower(datname) = 'secureshielddb';

-- 5.7 Server identity, for the record. EXPECT a loopback address (or NULL for a local socket) and the version you installed.
SELECT inet_server_addr() AS server_address, inet_server_port() AS server_port, current_setting('server_version') AS version;

-- 5.8 Inside each database (run these by hand after connecting as the administrative role):
--       \connect secureshield_dev
--       -- EXPECT: public schema USAGE for dev_app only (plus the owner); no PUBLIC entry
--       SELECT nspname, nspacl FROM pg_namespace WHERE nspname = 'public';
--       -- EXPECT 2 rows (tables r, sequences S) granted to secureshield_dev_app by secureshield_dev_owner
--       SELECT defaclrole::regrole AS grantor, defaclobjtype AS object_type, defaclacl FROM pg_default_acl;
--       \connect secureshield_test
--       SELECT nspname, nspacl FROM pg_namespace WHERE nspname = 'public';   -- EXPECT no PUBLIC entry
--       \connect postgres
