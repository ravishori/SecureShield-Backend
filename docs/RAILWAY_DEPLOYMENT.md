# SecureShield on Railway

| | Old | New |
|---|---|---|
| Database | Azure Database for PostgreSQL (`secureshield-pg-prod`) | **Railway PostgreSQL** |
| API | (Azure Container Apps / App Service) | **Railway `secureshield-api`** (Dockerfile) |

```
Flutter -> Railway SecureShield API -> Railway PostgreSQL
```

**The Azure PostgreSQL server no longer exists and held no data that needed
saving, so no data migration was performed.** Railway PostgreSQL is a fresh
database initialised with `alembic upgrade head` (head `l7m8n9o0p1q2`,
29 tables incl. the unmapped legacy `otp_vault_entries`).

## Staging project (`secureshield-staging`)
- Services: `Postgres`, `secureshield-api` (+ volume `/app/uploads`).
- `railway.toml`: Dockerfile builder, pre-deploy `alembic upgrade head`,
  healthcheck `/health`, 1 replica. Railway supplies `PORT`.
- `/ready` runs `SELECT current_database(), current_user` as the app role.

## Database
- Two roles (not created by migrations; create once as the Railway superuser):
  `secureshield_migrator` (owns schema `public`, runs Alembic) and
  `secureshield_app` (DML only, via `ALTER DEFAULT PRIVILEGES FOR ROLE
  secureshield_migrator ...`). Passwords live only in Railway variables.
- `DATABASE_URL` / `MIGRATOR_DATABASE_URL` use Railway references
  (`${{Postgres.RAILWAY_PRIVATE_DOMAIN}}`, `${{Postgres.PGDATABASE}}`).
  `app/config.py::normalize_async_db_url` converts `postgres://` and
  `postgresql://` to `postgresql+asyncpg://` and `?sslmode=` to `?ssl=`
  (asyncpg rejects `sslmode`). Private-network URLs need no SSL parameter.
- Local `.env` no longer defines the DB URLs; supply them via process env.
- Reference tables `tsp_codes`, `lsa_codes`, `sms_sender_registry` are empty
  until `scripts/seed_sms_registry.py` is run (needs psycopg2 + the TRAI xlsx).

## Uploads
Evidence and recordings are cwd-relative (`/app/uploads/{evidence,recordings}`);
the Railway volume is mounted at `/app/uploads`. Verified persistent across a
redeploy. Single replica only (in-memory rate limiter, local-disk uploads).

## Operations

### Reference data (TRAI SMS registry) — run once per database
`tsp_codes`, `lsa_codes`, `sms_sender_registry` are empty on a fresh DB. Inputs:
`List_SMS_Headers_16062020_0.xlsx` (repo parent folder, 23,192 rows) plus the TSP/LSA
tables embedded in the script (from `Detail_Header_Prefixes_16062020_0.pdf`).
```
pip install -r requirements-seed.txt
python scripts/seed_sms_registry.py --dry-run     # parse only
python scripts/seed_sms_registry.py               # refuses if tables already hold data
```
It connects with `MIGRATOR_DATABASE_URL` (TRUNCATE needs ownership). It must reach the
DB from your machine, i.e. via a *temporary* Railway TCP proxy on the Postgres service
(delete it afterwards); the private network is not reachable from a laptop.

### First Cyber Warriors admin (one-time, no HTTP endpoint)
Register the person through the app first, then in the running container:
```
railway ssh -s secureshield-api -- python -m app.cli.bootstrap_admin --email EMAIL --date-of-birth YYYY-MM-DD
railway ssh -s secureshield-api -- python -m app.cli.bootstrap_admin --email EMAIL --date-of-birth YYYY-MM-DD --confirm EMAIL
```
First command is a dry run. It refuses once any admin profile exists, is serialised by a
Postgres advisory lock, and writes a `warrior_audit_logs` row. Further admins use the
audited approve flow.

### Railway configuration
`railway.toml` (config-as-code) is deprecated by Railway but works until 2026-12-01. Needed
settings: Dockerfile build (auto-detected), healthcheck `/health`, pre-deploy
`alembic upgrade head`, 1 replica. Migration path (not yet applied):
`railway config migrate --service secureshield-api` (dry-run by default), review with
`railway config plan`, then `--apply`. `restartPolicy*` is not carried over (Railway defaults apply).

## Known issues (staging)
1. **Email OTP cannot work from Railway on this plan.** Railway allows outbound SMTP only on
   Pro and above; from the container IPv4 587/465 time out and IPv6 is unreachable. Railway
   recommends HTTPS email APIs (Resend, SendGrid, Mailgun, Postmark). Not yet implemented.
2. Twilio returns auth error 20003 with the current credentials: SMS OTP is down.
3. OTP codes are never logged (fixed; guarded by `tests/unit/test_otp_logging.py` and
   `tests/integration/test_otp_logging_api.py`).
4. Error-alert emails (`logger_service`, unreviewed pre-existing code) also use SMTP and will fail on Railway.
5. Error logging stores only an allowlisted set of request headers (never Authorization, Cookie
   or X-Admin-Token), never request bodies, only query-parameter *names*, the matched route template
   instead of the concrete path (share tokens, phone numbers), and the DB engine hides bound SQL
   parameters. Tracebacks/exception text are still stored — treat `error_logs` as sensitive.
6. Authoritative issue list: `docs/SECURESHIELD_FEATURE_GAPS_AND_ERRORS.md`.

## Deferred security backlog (NOT done; no values recorded here)
Rotate: Anthropic key, `SECRET_KEY`, Twilio credentials, Gmail SMTP credential,
Google Safe Browsing key, Azure PostgreSQL credentials (obsolete), `ADMIN_TOKEN`,
Azure Translator key. Purge historical secrets from Git history. Staging uses
its own freshly generated `SECRET_KEY` / `ADMIN_TOKEN` / DB passwords.
