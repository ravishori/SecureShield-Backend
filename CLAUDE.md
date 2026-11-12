# SecureShield AI backend - development instructions

FastAPI 0.115 / Python 3.11 / SQLAlchemy 2 async / Alembic / PostgreSQL. The Flutter app lives in a separate repository (`SecureShield-Frontend`,
checked out as `../flutter_app`). Layout: `app/routers`, `app/services`, `app/models`, `app/schemas`, `app/middleware`, `alembic/versions`, `tests/unit`,
`tests/integration`, `docs/`.

## Commands

* Tests (real PostgreSQL, disposable `*_test` database only): set `TEST_DATABASE_URL` to a database whose name ends in `_test`, then `python -m pytest -q`. Integration tests are skipped without it. Never point tests at a real or Neon database.
* Lint: `ruff check app tests scripts` and `ruff format --check app tests scripts` (ruff 0.9.4).
* Migrations: `python -m alembic upgrade head` (single linear head; add a migration for every schema change; `tests/integration/test_schema_drift.py` must stay green).

## Operations commands

* Dependencies: `pip install -r requirements.txt` into a fresh virtual environment (the repository pins; stale environments carry old advisories). Audit with `pip-audit` (install it outside the project environment); keep the result at zero runtime advisories and record it in `docs/audit/`.
* Admin accounts (the shared `X-Admin-Token` is legacy break-glass; set `ADMIN_LEGACY_TOKEN_ENABLED=false` once named admins are enrolled): `python -m app.cli.admin_accounts create --email <e-mail> --role superadmin` (hidden password prompt), `list`, `reset-mfa`, `set-password`, `unlock`, `disable`, `enable`. Passwords are never passed on the command line.
* OTP providers: `python scripts/otp_provider_check.py` (configuration by variable name only) and `--live` (read-only authentication, sends nothing). `--send-test-email/--send-test-sms` really send a dummy message: use only with an address/number you own.
* Admin auth rules to keep: role and account state are re-read from the database on every request; account-management changes stay serialised; every privileged action is audited with its actor; no code path may print passwords, TOTP secrets, recovery codes or OTPs.

## Non-negotiable rules

* Never print, log, commit or paste secrets, connection strings, tokens or personal data. Name them, do not show them. `.env*` files are git-ignored; keep it that way.
* Do not change production configuration, databases or provider accounts without explicit owner approval. Do not push, deploy or rotate credentials unasked.
* Every endpoint that returns or changes user data needs an authorisation test (owner succeeds, another user gets 404/403, anonymous gets 401).
* Security fixes need a regression test that fails without the fix.

## Audit documentation rule (mandatory)

`docs/audit/` is the project's living source of truth for status. **Whenever a feature is developed, modified or completed:**

1. Reassess its actual implementation (read the code; do not rely on the existence of a screen, endpoint or document).
2. Run the relevant tests (and the full suite before committing) and record the real results.
3. Update the feature's status and scores in `docs/audit/feature-completion-matrix.md`.
4. Update affected `architecture-and-integration.md`, `security-audit.md`, `testing-and-qa.md`, `production-readiness.md` and `development-roadmap.md` sections.
5. Add a dated entry with commit ids and test evidence to `docs/audit/audit-history.md`.
6. Recompute the dashboard in `docs/audit/project-status.md` (method in the matrix document).
7. Never mark a feature TESTED or PRODUCTION without supporting evidence: TESTED needs an automated test that passes, REVIEWED needs a documented security review with mutation-checked regression tests, PRODUCTION needs real-provider and deployed verification.

Changes in the Flutter repository follow the same rule: update this repository's `docs/audit/` in the same working session and reference the Flutter commit id.
