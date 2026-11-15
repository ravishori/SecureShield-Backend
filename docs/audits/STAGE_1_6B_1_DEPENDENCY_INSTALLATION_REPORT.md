# Stage 1.6B-1 — Seed Dependency Installation Report

**Result: PASS**

## Inspection (before installing)
- Convention: runtime dependencies live in `requirements.txt` (pinned, includes `asyncpg==0.29.0`). Seed-only tools live in a **dedicated `requirements-seed.txt`**, which is listed in `.dockerignore` (line 71) so it stays out of the API image.
- `requirements-seed.txt` already declares `psycopg2-binary>=2.9,<3.0` and `openpyxl>=3.1,<4.0`.
- There is no `pyproject.toml` and no lock file.
- Python 3.11.9. Before the install, neither package was present. `asyncpg` 0.29.0 and SQLAlchemy 2.0.35 were.
- I did not read `.env.local`.

## Installation
- Command: `.venv/Scripts/python.exe -m pip install -r requirements-seed.txt` (the backend `.venv` only, not global).
- Result: exit 0, `Successfully installed et-xmlfile-2.0.0 openpyxl-3.1.5 psycopg2-binary-2.9.13`.

| Package | Version | Note |
|---|---|---|
| psycopg2-binary | 2.9.13 | `cp311-win_amd64` binary wheel; libpq flags `dt dec pq3 ext lo64` |
| openpyxl | 3.1.5 | |
| et-xmlfile | 2.0.0 | openpyxl's only dependency, installed automatically |

- `pip freeze` before and after differs by exactly those three added lines. No other package was upgraded, downgraded or removed.
- `pip check`: no broken requirements.

## Verification (no database connection)
- Both packages import. `psycopg2.extras.execute_values`, which the seed script uses, is present.
- `openpyxl` wrote a two-row workbook to an in-memory buffer and read it back unchanged: `[['Header','Entity'],['TESTHD','Test Entity']]`.
- `asyncpg` 0.29.0 and SQLAlchemy 2.0.35 still import. The application's database stack is unchanged.

## Dependency management
- The packages belong in the **seed-tools group**, which is the existing `requirements-seed.txt`. They stay out of the production runtime set and the container image.
- **No manifest change was needed.** `requirements.txt`, `requirements-seed.txt` and `.dockerignore` are unmodified (`git status` shows nothing for them).

## Files changed
- None in the repository. Only the backend `.venv` site-packages changed (the three packages above).
- The only new file is this report.

## Confirmations
- No database connection was attempted. No seed script, dry run, migration, `--replace`, FastAPI startup, or AI, SMS, e-mail or WhatsApp activation.
- No Neon or production access. No application source, production dependency or configuration changed. No Git staging, commit or push.

## Notes for the next stage
- The seed script's `--dry-run` is now able to run. It parses the XLSX without a database. It still needs your separate approval.
- pip reports a newer pip (24.0 → 26.3). I did not upgrade it, per the restrictions.
