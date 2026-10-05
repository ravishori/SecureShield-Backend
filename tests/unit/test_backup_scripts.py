"""Backup tooling: credentials never reach argv, restore check refuses non-loopback servers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import db_backup  # noqa: E402

pytestmark = pytest.mark.unit
SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def test_pg_env_splits_the_url_into_environment_variables():
    env = db_backup.pg_env("postgresql+asyncpg://user:p%40ss@db.example.com:6543/app")
    assert env["PGHOST"] == "db.example.com" and env["PGPORT"] == "6543"
    assert (
        env["PGUSER"] == "user"
        and env["PGDATABASE"] == "app"
        and env["PGPASSWORD"] == "p@ss"
    )


def test_sha256_matches_known_value(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"abc")
    assert (
        db_backup.sha256_of(f)
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_backup_requires_a_url(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("BACKUP_DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["db_backup.py", "--out", str(tmp_path)])
    with pytest.raises(SystemExit) as exc:
        db_backup.main()
    assert "BACKUP_DATABASE_URL" in str(exc.value)


def test_restore_check_refuses_a_remote_server(tmp_path, monkeypatch):
    import db_restore_check

    dump = tmp_path / "d.dump"
    dump.write_bytes(b"x")
    monkeypatch.setenv(
        "RESTORE_ADMIN_URL", "postgresql://u:p@prod.example.com:5432/postgres"
    )
    monkeypatch.setattr(sys, "argv", ["db_restore_check.py", str(dump)])
    with pytest.raises(SystemExit) as exc:
        db_restore_check.main()
    assert "loopback" in str(exc.value)
