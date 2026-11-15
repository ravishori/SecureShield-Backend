"""Configuration precedence and explicit env-file selection (Stage 1.1).

Rule: process environment > explicitly selected env file > defaults. ``backend/.env`` is never loaded implicitly, and a
selected file that is missing is a configuration error.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic_settings import SettingsConfigDict

from app import config
from app.config import ConfigError, Settings, _resolve_env_files

pytestmark = [pytest.mark.unit, pytest.mark.security]

BACKEND = Path(__file__).resolve().parents[2]


def _settings_for(file: Path):
    """The real ``Settings`` class (real source ordering) pointed at ``file``."""

    class Selected(Settings):
        model_config = SettingsConfigDict(
            **{**Settings.model_config, "env_file": str(file)}
        )

    return Selected()


def _write(tmp_path, text):
    f = tmp_path / "selected.env"
    f.write_text(text, encoding="utf-8")
    return f


def test_e1_process_environment_beats_the_selected_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "5")
    assert (
        _settings_for(
            _write(tmp_path, "ACCESS_TOKEN_EXPIRE_MINUTES=9\n")
        ).ACCESS_TOKEN_EXPIRE_MINUTES
        == 5
    )


def test_e1b_process_environment_beats_the_file_for_the_database_url(tmp_path):
    f = _write(
        tmp_path, "DATABASE_URL=postgresql://file:file@filehost.invalid/filedb\n"
    )
    assert (
        "filehost.invalid" not in _settings_for(f).DATABASE_URL
    )  # conftest's process value wins


def test_e2_selected_file_supplies_values_the_environment_lacks(tmp_path, monkeypatch):
    monkeypatch.delenv("ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
    assert (
        _settings_for(
            _write(tmp_path, "ACCESS_TOKEN_EXPIRE_MINUTES=9\n")
        ).ACCESS_TOKEN_EXPIRE_MINUTES
        == 9
    )


def test_e3_defaults_apply_when_neither_sets_the_value(tmp_path, monkeypatch):
    monkeypatch.delenv("ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
    assert (
        _settings_for(_write(tmp_path, "# empty\n")).ACCESS_TOKEN_EXPIRE_MINUTES == 60
    )


def test_e4_no_implicit_env_file(monkeypatch):
    monkeypatch.delenv("SECURESHIELD_ENV_FILE", raising=False)
    assert _resolve_env_files() == ()
    assert Settings.model_config.get("env_file") is None


def test_e4b_fresh_process_never_reads_backend_dotenv():
    env = {k: v for k, v in os.environ.items() if k != "SECURESHIELD_ENV_FILE"}
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app.config import Settings; print(Settings.model_config.get('env_file'))",
        ],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr[-300:]
    assert out.stdout.strip() == "None"


def test_e5_selected_but_missing_file_is_a_clear_error(tmp_path, monkeypatch):
    missing = tmp_path / "SECRET-LOOKING-NAME.env"
    monkeypatch.setenv("SECURESHIELD_ENV_FILE", str(missing))
    with pytest.raises(ConfigError, match="SECURESHIELD_ENV_FILE"):
        _resolve_env_files()
    env = dict(os.environ, SECURESHIELD_ENV_FILE=str(missing))
    out = subprocess.run(
        [sys.executable, "-c", "import app.config"],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
    )
    assert (
        out.returncode != 0
        and "ConfigError" in out.stderr
        and "SECURESHIELD_ENV_FILE" in out.stderr
    )


def test_e5b_a_directory_is_not_an_env_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURESHIELD_ENV_FILE", str(tmp_path))
    with pytest.raises(ConfigError):
        _resolve_env_files()


def test_selected_existing_file_is_returned(tmp_path, monkeypatch):
    f = _write(tmp_path, "X=1\n")
    monkeypatch.setenv("SECURESHIELD_ENV_FILE", str(f))
    assert _resolve_env_files() == (str(f),)


def test_e7_unselected_dotenv_warns_once_without_leaking_values(
    tmp_path, monkeypatch, caplog
):
    (tmp_path / ".env").write_text("SENTINEL_KEY=SENTINEL-VALUE\n", encoding="utf-8")
    monkeypatch.setattr(config, "_BACKEND_DIR", tmp_path)
    monkeypatch.delenv("SECURESHIELD_ENV_FILE", raising=False)
    with caplog.at_level(logging.WARNING, logger="app.config"):
        assert config.warn_if_unselected_env_file() is True
    assert "SECURESHIELD_ENV_FILE" in caplog.text and "NOT read" in caplog.text
    assert "SENTINEL" not in caplog.text
    monkeypatch.setenv("SECURESHIELD_ENV_FILE", str(tmp_path / ".env"))
    assert config.warn_if_unselected_env_file() is False


def test_no_warning_when_no_dotenv_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_BACKEND_DIR", tmp_path)
    monkeypatch.delenv("SECURESHIELD_ENV_FILE", raising=False)
    assert config.warn_if_unselected_env_file() is False


def test_source_order_is_init_env_dotenv_secrets():
    names = ["init", "env", "dotenv", "secrets"]
    got = Settings.settings_customise_sources(Settings, *names)
    assert list(got) == names
