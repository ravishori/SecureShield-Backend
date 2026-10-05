"""Railway hands out postgres:// / postgresql:// URLs; the app needs
postgresql+asyncpg:// and asyncpg takes ?ssl=, never ?sslmode=."""

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.dialects.postgresql.asyncpg import dialect as asyncpg_dialect

from app.config import Settings, normalize_async_db_url

BASE = "user:pw@host.example:5432/db"


@pytest.mark.unit
@pytest.mark.parametrize("scheme", ["postgres", "postgresql"])
def test_plain_schemes_become_asyncpg(scheme):
    assert normalize_async_db_url(f"{scheme}://{BASE}") == f"postgresql+asyncpg://{BASE}"


@pytest.mark.unit
def test_correct_url_is_unchanged():
    u = f"postgresql+asyncpg://{BASE}?ssl=require"
    assert normalize_async_db_url(u) == u


@pytest.mark.unit
def test_sslmode_is_rewritten_to_ssl():
    out = normalize_async_db_url(f"postgres://{BASE}?sslmode=require")
    assert out == f"postgresql+asyncpg://{BASE}?ssl=require"
    assert "sslmode" not in out


@pytest.mark.unit
def test_explicit_ssl_wins_over_sslmode():
    out = normalize_async_db_url(f"postgresql://{BASE}?sslmode=disable&ssl=require")
    assert out == f"postgresql+asyncpg://{BASE}?ssl=require"


@pytest.mark.unit
def test_url_without_query_is_untouched_apart_from_scheme():
    assert normalize_async_db_url(f"postgres://{BASE}") == f"postgresql+asyncpg://{BASE}"


@pytest.mark.unit
def test_password_with_special_chars_survives():
    u = "postgres://u:p%40ss%3Aw%2Fd@h:5432/db?sslmode=require"
    out = normalize_async_db_url(u)
    assert make_url(out).password == "p@ss:w/d"
    assert make_url(out).query == {"ssl": "require"}


@pytest.mark.unit
def test_asyncpg_receives_ssl_not_sslmode():
    out = normalize_async_db_url(f"postgres://{BASE}?sslmode=require")
    _, kwargs = asyncpg_dialect().create_connect_args(make_url(out))
    assert kwargs.get("ssl") == "require"
    assert "sslmode" not in kwargs


@pytest.mark.unit
def test_settings_normalizes_both_urls(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"postgres://{BASE}")
    monkeypatch.setenv("MIGRATOR_DATABASE_URL", f"postgresql://{BASE}?sslmode=require")
    s = Settings()
    assert s.DATABASE_URL == f"postgresql+asyncpg://{BASE}"
    assert s.MIGRATOR_DATABASE_URL == f"postgresql+asyncpg://{BASE}?ssl=require"
