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
    assert (
        normalize_async_db_url(f"{scheme}://{BASE}") == f"postgresql+asyncpg://{BASE}"
    )


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
    assert (
        normalize_async_db_url(f"postgres://{BASE}") == f"postgresql+asyncpg://{BASE}"
    )


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


# --- Neon: channel_binding (libpq-only, asyncpg rejects it) ---------------------------------------------------------
NEON = "role:pw@ep-cool-name-123456.c-2.ap-southeast-1.aws.neon.tech:5432/mydb"


@pytest.mark.unit
def test_neon_console_string_is_made_asyncpg_safe():
    out = normalize_async_db_url(
        f"postgresql://{NEON}?sslmode=require&channel_binding=require"
    )
    assert out == f"postgresql+asyncpg://{NEON}?ssl=require"
    _, kwargs = asyncpg_dialect().create_connect_args(make_url(out))
    assert "channel_binding" not in kwargs and "sslmode" not in kwargs
    assert kwargs["ssl"] == "require"


@pytest.mark.unit
def test_channel_binding_alone_is_dropped_and_leaves_no_dangling_question_mark():
    assert (
        normalize_async_db_url(f"postgresql+asyncpg://{NEON}?channel_binding=require")
        == f"postgresql+asyncpg://{NEON}"
    )


@pytest.mark.unit
def test_channel_binding_is_dropped_when_ssl_is_already_explicit():
    out = normalize_async_db_url(
        f"postgresql+asyncpg://{NEON}?ssl=require&channel_binding=require"
    )
    assert out == f"postgresql+asyncpg://{NEON}?ssl=require"


@pytest.mark.unit
def test_other_query_options_survive_normalisation():
    out = normalize_async_db_url(
        f"postgres://{NEON}?sslmode=require&channel_binding=require&statement_cache_size=0"
    )
    assert make_url(out).query == {"ssl": "require", "statement_cache_size": "0"}


@pytest.mark.unit
def test_pooler_host_and_password_are_untouched():
    u = "postgres://role:p%40ss@ep-cool-name-123456-pooler.c-2.ap-southeast-1.aws.neon.tech/db?sslmode=require"
    parsed = make_url(normalize_async_db_url(u))
    assert parsed.host.endswith("-pooler.c-2.ap-southeast-1.aws.neon.tech")
    assert parsed.password == "p@ss" and parsed.database == "db"


@pytest.mark.unit
def test_settings_accepts_a_neon_string_end_to_end(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", f"postgresql://{NEON}?sslmode=require&channel_binding=require"
    )
    monkeypatch.setenv(
        "MIGRATOR_DATABASE_URL",
        f"postgresql://{NEON}?sslmode=require&channel_binding=require",
    )
    s = Settings()
    for url in (s.DATABASE_URL, s.MIGRATOR_DATABASE_URL):
        assert make_url(url).query == {"ssl": "require"}
