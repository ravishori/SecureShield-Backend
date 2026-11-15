"""asyncpg integer options in the database URL (e.g. ``?statement_cache_size=0`` for a pooler) must reach asyncpg as ints.

Regression: a URL query value is a string; SQLAlchemy's asyncpg dialect only converts ``prepared_statement_cache_size``,
so ``statement_cache_size=0`` arrived as "0" and asyncpg raised ``TypeError: '<' not supported between 'str' and 'int'``
before it even tried to log in (the app could not connect to a pooled endpoint configured that way).
"""

from __future__ import annotations


import pytest
from sqlalchemy.dialects.postgresql.asyncpg import dialect as asyncpg_dialect
from sqlalchemy.engine import make_url

from app.config import ASYNCPG_INT_OPTIONS, split_asyncpg_options
from app.database import build_async_engine

BASE = "postgresql+asyncpg://role:secret-pw@ep-x-pooler.c-2.aws.neon.tech:5432/db"


# ------------------------------------------------------------------ split_asyncpg_options
@pytest.mark.unit
def test_statement_cache_size_is_moved_out_of_the_url_as_an_int():
    url, opts = split_asyncpg_options(f"{BASE}?ssl=require&statement_cache_size=0")
    assert opts == {"statement_cache_size": 0} and isinstance(
        opts["statement_cache_size"], int
    )
    assert make_url(url).query == {"ssl": "require"}


@pytest.mark.unit
def test_the_url_left_behind_would_no_longer_hand_asyncpg_a_string():
    url, _ = split_asyncpg_options(f"{BASE}?ssl=require&statement_cache_size=0")
    _, kwargs = asyncpg_dialect().create_connect_args(make_url(url))
    assert "statement_cache_size" not in kwargs
    # and this is the bug being fixed: without the split the value is a string
    _, before = asyncpg_dialect().create_connect_args(
        make_url(f"{BASE}?statement_cache_size=0")
    )
    assert before["statement_cache_size"] == "0"


@pytest.mark.unit
def test_every_integer_option_is_coerced():
    q = "&".join(
        f"{name}={i}" for i, name in enumerate(sorted(ASYNCPG_INT_OPTIONS), start=1)
    )
    url, opts = split_asyncpg_options(f"{BASE}?ssl=require&{q}")
    assert set(opts) == set(ASYNCPG_INT_OPTIONS) and all(
        isinstance(v, int) for v in opts.values()
    )
    assert make_url(url).query == {"ssl": "require"}


@pytest.mark.unit
@pytest.mark.parametrize("value", ["0", "-1", "100", "007"])
def test_integer_forms(value):
    _, opts = split_asyncpg_options(f"{BASE}?statement_cache_size={value}")
    assert opts == {"statement_cache_size": int(value)}


@pytest.mark.unit
@pytest.mark.parametrize("value", ["abc", "1.5", "", " ", "0x10"])
def test_non_integer_value_is_rejected_without_leaking_the_url(value):
    with pytest.raises(ValueError) as e:
        split_asyncpg_options(f"{BASE}?statement_cache_size={value}")
    msg = str(e.value)
    assert "statement_cache_size" in msg and "integer" in msg
    assert "secret-pw" not in msg and "neon.tech" not in msg and "role" not in msg


@pytest.mark.unit
@pytest.mark.parametrize(
    "url",
    [
        BASE,
        f"{BASE}?ssl=require",
        f"{BASE}?ssl=require&prepared_statement_cache_size=0",  # SQLAlchemy converts this one itself
        "postgresql://u:p@h/db?statement_cache_size=0",  # not the asyncpg driver: left alone
        "sqlite:///x.db",
    ],
)
def test_other_urls_are_returned_unchanged(url):
    assert split_asyncpg_options(url) == (url, {})


@pytest.mark.unit
def test_password_with_special_characters_survives_the_split():
    url, opts = split_asyncpg_options(
        "postgresql+asyncpg://u:p%40ss%3Aw%2Fd@h:5432/db?ssl=require&statement_cache_size=0"
    )
    assert make_url(url).password == "p@ss:w/d" and opts == {"statement_cache_size": 0}


@pytest.mark.unit
def test_unrelated_options_keep_their_order_and_values():
    url, _ = split_asyncpg_options(
        f"{BASE}?ssl=require&statement_cache_size=0&application_name=x"
    )
    assert make_url(url).query == {"ssl": "require", "application_name": "x"}


# ------------------------------------------------------------------ build_async_engine
@pytest.mark.unit
def test_engine_keeps_hide_parameters_and_the_option_is_not_left_in_the_url():
    eng = build_async_engine(f"{BASE}?ssl=require&statement_cache_size=0", echo=False)
    assert eng.sync_engine.hide_parameters is True
    assert eng.url.query == {"ssl": "require"}  # no connection is opened here


@pytest.mark.unit
def test_engine_without_options_is_created_as_before():
    eng = build_async_engine(f"{BASE}?ssl=require")
    assert eng.sync_engine.hide_parameters is True and eng.url.query == {
        "ssl": "require"
    }


@pytest.mark.unit
def test_the_applications_own_engine_never_carries_the_option_in_its_url():
    from app.database import engine

    assert "statement_cache_size" not in engine.url.query


@pytest.mark.unit
def test_explicit_connect_args_are_merged_not_replaced(monkeypatch):
    import app.database as database

    captured = {}
    real = database.create_async_engine

    def spy(url, **kw):
        captured.update(kw)
        return real(url, **kw)

    monkeypatch.setattr(database, "create_async_engine", spy)
    database.build_async_engine(
        f"{BASE}?statement_cache_size=0",
        connect_args={"server_settings": {"application_name": "t"}},
    )
    assert captured["connect_args"] == {
        "server_settings": {"application_name": "t"},
        "statement_cache_size": 0,
    }
    assert captured["hide_parameters"] is True
