"""A REAL asyncpg connection through ``build_async_engine`` (moved out of the unit tests, Stage CI stabilisation).

This opens a real connection, so it is an integration test: unit tests never connect to a database (tests/unit/conftest.py). It runs
only when ``TEST_DATABASE_URL`` is set, and only after the harness safety check (loopback host, ``_test`` database name, not a
production endpoint) has accepted that URL. The query is read-only (``select 1``).
"""

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.database import build_async_engine
from tests.integration.conftest import _test_url, assert_safe_test_database

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        "",
        "?statement_cache_size=0",
        "?statement_cache_size=0&prepared_statement_cache_size=0",
    ],
)
async def test_real_connection_with_integer_options_in_the_url(extra):
    """With asyncpg itself: the options in the URL no longer raise TypeError and the cache really is disabled."""
    test_url = _test_url()
    assert test_url, (
        "the integration harness skips this test when TEST_DATABASE_URL is not set"
    )
    assert_safe_test_database(
        test_url
    )  # never connect to anything that is not clearly a disposable local test database
    url = make_url(test_url.replace("postgresql://", "postgresql+asyncpg://", 1))
    if "+asyncpg" not in str(url.drivername):
        url = url.set(drivername="postgresql+asyncpg")
    full = url.render_as_string(hide_password=False).split("?")[0] + extra
    eng = build_async_engine(full)
    try:
        async with eng.connect() as conn:
            await conn.execution_options(postgresql_readonly=True)
            assert (await conn.execute(text("select 1"))).scalar() == 1
            raw = await conn.get_raw_connection()
            asyncpg_conn = raw.driver_connection
            if "statement_cache_size=0" in extra:
                assert asyncpg_conn._stmt_cache.get_max_size() == 0
    finally:
        await eng.dispose()
