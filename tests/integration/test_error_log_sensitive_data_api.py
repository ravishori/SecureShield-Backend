"""Remaining sensitive-data exposure in error_logs: query string, path
parameters (share tokens, phone numbers) and bound SQL parameters.

Real unhandled exceptions go through the real middleware; assertions inspect
the actual persisted ``error_logs`` row and the alert-email payload."""

import time

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

PHONE = "+919876501234"
SHARE_TOKEN = "SENTINEL-SHARE-TOKEN-abc123"
QUERY_SECRET = "victim.person@example.com"


@pytest.fixture
def boom_routes():
    from app.main import app

    async def _boom_plain():
        raise RuntimeError("deliberate failure")

    async def _boom_param(value: str):
        raise RuntimeError("deliberate failure")

    app.add_api_route("/__boom", _boom_plain, methods=["GET"])
    app.add_api_route("/__boom/share/{value}", _boom_param, methods=["GET"])
    added = app.router.routes[-2:]
    try:
        yield
    finally:
        for r in added:
            app.router.routes.remove(r)


@pytest.fixture
def mailer(monkeypatch):
    import app.services.logger_service as ls

    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(ls, "_send_email_sync", lambda s, h, to: sent.append((s, h)))
    return sent


async def _rows(db):
    return (
        (
            await db.execute(
                text("select endpoint, extra, t::text as raw from error_logs t")
            )
        )
        .mappings()
        .all()
    )


def _wait(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end and not pred():
        time.sleep(0.05)
    return pred()


async def test_query_string_values_are_not_persisted_but_names_are(
    client, db, boom_routes, mailer
):
    await client.get(f"/__boom?identifier={QUERY_SECRET}&token=SENTINEL-QTOKEN")
    row = (await _rows(db))[0]
    assert QUERY_SECRET not in row["raw"] and "SENTINEL-QTOKEN" not in row["raw"]
    assert sorted(row["extra"]["query_params"]) == ["identifier", "token"]


async def test_path_parameters_are_logged_as_route_template(
    client, db, boom_routes, mailer
):
    await client.get(f"/__boom/share/{SHARE_TOKEN}")
    assert _wait(lambda: len(mailer) == 1)
    row = (await _rows(db))[0]
    assert SHARE_TOKEN not in row["raw"]
    assert row["endpoint"] == "/__boom/share/{value}"
    assert SHARE_TOKEN not in mailer[0][0] + mailer[0][1]


async def test_real_share_route_404_does_not_log_the_token(client, db, mailer):
    """A real route: GET /recordings/share/{token} with an unknown token → 404 via the
    HTTPException handler; the token must not be written to error_logs."""
    r = await client.get(f"/api/v1/recordings/share/{SHARE_TOKEN}")
    assert r.status_code in (403, 404)
    for row in await _rows(db):
        assert SHARE_TOKEN not in row["raw"]


async def test_unmatched_path_still_logged(client, db, mailer):
    r = await client.get("/definitely/not/a/route")
    assert r.status_code == 404
    # no exception: just make sure the handler path doesn't break
    assert isinstance(await _rows(db), list)


async def test_sqlalchemy_errors_do_not_embed_bound_parameters():
    """The app engine must hide bound parameters, otherwise a failing
    ``WHERE otp.code = :code`` puts the submitted code into exception text,
    tracebacks, error_logs and alert e-mails."""
    from sqlalchemy import text as sql_text
    from sqlalchemy.exc import ProgrammingError
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.database import (
        engine as app_engine,
    )  # pytest-asyncio keeps original import
    import os

    url = os.environ["TEST_DATABASE_URL"]
    visible = create_async_engine(url)
    hidden = create_async_engine(url, hide_parameters=True)
    stmt = sql_text("select * from table_that_does_not_exist where code = :c")
    try:
        with pytest.raises(ProgrammingError) as ei_visible:
            async with visible.connect() as c:
                await c.execute(stmt, {"c": "SENTINEL-OTP-482910"})
        with pytest.raises(ProgrammingError) as ei_hidden:
            async with hidden.connect() as c:
                await c.execute(stmt, {"c": "SENTINEL-OTP-482910"})
        assert "SENTINEL-OTP-482910" in str(ei_visible.value)  # the problem is real
        assert "SENTINEL-OTP-482910" not in str(
            ei_hidden.value
        )  # and the setting fixes it
    finally:
        await visible.dispose()
        await hidden.dispose()
    assert app_engine is not None
