"""``error_logs`` retention (FG-034), now an explicit maintenance operation: a zero/negative LOG_RETENTION_DAYS deleted every row,
and application startup must never delete anything."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app import config, main
from app.services.error_log_retention import purge_old_error_logs
from app.models.error_log import ErrorLog

pytestmark = pytest.mark.integration


async def _seed(db, ages_days):
    now = datetime.utcnow()
    for i, age in enumerate(ages_days):
        db.add(
            ErrorLog(
                level="ERROR",
                message=f"row {i}",
                created_at=now - timedelta(days=age),
            )
        )
    await db.commit()


async def _count(db) -> int:
    return (await db.execute(select(func.count()).select_from(ErrorLog))).scalar_one()


async def test_purge_deletes_only_rows_older_than_retention(db, monkeypatch):
    await _seed(db, [1, 30, 89, 91, 400])
    monkeypatch.setattr(config.settings, "LOG_RETENTION_DAYS", 90)

    await purge_old_error_logs()

    db.expire_all()
    assert await _count(db) == 3


async def test_larger_retention_preserves_older_rows(db, monkeypatch):
    await _seed(db, [1, 91, 137, 400])
    monkeypatch.setattr(config.settings, "LOG_RETENTION_DAYS", 365)

    await purge_old_error_logs()

    db.expire_all()
    assert await _count(db) == 3  # only the 400-day-old row goes


@pytest.mark.parametrize("bad", [0, -1, -90])
async def test_non_positive_retention_never_deletes_anything(db, monkeypatch, bad):
    await _seed(db, [0, 1, 400])
    monkeypatch.setattr(config.settings, "LOG_RETENTION_DAYS", bad)

    await purge_old_error_logs()

    db.expire_all()
    assert await _count(db) == 3


@pytest.fixture(autouse=True)
def _retention_enabled(monkeypatch):
    """Stage 1.1: retention deletes only when RETENTION_CLEANUP_ENABLED=true (and the identity is valid). These tests exercise
    the delete behaviour itself, so they enable it explicitly; the blocked paths are covered in tests/unit/test_retention_gate.py."""
    from app import config

    monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", "true")


async def test_application_startup_deletes_nothing_even_when_retention_is_enabled(
    db, monkeypatch
):
    await _seed(db, [1, 400, 900])
    monkeypatch.setattr(config.settings, "LOG_RETENTION_DAYS", 90)
    monkeypatch.setattr(main, "run_startup_checks", lambda s: None)
    monkeypatch.setattr(main, "_start_guardian_worker", lambda: None)

    async def no_check():
        return None

    monkeypatch.setattr(
        main, "_verify_database_identity", no_check
    )  # the global engine is bound to another loop here

    await main.on_startup()

    db.expire_all()
    assert await _count(db) == 3


async def test_purge_is_blocked_without_the_flag(db, monkeypatch):
    await _seed(db, [400])
    monkeypatch.setattr(config.settings, "RETENTION_CLEANUP_ENABLED", None)
    monkeypatch.setattr(config.settings, "LOG_RETENTION_DAYS", 90)

    result = await purge_old_error_logs()

    db.expire_all()
    assert result.error == "blocked" and await _count(db) == 1
