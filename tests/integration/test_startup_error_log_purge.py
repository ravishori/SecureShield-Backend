"""Startup purge of ``error_logs`` (FG-034): it was untested, and a zero/negative LOG_RETENTION_DAYS deleted every row."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app import main
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
    monkeypatch.setattr(main.settings, "LOG_RETENTION_DAYS", 90)

    await main._cleanup_old_error_logs()

    db.expire_all()
    assert await _count(db) == 3


async def test_larger_retention_preserves_older_rows(db, monkeypatch):
    await _seed(db, [1, 91, 137, 400])
    monkeypatch.setattr(main.settings, "LOG_RETENTION_DAYS", 365)

    await main._cleanup_old_error_logs()

    db.expire_all()
    assert await _count(db) == 3  # only the 400-day-old row goes


@pytest.mark.parametrize("bad", [0, -1, -90])
async def test_non_positive_retention_never_deletes_anything(db, monkeypatch, bad):
    await _seed(db, [0, 1, 400])
    monkeypatch.setattr(main.settings, "LOG_RETENTION_DAYS", bad)

    await main._cleanup_old_error_logs()

    db.expire_all()
    assert await _count(db) == 3
