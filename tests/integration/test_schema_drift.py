"""The migrated database must match the ORM models.

Regression: model enums had grown (AlertType gained 7 members) without a migration, so inserting
those alert types failed with 'invalid input value for enum' (HTTP 500) in any migrated database.
These checks run against the Alembic-migrated test database, so they catch the next such drift.
"""

import pytest
from sqlalchemy import Enum as SAEnum
from sqlalchemy import text

pytestmark = pytest.mark.integration


def _model_enums():
    import app.models  # noqa: F401  (register every model)
    from app.database import Base

    found = {}
    for table in Base.metadata.tables.values():
        for col in table.columns:
            if isinstance(col.type, SAEnum) and col.type.name:
                found.setdefault(col.type.name, set()).update(col.type.enums)
    return found


async def test_every_orm_enum_value_exists_in_the_database(db):
    rows = (
        await db.execute(
            text(
                "SELECT t.typname, e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid"
            )
        )
    ).all()
    in_db = {}
    for typname, label in rows:
        in_db.setdefault(typname, set()).add(label)
    missing = {
        name: sorted(values - in_db.get(name, set()))
        for name, values in _model_enums().items()
        if values - in_db.get(name, set())
    }
    assert not missing, f"enum values in models but not in the migrated DB: {missing}"


async def test_every_orm_table_and_column_exists_in_the_database(db):
    import app.models  # noqa: F401
    from app.database import Base

    cols = (
        await db.execute(
            text(
                "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public'"
            )
        )
    ).all()
    have = {}
    for t, c in cols:
        have.setdefault(t, set()).add(c)
    problems = []
    for name, table in Base.metadata.tables.items():
        if name not in have:
            problems.append(f"table {name} missing")
            continue
        for col in table.columns:
            if col.name not in have[name]:
                problems.append(f"{name}.{col.name} missing")
    assert not problems, problems
