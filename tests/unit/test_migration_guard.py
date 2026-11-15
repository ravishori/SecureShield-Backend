"""Alembic autogenerate protection (Stage 1.5B): ``app/migration_guard.include_object``.

No PostgreSQL is involved. The hook is called directly, and also driven through Alembic's real ``compare_metadata`` against an
in-memory SQLite database (a sync engine in the test process, no server, no network) that holds stand-ins for the protected
objects, so the test shows what Alembic would actually propose with and without the guard.
"""

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from app.migration_guard import (
    PROTECTED_INDEXES,
    PROTECTED_LEGACY_TABLES,
    include_object,
)

pytestmark = pytest.mark.unit

BACKEND = Path(__file__).resolve().parents[2]


def obj(table=None):
    return SimpleNamespace(table=SimpleNamespace(name=table) if table else None)


# ---- the hook itself ----------------------------------------------------------------------------------------------------------------
def test_protected_database_only_table_is_excluded():
    assert include_object(obj(), "otp_vault_entries", "table", True, None) is False


def test_indexes_of_the_protected_table_are_excluded():
    assert (
        include_object(
            obj("otp_vault_entries"),
            "ix_otp_vault_entries_user_id",
            "index",
            True,
            None,
        )
        is False
    )
    assert (
        include_object(
            obj("otp_vault_entries"), "otp_vault_entries_pkey", "index", True, None
        )
        is False
    )


def test_protected_partial_unique_index_is_excluded_when_database_only():
    assert (
        include_object(
            obj("warrior_applications"),
            "uq_warrior_app_user_pending",
            "index",
            True,
            None,
        )
        is False
    )


@pytest.mark.parametrize(
    "name,type_,table",
    [
        ("legacy_table", "table", None),
        (
            "otp_vault_entries_backup",
            "table",
            None,
        ),  # a lookalike name is not protected
        ("users", "table", None),
        ("ix_orphan", "index", "users"),
        ("uq_warrior_app_user_pending_v2", "index", "warrior_applications"),
        ("ix_warrior_applications_user_id", "index", "warrior_applications"),
        (
            "otp_vault_entries",
            "index",
            "other_table",
        ),  # protection is by table for indexes, and by exact index name
        (
            "user_id",
            "column",
            "otp_vault_entries",
        ),  # columns, constraints, FKs are never filtered here
        ("fk_x", "foreign_key_constraint", "otp_vault_entries"),
        ("uq_x", "unique_constraint", "warrior_applications"),
    ],
)
def test_unrelated_database_only_objects_keep_normal_comparison(name, type_, table):
    assert include_object(obj(table), name, type_, True, None) is True


def test_model_side_objects_are_never_filtered():
    assert (
        include_object(obj(), "otp_vault_entries", "table", False, None) is True
    )  # a model table with that name: compare it
    assert (
        include_object(
            obj("warrior_applications"),
            "uq_warrior_app_user_pending",
            "index",
            False,
            None,
        )
        is True
    )


def test_objects_that_have_a_model_counterpart_are_compared_normally():
    counterpart = object()
    assert (
        include_object(obj(), "otp_vault_entries", "table", True, counterpart) is True
    )
    assert (
        include_object(
            obj("warrior_applications"),
            "uq_warrior_app_user_pending",
            "index",
            True,
            counterpart,
        )
        is True
    )


def test_the_protected_sets_are_exactly_the_two_approved_objects():
    assert PROTECTED_LEGACY_TABLES == {"otp_vault_entries"}
    assert PROTECTED_INDEXES == {"uq_warrior_app_user_pending"}


# ---- through Alembic's real comparison ---------------------------------------------------------------------------------------------
@pytest.fixture
def sqlite_connection():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        for stmt in (
            "CREATE TABLE users (id INTEGER PRIMARY KEY)",
            "CREATE TABLE otp_vault_entries (id INTEGER PRIMARY KEY, user_id INTEGER)",
            "CREATE INDEX ix_otp_vault_entries_user_id ON otp_vault_entries (user_id)",
            "CREATE TABLE warrior_applications (id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT)",
            "CREATE UNIQUE INDEX uq_warrior_app_user_pending ON warrior_applications (user_id) WHERE status = 'pending'",
            "CREATE INDEX ix_unrelated_extra ON warrior_applications (status)",
            "CREATE TABLE legacy_unprotected (id INTEGER PRIMARY KEY)",
        ):
            conn.exec_driver_sql(stmt)
        yield conn
    engine.dispose()


def _metadata(declare_partial_index=False, partial_unique=True):
    md = sa.MetaData()
    sa.Table("users", md, sa.Column("id", sa.Integer, primary_key=True))
    apps = sa.Table(
        "warrior_applications",
        md,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer),
        sa.Column("status", sa.Text),
    )
    if declare_partial_index:
        sa.Index(
            "uq_warrior_app_user_pending",
            apps.c.user_id,
            unique=partial_unique,
            sqlite_where=sa.text("status = 'pending'"),
        )
    return md


def _proposed(conn, md, guard):
    opts = {"include_object": include_object} if guard else {}
    flat = []

    def walk(x):
        if isinstance(x, list):
            for item in x:
                walk(item)
        else:
            flat.append(x)

    walk(compare_metadata(MigrationContext.configure(conn, opts=opts), md))
    out = set()
    for op in flat:
        kind, target = op[0], op[1]
        out.add((kind, getattr(target, "name", None)))
    return out


def test_without_the_guard_alembic_proposes_to_drop_both_protected_objects(
    sqlite_connection,
):
    proposed = _proposed(sqlite_connection, _metadata(), guard=False)
    assert ("remove_table", "otp_vault_entries") in proposed
    assert ("remove_index", "uq_warrior_app_user_pending") in proposed


def test_with_the_guard_alembic_no_longer_proposes_dropping_them(sqlite_connection):
    proposed = _proposed(sqlite_connection, _metadata(), guard=True)
    assert ("remove_table", "otp_vault_entries") not in proposed
    assert ("remove_index", "uq_warrior_app_user_pending") not in proposed
    assert ("remove_index", "ix_otp_vault_entries_user_id") not in proposed


def test_with_the_guard_unrelated_differences_are_still_reported(sqlite_connection):
    proposed = _proposed(sqlite_connection, _metadata(), guard=True)
    assert (
        "remove_table",
        "legacy_unprotected",
    ) in proposed  # an unprotected database-only table
    assert (
        "remove_index",
        "ix_unrelated_extra",
    ) in proposed  # an unprotected database-only index


def test_a_declared_partial_index_is_compared_normally_not_hidden(sqlite_connection):
    assert not {
        p
        for p in _proposed(
            sqlite_connection, _metadata(declare_partial_index=True), guard=True
        )
        if p[1] == "uq_warrior_app_user_pending"
    }
    # if the model declared it as a NON-unique index, Alembic must still notice (the guard must not mask a real change)
    changed = _proposed(
        sqlite_connection,
        _metadata(declare_partial_index=True, partial_unique=False),
        guard=True,
    )
    assert any(p[1] == "uq_warrior_app_user_pending" for p in changed)


# ---- wiring in alembic/env.py ---------------------------------------------------------------------------------------------------------
def test_env_py_passes_the_guard_to_both_configure_calls():
    source = (BACKEND / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "from app.migration_guard import include_object" in source
    calls = re.findall(r"context\.configure\((.*?)\n\s*\)", source, flags=re.S)
    assert len(calls) == 2, "online and offline configure calls"
    assert all("include_object=include_object" in c for c in calls)
    assert (
        "compare_type" not in source and "compare_server_default" not in source
    )  # behaviour of everything else is unchanged
