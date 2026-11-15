"""Stage 1.5B: model metadata contract + static checks of the additive migration y0z1a2b3c4d5. No database."""

import ast
import re
from pathlib import Path

import pytest
from sqlalchemy.dialects import postgresql

import app.models  # noqa: F401  (registers every model on Base.metadata)
from app.database import Base

pytestmark = pytest.mark.unit

BACKEND = Path(__file__).resolve().parents[2]
MIGRATION = (
    BACKEND
    / "alembic"
    / "versions"
    / "y0z1a2b3c4d5_sms_header_upper_index_and_audit_comment.py"
)


def table(name):
    return Base.metadata.tables[name]


def idx(tname, iname):
    found = [i for i in table(tname).indexes if i.name == iname]
    assert len(found) == 1, f"{tname}.{iname}: {len(found)}"
    return found[0]


def idx_text(i):
    return [str(e.compile(dialect=postgresql.dialect())) for e in i.expressions]


def idx_names(tname):
    return {i.name for i in table(tname).indexes}


# ---- critical protections --------------------------------------------------------------------------------------------------------
def test_partial_unique_index_is_declared():
    i = idx("warrior_applications", "uq_warrior_app_user_pending")
    assert i.unique is True
    assert [c.name for c in i.columns] == ["user_id"]
    assert str(i.dialect_options["postgresql"]["where"]) == "status = 'pending'"


def test_sms_header_index_is_an_upper_expression():
    i = idx("sms_sender_registry", "ix_sms_sender_header_upper")
    assert i.unique is False
    assert idx_text(i) == ["upper(header)"]
    assert "ix_sms_sender_registry_header" in idx_names(
        "sms_sender_registry"
    )  # the existing plain index is untouched


def test_sms_index_compares_equal_to_reflected_postgres_form_and_differs_from_old_text():
    import sqlalchemy as sa
    from alembic.ddl.postgresql import PostgresqlImpl

    impl = PostgresqlImpl(postgresql.dialect(), None, True, False, None, {})
    model = idx("sms_sender_registry", "ix_sms_sender_header_upper")
    t = table("sms_sender_registry")

    def reflected(txt):
        return sa.Index(
            "ix_sms_sender_header_upper",
            sa.text(txt),
            _table=sa.Table("r", sa.MetaData(), *[c.copy() for c in t.columns]),
        )

    # SQLAlchemy reflects PostgreSQL's stored `upper((header)::text)` as `upper(header::text)` (observed by alembic check, 1.5E)
    assert not impl.compare_indexes(
        model, reflected("upper(header::text)")
    ).is_different
    assert not impl.compare_indexes(model, reflected("upper(header)")).is_different
    assert impl.compare_indexes(
        model, reflected("upper((header)::text)")
    ).is_different  # raw catalog text is NOT what is compared


def test_migration_still_issues_plain_upper_header():
    src = MIGRATION.read_text(encoding="utf-8")
    assert '[sa.text("upper(header)")]' in src and "::text" not in src


def test_sms_index_matches_validator_lookup_expression():
    from app.models.sms_sender_registry import SmsSenderRegistry
    from sqlalchemy import func, select

    q = str(
        select(SmsSenderRegistry)
        .where(func.upper(SmsSenderRegistry.header) == "X")
        .compile(dialect=postgresql.dialect())
    )
    assert "upper(sms_sender_registry.header)" in q


# ---- remaining alignment ---------------------------------------------------------------------------------------------------------
def test_audit_log_indexes_comment_and_fks():
    t = table("warrior_audit_logs")
    assert t.comment == "Append-only. Do not UPDATE or DELETE rows here."
    assert idx_names("warrior_audit_logs") == {
        "ix_warrior_audit_actor",
        "ix_warrior_audit_subject",
    }
    assert idx_text(idx("warrior_audit_logs", "ix_warrior_audit_actor")) == [
        "warrior_audit_logs.actor_user_id",
        "created_at DESC",
    ]
    assert idx_text(idx("warrior_audit_logs", "ix_warrior_audit_subject")) == [
        "warrior_audit_logs.subject_user_id",
        "created_at DESC",
    ]
    for fk in t.foreign_keys:
        assert fk.ondelete is None  # audit rows must never cascade away


@pytest.mark.parametrize(
    "tname", ["behavior_events", "community_scam_reports", "emergency_contacts"]
)
def test_user_fk_cascades(tname):
    fks = [fk for fk in table(tname).foreign_keys if fk.column.table.name == "users"]
    assert fks and all(fk.ondelete == "CASCADE" for fk in fks)


@pytest.mark.parametrize(
    "tname,iname,expr",
    [
        ("behavior_events", "ix_behavior_events_occurred_at", ["occurred_at DESC"]),
        ("clone_reports", "ix_clone_reports_created_at", ["created_at DESC"]),
        ("community_scam_reports", "ix_community_scam_created_at", ["created_at DESC"]),
        ("app_install_events", "ix_app_install_events_created_at", ["created_at DESC"]),
    ],
)
def test_desc_indexes(tname, iname, expr):
    assert idx_text(idx(tname, iname)) == expr


def test_community_scam_index_names():
    assert {
        "ix_community_scam_user_id",
        "ix_community_scam_city",
        "ix_community_scam_pincode",
        "ix_community_scam_created_at",
    } <= idx_names("community_scam_reports")


def test_app_install_events_extra_indexes_declared():
    assert {
        "ix_app_install_events_risk_level",
        "ix_app_install_events_flagged_as_clone",
    } <= idx_names("app_install_events")


def test_elderly_configs_unique_plus_plain_index():
    t = table("elderly_configs")
    assert "ix_elderly_configs_user_id" in idx_names("elderly_configs")
    assert t.c.user_id.unique is True


def test_warrior_profiles_unique_constraint_not_index():
    t = table("warrior_profiles")
    assert t.c.user_id.unique is True
    assert not [i for i in t.indexes if [c.name for c in i.columns] == ["user_id"]]


def test_otp_vault_entries_has_no_model():
    assert "otp_vault_entries" not in Base.metadata.tables


# ---- static checks of the migration ----------------------------------------------------------------------------------------------
def _calls(fn_name):
    tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    fn = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == fn_name
    )
    return [
        n.func.attr
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]


def test_migration_chain_and_single_head():
    src = MIGRATION.read_text(encoding="utf-8")
    assert 'revision: str = "y0z1a2b3c4d5"' in src
    assert 'down_revision: Union[str, None] = "x9y0z1a2b3c4"' in src
    revs = {}
    for p in (BACKEND / "alembic" / "versions").glob("*.py"):
        s = p.read_text(encoding="utf-8")
        r = re.search(r'^revision(?:: str)? = "([^"]+)"', s, re.M)
        d = re.search(r'^down_revision(?:: [^=]+)? = (?:"([^"]+)"|None)', s, re.M)
        if r:
            revs[r.group(1)] = d.group(1) if d else None
    heads = set(revs) - {d for d in revs.values() if d}
    assert heads == {"y0z1a2b3c4d5"}


def test_migration_operations_are_exactly_the_approved_ones():
    assert sorted(_calls("upgrade")) == ["create_index", "create_table_comment", "text"]
    assert sorted(_calls("downgrade")) == ["drop_index", "drop_table_comment"]


def test_migration_is_additive_and_touches_no_protected_object():
    src = MIGRATION.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in src.splitlines() if not line.lstrip().startswith("#")
    )
    body = code.split("def upgrade", 1)[1]
    for forbidden in (
        "drop_table(",
        "drop_column",
        "execute(",
        "DELETE",
        "TRUNCATE",
        "UPDATE ",
        "otp_vault_entries",
        "uq_warrior_app_user_pending",
    ):
        assert forbidden not in body, forbidden


def test_account_erasure_still_uses_otp_vault_entries():
    assert "otp_vault_entries" in (
        BACKEND / "app" / "services" / "account_erasure.py"
    ).read_text(encoding="utf-8")
