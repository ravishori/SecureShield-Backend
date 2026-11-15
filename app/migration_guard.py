"""Alembic autogenerate protection (Stage 1.5B). Imported by ``alembic/env.py`` and unit-tested without any database.

Two existing database objects must never be proposed for removal by ``alembic check`` / ``alembic revision --autogenerate``:

* the legacy table ``otp_vault_entries`` (and its indexes): it has no ORM model any more, but account erasure still deletes
  from it (``app/services/account_erasure.py``) and its foreign key to ``users`` requires that delete;
* the partial unique index ``uq_warrior_app_user_pending`` (``warrior_applications (user_id) WHERE status = 'pending'``): the only
  race-safe guarantee of "one pending application per user". It is now declared in the model as well; the guard is a second line
  of defence in case the declaration is ever lost.

The guard is deliberately narrow. Alembic calls ``include_object`` when it is about to emit an operation; a *removal* is always
reported as ``reflected=True`` with ``compare_to=None`` (an object that exists only in the database). Only that case is filtered,
and only for the names above. Everything else (additions, modifications, other tables, other indexes, columns, constraints) keeps
its normal comparison, and if a model for ``otp_vault_entries`` or the partial index is declared later, the two are compared
normally (``compare_to`` is then not ``None`` or the object is not a database-only one).
"""

from __future__ import annotations

PROTECTED_LEGACY_TABLES = frozenset({"otp_vault_entries"})
PROTECTED_INDEXES = frozenset({"uq_warrior_app_user_pending"})


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Return False only for a database-only object that is protected; True for everything else."""
    if not reflected or compare_to is not None:
        return True
    if type_ == "table":
        return name not in PROTECTED_LEGACY_TABLES
    if type_ == "index":
        if name in PROTECTED_INDEXES:
            return False
        table = getattr(obj, "table", None)
        if getattr(table, "name", None) in PROTECTED_LEGACY_TABLES:
            return False
    return True
