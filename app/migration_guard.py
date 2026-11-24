"""Idempotent schema operations for Alembic migrations.

Every node builds its schema TWICE: ``db.create_all()`` + ``_ensure_columns()``
at boot, and Alembic when an update runs ``flask db upgrade``. The installer
creates the database with ``flask create-db`` (``create_all``), so on a node
that was installed rather than grown from a git checkout every table already
exists when Alembic first runs -- and there is no ``alembic_version`` row
telling it so. A migration that calls ``op.create_table`` unconditionally
therefore dies on the very first revision, and every later revision (including
any that transforms data) never runs.

These wrappers make each operation a no-op when its target already exists, so
``upgrade`` walks the whole chain on such a node, does only what is genuinely
missing, and ends at head with the version recorded. They check NAMES and, for
indexes and foreign keys, the column shape too: ``create_all`` names some
indexes and constraints differently from the migration that introduced them,
and a second index on the same columns is waste, not schema.

Use them in ``upgrade()`` only. ``downgrade()`` keeps plain ``op`` calls: a
downgrade that silently skips a drop leaves a schema the older code does not
expect, which is worse than failing.

``tests/test_migrations_idempotent.py`` runs the full chain against a database
built by ``create_all`` -- a new migration that is not idempotent fails there.
"""
from __future__ import annotations

from contextlib import contextmanager

import sqlalchemy as sa
from alembic import op


def _inspector():
    # A fresh inspector per call: Inspector caches reflection, and the whole
    # point is to see what earlier operations in the same migration created.
    return sa.inspect(op.get_bind())


def has_table(name: str) -> bool:
    return name in _inspector().get_table_names()


def has_column(table: str, column: str) -> bool:
    if not has_table(table):
        return False
    return column in {c["name"] for c in _inspector().get_columns(table)}


def _index_shapes(table: str) -> list:
    insp = _inspector()
    shapes = [(ix["name"], tuple(ix.get("column_names") or ()), bool(ix.get("unique")))
              for ix in insp.get_indexes(table)]
    # A unique index declared in a model can come back as a unique CONSTRAINT.
    shapes += [(uc["name"], tuple(uc.get("column_names") or ()), True)
               for uc in insp.get_unique_constraints(table)]
    return shapes


def has_index(table: str, name: str, columns=None, unique=None) -> bool:
    if not has_table(table):
        return False
    for ix_name, ix_cols, ix_unique in _index_shapes(table):
        if ix_name == name:
            return True
        if columns is not None and ix_cols == tuple(columns) and (
                unique is None or ix_unique == bool(unique)):
            return True
    return False


def create_table(name: str, *columns, **kw) -> bool:
    if has_table(name):
        return False
    op.create_table(name, *columns, **kw)
    return True


def add_column(table: str, column: sa.Column, **kw) -> bool:
    if has_column(table, column.name):
        return False
    op.add_column(table, column, **kw)
    return True


def create_index(name, table: str, columns, **kw) -> bool:
    name = str(name)
    if has_index(table, name, columns, kw.get("unique")):
        return False
    op.create_index(name, table, columns, **kw)
    return True


def create_foreign_key(name, source: str, referent: str, local_cols,
                       remote_cols, **kw) -> bool:
    for fk in _inspector().get_foreign_keys(source):
        if fk.get("name") == name or (
                fk.get("referred_table") == referent
                and list(fk.get("constrained_columns") or ()) == list(local_cols)):
            return False
    if op.get_bind().dialect.name == "sqlite":
        # SQLite cannot ALTER a constraint in; create_all already declared it
        # with the column, and batch mode would rebuild the whole table.
        return False
    op.create_foreign_key(name, source, referent, local_cols, remote_cols, **kw)
    return True


class _BatchIndexes:
    """Stands in for ``batch_op`` where autogenerate only created indexes."""

    def __init__(self, table: str):
        self.table = table

    @staticmethod
    def f(name):
        return op.f(name)

    def create_index(self, name, columns, **kw) -> bool:
        return create_index(name, self.table, columns, **kw)


@contextmanager
def batch_alter_table(table: str, **_ignored):
    yield _BatchIndexes(table)
