"""The schema ceiling that made the fourth ADOM unwritable.

``fortiauthenticator`` is 18 characters.  Every product-scoping column had been
``varchar(16)`` because the longest key had been ``fortianalyzer`` (13).  The
models were widened to 32, but two paths could still hand an installation a
narrow column:

* ``_ensure_columns()`` emitted ``VARCHAR(16)`` DDL of its own — the model
  declaration is not what runs there.
* ``create_all()`` never ALTERs, so an installation that predates the widening
  keeps ``varchar(16)`` forever and fails on the first row written for the new
  ADOM — late, in an audit row or an alert, long after onboarding "worked".

``tests/test_fac.py`` already guards the *model* declarations.  These guard the
two runtime paths it cannot see.
"""
import ast
import os
import re

import pytest
from sqlalchemy import Column, MetaData, Table, String, Integer

from app import widen_plan

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INIT = os.path.join(REPO, "app", "__init__.py")


def _longest_adom_key():
    from app.branding import _FALLBACK
    return max(len(p["key"]) for p in _FALLBACK)


# --------------------------------------------------------------------------- #
#  1. the DDL emitters, which the model-level guard cannot see                 #
# --------------------------------------------------------------------------- #

def test_no_ddl_emitter_creates_a_product_column_too_narrow_for_an_adom_key():
    """_ensure_columns writes its own DDL strings; the model width is not used."""
    longest = _longest_adom_key()
    src = open(INIT).read()
    found = re.findall(r"\('product',\s*\"VARCHAR\((\d+)\)", src)
    assert found, "no product DDL emitters found - the guard would pass vacuously"
    for width in found:
        assert int(width) >= longest, (
            f"app/__init__.py emits product VARCHAR({width}); the longest ADOM "
            f"key is {longest} chars and would be truncated")


def test_the_emitter_guard_would_catch_a_narrow_declaration():
    """Anti-vacuity: the regex must actually match the shape it polices."""
    sample = """                ('product', "VARCHAR(16) DEFAULT 'fortiweb'"),"""
    assert re.findall(r"\('product',\s*\"VARCHAR\((\d+)\)", sample) == ["16"]


# --------------------------------------------------------------------------- #
#  2. the widening migration                                                   #
# --------------------------------------------------------------------------- #

def _md(*cols):
    md = MetaData()
    Table("t", md, *cols)
    return md


def test_a_column_narrower_than_the_model_is_widened():
    md = _md(Column("product", String(32)))
    assert widen_plan(md.sorted_tables, {"t": {"product": 16}}) == [
        ("t", "product", 32)]


def test_a_column_already_wide_enough_is_left_alone():
    md = _md(Column("product", String(32)))
    assert widen_plan(md.sorted_tables, {"t": {"product": 32}}) == []


def test_a_column_wider_than_the_model_is_never_narrowed():
    """Narrowing can truncate committed rows; a too-wide column is harmless."""
    md = _md(Column("product", String(32)))
    assert widen_plan(md.sorted_tables, {"t": {"product": 64}}) == []


def test_a_table_the_database_does_not_have_is_skipped():
    """create_all() owns table creation; emitting ALTER here would just error.

    Honest note: this is defence in depth, not the only thing standing between
    us and bad DDL.  Removing the ``live is None`` early-exit does not change
    the outcome - an absent table yields an empty width map, every column then
    reports ``have is None``, and the next guard skips it anyway.  Mutating the
    early-exit away leaves the suite green, and that is reported rather than
    papered over with a test that only appears to catch it.
    """
    md = _md(Column("product", String(32)))
    assert widen_plan(md.sorted_tables, {}) == []


def test_a_column_the_database_does_not_have_is_left_to_the_additive_pass():
    md = _md(Column("product", String(32)))
    assert widen_plan(md.sorted_tables, {"t": {"other": 8}}) == []


def test_unbounded_and_non_string_columns_are_ignored():
    md = _md(Column("body", String()), Column("n", Integer()))
    assert widen_plan(md.sorted_tables, {"t": {"body": 8, "n": None}}) == []


def test_every_narrow_column_is_reported_not_just_the_first():
    md = MetaData()
    Table("a", md, Column("product", String(32)))
    Table("b", md, Column("kind", String(32)))
    plan = widen_plan(md.sorted_tables, {"a": {"product": 16},
                                         "b": {"kind": 16}})
    assert sorted(plan) == [("a", "product", 32), ("b", "kind", 32)]


# --------------------------------------------------------------------------- #
#  3. the migration has to actually run                                        #
# --------------------------------------------------------------------------- #

def test_ensure_widths_runs_at_boot():
    """A migration that is defined but never called is not a migration."""
    tree = ast.parse(open(INIT).read())
    called = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "_ensure_widths" in called, (
        "_ensure_widths is defined but never called - existing installations "
        "would keep their narrow columns")


def test_ensure_widths_runs_after_the_additive_pass():
    """A column added narrow in the same boot must still get widened."""
    src = open(INIT).read()
    assert src.index("_ensure_widths()\n") > src.index("_ensure_columns()\n")


def test_sqlite_is_skipped():
    """SQLite does not enforce VARCHAR length and has no ALTER COLUMN TYPE."""
    src = open(INIT).read()
    i = src.index("def _ensure_widths(")
    body = src[i:src.index("\n    def ", i + 10)]
    body = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
    assert "sqlite" in body, "_ensure_widths must not emit ALTER on SQLite"


def test_widen_plan_is_importable_without_an_app_context():
    """It is pure; needing a context would make it untestable with data."""
    md = _md(Column("product", String(32)))
    assert widen_plan(md.sorted_tables, {"t": {"product": 16}})
