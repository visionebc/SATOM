"""The boot-time column migration must not lose a table to a duplicate key.

``app.create_app._ensure_columns`` holds one dict literal mapping table -> the
columns added after that table already existed. Write the same table name
twice and Python keeps the LAST entry: every column under the earlier copy is
never added, nothing raises, nothing is logged, and the feature that needs
those columns fails later with a database error that points nowhere near the
cause.

Caught for real on 2026-08-11. The wave columns (``wave_group``,
``wave_index``, ``wave_total``) were appended under a fresh ``'change_request'``
key while an existing one sat forty lines below. Boot was clean, the table was
created, ``/upgrade-flow/`` rendered — and the three columns simply did not
exist.

The guard has to read the SOURCE. By the time the dict is a value the duplicate
keys have already collapsed, so no runtime assertion can see them: this is the
same reason a test asserting on the merged dict would pass against the defect
it names.
"""
from __future__ import annotations

import ast
import pathlib


def _adds_literals() -> list[ast.Dict]:
    """Every dict literal assigned to a name ``adds`` in app/__init__.py."""
    source = (pathlib.Path(__file__).resolve().parents[1]
              / "app" / "__init__.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    out: list[ast.Dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "adds":
                out.append(node.value)
    return out


def test_the_migration_map_exists():
    """A guard that finds nothing to check passes for the wrong reason."""
    literals = _adds_literals()
    assert literals, ("no `adds = {...}` literal found in app/__init__.py — "
                      "the migration map moved and this guard went blind")


def test_no_table_appears_twice_in_the_column_migration():
    for literal in _adds_literals():
        names: list[str] = []
        for key in literal.keys:
            # Only plain string keys are checkable, and only plain string keys
            # have ever been used. A computed key would be a different problem
            # and is left to fail loudly rather than be silently skipped here.
            assert isinstance(key, ast.Constant) and isinstance(key.value, str), (
                "the column-migration map must be keyed by string literals")
            names.append(key.value)
        duplicates = sorted({n for n in names if names.count(n) > 1})
        assert not duplicates, (
            f"table(s) listed twice in _ensure_columns: {duplicates}. Python "
            f"keeps only the last entry, so every column under the earlier one "
            f"is silently never added. Merge them into a single key.")


def test_wave_columns_are_actually_registered():
    """The columns this defect ate, named explicitly.

    The duplicate-key guard above would have caught the mistake, but only while
    somebody remembers WHY it matters. This test states the outcome instead:
    the three wave columns must be in the map that runs at boot, whatever
    shape that map takes.
    """
    wanted = {"wave_group", "wave_index", "wave_total"}
    found: set[str] = set()
    for literal in _adds_literals():
        for key, value in zip(literal.keys, literal.values):
            if not (isinstance(key, ast.Constant) and key.value == "change_request"):
                continue
            for element in getattr(value, "elts", []):
                col = element.elts[0] if getattr(element, "elts", None) else None
                if isinstance(col, ast.Constant) and col.value in wanted:
                    found.add(col.value)
    assert found == wanted, f"never added at boot: {sorted(wanted - found)}"
