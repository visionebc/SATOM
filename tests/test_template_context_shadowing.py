"""A view keyword must not shadow a global the base layout renders.

``render_template(..., products=[...])`` replaced the ``products`` dict that
``base.html`` iterates with ``.items()`` for the ADOM navigation, and the new
field-map page answered 500 in production while its own tests were green: the
test app has no ADOM registry, so that block never ran there. The collision is
invisible per page, so it is checked once for every ``render_template`` call.
"""
import ast
import glob
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

#: Pre-existing overrides that pass the SAME shape as the global (the product
#: registry dict), so the layout still renders. A new entry needs that proof.
ALLOWED = {
    ("app/views/product.py", "products"),
    ("app/views/naming.py", "products"),
}


def _context_keys(app):
    keys = set()
    with app.test_request_context("/"):
        for fns in app.template_context_processors.values():
            for fn in fns:
                try:
                    keys |= set((fn() or {}).keys())
                except Exception:  # noqa: BLE001 — a processor needing a user is skipped
                    pass
    return keys


def _render_kwargs():
    for path in glob.glob(os.path.join(ROOT, "app", "**", "*.py"), recursive=True):
        rel = os.path.relpath(path, ROOT)
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "render_template":
                continue
            for kw in node.keywords:
                if kw.arg:
                    yield rel, node.lineno, kw.arg


def test_the_layout_globals_are_known(app):
    # Vacuity check: if the processors stopped answering, the guard below
    # would pass on an empty set.
    assert "products" in _context_keys(app)


def test_no_view_shadows_a_layout_global(app):
    keys = _context_keys(app)
    bad = [f"{rel}:{line} {arg}" for rel, line, arg in _render_kwargs()
           if arg in keys and (rel, arg) not in ALLOWED]
    assert not bad, "render_template keyword shadows a context global: %s" % bad
