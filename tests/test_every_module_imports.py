"""Every shipped Python module must at least *parse*, and the ones the runtime
imports lazily must actually import.

Why this exists: on 2026-07-27 ``app/services/cert_service.py`` sat in ``main``
for a day with ``import os`` placed above ``from __future__ import annotations``
— a hard ``SyntaxError``. The full suite (757 tests) stayed green because every
caller imports that module *inside a function* (``settings``, ``cert_manager``,
``alerts``), so nothing at collection time ever touched it. The only thing that
noticed was the nightly ``satom-cert-renew`` timer, failing where nobody looks,
and it shipped inside two offline bundles.

Parsing is not correctness, but a module that cannot be parsed is never correct,
and this is the cheapest possible net for it.
"""
from __future__ import annotations

import importlib
import pathlib
import py_compile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Sólo árboles nuestros: nada de venv, migraciones generadas o material de test.
SOURCE_DIRS = ("app", "deploy")


def _python_files():
    for d in SOURCE_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if "__pycache__" in p.parts:
                continue
            yield p


ALL_FILES = list(_python_files())


def test_there_is_something_to_check():
    # Si el glob se rompe, el test de abajo pasaría vacío y no protegería nada.
    assert len(ALL_FILES) > 50, "esperaba decenas de modulos, encontre %d" % len(ALL_FILES)


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_module_compiles(path, tmp_path):
    """Cada fichero .py del producto tiene que compilar."""
    try:
        py_compile.compile(str(path), cfile=str(tmp_path / "out.pyc"), doraise=True)
    except py_compile.PyCompileError as exc:  # pragma: no cover - el mensaje es el valor
        pytest.fail("%s no compila:\n%s" % (path.relative_to(ROOT), exc))


# Módulos que NINGÚN test importa a nivel de colección porque sus llamadores los
# importan dentro de funciones. Son justo los que se pueden pudrir en silencio.
LAZY_MODULES = [
    "app.services.cert_service",
    "app.services.cert_renew_log",
    "app.services.git_backup",
    "app.services.backup_server",
    "app.services.library_updates",
    "app.services.encryption_health",
    "app.services.node_security",
]


@pytest.mark.parametrize("dotted", LAZY_MODULES)
def test_lazily_imported_module_actually_imports(app, dotted):
    """Importable de verdad, no sólo parseable (imports rotos, typos en nombres)."""
    with app.app_context():
        importlib.import_module(dotted)
