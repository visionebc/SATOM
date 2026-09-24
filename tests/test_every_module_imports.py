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

# Only our own trees: no venv, generated migrations or test material.
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
    # If the glob breaks, the test below would pass empty and protect nothing.
    assert len(ALL_FILES) > 50, "expected dozens of modules, found %d" % len(ALL_FILES)


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_module_compiles(path, tmp_path):
    """Every .py file in the product has to compile."""
    try:
        py_compile.compile(str(path), cfile=str(tmp_path / "out.pyc"), doraise=True)
    except py_compile.PyCompileError as exc:  # pragma: no cover - the message is the value
        pytest.fail("%s does not compile:\n%s" % (path.relative_to(ROOT), exc))


# Modules that NO test imports at collection time because their callers import
# them inside functions. They are exactly the ones that can rot silently.
LAZY_MODULES = [
    "app.services.cert_service",
    "app.services.cert_renew_log",
    "app.services.sot_store",
    "app.services.vm_store",
    "app.services.metrics_collect",
    "app.services.git_backup",
    "app.services.backup_server",
    "app.services.library_updates",
    "app.services.encryption_health",
    "app.services.node_security",
    # Custody: both are imported INSIDE functions (system_backup, the CLI
    # snippets), so nothing touches them at collection time. That is exactly
    # how a syntactically broken cert_service.py rode inside releases 1.2 and
    # 1.2.1 while the app booted, /healthz returned 200 and the suite stayed
    # green -- the only symptom was a nightly timer failing where nobody looked.
    "app.services.recovery",
    "app.services.recovery_seal",
]


@pytest.mark.parametrize("dotted", LAZY_MODULES)
def test_lazily_imported_module_actually_imports(app, dotted):
    """Actually importable, not just parseable (broken imports, typos in names)."""
    with app.app_context():
        importlib.import_module(dotted)
