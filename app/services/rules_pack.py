"""The rules pack -- SATOM's package rules as a zip the SATOM Builder runs.

ONE SOURCE
----------
The rules a ``satom.plugin/1`` package must pass live in ONE place:
``services.package_check`` and the modules it calls (``plugin_package``,
``studio_apps``, ``studio_flow``, ``studio_store``, ...). The Builder never
re-implements them: it downloads this pack (``GET /api/v1/builder/rules-pack``)
and runs SATOM's own files, copied VERBATIM, in a subprocess. A rule changed
here is the Builder's rule as soon as it fetches the pack of that version, and
the server checks every package again on validate, rehearse and import.

WHAT IS IN IT (contract, section 3.1)
-------------------------------------
::

    rules.json                    format, satom_version, commit, files {path: sha256},
                                  entry, stubs, requires, runtime
    satom_rules/__init__.py       re-exports check, schema, author_guide, POLICIES,
                                  CHECK_VERSION
    satom_rules/app/__init__.py   empty
    satom_rules/app/extensions.py STUB: ``db`` raises on any attribute
    satom_rules/app/services/*.py VERBATIM copies: package_check, the runtime
                                  modules (RUNTIME_MODULES) and their import closure
    satom_rules/runtime/plugin-kit.css   static/css/plugin-kit.css, verbatim
    satom_rules/runtime/tokens.css       the default design tokens (plugin_frame)

THE RUNTIME (contract section 13)
---------------------------------
The SATOM Builder also TESTS a package before it ever reaches a server: it
renders a view with this server's renderer and frame, walks a diagram with
this server's walk and store rules, and runs a script in this server's jail
with this server's SDK -- on test data it keeps itself. Those modules travel
here, packed exactly like the rules, and ``rules.json`` lists them under
``runtime`` (packed or stub). Nothing of the runtime is re-implemented on the
Builder side; it only supplies the data the database would.

The closure is computed here, from the syntax tree: every relative import of
an ``app`` module, at module level AND inside functions, followed from
``package_check``. A module that cannot be imported without the server --
Flask, the database models, a library the pack does not carry (only jinja2,
markupsafe and cryptography) -- is replaced by a STUB whose names are
placeholders that raise when used; a module is never dropped. Anything the
closure needs and cannot pack (a missing file, a syntax error, an absolute
``app.`` import) fails the build loudly instead.

The zip is deterministic: sorted members, a fixed timestamp and mode, no
mtimes -- the same tree gives the same sha256. It is built once per process
and SATOM version (+ git commit when there is one).
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

FORMAT = "satom.rules-pack/1"
PACKAGE = "satom_rules"
ENTRY_MODULE = "app.services.package_check"
#: The runtime the SATOM Builder tests a package with, locally and on test
#: data (contract section 13): the same view renderer, frame, diagram walk,
#: store rules, jail and script SDK this server runs. Packed like the rules --
#: verbatim, or a stub when a module needs the server -- and listed in
#: ``rules.json`` under ``runtime`` with which of the two each one is.
RUNTIME_FORMAT = "satom.runtime/1"
RUNTIME_MODULES = (
    "app.services.plugin_frame", "app.services.plugin_sandbox",
    "app.services.studio_flow", "app.services.studio_apps", "app.services.studio_store",
    "app.services.studio_connections", "app.services.studio_apis",
    "app.services.studio_api_spec", "app.services.studio_checks",
    "app.services.studio_satom", "app.services.script_library",
    "app.services.sandbox", "app.services.sandbox_boot",
    "app.services.script_sdk", "app.services.integration_sdk",
    "app.services.studio_broker", "app.services.studio_http", "app.services.script_runner",
)
#: Data files of the runtime (paths inside the pack -> how they are made).
RUNTIME_KIT = PACKAGE + "/runtime/plugin-kit.css"       # static/css/plugin-kit.css, verbatim
RUNTIME_TOKENS = PACKAGE + "/runtime/tokens.css"        # the default design tokens
#: What the pack needs besides the standard library (contract 3.1).
REQUIRES = ("jinja2", "markupsafe", "cryptography")
#: Always stubs: the database layer and the Flask app factory.
FORCED_STUBS = ("app", "app.extensions", "app.models", "app.models_studio")

APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
_STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}

#: Test seam: {module name: source text} read instead of the file on disk.
_SOURCE_OVERRIDES: dict[str, str] = {}
_CACHE: dict[tuple, tuple[bytes, str]] = {}


class RulesPackError(RuntimeError):
    """The pack cannot be built; the message names the module and why."""


# --------------------------------------------------------------------------- #
#  sources                                                                     #
# --------------------------------------------------------------------------- #
def _module_file(mod: str) -> Path | None:
    parts = mod.split(".")[1:]
    base = APP_ROOT.joinpath(*parts) if parts else APP_ROOT
    if parts and base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return None


def _exists(mod: str) -> bool:
    return mod in _SOURCE_OVERRIDES or _module_file(mod) is not None


def _is_package(mod: str) -> bool:
    f = _module_file(mod)
    return f is not None and f.name == "__init__.py"


def _source(mod: str) -> str:
    if mod in _SOURCE_OVERRIDES:
        return _SOURCE_OVERRIDES[mod]
    f = _module_file(mod)
    if f is None:
        raise RulesPackError("%s is in the closure of %s and has no source file"
                             % (mod, ENTRY_MODULE))
    return f.read_text(encoding="utf-8")


def _member(mod: str) -> str:
    """The path of module *mod* inside the pack."""
    parts = mod.split(".")
    if mod == "app" or _is_package(mod):
        return "/".join([PACKAGE] + parts + ["__init__.py"])
    return "/".join([PACKAGE] + parts) + ".py"


# --------------------------------------------------------------------------- #
#  the closure                                                                 #
# --------------------------------------------------------------------------- #
def _toplevel(tree: ast.Module) -> set[int]:
    """ids of the nodes that run when the module is imported: everything but
    the bodies of functions and lambdas (their decorators and defaults run)."""
    out, stack = set(), list(tree.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = n.args
            stack.extend(list(getattr(n, "decorator_list", [])) + list(args.defaults)
                         + [d for d in args.kw_defaults if d is not None])
            continue
        out.add(id(n))
        stack.extend(ast.iter_child_nodes(n))
    return out


class _Info:
    """What the closure needs to know of one module."""

    def __init__(self, mod: str):
        self.mod = mod
        self.deps: set[str] = set()            # app modules, any level
        self.top_deps: set[str] = set()        # app modules imported at module level
        self.bound: dict[str, str] = {}        # top-level name -> app module it came from
        self.used_at_top: set[str] = set()     # names whose attribute / call runs at import
        self.foreign: set[str] = set()         # third-party modules imported at module level
        self.errors: list[str] = []


def _resolve(mod: str, node: ast.ImportFrom) -> str:
    pkg = mod.split(".") if _is_package(mod) or mod == "app" else mod.split(".")[:-1]
    if node.level - 1 > len(pkg) - 1:
        raise RulesPackError("%s: relative import beyond the app package" % mod)
    base = pkg[:len(pkg) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


def _analyse(mod: str) -> _Info:
    info = _Info(mod)
    try:
        tree = ast.parse(_source(mod), mod)
    except SyntaxError as exc:
        raise RulesPackError("%s does not parse: %s" % (mod, exc)) from None
    top = _toplevel(tree)
    parent = mod.rsplit(".", 1)[0] if "." in mod else ""
    if parent:
        info.deps.add(parent)
        info.top_deps.add(parent)          # importing a module runs its package first
    for node in ast.walk(tree):
        at_top = id(node) in top
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root == "app":
                    info.errors.append("absolute import of %s" % a.name)
                elif at_top and root not in _STDLIB:
                    info.foreign.add(root)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                root = (node.module or "").split(".")[0]
                if root == "app":
                    info.errors.append("absolute import from %s" % node.module)
                elif at_top and root not in _STDLIB:
                    info.foreign.add(root)
                continue
            target = _resolve(mod, node)
            for a in node.names:
                sub = "%s.%s" % (target, a.name)
                dep = sub if a.name != "*" and _exists(sub) else target
                if not _exists(dep) or (node.module is None and dep != sub):
                    raise RulesPackError("%s imports %s, which does not exist"
                                         % (mod, sub if node.module is None else target))
                if dep == "app" and a.name != "*" and not _exists(sub):
                    info.errors.append("from %s import %s (the app factory is not packed)"
                                       % ("." * node.level, a.name))
                info.deps.add(dep)
                if at_top:
                    info.top_deps.add(dep)
                    info.bound[a.asname or a.name] = dep
                # the package of a submodule runs first
                if dep == sub:
                    info.deps.add(target)
                    if at_top:
                        info.top_deps.add(target)
    names = set(info.bound)
    for node in ast.walk(tree):
        if id(node) not in top:
            continue
        base = node.value if isinstance(node, ast.Attribute) else \
            node.func if isinstance(node, ast.Call) else None
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name) and base.id in names:
            info.used_at_top.add(base.id)
    return info


def closure() -> dict:
    """``{"packed": [modules], "stubs": {module: why}}`` -- what the pack
    holds. Raises RulesPackError when the closure cannot be packed."""
    infos: dict[str, _Info] = {}
    todo = [ENTRY_MODULE] + list(RUNTIME_MODULES)
    while todo:
        mod = todo.pop()
        if mod in infos or mod in FORCED_STUBS:
            continue
        if not _exists(mod):
            raise RulesPackError("%s is in the closure of %s and has no source file"
                                 % (mod, ENTRY_MODULE))
        infos[mod] = info = _analyse(mod)
        if info.foreign - set(REQUIRES):
            # stubbed: what it imports is not needed, but its package is
            todo.extend(sorted(d for d in info.top_deps if mod.startswith(d + ".")))
            continue
        todo.extend(sorted(info.deps))
    why: dict[str, str] = {m: "the SATOM server (Flask, the database)" for m in FORCED_STUBS}
    for mod, info in infos.items():
        foreign = sorted(info.foreign - set(REQUIRES))
        if foreign:
            why[mod] = "a library the rules pack does not carry (%s)" % ", ".join(foreign)
    changed = True
    while changed:                      # a module whose import needs a stub is a stub
        changed = False
        for mod, info in infos.items():
            if mod in why:
                continue
            used = sorted(n for n in info.used_at_top if info.bound.get(n) in why)
            if used:
                why[mod] = "it uses %s at import time" % ", ".join(used)
                changed = True
    packed, stubs, seen = [], {}, set()
    todo = [ENTRY_MODULE] + list(RUNTIME_MODULES)
    if ENTRY_MODULE in why:
        raise RulesPackError("%s itself cannot be packed: %s" % (ENTRY_MODULE, why[ENTRY_MODULE]))
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        seen.add(mod)
        if mod in why:
            stubs[mod] = why[mod]
            parent = mod.rsplit(".", 1)[0] if "." in mod else ""
            if parent:
                todo.append(parent)
            continue
        info = infos[mod]
        if info.errors:
            raise RulesPackError("%s cannot be packed: %s" % (mod, "; ".join(info.errors)))
        packed.append(mod)
        todo.extend(sorted(info.deps))
    stubs.setdefault("app", why["app"])
    stubs.setdefault("app.extensions", why["app.extensions"])
    stubs.setdefault("app.models_studio", why["app.models_studio"])
    return {"packed": sorted(packed), "stubs": dict(sorted(stubs.items()))}


# --------------------------------------------------------------------------- #
#  stubs                                                                       #
# --------------------------------------------------------------------------- #
_STUB = '''"""STUB of SATOM's {mod} (rules pack): it needs {why}.

Generated by app/services/rules_pack.py. Every name imported from here is a
placeholder class: using it (an attribute, a call) raises RuntimeError, so a
rule that would need the server fails loudly instead of answering wrongly.
"""


class _Missing(type):
    def __getattr__(cls, name):
        raise RuntimeError("{mod}.%s is not in the rules pack (it needs the SATOM server)"
                           % cls.__name__)

    def __call__(cls, *args, **kwargs):
        raise RuntimeError("{mod}.%s is not in the rules pack (it needs the SATOM server)"
                           % cls.__name__)


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    cls = _Missing(name, (Exception,), {{"__module__": __name__}})
    globals()[name] = cls
    return cls
'''

_EXTENSIONS_EXTRA = '''

class _NoDatabase:
    def __getattr__(self, name):
        raise RuntimeError("no database in the rules pack")


db = _NoDatabase()
'''

_APP_INIT = '"""SATOM\'s ``app`` package, without its Flask factory (rules pack)."""\n'

_ROOT_INIT = '''"""SATOM's package rules (rules pack). See rules.json and SATOM's
app/services/rules_pack.py: everything under app/ is SATOM's own code, copied
verbatim, or a stub of a module that needs the SATOM server."""
from .app.services.package_check import check, schema, author_guide, POLICIES, CHECK_VERSION

__all__ = ["check", "schema", "author_guide", "POLICIES", "CHECK_VERSION"]
'''


def _stub_source(mod: str, why: str) -> str:
    if mod == "app":
        return _APP_INIT
    src = _STUB.format(mod=mod, why=why)
    return src + _EXTENSIONS_EXTRA if mod == "app.extensions" else src


# --------------------------------------------------------------------------- #
#  the zip                                                                     #
# --------------------------------------------------------------------------- #
def _version() -> str:
    from ..version import app_version
    return app_version()


_COMMIT: list = []


def _commit() -> str:
    if not _COMMIT:
        try:
            out = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                                 capture_output=True, text=True, timeout=5, check=False)
            sha = out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            sha = ""
        _COMMIT.append(sha if len(sha) == 40 else "")
    return _COMMIT[0]


def _runtime_files() -> dict[str, bytes]:
    from . import plugin_frame
    with open(plugin_frame.KIT_PATH, "rb") as fh:
        kit = fh.read()
    return {RUNTIME_KIT: kit,
            RUNTIME_TOKENS: plugin_frame.default_tokens_css().encode("utf-8")}


def runtime_manifest(c: dict | None = None) -> dict:
    """``rules.json`` ``runtime``: each runtime module, packed or stubbed."""
    c = c or closure()
    packed = set(c["packed"])
    return {"format": RUNTIME_FORMAT,
            "modules": {m: ("packed" if m in packed else "stub") for m in RUNTIME_MODULES},
            "kit_css": RUNTIME_KIT, "tokens_css": RUNTIME_TOKENS}


def members() -> dict[str, bytes]:
    """Every member of the pack but rules.json, by path."""
    c = closure()
    out = {"%s/__init__.py" % PACKAGE: _ROOT_INIT.encode("utf-8")}
    for mod in c["packed"]:
        out[_member(mod)] = _source(mod).encode("utf-8")
    for mod, why in c["stubs"].items():
        out[_member(mod)] = _stub_source(mod, why).encode("utf-8")
    out.update(_runtime_files())
    return out


def build(*, cache: bool = True) -> tuple[bytes, str]:
    """``(zip bytes, sha256 hex)`` of the rules pack of this SATOM."""
    key = (_version(), _commit())
    if cache and not _SOURCE_OVERRIDES and key in _CACHE:
        return _CACHE[key]
    files = members()
    c = closure()
    manifest = {"format": FORMAT, "satom_version": key[0], "commit": key[1],
                "entry": PACKAGE, "requires": list(REQUIRES),
                "runtime": runtime_manifest(c),
                "stubs": sorted(m for m in c["stubs"]),
                "files": {p: hashlib.sha256(b).hexdigest() for p, b in sorted(files.items())}}
    files["rules.json"] = json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(files):
            zi = zipfile.ZipInfo(path, _ZIP_EPOCH)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zi.create_system = 3
            z.writestr(zi, files[path], compresslevel=9)
    data = buf.getvalue()
    res = (data, hashlib.sha256(data).hexdigest())
    if cache and not _SOURCE_OVERRIDES:
        _CACHE[key] = res
    return res


def filename(sha256_hex: str) -> str:
    """The name the pack is served under (contract 3.1)."""
    return "satom-rules-%s-%s.zip" % (_version(), sha256_hex[:12])
