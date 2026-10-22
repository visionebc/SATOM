"""Code plugins -- signed Flask blueprints installed without an update package.

A ``kind: code`` plugin package (see plugin_package) carries a Python package
``code/<entry>/`` whose ``__init__.py`` defines a Blueprint ``bp``. Import
writes it under ``data/plugins/code/<slug>/``; it is mounted at ``/x/<slug>/``
the next time the app starts (``satom execute restart-all``) -- a running app
never imports new code.

Trust: install REFUSES a package that is not signed by a key in
``plugin_package.TRUSTED_KEYS``, and every start re-verifies the signature and
the sha256 of every file on disk before importing anything, so a file edited or
dropped into the plugin folder after install keeps that plugin from loading.
A plugin that fails (bad signature, import error, no ``bp``, name clash) is
skipped with its error recorded -- it never stops SATOM from starting.

Every ``/x/<slug>/`` route requires a signed-in user; anything further (which
profile may do what) is the plugin's own business, with SATOM's permission
helpers. The code runs with SATOM's privileges: that is what the signature is
for.

``data/`` is replicated to the standby by the HA data sync, so the standby has
the same plugins and loads them at its own next restart.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import plugin_package as pkgmod
from .plugin_package import PackageError

logger = logging.getLogger(__name__)

URL_PREFIX = "/x"
EXT_KEY = "satom_code_plugins"
_META = ("plugin.json", "plugin.sig", "state.json")


def code_dir() -> Path:
    return Path(os.environ.get("SATOM_PLUGIN_CODE_DIR")
                or Path(__file__).resolve().parents[2] / "data" / "plugins" / "code")


def _slug_dir(slug: str) -> Path:
    if not pkgmod.SLUG_RE.match(slug or ""):
        raise PackageError("Bad plugin slug.")
    return code_dir() / slug


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_state(slug: str) -> dict | None:
    d = _slug_dir(slug)
    try:
        state = json.loads((d / "state.json").read_text())
        manifest = json.loads((d / "plugin.json").read_text())
    except (OSError, ValueError):
        return None
    return {"slug": slug, "name": manifest.get("name") or slug,
            "version": manifest.get("version") or "?",
            "icon": manifest.get("icon") or "bi-plug",
            "description": manifest.get("description") or "",
            "signer": state.get("signer") or "",
            "enabled": bool(state.get("enabled", True)),
            "installed_at": state.get("installed_at") or "",
            "installed_by": state.get("installed_by") or ""}


def _write_state(d: Path, state: dict) -> None:
    tmp = d / ".state.json.tmp"
    tmp.write_text(json.dumps(state, indent=1))
    os.replace(tmp, d / "state.json")


def install(pkg: pkgmod.Package, user: str, allow_downgrade: bool = False) -> dict:
    """Write a VERIFIED code package to disk (atomic swap). Loads at next start."""
    if pkg.kind != "code":
        raise PackageError("Only code plugins install here.")
    if not pkg.signer or not pkg.sig_bytes:
        raise PackageError("A code plugin must be signed by a key this server "
                           "trusts; unsigned code is never installed.")
    current = read_state(pkg.slug)
    if (current and not allow_downgrade
            and pkgmod.version_tuple(pkg.version) < pkgmod.version_tuple(current["version"])):
        raise PackageError(f"{pkg.slug} {current['version']} is installed; "
                           f"{pkg.version} is older (tick 'Allow downgrade').")
    root = code_dir()
    root.mkdir(parents=True, exist_ok=True)
    final = _slug_dir(pkg.slug)
    stage = root / f".stage-{pkg.slug}-{uuid.uuid4().hex[:8]}"
    stage.mkdir()
    try:
        (stage / "plugin.json").write_bytes(pkg.manifest_bytes)
        (stage / "plugin.sig").write_bytes(pkg.sig_bytes)
        for name, data in pkg.files.items():
            p = stage / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        _write_state(stage, {"enabled": True, "installed_at": _now(),
                             "installed_by": user, "signer": pkg.signer,
                             "version": pkg.version})
        verify_installed(stage, expect_slug=pkg.slug)   # disk == what was verified
        old = None
        if final.exists():
            old = root / f".old-{pkg.slug}-{uuid.uuid4().hex[:8]}"
            os.replace(final, old)
        os.replace(stage, final)
        if old is not None:
            shutil.rmtree(old, ignore_errors=True)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return read_state(pkg.slug) or {}


def set_enabled(slug: str, enabled: bool) -> dict:
    d = _slug_dir(slug)
    st = json.loads((d / "state.json").read_text())
    st["enabled"] = bool(enabled)
    _write_state(d, st)
    return read_state(slug) or {}


def remove(slug: str) -> None:
    d = _slug_dir(slug)
    if not d.is_dir():
        raise PackageError(f"{slug} is not installed.")
    shutil.rmtree(d)


def verify_installed(d: Path, keys: dict | None = None,
                     expect_slug: str | None = None) -> pkgmod.Package:
    """Re-check an installed plugin exactly as at install: signature over
    plugin.json, every listed file's sha256, and NOTHING else on disk."""
    try:
        mbytes = (d / "plugin.json").read_bytes()
        sbytes = (d / "plugin.sig").read_bytes()
    except OSError:
        raise PackageError("plugin.json or plugin.sig is missing on disk.")
    signer = pkgmod.verify_signature(mbytes, sbytes, keys)
    try:
        manifest = json.loads(mbytes.decode("utf-8"))
    except ValueError:
        raise PackageError("plugin.json on disk is not valid JSON.")
    pkgmod.validate_manifest(manifest)
    if manifest["kind"] != "code":
        raise PackageError("Only code plugins live in the code plugin folder.")
    if manifest["slug"] != (expect_slug or d.name):
        raise PackageError("The folder does not match the plugin's slug.")
    listed = manifest["files"]
    files: dict[str, bytes] = {}
    for p in sorted(d.rglob("*")):
        rel = p.relative_to(d).as_posix()
        if "__pycache__" in p.parts:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)   # never trust stale bytecode
            continue
        if p.is_dir() or rel in _META or rel == ".state.json.tmp":
            continue
        if rel not in listed:
            raise PackageError(f"Unexpected file on disk: {rel}")
        b = p.read_bytes()
        if pkgmod.sha256(b) != listed[rel]:
            raise PackageError(f"{rel} was changed after install.")
        files[rel] = b
    missing = sorted(set(listed) - set(files))
    if missing:
        raise PackageError("Missing on disk: " + ", ".join(missing[:5]))
    return pkgmod.Package(manifest=manifest, files=files, signer=signer,
                          manifest_bytes=mbytes, sig_bytes=sbytes)


def _import(pkg: pkgmod.Package, d: Path):
    entry = pkg.manifest["entry"]
    modname = "satom_codeplugin_" + pkg.slug.replace("-", "_")
    pkgdir = d / "code" / entry
    for name in [m for m in sys.modules if m == modname or m.startswith(modname + ".")]:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        modname, pkgdir / "__init__.py", submodule_search_locations=[str(pkgdir)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(modname, None)
        raise
    return mod


def load_all(app) -> dict:
    """Mount every enabled, verified code plugin. Never raises."""
    from flask import Blueprint, request
    from flask_login import current_user

    from ..extensions import login_manager

    loaded: dict[str, dict] = {}
    app.extensions[EXT_KEY] = loaded
    root = code_dir()
    if not root.is_dir():
        return loaded
    bp_names: set[str] = set()
    for d in sorted(root.iterdir()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        slug = d.name
        rec = {"slug": slug, "version": None, "status": "error", "error": "",
               "url": f"{URL_PREFIX}/{slug}/"}
        loaded[slug] = rec
        try:
            st = read_state(slug)
            if st is None:
                raise PackageError("state.json or plugin.json is unreadable.")
            rec["version"] = st["version"]
            if not st["enabled"]:
                rec["status"] = "disabled"
                continue
            pkg = verify_installed(d)
            mod = _import(pkg, d)
            bp = getattr(mod, "bp", None)
            if not isinstance(bp, Blueprint):
                raise PackageError("The entry module has no Blueprint named 'bp'.")
            if bp.name in app.blueprints:
                raise PackageError(f"Blueprint name {bp.name!r} is already taken.")
            app.register_blueprint(bp, url_prefix=f"{URL_PREFIX}/{slug}")
            bp_names.add(bp.name)
            rec["version"] = pkg.version
            rec["status"] = "loaded"
        except Exception as exc:  # noqa: BLE001 -- one plugin never stops the app
            rec["status"] = "error"
            rec["error"] = f"{type(exc).__name__}: {exc}"[:500]
            logger.warning("code plugin %s not loaded: %s", slug, rec["error"])

    if bp_names:
        @app.before_request
        def _code_plugin_login_gate():
            bpn = request.blueprint or ""
            if bpn.split(".")[0] in bp_names and not current_user.is_authenticated:
                return login_manager.unauthorized()
            return None
    return loaded


def overview(app) -> list[dict]:
    """Installed plugins on disk joined with what THIS process loaded at start."""
    loaded = dict(app.extensions.get(EXT_KEY) or {})
    rows: list[dict] = []
    root = code_dir()
    names = sorted(p.name for p in root.iterdir()
                   if p.is_dir() and not p.name.startswith(".")) if root.is_dir() else []
    for slug in names:
        st = read_state(slug) or {"slug": slug, "name": slug, "version": "?",
                                  "enabled": False, "icon": "bi-plug"}
        rec = loaded.pop(slug, None)
        if rec and rec["status"] == "error":
            state, note = "error", rec["error"]
        elif rec and rec["status"] == "loaded" and rec["version"] == st["version"] and st["enabled"]:
            state, note = "loaded", ""
        elif rec and rec["status"] == "loaded" and not st["enabled"]:
            state, note = "restart", "Disabled -- unloads at the next restart."
        elif st["enabled"]:
            state, note = "restart", "Loads at the next restart."
        else:
            state, note = "disabled", ""
        rows.append(dict(st, state=state, note=note, url=f"{URL_PREFIX}/{slug}/"))
    for slug, rec in loaded.items():           # mounted at start, removed since
        if rec["status"] == "loaded":
            rows.append({"slug": slug, "name": slug, "version": rec["version"],
                         "icon": "bi-plug", "enabled": False, "signer": "",
                         "state": "restart", "url": rec["url"],
                         "note": "Removed -- unloads at the next restart."})
    return rows
