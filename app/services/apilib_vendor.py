"""Vendor Ansible collections -> API library evidence documents.

Fortinet publishes one Ansible collection per product, and two of them carry
something SATOM cannot measure on its own: the firmware range each endpoint
and each field is valid for.

* ``fortinet.fortios`` -- every cmdb module holds a ``versioned_schema``
  literal whose nodes carry ``"v_range": [["v6.0.0", ""]]``. FortiGate is
  catalog-only in SATOM (no FortiGate is managed), so this collection is the
  ONLY evidence the library will ever have for it.
* ``fortinet.fortianalyzer`` -- every module's ``main()`` builds a
  ``module_arg_spec`` whose object node carries ``'v_range': [['6.2.1', '']]``
  and a ``urls_list`` with the JSON-RPC URL(s).

``fortinet.fortiweb`` and ``fortinet.fortiadc`` carry no per-field or
per-endpoint version data at all (only ``version_added`` of the collection
itself), so they yield no evidence here: an endpoint list without ranges would
assert "valid on every build", which is exactly the claim the library refuses
to make without a measurement.

The output is the ``scope.kind == "spans"`` form of the evidence document in
``docs/api-library.md``. Vendor ranges are stored as ranges, never expanded
per build; ``""`` as the end of a span means "open", and ``summary.max_version``
is the cap the library applies to it -- a build newer than the collection knows
about is ``unmeasured``, not ``ok``.

Two rules this module is shaped around:

1. **Never import or execute vendor code.** The modules import
   ``ansible.module_utils``; importing them would need Ansible installed and
   would run a third party's module-level code inside SATOM. Everything is read
   with ``ast`` and ``ast.literal_eval`` on the one assignment we need.
2. **Skip loudly.** A module that is not a configuration object (monitor, fact,
   exec, RPC action) or whose structure we do not recognise is left out AND
   listed in ``summary.skipped`` with the reason, so a shrinking endpoint count
   after a collection upgrade is explainable instead of silent.

Pure functions: no database, no Flask app context.
"""
from __future__ import annotations

import ast
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")


def normalize_version(v) -> str:
    """``"v7.4.3"`` -> ``"7.4.3"``; ``""`` (open end) stays ``""``.

    FortiOS writes the ``v`` prefix, FortiAnalyzer does not. The library keys
    builds by bare version, so both must land on the same spelling or the same
    build would be stored twice.
    """
    s = str(v or "").strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    if s and not _VERSION_RE.match(s):
        raise ValueError(f"unparseable version {v!r}")
    return s


def version_key(v: str) -> tuple:
    """Numeric sort key. String sorting puts ``7.0.12`` before ``7.0.2``."""
    return tuple(int(p) for p in normalize_version(v).split("."))


def _spans(v_range) -> list:
    """Vendor ``v_range`` -> ``[[from, to], ...]`` with normalized versions.

    Raises ValueError on a malformed range so the caller can skip the whole
    module rather than store half of it.
    """
    out = []
    for pair in v_range or []:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError(f"malformed v_range entry {pair!r}")
        lo, hi = normalize_version(pair[0]), normalize_version(pair[1])
        if not lo:
            raise ValueError(f"v_range without a start {pair!r}")
        out.append([lo, hi])
    return out


def _collect_versions(node, acc: set) -> None:
    """Every version named by any ``v_range`` below ``node``.

    Walks the whole tree, not only the top-level fields we emit: option values
    and nested columns also name builds (``"mac"`` appears in 6.2.5 ...), and
    the scope must list every build the collection has an opinion about.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "v_range" and isinstance(v, (list, tuple)):
                for pair in v:
                    if isinstance(pair, (list, tuple)):
                        for x in pair:
                            s = normalize_version(x)
                            if s:
                                acc.add(s)
            else:
                _collect_versions(v, acc)
    elif isinstance(node, (list, tuple)):
        for x in node:
            _collect_versions(x, acc)


# ---------------------------------------------------------------------------
# source reading (ast only)
# ---------------------------------------------------------------------------

def _parse(path: str) -> ast.Module:
    with open(path, encoding="utf-8") as fh:
        return ast.parse(fh.read(), filename=path)


def _assignment(tree: ast.Module, name: str, *, module_level: bool):
    """``literal_eval`` of the assignment to ``name``, or None.

    ``module_level`` restricts the search to top-level statements: FortiOS's
    ``versioned_schema`` lives there, while FortiAnalyzer builds its arg spec
    inside ``main()``. A value that is not a pure literal (``faz_fact`` calls
    ``list(...)`` inside its spec) also returns None -- it is never evaluated.
    """
    nodes = tree.body if module_level else ast.walk(tree)
    for node in nodes:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            try:
                return ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                return None
    return None


def _read_manifest(path: str) -> dict:
    mpath = os.path.join(path, "MANIFEST.json")
    if not os.path.isfile(mpath):
        raise ValueError(f"not an Ansible collection (no MANIFEST.json): {path}")
    with open(mpath, encoding="utf-8") as fh:
        info = (json.load(fh) or {}).get("collection_info") or {}
    return {"namespace": info.get("namespace") or "",
            "name": info.get("name") or "",
            "version": info.get("version") or ""}


_RELEASE_RE = re.compile(r"^  (['\"]?)(?P<v>[0-9][^'\":\s]*)\1:\s*$")
_DATE_RE = re.compile(r"^\s+release_date:\s*['\"]?(?P<d>\d{4}-\d{2}-\d{2})")


def _release_date(path: str, version: str) -> str | None:
    """The collection's release date from ``changelogs/changelog.yaml``.

    ``MANIFEST.json`` carries no build date, and the file mtime is when the
    tarball was extracted here, not when Fortinet produced the data. The
    changelog is antsibull's fixed layout (``releases:`` -> two-space version
    keys -> ``release_date``), read by line so this needs no YAML dependency.
    """
    cpath = os.path.join(path, "changelogs", "changelog.yaml")
    if not os.path.isfile(cpath):
        return None
    current = None
    with open(cpath, encoding="utf-8") as fh:
        for line in fh:
            m = _RELEASE_RE.match(line)
            if m:
                current = m.group("v")
                continue
            m = _DATE_RE.match(line)
            if m and current == version:
                return m.group("d") + "T00:00:00"
    return None


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0).isoformat()


def _module_files(path: str, prefix: str) -> list[tuple[str, str]]:
    mdir = os.path.join(path, "plugins", "modules")
    if not os.path.isdir(mdir):
        return []
    return [(f[:-3], os.path.join(mdir, f)) for f in sorted(os.listdir(mdir))
            if f.startswith(prefix) and f.endswith(".py")]


# ---------------------------------------------------------------------------
# FortiOS (fortinet.fortios)
# ---------------------------------------------------------------------------

# Methods whose first two positional args are the cmdb (path, name). Every
# config module calls several of them with the SAME pair; disagreement means
# the module is not a plain one-endpoint wrapper and we refuse to guess.
_FOS_URL_METHODS = frozenset({"set", "get", "delete", "get_mkey", "do_member_operation"})


def _fos_skip_by_name(module: str) -> str | None:
    # ``fortios_monitor`` / ``fortios_monitor_fact`` wrap /api/v2/monitor.
    # ``fortios_monitoring_*`` look alike but are real cmdb tables
    # (``config monitoring npu-hpe``), so a bare prefix match would drop them.
    if module == "fortios_monitor" or module.startswith("fortios_monitor_"):
        return "monitor module (live state, not cmdb)"
    if module.endswith("_fact"):
        return "fact module (read-only query)"
    if module == "fortios_json_generic":
        return "generic JSON passthrough"
    return None


def _fos_cmdb_pair(tree: ast.Module) -> set[tuple[str, str]]:
    pairs = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _FOS_URL_METHODS
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "fos"
                and len(node.args) >= 2
                and all(isinstance(a, ast.Constant) and isinstance(a.value, str)
                        for a in node.args[:2])):
            pairs.add((node.args[0].value, node.args[1].value))
    return pairs


def _fos_field(node: dict, endpoint_spans: list) -> dict:
    field = {"type": node.get("type")}
    opts = node.get("options")
    if isinstance(opts, list):
        # Option-level v_range is real vendor data, but the field-fact carries
        # a flat option list; the versions still reach scope.versions.
        field["options"] = [o.get("value") if isinstance(o, dict) else o for o in opts]
    kids = node.get("children")
    if isinstance(kids, dict):
        # Names only: nested tables are one level of the API, not endpoints.
        field["children"] = list(kids.keys())
    if "required" in node:
        field["required"] = bool(node["required"])
    field["spans"] = _spans(node["v_range"]) if node.get("v_range") else [list(s) for s in endpoint_spans]
    return field


def _fos_endpoint(module: str, tree: ast.Module):
    """(logical name, endpoint dict, schema) or raises ValueError(reason)."""
    schema = _assignment(tree, "versioned_schema", module_level=True)
    if not isinstance(schema, dict):
        raise ValueError("no versioned_schema")
    pairs = _fos_cmdb_pair(tree)
    if len(pairs) != 1:
        raise ValueError(f"cannot derive cmdb path ({len(pairs)} distinct fos.<call> targets)")
    path, name = next(iter(pairs))
    if not schema.get("v_range"):
        raise ValueError("versioned_schema has no endpoint v_range")
    spans = _spans(schema["v_range"])
    children = schema.get("children")
    if not isinstance(children, dict):
        raise ValueError("versioned_schema has no children")
    fields = {fname: _fos_field(fnode, spans) for fname, fnode in children.items()
              if isinstance(fnode, dict)}
    endpoint = {
        # FortiOS REST spells the path with dots (``log.syslogd2``); it is
        # kept verbatim so the URN is the URL a FortiGate actually serves.
        "urn": f"/api/v2/cmdb/{path}/{name}",
        # The dotted head is the CLI ``config <section>`` family
        # (``wireless-controller.hotspot20`` -> ``wireless-controller``).
        "section": path.split(".")[0],
        "rows": None,
        "spans": spans,
        "fields": fields,
    }
    return module[len("fortios_"):], endpoint, schema


def _fortios_doc(path: str, manifest: dict) -> dict:
    endpoints, skipped, versions = {}, [], set()
    files = _module_files(path, "fortios_")
    for module, fpath in files:
        reason = _fos_skip_by_name(module)
        if reason is None:
            try:
                tree = _parse(fpath)
                logical, endpoint, schema = _fos_endpoint(module, tree)
                found = set()
                _collect_versions(schema, found)
                endpoints[logical] = endpoint
                versions |= found
                continue
            except (ValueError, SyntaxError) as exc:
                reason = str(exc)
        skipped.append({"module": module, "reason": reason})
    return _document("fortigate", path, manifest, files, endpoints, skipped, versions)


# ---------------------------------------------------------------------------
# FortiAnalyzer (fortinet.fortianalyzer)
# ---------------------------------------------------------------------------

# ``FortiAnalyzerAnsible(..., task_type=...)`` says what a module does. Only
# these two are objects with a stored configuration; the rest are actions
# (``exec``, ``jsonrpc2_add/update/delete`` for alert ack, report run/import),
# membership edits (``object member``), or the fact/rename helpers.
_FAZ_CONFIG_TASKS = frozenset({"full crud", "partial crud"})
_FAZ_SKIP_NAMES = {
    "faz_fact": "fact module (read-only query)",
    "faz_generic": "generic JSON-RPC passthrough",
    "faz_rename": "rename action across object types",
}


def _faz_task_type(tree: ast.Module) -> str | None:
    for node in ast.walk(tree):
        if (isinstance(node, ast.keyword) and node.arg == "task_type"
                and isinstance(node.value, ast.Constant)):
            return node.value.value
    return None


def _faz_urls(tree: ast.Module) -> list:
    # 1.10.0 names it ``urls_list`` inside main(); older generators emitted a
    # module-level ``jrpc_urls``. Accept both so a collection bump does not
    # silently drop every endpoint.
    for name in ("jrpc_urls", "urls_list"):
        urls = _assignment(tree, name, module_level=False)
        if isinstance(urls, list) and urls and all(isinstance(u, str) for u in urls):
            return urls
    return []


def _faz_field(node: dict, endpoint_spans: list) -> dict:
    field = {"type": node.get("type")}
    # Ansible arg-spec vocabulary: ``choices`` are the enum values, ``options``
    # are the nested sub-fields -- the reverse of what the names suggest.
    if isinstance(node.get("choices"), list):
        field["options"] = list(node["choices"])
    if isinstance(node.get("options"), dict):
        field["children"] = list(node["options"].keys())
    if "required" in node:
        field["required"] = bool(node["required"])
    field["spans"] = _spans(node["v_range"]) if node.get("v_range") else [list(s) for s in endpoint_spans]
    return field


def _faz_endpoint(module: str, tree: ast.Module):
    task = _faz_task_type(tree)
    if task not in _FAZ_CONFIG_TASKS:
        raise ValueError(f"task_type {task!r} is not a configuration object")
    spec = _assignment(tree, "module_arg_spec", module_level=False)
    key = module[len("faz_"):]
    obj = spec.get(key) if isinstance(spec, dict) else None
    if not isinstance(obj, dict):
        raise ValueError("no object key in module_arg_spec")
    urls = _faz_urls(tree)
    if not urls:
        raise ValueError("no JSON-RPC URL")
    if not obj.get("v_range"):
        # Refuse rather than invent "valid everywhere".
        raise ValueError("object has no v_range")
    spans = _spans(obj["v_range"])
    options = obj.get("options") if isinstance(obj.get("options"), dict) else {}
    fields = {fname: _faz_field(fnode, spans) for fname, fnode in options.items()
              if isinstance(fnode, dict)}
    urn = urls[0]
    endpoint = {
        "urn": urn,
        "section": urn.lstrip("/").split("/")[0],
        "rows": None,
        "spans": spans,
        "fields": fields,
    }
    return key, endpoint, obj


def _fortianalyzer_doc(path: str, manifest: dict) -> dict:
    endpoints, skipped, versions = {}, [], set()
    files = _module_files(path, "faz_")
    for module, fpath in files:
        if module in _FAZ_SKIP_NAMES:
            reason = _FAZ_SKIP_NAMES[module]
        elif module.startswith("faz_cli_exec_"):
            reason = "CLI exec action"
        else:
            try:
                tree = _parse(fpath)
                logical, endpoint, obj = _faz_endpoint(module, tree)
                found = set()
                _collect_versions(obj, found)
                endpoints[logical] = endpoint
                versions |= found
                continue
            except (ValueError, SyntaxError) as exc:
                reason = str(exc)
        skipped.append({"module": module, "reason": reason})
    return _document("fortianalyzer", path, manifest, files, endpoints, skipped, versions)


# ---------------------------------------------------------------------------
# document assembly + entry point
# ---------------------------------------------------------------------------

def _reason_bucket(reason: str) -> str:
    # ``task_type 'exec' ...`` and ``cannot derive cmdb path (3 ...)`` vary in
    # their detail; the count table groups by the stable prefix.
    return reason.split(" (")[0]


def _document(product, path, manifest, files, endpoints, skipped, versions) -> dict:
    ordered = sorted(versions, key=version_key)
    return {
        "product": product,
        "source": "vendor_doc",
        "captured_at": _release_date(path, manifest["version"]) or _now(),
        "origin_ref": f"ansible:{manifest['namespace']}.{manifest['name']}:{manifest['version']}",
        "device": None,
        "scope": {"kind": "spans", "versions": ordered},
        "healthy": True,
        "skip_reason": "",
        "endpoints": dict(sorted(endpoints.items())),
        "summary": {
            "collection": f"{manifest['namespace']}.{manifest['name']}",
            "collection_version": manifest["version"],
            # The cap for open-ended spans: the newest build this collection
            # has any opinion on.
            "max_version": ordered[-1] if ordered else None,
            "min_version": ordered[0] if ordered else None,
            "modules_total": len(files),
            "endpoints": len(endpoints),
            "fields": sum(len(e["fields"] or {}) for e in endpoints.values()),
            "skipped_count": len(skipped),
            "skipped_by_reason": dict(Counter(_reason_bucket(s["reason"]) for s in skipped)),
            "skipped": skipped,
        },
    }


# (namespace, name) -> builder. fortinet.fortiweb / fortinet.fortiadc are
# absent on purpose: they carry no version ranges (see module docstring).
_BUILDERS = {
    ("fortinet", "fortios"): _fortios_doc,
    ("fortinet", "fortianalyzer"): _fortianalyzer_doc,
}


def evidence_from_ansible_collection(path: str) -> list[dict]:
    """Evidence documents for the extracted collection at ``path``.

    Returns one document for a supported collection and ``[]`` for a
    collection that carries no version data. Raises ValueError when ``path``
    is not a collection at all -- that is an operator mistake, not "no data".
    """
    manifest = _read_manifest(path)
    builder = _BUILDERS.get((manifest["namespace"], manifest["name"]))
    if builder is None:
        return []
    return [builder(path, manifest)]
