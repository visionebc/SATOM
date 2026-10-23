"""Installed software, per node — Settings > General > Installed software.

Answers one question for an operator or an auditor: "what does this SATOM run
on, and which version of each piece is installed?" Three lists:

* Platform components -- the OS packages the installer puts down
  (``installers/install-satom.sh`` ``REQUIRED_PKGS`` / ``SSH_PKGS``) plus the
  pieces SATOM installs itself (VictoriaMetrics) or uses when present (Redis,
  Lua). Each row carries the version the BINARY reports and, separately, the
  version the distro PACKAGE MANAGER has on record: the first is what runs,
  the second is what a security advisory names (``1.22.1`` vs
  ``1.22.1-9+deb12u9``).
* Python packages -- every distribution in the interpreter that runs the app
  (the venv), not a curated subset; ``direct`` marks what requirements.txt
  asks for, the rest are transitive.
* Browser assets -- ``app/static/vendor/MANIFEST.json``, the single record of
  every third-party file the console serves.

Read-only by construction: fixed argv, no shell, short timeouts. A probe that
fails says "not found" -- it never invents a version. Per node, because a
standby can lag its primary: the peer answers over the node-to-node channel
(``/settings/peer/software-inventory``) and a silent peer is shown as
unreachable, never as "same as here".

Versions of everything installed are reconnaissance data, so the route is
admin-only (USER_MANAGE), like the System packages card.
"""
from __future__ import annotations

import fnmatch
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import time
from importlib import metadata as _meta
from pathlib import Path

from . import self_update as su

REPO = Path(__file__).resolve().parents[2]
REQUIREMENTS = REPO / "requirements.txt"
VENDOR_MANIFEST = REPO / "app" / "static" / "vendor" / "MANIFEST.json"
PEER_PATH = "/settings/peer/software-inventory"

# nginx, sshd & co. live in sbin, which is not on the app user's PATH.
_SEARCH_PATH = os.pathsep.join([os.environ.get("PATH", ""), "/usr/local/sbin",
                                "/usr/local/bin", "/usr/sbin", "/usr/bin",
                                "/sbin", "/bin"])
_PROBE_TIMEOUT = 4
_CACHE_TTL = 60.0
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+(?:[a-z]\d+)?)")

# key -> how to measure it. ``binaries`` are tried in order; ``version_re``
# overrides the generic dotted-number match; ``deb`` / ``rpm`` are package
# name globs, first installed match wins. Order = display order.
COMPONENTS: tuple[dict, ...] = (
    {"key": "python", "label": "Python", "purpose": "Application runtime",
     "probe": "python", "deb": ["python3"],
     "rpm": ["python3.11", "python311", "python3"]},
    {"key": "postgresql", "label": "PostgreSQL server", "purpose": "Database",
     "probe": "database", "deb": ["postgresql-[0-9]*"],
     "rpm": ["postgresql*-server"]},
    {"key": "postgresql-client", "label": "PostgreSQL client",
     "purpose": "pg_dump / psql for backups and restores",
     "binaries": [("pg_dump", ["--version"])],
     "deb": ["postgresql-client-[0-9]*"], "rpm": ["postgresql[0-9][0-9]", "postgresql"]},
    {"key": "nginx", "label": "nginx", "purpose": "TLS front end and reverse proxy",
     "binaries": [("nginx", ["-v"])], "deb": ["nginx"], "rpm": ["nginx"]},
    {"key": "victoria-metrics", "label": "VictoriaMetrics",
     "purpose": "Metrics store (installed by SATOM, not a distro package)",
     "binaries": [("victoria-metrics", ["-version"]),
                  ("victoria-metrics-prod", ["-version"])]},
    {"key": "redis", "label": "Redis", "purpose": "Shared rate-limit and cache store",
     "binaries": [("redis-server", ["--version"])],
     "deb": ["redis-server"], "rpm": ["redis", "redis7"]},
    {"key": "openssl", "label": "OpenSSL", "purpose": "TLS, certificates, PKI",
     "binaries": [("openssl", ["version"])],
     "deb": ["openssl"], "rpm": ["openssl"]},
    {"key": "openssl-python", "label": "OpenSSL (linked by Python)",
     "purpose": "The TLS library the app's own HTTPS calls use",
     "probe": "python_ssl", "deb": ["libssl3*"], "rpm": ["libopenssl3", "openssl-libs"]},
    {"key": "ca-certificates", "label": "CA certificates",
     "purpose": "System trust store", "deb": ["ca-certificates"],
     "rpm": ["ca-certificates"]},
    {"key": "openssh", "label": "OpenSSH client", "purpose": "Device CLI, HA data sync",
     "binaries": [("ssh", ["-V"])],
     "deb": ["openssh-client"], "rpm": ["openssh-clients", "openssh"]},
    {"key": "git", "label": "Git", "purpose": "Code updates and release trust",
     "binaries": [("git", ["--version"])], "deb": ["git"], "rpm": ["git", "git-core"]},
    {"key": "rsync", "label": "rsync", "purpose": "HA data sync to the standby",
     "binaries": [("rsync", ["--version"])], "deb": ["rsync"], "rpm": ["rsync"]},
    {"key": "curl", "label": "curl", "purpose": "Health checks and downloads",
     "binaries": [("curl", ["--version"])], "deb": ["curl"], "rpm": ["curl", "curl-minimal"]},
    {"key": "sudo", "label": "sudo", "purpose": "Privilege drop for maintenance commands",
     "binaries": [("sudo", ["-V"])], "deb": ["sudo"], "rpm": ["sudo"]},
    {"key": "bubblewrap", "label": "bubblewrap", "purpose": "Sandbox for operator Python",
     "binaries": [("bwrap", ["--version"])], "deb": ["bubblewrap"], "rpm": ["bubblewrap"]},
    {"key": "lua", "label": "Lua", "purpose": "Lua Studio syntax check (luac -p)",
     "binaries": [("lua5.4", ["-v"]), ("lua", ["-v"])],
     "deb": ["lua5.4", "lua5.3"], "rpm": ["lua54", "lua"]},
    {"key": "systemd", "label": "systemd", "purpose": "Service manager",
     "binaries": [("systemctl", ["--version"])], "version_re": r"systemd (\d+)",
     "deb": ["systemd"], "rpm": ["systemd"]},
    {"key": "kernel", "label": "Linux kernel", "purpose": "Host kernel (shared with the hypervisor in a container)",
     "probe": "kernel"},
)

_cache: dict = {"at": 0.0, "data": None}


def _first_line(argv: list[str]) -> str:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=_PROBE_TIMEOUT, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    # nginx -v and ssh -V print to stderr
    for stream in (p.stdout, p.stderr):
        for line in (stream or "").splitlines():
            if line.strip():
                return line.strip()[:160]
    return ""


def parse_version(line: str, pattern: str | None = None) -> str:
    """The version number in a ``--version`` line; '' when there is none."""
    if not line:
        return ""
    m = re.search(pattern, line) if pattern else _VERSION_RE.search(line)
    return m.group(1) if m else ""


def _package_manager() -> str:
    if shutil.which("dpkg-query", path=_SEARCH_PATH):
        return "deb"
    if shutil.which("rpm", path=_SEARCH_PATH):
        return "rpm"
    return ""


def _installed_packages(family: str, patterns: list[str]) -> dict[str, str]:
    """name -> version for the installed packages matching any glob."""
    if not family or not patterns:
        return {}
    if family == "deb":
        argv = ["dpkg-query", "-W",
                "-f=${db:Status-Abbrev}|${Package}|${Version}\n"] + patterns
    else:
        argv = ["rpm", "-qa", "--qf", "%{NAME}|%{VERSION}-%{RELEASE}\n"] + patterns
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=_PROBE_TIMEOUT * 2, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[str, str] = {}
    for line in (p.stdout or "").splitlines():
        parts = line.split("|")
        if family == "deb":
            # dpkg lists removed-but-configured and never-installed names too
            if len(parts) != 3 or not parts[0].startswith("ii"):
                continue
            name, ver = parts[1], parts[2]
        else:
            if len(parts) != 2:
                continue
            name, ver = parts
        if name and ver:
            out[name] = ver
    return out


def _match_package(globs: list[str], installed: dict[str, str]) -> tuple[str, str]:
    for g in globs:
        hits = sorted(n for n in installed if fnmatch.fnmatchcase(n, g))
        if hits:
            return hits[-1], installed[hits[-1]]
    return "", ""


def _probe(comp: dict) -> dict:
    """Binary-side facts for one component: found / version / raw line."""
    kind = comp.get("probe")
    if kind == "python":
        return {"found": True, "version": platform.python_version(),
                "detail": "%s %s" % (platform.python_implementation(),
                                     platform.python_version())}
    if kind == "python_ssl":
        return {"found": True, "version": parse_version(ssl.OPENSSL_VERSION),
                "detail": ssl.OPENSSL_VERSION}
    if kind == "kernel":
        return {"found": True, "version": platform.release(),
                "detail": platform.version()[:160]}
    if kind == "database":
        from . import system_info
        db = system_info._database()  # noqa: SLF001 -- one measurement, one place
        ver = db.get("version") or ""
        if ver == "unknown":
            ver = ""
        return {"found": bool(ver), "version": ver,
                "detail": "%s %s" % (db.get("engine", ""), ver)}
    for name, args in comp.get("binaries") or []:
        path = shutil.which(name, path=_SEARCH_PATH)
        if not path:
            continue
        line = _first_line([path] + list(args))
        return {"found": True, "version": parse_version(line, comp.get("version_re")),
                "detail": line, "path": path}
    return {"found": False, "version": "", "detail": ""}


def _components() -> list[dict]:
    family = _package_manager()
    globs = sorted({g for c in COMPONENTS for g in (c.get(family) or [])})
    installed = _installed_packages(family, globs)
    rows = []
    for comp in COMPONENTS:
        row = {"key": comp["key"]}
        row.update(_probe(comp))
        pkg, pver = _match_package(comp.get(family) or [], installed)
        row["package"], row["package_version"] = pkg, pver
        # A package on record but no binary on this host still counts as
        # installed (ca-certificates has no binary at all).
        row["found"] = bool(row.get("found") or pkg)
        rows.append(row)
    return rows


def _req_name(line: str) -> str:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return ""
    m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line)
    return _norm(m.group(0)) if m else ""


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_requirements() -> set[str]:
    try:
        text = REQUIREMENTS.read_text(encoding="utf-8")
    except OSError:
        return set()
    return {n for n in (_req_name(ln) for ln in text.splitlines()) if n}


def _python_packages() -> list[dict]:
    direct = direct_requirements()
    seen: dict[str, dict] = {}
    for dist in _meta.distributions():
        try:
            name = dist.metadata["Name"] or ""
            ver = dist.version or ""
        except Exception:  # noqa: BLE001 -- a broken dist-info must not hide the rest
            continue
        if not name:
            continue
        key = _norm(name)
        if key in seen:
            continue
        seen[key] = {"name": name, "version": ver, "direct": key in direct}
    return sorted(seen.values(), key=lambda r: r["name"].lower())


def browser_assets() -> list[dict]:
    try:
        data = json.loads(VENDOR_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [{"name": a.get("name", ""), "version": a.get("version", ""),
             "license": a.get("license", "")}
            for a in data.get("assets") or [] if a.get("name")]


def local_inventory(refresh: bool = False) -> dict:
    """THIS node's inventory. Cached briefly: ~20 probes per page view is
    cheap, but not per worker per refresh click."""
    now = time.monotonic()
    if not refresh and _cache["data"] is not None and now - _cache["at"] < _CACHE_TTL:
        return _cache["data"]
    from . import system_info
    data = {"os": system_info._os_label(),  # noqa: SLF001
            "machine": platform.machine(),
            "package_manager": _package_manager() or "none",
            "components": _components(),
            "python": _python_packages()}
    _cache.update(at=now, data=data)
    return data


def _peer_inventory(host: str) -> dict:
    from . import node_security as nsec
    try:
        st, raw, _secure = nsec.peer_get(host, PEER_PATH, timeout=su._PEER_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}
    if st is None:
        return {"reachable": False, "error": nsec.unreachable_detail(host)}
    ans = su._peer_answer(raw)
    inv = ans.get("inventory") if isinstance(ans, dict) else None
    if not (200 <= int(st) < 300) or not isinstance(inv, dict) \
            or not isinstance(inv.get("components"), list) \
            or not isinstance(inv.get("python"), list):
        return {"reachable": False, "error": "HTTP %s" % st}
    upd = ans.get("updates")
    return {"reachable": True, "error": None, "role": ans.get("role"),
            "inventory": inv, "updates": upd if isinstance(upd, dict) else None}


_UNKNOWN = object()


def _differs(values: list) -> bool:
    """True when the reachable nodes disagree. A node that lacks the item
    counts as a difference; an unreachable node is not evidence either way."""
    seen = {v for v in values if v is not _UNKNOWN}
    return len(seen) > 1


def overview(refresh: bool = False) -> dict:
    """Every node x every component and Python package, for the card."""
    from . import system_packages as sp
    nodes = [{"name": su.this_node_name(), "self": True, "role": su.node_role(),
              "reachable": True, "error": None,
              "inventory": local_inventory(refresh=refresh),
              "updates": sp.latest_check()}]
    for n in su.peer_nodes():
        rep = _peer_inventory(n["host"])
        nodes.append({"name": n.get("name"), "self": False,
                      "role": rep.get("role"), "reachable": rep["reachable"],
                      "error": rep.get("error"),
                      "inventory": rep.get("inventory") or {},
                      "updates": rep.get("updates")})

    by_node_comp = {nd["name"]: {c.get("key"): c for c in
                                 (nd["inventory"].get("components") or [])
                                 if isinstance(c, dict)}
                    for nd in nodes}
    components = []
    for comp in COMPONENTS:
        per = {}
        vals = []
        for nd in nodes:
            if not nd["reachable"]:
                per[nd["name"]] = None
                vals.append(_UNKNOWN)
                continue
            row = dict(by_node_comp[nd["name"]].get(comp["key"]) or {"found": False})
            avail = ((nd.get("updates") or {}).get("available") or {}).get(comp["key"])
            if isinstance(avail, dict):
                newer = {n: v.get("candidate") for n, v in
                         (avail.get("packages") or {}).items()
                         if isinstance(v, dict) and v.get("candidate")}
                row["update"] = {"available": bool(avail.get("upgradable")),
                                 "packages": newer}
            per[nd["name"]] = row
            vals.append((row.get("version") or "", row.get("package_version") or "")
                        if row.get("found") else None)
        components.append({"key": comp["key"], "label": comp["label"],
                           "purpose": comp["purpose"], "nodes": per,
                           "differs": _differs(vals),
                           "upgradable": comp["key"] in sp.UPGRADABLE,
                           "impact": sp.UPGRADABLE.get(comp["key"], "")})

    by_node_py = {nd["name"]: {_norm(p.get("name", "")): p for p in
                               (nd["inventory"].get("python") or [])
                               if isinstance(p, dict) and p.get("name")}
                  for nd in nodes}
    names: dict[str, str] = {}
    for nd in nodes:
        for key, p in by_node_py[nd["name"]].items():
            names.setdefault(key, p["name"])
    direct = direct_requirements()
    python = []
    for key in sorted(names, key=lambda k: names[k].lower()):
        per = {}
        vals = []
        for nd in nodes:
            if not nd["reachable"]:
                per[nd["name"]] = None
                vals.append(_UNKNOWN)
                continue
            p = by_node_py[nd["name"]].get(key)
            per[nd["name"]] = p.get("version") if p else ""
            vals.append(p.get("version") if p else None)
        python.append({"name": names[key], "direct": key in direct,
                       "nodes": per, "differs": _differs(vals)})

    return {
        "nodes": [{"name": nd["name"], "self": nd["self"], "role": nd["role"],
                   "reachable": nd["reachable"], "error": nd["error"],
                   "os": nd["inventory"].get("os", ""),
                   "machine": nd["inventory"].get("machine", ""),
                   "package_manager": nd["inventory"].get("package_manager", ""),
                   "checked_at": (nd.get("updates") or {}).get("checked_at"),
                   "index_refreshed": (nd.get("updates") or {}).get("index_refreshed")}
                  for nd in nodes],
        "components": components,
        "python": python,
        "assets": browser_assets(),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
