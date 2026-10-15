"""OS packages SATOM itself depends on, and the Install button for them.

Settings > General > System packages. Same split as the Libraries card: the
web worker only ENQUEUES ``{"kind": "syspkg"}`` into ``data/update-requests/``;
the privileged runner (``deploy/self_update_runner.py``, as root) installs.

The list is CURATED and short on purpose. An "install any package" button on
a root runner fed by the web account is a root shell with extra steps; a
package reaches this table only when the product needs it. The runner keeps
its own copy of the table ([SATOM-RUNNER-NO-APP-IMPORT]) and
``tests/test_system_packages.py`` asserts the two are equal.

Install only, never remove: everything here is a dependency the product fails
closed without (no bubblewrap = no hook, no console, no script runs).

Per node, because OS packages are node-local: the card shows every registered
node, and "Install" can fan out to the peer over the node-to-node channel the
Libraries card already uses. A peer only ever receives a package KEY, which it
re-checks against its own table.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime

from . import self_update as su

# key -> what the card shows and how presence is measured. The distro package
# names live in the runner (it is the one that installs).
PACKAGES: dict[str, dict] = {
    "bubblewrap": {
        "binary": "bwrap",
        "version_args": ["--version"],
        "purpose": ("Sandbox for operator Python: integration hooks, the "
                    "Python console and Script Library. Without it that code "
                    "is refused, never run unconfined."),
        "required": True,
    },
}

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}$")
PEER_STATE_PATH = "/settings/peer/system-packages"
PEER_INSTALL_PATH = "/settings/peer/system-package-install"


def _version(binary_path: str, args: list[str]) -> str:
    try:
        p = subprocess.run([binary_path] + list(args), capture_output=True,
                           text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    out = (p.stdout or p.stderr or "").strip().splitlines()
    return out[0][:80] if out else ""


def _functional(key: str) -> tuple[bool, str]:
    """Installed is not enough: bubblewrap also needs the kernel to let this
    user create namespaces (an LXC or a sysctl can forbid it). Measured by
    running ``true`` in the very jail the product uses."""
    if key != "bubblewrap":
        return True, ""
    from . import sandbox
    with tempfile.TemporaryDirectory(prefix="satom-bwrap-probe-") as work:
        argv = sandbox.jail_argv(["/usr/bin/true"], work)
        if argv is None:
            return False, "bwrap not found"
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)[:200]
    if p.returncode != 0:
        return False, (p.stderr or "exit %s" % p.returncode).strip()[:200]
    return True, ""


def local_state() -> dict[str, dict]:
    """THIS node: per package, installed / version / works."""
    out: dict[str, dict] = {}
    for key, meta in PACKAGES.items():
        path = shutil.which(meta["binary"])
        row = {"installed": bool(path), "version": "", "works": False,
               "detail": ""}
        if path:
            row["version"] = _version(path, meta.get("version_args") or [])
            row["works"], row["detail"] = _functional(key)
        out[key] = row
    return out


def request_install(key: str, by: str, *, origin: str = "system-packages-card") -> str:
    """Enqueue an install of a CURATED package on this node. Returns the id."""
    from .. import runtime
    runtime.require("self_update")
    if runtime.is_container_runtime():
        raise runtime.CapabilityUnavailable("self_update",
                                            runtime.CONTAINER_UPDATE_REDIRECT)
    key = (key or "").strip()
    if not _KEY_RE.match(key) or key not in PACKAGES:
        raise ValueError("%r is not a curated system package" % key)
    su.REQ_DIR.mkdir(parents=True, exist_ok=True)
    su.STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    now = datetime.utcnow().isoformat() + "Z"
    req = {"id": uid, "kind": "syspkg", "package": key, "action": "install",
           "requested_by": by, "requested_at": now,
           "node": su.this_node_name(), "role": su.node_role(), "origin": origin}
    (su.STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "syspkg",
        "package": key, "action": "install", "requested_by": by,
        "node": req["node"], "role": req["role"], "origin": origin,
        "updated_at": now}))
    tmp = su.REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(su.REQ_DIR / (uid + ".json"))
    return uid


def request_install_on_peers(key: str, by: str) -> list[dict]:
    """Ask every peer to enqueue the same install on itself.

    ``queued`` / ``rejected`` / ``unreachable`` per peer, exactly as the
    Libraries fan-out: not knowing is never shown as done."""
    from . import node_security as nsec
    body = json.dumps({"package": key, "requested_by": by,
                       "origin_node": su.this_node_name()}).encode()
    out: list[dict] = []
    for n in su.peer_nodes():
        row = {"node": n.get("name"), "host": n.get("host"), "uid": None,
               "error": None}
        try:
            st, raw, _secure = nsec.peer_post(n["host"], PEER_INSTALL_PATH, body,
                                              timeout=su._PEER_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            out.append({**row, "state": "unreachable", "error": str(exc)})
            continue
        if st is None:
            out.append({**row, "state": "unreachable",
                        "error": nsec.unreachable_detail(n["host"])})
            continue
        ans = su._peer_answer(raw)
        if ans is None:
            out.append({**row, "state": "unreachable",
                        "error": "HTTP %s with an unreadable body" % st})
        elif 200 <= int(st) < 300 and ans.get("uid"):
            out.append({**row, "state": "queued", "uid": ans["uid"]})
        else:
            out.append({**row, "state": "rejected",
                        "error": ans.get("error") or "HTTP %s" % st})
    return out


def _peer_state(host: str) -> dict:
    from . import node_security as nsec
    try:
        st, raw, _secure = nsec.peer_get(host, PEER_STATE_PATH,
                                         timeout=su._PEER_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc), "packages": {}}
    if st is None:
        return {"reachable": False, "packages": {},
                "error": nsec.unreachable_detail(host)}
    ans = su._peer_answer(raw)
    if not (200 <= int(st) < 300) or ans is None \
            or not isinstance(ans.get("packages"), dict):
        return {"reachable": False, "packages": {}, "error": "HTTP %s" % st}
    return {"reachable": True, "packages": ans["packages"],
            "role": ans.get("role"), "error": None}


def overview() -> dict:
    """Every node x every curated package, for the card.

    A peer that did not answer contributes no state and is shown as
    unreachable -- never as "installed"."""
    nodes = [{"name": su.this_node_name(), "self": True, "role": su.node_role(),
              "reachable": True, "error": None, "packages": local_state()}]
    for n in su.peer_nodes():
        rep = _peer_state(n["host"])
        nodes.append({"name": n.get("name"), "self": False,
                      "role": rep.get("role"), "reachable": rep["reachable"],
                      "error": rep.get("error"), "packages": rep["packages"]})
    rows = []
    for key, meta in PACKAGES.items():
        per = {nd["name"]: (nd["packages"].get(key) if nd["reachable"] else None)
               for nd in nodes}
        rows.append({"package": key, "purpose": meta["purpose"],
                     "required": meta["required"], "nodes": per,
                     "ok": all(v and v.get("works") for v in per.values())})
    return {"nodes": [{k: nd[k] for k in ("name", "self", "role", "reachable", "error")}
                      for nd in nodes],
            "packages": rows, "ok": all(r["ok"] for r in rows)}
