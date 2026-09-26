"""Container operations -- the web half of the Docker operations agent.

Mirror of the host model (``service_control`` + ``satom-updater``): this module
only ENQUEUES. It writes a JSON request into ``data/update-requests/`` and a
``queued`` row into ``data/update-status/``; in a container with the agent
overlay both paths are volumes shared with the ``agent`` service
(``deploy/docker/compose.agent.yaml``), which re-validates every request
against its own copy of the allowlist and does the work.

The allowlist exists twice on purpose -- here, so the UI only offers what the
agent will accept, and in ``deploy/docker/satom_agent.py``, which is the
security boundary and must not import this package.
``tests/test_container_ops.py`` fails if the two drift, and feeds every request
this module writes through the agent's own validator.

Nothing here talks to the Docker engine. The web container has no socket and
never will: that is the boundary the agent exists to keep.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime

from .. import runtime

#: service -> (actions, label, note). Same actions as the agent's
#: SERVICE_POLICY; same rules as the host table in service_control: nothing
#: that removes the only way to undo it is ever stoppable.
POLICY: dict[str, dict] = {
    "web": {"actions": ("restart",), "label": "Web application",
            "note": "Gunicorn serving this console. Restart only — a stop would "
                    "take away the page that could start it again."},
    "scheduler": {"actions": ("start", "stop", "restart"), "label": "Scheduler",
                  "note": "Fires scheduled actions. Primary-only by role guard."},
    "cron": {"actions": ("start", "stop", "restart"), "label": "Periodic jobs",
             "note": "The container stand-in for the host's systemd timers "
                     "(alerts, certificate renewal pass, sweeps)."},
    "proxy": {"actions": ("restart",), "label": "TLS proxy (nginx)",
              "note": "Terminates TLS in front of the app. Restart only — a stop "
                      "ends this session with no way back except a shell."},
    "postgres": {"actions": ("restart",), "label": "PostgreSQL",
                 "note": "Restart recycles the database; the app reconnects. "
                         "Never stopped from here."},
    "redis": {"actions": ("restart",), "label": "Redis (rate limits)",
              "note": "Derivable state only: a restart resets rate-limit windows."},
    "victoria-metrics": {"actions": ("restart",), "label": "Metrics store",
                         "note": "While it is down, dashboards report query errors."},
}
FORBIDDEN = ("agent", "tls-init")
ACTIONS = ("start", "stop", "restart")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\Z")
#: How long a certificate install waits for the agent before answering. An
#: import is seconds of work plus a proxy restart; the callers (Node
#: certificate page, autopull) expect an answer, not a ticket.
CERT_WAIT_SECONDS = 90


class AgentUnavailable(RuntimeError):
    """Raised when a request cannot be queued because no live agent exists."""


def allowed(service: str, action: str) -> bool:
    if not service or not action or service in FORBIDDEN:
        return False
    entry = POLICY.get(service)
    return bool(entry) and action in entry["actions"]


def state() -> dict:
    """What the Container operations page renders."""
    return runtime.agent_state()


def _require_agent(capability: str) -> None:
    if not runtime.delegated(capability):
        raise AgentUnavailable(runtime.unavailable_reason(capability)
                               or "the operations agent is not available")


def _enqueue(kind: str, body: dict, by: str, origin: str, target: str,
             extra_status: dict | None = None) -> str:
    """Write the ``queued`` status row, then the request -- same order and
    same atomic rename as the host enqueues (self_update.request_update)."""
    from . import self_update as su  # queue paths live in exactly one module
    su.REQ_DIR.mkdir(parents=True, exist_ok=True)
    su.STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    node, role = su.this_node_name(), su.node_role()
    req = {"id": uid, "kind": kind, "requested_by": by,
           "requested_at": datetime.utcnow().isoformat() + "Z",
           "node": node, "role": role, "origin": origin, **body}
    row = {"id": uid, "state": "queued", "steps": [], "kind": kind,
           "runner": "container-agent", "target": target,
           "requested_by": by, "node": node, "role": role, "origin": origin,
           "updated_at": datetime.utcnow().isoformat() + "Z"}
    row.update(extra_status or {})
    (su.STATUS_DIR / (uid + ".json")).write_text(json.dumps(row))
    tmp = su.REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(su.REQ_DIR / (uid + ".json"))
    return uid


def request_restart(service: str, action: str, by: str,
                    origin: str = "container-ops") -> str:
    _require_agent("service_control")
    service = (service or "").strip()
    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise ValueError("action must be one of %s" % ", ".join(ACTIONS))
    if not allowed(service, action):
        raise ValueError("%s is not allowed on %r from this console" % (action, service))
    return _enqueue("ctr-restart", {"service": service, "action": action}, by,
                    origin, service, {"unit": service, "action": action})


def request_update(version: str, by: str, origin: str = "container-ops") -> str:
    _require_agent("self_update")
    version = (version or "").strip().lstrip("v")
    if not VERSION_RE.match(version):
        raise ValueError("version must be X.Y.Z")
    return _enqueue("ctr-update", {"version": version}, by, origin, version)


def request_cert(cert_pem: bytes | str, key_pem: bytes | str,
                 chain_pem: bytes | str | None, by: str,
                 origin: str = "node-cert") -> str:
    _require_agent("cert_activation")

    def _t(v):
        return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else (v or "")
    body = {"cert_pem": _t(cert_pem), "key_pem": _t(key_pem)}
    if chain_pem:
        body["chain_pem"] = _t(chain_pem)
    # The key travels in the REQUEST (consumed and deleted by the agent), never
    # in the status row the UI lists.
    return _enqueue("ctr-cert", body, by, origin, "proxy certificate")


def wait(uid: str, timeout: float, poll: float = 1.0) -> dict:
    """Poll a request's status row until it is final or *timeout* passes."""
    from . import self_update as su
    deadline = time.monotonic() + timeout
    st: dict = {}
    while time.monotonic() < deadline:
        st = su.update_status(uid) or {}
        if st.get("state") in ("success", "failed"):
            return st
        time.sleep(poll)
    return st or {"state": "queued"}


def install_cert(cert_pem, key_pem, chain_pem, by: str) -> dict:
    """cert_service._install's container branch: hand the pair to the agent and
    wait for its verdict. Raises RuntimeError with the agent's reason."""
    uid = request_cert(cert_pem, key_pem, chain_pem, by)
    st = wait(uid, CERT_WAIT_SECONDS)
    if st.get("state") == "success":
        return st
    if st.get("state") == "failed":
        raise RuntimeError("the operations agent refused the certificate: %s"
                           % (st.get("error") or "see its log"))
    raise RuntimeError("the operations agent has not finished installing the "
                       "certificate (request %s); check %s" % (uid, runtime.CONTAINER_OPS_PAGE))


def service_rows() -> list[dict]:
    """Container rows in the Services card's shape (service_control.states)."""
    hb = runtime.agent_state()["heartbeat"]
    by_svc: dict[str, list[dict]] = {}
    for c in hb.get("containers") or []:
        by_svc.setdefault(c.get("service", ""), []).append(c)
    out = []
    for svc, entry in POLICY.items():
        cs = by_svc.get(svc, [])
        installed = bool(cs)
        running = installed and all(c.get("state") == "running" for c in cs)
        healthy = running and all(c.get("health") in ("", "healthy") for c in cs)
        active = ("running" if running else
                  (cs[0].get("state") or "unknown") if installed else "")
        health = ", ".join(sorted({c.get("health") for c in cs if c.get("health")}))
        row = {"unit": svc, "label": entry["label"], "note": entry["note"],
               "actions": list(entry["actions"]) if installed else [],
               "installed": installed, "active": active,
               "sub": health, "enabled": "container", "ok": healthy if installed else None,
               "image": cs[0].get("image", "") if cs else ""}
        row["available"] = available_actions(svc, running, installed)
        out.append(row)
    return out


def available_actions(service: str, running: bool, installed: bool = True) -> list[str]:
    """Presentation only, like service_control.available_actions: a running
    service offers restart/stop, a stopped one start -- or restart where
    restart is its only permitted action (restart starts a stopped container)."""
    if not installed:
        return []
    allowed_here = POLICY.get(service, {}).get("actions", ())
    if running:
        return [a for a in ("restart", "stop") if a in allowed_here]
    if "start" in allowed_here:
        return ["start"]
    return [a for a in ("restart",) if a in allowed_here]


def health_rows() -> list[dict]:
    """system_health.service_status's container branch."""
    hb = runtime.agent_state()["heartbeat"]
    out = []
    for c in hb.get("containers") or []:
        state = c.get("state") or "unknown"
        h = c.get("health") or ""
        out.append({"unit": "%s (container)" % (c.get("service") or c.get("name")),
                    "state": state + ("/" + h if h else ""),
                    "ok": state == "running" and h in ("", "healthy"),
                    "installed": True})
    return out


def versions() -> dict:
    """Releases the agent can switch to, and what the stack runs now."""
    hb = runtime.agent_state()["heartbeat"]
    vs = hb.get("versions") or {}

    def _key(v):
        return tuple(int(x) for x in v.split("."))
    rows = [{"version": v, "image": bool(d.get("image")), "tree": bool(d.get("tree"))}
            for v, d in vs.items() if VERSION_RE.match(v)]
    rows.sort(key=lambda r: _key(r["version"]), reverse=True)
    cfg = hb.get("configured_image") or hb.get("stack_image") or ""
    return {"rows": rows, "current": cfg.split(":", 1)[1] if ":" in cfg else cfg,
            "layout": hb.get("layout", ""), "agent_version": hb.get("agent_version", "")}


def served_cert_pem() -> tuple[bytes | None, str]:
    """The certificate the proxy serves, as forwarded by the agent."""
    c = (runtime.agent_state()["heartbeat"].get("cert") or {})
    pem = c.get("pem") or ""
    if not pem or "PRIVATE KEY" in pem:
        return None, c.get("source", "")
    return pem.encode(), c.get("source", "")


def recent(limit: int = 15) -> list[dict]:
    from . import self_update as su
    return [r for r in su.recent_updates(limit=limit * 2)
            if r.get("runner") == "container-agent"
            or str(r.get("kind", "")).startswith("ctr-")][:limit]
