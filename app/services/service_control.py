"""Service control — start/stop/restart the units this node runs.

The web worker runs as the unprivileged service account and CANNOT touch
systemd. ``/etc/sudoers.d/satom`` grants exactly two commands (``nginx -t`` and
``systemctl reload nginx``) and a generic ``systemctl`` grant was rejected on
purpose: ``systemctl start <anything>`` reaches every unit on the box, so it IS
root, just spelled differently (``docs/privilege-model.md``).

So this module never runs systemctl for a state change. It ENQUEUES a JSON
request that the privileged runner (``satom-updater.path`` ->
``satom-updater.service``) applies, exactly like the curated pip path. Reads are
different: ``systemctl show`` / ``is-active`` answer any user, so rendering the
card costs nothing and opens no privileged path -- a page load never enqueues.

Five rules hold this together.

1. **The allowlist is a table, not a free-text unit name.** A request names a
   unit and an action that must BOTH appear in ``POLICY``, and the runner keeps
   its own copy and re-validates (defence in depth, mirroring the curated pip
   allowlist). ``tests/test_service_control.py`` fails if the two drift.

2. **``satom-updater`` is absent on purpose.** It IS the runner. Stopping it
   means no future request can ever be processed -- including the request to
   start it again -- so the card would brick its own escalation path while
   reporting success. Restarting it kills whatever it is applying mid-flight.

3. **No action may remove the only way to undo it.** ``stop`` is withheld from
   ``satom.service`` (the console you are clicking in), from ``nginx`` (the
   front that serves it) and from ``postgresql`` (without it the app cannot
   even record what happened). All three would leave recovery possible only
   from a shell, and this page exists precisely for the operator who has the
   browser and not the shell. ``restart`` is offered instead: same diagnostic
   value, lands back in a running state.

4. **Restarting the web is fire-and-forget.** Restarting ``satom.service`` kills
   the worker handling the click, so the HTTP response can never carry the
   outcome. The request is queued, the id comes back immediately, and the
   browser polls the status file -- which the ROOT runner writes, not the web
   worker, so it survives the worker dying. That asymmetry is the only reason
   a self-restart button can be honest about its result.

5. **Every row names its node.** ``systemctl`` is node-local, so an HA pair has
   no single "the services" -- each node has its own set, in its own state. The
   card therefore renders one section PER NODE and a peer's row is reached
   through the peer's OWN web endpoint, which re-validates against its OWN copy
   of this table before enqueueing for its OWN runner. Only a unit name and an
   action ever cross the wire; a peer holding a valid identity key still cannot
   make this node do something this node does not permit. The node name is
   repeated in the section header, the confirm dialog and the log line, because
   "which box did I just restart" is the one question this card must never
   leave ambiguous.

Nothing here enables or disables a unit. ``start``/``stop`` are runtime-only, so
a unit stopped from this page comes back at the next boot -- a stop that
self-heals is the safer default, and the card prints the boot state next to the
live state so that is visible rather than surprising. Changing what a node arms
at boot is a durable decision that belongs to the installer and the CLI.
"""
from __future__ import annotations

import json
import re
import subprocess
import uuid
from datetime import datetime

#: Unit name shape. Anchored, and deliberately narrow: no slashes, no spaces,
#: no shell metacharacters. The table lookup below is the real gate -- this is
#: the belt that makes a malformed name fail loudly instead of reaching a
#: lookup with something exotic in it.
UNIT_RE = re.compile(r"^[A-Za-z0-9@:._-]+\.(service|timer|path)$")

#: Every action this module will ever emit. The runner refuses anything else.
ACTIONS = ("start", "stop", "restart")

#: unit -> (allowed actions, one-line purpose). See the module docstring for
#: why the restricted entries are restricted; the reasons are load-bearing, not
#: conservatism. Adding a unit here is a privilege decision: whatever lands in
#: this table becomes something a console admin can do to this host as root.
POLICY: dict[str, dict] = {
    "satom.service": {
        "actions": ("restart",),
        "label": "Web application",
        "note": "Gunicorn workers serving this console. Restart only — a stop "
                "from here would take away the page that could start it again.",
    },
    "satom-scheduler.service": {
        "actions": ("start", "stop", "restart"),
        "label": "Scheduler",
        "note": "Fires scheduled actions. Primary-only by role guard; inert "
                "on a standby even while running.",
    },
    "satom-reconciler.service": {
        "actions": ("start", "stop", "restart"),
        "label": "HA reconciler",
        "note": "Pulls the repo and stages self-updates. Stop it to pin this "
                "node at its current commit.",
    },
    "satom-metrics.service": {
        "actions": ("start", "stop", "restart"),
        "label": "Metrics store",
        "note": "Local time-series store. While it is down, Analytics boards "
                "and Collection report query errors.",
    },
    "satom-alerts.timer": {
        "actions": ("start", "stop", "restart"),
        "label": "Alert engine (timer)",
        "note": "Evaluates the alert signals every 15 minutes. Stopping it "
                "silences e-mail and the bell.",
    },
    "satom-cert-renew.timer": {
        "actions": ("start", "stop", "restart"),
        "label": "Certificate renewal (timer)",
        "note": "Nightly renewal pass for a CA-issued node certificate.",
    },
    "satom-ha-datasync.timer": {
        "actions": ("start", "stop", "restart"),
        "label": "HA data sync (timer)",
        "note": "Standby pulls data/ from the primary every 5 minutes. "
                "Role-guarded and inert on a primary.",
    },
    "nginx.service": {
        "actions": ("start", "restart"),
        "label": "Web front (nginx)",
        "note": "Terminates TLS in front of the app. Restart only — a stop "
                "ends this session with no way back except a shell.",
    },
    "postgresql.service": {
        "actions": ("restart",),
        "label": "PostgreSQL",
        "note": "Restart recycles the cluster; the app's pool reconnects and "
                "the runner verifies health afterwards. Never stopped from here.",
    },
}

#: Units the runner must refuse even if some future edit lists them. Rule 2 is
#: the one that fails silently and unrecoverably, so it gets an explicit deny
#: rather than relying on absence from the table.
FORBIDDEN = ("satom-updater.service", "satom-updater.path")


def allowed(unit: str, action: str) -> bool:
    """Single source of truth for 'may this request exist at all'."""
    if not unit or not action:
        return False
    if unit in FORBIDDEN or not UNIT_RE.match(unit):
        return False
    entry = POLICY.get(unit)
    return bool(entry) and action in entry["actions"]


def _show(unit: str, prop: str) -> str:
    """One ``systemctl show`` property, or '' when it cannot be read.

    Read-only and unprivileged: this is why the card renders without touching
    the runner at all.
    """
    try:
        r = subprocess.run(["systemctl", "show", "-p", prop, "--value", unit],
                           capture_output=True, text=True, timeout=5)
        return (r.stdout or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def states() -> list[dict]:
    """Live state of every controllable unit, in table order.

    ``is-active`` answers ``inactive`` for a unit that does not exist on this
    host, which is indistinguishable from a unit that exists and is stopped --
    and those are opposite findings. ``LoadState`` tells them apart, so a unit
    that is simply not installed on this node (``satom-ha-datasync.timer`` on a
    standalone install) comes back neutral with no buttons, never as a red
    'stopped' the operator would try to fix.
    """
    out = []
    for unit, entry in POLICY.items():
        installed = _show(unit, "LoadState") != "not-found"
        row = {
            "unit": unit,
            "label": entry["label"],
            "note": entry["note"],
            "actions": list(entry["actions"]) if installed else [],
            "installed": installed,
            "active": "",
            "sub": "",
            "enabled": "",
            "ok": None,
        }
        if installed:
            row["active"] = _show(unit, "ActiveState") or "unknown"
            row["sub"] = _show(unit, "SubState")
            row["enabled"] = _show(unit, "UnitFileState")
            # A timer that is 'waiting' and a service that is 'running' are both
            # healthy; 'exited' is healthy for the Debian postgresql meta-unit,
            # which starts the cluster and leaves. Only failed/inactive is bad.
            row["ok"] = row["active"] in ("active", "activating")
        # `actions` stays the PERMITTED set (the endpoint gate, and what the
        # runner re-validates). `available` is what to draw right now.
        row["available"] = available_actions(unit, row["active"], installed)
        out.append(row)
    return out


#: States systemd reports for a unit that is up or on its way up.
#: ``deactivating`` counts as running on purpose: a stop is already in flight,
#: so Start is the wrong button to offer and Stop/Restart are the honest ones.
RUNNING_STATES = ("active", "activating", "reloading", "deactivating")


def available_actions(unit: str, active: str, installed: bool = True) -> list[str]:
    """The actions worth OFFERING for a unit currently in state ``active``.
    [SATOM-SERVICE-AVAILABLE]

    Deliberately NOT the same thing as ``POLICY[unit]["actions"]``, and the
    difference is the whole point:

    * ``POLICY`` is a **privilege** decision -- what a console admin may ever
      ask this host to do. It gates the endpoint, and the runner keeps its own
      copy and re-validates.
    * this function is a **presentation** decision -- which of those are useful
      right now. It gates nothing.

    Keeping them apart is what makes the race harmless. State is polled, so a
    unit can change between the render and the click. If the endpoint filtered
    on live state too, a button that was legitimately on screen a second ago
    would come back "not allowed" and the operator would conclude the console
    is broken. It does not: a stale Start on a unit that came up meanwhile is a
    systemd no-op, which is the correct outcome for a lost race -- the state
    the operator asked for is the state they get.

    The rule for a unit that is DOWN is the load-bearing one. Some units are
    restart-only by policy (the web console, PostgreSQL -- stopping them
    removes the only way to undo it, rule 3). ``systemctl restart`` on a
    stopped unit STARTS it, so Restart *is* their start path; withholding it
    because the word reads like "already running" would leave a dead unit with
    no button at all, which is precisely the moment the operator needs one.
    """
    if not installed:
        return []
    allowed_here = POLICY.get(unit, {}).get("actions", ())
    if (active or "") in RUNNING_STATES:
        return [a for a in ("restart", "stop") if a in allowed_here]
    if "start" in allowed_here:
        return ["start"]
    return [a for a in ("restart",) if a in allowed_here]


# ---------------------------------------------------------------------------
# Peer fan-out -- the standby's units, reached through the standby's own web
# ---------------------------------------------------------------------------
#: Paths on the PEER. They are the peer's endpoints, not ours; the peer applies
#: its own allowlist behind each one.
PEER_STATE_PATH = "/settings/peer/services"
PEER_ACTION_PATH = "/settings/peer/service-action"
PEER_STATUS_PATH = "/settings/peer/service-status/"
PEER_TIMEOUT = 6.0


def _peer_json(raw):
    """A peer's JSON object, or None when the body is not one.

    An nginx error page, a proxy interstitial or a truncated read must never be
    mistaken for an answer -- "I could not read it" and "it said no" are
    different findings and the card prints them differently.
    """
    import json as _json
    try:
        d = _json.loads((raw or b"").decode("utf-8", "replace") or "{}")
    except Exception:  # noqa: BLE001
        return None
    return d if isinstance(d, dict) else None


def _peer_by_name(node: str):
    """The registered peer row for ``node``, or None. Name -> host resolution
    happens HERE, from the node registry: a host is never taken from the
    browser, so the console cannot be pointed at an arbitrary address."""
    from . import self_update as su
    for n in su.peer_nodes():
        if (n.get("name") or "") == (node or ""):
            return n
    return None


def peer_states() -> list[dict]:
    """One row per registered peer: its units, or why they could not be read.

    ``unreachable`` is never collapsed into "no units" and never into a healthy
    empty list. A peer we cannot read is its own state and has to look like
    one, or the pair drifts while the page implies everything is accounted for.
    """
    from . import node_security as nsec
    from . import self_update as su
    out = []
    for n in su.peer_nodes():
        row = {"node": n.get("name"), "host": n.get("host"), "units": [],
               "role": "", "reachable": False, "secure": None, "error": None}
        try:
            st, raw, secure = nsec.peer_get(n["host"], PEER_STATE_PATH,
                                            timeout=PEER_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 -- any transport fault at all
            row["error"] = str(exc)
            out.append(row)
            continue
        row["secure"] = bool(secure)
        if st is None:
            row["error"] = "no answer on :%d or :%d" % (nsec.HTTPS_PORT,
                                                        nsec.HTTP_PORT)
            out.append(row)
            continue
        ans = _peer_json(raw)
        if ans is None:
            # A 404 here has one realistic cause and it is worth naming: the
            # peer is running a release without these endpoints (a rolling
            # upgrade, mid-flight). "Unreadable body" would send the operator
            # looking at the network instead of at the version.
            row["error"] = ("peer does not expose service control (HTTP 404) — "
                            "it is probably on an older release"
                            if int(st) == 404 else
                            "HTTP %s with an unreadable body" % st)
            out.append(row)
            continue
        if not (200 <= int(st) < 300):
            row["error"] = ans.get("error") or ("HTTP %s" % st)
            out.append(row)
            continue
        row["reachable"] = True
        row["units"] = ans.get("units") or []
        row["role"] = ans.get("role") or ""
        out.append(row)
    return out


def request_service_action_on_peer(node: str, unit: str, action: str,
                                   by: str) -> dict:
    """Ask a registered PEER to enqueue ``action`` on ``unit`` for itself.

    Returns a row with an explicit ``state``:

    * ``queued``      -- the peer accepted it; ITS privileged runner applies it
    * ``rejected``    -- the peer answered and refused (its own allowlist)
    * ``unreachable`` -- no answer, or an answer we cannot read

    Nothing is executed here and nothing is executed on the peer by us: the
    peer's own web re-validates against the peer's own copy of ``POLICY`` and
    hands the work to the peer's own root runner. This node's table is checked
    first anyway -- not as the security boundary (that is the peer's job) but
    so an obviously bad request fails here, with a message, instead of
    consuming a round trip to be refused there.
    """
    import json as _json
    from . import node_security as nsec
    from . import self_update as su

    row = {"node": node, "unit": unit, "action": action, "uid": None,
           "secure": None, "error": None, "state": "rejected"}
    peer = _peer_by_name(node)
    if peer is None:
        row["error"] = "%r is not a registered peer node" % node
        return row
    row["host"] = peer.get("host")
    if not allowed(unit, action):
        row["error"] = "%s is not allowed on %r from this console" % (action, unit)
        return row
    body = _json.dumps({"unit": unit, "action": action,
                        "requested_by": by,
                        "origin_node": su.this_node_name()}).encode()
    try:
        st, raw, secure = nsec.peer_post(peer["host"], PEER_ACTION_PATH, body,
                                         timeout=PEER_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {**row, "state": "unreachable", "error": str(exc)}
    row["secure"] = bool(secure)
    if st is None:
        return {**row, "state": "unreachable",
                "error": "no answer on :%d or :%d" % (nsec.HTTPS_PORT,
                                                      nsec.HTTP_PORT)}
    ans = _peer_json(raw)
    if ans is None:
        return {**row, "state": "unreachable",
                "error": "HTTP %s with an unreadable body" % st}
    if 200 <= int(st) < 300 and ans.get("uid"):
        return {**row, "state": "queued", "uid": ans.get("uid")}
    return {**row, "state": "rejected",
            "error": ans.get("error") or ("HTTP %s" % st)}


def peer_action_status(node: str, uid: str) -> dict:
    """Poll a queued action's status ON the peer that is applying it.

    Without this the peer button would be fire-and-hope: the status file is
    written by the PEER's root runner on the PEER's disk, so this node can only
    learn the outcome by asking. A restart of the standby's web is exactly the
    case where "did it come back?" is the only question that matters, and the
    peer's runner keeps writing that file while the peer's web is down -- so a
    poll that fails mid-restart is expected, not a failure.
    """
    from . import node_security as nsec
    peer = _peer_by_name(node)
    if peer is None:
        return {"state": "unknown", "error": "%r is not a registered peer" % node}
    # Dots are stripped too: a real id never has one, and keeping them lets
    # "../.." survive as "...." -- harmless here only because the receiving
    # side now validates as well. Two narrow checks, neither relying on the
    # other, is the point.
    safe = re.sub(r"[^A-Za-z0-9_-]", "", uid or "")
    if not safe:
        return {"state": "unknown", "error": "bad id"}
    try:
        st, raw, _secure = nsec.peer_get(peer["host"], PEER_STATUS_PATH + safe,
                                         timeout=PEER_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {"state": "polling", "error": str(exc)}
    if st is None:
        # Unreachable mid-restart is the EXPECTED middle of a successful
        # restart, not a verdict. Say "polling", never "failed".
        return {"state": "polling", "error": "peer not answering yet"}
    ans = _peer_json(raw)
    if ans is None:
        return {"state": "polling", "error": "HTTP %s with an unreadable body" % st}
    return ans


def request_service_action(unit: str, action: str, by: str,
                           origin: str = "settings-general") -> str:
    """Enqueue a start/stop/restart for the privileged runner. Returns the id.

    Validates against the same table the runner re-validates against, so a
    forged request can never turn this into ``systemctl <anything> <anything>``.
    Node-local by construction: the runner that picks this up is the one on
    THIS host.
    """
    from . import self_update as su  # queue paths live in exactly one module

    unit = (unit or "").strip()
    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise ValueError("action must be one of %s" % ", ".join(ACTIONS))
    if not allowed(unit, action):
        raise ValueError("%s is not allowed on %r from this console" % (action, unit))

    su.REQ_DIR.mkdir(parents=True, exist_ok=True)
    su.STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    node, role = su.this_node_name(), su.node_role()
    req = {
        "id": uid,
        "kind": "service",
        "unit": unit,
        "action": action,
        "requested_by": by,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "node": node,
        "role": role,
        "origin": origin,
    }
    # Status first: a restart of satom.service can kill this worker between the
    # two writes, and a queued request with no status row is a click that
    # vanished. The reverse order is recoverable -- the runner rewrites it.
    (su.STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "service",
        "unit": unit, "action": action, "target": unit,
        "requested_by": by, "node": node, "role": role, "origin": origin,
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    tmp = su.REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(su.REQ_DIR / (uid + ".json"))
    return uid
