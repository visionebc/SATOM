"""Renewal journal — every certificate renewal attempt, with its error text.

The nightly satom-cert-renew timer used to print its result to stdout and
nothing else: the only trace of a failed renewal was journalctl, and the
only *notification* was the alert e-mail at T-N days. This module persists every
attempt so the UI can show WHAT ran, WHEN, and WHY it failed.

Why a FILE and not a table — deliberate, do not "fix" this into Postgres:

* the standby's Postgres is a **read-only replica**, so the node that fails to
  renew is exactly the node that cannot write a DB row about that failure;
* data/ is not an option either — satom-ha-datasync pulls it with
  rsync --delete, so anything the standby writes under data/ is erased
  within 5 minutes.

So the journal is node-local at /opt/satom/state/cert-renew.jsonl (outside
data/, gitignored) and each node publishes its own over
/healthz/cert-renewals — the same peer-probe pattern as
/healthz/backups — so one page renders both nodes side by side.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

STATE = Path("/opt/satom/state")
JOURNAL = STATE / "cert-renew.jsonl"
MAX_ENTRIES = 400

# channel = which renewal pipeline produced the entry
CH_INTERNAL = "internal-ca"     # re-mint of a CA-issued leaf (renew_if_needed)
CH_AUTOPULL = "autopull"        # SFTP fetch of a renewed cert from the source
CH_IMPORT = "import"            # operator/pull installed an external PEM
CH_ISSUE = "issue"              # operator minted from the internal CA
CH_TIMER = "timer"              # the nightly runner itself (crash/exception)

OK_RENEWED = "renewed"
OK_SKIPPED = "skipped"
OK_ERROR = "error"


def _node() -> tuple[str, str]:
    try:
        from . import self_update as su
        return su.this_node_name() or "?", su.node_role() or "?"
    except Exception:
        return "?", "?"


def record(channel: str, status: str, summary: str = "", *, error: str = "",
           by: str = "", days_left=None, not_after: str | None = None,
           extra: dict | None = None) -> dict:
    """Append one attempt. NEVER raises — a journal problem must not turn a
    successful renewal into a failure, nor mask the real error."""
    name, role = _node()
    entry = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "node": name, "role": role,
        "channel": channel, "status": status,
        "summary": (summary or "")[:600],
        "error": (error or "")[:2000],
        "by": by, "days_left": days_left, "not_after": not_after,
    }
    if extra:
        entry["extra"] = extra
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE, 0o700)
        with JOURNAL.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        _trim()
    except Exception:  # noqa: BLE001 — journaling is best-effort by design
        pass
    return entry


def _trim() -> None:
    try:
        lines = JOURNAL.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_ENTRIES:
            JOURNAL.write_text("\n".join(lines[-MAX_ENTRIES:]) + "\n", encoding="utf-8")
    except Exception:
        pass


def history(limit: int = 200, only_errors: bool = False) -> list[dict]:
    """Newest first."""
    out = []
    try:
        for line in JOURNAL.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except FileNotFoundError:
        return []
    except Exception:
        return []
    out.reverse()
    if only_errors:
        out = [e for e in out if e.get("status") == OK_ERROR]
    return out[:limit]


def summary() -> dict:
    """Compact state for the page header / peer probe."""
    runs = history(limit=MAX_ENTRIES)
    name, role = _node()
    last = runs[0] if runs else None
    last_err = next((e for e in runs if e.get("status") == OK_ERROR), None)
    # consecutive failures at the head of the journal (an ongoing problem)
    streak = 0
    for e in runs:
        if e.get("status") == OK_ERROR:
            streak += 1
        else:
            break
    return {"node": name, "role": role, "count": len(runs),
            "errors": sum(1 for e in runs if e.get("status") == OK_ERROR),
            "last": last, "last_error": last_err, "fail_streak": streak}


# ---------------------------------------------------------------------------
# Fleet view — this node + the peer, without any SSH between them
# ---------------------------------------------------------------------------
def _cert_state() -> dict:
    from . import cert_service as cs
    try:
        cur = cs.current()
        out = {k: cur.get(k) for k in
               ("source", "days_left", "not_after", "subject", "hostname",
                "installed_at", "can_issue_internal", "issuer")}
        out["renew_mode"] = cs.renew_mode()
        try:
            out["autopull_configured"] = bool(cs.autopull_config().get("configured"))
        except Exception:
            out["autopull_configured"] = False
        return out
    except Exception as exc:  # noqa: BLE001
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


def local_view(limit: int = 100) -> dict:
    return {"reachable": True, "is_self": True, "secure": None,
            "host": "127.0.0.1", "cert": _cert_state(),
            "summary": summary(), "runs": history(limit=limit)}


def peer_view(host: str, limit: int = 100, timeout: float = 2.5) -> dict:
    """Read the PEER's journal over the authenticated HTTPS peer channel
    (node_security.peer_get → /healthz/cert-renewals). No SSH, no shared FS —
    the peer's journal is node-local and only the peer can produce it."""
    out = {"reachable": False, "is_self": False, "secure": False, "host": host,
           "cert": {}, "summary": {}, "runs": [], "error": ""}
    if not host or host in ("127.0.0.1", "localhost"):
        return out
    try:
        from . import node_security as nsec
        st, body, secure = nsec.peer_get(
            host, "/healthz/cert-renewals?limit=%d" % int(limit), timeout=timeout)
        out["secure"] = bool(secure)
        if st != 200:
            out["error"] = "peer answered %s" % (st if st is not None else "nothing (unreachable)")
            return out
        data = json.loads(body.decode("utf-8", "replace"))
        out.update(reachable=True, cert=data.get("cert") or {},
                   summary=data.get("summary") or {}, runs=data.get("runs") or [])
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def fleet_view(limit: int = 100) -> list[dict]:
    """One entry per HA node: this node read locally, every other node probed."""
    try:
        from . import self_update as su
        me = su.this_node_name()
        nodes = su.load_nodes()
    except Exception:
        me, nodes = "", []
    out = []
    for n in nodes or []:
        name = (n.get("name") or "").strip()
        host = (n.get("host") or "").strip()
        if n.get("self") or (name and name == me) or host in ("127.0.0.1", "localhost"):
            v = local_view(limit=limit)
        else:
            v = peer_view(host, limit=limit)
        v["name"] = name or host or me or "this node"
        v["desc"] = n.get("desc") or ""
        out.append(v)
    if not out:
        v = local_view(limit=limit)
        v["name"] = me or "this node"
        v["desc"] = ""
        out.append(v)
    return out
