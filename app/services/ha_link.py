"""HA link: "can the standby fetch code from me?" -- checked and repaired on
the PRIMARY.   [SATOM-HA-LINK]

The incident this exists for (2026-10-11 23:49Z, satom-node-1): systemd-logind
lost a job ("Failed to start session scope session-NNNN.scope: Connection
timed out"). From then on every SSH login of the service account stayed in
logind ``State=opening``: sshd waits on pam_systemd and never runs the forced
command. The standby's reconciler fetches the code with ``git fetch origin``
over exactly that kind of login (``git-upload-pack`` as the service account),
so every fetch hung for 120 s and the standby silently stopped converging.
Root SSH and the data sync kept working, the web stayed green, and the only
trace was a traceback in the STANDBY's journal. ``systemctl restart
systemd-logind`` on the primary fixed it within one reconciler cycle.

Three questions, answered here without touching the standby's shell:

1. **Is the primary's login path wedged?** :func:`logind_sessions` counts
   sessions of the service account stuck in ``opening`` for more than
   :data:`STUCK_AFTER_S`, and treats a ``loginctl`` that does not answer as
   the stronger form of the same fault. ``loginctl`` reads answer any user, so
   this runs in the unprivileged web worker. A loopback ``git ls-remote`` over
   SSH would be the more direct test, but the primary holds no key the standby's
   forced command accepts (and ``from=`` pins it to the standby's address);
   minting one for a health check would widen the very channel it measures.
2. **What does the standby itself say?** :func:`probe_standby` reads the
   standby's node-local reconciler record over ``/healthz/reconciler`` -- the
   same unauthenticated peer-probe pattern as ``/healthz/backups``. The lag is
   computed HERE, against this node's branch head, because a standby that
   cannot fetch measures itself against a stale ``origin`` and reads "0
   behind".
3. **Can the operator fix it from the console?** :func:`request_repair`
   restarts ``systemd-logind`` -- never from the web worker: it enqueues the
   allowlisted service action (``service_control.POLICY``) that the root
   runner re-validates, including a primary-only role check of its own.

Nothing here restarts anything on the standby, and nothing here is reached by
a page load except reads.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import socket
import subprocess
import time
from datetime import datetime, timezone

from . import self_update as su

LOGIND_UNIT = "systemd-logind.service"
PROBE_PATH = "/healthz/reconciler"
PROBE_TIMEOUT = 2.5

#: A login normally leaves ``opening`` in milliseconds. One that is still there
#: after a minute is not slow, it is stuck -- and on 2026-10-11 they piled up.
STUCK_AFTER_S = 60
#: How long the standby must have been failing to fetch before it is an alert.
#: One failed fetch is the primary restarting or a network blip; ten minutes is
#: several reconciler ticks in a row, each having waited out the full timeout.
ALERT_AFTER_S = 600
#: The standby ticks every 60 s (plus up to the fetch timeout). No tick for
#: this long means its reconciler is not running, which is a finding of its own.
STALE_AFTER_S = 300
LOGINCTL_TIMEOUT = 5
SSHD_PORT = 22

#: The key the alert engine files this finding under. ``git.`` puts it in the
#: git-sync family whose toggle already covers "the standby is behind".
ALERT_KEY = "git.ha_link"

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_UID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: What the repair does and does not do. Printed by the preview, the CLI and
#: the docs verbatim, so the three cannot describe different actions.
REPAIR_DOES = (
    "restarts systemd-logind on THIS node (the primary) through the privileged "
    "runner, the same queue as every Services action",
    "lets sshd finish the logins it was waiting on, so the standby's next git "
    "fetch (within about a minute) gets through",
    "re-runs this check afterwards and shows before and after",
)
REPAIR_DOES_NOT = (
    "touch the standby, its reconciler, or anything over SSH",
    "restart sshd, the web app, PostgreSQL or the data sync",
    "end open sessions -- logind re-attaches them when it comes back",
    "fix a network, key or sshd fault: if sshd is down or the standby is "
    "unreachable, the check says so and this button will not help",
)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age_s(value, now: datetime | None = None) -> float | None:
    dt = _parse_iso(value)
    if dt is None:
        return None
    return max(0.0, ((now or _now()) - dt).total_seconds())


def _fmt_age(seconds) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    if s < 120:
        return "%ds" % s
    if s < 7200:
        return "%dm" % (s // 60)
    return "%dh%02dm" % (s // 3600, (s % 3600) // 60)


def app_user() -> str:
    """The service account the standby logs in as: the app tree's owner, the
    same single source of truth the runner and the datasync use."""
    try:
        return pwd.getpwuid(su.APP_DIR.stat().st_uid).pw_name
    except Exception:  # noqa: BLE001
        return "satom"


# ---------------------------------------------------------------------------
# 1. the primary's own login path
# ---------------------------------------------------------------------------
def _loginctl(*args: str):
    """(rc, stdout, stderr); rc 124 = timed out, 127 = no loginctl here."""
    try:
        p = subprocess.run(["loginctl", *args], capture_output=True, text=True,
                           timeout=LOGINCTL_TIMEOUT)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except FileNotFoundError:
        return 127, "", "loginctl not found"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def parse_show_session(text: str) -> list[dict]:
    """``loginctl show-session A B ... -p X -p Y`` prints one KEY=VALUE block
    per session, separated by a blank line."""
    out, cur = [], {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            if cur:
                out.append(cur)
                cur = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    if cur:
        out.append(cur)
    return out


def logind_sessions(user: str | None = None,
                    now_mono: float | None = None) -> dict:
    """Sessions of ``user`` stuck in ``opening``, and whether logind answers.

    ``TimestampMonotonic`` is compared with this process's CLOCK_MONOTONIC.
    Both come from the same kernel, which matters in an LXC: /proc/uptime is
    the container's (virtualised) uptime there and would date every session in
    the future.
    """
    user = user or app_user()
    res = {"responsive": True, "user": user, "sessions": 0, "opening": 0,
           "stuck": [], "error": ""}
    rc, out, err = _loginctl("list-sessions", "--no-legend")
    if rc == 127:
        res.update(responsive=None, error="loginctl is not available on this "
                                          "node, so the login path cannot be read")
        return res
    if rc == 124:
        res.update(responsive=False,
                   error="loginctl did not answer within %ds: systemd-logind is "
                         "not responding" % LOGINCTL_TIMEOUT)
        return res
    if rc != 0:
        res.update(responsive=False, error="loginctl list-sessions failed: %s"
                   % (err.strip() or "exit %d" % rc)[:200])
        return res
    ids = [ln.split()[0] for ln in out.splitlines()
           if ln.strip() and ln.split()[0].isdigit()]
    res["sessions"] = len(ids)
    if not ids:
        return res
    rc, out, err = _loginctl("show-session", *ids, "-p", "Id", "-p", "Name",
                             "-p", "State", "-p", "TimestampMonotonic",
                             "-p", "Service")
    if rc == 124:
        res.update(responsive=False,
                   error="loginctl show-session did not answer within %ds: "
                         "systemd-logind is not responding" % LOGINCTL_TIMEOUT)
        return res
    # A session can end between the two calls; loginctl then exits non-zero
    # but still prints every session it did find. Read what is there.
    now = time.monotonic() if now_mono is None else now_mono
    stuck = []
    for s in parse_show_session(out):
        if s.get("State") != "opening":
            continue
        res["opening"] += 1
        ts = s.get("TimestampMonotonic", "")
        age = (now - int(ts) / 1e6) if ts.isdigit() and int(ts) > 0 else None
        if s.get("Name") == user and age is not None and age >= STUCK_AFTER_S:
            stuck.append({"id": s.get("Id", "?"), "age_s": int(age),
                          "service": s.get("Service", "")})
    stuck.sort(key=lambda r: r["age_s"], reverse=True)
    res["stuck"] = stuck
    return res


def sshd_banner(host: str = "127.0.0.1", port: int = SSHD_PORT,
                timeout: float = 3.0) -> dict:
    """Does sshd answer at all? It tells the two faults apart: a dead sshd
    looks the same from the standby (fetch fails) and restarting logind does
    nothing for it."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            line = s.recv(256).decode("ascii", "replace").strip()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "banner": "", "error": "%s:%d: %s" % (host, port, exc)}
    ok = line.startswith("SSH-")
    return {"ok": ok, "banner": line.splitlines()[0][:80] if line else "",
            "error": "" if ok else "port %d answered without an SSH banner" % port}


# ---------------------------------------------------------------------------
# 2. the standby's own account, over the peer probe
# ---------------------------------------------------------------------------
def _peer_json(raw):
    try:
        d = json.loads((raw or b"").decode("utf-8", "replace") or "{}")
    except Exception:  # noqa: BLE001
        return None
    return d if isinstance(d, dict) else None


def probe_standby(node: dict, timeout: float = PROBE_TIMEOUT) -> dict:
    """One peer's reconciler record, or why it could not be read. "Could not
    read" never collapses into "no problem"."""
    from . import node_security as nsec
    row = {"node": node.get("name"), "host": node.get("host"),
           "reachable": False, "status": None, "error": "", "old_release": False}
    try:
        st, raw, _secure = nsec.peer_get(node.get("host") or "", PROBE_PATH,
                                         timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        row["error"] = str(exc)
        return row
    if st is None:
        row["error"] = "no answer on :%d or :%d" % (nsec.HTTPS_PORT, nsec.HTTP_PORT)
        return row
    row["reachable"] = True
    if int(st) == 404:
        row["old_release"] = True
        row["error"] = ("the standby does not expose %s (HTTP 404) -- it is "
                        "probably on an older release" % PROBE_PATH)
        return row
    ans = _peer_json(raw)
    if not (200 <= int(st) < 300) or ans is None:
        row["error"] = "HTTP %s with an unreadable body" % st
        return row
    rec = ans.get("reconciler")
    row["status"] = rec if isinstance(rec, dict) else None
    return row


def branch_head() -> str:
    """This node's branch head: exactly what the standby's ``git fetch origin
    main`` asks this node's repository for."""
    try:
        r = su._git("rev-parse", "--verify", "-q", "refs/heads/%s" % su.BRANCH,
                    timeout=10)
        return (r.stdout or "").strip() if r.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


def lag_behind(standby_sha: str, head: str) -> int | None:
    """Commits the standby's checkout is behind this node's head, or None.

    The sha arrives from the network, so it is shape-checked before it gets
    anywhere near a git argument list.
    """
    sha = (standby_sha or "").strip().lower()
    if not head or not _SHA_RE.match(sha):
        return None
    if head.startswith(sha):
        return 0
    try:
        r = su._git("rev-list", "--count", "%s..%s" % (sha, head), timeout=10)
    except Exception:  # noqa: BLE001
        return None
    out = (r.stdout or "").strip()
    return int(out) if r.returncode == 0 and out.isdigit() else None


def assess_standby(row: dict, head: str = "", now: datetime | None = None) -> dict:
    """Classify one probed standby: ``state`` + one sentence for the page."""
    now = now or _now()
    name = row.get("node") or "standby"
    rec = row.get("status")
    if not row.get("reachable"):
        return {"state": "unreachable", "behind": None,
                "text": "%s is not answering: %s" % (name, row.get("error") or "?")}
    if row.get("old_release"):
        return {"state": "unknown", "behind": None, "text": row.get("error")}
    if not rec:
        return {"state": "no-status", "behind": None,
                "text": ("%s has no reconciler record yet: its reconciler is "
                         "not running, or has not ticked since it was updated"
                         % name)}
    tick_age = _age_s(rec.get("at"), now)
    behind = lag_behind(rec.get("current") or "", head)
    if rec.get("decision") == "fetch-error":
        since = rec.get("fetch_error_since") or rec.get("at")
        text = ("%s cannot fetch from this node since %s (%s, %s failed "
                "attempt(s)): %s" % (name, since, _fmt_age(_age_s(since, now)),
                                     rec.get("fetch_failures") or 1,
                                     rec.get("error") or "no error text"))
        if behind:
            text += " -- it is %d commit(s) behind" % behind
        return {"state": "fetch-error", "behind": behind, "text": text,
                "since": since, "since_s": _age_s(since, now)}
    if tick_age is not None and tick_age > STALE_AFTER_S:
        return {"state": "stale", "behind": behind,
                "text": ("%s last reported %s ago: satom-reconciler is not "
                         "ticking there" % (name, _fmt_age(tick_age)))}
    if behind is None:
        # Not resolvable here (a sha this node does not have): fall back to
        # what the standby measured itself, and say that it is its own number.
        behind_self = int(rec.get("behind") or 0)
        if behind_self == 0 and head and (rec.get("current") or "") and \
                not head.startswith(rec.get("current") or ""):
            return {"state": "diverged", "behind": None,
                    "text": ("%s runs %s, which this node's %s does not contain"
                             % (name, rec.get("current"), su.BRANCH))}
        behind = behind_self
    if behind == 0:
        return {"state": "in-sync", "behind": 0,
                "text": "%s is in sync (%s)" % (name, rec.get("current") or "?")}
    return {"state": "behind", "behind": behind,
            "text": ("%s is %d commit(s) behind (its reconciler says: %s)"
                     % (name, behind, rec.get("decision") or "?"))}


# ---------------------------------------------------------------------------
# the combined check
# ---------------------------------------------------------------------------
def repair_refusal(role: str, mode: str) -> str | None:
    """Why the repair must not run on this node, or None. The reasons are
    worded for the operator who clicked: each names what to do instead."""
    if role == "standby":
        return ("This node is the STANDBY. The standby fetches FROM the primary, "
                "so the login service on the fetch path is the primary's: run "
                "the check and the repair on the primary.")
    if role != "primary":
        return ("This node's role cannot be determined (PostgreSQL is not "
                "answering). Refusing to restart a system service blind.")
    if mode != "ha":
        return ("This node is in STANDALONE mode: no standby fetches from it, "
                "so there is no HA link to repair.")
    return None


def _problems(logind: dict, sshd: dict, standby: list[dict]) -> list[dict]:
    out = []
    user = logind.get("user") or "satom"
    if logind.get("responsive") is False:
        out.append({"code": "logind-unresponsive", "severity": "critical",
                    "fixable": True, "text": logind.get("error")})
    elif logind and logind.get("responsive") is None:   # {} = not probed
        out.append({"code": "logind-unknown", "severity": "warning",
                    "fixable": False, "text": logind.get("error")})
    if logind.get("stuck"):
        oldest = logind["stuck"][0]
        out.append({"code": "logind-stuck", "severity": "critical", "fixable": True,
                    "text": ("%d SSH login(s) of %s stuck in logind state "
                             "'opening' (oldest: session %s, %s): sshd is waiting "
                             "on systemd-logind and never runs the standby's "
                             "git-upload-pack"
                             % (len(logind["stuck"]), user, oldest["id"],
                                _fmt_age(oldest["age_s"])))})
    if sshd and not sshd.get("ok"):
        out.append({"code": "sshd-down", "severity": "critical", "fixable": False,
                    "text": ("sshd is not answering on this node (%s). Restarting "
                             "logind will not help: systemctl status ssh"
                             % (sshd.get("error") or "no banner"))})
    for s in standby:
        st = s.get("state")
        if st == "fetch-error":
            out.append({"code": "standby-fetch-error", "severity": "critical",
                        "fixable": None, "text": s.get("text"),
                        "node": s.get("node"), "since": s.get("since"),
                        "since_s": s.get("since_s")})
        elif st in ("unreachable", "stale", "no-status", "unknown", "diverged",
                    "behind"):
            out.append({"code": "standby-" + st, "severity": "warning",
                        "fixable": False, "text": s.get("text"),
                        "node": s.get("node")})
    return out


def check(*, probe: bool = True, timeout: float = PROBE_TIMEOUT) -> dict:
    """The whole answer to "can the standby fetch from me?". Never raises.

    ``verdict``: ``ok`` | ``warning`` | ``broken`` on a primary in HA mode;
    ``n/a`` elsewhere, with nothing probed: on a standby or a standalone node
    nobody fetches from this node's sshd, so its login path is not an HA link
    fault there -- and the page that renders this must not pay two local
    timeouts on every load to say so.
    """
    node, role, mode = su.this_node_name(), su.node_role(), su.ha_mode()
    applicable = role == "primary" and mode == "ha"
    logind = logind_sessions() if applicable else {}
    sshd = sshd_banner() if applicable else {}
    standby = []
    head = branch_head() if applicable else ""
    if applicable and probe:
        for n in su.peer_nodes():
            row = probe_standby(n, timeout=timeout)
            row.update(assess_standby(row, head))
            standby.append(row)
    problems = _problems(logind, sshd, standby)
    if not applicable:
        verdict = "n/a"
    elif any(p["severity"] == "critical" for p in problems):
        verdict = "broken"
    elif problems:
        verdict = "warning"
    else:
        verdict = "ok"
    refusal = repair_refusal(role, mode)
    local_fault = any(p["code"] in ("logind-stuck", "logind-unresponsive")
                      for p in problems)
    return {
        "at": _now().isoformat(timespec="seconds"),
        "node": node, "role": role, "mode": mode,
        "applicable": applicable, "verdict": verdict,
        "head": head[:12], "problems": problems,
        "logind": logind, "sshd": sshd, "standby": standby,
        "repair": {"allowed": refusal is None, "refusal": refusal,
                   "recommended": refusal is None and local_fault,
                   "unit": LOGIND_UNIT,
                   "does": list(REPAIR_DOES), "does_not": list(REPAIR_DOES_NOT)},
    }


# ---------------------------------------------------------------------------
# 3. the repair
# ---------------------------------------------------------------------------
def _repair_in_flight() -> str:
    """A logind restart already queued or running on this node, if any. A
    second click must not queue a second restart behind the first."""
    for st in su.recent_updates(limit=20):
        if (st.get("kind") == "service" and st.get("unit") == LOGIND_UNIT
                and st.get("state") in ("queued", "running")):
            return st.get("id") or ""
    return ""


def request_repair(by: str, *, origin: str = "ha-link",
                   dry_run: bool = True) -> dict:
    """Preview (default) or enqueue the HA link repair.

    ``dry_run`` is the default so a caller that forgets the flag gets the plan,
    not a restart. The enqueue goes through ``service_control`` -- the same
    allowlist the root runner re-validates -- so this function never runs
    systemctl and cannot name any unit but logind.
    """
    from . import service_control as sc
    before = check()
    out = {"ok": False, "dry_run": dry_run, "node": before["node"],
           "unit": LOGIND_UNIT, "before": before, "uid": None, "refused": None,
           "does": list(REPAIR_DOES), "does_not": list(REPAIR_DOES_NOT)}
    refusal = before["repair"]["refusal"]
    if refusal:
        out["refused"] = refusal
        return out
    if dry_run:
        out["ok"] = True
        return out
    pending = _repair_in_flight()
    if pending:
        out.update(ok=True, uid=pending, already_queued=True)
        return out
    out["uid"] = sc.request_service_action(LOGIND_UNIT, "restart", by=by,
                                           origin=origin)
    out["ok"] = True
    return out


def repair_outcome(uid: str) -> dict:
    """The queued repair's runner record, plus a fresh check once it is done.

    Only a logind service record is accepted: this endpoint must not become a
    general reader of the update-status directory.
    """
    if not _UID_RE.match(uid or ""):
        return {"state": "unknown", "error": "bad id", "done": False}
    st = su.update_status(uid)
    if not st or st.get("kind") != "service" or st.get("unit") != LOGIND_UNIT:
        return {"state": "unknown", "error": "no such repair", "done": False}
    done = st.get("state") in ("success", "failed")
    out = {"state": st.get("state"), "done": done, "steps": st.get("steps") or [],
           "error": st.get("error") or "", "after": None}
    if done:
        out["after"] = check()
    return out


# ---------------------------------------------------------------------------
# 5. the alert
# ---------------------------------------------------------------------------
def alert_findings(res: dict | None = None) -> tuple[list[dict], bool]:
    """(findings, cleared) for the alert engine.

    One finding per incident, under one key, whichever symptom shows first: a
    wedged logind and the standby's fetch errors are the same outage seen from
    two ends, and two bells for one fault is the spam this has to avoid.
    ``cleared`` is True only when the link is AFFIRMATIVELY healthy (verdict
    ``ok``); the engine then re-arms the key so the next break notifies at
    once instead of hiding inside the previous one's cooldown. An unreachable
    standby is not "cleared" -- not knowing must not re-arm a live incident.
    """
    if res is None:
        # Cheap role gate first: the engine runs on the standby too, and there
        # is nothing to probe from there (notification is primary-only anyway).
        if su.node_role() != "primary" or su.ha_mode() != "ha":
            return [], False
        res = check()
    if not res.get("applicable"):
        return [], False
    if res.get("verdict") == "ok":
        return [], True
    probs = res.get("problems") or []
    local = [p for p in probs if p["code"] in ("logind-stuck", "logind-unresponsive")]
    fetch = [p for p in probs if p["code"] == "standby-fetch-error"
             and (p.get("since_s") or 0) >= ALERT_AFTER_S]
    if not (local or fetch):
        return [], False
    node = res.get("node")
    if fetch:
        title = ("HA link broken: standby %s cannot fetch code from %s"
                 % (fetch[0].get("node") or "?", node))
    else:
        title = "HA link broken on %s: systemd-logind is wedged" % node
    lines = [p["text"] for p in (local + fetch) if p.get("text")]
    lines.append("Check: Software Update & HA -> HA link, or 'satom ha check'. "
                 "Repair (restarts systemd-logind on the primary): the Repair "
                 "HA link button, or 'sudo satom ha repair --yes'.")
    return [{"key": ALERT_KEY, "severity": "critical", "title": title,
             "detail": "\n".join(lines)}], False


__all__ = ["check", "request_repair", "repair_outcome", "repair_refusal",
           "alert_findings", "logind_sessions", "probe_standby",
           "assess_standby", "LOGIND_UNIT"]
