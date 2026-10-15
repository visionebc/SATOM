"""Libraries card changes as server-side jobs: this node first, then the peer.

A curated pip change with "also the peer" is two runs on two nodes, and the
peer may only start once this node finished with success (psycopg 3.3.6 took
a1 AND a2 down together on 2026-10-15 when both started at once). That hand-off
used to live in the browser: the card waited for local success and then asked
the server to contact the peer. Closing the tab, or a laptop going to sleep,
left the peer untouched and nothing said so.

Now the request becomes a job in the global job ledger (``services/jobs``) and
the browser only watches it. The job cannot be a worker thread: the change
restarts the web AND the scheduler, so any thread driving it would die halfway.
It is a *durable* job instead -- every fact lives in the job file -- and
``advance()`` moves it one step from whatever it finds there. The scheduler
sidecar calls ``advance_all()`` every few seconds and is back within seconds of
the restart the change itself causes, so the job resumes where it was.

Phases, in ``meta.phase``:

* ``local``       -- this node's runner applies the change (status file).
* ``dispatching`` -- written BEFORE the peer is asked. Found on entry it means a
  driver died during the request, so whether the peer got it is unknown: the
  job fails and says so instead of asking twice.
* ``peer``        -- each peer's runner applies it; polled over the node channel.

Every terminal state is a verdict about BOTH nodes: a peer that refused, could
not be reached or failed is an error, never a quiet success.

Two kinds ride the same machinery, both from Settings → General: a curated pip
change (``library_pip``) and a curated OS package install (``system_package``,
``services/system_packages``). The OS install used to ask the peer at the same
moment as this node -- the simultaneity that took the pair down with psycopg.
"""
from __future__ import annotations

import fcntl
import os
from datetime import datetime
from pathlib import Path

from . import jobs

JOB_TYPE = "library_pip"
SYSPKG_TYPE = "system_package"
JOB_TYPES = (JOB_TYPE, SYSPKG_TYPE)
#: Steps a run of each kind writes, for a progress bar that never ends early.
_EXPECTED_STEPS = {JOB_TYPE: 10, SYSPKG_TYPE: 4}
#: How often the scheduler sidecar drives active jobs.
TICK_S = 3
#: The updater normally picks a request up within a second or two.
QUEUED_WARN_S = 120
QUEUED_FAIL_S = 30 * 60
#: A run that never reaches a final state (the runner's own steps are bounded).
RUNNING_FAIL_S = 30 * 60
#: A peer that does not answer at all for this long fails the job.
PEER_SILENT_FAIL_S = 10 * 60

_TERMINAL_RUN = ("success", "failed")


def _utcnow() -> datetime:
    return datetime.utcnow()


def _iso() -> str:
    return _utcnow().isoformat(timespec="seconds")


def _since(iso: str | None) -> float:
    """Seconds since a naive-UTC ISO stamp written by this module (0 if none).
    Differences of two naive UTC datetimes: no dependence on the local TZ."""
    try:
        return (_utcnow() - datetime.fromisoformat(iso)).total_seconds()
    except Exception:  # noqa: BLE001
        return 0.0


def _markers() -> Path:
    """One empty file per active job of this type, so the sidecar does not
    parse the whole ledger every few seconds."""
    d = jobs._state_dir() / "library-active"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _locks() -> Path:
    d = jobs._state_dir() / "locks"
    d.mkdir(parents=True, exist_ok=True)
    return d


def start(package: str, version: str, *, action: str, also_peer: bool,
          by: str) -> dict:
    """Queue the change on THIS node and open the job that carries it through.

    Raises ValueError for a request the allowlist/regexes refuse (nothing is
    queued). No driver check here: the runner restarts satom-scheduler as part
    of every change, and a scheduler that cannot come back leaves the job
    un-advanced, which ``jobs.sweep_orphans`` fails after a while (durable rule).
    """
    from . import self_update as su
    uid = su.request_pip_change(package, version, by=by, action=action)
    verb = "Roll back" if action == "rollback" else "Upgrade"
    return _open(JOB_TYPE, "%s %s → %s" % (verb, package, version), uid, by,
                 also_peer, {"package": package, "version": version,
                             "action": action})


def start_install(key: str, *, also_peer: bool, by: str) -> dict:
    """Same as :func:`start` for a curated OS package (System packages card)."""
    from . import system_packages as sp
    uid = sp.request_install(key, by=by)
    return _open(SYSPKG_TYPE, "Install %s" % key, uid, by, also_peer,
                 {"package": key, "action": "install"})


def _open(type_: str, what: str, uid: str, by: str, also_peer: bool,
          extra: dict) -> dict:
    from . import self_update as su
    node = su.this_node_name()
    scope = "%s + peer" % node if also_peer else node
    job = jobs.create_job(
        type_, "%s (%s)" % (what, scope), by=by,
        meta=dict(extra, also_peer=bool(also_peer), node=node, local_uid=uid,
                  phase="local", peers=[], steps=[], phase_since=_iso()),
        cancelable=False, durable=True)
    jobs.update_job(job["id"], status=jobs.RUNNING,
                    message="queued on %s — waiting for its updater" % node)
    (_markers() / job["id"]).touch()
    return jobs.get_job(job["id"]) or job


def has_active() -> bool:
    try:
        return any(True for _ in os.scandir(_markers()))
    except OSError:
        return False


def advance_all() -> list[str]:
    """Drive every active job of this type once. Never raises."""
    done = []
    try:
        ids = sorted(os.listdir(_markers()))
    except OSError:
        return done
    for job_id in ids:
        try:
            advance(job_id)
        except Exception:  # noqa: BLE001 — one bad job must not stop the others
            continue
        done.append(job_id)
    return done


def advance(job_id: str) -> dict | None:
    """Move one job forward from what its file and the runners' status say.

    Serialised per job with an flock, so two drivers can never both ask the
    peer. The kernel drops the lock if the driver dies.
    """
    with open(_locks() / ("library-%s.lock" % job_id), "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return None
        st = jobs.get_job(job_id)
        if not st or st.get("type") not in JOB_TYPES or st.get("status") not in jobs._ACTIVE \
                or (st.get("host") or jobs._HOST) != jobs._HOST:
            _retire(job_id)
            return st
        meta = st.get("meta") or {}
        phase = meta.get("phase")
        if phase == "local":
            _advance_local(job_id, meta)
        elif phase == "dispatching":
            _fail(job_id, "The driver stopped while asking the peer, so it is "
                          "unknown whether the peer received the change. Check "
                          "the drift table before retrying.")
        elif phase == "peer":
            _advance_peer(job_id, meta)
        else:
            _fail(job_id, "unknown phase %r" % phase)
        return jobs.get_job(job_id)


# ── phases ──────────────────────────────────────────────────────────────────
def _age(meta: dict) -> float:
    return _since(meta.get("phase_since"))


def _run_steps(node: str, run: dict | None) -> list[dict]:
    out = []
    for s in (run or {}).get("steps") or []:
        out.append({"at": (s.get("at") or "")[:19], "label": "%s · %s" % (node, s.get("name")),
                    "outcome": (s.get("detail") or "")[:300], "ok": bool(s.get("ok"))})
    cur = (run or {}).get("current") or {}
    if cur.get("name"):
        out.append({"at": "", "label": "%s · %s" % (node, cur["name"]),
                    "outcome": "running…", "ok": True})
    return out


def _percent(run: dict | None, lo: int, hi: int, expected: int) -> int:
    # The bar follows the steps written so far and never claims the end early.
    n = len((run or {}).get("steps") or [])
    return lo + min(hi - lo - 1, int((hi - lo) * n / expected))


def _advance_local(job_id: str, meta: dict) -> None:
    from . import self_update as su
    node = meta.get("node") or "?"
    run = su.update_status(meta.get("local_uid") or "")
    state = (run or {}).get("state") or "queued"
    hi = 50 if meta.get("also_peer") else 100

    def _mirror(s):
        s["meta"]["local_state"] = state
        s["meta"]["steps"] = _run_steps(node, run)
        s["percent"] = _percent(run, 0, hi, _EXPECTED_STEPS.get(s.get("type"), 9))
    jobs.mutate_job(job_id, _mirror)

    if state in ("queued", "running"):
        age = _age(meta)
        if state == "queued" and age > QUEUED_FAIL_S:
            _fail(job_id, "The updater on %s did not pick the change up in %d min. "
                          "Check that satom-updater.path is enabled there. If it "
                          "runs later, the peer will NOT follow." % (node, QUEUED_FAIL_S // 60))
        elif state == "running" and age > RUNNING_FAIL_S:
            _fail(job_id, "No final state from %s after %d min." % (node, RUNNING_FAIL_S // 60))
        elif state == "queued":
            msg = "queued on %s — waiting for its updater" % node
            if age > QUEUED_WARN_S:
                msg += " (%d min; is satom-updater.path enabled?)" % (age // 60)
            jobs.update_job(job_id, message=msg)
        else:
            cur = ((run or {}).get("current") or {}).get("name") \
                or (((run or {}).get("steps") or [{}])[-1].get("name")) or "running"
            jobs.update_job(job_id, message="%s: %s" % (node, cur))
        if state == "running" and not meta.get("running_since"):
            stamp = _iso()
            jobs.mutate_job(job_id, lambda s: s["meta"].update(
                phase_since=stamp, running_since=stamp))
        return

    if state != "success":
        why = (run or {}).get("error") or state
        rolled = " It was rolled back there." if (run or {}).get("rolled_back") else ""
        peer = " The peer was NOT touched." if meta.get("also_peer") else ""
        _fail(job_id, "Failed on %s: %s.%s%s" % (node, why, rolled, peer))
        return

    if not meta.get("also_peer"):
        _succeed(job_id, "Applied on %s." % node)
        return
    _dispatch(job_id, meta)


def _dispatch(job_id: str, meta: dict) -> None:
    from . import self_update as su
    from .audit import log_action
    # Persist the intent FIRST: a driver that dies inside the request leaves
    # 'dispatching' behind, and the next pass refuses to ask a second time.
    jobs.mutate_job(job_id, lambda s: s["meta"].update(phase="dispatching"))
    st = jobs.get_job(job_id) or {}
    syspkg = st.get("type") == SYSPKG_TYPE
    try:
        if syspkg:
            from . import system_packages as sp
            peers = sp.request_install_on_peers(meta["package"], by=_by(job_id))
        else:
            peers = su.request_pip_change_on_peers(
                meta["package"], meta["version"],
                by=_by(job_id), action=meta.get("action") or "upgrade")
    except Exception as exc:  # noqa: BLE001
        peers = [{"node": "?", "host": "", "uid": None,
                  "state": "unreachable", "error": str(exc)}]
    now = _iso()
    for p in peers:
        p.update(asked_at=now, last_seen=now if p.get("state") == "queued" else None,
                 run_state=None)
    try:
        log_action("settings.system_package" if syspkg else "settings.library_pip",
                   detail="%s %s%s on peers after %s succeeded (job %s): %s" % (
                       meta.get("action"), meta["package"],
                       "" if syspkg else "==%s" % meta["version"],
                       meta.get("node"), job_id,
                       ", ".join("%s=%s" % (p.get("node"), p.get("state")) for p in peers)
                       or "none registered"))
    except Exception:  # noqa: BLE001 — audit is best-effort; the job records it too
        pass

    def _apply(s):
        s["meta"].update(phase="peer", peers=peers, phase_since=now)
        s["meta"]["steps"] = list(s["meta"].get("steps") or []) + [
            {"at": now[:19], "label": "%s · ask %s" % (meta.get("node"), p.get("node")),
             "outcome": p.get("state") + (" — %s" % p["error"] if p.get("error") else ""),
             "ok": p.get("state") == "queued"} for p in peers]
        s["percent"] = 50
    jobs.mutate_job(job_id, _apply)
    if not peers:
        _succeed(job_id, "Applied on %s. No peer is registered." % meta.get("node"))
        return
    bad = [p for p in peers if p.get("state") != "queued"]
    if bad:
        _fail(job_id, "Applied on %s, but NOT on %s. The pair now differs; "
                      "retry on the peer." % (meta.get("node"), _describe(bad)))
        return
    jobs.update_job(job_id, message="applied on %s — %s applying it"
                    % (meta.get("node"), ", ".join(p["node"] for p in peers)))


def _advance_peer(job_id: str, meta: dict) -> None:
    from . import service_control as svc
    peers = [dict(p) for p in meta.get("peers") or []]
    peer_steps = dict(meta.get("peer_steps") or {})
    for p in peers:
        if p.get("run_state") in _TERMINAL_RUN:
            continue
        run = svc.peer_action_status(p["node"], p["uid"])
        state = (run or {}).get("state")
        if state in ("polling", "unknown", None):
            # Unreachable mid-restart is the expected middle of a good run.
            p["silent_s"] = int(_since(p.get("last_seen") or p.get("asked_at")))
            p["note"] = (run or {}).get("error") or "not answering"
            continue
        p.update(last_seen=_iso(), silent_s=0, note="", run_state=state,
                 error=(run or {}).get("error"),
                 rolled_back=bool((run or {}).get("rolled_back")),
                 steps_done=len((run or {}).get("steps") or []))
        peer_steps[p["node"]] = _run_steps(p["node"], run)
    own = [x for x in meta.get("steps") or []
           if not any(str(x.get("label", "")).startswith("%s · " % p.get("node"))
                      for p in peers)]

    def _apply(s):
        s["meta"].update(peers=peers, peer_steps=peer_steps,
                         steps=own + [x for p in peers
                                      for x in peer_steps.get(p.get("node"), [])])
        n = max([int(p.get("steps_done") or 0) for p in peers] or [0])
        s["percent"] = 50 + min(49, int(50 * n / _EXPECTED_STEPS.get(s.get("type"), 9)))
    jobs.mutate_job(job_id, _apply)

    failed = [p for p in peers if p.get("run_state") == "failed"]
    silent = [p for p in peers if int(p.get("silent_s") or 0) > PEER_SILENT_FAIL_S]
    stuck = [p for p in peers if p.get("run_state") not in _TERMINAL_RUN
             and _age(meta) > RUNNING_FAIL_S]
    if failed:
        _fail(job_id, "Applied on %s, but it FAILED on %s. The pair now differs."
              % (meta.get("node"), ", ".join(
                  "%s (%s%s)" % (p["node"], p.get("error") or "failed",
                                 ", rolled back" if p.get("rolled_back") else "")
                  for p in failed)))
    elif silent:
        _fail(job_id, "Applied on %s; %s stopped answering for %d min, so its "
                      "result is unknown. Check the drift table."
              % (meta.get("node"), ", ".join(p["node"] for p in silent),
                 PEER_SILENT_FAIL_S // 60))
    elif stuck:
        _fail(job_id, "Applied on %s; no final state from %s after %d min."
              % (meta.get("node"), ", ".join(p["node"] for p in stuck),
                 RUNNING_FAIL_S // 60))
    elif all(p.get("run_state") == "success" for p in peers):
        _succeed(job_id, "Applied on %s and %s." % (
            meta.get("node"), ", ".join(p["node"] for p in peers)))
    else:
        jobs.update_job(job_id, message="applied on %s — %s" % (
            meta.get("node"), ", ".join(
                "%s: %s" % (p["node"], p.get("run_state") or p.get("note") or "queued")
                for p in peers if p.get("run_state") != "success")))


# ── helpers ─────────────────────────────────────────────────────────────────
def _by(job_id: str) -> str:
    return (jobs.get_job(job_id) or {}).get("by") or "?"


def _describe(rows: list[dict]) -> str:
    return ", ".join("%s (%s%s)" % (p.get("node"), p.get("state"),
                                    ": %s" % p["error"] if p.get("error") else "")
                     for p in rows)


def _succeed(job_id: str, msg: str) -> None:
    jobs.finish_success(job_id, message=msg)
    _retire(job_id)


def _fail(job_id: str, msg: str) -> None:
    jobs.finish_error(job_id, msg)
    _retire(job_id)


def _retire(job_id: str) -> None:
    try:
        (_markers() / job_id).unlink()
    except OSError:
        pass
