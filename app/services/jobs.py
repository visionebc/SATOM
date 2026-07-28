"""Generic background-job store + runner (worker-proof under multi-worker
gunicorn).

Job state is a small JSON file under ``data/jobs/<id>.json``, written
*atomically* (tmp file + ``os.replace``) under a process lock, so a status poll
landing on ANY gunicorn worker always reads a consistent view — the exact
pattern proven in ``services/deep_jobs.py``, here generalised to ANY job type so
every future async operation (firmware upload finalize, device upgrades, bulk
pushes…) reuses one framework + one global toast UI (``static/js/jobs.js``).

A job is a JSON-able dict::

    {id, type, title, status, percent, message, result, error,
     by, meta, cancelable, reversible, cancel_requested,
     created, updated, finished}

    status ∈ pending | running | cancelling | cancelled | success | error

Typical use inside a request::

    job = jobs.create_job("firmware_finalize", "Verifying image.out", by=user)
    jobs.run_async(current_app._get_current_object(), job["id"], worker)
    return jsonify({"job_id": job["id"]})          # client polls /jobs/<id>

``worker(app, job_id)`` runs in a daemon thread: it opens its own app context,
reports progress with ``jobs.set_progress(job_id, pct, msg)`` and either returns
a JSON-able result (→ success) or raises (→ error). This module has NO Flask /
DB / Qt imports — it is pure stdlib and unit-testable.

Cooperative cancellation (worker-proof)
---------------------------------------
Workers run as daemon *threads* inside one gunicorn worker; a Stop request may
land on a *different* worker process, and a thread cannot be force-killed from
outside. So cancellation is **cooperative and file-mediated**: ``request_cancel``
writes a flag into the job file (any worker can), and the running worker checks
it at *safe checkpoints* — between devices, between items — via ``checkpoint``
(which raises :class:`JobCancelled`) or ``is_cancel_requested``. An in-flight
device write is never interrupted mid-call; the worker stops at its next
checkpoint. This module standardises the *mechanism*; each job type decides
*where* its safe checkpoints are and *what*, if anything, it compensates.

Rollback harness
----------------
There is no universal "undo" — only the job that made a change knows how to
reverse it. :class:`Rollback` is the reusable accumulator: as a worker performs
reversible steps it registers a compensating callable; on cancel/failure the
worker calls ``rb.run()`` to replay them in reverse (best-effort, fully
reported). Read-only jobs register nothing and just stop.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

PENDING, RUNNING, SUCCESS, ERROR = "pending", "running", "success", "error"
CANCELLING, CANCELLED = "cancelling", "cancelled"
PAUSING, PAUSED = "pausing", "paused"
# A job still doing (or winding down) work. CANCELLING is active — the worker is
# on its way to a clean stop — so a status poll keeps tracking it. PAUSING/PAUSED
# are active too: the worker thread is alive, parked inside checkpoint().
_ACTIVE = (PENDING, RUNNING, CANCELLING, PAUSING, PAUSED)
_TERMINAL = (SUCCESS, ERROR, CANCELLED)

_LOCK = threading.Lock()
_HOST = socket.gethostname()
_PAUSE_POLL_S = 1.0


class JobCancelled(Exception):
    """Raised by :func:`checkpoint` when a Stop has been requested. A worker may
    let it propagate (``run_async`` marks the job ``cancelled``) or catch it to
    run compensations first, then re-raise or ``finish_cancelled`` itself."""


def _state_dir() -> Path:
    """Where the job ledger lives.

    ``SATOM_JOBS_DIR`` overrides the in-tree default. This exists so a test run
    -- or any throwaway process -- cannot write into the PRODUCTION ledger: the
    suite creates real job files that nobody ever finishes, and the toast dock
    replays every active job on every navigation, so those ghosts become a
    floating window with a Stop button that can never work. Same isolation
    pattern as FORTINET_DIAG_DIR."""
    override = os.environ.get("SATOM_JOBS_DIR")
    d = (Path(override) if override
         else Path(__file__).resolve().parents[2] / "data" / "jobs")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(job_id: str) -> Path:
    return _state_dir() / f"{job_id}.json"


def _write(job_id: str, state: dict) -> None:
    p = _path(job_id)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, default=str), encoding="utf-8")
    os.replace(tmp, p)


def _new_id() -> str:
    # Time-prefixed (filename sort == creation order) + a random suffix so two
    # jobs created in the same millisecond — even by different worker
    # processes — can never collide and silently overwrite each other.
    return (datetime.utcnow().strftime("%Y%m%d-%H%M%S-")
            + str(int(time.time() * 1000) % 100000)
            + "-" + uuid.uuid4().hex[:6])


def create_job(type_: str, title: str, *, by: str = "",
               meta: dict | None = None, cancelable: bool = True,
               reversible: bool = False, background: bool = False) -> dict:
    """Create a pending job.

    ``cancelable`` — the UI offers a Stop control (default True). Set False for
    physically un-stoppable work (a firmware flash + reboot in progress).
    ``reversible`` — this job type can compensate committed changes on cancel
    (default False; read-only jobs stay False). Purely advisory metadata the UI
    reads so it never promises an undo the worker can't deliver.
    ``background`` — nobody is waiting on this job. It is housekeeping fired
    from a page that refreshes itself (a monitoring sweep), so the toast dock
    skips it ENTIRELY: it still lives on the Jobs page with its full progress
    and log, and the only thing that reaches the operator unprompted is a bell
    notification when it FAILS. Default False — a job is foreground unless it
    says otherwise, so no new job type can go silent by accident.
    """
    job_id = _new_id()
    now = datetime.utcnow().isoformat()
    meta = dict(meta or {})
    if not meta.get("product"):
        # Which ADOM launched it — '' when unscoped (worker thread / global).
        try:
            from .product_scope import stamp
            meta["product"] = stamp()
        except Exception:  # noqa: BLE001 — scoping is best-effort, never fatal
            meta["product"] = ""
    state = {
        "id": job_id, "type": type_, "title": title, "status": PENDING,
        "percent": 0, "message": "", "result": None, "error": None,
        "by": by or "", "meta": meta,
        "cancelable": bool(cancelable), "reversible": bool(reversible),
        "background": bool(background),
        "cancel_requested": False, "pause_requested": False,
        "host": _HOST, "pid": None,
        "created": now, "updated": now, "finished": None,
    }
    with _LOCK:
        _write(job_id, state)
    return state


def get_job(job_id: str) -> dict | None:
    p = _path(job_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a half-written file just reads as absent
        return None


def update_job(job_id: str, **fields) -> dict | None:
    with _LOCK:
        st = get_job(job_id)
        if not st:
            return None
        st.update(fields)
        st["updated"] = datetime.utcnow().isoformat()
        _write(job_id, st)
        return st


def mutate_job(job_id: str, fn) -> dict | None:
    """Atomic read-modify-write under the process lock: ``fn(state)`` edits the
    dict IN PLACE (nested ``meta`` included — the one thing ``update_job``'s
    flat field replace can't do safely from concurrent worker threads).
    Returns the updated state, or None if the job is unknown."""
    with _LOCK:
        st = get_job(job_id)
        if not st:
            return None
        fn(st)
        st["updated"] = datetime.utcnow().isoformat()
        _write(job_id, st)
        return st


def set_progress(job_id: str, percent: int, message: str | None = None) -> None:
    # A pending cancel takes priority — reflect it in the status even while the
    # worker is still ticking progress on its way to a checkpoint. A pending
    # pause likewise shows as pausing/paused rather than snapping back to running.
    st = get_job(job_id) or {}
    if st.get("cancel_requested"):
        status = CANCELLING
    elif st.get("pause_requested"):
        status = st.get("status") if st.get("status") in (PAUSING, PAUSED) else PAUSING
    else:
        status = RUNNING
    fields = {"status": status, "percent": max(0, min(100, int(percent)))}
    if message is not None:
        fields["message"] = message
    update_job(job_id, **fields)


def finish_success(job_id: str, *, message: str = "", result=None) -> None:
    update_job(job_id, status=SUCCESS, percent=100, message=message,
               result=result, error=None,
               finished=datetime.utcnow().isoformat())


def finish_error(job_id: str, error: str) -> None:
    update_job(job_id, status=ERROR, message=error, error=error,
               finished=datetime.utcnow().isoformat())


def finish_cancelled(job_id: str, *, message: str = "Stopped", result=None) -> None:
    """Terminal ``cancelled`` state (distinct from ``error`` — a Stop is not a
    failure). ``result`` typically carries the rollback / mid-change report."""
    update_job(job_id, status=CANCELLED, message=message, result=result,
               error=None, finished=datetime.utcnow().isoformat())


# ── cooperative cancellation ────────────────────────────────────────────────
def request_cancel(job_id: str) -> dict | None:
    """Ask a job to stop. Sets ``cancel_requested`` and flips an active job to
    ``cancelling`` (a terminal job is left untouched). Any gunicorn worker may
    call this — the running worker sees it at its next checkpoint. Returns the
    updated job, or None if unknown."""
    with _LOCK:
        st = get_job(job_id)
        if not st:
            return None
        if st.get("status") in _TERMINAL:
            return st
        st["cancel_requested"] = True
        st["pause_requested"] = False   # a Stop overrides a pending/active pause
        if st.get("status") in (PENDING, RUNNING, PAUSING, PAUSED):
            st["status"] = CANCELLING
        st["updated"] = datetime.utcnow().isoformat()
        _write(job_id, st)
        return st


def is_cancel_requested(job_id: str) -> bool:
    """Cheap read of the cancel flag — safe to poll in a worker's inner loop."""
    st = get_job(job_id)
    return bool(st and st.get("cancel_requested"))


# ── cooperative pause / resume ──────────────────────────────────────────────
def request_pause(job_id: str) -> dict | None:
    """Ask a job to pause at its next safe checkpoint. Same file-mediated
    contract as :func:`request_cancel` — any worker process may set the flag;
    the running worker parks *inside* :func:`checkpoint` until resumed (or
    stopped). No effect on terminal or already-cancelling jobs."""
    with _LOCK:
        st = get_job(job_id)
        if not st:
            return None
        if st.get("status") in _TERMINAL or st.get("cancel_requested"):
            return st
        st["pause_requested"] = True
        if st.get("status") in (PENDING, RUNNING):
            st["status"] = PAUSING
        st["updated"] = datetime.utcnow().isoformat()
        _write(job_id, st)
        return st


def request_resume(job_id: str) -> dict | None:
    """Clear a pending pause. The parked worker leaves checkpoint() within
    ~1s and the job reads ``running`` again."""
    with _LOCK:
        st = get_job(job_id)
        if not st:
            return None
        if st.get("status") in _TERMINAL:
            return st
        st["pause_requested"] = False
        if st.get("status") in (PAUSING, PAUSED):
            st["status"] = RUNNING
        st["updated"] = datetime.utcnow().isoformat()
        _write(job_id, st)
        return st


def is_pause_requested(job_id: str) -> bool:
    st = get_job(job_id)
    return bool(st and st.get("pause_requested"))


def checkpoint(job_id: str) -> None:
    """Raise :class:`JobCancelled` if a Stop has been requested; PARK here while
    a pause is requested. Call at the worker's *safe* points (between devices /
    between items) — never mid-write. While parked the job shows ``paused``; a
    Stop issued during the pause raises immediately (no resume needed)."""
    if is_cancel_requested(job_id):
        raise JobCancelled(job_id)
    parked = False
    while is_pause_requested(job_id):
        if not parked:
            parked = True
            update_job(job_id, status=PAUSED,
                       message="Paused — waiting at a safe checkpoint")
        time.sleep(_PAUSE_POLL_S)
        if is_cancel_requested(job_id):
            raise JobCancelled(job_id)
    if parked:
        update_job(job_id, status=RUNNING, message="Resumed")


def list_jobs(*, limit: int = 30, by: str | None = None,
              active_only: bool = False, status: str | None = None,
              type_: str | None = None) -> list[dict]:
    """Most-recent first (the filename carries the UTC timestamp). ``by`` filters
    to one owner; ``active_only`` keeps only active (pending/running/cancelling/
    pausing/paused) jobs; ``status``/``type_`` filter exactly."""
    out: list[dict] = []
    for p in sorted(_state_dir().glob("*.json"), reverse=True):
        try:
            st = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if by is not None and (st.get("by") or "") != by:
            continue
        if active_only and st.get("status") not in _ACTIVE:
            continue
        if status and st.get("status") != status:
            continue
        if type_ and st.get("type") != type_:
            continue
        out.append(st)
        if len(out) >= limit:
            break
    return out


def run_async(flask_app, job_id: str, worker) -> None:
    """Run ``worker(flask_app, job_id)`` in a daemon thread. Marks the job
    ``running`` immediately (so the first poll reflects it); on return without
    the worker finishing it itself → ``success`` (or ``cancelled`` if a Stop was
    requested); on :class:`JobCancelled` → ``cancelled``; on any other exception
    → ``error``."""
    update_job(job_id, status=RUNNING, pid=os.getpid(), host=_HOST)

    def _runner():
        try:
            result = worker(flask_app, job_id)
            st = get_job(job_id) or {}
            if st.get("status") in _ACTIVE:   # worker didn't finish itself
                if st.get("cancel_requested"):
                    finish_cancelled(job_id, result=result)
                else:
                    finish_success(job_id, result=result)
        except JobCancelled:
            st = get_job(job_id) or {}
            if st.get("status") in _ACTIVE:   # worker didn't finalize itself
                finish_cancelled(job_id)
        except Exception as exc:  # noqa: BLE001 — a failed job never kills the worker
            try:
                flask_app.logger.exception("background job %s failed", job_id)
            except Exception:  # noqa: BLE001
                pass
            st = get_job(job_id) or {}
            if st.get("status") in _ACTIVE:   # worker didn't record its own error
                finish_error(job_id, f"{type(exc).__name__}: {exc}"[:300])

    threading.Thread(target=_runner, name=f"job-{job_id}", daemon=True).start()


class Rollback:
    """Reusable compensation accumulator — the *mechanism* half of rollback.

    A worker registers a compensating callable as each reversible step commits::

        rb = Rollback()
        r = ops.create(ep, data, mkey=name, dry_run=False)
        if r.ok:
            rb.add(lambda: ops.delete(ep, name, dry_run=False),
                   label=f"delete {ep}/{name}")

    On cancel/failure ``rb.run()`` replays them **in reverse** (LIFO — undo the
    newest change first), best-effort: one failing compensation never stops the
    rest, and every outcome is reported. The framework owns the replay; the
    caller owns *what* each undo does (only it knows how). Pure — no Flask/DB."""

    def __init__(self) -> None:
        self._steps: list[tuple] = []

    def __len__(self) -> int:
        return len(self._steps)

    def add(self, undo, *, label: str = "") -> None:
        """Register ``undo()`` (a zero-arg callable) to reverse the step just
        committed. Registered in commit order; replayed in reverse."""
        self._steps.append((undo, label))

    def run(self) -> list[dict]:
        """Replay compensations newest-first, best-effort. Returns one
        ``{label, ok, error}`` per step (in replay order)."""
        report: list[dict] = []
        for undo, label in reversed(self._steps):
            try:
                undo()
                report.append({"label": label, "ok": True, "error": ""})
            except Exception as exc:  # noqa: BLE001 — one bad undo never sinks the rest
                report.append({"label": label, "ok": False,
                               "error": f"{type(exc).__name__}: {exc}"[:200]})
        return report


def _pid_alive(pid: int) -> bool:
    """True when ``pid`` exists AND still looks like one of our python/gunicorn
    processes (guards against PID reuse after a reboot)."""
    try:
        os.kill(pid, 0)
    except (OSError, TypeError, ValueError):
        return False
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
        return ("python" in cmd) or ("gunicorn" in cmd)
    except Exception:  # noqa: BLE001 — no /proc (mac/tests): liveness alone decides
        return True


def sweep_orphans(*, stale_after_s: int = 3600,
                  no_pid_stale_after_s: int = 600) -> list[dict]:
    """Mark active jobs whose worker no longer exists as terminal ``error``.

    A worker is a daemon thread inside a gunicorn worker process: a service
    restart kills it without touching the job file, leaving a forever-"running"
    ghost (the fw5 signatures_sync incident). Called once at app startup — any
    booting worker may run it, the atomic write makes it idempotent. Rules:

    * active job, ``pid`` recorded, that pid is gone → orphan.
    * active job with NO pid not updated for ``no_pid_stale_after_s`` →
      orphan. ``run_async`` stamps the pid the instant the worker thread
      starts, so a job still missing one minutes later was never dispatched
      (the request died, or a test built it and walked away). A false positive
      self-heals: if the worker does start, it rewrites status + pid.
    * a job on another host (shared/synced data dir) is never touched.
    """
    swept: list[dict] = []
    for st in list_jobs(limit=1000, active_only=True):
        if (st.get("host") or _HOST) != _HOST:
            continue
        pid = st.get("pid")
        if pid:
            if _pid_alive(int(pid)):
                continue
        else:
            try:
                age = time.time() - datetime.fromisoformat(
                    st.get("updated") or st.get("created")).timestamp()
            except Exception:  # noqa: BLE001
                age = stale_after_s + 1
            if age <= no_pid_stale_after_s:
                continue
        updated = update_job(
            st["id"], status=ERROR,
            error="Orphaned — the service restarted while this job was running.",
            message="Orphaned — the service restarted while this job was running.",
            finished=datetime.utcnow().isoformat())
        if updated:
            swept.append(updated)
    return swept


_SWEEP_EVERY_S = 120.0
_SWEEP_LOCK = threading.Lock()   # NOT _LOCK: sweep_orphans writes under _LOCK
_last_sweep = 0.0


def maybe_sweep_orphans() -> list[dict]:
    """Throttled sweep for the read paths (the dock feed, the Job Manager).

    Sweeping only at boot is not enough: a job that goes stale AFTER boot stays
    active until the next restart, and the dock re-opens a toast for it on
    every single navigation. Runs at most every ``_SWEEP_EVERY_S`` and scans
    active jobs only, so the poll stays cheap. Never raises -- housekeeping must
    not be able to break the feed it is cleaning."""
    global _last_sweep
    now = time.monotonic()
    with _SWEEP_LOCK:
        if now - _last_sweep < _SWEEP_EVERY_S:
            return []
        _last_sweep = now
    try:
        return sweep_orphans()
    except Exception:  # noqa: BLE001
        return []


def prune(older_than_days: int = 7, *, keep_active: bool = True) -> int:
    """Housekeeping: delete finished job files older than N days. Returns count."""
    cutoff = time.time() - older_than_days * 86400
    removed = 0
    for p in _state_dir().glob("*.json"):
        try:
            if p.stat().st_mtime >= cutoff:
                continue
            if keep_active:
                st = json.loads(p.read_text(encoding="utf-8"))
                if st.get("status") in _ACTIVE:
                    continue
            p.unlink()
            removed += 1
        except Exception:  # noqa: BLE001
            continue
    return removed
