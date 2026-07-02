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
     by, meta, created, updated, finished}

    status ∈ pending | running | success | error

Typical use inside a request::

    job = jobs.create_job("firmware_finalize", "Verifying image.out", by=user)
    jobs.run_async(current_app._get_current_object(), job["id"], worker)
    return jsonify({"job_id": job["id"]})          # client polls /jobs/<id>

``worker(app, job_id)`` runs in a daemon thread: it opens its own app context,
reports progress with ``jobs.set_progress(job_id, pct, msg)`` and either returns
a JSON-able result (→ success) or raises (→ error). This module has NO Flask /
DB / Qt imports — it is pure stdlib and unit-testable.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path

PENDING, RUNNING, SUCCESS, ERROR = "pending", "running", "success", "error"
_ACTIVE = (PENDING, RUNNING)

_LOCK = threading.Lock()


def _state_dir() -> Path:
    d = Path(__file__).resolve().parents[2] / "data" / "jobs"
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
    return (datetime.utcnow().strftime("%Y%m%d-%H%M%S-")
            + str(int(time.time() * 1000) % 100000))


def create_job(type_: str, title: str, *, by: str = "",
               meta: dict | None = None) -> dict:
    job_id = _new_id()
    now = datetime.utcnow().isoformat()
    state = {
        "id": job_id, "type": type_, "title": title, "status": PENDING,
        "percent": 0, "message": "", "result": None, "error": None,
        "by": by or "", "meta": meta or {},
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


def set_progress(job_id: str, percent: int, message: str | None = None) -> None:
    fields = {"status": RUNNING, "percent": max(0, min(100, int(percent)))}
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


def list_jobs(*, limit: int = 30, by: str | None = None,
              active_only: bool = False) -> list[dict]:
    """Most-recent first (the filename carries the UTC timestamp). ``by`` filters
    to one owner; ``active_only`` keeps only pending/running jobs."""
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
        out.append(st)
        if len(out) >= limit:
            break
    return out


def run_async(flask_app, job_id: str, worker) -> None:
    """Run ``worker(flask_app, job_id)`` in a daemon thread. Marks the job
    ``running`` immediately (so the first poll reflects it); on return without
    the worker finishing it itself → ``success``; on exception → ``error``."""
    update_job(job_id, status=RUNNING)

    def _runner():
        try:
            result = worker(flask_app, job_id)
            st = get_job(job_id) or {}
            if st.get("status") in _ACTIVE:   # worker didn't finish itself
                finish_success(job_id, result=result)
        except Exception as exc:  # noqa: BLE001 — a failed job never kills the worker
            try:
                flask_app.logger.exception("background job %s failed", job_id)
            except Exception:  # noqa: BLE001
                pass
            finish_error(job_id, f"{type(exc).__name__}: {exc}"[:300])

    threading.Thread(target=_runner, name=f"job-{job_id}", daemon=True).start()


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
