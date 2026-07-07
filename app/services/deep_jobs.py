"""Fleet deep-capture on the GLOBAL background-job framework (services.jobs).

Migrated 2026-07-03 from the standalone ``data/deep_jobs`` JSON store: a deep
capture is now an ordinary ``deep_capture`` job, so it shows up in the global
Job Manager (Global → Jobs) with live progress, ownership, worker host/pid and
the cooperative Pause / Resume / Stop controls — and the boot orphan sweep
fails it cleanly if the service restarts mid-run (no more ghost jobs).

What is kept from the old design:

* the per-device checkpoint LEDGER (pending/capturing/ingested/failed/skipped +
  object counts + errors) — now living in the job's ``meta["devices"]``;
* the bounded device-level pool (speed comes from N devices in parallel, each
  device's walk stays serial — gentle on the appliance);
* the legacy poll shape (``job_id``/``total``/``done``/``percent``/``devices``/
  ``finished``) the Analysis page consumes, projected by :func:`load_job`.

Old ``data/deep_jobs/*.json`` files are inert history — nothing reads them.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import jobs

JOB_TYPE = "deep_capture"
_DONE = "ingested"
_SETTLED = (_DONE, "failed", "skipped")

# Device-level fan-out is where speed comes from at 100 boxes; keep it bounded so
# the DB + network stay healthy. Intra-device reads stay serial (the walker).
DEFAULT_MAX_WORKERS = 8


def new_job(*, device_ids: list[int], by: str = "") -> dict:
    """Create the global job carrying the per-device ledger. Returns the legacy
    projection (``job_id`` etc.) so existing callers keep working."""
    devices = {str(i): {"state": "pending", "objects": 0, "error": None}
               for i in device_ids}
    job = jobs.create_job(
        JOB_TYPE, "Deep capture — %d device(s)" % len(device_ids), by=by,
        meta={"devices": devices})
    return load_job(job["id"])


def load_job(job_id: str) -> dict | None:
    """The legacy poll shape the Analysis page consumes, projected straight off
    the global job file (single source of truth)."""
    st = jobs.get_job(job_id)
    if not st or st.get("type") != JOB_TYPE:
        return None
    devices = (st.get("meta") or {}).get("devices") or {}
    done = sum(1 for d in devices.values() if d.get("state") == _DONE)
    total = len(devices)
    return {
        "job_id": st["id"], "id": st["id"], "by": st.get("by", ""),
        "status": st.get("status"), "started": st.get("created"),
        "finished": st.get("finished"), "total": total, "done": done,
        "percent": int(done * 100 / total) if total else 100,
        "devices": devices,
    }


def mark_device(job_id: str, device_id: int, state_name: str, *, objects: int = 0,
                error: str | None = None) -> None:
    """Checkpoint one device's state into the ledger (atomic nested-meta write)
    and tick the job's visible progress."""
    def _mut(st: dict) -> None:
        dev = (st.setdefault("meta", {}).setdefault("devices", {})
               .setdefault(str(device_id), {}))
        dev.update(state=state_name, objects=objects, error=error,
                   updated=datetime.utcnow().isoformat())

    st = jobs.mutate_job(job_id, _mut)
    if not st or st.get("status") not in jobs._ACTIVE:
        return
    devices = (st.get("meta") or {}).get("devices") or {}
    done = sum(1 for d in devices.values() if d.get("state") == _DONE)
    settled = sum(1 for d in devices.values() if d.get("state") in _SETTLED)
    total = len(devices) or 1
    jobs.set_progress(job_id, int(settled * 100 / total),
                      "%d/%d device(s) captured" % (done, len(devices)))


def pending_device_ids(job_id: str) -> list[int]:
    st = load_job(job_id) or {"devices": {}}
    return [int(i) for i, d in st["devices"].items() if d.get("state") != _DONE]


def run_fleet(job_id: str, device_ids: list[int], capture_fn, *,
              max_workers: int = DEFAULT_MAX_WORKERS) -> dict:
    """Run ``capture_fn(device_id) -> object_count`` for each device with a
    bounded device-level pool, checkpointing per device. One box raising never
    sinks the fleet — it is marked ``failed`` and the others continue. A Stop
    finishes the in-flight devices and marks the rest ``skipped``; a Pause parks
    every pool thread at the pre-device checkpoint.

    ``capture_fn`` runs in a worker thread, so it MUST open its own Flask app
    context / DB session (see deep_jobs.capture_device)."""
    def _one(device_id: int):
        try:
            jobs.checkpoint(job_id)   # park on pause; JobCancelled on stop
        except jobs.JobCancelled:
            mark_device(job_id, device_id, "skipped",
                        error="stopped before capture")
            return
        mark_device(job_id, device_id, "capturing")
        try:
            n = capture_fn(device_id)
            mark_device(job_id, device_id, _DONE, objects=int(n or 0))
        except Exception as exc:  # noqa: BLE001 — one box never sinks the fleet
            mark_device(job_id, device_id, "failed",
                        error=f"{type(exc).__name__}: {exc}"[:200])

    with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as ex:
        list(ex.map(_one, device_ids))
    return load_job(job_id) or {}


def capture_device(flask_app, appliance_id: int) -> int:
    """Deep-capture ONE device end-to-end inside a fresh app context (safe to
    call from a worker thread). Returns the deep object count. Raises on a
    missing device / transport failure so run_fleet records it as ``failed``."""
    from . import device_sync
    from ..models import Appliance
    with flask_app.app_context():
        appliance = Appliance.query.get(appliance_id)
        if appliance is None:
            raise ValueError("appliance %s not found" % appliance_id)
        snap = device_sync.deep_snapshot_from_device(appliance)
        device_sync.persist_deep_snapshot(appliance, snap)
        return int(snap.get("total_objects", 0) or 0)


def start_fleet_job(flask_app, device_ids, *, by: str = "",
                    max_workers: int = DEFAULT_MAX_WORKERS) -> dict:
    """Create the job and run the bounded fleet capture through the global
    runner (``jobs.run_async``): the HTTP request returns immediately with the
    legacy job dict; poll ``load_job(job_id)`` (or the global Job Manager).

    Terminal semantics: every device failed → ``error`` (a fleet-wide dead
    destination must never read as success); a Stop → ``cancelled``; otherwise
    ``success`` with the per-device summary as the result."""
    ids = [int(i) for i in device_ids]
    job = new_job(device_ids=ids, by=by)
    job_id = job["job_id"]

    def _worker(app, jid):
        st = run_fleet(jid, ids, lambda did: capture_device(app, did),
                       max_workers=max_workers)
        if jobs.is_cancel_requested(jid):
            raise jobs.JobCancelled(jid)
        devices = st.get("devices") or {}
        failed = {i: d.get("error") for i, d in devices.items()
                  if d.get("state") == "failed"}
        if devices and len(failed) == len(devices):
            raise RuntimeError(
                "all %d device(s) failed — first error: %s"
                % (len(failed), next(iter(failed.values())) or "?"))
        return {"done": st.get("done", 0), "total": st.get("total", 0),
                "objects": sum(int(d.get("objects") or 0)
                               for d in devices.values()),
                "failed": failed}

    jobs.run_async(flask_app, job_id, _worker)
    return load_job(job_id)
