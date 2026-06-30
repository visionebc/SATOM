"""Fleet-scale deep-capture orchestration: a resumable, checkpointed job over
many devices, with a bounded device-level worker pool. Progress + per-device
state live in a JSON file (worker-proof under multi-worker gunicorn, exactly
like rediscovery's progress files). A crash or one unreachable box never
restarts the other devices — resume re-runs only the not-yet-ingested ones.

Designed to scale linearly to ~100 appliances: the speed comes from running N
*devices* concurrently (run_fleet's bounded pool), while each device's walk
stays serial (gentle on the appliance — a FortiWeb is not a load balancer).
"""
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

_DONE = "ingested"

# Device-level fan-out is where speed comes from at 100 boxes; keep it bounded so
# the DB + network stay healthy. Intra-device reads stay serial (the walker).
DEFAULT_MAX_WORKERS = 8

_LOCK = threading.Lock()


def _state_dir() -> Path:
    d = Path(__file__).resolve().parents[2] / "data" / "deep_jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(job_id: str) -> Path:
    return _state_dir() / f"{job_id}.json"


def _write(job_id: str, state: dict) -> None:
    p = _path(job_id)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, p)


def new_job(*, device_ids: list[int], by: str = "") -> dict:
    job_id = (datetime.utcnow().strftime("%Y%m%d-%H%M%S-")
              + str(int(time.time() * 1000) % 100000))
    state = {
        "job_id": job_id, "by": by, "started": datetime.utcnow().isoformat(),
        "finished": None, "total": len(device_ids), "done": 0, "percent": 0,
        "devices": {str(i): {"state": "pending", "objects": 0, "error": None}
                    for i in device_ids},
    }
    _write(job_id, state)
    return state


def load_job(job_id: str) -> dict | None:
    p = _path(job_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def list_jobs(limit: int = 20) -> list[dict]:
    """Most-recent jobs first (filename carries the UTC timestamp)."""
    paths = sorted(_state_dir().glob("*.json"), reverse=True)[:limit]
    out = []
    for p in paths:
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    return out


def mark_device(job_id: str, device_id: int, state_name: str, *, objects: int = 0,
                error: str | None = None) -> None:
    with _LOCK:
        st = load_job(job_id)
        if not st:
            return
        dev = st["devices"].setdefault(str(device_id), {})
        dev.update(state=state_name, objects=objects, error=error,
                   updated=datetime.utcnow().isoformat())
        done = sum(1 for d in st["devices"].values() if d.get("state") == _DONE)
        st["done"] = done
        st["percent"] = int(done * 100 / st["total"]) if st["total"] else 100
        if all(d.get("state") in (_DONE, "failed") for d in st["devices"].values()):
            st["finished"] = datetime.utcnow().isoformat()
        _write(job_id, st)


def pending_device_ids(job_id: str) -> list[int]:
    st = load_job(job_id) or {"devices": {}}
    return [int(i) for i, d in st["devices"].items() if d.get("state") != _DONE]
