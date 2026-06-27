"""Rediscovery — re-read **all** config objects of a FortiWeb in one sweep.

The user's "rediscovery" button: a single read-only pass that GETs every
top-level CMDB endpoint in the registry (``endpoints.yaml``), captures the
object lists section by section, and writes a ``_config.json`` snapshot under
``data/rediscovery/<appliance_id>/`` so the whole box's state is refreshed at
once.

Web port of the desktop ``services/rediscovery.py``, reimplemented against the
web's flat endpoint registry + the simple :class:`FortiWebClient`. It runs in a
background thread and reports progress through a **file** (``progress.json``) —
the app serves under gunicorn with 4 workers, so an in-memory progress dict
would be invisible to the worker that handles the poll; a file is worker-proof.

By-parent sub-tables (a child whose parent URN is itself an endpoint, e.g.
``server-pool/pserver-list``) are skipped — they need an ``mkey`` and their deep
contents belong to the Policy Inspector; this sweep is the object-list layer.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..clients.fortiweb import FortiWebClient
from ..registry import loader


def _data_dir() -> Path:
    d = Path(__file__).resolve().parents[2] / "data" / "rediscovery"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _dev_dir(appliance_id: int) -> Path:
    d = _data_dir() / str(appliance_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_json(path: Path, obj: Any) -> None:
    """Atomic write so a poller never reads a half-written file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _normalize(urn: str) -> str:
    """Drop a leading ``/api/v2.X/`` so URNs compare uniformly."""
    return (urn or "").lstrip("/").split("/", 2)[-1] if "/api/" in (urn or "") else (urn or "").lstrip("/")


def sweep_plan() -> list[dict]:
    """The top-level CMDB GET endpoints to sweep (by-parent children dropped)."""
    eps = [e for e in loader.get_all_endpoints() if "/cmdb/" in (e.get("urn") or "")]
    urn_set = {_normalize(e["urn"]) for e in eps}
    plan: list[dict] = []
    for e in eps:
        nu = _normalize(e["urn"])
        parent = nu.rsplit("/", 1)[0] if "/" in nu else ""
        if parent and parent in urn_set:
            continue  # by-parent sub-table — needs an mkey; skip in the list layer
        plan.append({"name": e["name"], "urn": e["urn"], "section": e.get("section") or "Other"})
    return plan


def status(appliance_id: int) -> dict | None:
    """Current/last run progress for an appliance (None if never run)."""
    p = _dev_dir(appliance_id) / "progress.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def latest_snapshot_meta(appliance_id: int) -> dict | None:
    p = _dev_dir(appliance_id) / "_config.json"
    if not p.exists():
        return None
    try:
        snap = json.loads(p.read_text(encoding="utf-8"))
        return {
            "generated_at": snap.get("generated_at"),
            "sections": len(snap.get("sections") or {}),
            "objects": snap.get("total_objects"),
        }
    except Exception:  # noqa: BLE001
        return None


def _client_snapshot(appliance) -> SimpleNamespace:
    """A DB-detached copy of just the fields FortiWebClient reads, so the worker
    thread never touches the SQLAlchemy session."""
    return SimpleNamespace(
        id=appliance.id, name=appliance.name, host=appliance.host,
        port=appliance.port, verify_ssl=appliance.verify_ssl,
        username=appliance.username, password=appliance.password,
        vdom=appliance.vdom,
    )


def _run(appliance_snap: SimpleNamespace, by: str) -> None:
    aid = appliance_snap.id
    devdir = _dev_dir(aid)
    progress_path = devdir / "progress.json"
    plan = sweep_plan()
    total = len(plan)
    started = datetime.utcnow().isoformat()
    state = {
        "state": "running", "appliance_id": aid, "appliance": appliance_snap.name,
        "total": total, "done": 0, "percent": 0, "objects": 0,
        "started": started, "by": by, "section": "", "errors": [], "finished": None,
    }
    _write_json(progress_path, state)

    client = FortiWebClient(appliance_snap, timeout=20.0)
    sections: dict[str, dict[str, list]] = {}
    total_objects = 0
    errors: list[dict] = []
    for i, ep in enumerate(plan, 1):
        try:
            rows = client._results_list(client.get(ep["urn"]).json())
            rows = [r for r in rows if isinstance(r, dict)]
            if rows:
                sections.setdefault(ep["section"], {})[ep["name"]] = rows
                total_objects += len(rows)
        except Exception as exc:  # noqa: BLE001 — one endpoint never sinks the sweep
            errors.append({"endpoint": ep["name"], "error": f"{type(exc).__name__}: {exc}"[:160]})
        if i % 5 == 0 or i == total:
            state.update(done=i, percent=int(i * 100 / total) if total else 100,
                         objects=total_objects, section=ep["section"], errors=errors[-25:])
            _write_json(progress_path, state)

    generated_at = datetime.utcnow().isoformat()
    snapshot = {
        "device": appliance_snap.name, "appliance_id": aid, "generated_at": generated_at,
        "by": by, "endpoints_swept": total, "total_objects": total_objects,
        "section_count": len(sections), "sections": sections, "errors": errors,
    }
    _write_json(devdir / "_config.json", snapshot)
    state.update(state="done", done=total, percent=100, objects=total_objects,
                 section_count=len(sections), errors=errors, finished=generated_at,
                 summary=f"{total_objects} object(s) across {len(sections)} section(s) "
                         f"from {total} endpoint(s)" + (f", {len(errors)} error(s)" if errors else ""))
    _write_json(progress_path, state)


def start(appliance, by: str = "") -> dict:
    """Kick off a rediscovery sweep in a background thread.

    Refuses to start a second concurrent run for the same appliance. Returns the
    initial progress dict.
    """
    cur = status(appliance.id)
    if cur and cur.get("state") == "running":
        # guard against a stuck 'running' flag: only block if it looks live (<15 min)
        try:
            age = time.time() - datetime.fromisoformat(cur["started"]).timestamp()
        except Exception:  # noqa: BLE001
            age = 0
        if age < 900:
            return {"started": False, "reason": "a rediscovery is already running", "progress": cur}

    snap = _client_snapshot(appliance)
    init = {"state": "running", "appliance_id": appliance.id, "appliance": appliance.name,
            "total": 0, "done": 0, "percent": 0, "objects": 0,
            "started": datetime.utcnow().isoformat(), "by": by, "errors": [], "finished": None}
    _write_json(_dev_dir(appliance.id) / "progress.json", init)
    threading.Thread(target=_run, args=(snap, by), daemon=True).start()
    return {"started": True, "progress": init}


__all__ = ["sweep_plan", "status", "latest_snapshot_meta", "start"]
