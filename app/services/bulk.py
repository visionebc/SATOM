"""Dry-run preview + canary fleet-apply runner over ``FortiWebOps``.

The mandatory discipline for any fleet config push: **preview (dry-run) across
all targets**, then **apply for real with a canary** — the canary device runs
first and, if it fails, the rest are skipped. Mirrors the desktop ``BulkRunner``.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from ..models import Appliance
from .fortiweb_ops import FortiWebOps

_MAX_WORKERS = 8


def iter_push_items(body) -> list[dict]:
    """Flatten a template/profile body into ordered push items (sub-objects first).

    Each item = ``{action, endpoint, mkey, data}``. A node may carry
    ``subobjects: [...]`` which are emitted BEFORE their parent (dependency
    order), so referenced objects exist before the object that references them.
    """
    items: list[dict] = []

    def _walk(node: dict) -> None:
        for sub in node.get("subobjects", []) or []:
            if isinstance(sub, dict):
                _walk(sub)
        if node.get("endpoint"):
            items.append({
                "action": node.get("action", "create"),
                "endpoint": node["endpoint"],
                "mkey": node.get("mkey"),
                "data": node.get("data", {}),
            })

    if isinstance(body, dict):
        _walk(body)
    elif isinstance(body, list):
        for n in body:
            if isinstance(n, dict):
                _walk(n)
    return items


def _run_one(appliance, items, dry_run) -> dict:
    ops = FortiWebOps(appliance)
    results = []
    for it in items:
        action = it.get("action", "create")
        if action == "create":
            r = ops.create(it["endpoint"], it.get("data", {}), mkey=it.get("mkey"), dry_run=dry_run)
        elif action == "update":
            r = ops.update(it["endpoint"], it.get("mkey"), it.get("data", {}), dry_run=dry_run)
        elif action == "delete":
            r = ops.delete(it["endpoint"], it.get("mkey"), dry_run=dry_run)
        else:
            r = {"ok": False, "error": f"unknown action {action}", "endpoint": it.get("endpoint")}
        results.append(r)
        if not r.get("ok") and not dry_run:
            break  # stop this device on the first real failure
    return {
        "appliance_id": getattr(appliance, "id", None),
        "appliance": getattr(appliance, "name", ""),
        "ok": all(r.get("ok") for r in results) if results else True,
        "results": results,
    }


def start_apply_job(flask_app, *, title: str, items: list[dict],
                    device_ids, by: str, meta: dict | None = None,
                    canary: int = 1, audit_action: str = "bulk.apply",
                    audit_target: str = "") -> dict:
    """Launch a canary-gated fleet apply as a background job (services.jobs).

    Fleet writes must not run inside an HTTP request: with a large fleet the
    rollout outlives any gunicorn/proxy timeout and a dropped connection would
    kill it midway. The job survives the request, reports per-device progress
    to the toast dock, and writes the completion audit row itself.
    Returns the created job dict (poll ``/jobs/<id>``)."""
    from . import jobs

    job = jobs.create_job("bulk_apply", title, by=by, meta=meta or {})

    def _worker(app, job_id):
        with app.app_context():
            def _cb(done, total, name):
                pct = int(done * 100 / max(1, total))
                jobs.set_progress(job_id, pct, f"{name} — {done}/{total} device(s)")

            result = BulkRunner(items).apply(device_ids, canary=canary,
                                             progress_cb=_cb)
            runs = (result.get("canary") or []) + (result.get("rest") or [])
            ok_count = sum(1 for r in runs if r.get("ok"))
            summary = {
                "aborted": bool(result.get("aborted")),
                "ok": ok_count, "total": len(runs),
                "devices": [{"appliance": r.get("appliance"),
                             "ok": bool(r.get("ok"))} for r in runs],
                "detail": result,
            }
            try:
                from .audit import log_action
                log_action(audit_action, target=audit_target,
                           detail=f"by={by} devices={device_ids} "
                                  f"items={len(items)} "
                                  f"aborted={summary['aborted']} "
                                  f"ok={ok_count}/{len(runs)}")
            except Exception:  # noqa: BLE001 — audit is best-effort here
                app.logger.exception("bulk apply audit write failed")
            if summary["aborted"]:
                jobs.update_job(job_id, result=summary)
                jobs.finish_error(
                    job_id, f"Aborted — canary device failed "
                            f"({ok_count}/{len(runs)} ok)")
            elif ok_count < len(runs):
                jobs.update_job(job_id, result=summary)
                jobs.finish_error(
                    job_id, f"Completed with failures — "
                            f"{ok_count}/{len(runs)} device(s) ok")
            else:
                jobs.finish_success(
                    job_id,
                    message=f"Applied to {ok_count}/{len(runs)} device(s)",
                    result=summary)

    jobs.run_async(flask_app, job["id"], _worker)
    return job


class BulkRunner:
    def __init__(self, items: list[dict]):
        self.items = items

    def _appliances(self, device_ids):
        if device_ids:
            return Appliance.query.filter(Appliance.id.in_(device_ids)).all()
        return Appliance.query.all()

    def preview(self, device_ids) -> list[dict]:
        """Dry-run across all targets — pure, no device contact."""
        return [_run_one(d, self.items, dry_run=True) for d in self._appliances(device_ids)]

    def apply(self, device_ids, canary: int = 1, progress_cb=None) -> dict:
        """Canary subset first (real writes); abort the rest if the canary fails.

        ``progress_cb(done, total, device_name)`` — optional, called after each
        device finishes, so a background job can report live progress. It must
        never raise into the rollout (guarded)."""
        devs = self._appliances(device_ids)
        if not devs:
            return {"canary": [], "rest": [], "aborted": False}

        total = len(devs)
        done_count = 0
        cb_lock = threading.Lock()

        def _tick(name: str) -> None:
            nonlocal done_count
            if progress_cb is None:
                return
            with cb_lock:
                done_count += 1
                try:
                    progress_cb(done_count, total, name)
                except Exception:  # noqa: BLE001 — progress must never sink a rollout
                    pass

        def _run_and_tick(d):
            r = _run_one(d, self.items, dry_run=False)
            _tick(r.get("appliance") or "")
            return r

        canary = max(1, canary)
        canary_devs, rest_devs = devs[:canary], devs[canary:]
        canary_res = [_run_and_tick(d) for d in canary_devs]
        if not all(r["ok"] for r in canary_res):
            return {"canary": canary_res, "rest": [], "aborted": True}
        rest_res = []
        if rest_devs:
            with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(rest_devs))) as ex:
                rest_res = list(ex.map(_run_and_tick, rest_devs))
        return {"canary": canary_res, "rest": rest_res, "aborted": False}
