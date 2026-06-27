"""Dry-run preview + canary fleet-apply runner over ``FortiWebOps``.

The mandatory discipline for any fleet config push: **preview (dry-run) across
all targets**, then **apply for real with a canary** — the canary device runs
first and, if it fails, the rest are skipped. Mirrors the desktop ``BulkRunner``.
"""
from __future__ import annotations

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

    def apply(self, device_ids, canary: int = 1) -> dict:
        """Canary subset first (real writes); abort the rest if the canary fails."""
        devs = self._appliances(device_ids)
        if not devs:
            return {"canary": [], "rest": [], "aborted": False}
        canary = max(1, canary)
        canary_devs, rest_devs = devs[:canary], devs[canary:]
        canary_res = [_run_one(d, self.items, dry_run=False) for d in canary_devs]
        if not all(r["ok"] for r in canary_res):
            return {"canary": canary_res, "rest": [], "aborted": True}
        rest_res = []
        if rest_devs:
            with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(rest_devs))) as ex:
                rest_res = list(ex.map(lambda d: _run_one(d, self.items, dry_run=False), rest_devs))
        return {"canary": canary_res, "rest": rest_res, "aborted": False}
