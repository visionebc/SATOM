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


# The deep-capture pass writes to the DB, so it needs a Flask app context inside
# the worker thread. ``start()`` captures the live app here; ``_get_flask_app``
# falls back to ``current_app`` when called from within a request.
_APP = None


def _get_flask_app():
    from flask import current_app
    if _APP is not None:
        return _APP
    return current_app._get_current_object()


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


def sweep_plan_adc() -> list[dict]:
    """The FortiADC sweep plan — delegated to :mod:`app.services.adc_ops`
    (the ADC module holds the fortiadc-side imports; import direction is
    enforced by ``tests/test_product_separation.py``)."""
    from . import adc_ops
    return adc_ops.discovery_plan()


def plan_for(appliance) -> list[dict]:
    """The sweep plan matching the appliance's kind."""
    if getattr(appliance, "kind", "") == "fortiadc":
        return sweep_plan_adc()
    return sweep_plan()


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


def has_snapshot(appliance_id: int) -> bool:
    """True once a rediscovery sweep has written a snapshot for this appliance.

    Cheap existence check (no JSON parse) — drives the **Discovery** vs
    **Rediscovery** label: a never-swept appliance shows "Discovery".
    """
    return (_dev_dir(appliance_id) / "_config.json").exists()


# --- Physical-inventory sync (hybrid: auto-fill, never clobber manual data) ---

def _clean_ip(v) -> str | None:
    v = (v or "").strip()
    if not v:
        return None
    head = v.split()[0].split("/")[0]
    if head in ("0.0.0.0", "::"):
        return None
    return v


def _iface_rows(snapshot: dict) -> list[dict]:
    """All discovered ``system/interface`` rows out of a snapshot."""
    rows: list[dict] = []
    for section in (snapshot.get("sections") or {}).values():
        if not isinstance(section, dict):
            continue
        for name, eprows in section.items():
            n = str(name)
            # FortiWeb logical: "interface*"; FortiADC logical: "system_interface"
            if (n.startswith("interface") or n.endswith("interface")) \
                    and isinstance(eprows, list):
                rows.extend(r for r in eprows if isinstance(r, dict))
    return rows


def _model_from_status(appliance) -> tuple[str | None, str | None, str | None]:
    """Best-effort ``(model, hw_type, firmware)`` from a live status call.

    Returns ``(None, None, None)`` on any failure so a sync never breaks on a
    probe. FortiADC keys off ``/api/platform/version`` (live-verified 8.0.3);
    FortiWeb keeps its ``status.systemstatus`` read (firmware not derived
    there — unchanged behaviour).
    """
    if getattr(appliance, "kind", "") == "fortiadc":
        from . import adc_ops
        return adc_ops.model_inventory(appliance)
    try:
        from ..clients.fortiweb import FortiWebClient
        raw = FortiWebClient(appliance, timeout=15.0).status_check()
        d = raw.get("results", raw) if isinstance(raw, dict) else {}
    except Exception:  # noqa: BLE001
        return None, None, None
    fw = str(d.get("firmwareVersion") or "")
    platform = str(d.get("platformName") or "")
    serial = str(d.get("serialNumber") or "")
    model = fw.split(",")[0].strip() if fw else (platform or None)
    blob = f"{platform} {fw} {serial}".upper()
    if "VM" in blob or "KVM" in blob:
        hw = "vm"
    elif platform or fw:
        hw = "hardware"
    else:
        hw = None
    return (model or None), hw, None


def apply_inventory(appliance) -> dict:
    """Merge the latest discovery snapshot into the physical-inventory tables.

    Hybrid policy: add new interfaces and refresh auto-derived fields
    (type, IP) plus model + HW/VM. NEVER deletes interfaces and NEVER overwrites
    operator-entered fields (``connected_to``, ``notes``) or the datasheet.
    Must run inside a Flask app context (uses the DB session).
    """
    from ..extensions import db
    from ..models import ApplianceInterface

    snap_path = _dev_dir(appliance.id) / "_config.json"
    if not snap_path.exists():
        return {"applied": False, "reason": "no snapshot"}
    try:
        snapshot = json.loads(snap_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {"applied": False, "reason": "unreadable snapshot"}

    existing = {i.name: i for i in appliance.interfaces}
    next_sort = max([i.sort_order or 0 for i in appliance.interfaces], default=-1) + 1
    added = updated = 0
    seen: set[str] = set()
    for row in _iface_rows(snapshot):
        nm = (row.get("name") or row.get("intf") or row.get("mkey") or "").strip()
        if not nm or nm in seen:
            continue
        seen.add(nm)
        if_type = (row.get("type") or "").strip() or None
        ip = _clean_ip(row.get("ip"))
        cur = existing.get(nm)
        if cur is None:
            db.session.add(ApplianceInterface(
                appliance_id=appliance.id, name=nm, if_type=if_type,
                ip_address=ip, sort_order=next_sort))
            next_sort += 1
            added += 1
        else:
            changed = False
            if if_type and cur.if_type != if_type:
                cur.if_type = if_type
                changed = True
            if ip and cur.ip_address != ip:
                cur.ip_address = ip
                changed = True
            if changed:
                updated += 1

    model, hw, fw = _model_from_status(appliance)
    if model:
        appliance.model = model
    if hw:
        appliance.hw_type = hw
    if fw:
        appliance.firmware = fw

    db.session.commit()
    return {"applied": True, "interfaces_added": added, "interfaces_updated": updated,
            "model": appliance.model, "hw_type": appliance.hw_type,
            "generated_at": snapshot.get("generated_at")}


def maybe_apply_inventory(appliance) -> dict | None:
    """Apply the inventory sync once per snapshot (idempotent across status polls).

    Returns the apply result the first time a given snapshot is seen, else None.
    """
    snap_path = _dev_dir(appliance.id) / "_config.json"
    if not snap_path.exists():
        return None
    try:
        gen = json.loads(snap_path.read_text(encoding="utf-8")).get("generated_at")
    except Exception:  # noqa: BLE001
        return None
    marker = _dev_dir(appliance.id) / "_inventory_applied.json"
    if marker.exists():
        try:
            if json.loads(marker.read_text(encoding="utf-8")).get("generated_at") == gen:
                return None
        except Exception:  # noqa: BLE001
            pass
    res = apply_inventory(appliance)
    if res.get("applied"):
        _write_json(marker, {"generated_at": gen, "result": res})
    return res


# --- per-endpoint verdicts -------------------------------------------------
# The sweep's job is not only to collect rows: it is the only thing in SATOM
# that asks a live appliance about EVERY endpoint in the catalog. Recording
# only the rows threw that away. ``_results_list`` folds a device error
# envelope into ``[]``, so "this collection is empty" and "this firmware has
# no such endpoint" were the same observation — which is why every snapshot
# ever written carries ``errors: []``, including one taken from an appliance
# that was answering ``errcode -20001`` to one of its URNs.
VERDICT_OK = "ok"
VERDICT_ABSENT = "absent"
VERDICT_ERROR = "error"


def _resp_message(resp) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict):
            return str(body.get("message") or body.get("error") or "")[:120]
    except Exception:  # noqa: BLE001 — non-JSON body
        pass
    return (getattr(resp, "text", "") or "")[:120]


def _device_firmware(appliance_snap, is_adc: bool) -> str:
    """Best-effort running firmware line, read from the device at sweep time.

    NOT ``Appliance.firmware``: that column is filled by other flows and was
    ``None`` for two of the three live FortiWebs when this was written. A
    verdict ledger whose firmware is a guess is worse than one that says
    "unknown", because the reconciler weights absence BY FIRMWARE LINE — the
    endpoint catalog is a deliberate cross-firmware superset, so "absent" only
    ever means "absent on the line this appliance runs".

    Reads the same documented field as ``_model_from_status``
    (``status.systemstatus → firmwareVersion``), which returns firmware as
    ``None`` for FortiWeb and therefore cannot be reused directly.
    """
    import re as _re
    try:
        if is_adc:
            from . import adc_ops
            raw = adc_ops.model_inventory(appliance_snap)[2] or ""
        else:
            body = FortiWebClient(appliance_snap, timeout=10.0).status_check()
            d = body.get("results", body) if isinstance(body, dict) else {}
            raw = str(d.get("firmwareVersion") or "")
        # Normalised to X.Y.Z for BOTH products: the reconciler groups by line,
        # and "8.0.3 build0093,260401" would be its own line on every rebuild.
        m = _re.search(r"\d+\.\d+(?:\.\d+)?", raw)
        return m.group(0) if m else ""
    except Exception:  # noqa: BLE001 — never let a version read sink a sweep
        return ""


def _probe_fortiweb(client, ep: dict) -> tuple[list, str, str]:
    """GET one FortiWeb endpoint and classify the answer three ways.

    ``ok``     the device answered — an empty list then means an EMPTY
               collection, which is a fact about the config, not the catalog.
    ``absent`` this firmware does not serve the path at all (``errcode -20001``
               "The REST API has invalid URL", or ``-3``). Evidence about the
               CATALOG.
    ``error``  anything else — transport, auth, HTTP >= 400 without an absent
               code, or a device-wide refusal such as ``-20010`` ("The license
               of peer VM FortiWeb is not valid", observed live on fortiweb08
               for every single read). Evidence about the DEVICE.

    Collapsing ``absent`` into ``error`` loses the reconciler its only signal;
    collapsing ``error`` into ``absent`` lets one sick appliance propose
    deleting the whole catalog. The codes are the same ones
    ``FortiWebClient.cmdb_names_checked`` already trusts.
    """
    resp = client.get(ep["urn"])
    code = client._errcode(resp)
    if code is not None and str(code) in client._ABSENT_ERRCODES:
        return [], VERDICT_ABSENT, f"errcode {code}"
    if code is not None:
        return [], VERDICT_ERROR, f"errcode {code}: {_resp_message(resp)}"[:200]
    if resp.status_code >= 400:
        return [], VERDICT_ERROR, f"HTTP {resp.status_code}: {_resp_message(resp)}"[:200]
    return client._results_list(resp.json()), VERDICT_OK, ""


def _client_snapshot(appliance) -> SimpleNamespace:
    """A DB-detached copy of just the fields FortiWebClient reads, so the worker
    thread never touches the SQLAlchemy session."""
    return SimpleNamespace(
        id=appliance.id, name=appliance.name, host=appliance.host,
        port=appliance.port, verify_ssl=appliance.verify_ssl,
        username=appliance.username, password=appliance.password,
        vdom=appliance.vdom, kind=getattr(appliance, "kind", "fortiweb"),
    )


def _run(appliance_snap: SimpleNamespace, by: str, deep: bool = False,
         plan: list[dict] | None = None) -> None:
    aid = appliance_snap.id
    devdir = _dev_dir(aid)
    progress_path = devdir / "progress.json"
    is_adc = getattr(appliance_snap, "kind", "") == "fortiadc"
    if plan is None:
        plan = sweep_plan_adc() if is_adc else sweep_plan()
    total = len(plan)
    started = datetime.utcnow().isoformat()
    firmware = _device_firmware(appliance_snap, is_adc)
    state = {
        "state": "running", "appliance_id": aid, "appliance": appliance_snap.name,
        "firmware": firmware,
        "total": total, "done": 0, "percent": 0, "objects": 0,
        "started": started, "by": by, "section": "", "errors": [], "finished": None,
    }
    _write_json(progress_path, state)

    if is_adc:
        from . import adc_ops

        _probe = adc_ops.make_probe(appliance_snap)
    else:
        client = FortiWebClient(appliance_snap, timeout=20.0)

        def _probe(ep: dict):
            return _probe_fortiweb(client, ep)

    sections: dict[str, dict[str, list]] = {}
    total_objects = 0
    errors: list[dict] = []
    absent: list[dict] = []
    ledger: dict[str, dict] = {}
    for i, ep in enumerate(plan, 1):
        try:
            rows, verdict, detail = _probe(ep)
            rows = [r for r in rows if isinstance(r, dict)]
        except Exception as exc:  # noqa: BLE001 — one endpoint never sinks the sweep
            rows, verdict = [], VERDICT_ERROR
            detail = f"{type(exc).__name__}: {exc}"[:160]
        ledger[ep["name"]] = {"urn": ep["urn"], "section": ep["section"],
                              "verdict": verdict, "rows": len(rows),
                              "detail": (detail or "")[:200]}
        if verdict == VERDICT_ERROR:
            errors.append({"endpoint": ep["name"], "error": detail or "unknown error"})
        elif verdict == VERDICT_ABSENT:
            absent.append({"endpoint": ep["name"], "urn": ep["urn"],
                           "detail": detail or ""})
        elif rows:
            sections.setdefault(ep["section"], {})[ep["name"]] = rows
            total_objects += len(rows)
        if i % 5 == 0 or i == total:
            state.update(done=i, percent=int(i * 100 / total) if total else 100,
                         objects=total_objects, section=ep["section"],
                         errors=errors[-25:], absent_count=len(absent))
            _write_json(progress_path, state)

    generated_at = datetime.utcnow().isoformat()
    snapshot = {
        "device": appliance_snap.name, "appliance_id": aid, "generated_at": generated_at,
        "firmware": firmware,
        "by": by, "endpoints_swept": total, "total_objects": total_objects,
        "section_count": len(sections), "sections": sections, "errors": errors,
        # The ledger is the sweep's OTHER product: one verdict per endpoint,
        # read back by services.registry_reconcile. ``absent`` is kept out of
        # ``errors`` on purpose — an endpoint this firmware does not have is not
        # a failure of the sweep, and folding it in would bury the real errors
        # under dozens of benign rows on every run.
        "endpoint_status": ledger,
        "absent": absent,
        "verdict_counts": {
            "ok": sum(1 for v in ledger.values() if v["verdict"] == VERDICT_OK),
            "absent": len(absent),
            "error": len(errors),
        },
    }
    _write_json(devdir / "_config.json", snapshot)
    state.update(state="done", done=total, percent=100, objects=total_objects,
                 section_count=len(sections), errors=errors, finished=generated_at,
                 absent_count=len(absent),
                 summary=f"{total_objects} object(s) across {len(sections)} section(s) "
                         f"from {total} endpoint(s)"
                         + (f", {len(absent)} absent" if absent else "")
                         + (f", {len(errors)} error(s)" if errors else ""))
    _write_json(progress_path, state)

    _persist_firmware(aid, firmware)
    _refresh_api_matrix(appliance_snap)

    if deep and not is_adc:  # deep capture is the FortiWeb WPP/policy layer
        _run_deep(appliance_snap, progress_path, state)


def _persist_firmware(appliance_id: int, firmware: str) -> None:
    """Write the firmware the sweep just measured onto the appliance row.

    The sweep has always read the running firmware (``_device_firmware``) and
    always thrown it away: ``appliances.firmware`` is filled only by
    ``_apply_inventory``, out of ``_model_from_status``, which returns ``None``
    for FortiWeb. That is why 8 of 10 appliances had an empty firmware column
    while their own snapshots said 7.6.8 / 8.0.3 — and why anything keyed by
    firmware line (capacity limits, the API matrix, the field catalog) had to
    treat most of the fleet as "unknown line".

    Best-effort by construction: a sweep that produced a good snapshot must not
    be reported as failed because a column write did not land.
    """
    if not firmware:
        return
    try:
        from ..extensions import db
        from ..models import Appliance
        app = _get_flask_app()
        with app.app_context():
            row = db.session.get(Appliance, appliance_id)
            if row is None or (row.firmware or "") == firmware:
                return
            row.firmware = firmware
            db.session.commit()
    except Exception:  # noqa: BLE001 — never let bookkeeping sink a good sweep
        pass


def _refresh_api_matrix(appliance_snap) -> None:
    """Fold this sweep's verdicts and field keys into the API matrix.

    The matrix is derived, so this is a convenience, not a source of truth: it
    only spares the operator a manual rebuild after every sweep. A failure here
    leaves a stale-but-valid matrix and is silent for the same reason as above.
    """
    try:
        from . import api_matrix
        kind = getattr(appliance_snap, "kind", "") or "fortiweb"
        app = _get_flask_app()
        with app.app_context():
            api_matrix.rebuild(kind)
    except Exception:  # noqa: BLE001
        pass


def _run_deep(appliance_snap: SimpleNamespace, progress_path, state: dict) -> None:
    """Opt-in deep-capture pass appended after the shallow sweep: walk every
    server policy + WPP (sub-tables + named-rule objects nested) and ingest under
    layer='deep'. Best-effort — a failure is recorded but never breaks the
    shallow rediscovery that already completed."""
    state.update(state="deep-running", section="deep capture (WPP + policy graph)",
                 finished=None)
    _write_json(progress_path, state)
    try:
        from . import device_sync
        app = _get_flask_app()
        with app.app_context():
            snap = device_sync.deep_snapshot_from_device(appliance_snap)
            device_sync.persist_deep_snapshot(appliance_snap, snap)
        state.update(state="done", section="deep capture complete",
                     deep_objects=snap.get("total_objects"),
                     finished=datetime.utcnow().isoformat())
    except Exception as exc:  # noqa: BLE001
        state.update(state="done", deep_error=f"{type(exc).__name__}: {exc}"[:200],
                     finished=datetime.utcnow().isoformat())
    _write_json(progress_path, state)


def start(appliance, by: str = "", deep: bool = False) -> dict:
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

    global _APP
    try:
        from flask import current_app
        _APP = current_app._get_current_object()
    except Exception:  # noqa: BLE001 — outside a request (tests set _APP directly)
        pass

    snap = _client_snapshot(appliance)
    if snap.kind == "fortiadc":
        deep = False  # deep capture is the FortiWeb WPP/policy layer
    # Resolve the plan HERE (request context): the registry is DB-first and the
    # worker thread has no app context to fall back through.
    plan = plan_for(appliance)
    init = {"state": "running", "appliance_id": appliance.id, "appliance": appliance.name,
            "total": 0, "done": 0, "percent": 0, "objects": 0, "deep": bool(deep),
            "started": datetime.utcnow().isoformat(), "by": by, "errors": [], "finished": None}
    _write_json(_dev_dir(appliance.id) / "progress.json", init)
    threading.Thread(target=_run, args=(snap, by, deep, plan), daemon=True).start()
    return {"started": True, "progress": init}


__all__ = ["sweep_plan", "sweep_plan_adc", "plan_for", "status",
           "latest_snapshot_meta", "start", "apply_inventory",
           "maybe_apply_inventory", "_run_deep", "_probe_fortiweb",
           "VERDICT_OK", "VERDICT_ABSENT", "VERDICT_ERROR"]
