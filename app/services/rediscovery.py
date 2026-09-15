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
import socket
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


#: Terminal state for a sweep whose worker process no longer exists. It is
#: NEITHER ``done`` NOR ``failed`` on purpose: a run killed mid-flight produced
#: no snapshot and reported no error, so calling it done would claim a result
#: that was never written and calling it failed would blame the device for a
#: service restart. Three outcomes, three words — the same rule the CLI capture
#: and the probe verdicts already follow.
INTERRUPTED = "interrupted"
FAILED = "failed"

_HOST = socket.gethostname()


def _data_dir() -> Path:
    """Where sweep state lives.

    ``SATOM_REDISCOVERY_DIR`` overrides the in-tree default, and it exists for
    one measured reason: ``tests/test_rediscovery_*`` drive real sweeps against
    the TEST database while writing their progress and ``_config.json`` into
    the PRODUCTION tree. On 2026-09-15 that also wiped
    ``data/api_matrix/fortiweb.json`` (which is rebuilt from this directory)
    down to ``swept: 0`` — untracked, so git said nothing, and an empty matrix
    renders as a page with no differences rather than as an error. Same
    isolation pattern as ``SATOM_JOBS_DIR`` / ``SATOM_SOT_DIR``.
    """
    override = os.environ.get("SATOM_REDISCOVERY_DIR")
    d = (Path(override) if override
         else Path(__file__).resolve().parents[2] / "data" / "rediscovery")
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


#: Sub-directory of a device's sweep dir holding ONE SNAPSHOT PER FIRMWARE
#: VERSION. ``_config.json`` stays exactly what it was — the latest sweep, read
#: by ``registry_reconcile`` and by every existing consumer — and this is the
#: history beside it.
#:
#: The defect it closes, measured on this fleet: the sweep wrote one file per
#: APPLIANCE and overwrote it every run, so the first sweep after a firmware
#: upgrade DESTROYED the only evidence backing the previous line. Nothing
#: reported a loss; ``/web/registry/versions`` simply showed the old line with
#: fewer endpoints, which reads as "that line has less API", not as "we deleted
#: the proof".
#:
#: There is deliberately NO retention cap here. A cap would reintroduce the
#: exact failure being fixed — silently dropping the evidence for a version
#: somebody is still running — and the growth is bounded by how often a box is
#: upgraded, not by traffic.
VERSION_DIR = "by-version"


def _version_of(snapshot: dict) -> str:
    """The full firmware version a snapshot was measured against, or ``""``.

    Read from the SNAPSHOT, never from the appliance row: the row can have been
    upgraded since, and attributing old evidence to the new version is the
    error this whole directory exists to prevent.
    """
    from . import firmware_versions
    return firmware_versions.normalize(snapshot.get("firmware") if isinstance(snapshot, dict) else "")


def _version_dir(appliance_id: int) -> Path:
    d = _dev_dir(appliance_id) / VERSION_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def archive_snapshot(appliance_id: int, snapshot: dict) -> Path | None:
    """Persist ``snapshot`` under its own firmware version. Returns the path.

    ``None`` when the snapshot records no firmware: a snapshot that cannot say
    which version it measured must NOT be filed under a guess. It stays
    reachable as ``_config.json`` and ``api_matrix`` reports it as a witness
    with no version rather than crediting it to one.
    """
    version = _version_of(snapshot)
    if not version:
        return None
    path = _version_dir(appliance_id) / ("%s.json" % version)
    _write_json(path, snapshot)
    return path


def version_snapshots(appliance_id: int) -> dict:
    """``{version: Path}`` of every archived sweep for one appliance."""
    d = _dev_dir(appliance_id) / VERSION_DIR
    if not d.is_dir():
        return {}
    out: dict = {}
    for p in sorted(d.glob("*.json")):
        out[p.stem] = p
    return out


def migrate_version_archive() -> list[dict]:
    """File every existing ``_config.json`` under its own version. Idempotent.

    Runs at boot beside the stale-sweep reconcile. It is a pure BACKFILL: an
    archive entry that already exists is left alone unless the ``_config.json``
    beside it is strictly newer for the SAME version, because overwriting a
    version's evidence with a different version's is the bug, and overwriting
    it with older evidence of its own version is pointless churn on a tree the
    standby rsyncs every five minutes.
    """
    from . import firmware_versions  # noqa: F401  (import guard: same module)

    moved: list[dict] = []
    root = _data_dir()
    if not root.is_dir():
        return moved
    for devdir in sorted(root.iterdir()):
        if not devdir.is_dir() or not devdir.name.isdigit():
            continue
        cfg = devdir / "_config.json"
        if not cfg.exists():
            continue
        try:
            snap = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — an unreadable snapshot is not fatal
            continue
        version = _version_of(snap)
        if not version:
            continue
        target = devdir / VERSION_DIR / ("%s.json" % version)
        if target.exists():
            try:
                existing = json.loads(target.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                existing = {}
            if str(existing.get("generated_at") or "") >= str(snap.get("generated_at") or ""):
                continue
        try:
            archive_snapshot(int(devdir.name), snap)
        except OSError:
            continue
        moved.append({"appliance_id": int(devdir.name),
                      "device": snap.get("device") or "",
                      "version": version})
    return moved


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
    operator-entered fields (``role``, ``segment``, ``connected_to``, ``notes``)
    or the datasheet.

    ``role`` in particular is not merely "not overwritten" — it is
    UNDISCOVERABLE. The appliance exposes a port's name, media type and
    address; it has no field that says what the port is FOR. A newly-discovered
    port therefore lands as ``unspecified`` and stays there until a human says
    otherwise. Deriving it (e.g. "the port holding the management IP is the
    management port") would manufacture a declaration and the clone/migrate
    gate would then report agreement nobody asserted.
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
        # Stamped with the moment the sweep OBSERVED the version, never with
        # "now": the snapshot can be minutes old by the time this merge runs,
        # and an attestation dated later than its observation is a lie about
        # freshness. Until 2026-09-15 this branch wrote the version and NO
        # timestamp at all, so the sweep left behind a firmware no consumer
        # (CVE correlation, the Upgrade Scout) could date.
        observed = _parse_iso(snapshot.get("generated_at"))
        if observed is not None:
            appliance.firmware_checked_at = observed

    db.session.commit()
    return {"applied": True, "interfaces_added": added, "interfaces_updated": updated,
            "model": appliance.model, "hw_type": appliance.hw_type,
            "generated_at": snapshot.get("generated_at")}


def _parse_iso(value) -> datetime | None:
    """An ISO stamp, or None. None is returned rather than ``utcnow()`` so a
    snapshot with no readable time leaves the previous attestation alone
    instead of inventing one."""
    try:
        return datetime.fromisoformat(str(value))
    except Exception:  # noqa: BLE001
        return None


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


def probe_endpoint(appliance, urn: str) -> tuple[list, str, str]:
    """GET one URN and classify it the way a sweep does — ``(rows, verdict, detail)``.

    The public door onto the two private probes, so a caller outside the sweep
    (the CLI-coverage section, promoting a finding into the catalog) gets the
    SAME three verdicts with the same meanings instead of inventing a fourth
    reading of an HTTP status. ``absent`` in particular is a claim about the
    catalog and ``error`` is a claim about the device; anything that re-derived
    that distinction would eventually disagree with the reconciler, which acts
    on it.
    """
    snap = _client_snapshot(appliance)
    if getattr(snap, "kind", "") == "fortiadc":
        from . import adc_ops
        return adc_ops.make_probe(snap)({"urn": urn})
    return _probe_fortiweb(FortiWebClient(snap, timeout=20.0), {"urn": urn})


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
         plan: list[dict] | None = None, cli: bool = False) -> None:
    """Thread entry point: :func:`_sweep` plus the one thing a file-backed
    status owes its readers — a TERMINAL state when the worker dies.

    Without this, an exception anywhere in the sweep left ``running`` on disk
    forever, indistinguishable on screen from a sweep still in flight, and the
    only thing that ever cleared it was a restart (and, until 2026-09-15, not
    even that: appliance 4 sat at 71 % from 2026-07-03).
    """
    try:
        _sweep(appliance_snap, by, deep, plan, cli)
    except BaseException as exc:  # noqa: BLE001 — record, then let it propagate
        try:
            p = _dev_dir(appliance_snap.id) / "progress.json"
            st = status(appliance_snap.id) or {}
            st.update(state=FAILED,
                      error="%s: %s" % (type(exc).__name__, exc),
                      finished=datetime.utcnow().isoformat(),
                      heartbeat=datetime.utcnow().isoformat())
            _write_json(p, st)
        except Exception:  # noqa: BLE001 — never mask the original failure
            pass
        raise


def _sweep(appliance_snap: SimpleNamespace, by: str, deep: bool = False,
           plan: list[dict] | None = None, cli: bool = False) -> None:
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
        # WHO is running this, so a boot-time reconciler can tell a live sweep
        # from the ghost of one. ``host`` matters as much as ``pid``: the
        # standby PULLS this whole data/ tree every 5 minutes, so a2 sees a1's
        # progress files and must never judge a pid that is not its own.
        "pid": os.getpid(), "host": _HOST, "heartbeat": started,
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
                         errors=errors[-25:], absent_count=len(absent),
                         heartbeat=datetime.utcnow().isoformat())
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
    # ...and beside it, the same snapshot filed under the version it measured.
    # ``_config.json`` is the LATEST; this is the history, and it is what makes
    # a firmware upgrade stop destroying the evidence for the previous version.
    archive_snapshot(aid, snapshot)
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

    # LAST, and only when asked. ``cli`` defaults to False so the post-
    # registration sweep (views.appliances) and every other internal caller
    # keep their current cost and their current side effects.
    if cli:
        _run_cli(appliance_snap, progress_path, state)


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


# --------------------------------------------------------------------------- #
# Third pass — capture what the CLI serves                                     #
# --------------------------------------------------------------------------- #
# The sweep reads what REST serves. ``show full-configuration`` reads what the
# CLI serves, and the gap between the two IS the CLI-coverage report
# (:mod:`app.services.cli_coverage`). Capturing it HERE is what makes that
# report describe the box *as swept* — same box, same firmware, same minute —
# instead of whatever dump happened to already be sitting in the vault.
#
# It is a SEPARATE, OPT-IN pass appended after ``_config.json`` is already on
# disk, for three measured reasons:
#   * an SSH dump is a single session bounded at 300 s against a REST sweep
#     that finishes in seconds, so folding it inline would make EVERY sweep
#     minutes long — including the silent one behind device registration;
#   * SSH can fail on a box whose REST just answered perfectly, and a sweep
#     that SUCCEEDED must not be reported as failed because a second transport
#     could not connect;
#   * it writes ~700 KB of device configuration into the vault. That is a state
#     change, and a state change nobody asked for is not a default.
CLI_CAPTURE_MAX_AGE_H = 24

#: Every skip carries its OWN reason. A single generic "no" would be
#: indistinguishable from a capture that ran and found nothing — precisely the
#: confusion the coverage report exists to remove.
CLI_SKIP_NOT_REQUESTED = "not requested for this sweep"
CLI_SKIP_NO_PERMISSION = ("the CLI dump is written to the configuration vault, "
                          "which this user may not write")
CLI_SKIP_MAINTENANCE = ("the appliance is in maintenance mode, where scheduled "
                        "collection is suppressed")


def _latest_usable_dump(appliance_id: int, evidence: list | None = None) -> dict | None:
    """Newest vault dump for THIS appliance that the coverage report would accept.

    ``usable`` is not decoration. An encrypted dump (the box has a backup
    password set) can never be parsed, so counting it as freshness would
    suppress every future capture and leave the coverage section permanently
    empty on exactly the appliances that need it most.
    """
    from . import cli_coverage

    rows = cli_coverage.evidence_index() if evidence is None else evidence
    for rec in rows:                     # evidence_index is newest-first
        if rec.get("appliance_id") == appliance_id and rec.get("usable"):
            return rec
    return None


def _dump_age_hours(rec: dict | None, now: datetime) -> float | None:
    """Age of an evidence row in hours, or ``None`` when it cannot be established.

    Reads ``created_iso``, never the ``created_at`` display string.
    """
    stamp = (rec or {}).get("created_iso") or ""
    if not stamp:
        return None
    try:
        when = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return max(0.0, (now - when).total_seconds() / 3600.0)


def cli_capture_decision(*, requested: bool, kind: str, appliance_id: int,
                         evidence: list | None = None, maintenance: bool = False,
                         may_write_vault: bool = True,
                         max_age_h: float = CLI_CAPTURE_MAX_AGE_H,
                         now: datetime | None = None) -> dict:
    """Decide — BEFORE any session is opened — whether this sweep captures a dump.

    ONE authority for the question, because it has two callers that must never
    disagree: the worker (which acts on it) and the rediscovery page (which
    tells the operator in advance what the checkbox will do). Two answers to
    "will this capture?" is how a UI ends up promising a dump that the worker
    then silently declines to take.

    Returns ``{"capture", "reason", "existing", "age_h"}``. ``reason`` is empty
    only when ``capture`` is True.
    """
    from . import cli_coverage

    now = now or datetime.utcnow()
    if not requested:
        return {"capture": False, "reason": CLI_SKIP_NOT_REQUESTED,
                "existing": None, "age_h": None}
    kind = (kind or "fortiweb").lower()
    if kind not in cli_coverage.SUPPORTED_PRODUCTS:
        # FortiAnalyzer and FortiAuthenticator do not answer this question with
        # a configuration dump; say which one and why, never a bare False.
        return {"capture": False,
                "reason": cli_coverage.UNSUPPORTED_REASON.get(
                    kind, "this product has no CLI configuration dump to capture"),
                "existing": None, "age_h": None}
    if not may_write_vault:
        return {"capture": False, "reason": CLI_SKIP_NO_PERMISSION,
                "existing": None, "age_h": None}
    if maintenance:
        return {"capture": False, "reason": CLI_SKIP_MAINTENANCE,
                "existing": None, "age_h": None}

    fresh = _latest_usable_dump(appliance_id, evidence)
    age_h = _dump_age_hours(fresh, now)
    if fresh is not None and age_h is not None and age_h < max_age_h:
        return {"capture": False, "existing": fresh, "age_h": round(age_h, 1),
                "reason": (f"a usable dump captured {age_h:.1f} h ago is inside "
                           f"the {max_age_h:g} h budget - re-reading the same "
                           f"configuration would only cost the box another "
                           f"300 s session")}
    return {"capture": True, "reason": "", "existing": fresh, "age_h": age_h}


def _run_cli(appliance_snap: SimpleNamespace, progress_path, state: dict) -> None:
    """Opt-in CLI-dump pass, appended after the sweep snapshot is already on disk.

    Best-effort BY CONSTRUCTION: ``_config.json`` is written before this runs,
    so nothing here — including hanging on a dead SSH port until the 300 s
    ceiling — can cost the operator the sweep that already succeeded. The
    outcome lands in ``progress.json`` beside the sweep's own, under separate
    keys, because a capture that was SKIPPED and a capture that FAILED must
    never look alike.
    """
    aid = appliance_snap.id
    state.update(state="cli-running",
                 section="CLI capture (show full-configuration)", finished=None)
    _write_json(progress_path, state)
    outcome: dict = {}
    try:
        from ..extensions import db
        from ..models import Appliance
        from . import backup as backup_svc
        from .audit import log_action

        app = _get_flask_app()
        with app.app_context():
            # Re-read the row inside THIS thread's context, by id. Carrying a
            # request's ORM instance into a worker thread is what made every
            # status badge read "offline" on 2026-09-14 — and the credential
            # this capture needs may live in the vault, which reads the DB.
            row = db.session.get(Appliance, aid)
            if row is None:
                raise RuntimeError("the appliance row disappeared mid-sweep")
            decision = cli_capture_decision(
                requested=True, kind=getattr(row, "kind", "") or "fortiweb",
                appliance_id=aid,
                maintenance=bool(getattr(row, "maintenance", False)))
            if not decision["capture"]:
                outcome = {"cli_skipped": decision["reason"]}
                if decision.get("existing"):
                    outcome["cli_backup_id"] = decision["existing"].get("backup_id")
            else:
                rec = backup_svc.fetch_device_backup_auto(
                    row, created_by=(state.get("by") or "rediscovery")[:64],
                    method="ssh")
                outcome = {"cli_backup_id": rec.id,
                           "cli_kb": (rec.size_bytes or 0) // 1024,
                           "cli_firmware": rec.firmware or ""}
                log_action("appliance.cli_capture", target=row.name or "",
                           extra={"backup_id": rec.id, "by": "rediscovery sweep",
                                  "kb": (rec.size_bytes or 0) // 1024,
                                  "firmware": rec.firmware or ""})
    except Exception as exc:  # noqa: BLE001 — never sink a sweep that succeeded
        outcome = {"cli_error": f"{type(exc).__name__}: {exc}"[:200]}
    state.update(state="done", finished=datetime.utcnow().isoformat(), **outcome)
    _write_json(progress_path, state)


def start(appliance, by: str = "", deep: bool = False,
          cli: bool = False) -> dict:
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
    _now = datetime.utcnow().isoformat()
    init = {"state": "running", "appliance_id": appliance.id, "appliance": appliance.name,
            "total": 0, "done": 0, "percent": 0, "objects": 0, "deep": bool(deep),
            "cli": bool(cli),
            "started": _now, "by": by, "errors": [], "finished": None,
            "pid": os.getpid(), "host": _HOST, "heartbeat": _now}
    _write_json(_dev_dir(appliance.id) / "progress.json", init)
    threading.Thread(target=_run, args=(snap, by, deep, plan, cli),
                     daemon=True).start()
    return {"started": True, "progress": init}


def _pid_alive(pid) -> bool:
    """True when ``pid`` exists AND still looks like one of our processes.

    Deliberately identical to ``jobs._pid_alive``: "the worker is gone" must
    have ONE definition in this product, not two that drift apart. The cmdline
    check guards against PID reuse after a reboot.
    """
    try:
        os.kill(int(pid), 0)
    except (OSError, TypeError, ValueError):
        return False
    try:
        cmd = Path("/proc/%s/cmdline" % int(pid)).read_bytes().decode(errors="replace")
        return ("python" in cmd) or ("gunicorn" in cmd)
    except Exception:  # noqa: BLE001 — no /proc: liveness alone decides
        return True


def reconcile_stale_runs(*, no_pid_stale_after_s: int = 900) -> list[dict]:
    """Retire ``running`` sweeps whose worker process no longer exists.

    The sweep runs in a daemon thread and its state lives in a file, so a
    ``systemctl restart satom`` kills the thread without touching the file and
    every live run becomes a permanent ``running``. Nothing corrected that: the
    guard in :func:`start` only stops BLOCKING a new run after 15 minutes,
    which unblocks the operator and leaves the page reading 71 % forever.

    Rules, mirroring ``jobs.sweep_orphans``:

    * a file from ANOTHER host is never touched — ``satom-ha-datasync`` pulls
      this whole tree onto the standby every 5 minutes, so the peer's progress
      files are visible here and its pids mean nothing on this machine;
    * a recorded pid that is alive → left alone (another gunicorn worker may be
      running the sweep right now, and booting workers run this too);
    * no pid recorded (a file written before this field existed) → judged by
      age, because such a file can only predate the current process.

    Never raises: housekeeping must not be able to block boot.
    """
    out: list[dict] = []
    base = _data_dir()
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return out
    for entry in entries:
        p = base / entry / "progress.json"
        if not p.exists():
            continue
        try:
            st = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if st.get("state") != "running":
            continue
        if (st.get("host") or _HOST) != _HOST:
            continue
        pid = st.get("pid")
        if pid:
            if _pid_alive(pid):
                continue
        else:
            stamp = st.get("heartbeat") or st.get("started")
            try:
                age = time.time() - datetime.fromisoformat(stamp).timestamp()
            except Exception:  # noqa: BLE001 — unreadable stamp is not evidence of life
                age = no_pid_stale_after_s + 1
            if age <= no_pid_stale_after_s:
                continue
        st.update(state=INTERRUPTED,
                  finished=datetime.utcnow().isoformat(),
                  error="Interrupted — the service restarted while this sweep "
                        "was running. It wrote no snapshot; run it again.")
        try:
            _write_json(p, st)
        except Exception:  # noqa: BLE001
            continue
        out.append(st)
    return out


__all__ = ["sweep_plan", "sweep_plan_adc", "plan_for", "status",
           "reconcile_stale_runs", "INTERRUPTED", "FAILED",
           "VERSION_DIR", "archive_snapshot", "version_snapshots",
           "migrate_version_archive",
           "latest_snapshot_meta", "start", "apply_inventory",
           "maybe_apply_inventory", "_run_deep", "_run_cli", "_probe_fortiweb",
           "cli_capture_decision", "CLI_CAPTURE_MAX_AGE_H",
           "CLI_SKIP_NOT_REQUESTED", "CLI_SKIP_NO_PERMISSION",
           "CLI_SKIP_MAINTENANCE",
           "VERDICT_OK", "VERDICT_ABSENT", "VERDICT_ERROR"]
