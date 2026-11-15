"""Intent deviation: is a bound device still configured the way its template says?

Templates and bindings are SATOM's desired state (the *Intent* block of the
NAF Framework); the cached device objects are the actual state the last sync
read. Until this module existed nothing compared the two: ``alerts._check_drift``
tells you a device CHANGED (new source-of-truth version vs the previous one),
not that it stopped matching what the operator meant it to run. A device that
drifted three weeks ago and has been stable since raises no drift and is still
non-compliant.

The comparison is a key-subset diff of the RENDERED template against the
cached object (:func:`write_through.diff_object`), never equality against a raw
snapshot: an appliance fills in defaults the template never set, and whole-row
equality would flag every device as deviating. On top of that diff a few
classes of key are ignored because the appliance derives or renumbers them
(measured on fortiweb17 / fortiweb18, 2026-10-21):

* ``*_val`` handles (``sot_store.HANDLE_SUFFIX``) -- renumbered on proxyd restart;
* FortiWeb's last sub-table edit echo (``sot_store.EDIT_OP_KEYS``), the
  rolling ``allow-time`` (``ROLLING_KEYS``) and reverse-reference lists;
* ``sz_*`` sub-table row counters -- the appliance counts its rows; a
  template captured from a box with two NTP servers says ``sz_ntpserver: 2``
  and the write never sets it.

Values are compared after a light normalisation (``1`` vs ``"1"``, surrounding
whitespace, list order of plain lists) because the REST write accepts either
form and the read returns one.

Only TOP-LEVEL objects are compared. A sub-table row (a signature class, a
pool member) is pushed by the apply without the parent it belongs to in the
item, and the config layer caches no sub-table rows at all; such items are
reported as ``unmeasured`` with that reason rather than guessed at.

Secrets never leave this module: a deviation names the KEYS that differ, not
the values, and the stable hash of a deviation is computed over values with
every secret-looking key (``cli_writer.is_secret``) and every ``["ENC", …]``
pair replaced by a marker.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..extensions import db
from ..models import Appliance, Template
from ..models_cache import DeviceObject
from ..models_tpl_binding import TemplateBinding
from . import sot_store
from . import template_bindings as tb
from . import write_through as wt
from .bulk import iter_push_items
from .cli_writer import is_secret
from .device_store import _mkey_of

STATUS_MET = "met"
STATUS_DEVIATES = "deviates"
STATUS_UNMEASURED = "unmeasured"
STATUSES = (STATUS_MET, STATUS_DEVIATES, STATUS_UNMEASURED)

#: Keys the appliance derives, renumbers or rolls on its own: never a deviation.
IGNORED_KEYS: frozenset = (sot_store.EDIT_OP_KEYS | sot_store.ROLLING_KEYS
                           | sot_store.REF_LIST_KEYS
                           | frozenset({"q_ref", "can_view", "can_clone"}))
#: ``sz_<subtable>``: the appliance's own count of a sub-table's rows.
IGNORED_PREFIXES: tuple = ("sz_",)
#: ``<field>_val``: the numeric handle next to a name.
IGNORED_SUFFIXES: tuple = (sot_store.HANDLE_SUFFIX,)

SECRET_MARK = "<secret>"
#: Deviating objects spelled out in a finding; the rest are counted.
DETAIL_LINES_MAX = 8


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

def ignored_key(key: str) -> bool:
    k = str(key or "")
    return (k in IGNORED_KEYS or k.startswith(IGNORED_PREFIXES)
            or k.endswith(IGNORED_SUFFIXES))


def normalise(value: Any) -> Any:
    """The comparable form of a value: scalars as stripped text (``1`` and
    ``"1"`` are the same write), booleans as the appliance's ``enable`` /
    ``disable``, plain lists order-free, mappings recursed."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "enable" if value else "disable"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        items = [normalise(v) for v in value]
        if all(isinstance(v, str) for v in items):
            return sorted(items)
        return items
    if isinstance(value, dict):
        return {str(k): normalise(v) for k, v in sorted(value.items())}
    return str(value)


def _secret_key(key: str, value: Any) -> bool:
    return is_secret(str(key or "")) or sot_store._is_rpc_secret(value)


def fields_of(item: dict) -> dict:
    """The fields a push item writes. A config template wraps them as the
    FortiWeb write body ``{"data": {...}}``; a profile template is flat."""
    data = item.get("data") if isinstance(item, dict) else None
    if not isinstance(data, dict):
        return {}
    if set(data) == {"data"} and isinstance(data["data"], dict):
        return dict(data["data"])
    return dict(data)


def deviation_hash(deviating: list[dict]) -> str:
    """Stable 12-hex identity of a set of deviations. Over the KEYS and the
    normalised values so the same deviation keeps the same finding key run
    after run, and a corrected-then-broken-differently object mints a new
    one; secret values never enter the digest."""
    canon = [(d.get("endpoint", ""), str(d.get("mkey") or ""),
              [(k, SECRET_MARK if d.get("secret", {}).get(k) else d.get("before", {}).get(k),
                SECRET_MARK if d.get("secret", {}).get(k) else d.get("after", {}).get(k))
               for k in sorted(d.get("keys", []))])
             for d in sorted(deviating, key=lambda x: (x.get("endpoint", ""), str(x.get("mkey") or "")))]
    raw = json.dumps(canon, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


# ---------------------------------------------------------------------------
# per push item
# ---------------------------------------------------------------------------

def _collection_rows(appliance_id: int, logical: str) -> bool:
    """Does the cache hold ANY top-level object of this collection?"""
    return (db.session.query(DeviceObject.id)
            .filter_by(appliance_id=appliance_id, logical_name=logical, depth=0)
            .first() is not None)


def _is_subtable(logical: str, version: str) -> bool:
    """A logical whose URN sits under another collection's URN: a sub-table
    row, which the apply pushes without naming its parent."""
    from ..registry import loader
    reg = loader.registry_for("fortiweb", version) or {}
    tail = wt._norm_tail(reg.get(logical, "") or "")
    if not tail:
        return False
    parents = {wt._norm_tail(u) for name, u in reg.items() if name != logical}
    head = tail.rsplit("/", 1)[0] if "/" in tail else ""
    return bool(head) and head in parents


def compare_item(appliance, item: dict, *, version: str = "") -> dict:
    """One push item against the cache of ``appliance``.

    ``{endpoint, mkey, logical, action, status, reason, keys, before, after,
    secret}`` -- ``before``/``after`` hold NORMALISED values per deviating key
    and are only ever consumed by :func:`deviation_hash`; ``secret`` marks the
    keys whose values must never be shown."""
    endpoint = str(item.get("endpoint") or "")
    action = str(item.get("action") or "create")
    fields = fields_of(item)
    mkey = item.get("mkey")
    if mkey in (None, ""):
        mkey = _mkey_of(fields) or ""
    out = {"endpoint": endpoint, "mkey": mkey, "action": action, "logical": "",
           "status": STATUS_UNMEASURED, "reason": "", "keys": [],
           "before": {}, "after": {}, "secret": {}}
    logical = wt.logical_for_collection(endpoint, version) if endpoint else None
    if not logical:
        out["reason"] = "collection %r is not known for this build" % endpoint
        return out
    out["logical"] = logical
    if not _collection_rows(appliance.id, logical):
        if _is_subtable(logical, version):
            out["reason"] = ("sub-table rows are not compared; the parent object is")
        else:
            out["reason"] = "collection %r is not in the device cache" % logical
        return out
    obj = wt._find(db.session, appliance.id, str(mkey), logical)
    if action == "delete":
        if obj is None:
            out["status"] = STATUS_MET
        else:
            out["status"] = STATUS_DEVIATES
            out["reason"] = "object the template deletes is still present"
        return out
    if obj is None:
        out["status"] = STATUS_DEVIATES
        out["reason"] = "object is absent from the device"
        out["keys"] = sorted(k for k in fields if not ignored_key(k))
        for k in out["keys"]:
            out["after"][k] = normalise(fields[k])
            out["before"][k] = None
            if _secret_key(k, fields[k]):
                out["secret"][k] = True
        return out
    raw = wt.diff_object(appliance.id, endpoint, str(mkey), fields)
    before_all = obj.payload or {}
    for k, pair in sorted(raw.items()):
        if ignored_key(k):
            continue
        b, a = normalise(pair.get("before")), normalise(pair.get("after"))
        if b == a:
            continue
        out["keys"].append(k)
        out["before"][k] = b
        out["after"][k] = a
        if _secret_key(k, fields.get(k)) or _secret_key(k, before_all.get(k)):
            out["secret"][k] = True
    out["status"] = STATUS_DEVIATES if out["keys"] else STATUS_MET
    if out["keys"]:
        out["reason"] = "%d field(s) differ" % len(out["keys"])
    return out


# ---------------------------------------------------------------------------
# per binding
# ---------------------------------------------------------------------------

def _public_item(it: dict) -> dict:
    """The item without values: endpoint, mkey, status, reason, keys."""
    return {"endpoint": it["endpoint"], "mkey": it["mkey"], "logical": it["logical"],
            "action": it["action"], "status": it["status"], "reason": it["reason"],
            "keys": list(it["keys"])}


def binding_compliance(binding: TemplateBinding, appliance=None, *,
                       template: Template | None = None) -> dict:
    """The compliance verdict of one binding. Never contacts the device.

    ``status`` is ``deviates`` when any compared object deviates, ``met`` when
    at least one object was compared and none deviates, ``unmeasured`` when
    nothing could be compared (no approved version, a variable unset, a body
    with no endpoint, nothing cached) -- with the reason in ``reason``."""
    from ..registry import loader
    appliance = appliance or db.session.get(Appliance, binding.appliance_id)
    tpl = template if template is not None else tb.resolve(binding)
    out = {"binding_id": binding.id, "appliance_id": binding.appliance_id,
           "appliance": getattr(appliance, "name", "") or "",
           "kind": binding.kind, "name": binding.name,
           "template_id": getattr(tpl, "id", None),
           "version": getattr(tpl, "version", None),
           "status": STATUS_UNMEASURED, "reason": "", "hash": "",
           "compared": 0, "deviations": 0, "unmeasured": 0,
           "items": [], "deviating": []}
    if appliance is None:
        out["reason"] = "appliance no longer exists"
        return out
    if tpl is None:
        out["reason"] = (("no approved version of %r" % binding.name)
                         if not binding.pinned_version
                         else "version %s no longer exists" % binding.pinned_version)
        return out
    rendered, missing = tb.render(tpl.body_dict, binding.variables_dict)
    if missing:
        out["reason"] = "unset variable(s): %s" % ", ".join(missing)
        return out
    items = iter_push_items(rendered)
    if not items:
        out["reason"] = "the template body declares no endpoint"
        return out
    version = loader.version_of(appliance)
    results = [compare_item(appliance, it, version=version) for it in items]
    out["items"] = [_public_item(r) for r in results]
    deviating = [r for r in results if r["status"] == STATUS_DEVIATES]
    compared = [r for r in results if r["status"] != STATUS_UNMEASURED]
    out["compared"] = len(compared)
    out["deviations"] = len(deviating)
    out["unmeasured"] = len(results) - len(compared)
    if deviating:
        out["status"] = STATUS_DEVIATES
        out["deviating"] = [_public_item(r) for r in deviating]
        out["hash"] = deviation_hash(deviating)
        out["reason"] = "%d of %d object(s) deviate" % (len(deviating), len(results))
    elif compared:
        out["status"] = STATUS_MET
        out["reason"] = ("%d object(s) match" % len(compared)
                         + (", %d not compared" % out["unmeasured"] if out["unmeasured"] else ""))
    else:
        out["reason"] = "nothing to compare: " + "; ".join(
            sorted({r["reason"] for r in results if r["reason"]})[:3])
    return out


def all_bindings(product: str = "") -> list[dict]:
    """Every binding's verdict, newest template resolved once per family."""
    q = TemplateBinding.query
    if product:
        q = q.filter_by(product=product)
    rows = q.order_by(TemplateBinding.appliance_id, TemplateBinding.kind,
                      TemplateBinding.name).all()
    out = []
    for b in rows:
        try:
            out.append(binding_compliance(b))
        except Exception as exc:  # noqa: BLE001 -- one unreadable binding never hides the rest
            out.append({"binding_id": b.id, "appliance_id": b.appliance_id,
                        "appliance": "", "kind": b.kind, "name": b.name,
                        "template_id": None, "version": None,
                        "status": STATUS_UNMEASURED,
                        "reason": "%s: %s" % (type(exc).__name__, exc), "hash": "",
                        "compared": 0, "deviations": 0, "unmeasured": 0,
                        "items": [], "deviating": []})
    return out


def describe(result: dict, cap: int = DETAIL_LINES_MAX) -> list[str]:
    """One line per deviating object, keys only, the rest counted."""
    lines = []
    dev = result.get("deviating") or []
    for d in dev[:cap]:
        what = d["endpoint"] + ((" / " + str(d["mkey"])) if d.get("mkey") else "")
        if d.get("keys"):
            lines.append("- %s: %s (%s)" % (what, d["reason"], ", ".join(d["keys"])))
        else:
            lines.append("- %s: %s" % (what, d["reason"]))
    if len(dev) > cap:
        lines.append("- ... and %d more object(s)" % (len(dev) - cap))
    return lines
