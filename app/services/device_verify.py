"""Verify a write SATOM sent OUTSIDE ``FortiWebOps``: re-read what it touched,
judge whether the device now holds it, keep SATOM's copy current, audit what
did not land.

``object_refresh`` gave every FortiWeb write that goes through
``FortiWebOps._apply`` a verdict. Every other writer still reported "ok" the
moment the device ACCEPTED the request: the FortiADC certificate upload and
delete, the Lua deploy, the decommission's virtual-server / pool / profile
deletes, the ADC object editor and its wizard, the external ADC API, and the
raw API consoles of FortiADC, FortiGate, FortiAuthenticator and FortiWeb. An
accepted write is not proof of a change — a build that answers 200 and drops
the field, a delete the box acknowledges and keeps (a referenced object), a
create that lands under another name — so each of those now re-reads the
object it touched, exactly once, and answers with the same three verdicts as
``object_refresh``:

* ``verified``   — every comparable field that was sent is what the device now
  serves (a delete: the device no longer has the object);
* ``mismatch``   — the device accepted the write and does NOT hold it. Audited
  as ``config.<op>.not_applied``; the callers treat it as a failed operation;
* ``unverified`` — nothing could be compared (the re-read failed, only secrets,
  certificate material or sub-tables were sent, an action endpoint with no
  object behind it). Never a fake "verified": the caller says "not verified"
  and why.

What is NEVER compared: secrets (passwords, keys, tokens, PSKs, ``ENC …``
values), private keys and certificate material (anything PEM). The devices
mask or never return them, and a comparison would either leak them into a
verdict or fail on a mask. Names, ids and scalar configuration only.

"Not found" is product-specific and was MEASURED, not assumed (2026-10-12):

* FortiADC 7.6.7 build0676 (fortiadc10): ``GET /api/<entity>?mkey=<absent>``
  answers **HTTP 200 ``{"payload": null}``** — top-level objects and child
  table rows (``?pkey=<parent>&mkey=<absent>``) alike. A present object is
  ``{"payload": {…}}``. A 404 there means the PATH is not served, which is a
  failed read, never "absent";
* FortiGate 8.0.1 build245 (fgt02): ``GET /api/v2/cmdb/<a>/<b>/<absent>``
  answers **HTTP 404** with a JSON envelope (``"status": "error",
  "http_status": 404``); ``FortiGateClient`` reports it as ``"404 — no such
  object on the device: …"``;
* FortiAuthenticator 8.0.3 (fac01): ``GET /api/v1/<resource>/<absent id>/``
  answers **HTTP 404 with an empty body**; the client reports ``"HTTP 404: "``.
* FortiWeb keeps ``object_refresh``'s own rule (errcode -3, HTTP 500).

Product-neutral by construction: every reader takes the client the write was
sent with (duck-typed — no product client is imported here), so the ADC and
the non-ADC modules can share it without crossing the import line
``tests/test_product_separation.py`` locks. Never raises into a write path.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from . import object_refresh as orf

log = logging.getLogger(__name__)

VERIFIED, MISMATCH, UNVERIFIED = orf.VERIFIED, orf.MISMATCH, orf.UNVERIFIED

#: The write verb → the operation it is (what the audit and the verdict name).
OPS = {"POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}

#: The re-read said "there is no such object" (as opposed to "the read failed").
ABSENT = object()

#: Field names never compared, beyond ``object_refresh``'s own list: pass
#: phrases, credentials, private keys and any ``key`` / ``token`` field
#: (``api-key``, ``ssh_key``) — but not ``mkey`` / ``pkey`` (the object's
#: name) nor ``key-size`` (a description of a key, not the key). The same
#: rule as the FortiADC GUI pages' scrubber, so one secret is a secret
#: everywhere.
_SECRET = re.compile(r"(passw|passwd|passphrase|secret|psk|private[-_]?key|credential)"
                     r"|(^|[-_])(key|token)$", re.I)

#: A FortiADC REST entity (``/api/load_balance_pool``). Anything deeper
#: (``/api/system_global/boot_partition``, ``/api/upload/certificate_local``)
#: is a GUI helper or an action: there is no object to re-read.
_ADC_ENTITY = re.compile(r"/api/([a-z][a-z0-9_]{0,127})/?")

_FGT_CMDB = "/api/v2/cmdb/"
_FAC_ROOT = "/api/v1/"

#: Fields a FortiAuthenticator object is found by when the create reply does
#: not name it (no ``id`` / ``resource_uri``): its identity, in this order.
_FAC_IDENTITY = ("username", "name", "email")


# --------------------------------------------------------------------------- #
#  The verdict (pure)                                                          #
# --------------------------------------------------------------------------- #

def op_of(method: str) -> str:
    """``create`` / ``update`` / ``delete`` of an HTTP write verb, ``""`` for a read."""
    return OPS.get(str(method or "").upper(), "")


def _out(verdict: str, why: str, *, what: str = "", checked=None, mismatch=None,
         unchecked=None) -> dict:
    v = {"verdict": verdict, "why": why, "what": what, "refreshed": False,
         "checked": list(checked or []), "mismatch": dict(mismatch or {}),
         "unchecked": list(unchecked or [])}
    v["label"] = label(v)
    return v


def unverified(why: str, *, what: str = "") -> dict:
    """An explicit "not verified" — the only honest answer when no re-read can
    say anything (an action endpoint, a reply that names no object)."""
    return _out(UNVERIFIED, why, what=what)


def label(v: dict | None) -> str:
    """One line for an operator, the same three words on every surface."""
    v = v or {}
    verdict = v.get("verdict")
    if verdict == VERIFIED:
        return "Verified on the device"
    if verdict == MISMATCH:
        return "Not applied: " + orf.describe_mismatch(v)
    return "Not verified: " + (v.get("why") or "nothing could be compared")


def failed(v: dict | None) -> bool:
    """The device accepted the write and does NOT hold it."""
    return (v or {}).get("verdict") == MISMATCH


def _secret_value(val) -> bool:
    if not isinstance(val, str):
        return False
    s = val.strip()
    return s.startswith("ENC ") or "-----BEGIN" in s


def comparable(sent) -> dict:
    """The part of a sent body that may be compared: scalar fields only, no
    secret by name and no secret-looking value (``ENC …``, a PEM block)."""
    inner = orf._inner(sent) if isinstance(sent, dict) else {}
    out = {}
    for k, val in inner.items():
        if isinstance(k, str) and k not in ("mkey", "pkey") and _SECRET.search(k):
            continue
        if _secret_value(val):
            continue
        out[k] = val
    return out


def _net(val):
    """``192.0.2.0/24`` and ``192.0.2.0 255.255.255.0`` are one network to a
    Fortinet device, which stores whichever form it prefers (FortiOS answers
    the mask form for a CIDR it was sent)."""
    s = str(val or "").strip()
    if not s or not any(ch.isdigit() for ch in s):
        return None
    parts = s.split()
    try:
        if len(parts) == 2:
            return ipaddress.ip_network("%s/%s" % (parts[0], parts[1]), strict=False)
        if len(parts) == 1 and "/" in s:
            return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None
    return None


def _equivalent(sent_val, dev_val) -> bool:
    a, b = _net(sent_val), _net(dev_val)
    return a is not None and a == b


def judge(op: str, device, sent=None, *, what: str = "") -> dict:
    """Pure: the verdict on ONE re-read.

    ``device`` is the object the device now serves (a dict), :data:`ABSENT`
    when the device says there is no such object, or None when the read
    itself failed (unknown — never "absent").
    """
    if op == "delete":
        if device is ABSENT:
            return _out(VERIFIED, "the device no longer has it", what=what)
        if device is None:
            return _out(UNVERIFIED, "re-read failed", what=what)
        return _out(MISMATCH, "the device still has it", what=what,
                    mismatch={"(object)": {"sent": "deleted", "device": "still present"}})
    if device is ABSENT:
        return _out(MISMATCH, "the device does not have it", what=what,
                    mismatch={"(object)": {"sent": op or "write", "device": "not found"}})
    if not isinstance(device, dict):
        return _out(UNVERIFIED, "re-read failed", what=what)
    want = comparable(sent)
    # The device's own spelling of an equivalent value (a network in mask
    # form) is not a mismatch: compare what it means, not how it is written.
    for k, val in list(want.items()):
        if k in device and _equivalent(val, device[k]):
            want[k] = device[k]
    c = orf.compare(want, device)
    # A mismatch quotes what the device holds, in the verdict AND its label —
    # and a field that is no secret by name can still hold one (FortiOS
    # answers ``ENC …`` for it). Never quoted, on any console.
    c["mismatch"] = {k: ({**d, "device": "(a secret value, not shown)"}
                         if _secret_value(d.get("device")) else d)
                     for k, d in c["mismatch"].items()}
    if c["verdict"] == UNVERIFIED:
        why = ("the read does not return what was sent" if c["unchecked"]
               else "nothing comparable was sent (secrets, certificate material "
                    "and sub-tables are never compared)")
    else:
        why = "re-read"
    return _out(c["verdict"], why, what=what, checked=c["checked"],
                mismatch=c["mismatch"], unchecked=c["unchecked"])


def _audit(appliance, op: str, product: str, v: dict) -> None:
    """``config.<op>.not_applied`` — the same action ``FortiWebOps`` writes, so
    one audit query finds every write that did not land, whatever sent it."""
    if not failed(v):
        return
    try:
        from .audit import log_action
        log_action("config.%s.not_applied" % (op or "write"),
                   target="%s:%s" % (product, v.get("what") or ""),
                   appliance_id=getattr(appliance, "id", None),
                   detail=orf.describe_mismatch(v)[:900])
    except Exception:  # noqa: BLE001 — auditing must never sink the verdict
        log.warning("not_applied audit failed for %s", v.get("what"))


def _safe(fn, what: str):
    """Run one product's verification; any surprise is "not verified", never an
    exception into a write that already happened."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        log.warning("device_verify %s: %s", what, exc)
        return unverified("verification error: %s" % exc, what=what)


# --------------------------------------------------------------------------- #
#  FortiADC                                                                    #
# --------------------------------------------------------------------------- #

def adc_refusal(resp) -> str:
    """Why FortiADC refused a raw write (``""`` = accepted): HTTP >= 400 or the
    negative-integer ``payload`` it answers a refusal with. An empty or
    non-JSON 2xx body is an accepted write. The rule of
    ``FortiADCClient._device_error``, duck-typed so a module outside the ADC
    side can ask it without importing the ADC client."""
    status = getattr(resp, "status_code", 0) or 0
    if status >= 400:
        return "HTTP %s" % status
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return ""
    p = body.get("payload") if isinstance(body, dict) else None
    if isinstance(p, int) and not isinstance(p, bool) and p < 0:
        return "device errcode %s" % p
    return ""


def _adc_read(client, path: str, params: dict):
    """The object/rows of one ADC GET: a dict or list, :data:`ABSENT` for the
    measured ``{"payload": null}``, None when the read failed."""
    q = urlencode({k: v for k, v in (params or {}).items() if v is not None})
    resp = client.api_call("GET", path + ("?" + q if q else ""))
    if resp is None or getattr(resp, "status_code", 500) >= 400:
        return None
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(body, dict) or "payload" not in body:
        return None
    p = body.get("payload")
    if p is None:
        return ABSENT
    if isinstance(p, (dict, list)):
        return p
    return None   # a number: a refusal (negative) or a write result, not an object


def _adc_pick(res, mkey: str):
    if res is ABSENT or res is None:
        return res
    if isinstance(res, dict):
        if mkey and str(res.get("mkey", mkey)) != str(mkey):
            return ABSENT
        return res
    rows = [r for r in res if isinstance(r, dict)]
    if not mkey:
        return rows[0] if len(rows) == 1 else None
    hit = [r for r in rows if str(r.get("mkey")) == str(mkey)]
    return hit[0] if hit else ABSENT


def _adc_logical(appliance, entity: str) -> str:
    """The cache's name for an entity: the registry logical whose URN it is
    (they are the same name on every measured build), else the entity."""
    try:
        from ..registry import loader
        reg = loader.registry_for("fortiadc", loader.version_of(appliance)) or {}
        for name, urn in reg.items():
            if str(urn or "").rstrip("/") == "/api/" + entity:
                return name
    except Exception:  # noqa: BLE001
        pass
    return entity


def _adc_cache(appliance, op: str, entity: str, mkey: str, obj, session=None) -> bool:
    """Keep SATOM's FortiADC copy current — only for a type the sweep READ on
    this device: one with a cached row, or one the last good sweep answered
    empty (``DeviceCoverage``). Before the coverage row, the first object
    created in an empty table was never cached, so a cache read kept saying
    the table was empty until the next hourly sweep."""
    aid = getattr(appliance, "id", None)
    # No name is fine for ONE case: a settings singleton (``system_global``)
    # updated in place — the sweep caches it under ``mkey=''``.
    if aid is None or (not mkey and op != "update"):
        return False
    from ..extensions import db
    from ..models_cache import DeviceObject
    from . import write_through as wt
    session = session or db.session
    logical = _adc_logical(appliance, entity)
    try:
        held = (session.query(DeviceObject.id)
                .filter_by(appliance_id=aid, logical_name=logical, depth=0).first())
        section = None
        if held is None:
            from .device_sync import coverage_for
            cov = coverage_for(aid, session=session)
            section = ((cov.tables or {}).get(logical) if cov is not None else None)
            if not section:
                return False
            if op == "delete":
                return False      # an empty table: nothing cached to drop
        if op == "delete":
            # By logical AND mkey: ``write_through.local_delete`` maps a
            # collection through the FortiWeb registry, and with no match it
            # would drop every cached object of ANY type carrying this name.
            roots = [r.id for r in session.query(DeviceObject.id).filter_by(
                appliance_id=aid, logical_name=logical, depth=0, mkey=str(mkey))]
            ids, frontier = list(roots), list(roots)
            while frontier:
                frontier = [k.id for k in session.query(DeviceObject.id)
                            .filter(DeviceObject.parent_id.in_(frontier))]
                ids.extend(frontier)
            if ids:
                (session.query(DeviceObject).filter(DeviceObject.id.in_(ids))
                 .delete(synchronize_session=False))
                session.commit()
            return bool(roots)
        if isinstance(obj, dict) and obj:
            if not mkey:
                return wt.local_refresh(aid, logical, "", obj, session=session) > 0
            return bool(wt.local_insert(aid, logical, str(mkey), obj, session=session,
                                        section=section))
    except Exception as exc:  # noqa: BLE001 — a stale row is refreshed by the next sweep
        log.warning("device_verify ADC cache %s/%s: %s", logical, mkey, exc)
        try:
            session.rollback()
        except Exception:  # noqa: BLE001
            pass
    return False


def _adc_side_effect(path: str) -> str:
    """The ``adc_ops.ADC_SIDE_EFFECT_PATHS`` entry ``path`` reaches (``""`` =
    none). On FortiADC a plain GET of these reboots, shuts down, resets or
    swaps the boot partition: a "re-read" of one would BE the action."""
    from .adc_ops import side_effect_path
    return side_effect_path(path)


def adc_after_write(appliance, client, op: str, *, logical: str = "", path: str = "",
                    mkey=None, sent=None, pkey=None, compare=None, session=None) -> dict:
    """Verify one accepted FortiADC write (call ONLY after the device accepted it).

    ``logical`` (resolved through the client) or ``path`` (``/api/<entity>``,
    a query string is honoured: ``mkey`` / ``pkey`` / ``vdom``) names what was
    written; ``mkey`` the object (a create defaults to the body's ``mkey``; a
    settings entity such as ``system_global`` has none); ``pkey`` the parent of
    a child-table row (``…_child_…``).

    ``compare`` (field names) restricts the VERDICT to those fields of
    ``sent`` — an upload is verified by identity, not content — while the
    whole of ``sent`` still decides whether the cache needs the fuller
    collection row. A path in ``adc_ops.ADC_SIDE_EFFECT_PATHS`` is never
    read: it answers "not verified" without a single request.
    """
    what = "%s:%s" % (logical or path, mkey or "")
    judged = sent
    if compare is not None and isinstance(sent, dict):
        inner = orf._inner(sent)
        judged = {k: inner[k] for k in compare if k in inner}

    def run():
        p = path
        if not p:
            try:
                p = client._resolve(logical)
            except Exception:  # noqa: BLE001 — not in the registry: the entity itself
                p = "/api/%s" % logical
        parts = urlsplit(p)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        base = parts.path if parts.path.startswith("/") else "/" + parts.path
        hit = _adc_side_effect(base)
        if hit:
            return unverified("%s acts on the appliance itself: never re-read" % hit,
                              what=base)
        m = _ADC_ENTITY.fullmatch(base)
        if not m:
            return unverified("an action endpoint, not an object: nothing to re-read",
                              what=base)
        entity = m.group(1)
        key = mkey if mkey not in (None, "") else q.get("mkey", "")
        if op == "create" and not key:
            key = str(comparable(sent).get("mkey") or "")
        key = str(key or "")
        parent = pkey if pkey is not None else q.get("pkey")
        tag = "%s:%s" % (entity, key) + ("@%s" % parent if parent else "")
        params = {k: v for k, v in q.items() if k not in ("mkey", "pkey")}
        if "_child_" in entity:
            return _adc_child(client, op, base, entity, key, parent, params, judged, tag)
        if not key:
            if op != "update":
                return unverified("the write names no object", what=tag)
            # a settings entity (``system_global``): read it whole
            got = _adc_pick(_adc_read(client, base, params), "")
            v = judge(op, got, judged, what=tag)
            if isinstance(got, dict):
                v["refreshed"] = _adc_cache(appliance, op, entity, "", got, session=session)
            return v
        got = _adc_pick(_adc_read(client, base, {**params, "mkey": key}), key)
        missing = (isinstance(got, dict)
                   and any(k not in got for k in comparable(sent)))
        if missing:
            # The single-object read does not return every field the list
            # does: ``system_scripting?mkey=`` omits ``script`` (the Lua body)
            # while the collection read carries it (measured on fortiadc10,
            # 7.6.7). One more GET, only when something sent is not in the
            # read — so the verdict sees it and the cache gets the whole row.
            row = _adc_pick(_adc_read(client, base, params), key)
            if isinstance(row, dict):
                got = {**got, **row}
        v = judge(op, got, judged, what=tag)
        if (op == "delete" and v["verdict"] == VERIFIED) or isinstance(got, dict):
            v["refreshed"] = _adc_cache(appliance, op, entity, key, got, session=session)
        return v

    v = _safe(run, what)
    _audit(appliance, op, "fortiadc", v)
    return v


def _adc_child(client, op, base, entity, key, parent, params, sent, tag) -> dict:
    """A child-table row: read the parent's rows (``?pkey=``) and find it. A
    new row has no id the write returned, so a create is verified when SOME
    row carries what was sent (``object_refresh``'s sub-table rule)."""
    if parent is None:
        return unverified("child-table write without a parent", what=tag)
    q = dict(params)
    if parent != "":
        q["pkey"] = parent   # a settings parent has no name: its rows read bare
    rows = _adc_read(client, base, q)
    if rows is ABSENT:
        rows = []
    if not isinstance(rows, (list, dict)):
        return unverified("re-read failed", what=tag)
    rows = [rows] if isinstance(rows, dict) else [r for r in rows if isinstance(r, dict)]
    if key:
        got = next((r for r in rows if str(r.get("mkey")) == key), ABSENT)
        return judge(op, got, sent, what=tag)
    if op == "delete":
        return unverified("no row id", what=tag)
    verdicts = [judge(op, r, sent, what=tag) for r in rows]
    best = next((v for v in verdicts if v["verdict"] == VERIFIED), None)
    if best:
        return best
    if any(v["checked"] or v["mismatch"] for v in verdicts) or (not rows and comparable(sent)):
        return _out(MISMATCH, "no row matches", what=tag,
                    mismatch={"(row)": {"sent": comparable(sent), "device": "no row matches"}})
    return unverified("nothing comparable was sent", what=tag)


# --------------------------------------------------------------------------- #
#  FortiGate                                                                   #
# --------------------------------------------------------------------------- #

def _fgt_names_object(path: str) -> bool:
    rest = path[len(_FGT_CMDB):].strip("/")
    return rest.count("/") >= 2


def fgt_after_write(appliance, client, op: str, path: str, sent=None, reply=None) -> dict:
    """Verify one accepted FortiGate cmdb write. ``reply`` is the device's
    answer to it: a create's object key is the ``mkey`` FortiOS returns."""
    what = str(path or "")

    def run():
        base = urlsplit(path).path
        if not base.startswith(_FGT_CMDB):
            return unverified("not a cmdb object: nothing to re-read", what=base)
        obj_path = base
        if op == "create" and not _fgt_names_object(base):
            key = reply.get("mkey") if isinstance(reply, dict) else None
            if key in (None, ""):
                return unverified("the reply names no object", what=base)
            obj_path = base.rstrip("/") + "/" + quote(str(key), safe="")
        payload, err = client.api_call("GET", obj_path)
        names = _fgt_names_object(obj_path)
        if err:
            got = ABSENT if (names and str(err).startswith("404")) else None
        else:
            res = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(res, list):
                got = (res[0] if len(res) == 1 and isinstance(res[0], dict)
                       else (ABSENT if not res and names else None))
            else:
                got = res if isinstance(res, dict) else None
        return judge(op, got, sent, what=obj_path)

    v = _safe(run, what)
    _audit(appliance, op, "fortigate", v)
    return v


# --------------------------------------------------------------------------- #
#  FortiAuthenticator                                                          #
# --------------------------------------------------------------------------- #

def _fac_split(path: str) -> list:
    base = urlsplit(path).path
    if not base.startswith(_FAC_ROOT):
        return []
    return [s for s in base[len(_FAC_ROOT):].split("/") if s]


def _fac_get(client, obj_path: str):
    payload, err = client.api_call("GET", obj_path)
    if err:
        return ABSENT if str(err).startswith("HTTP 404") else None
    return payload if isinstance(payload, dict) and payload else None


def fac_after_write(appliance, client, op: str, path: str, sent=None, reply=None) -> dict:
    """Verify one accepted FortiAuthenticator write (Tastypie REST:
    ``/api/v1/<resource>/`` is the collection, ``/api/v1/<resource>/<id>/``
    one object). A create is found by the ``resource_uri`` / ``id`` it
    answered, else by its identity field (``?username=`` / ``?name=``)."""
    what = str(path or "")

    def run():
        segs = _fac_split(path)
        if not segs:
            return unverified("not a REST object: nothing to re-read", what=what)
        res = segs[0]
        coll = "%s%s/" % (_FAC_ROOT, res)
        if len(segs) >= 2:
            obj_path = "%s%s/" % (coll, "/".join(segs[1:]))
            return judge(op, _fac_get(client, obj_path), sent, what=obj_path)
        if op != "create":
            return unverified("the write names no object (a collection-wide %s)" % op,
                              what=coll)
        rep = reply
        if isinstance(rep, list):
            # ``POST /api/v1/localusers/`` answers a one-item LIST even for a
            # single body (``[{"statue": 201, "user": …, "user_id": 24}]``,
            # measured on fac01 8.0.3): one dict sent, one item back = that
            # object. A real bulk (a list sent) is per-item in the reply.
            items = [r for r in rep if isinstance(r, dict)]
            if not isinstance(sent, dict) or len(items) != 1:
                return unverified("a bulk create: the per-item status is in the reply",
                                  what=coll)
            item = items[0]
            st = item.get("statue", item.get("status"))
            if isinstance(st, int) and st >= 400:
                return unverified("the device refused the item (status %s)" % st,
                                  what=coll)
            oid = next((item[k] for k in ("user_id", "id") if item.get(k) not in (None, "")),
                       None)
            if oid is not None:
                obj_path = "%s%s/" % (coll, oid)
                return judge(op, _fac_get(client, obj_path), sent, what=obj_path)
            rep = None   # no id: found by its identity field below
        if isinstance(rep, dict):
            uri = str(rep.get("resource_uri") or "")
            if uri.startswith(_FAC_ROOT):
                obj_path = uri.rstrip("/") + "/"   # GET without the slash is a redirect
                return judge(op, _fac_get(client, obj_path), sent, what=obj_path)
            if rep.get("id") not in (None, ""):
                obj_path = "%s%s/" % (coll, rep["id"])
                return judge(op, _fac_get(client, obj_path), sent, what=obj_path)
        want = comparable(sent)
        ident = next((k for k in _FAC_IDENTITY if want.get(k) not in (None, "")), None)
        if ident is None or not hasattr(client, "list_path_with_error"):
            return unverified("the reply names no object", what=coll)
        rows, err = client.list_path_with_error(coll, **{ident: want[ident]})
        if err:
            return unverified("re-read failed", what=coll)
        hit = [r for r in rows or [] if isinstance(r, dict)
               and str(r.get(ident)) == str(want[ident])]
        return judge(op, hit[0] if hit else ABSENT, sent,
                     what="%s?%s=%s" % (coll, ident, want[ident]))

    v = _safe(run, what)
    _audit(appliance, op, "fortiauthenticator", v)
    return v


# --------------------------------------------------------------------------- #
#  FortiWeb (the raw console / proxy; FortiWebOps has its own)                 #
# --------------------------------------------------------------------------- #

def fortiweb_after_write(appliance, client, op: str, path: str, sent=None) -> dict:
    """A raw FortiWeb write that did not go through ``FortiWebOps``: the same
    ``object_refresh`` re-read (cache + verdict) its writes get."""
    p = str(path or "").lstrip("/")
    what = p

    def run():
        r = orf.after_write(appliance, client, op, p, sent)
        v = dict(r.get("verify") or {})
        why = v.get("why") or r.get("why") or ""
        out = _out(v.get("verdict") or UNVERIFIED, why, what=r.get("what") or p,
                   checked=v.get("checked"), mismatch=v.get("mismatch"),
                   unchecked=v.get("unchecked"))
        if out["verdict"] == UNVERIFIED and not v.get("why"):
            out["why"] = r.get("why") or "nothing could be compared"
            out["label"] = label(out)
        out["refreshed"] = bool(r.get("refreshed"))
        return out

    v = _safe(run, what)
    _audit(appliance, op, "fortiweb", v)
    return v


# --------------------------------------------------------------------------- #
#  One door for the consoles                                                   #
# --------------------------------------------------------------------------- #

def after_request(appliance, client, method: str, path: str, sent=None, reply=None) -> dict:
    """The verdict of one ACCEPTED raw write, by the appliance's product.
    A read (or a verb that is no write) has no verdict: None."""
    op = op_of(method)
    if not op:
        return None
    kind = getattr(appliance, "kind", "") or "fortiweb"
    if kind == "fortiadc":
        return adc_after_write(appliance, client, op, path=path, sent=sent)
    if kind == "fortigate":
        return fgt_after_write(appliance, client, op, path, sent, reply)
    if kind == "fortiauthenticator":
        return fac_after_write(appliance, client, op, path, sent, reply)
    if kind == "fortiweb":
        return fortiweb_after_write(appliance, client, op, path, sent)
    return unverified("no verification for %s" % kind, what=str(path or ""))


__all__ = ["VERIFIED", "MISMATCH", "UNVERIFIED", "ABSENT", "OPS", "op_of", "judge",
           "comparable", "label", "failed", "unverified", "adc_after_write",
           "fgt_after_write", "fac_after_write", "fortiweb_after_write",
           "after_request"]
