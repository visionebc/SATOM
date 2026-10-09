"""One GUI engine, three products: what differs per product, in one place.

The measured GUI pages (``gui_pages`` / ``gui_template``; layouts per exact
build from the knowledge packs) are drawn by the same routes and templates for
FortiWeb, FortiGate and FortiAuthenticator. What is NOT the same is how a
product's objects are read, named and written; each product has an adapter:

============  =====================================  ===========================
product       rows (list / object)                   write
============  =====================================  ===========================
FortiWeb      SATOM cache (``gui_pages.rows``);       the object editor's guarded
              the object editor's device reads        endpoints (``objedit``),
                                                      unchanged
FortiGate     live cmdb ``/api/v2/cmdb/<path>``      ``PUT|POST|DELETE`` cmdb
              (vdom aware; SATOM keeps no FortiGate   through ``FortiGateClient
              config cache); ``monitor:<path>`` is    .write``; mkey = the row's
              read-only                               ``q_origin_key``
FortiAuth.    SATOM cache (the FAC sweep, registry    ``PATCH|POST|DELETE``
              logicals), else live ``/api/v1/<res>/``  ``/api/v1/<res>/[<id>/]``
                                                      through the FAC client
============  =====================================  ===========================

Every FortiGate / FortiAuthenticator write goes through :class:`GuiOps`, the
counterpart of ``FortiWebOps``: a dry run returns the exact request without
contacting the device; an apply reads the object first (the before-snapshot),
sends, records a ``ChangeHistory`` row and an audit entry, and never raises.

Template endpoints: FortiGate views name the cmdb path after ``/api/v2/cmdb/``
(``firewall/policy``) or ``monitor:<path>``; FortiAuthenticator views name the
REST resource after ``/api/v1/`` (``localusers``) or its registry logical
(``auth_local_users``); a page with no REST at all is ``gui:<url-path>``. A
field measured ``key_from: "gui-only"`` has no API on that build: drawn
read-only and marked, never saved.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from urllib.parse import quote

FORTIWEB, FORTIGATE, FORTIAUTH = "fortiweb", "fortigate", "fortiauthenticator"
PRODUCTS = (FORTIWEB, FORTIGATE, FORTIAUTH)
LABELS = {FORTIWEB: "FortiWeb", FORTIGATE: "FortiGate", FORTIAUTH: "FortiAuthenticator"}
#: Sidebar group icon colour per product (SATOM accents, light theme).
ICONS = {FORTIWEB: "#ef4444", FORTIGATE: "#0d9488", FORTIAUTH: "#7c3aed"}

GUI_ONLY = "gui:"
MONITOR = "monitor:"
API = "api:"
KEY_GUI_ONLY = "gui-only"


def product_of(appliance) -> str | None:
    kind = getattr(appliance, "kind", "") or ""
    return kind if kind in PRODUCTS else None


def label(product: str | None) -> str:
    return LABELS.get(product or "", product or "")


def is_gui_only(endpoint: str | None) -> bool:
    return (endpoint or "").startswith(GUI_ONLY)


def is_monitor(endpoint: str | None) -> bool:
    return (endpoint or "").startswith(MONITOR)


def read_only_endpoint(endpoint: str | None) -> bool:
    """A view nothing is written to: GUI-only pages and FortiGate monitor
    views (the monitor tree holds status and actions, never config)."""
    return not endpoint or is_gui_only(endpoint) or is_monitor(endpoint)


def gui_only_fields(view: dict) -> int:
    """Mark the dialog view's fields measured with no API on the build
    (``gui_only``: drawn read-only, never saved). Returns how many."""
    n = 0
    for b in view.get("blocks") or []:
        for f in b.get("fields") or []:
            if f.get("gui_only"):
                f["editable"] = False
                n += 1
    return n


def strip_fortiweb_refs(view: dict) -> None:
    """A FortiGate / FortiAuthenticator dialog has no FortiWeb reference list
    behind a ``ref`` control (``gui_template`` resolves those through
    FortiWeb's REF_ENDPOINTS) nor its object editor behind the pencil: the
    control is a plain value, never a select fed by a FortiWeb collection."""
    for b in view.get("blocks") or []:
        for f in b.get("fields") or []:
            f["ref"] = ""
            f["edit_shortcut"] = False


def lib_key(product: str, endpoint: str) -> str:
    """The API-library key of a template endpoint: FortiAuthenticator's
    library names a resource by its REST path (``localusers``), a template
    may name it by registry logical (``auth_local_users``)."""
    if product != FORTIAUTH:
        return endpoint or ""
    ep = (endpoint or "").strip("/")
    if not ep or "/" in ep:
        return ep
    try:
        from ..registry import loader
        urn = (loader.load_fac_registry() or {}).get(ep)
    except Exception:  # noqa: BLE001 -- no registry: the name as given
        urn = None
    if urn and urn.startswith("/api/v1/"):
        return urn[len("/api/v1/"):].strip("/")
    return ep


# --------------------------------------------------------------------------- #
# Values: what the form shows / what the device takes back
# --------------------------------------------------------------------------- #
def _member_names(v) -> str | None:
    """FortiOS member list ``[{"name": "port1", "q_origin_key": "port1"}]`` as
    the space-separated text the form edits; None when not such a list."""
    if not isinstance(v, list) or not v:
        return None
    out = []
    for it in v:
        if isinstance(it, dict):
            n = it.get("name", it.get("q_origin_key"))
            if n is None or len(set(it) - {"name", "q_origin_key"}) > 0:
                return None
            out.append(str(n))
        else:
            return None
    return " ".join(out)


def _typed(old, new):
    """``new`` (a form string) in the type the device served ``old`` in."""
    if isinstance(old, bool):
        return str(new).strip().lower() in ("true", "1", "yes", "on", "enable", "enabled")
    if isinstance(old, int) and not isinstance(old, bool):
        try:
            return int(str(new).strip())
        except (TypeError, ValueError):
            return new
    if isinstance(old, float):
        try:
            return float(str(new).strip())
        except (TypeError, ValueError):
            return new
    return new


class Adapter:
    product = ""
    #: the write verb of a partial update
    update_method = "PUT"

    # -- naming ----------------------------------------------------------
    def mkey_of(self, row: dict, endpoint: str = "") -> str:
        for k in ("name", "id"):
            v = (row or {}).get(k)
            if v not in (None, ""):
                return str(v)
        return ""

    # -- reads -----------------------------------------------------------
    def rows(self, appliance, endpoint: str) -> tuple:
        return [], None

    def read(self, appliance, endpoint: str, mkey: str | None):
        return None

    def writable(self, endpoint: str) -> bool:
        return not read_only_endpoint(endpoint)

    def form_row(self, row: dict) -> dict:
        """The row as the form draws and edits it."""
        return dict(row or {})

    def payload(self, fields: dict, orig: dict | None) -> dict:
        """Form values back in the shape the device takes."""
        orig = orig or {}
        return {k: (_typed(orig[k], v) if k in orig else v) for k, v in (fields or {}).items()}

    # -- writes ----------------------------------------------------------
    def path(self, endpoint: str, mkey: str | None) -> str:
        raise NotImplementedError

    def send(self, appliance, method: str, path: str, body) -> tuple:
        """(ok, error)"""
        raise NotImplementedError

    def after_write(self, appliance, endpoint: str, mkey: str, obj, op: str) -> bool:
        """Keep SATOM's copy current (write-through); True when it was."""
        return False

    def secret(self, key: str, value) -> bool:
        return False

    def scrub(self, row):
        if isinstance(row, dict):
            return {k: self.scrub(v) for k, v in row.items() if not self.secret(k, v)}
        if isinstance(row, list):
            return [self.scrub(v) for v in row]
        return row


# --------------------------------------------------------------------------- #
# FortiGate
# --------------------------------------------------------------------------- #
_FGT_MKEYS = ("q_origin_key", "name", "policyid", "seq-num", "id")
_FGT_TTL = 15.0
_fgt_cache: dict = {}


class FortiGateAdapter(Adapter):
    product = FORTIGATE
    update_method = "PUT"

    def _client(self, appliance):
        from ..clients.fortigate import FortiGateClient
        return FortiGateClient(appliance, timeout=20.0)

    def mkey_of(self, row, endpoint=""):
        for k in _FGT_MKEYS:
            v = (row or {}).get(k)
            if v not in (None, ""):
                return str(v)
        return ""

    def secret(self, key, value):
        from ..views.fgt import _is_secret
        return _is_secret(key, value)

    def path(self, endpoint, mkey):
        from ..clients.fortigate import cmdb_url
        p = cmdb_url(endpoint)
        return p + ("/" + quote(str(mkey), safe="") if mkey not in (None, "") else "")

    def _get(self, appliance, endpoint):
        """(results, error), cached a few seconds per device and endpoint so a
        page that lists then opens an object reads the device once."""
        key = (getattr(appliance, "id", None), endpoint)
        hit = _fgt_cache.get(key)
        if hit and time.monotonic() - hit[0] < _FGT_TTL:
            return hit[1], None
        c = self._client(appliance)
        if is_monitor(endpoint):
            payload, err = c._call("GET", "/api/v2/monitor/" + endpoint[len(MONITOR):].strip("/"))
            res = None if err else (payload or {}).get("results") if isinstance(payload, dict) else None
        else:
            res, err = c.cmdb(endpoint)
        if err is None:
            _fgt_cache[key] = (time.monotonic(), res)
        return res, err

    def forget(self, appliance, endpoint):
        _fgt_cache.pop((getattr(appliance, "id", None), endpoint), None)

    def rows(self, appliance, endpoint):
        if not endpoint or is_gui_only(endpoint):
            return [], None
        try:
            res, err = self._get(appliance, endpoint)
        except Exception as exc:  # noqa: BLE001 -- drawn as unreadable, never a 500
            res, err = None, "%s: %s" % (type(exc).__name__, exc)
        meta = {"generated_at": None, "source": "live", "cached": False, "error": err}
        if err:
            return [], meta
        rows = [res] if isinstance(res, dict) else [r for r in (res or []) if isinstance(r, dict)]
        return [self.scrub(r) for r in rows], meta

    def read(self, appliance, endpoint, mkey):
        if read_only_endpoint(endpoint) and not is_monitor(endpoint):
            return None
        if not mkey:
            rows, meta = self.rows(appliance, endpoint)
            return rows[0] if rows and not (meta or {}).get("error") else None
        c = self._client(appliance)
        try:
            res, err = c.cmdb(endpoint + "/" + quote(str(mkey), safe=""))
        except Exception:  # noqa: BLE001
            return None
        if err:
            return None
        if isinstance(res, list):
            res = res[0] if res else None
        return self.scrub(res) if isinstance(res, dict) else None

    def form_row(self, row):
        out = dict(row or {})
        for k, v in list(out.items()):
            names = _member_names(v)
            if names is not None:
                out[k] = names
        return out

    def payload(self, fields, orig):
        orig = orig or {}
        out = {}
        for k, v in (fields or {}).items():
            o = orig.get(k)
            if isinstance(o, list) and (_member_names(o) is not None or not o):
                out[k] = [{"name": n} for n in str(v).split()]
            elif k in orig:
                out[k] = _typed(o, v)
            else:
                out[k] = v
        return out

    def send(self, appliance, method, path, body):
        payload, err = self._client(appliance).write(method, path, body)
        if err:
            return False, err
        if isinstance(payload, dict) and payload.get("status") not in (None, "success"):
            return False, "status %s: %s" % (payload.get("status"),
                                            payload.get("cli_error") or payload.get("error") or "")
        return True, ""

    def after_write(self, appliance, endpoint, mkey, obj, op):
        # SATOM keeps no FortiGate config cache: the next read is the device's
        self.forget(appliance, endpoint)
        return True


# --------------------------------------------------------------------------- #
# FortiAuthenticator
# --------------------------------------------------------------------------- #
_FAC_NEVER = ("password", "secret", "passwd", "private_key", "api_key")


class FortiAuthenticatorAdapter(Adapter):
    product = FORTIAUTH
    update_method = "PATCH"

    def _client(self, appliance):
        from ..clients.fortiauthenticator import FortiAuthenticatorClient
        return FortiAuthenticatorClient(appliance, timeout=20.0)

    def secret(self, key, value):
        return key in _FAC_NEVER

    def resolve(self, appliance, endpoint: str) -> tuple:
        """``(registry logical | None, REST path)`` of a template endpoint
        (a resource name ``localusers`` or a logical ``auth_local_users``)."""
        from ..registry import loader
        ep = (endpoint or "").strip("/")
        try:
            reg = loader.registry_for(FORTIAUTH, loader.version_of(appliance)) or {}
        except Exception:  # noqa: BLE001 -- no registry: the resource path alone
            reg = {}
        if ep in reg:
            return ep, reg[ep]
        want = "/api/v1/%s/" % ep
        for name, urn in reg.items():
            if (urn or "").rstrip("/") + "/" == want:
                return name, urn
        return None, want

    def mkey_of(self, row, endpoint=""):
        # the detail URL's own key: some resources serve no ``id`` field
        # (radiusclients, measured on fac01 8.0.3) but every row carries
        # ``resource_uri`` = /api/v1/<res>/<pk>[/]
        uri = str((row or {}).get("resource_uri") or "").rstrip("/")
        if uri.startswith("/api/v1/") and uri.count("/") >= 4:
            return uri.rsplit("/", 1)[1]
        v = (row or {}).get("id")
        if v not in (None, ""):
            return str(v)
        return super().mkey_of(row, endpoint)

    def path(self, endpoint, mkey):
        # the template endpoint alone (no device read): resolved at send time
        base = "/api/v1/%s/" % (endpoint or "").strip("/")
        return base + ("%s/" % quote(str(mkey), safe="") if mkey not in (None, "") else "")

    def rows(self, appliance, endpoint):
        if not endpoint or is_gui_only(endpoint):
            return [], None
        logical, path = self.resolve(appliance, endpoint)
        if logical:
            from . import read_layer
            try:
                got, meta = read_layer.read_objects(appliance.id, logical)
                got = [self.scrub(r) for r in got or [] if isinstance(r, dict)]
                if got:
                    return got, meta
            except Exception:  # noqa: BLE001 -- cache unreadable: the device
                pass
        try:
            got, err = self._client(appliance).list_path_with_error(path)
        except Exception as exc:  # noqa: BLE001
            got, err = [], "%s: %s" % (type(exc).__name__, exc)
        meta = {"generated_at": None, "source": "live", "cached": False, "error": err}
        return [self.scrub(r) for r in got or [] if isinstance(r, dict)], meta

    def read(self, appliance, endpoint, mkey):
        if read_only_endpoint(endpoint):
            return None
        _logical, path = self.resolve(appliance, endpoint)
        if mkey:
            path = path.rstrip("/") + "/%s/" % quote(str(mkey), safe="")
        try:
            got, err = self._client(appliance).api_call("GET", path)
        except Exception:  # noqa: BLE001
            return None
        if err or not isinstance(got, dict):
            return None
        if isinstance(got.get("objects"), list):     # a collection answered
            got = got["objects"][0] if len(got["objects"]) == 1 and not mkey else None
        return self.scrub(got) if isinstance(got, dict) else None

    def send(self, appliance, method, path, body):
        _got, err = self._client(appliance).api_call(method, path, body)
        return (not err), (err or "")

    def after_write(self, appliance, endpoint, mkey, obj, op):
        from . import write_through
        from .device_store import _mkey_of
        logical, _path = self.resolve(appliance, endpoint)
        if not logical:
            return False
        try:
            if op == "delete":
                from ..extensions import db
                from ..models_cache import DeviceObject
                n = (db.session.query(DeviceObject)
                     .filter_by(appliance_id=appliance.id, logical_name=logical, depth=0)
                     .filter(DeviceObject.mkey.in_([str(mkey)] + ([str(_mkey_of(obj))]
                                                                 if obj else [])))
                     .delete(synchronize_session=False))
                db.session.commit()
                return n > 0
            if not isinstance(obj, dict) or not obj:
                return False
            cm = _mkey_of(obj)
            if op == "create":
                return write_through.local_insert(appliance.id, logical, cm, obj)
            return write_through.local_refresh(appliance.id, logical, cm, obj) > 0
        except Exception:  # noqa: BLE001 -- the write itself succeeded
            return False

    def payload(self, fields, orig):
        orig = orig or {}
        out = {}
        for k, v in (fields or {}).items():
            out[k] = _typed(orig[k], v) if k in orig else v
        return out


class FortiWebAdapter(Adapter):
    """FortiWeb keeps its own path (objedit routes); the adapter only names
    and lists rows the way the FortiWeb pages always did."""
    product = FORTIWEB

    def rows(self, appliance, endpoint):
        from . import gui_pages
        return gui_pages.rows(appliance.id, endpoint)


_ADAPTERS = {FORTIWEB: FortiWebAdapter(), FORTIGATE: FortiGateAdapter(),
             FORTIAUTH: FortiAuthenticatorAdapter()}


def adapter(product_or_appliance) -> Adapter:
    p = product_or_appliance if isinstance(product_or_appliance, str) \
        else product_of(product_or_appliance)
    return _ADAPTERS.get(p or "", _ADAPTERS[FORTIWEB])


# --------------------------------------------------------------------------- #
# The audited write path (FortiGate / FortiAuthenticator)
# --------------------------------------------------------------------------- #
class GuiOps:
    """FortiWebOps for the other two products: dry run = the exact request,
    no device contact; apply = before-read, send, ChangeHistory + audit."""

    METHODS = {"create": "POST", "delete": "DELETE"}

    def __init__(self, appliance):
        self.appliance = appliance
        self.ad = adapter(appliance)

    def request(self, op: str, endpoint: str, mkey: str | None, body) -> dict:
        method = self.METHODS.get(op) or self.ad.update_method
        path = self.ad.path(endpoint, None if op == "create" else mkey)
        if self.ad.product == FORTIAUTH:
            _lg, base = self.ad.resolve(self.appliance, endpoint)
            path = base if op == "create" or not mkey else \
                base.rstrip("/") + "/%s/" % quote(str(mkey), safe="")
        return {"method": method, "path": path, "body": None if op == "delete" else body}

    def run(self, op: str, endpoint: str, mkey: str | None, body, *, dry_run: bool = True) -> dict:
        req = self.request(op, endpoint, mkey, body)
        if not self.ad.writable(endpoint):
            return {"ok": False, "dry_run": dry_run, "request": req,
                    "error": "this page has no API on this build: nothing is sent"}
        if dry_run:
            return {"ok": True, "dry_run": True, "request": req, "error": ""}
        before = None
        if op != "create":
            before = self.ad.read(self.appliance, endpoint, mkey)
        try:
            ok, err = self.ad.send(self.appliance, req["method"], req["path"], req["body"])
        except Exception as exc:  # noqa: BLE001 -- a dead device is an answer
            ok, err = False, "%s: %s" % (type(exc).__name__, exc)
        self._record(op, endpoint, mkey, before, req["body"], err)
        return {"ok": ok, "dry_run": False, "request": req, "error": err, "before": before}

    def _record(self, op, endpoint, mkey, before, after, error):
        from ..models import ChangeHistory, db
        from .audit import log_action
        from .fortiweb_ops import _current_username
        try:
            db.session.add(ChangeHistory(
                appliance_id=getattr(self.appliance, "id", None),
                endpoint="%s:%s" % (self.ad.product, endpoint), mkey=str(mkey or ""), action=op,
                before=json.dumps(before) if before is not None else "",
                after=json.dumps(after) if after is not None else "",
                dry_run=False, username=_current_username(), ts=datetime.utcnow()))
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
        log_action("config.%s" % op, target="%s:%s" % (self.ad.product, endpoint),
                   appliance_id=getattr(self.appliance, "id", None),
                   detail="mkey=%s dry_run=False error=%s" % (mkey, error))


def drift(sent: dict, after: dict | None) -> list | None:
    """[{key, sent, now}] of the fields the device stored differently from
    what was sent (compared in the form's text, so ``[{"name": "a"}]`` and
    ``"a"`` agree); None when the object could not be read back."""
    if after is None:
        return None
    out = []
    for k, v in (sent or {}).items():
        if k not in after:
            continue
        a = after.get(k)
        sv = _member_names(v) if isinstance(v, list) else v
        av = _member_names(a) if isinstance(a, list) else a
        if isinstance(sv, bool) or isinstance(av, bool):
            same = bool(sv) == bool(av) if isinstance(sv, bool) and isinstance(av, bool) \
                else str(sv).lower() == str(av).lower()
        else:
            same = str("" if sv is None else sv) == str("" if av is None else av)
        if not same:
            out.append({"key": k, "sent": v, "now": a})
    return out


__all__ = ["PRODUCTS", "LABELS", "FORTIWEB", "FORTIGATE", "FORTIAUTH", "product_of", "label",
           "is_gui_only", "is_monitor", "read_only_endpoint", "gui_only_fields",
           "strip_fortiweb_refs", "lib_key", "adapter", "GuiOps", "drift", "Adapter"]
