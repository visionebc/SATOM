"""One GUI engine, four products: what differs per product, in one place.

The measured GUI pages (``gui_pages`` / ``gui_template``; layouts per exact
build from the knowledge packs) are drawn by the same routes and templates for
FortiWeb, FortiGate, FortiAuthenticator and FortiADC. What is NOT the same is
how a product's objects are read, named and written; each product has an
adapter:

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
FortiADC      live ``GET /api/<entity>`` (``vdom``    ``POST /api/<entity>``,
              aware; SATOM keeps no FortiADC config   ``PUT|DELETE /api/<entity>
              cache for these pages); one object is   ?mkey=<name>`` through
              ``?mkey=<name>``; a settings entity     ``adc_ops.rest_call``;
              answers ONE object (singleton); a       mkey = the row's ``mkey``;
              child table ``<parent>_child_<t>`` is   child tables read-only
              read with ``?pkey=<parent>``            here
============  =====================================  ===========================

Every FortiGate / FortiAuthenticator / FortiADC write goes through
:class:`GuiOps`, the counterpart of ``FortiWebOps``: a dry run returns the
exact request without contacting the device; an apply reads the object first
(the before-snapshot), sends, records a ``ChangeHistory`` row and an audit
entry, and never raises.

Template endpoints: FortiGate views name the cmdb path after ``/api/v2/cmdb/``
(``firewall/policy``) or ``monitor:<path>``; FortiAuthenticator views name the
REST resource after ``/api/v1/`` (``localusers``) or its registry logical
(``auth_local_users``); FortiADC views name the bare REST entity
(``load_balance_virtual_server``, which is also its registry logical); a page
with no REST at all is ``gui:<url-path>``. A field measured
``key_from: "gui-only"`` has no API on that build: drawn read-only and marked,
never saved.
"""
from __future__ import annotations

import copy
import json
import re
import time
from datetime import datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

FORTIWEB, FORTIGATE, FORTIAUTH = "fortiweb", "fortigate", "fortiauthenticator"
FORTIADC = "fortiadc"
PRODUCTS = (FORTIWEB, FORTIGATE, FORTIAUTH, FORTIADC)
LABELS = {FORTIWEB: "FortiWeb", FORTIGATE: "FortiGate", FORTIAUTH: "FortiAuthenticator",
          FORTIADC: "FortiADC"}
#: Sidebar group icon colour per product (SATOM accents, light theme; the
#: FortiADC one is the ADOM colour base.html already gives it).
ICONS = {FORTIWEB: "#ef4444", FORTIGATE: "#0d9488", FORTIAUTH: "#7c3aed", FORTIADC: "#10b981"}

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


def flat_dicts(row: dict) -> dict:
    """The row with every nested object also under its dotted key path
    (``{"ipv6": {"ip6-mode": "static"}}`` -> ``"ipv6.ip6-mode": "static"``):
    the FortiGate templates name a field of a nested object that way
    (measured: ``ipv6.ip6-mode`` on the interface dialog,
    ``http.comfort-interval`` on protocol options). Lists stay as they are."""
    out = dict(row or {})

    def walk(pre, v):
        for k, x in v.items():
            if str(k).startswith("q_"):
                continue
            p = "%s.%s" % (pre, k)
            if isinstance(x, dict):
                walk(p, x)
            else:
                out[p] = x
    for k, v in list((row or {}).items()):
        if isinstance(v, dict):
            walk(k, v)
    return out


def is_dotted(key) -> bool:
    return isinstance(key, str) and "." in key


def get_dotted(obj: dict, key: str):
    cur = obj
    for seg in key.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return None
        cur = cur[seg]
    return cur


def set_dotted(out: dict, key: str, value) -> None:
    """``out["a"]["b"] = value`` for ``"a.b"``: only the changed sub-key is
    sent (FortiOS sets the attributes a PUT names and keeps the others)."""
    segs = key.split(".")
    cur = out
    for seg in segs[:-1]:
        if not isinstance(cur.get(seg), dict):
            cur[seg] = {}
        cur = cur[seg]
    cur[segs[-1]] = value


def is_cli(endpoint: str | None) -> bool:
    """A FortiAuthenticator object only the CLI serves (``cli:system/dns``)."""
    return (endpoint or "").startswith("cli:")


def cli_object(endpoint: str | None) -> str:
    return (endpoint or "")[len("cli:"):].strip("/") if is_cli(endpoint) else ""


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

    def refusal(self, endpoint: str) -> str:
        """Why SATOM writes nothing to ``endpoint`` from a GUI page, beyond
        "no API on this build" ("" = no particular reason)."""
        return ""

    # -- writes ----------------------------------------------------------
    def path(self, endpoint: str, mkey: str | None) -> str:
        raise NotImplementedError

    def request_path(self, appliance, op: str, endpoint: str, mkey: str | None) -> str:
        """The exact path (query included) a write of ``op`` is sent to;
        built without contacting the device (the dry run shows it)."""
        return self.path(endpoint, None if op == "create" else mkey)

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
        meta = {"generated_at": None, "source": "live", "cached": False, "error": err,
                # the endpoint answered ONE settings object, not a table
                "singleton": isinstance(res, dict)}
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
        out = flat_dicts(row)
        for k, v in list(out.items()):
            names = _member_names(v)
            if names is not None:
                out[k] = names
        return out

    def payload(self, fields, orig):
        orig = orig or {}
        out = {}
        for k, v in (fields or {}).items():
            o = get_dotted(orig, k) if is_dotted(k) and k not in orig else orig.get(k)
            if isinstance(o, list) and (_member_names(o) is not None or not o):
                val = [{"name": n} for n in str(v).split()]
            elif o is not None or k in orig:
                val = _typed(o, v)
            else:
                val = v
            if is_dotted(k) and k not in orig:
                # a field of a nested object: sent inside it
                set_dotted(out, k, val)
            else:
                out[k] = val
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
_cli_cache: dict = {}


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

    # -- objects only the CLI serves (``cli:system/dns``) -----------------
    def cli_rows(self, appliance, endpoint: str) -> tuple:
        """(rows, error) of a CLI-only object, read with ``show
        full-configuration <path>`` over a read-only SSH session: one row for
        a singleton, one per ``edit`` for a table (its key in ``_edit``, the
        name the templates give the CLI row id). The CLI path comes from the
        API library of the device's exact build; secrets are never returned.
        Kept a few seconds per device and object (a page reads it twice)."""
        key = (getattr(appliance, "id", None), endpoint)
        hit = _cli_cache.get(key)
        if hit and time.monotonic() - hit[0] < _FGT_TTL:
            return hit[1], None
        from . import cli_writer
        obj = cli_object(endpoint)
        try:
            split = cli_writer.split_payload(appliance, obj, {})
        except Exception as exc:  # noqa: BLE001 -- the library never sinks a page
            return [], "API library: %s" % exc
        o = split.get("object") or {}
        path = " ".join(str(o.get("cli_path") or "").split())
        if not path:
            return [], ("the API library does not name the CLI path of %s on this build"
                        % obj)
        if o.get("parent"):
            return [], "%s is nested in another CLI table: not listed here" % obj
        kind = o.get("kind") or cli_writer.cli_schema.KIND_TABLE
        plan = cli_writer.CliPlan(product=split.get("product") or FORTIAUTH,
                                  levels=[cli_writer.CliLevel(path, None, kind)],
                                  endpoint=split.get("endpoint") or obj)
        try:
            read = cli_writer.CliWriter(appliance, audit=False)._read_object(plan)
        except Exception as exc:  # noqa: BLE001 -- unreachable: said on the page
            return [], "CLI read failed: %s: %s" % (type(exc).__name__, exc)
        if read.get("not_found"):
            return [], "the CLI does not show %s" % path
        from .not_in_gui import _channels
        lib = (_channels(split.get("product") or "", split.get("version") or "",
                         split.get("endpoint") or obj).get("fields") or {})

        def clean(lines):
            vals = cli_writer.row_values(lines, path)["values"]
            return {k: v for k, v in vals.items()
                    if not cli_writer.is_secret(k, (lib.get(k) or {}).get("attrs"))}
        rows = []
        for chain, lines in (read.get("rows") or {}).items():
            if len(chain) != 1 or " ".join(chain[0][0].split()) != path:
                continue
            if kind == cli_writer.cli_schema.KIND_SINGLETON:
                if chain[0][1] is None:
                    rows.append(clean(lines))
            elif chain[0][1] is not None:
                rows.append(dict(clean(lines), _edit=chain[0][1]))
        _cli_cache[key] = (time.monotonic(), rows)
        return rows, None

    def forget(self, appliance, endpoint):
        _cli_cache.pop((getattr(appliance, "id", None), endpoint), None)

    def form_row(self, row):
        """Tastypie lists of plain values (``groups``, ``ip_list``) as the
        space-separated text the form edits; JSON booleans stay booleans
        (the page draws them as the control's on / off)."""
        out = dict(row or {})
        for k, v in list(out.items()):
            if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
                out[k] = " ".join(str(x) for x in v)
        return out

    def mkey_of(self, row, endpoint=""):
        if is_cli(endpoint) or "_edit" in (row or {}):
            v = (row or {}).get("_edit")
            return "" if v in (None, "") else str(v)
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

    def request_path(self, appliance, op, endpoint, mkey):
        # the registry's REST path of the endpoint (a logical or a resource)
        _lg, base = self.resolve(appliance, endpoint)
        if op == "create" or not mkey:
            return base
        return base.rstrip("/") + "/%s/" % quote(str(mkey), safe="")

    def rows(self, appliance, endpoint):
        if not endpoint or is_gui_only(endpoint):
            return [], None
        if is_cli(endpoint):
            got, err = self.cli_rows(appliance, endpoint)
            return got, {"generated_at": None, "source": "live-cli", "cached": False,
                         "error": err}
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
        if is_cli(endpoint):
            self.forget(appliance, endpoint)
            got, err = self.cli_rows(appliance, endpoint)
            if err:
                return None
            if not mkey:
                return got[0] if len(got) == 1 and "_edit" not in got[0] else None
            return next((r for r in got if str(r.get("_edit")) == str(mkey)), None)
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
            if op == "update" and write_through.local_refresh(appliance.id, logical, cm, obj) > 0:
                return True
            # created, or an object the cache does not hold yet (its last
            # sweep predates it): cached now, beside its siblings
            return write_through.local_insert(appliance.id, logical, cm, obj)
        except Exception:  # noqa: BLE001 -- the write itself succeeded
            return False

    def payload(self, fields, orig):
        orig = orig or {}
        out = {}
        for k, v in (fields or {}).items():
            o = orig.get(k)
            if isinstance(o, list) and all(not isinstance(x, (dict, list)) for x in o):
                out[k] = [_typed(o[0], x) if o else x for x in str(v).split()]
            else:
                out[k] = _typed(o, v) if k in orig else v
        return out


# --------------------------------------------------------------------------- #
# FortiADC
# --------------------------------------------------------------------------- #
#: A FortiADC REST entity: the CLI path with its separators flattened to
#: underscores (``config load-balance virtual-server`` ->
#: ``load_balance_virtual_server``); the registry logical has the same name.
_ADC_ENTITY = re.compile(r"[a-z][a-z0-9_]{0,127}")
#: A child table of an entity (``load_balance_pool_child_pool_member``): its
#: rows are read with ``?pkey=<parent mkey>``.
ADC_CHILD = "_child_"
#: A GET helper the FortiADC GUI calls beside an entity
#: (``load_balance_virtual_server/get_vs_advanced_edit_options``, measured on
#: 7.6.7 build0676): a layout may name one where SATOM reads; the adapter
#: lists entities only, so such a view reads as an error, never a guess.
_ADC_GET_HELPER = re.compile(r"[a-z][a-z0-9_]{0,127}/get_[a-z0-9_]{1,64}")
#: Field names never echoed back: passwords, pass phrases, secrets, PSKs,
#: private keys, credentials, and any ``key`` / ``token`` (``api-key``,
#: ``ssh_key``) -- but not ``mkey`` / ``pkey`` (the object's own name) nor
#: ``key-size`` / ``key_type`` (descriptions of a key, not the key).
_ADC_SECRET = re.compile(r"(passw|passwd|passphrase|secret|psk|private[-_]?key|credential)"
                         r"|(^|[-_])(key|token)$", re.I)


class FortiADCAdapter(Adapter):
    """FortiADC: rows live from ``GET /api/<entity>`` (SATOM keeps no
    FortiADC config cache for these pages), one object by ``?mkey=``, writes
    ``POST`` / ``PUT ?mkey=`` / ``DELETE ?mkey=`` through
    ``adc_ops.rest_call`` (the fleet-wide engine never builds the ADC client
    itself). A settings entity (``system_global``) answers one object: listed
    as a singleton and updated with an empty ``mkey`` (as
    ``FortiADCClient.update('system_global', '', ...)``, verified live)."""
    product = FORTIADC
    update_method = "PUT"

    # -- naming ----------------------------------------------------------
    def mkey_of(self, row, endpoint=""):
        v = (row or {}).get("mkey")
        if v not in (None, ""):
            return str(v)
        return super().mkey_of(row, endpoint)

    def secret(self, key, value):
        if isinstance(value, str) and value.startswith("ENC "):
            return True
        return isinstance(key, str) and key not in ("mkey", "pkey") \
            and bool(_ADC_SECRET.search(key))

    @staticmethod
    def is_child(endpoint: str | None) -> bool:
        return ADC_CHILD in (endpoint or "")

    def writable(self, endpoint):
        # an entity, never one of its GET helpers nor a child table
        return super().writable(endpoint) and bool(_ADC_ENTITY.fullmatch(endpoint or "")) \
            and not self.is_child(endpoint)

    def refusal(self, endpoint):
        if self.is_child(endpoint):
            return ("%s is a FortiADC child table (its rows belong to one parent object): "
                    "edit its rows from the parent in the FortiADC object editor; nothing "
                    "is sent from this page" % endpoint)
        return ""

    @staticmethod
    def vdom_params(appliance) -> dict:
        """``{"vdom": <name>}`` of a row that administers one virtual domain;
        nothing for a box with none (or ``global``: the client omits it)."""
        v = (getattr(appliance, "vdom", "") or "").strip()
        return {"vdom": v} if v and v.lower() != "global" else {}

    def base_path(self, appliance, endpoint: str) -> tuple:
        """``(path, error)`` of a template endpoint: the registry's URN for
        the device's build (an entity that build is measured NOT serving is
        an error), else ``/api/<entity>``. Never a path the grammar refuses."""
        ep = (endpoint or "").strip()
        if not _ADC_ENTITY.fullmatch(ep):
            return "", "not a FortiADC REST entity: %r" % (endpoint,)
        try:
            from ..registry import loader
        except Exception:  # noqa: BLE001
            return "/api/%s" % ep, ""
        try:
            urn = loader.resolve_for(FORTIADC, ep, loader.version_of(appliance))
        except loader.EndpointNotServed as exc:
            return "", str(exc)
        except Exception:  # noqa: BLE001 -- not in the registry: the entity itself
            urn = None
        urn = str(urn or "")
        if not (urn.startswith("/api/") and _ADC_ENTITY.fullmatch(urn[len("/api/"):])):
            urn = "/api/%s" % ep
        return urn, ""

    def path(self, endpoint, mkey):
        base = "/api/%s" % (endpoint or "").strip()
        return base + ("?" + urlencode({"mkey": str(mkey)}) if mkey not in (None, "") else "")

    def request_path(self, appliance, op, endpoint, mkey):
        base, _err = self.base_path(appliance, endpoint)
        params = {}
        if op != "create":
            # a settings entity is addressed with an EMPTY mkey
            params["mkey"] = "" if mkey in (None, "") else str(mkey)
        params.update(self.vdom_params(appliance))
        base = base or "/api/%s" % (endpoint or "").strip()
        return base + ("?" + urlencode(params) if params else "")

    # -- reads -----------------------------------------------------------
    def _get(self, appliance, endpoint, params: dict | None = None, *, cached: bool = True):
        """(payload, error) of one GET, kept a few seconds per device,
        endpoint and query (a page that lists then opens reads once)."""
        base, err = self.base_path(appliance, endpoint)
        if err:
            return None, err
        q = dict(params or {})
        q.update(self.vdom_params(appliance))
        key = (getattr(appliance, "id", None), endpoint, tuple(sorted(q.items())))
        hit = _adc_cache.get(key)
        if cached and hit and time.monotonic() - hit[0] < _FGT_TTL:
            return copy.deepcopy(hit[1]), None
        from . import adc_ops
        payload, err = adc_ops.rest_call(appliance, "GET", base, params=q)
        if err is None:
            _adc_cache[key] = (time.monotonic(), copy.deepcopy(payload))
        return payload, err

    def forget(self, appliance, endpoint):
        aid = getattr(appliance, "id", None)
        for k in [k for k in _adc_cache if k[0] == aid and k[1] == endpoint]:
            _adc_cache.pop(k, None)

    @staticmethod
    def _is_singleton(res) -> bool:
        """A settings entity: one object (or one row that names no ``mkey``)."""
        if isinstance(res, dict):
            return True
        return isinstance(res, list) and len(res) == 1 and isinstance(res[0], dict) \
            and "mkey" not in res[0]

    def rows(self, appliance, endpoint):
        if not endpoint or is_gui_only(endpoint):
            return [], None
        try:
            res, err = self._get(appliance, endpoint)
        except Exception as exc:  # noqa: BLE001 -- drawn as unreadable, never a 500
            res, err = None, "%s: %s" % (type(exc).__name__, exc)
        meta = {"generated_at": None, "source": "live", "cached": False, "error": err,
                "singleton": not err and self._is_singleton(res)}
        if err:
            return [], meta
        rows = [res] if isinstance(res, dict) else [r for r in (res or []) if isinstance(r, dict)]
        return [self.scrub(r) for r in rows], meta

    def child_rows(self, appliance, endpoint: str, parent: str | None) -> tuple:
        """(rows, error) of a child table of one parent object
        (``?pkey=<parent>``); no parent (Create New) = no rows."""
        if not parent:
            return [], None
        try:
            res, err = self._get(appliance, endpoint, {"pkey": str(parent)})
        except Exception as exc:  # noqa: BLE001
            return [], "%s: %s" % (type(exc).__name__, exc)
        if err:
            return [], err
        rows = [res] if isinstance(res, dict) else [r for r in (res or []) if isinstance(r, dict)]
        return [self.scrub(r) for r in rows], None

    def read(self, appliance, endpoint, mkey):
        if read_only_endpoint(endpoint):
            return None
        if not mkey:
            rows, meta = self.rows(appliance, endpoint)
            if (meta or {}).get("error") or not rows:
                return None
            return rows[0] if (meta or {}).get("singleton") or len(rows) == 1 else None
        try:
            res, err = self._get(appliance, endpoint, {"mkey": str(mkey)}, cached=False)
        except Exception:  # noqa: BLE001
            return None
        if err:
            return None
        if isinstance(res, list):
            res = next((r for r in res if isinstance(r, dict)
                        and str(r.get("mkey", mkey)) == str(mkey)), None)
        return self.scrub(res) if isinstance(res, dict) and res else None

    def payload(self, fields, orig):
        """The changed fields only (a partial PUT keeps every key it does not
        name: ``FortiADCClient.bind_https_admin_cert``, verified live), typed
        as the device served them; an object of a table also names its own
        ``mkey`` in the body, as the FortiADC object editor and the vendor's
        tooling send it. Secrets were never read, so they are never sent."""
        out = super().payload(fields, orig)
        mk = (orig or {}).get("mkey")
        if mk not in (None, "") and "mkey" not in out:
            out = {"mkey": mk, **out}
        return out

    # -- writes ----------------------------------------------------------
    def send(self, appliance, method, path, body):
        parts = urlsplit(path)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        from . import adc_ops
        _payload, err = adc_ops.rest_call(appliance, method, parts.path, params=params,
                                          body=body)
        return (not err), (err or "")

    def after_write(self, appliance, endpoint, mkey, obj, op):
        # SATOM keeps no FortiADC config cache for these pages: the next read
        # is the device's
        self.forget(appliance, endpoint)
        return True


_adc_cache: dict = {}


class FortiWebAdapter(Adapter):
    """FortiWeb keeps its own path (objedit routes); the adapter only names
    and lists rows the way the FortiWeb pages always did."""
    product = FORTIWEB

    def rows(self, appliance, endpoint):
        from . import gui_pages
        return gui_pages.rows(appliance.id, endpoint)


_ADAPTERS = {FORTIWEB: FortiWebAdapter(), FORTIGATE: FortiGateAdapter(),
             FORTIAUTH: FortiAuthenticatorAdapter(), FORTIADC: FortiADCAdapter()}


def adapter(product_or_appliance) -> Adapter:
    p = product_or_appliance if isinstance(product_or_appliance, str) \
        else product_of(product_or_appliance)
    return _ADAPTERS.get(p or "", _ADAPTERS[FORTIWEB])


# --------------------------------------------------------------------------- #
# The audited write path (FortiGate / FortiAuthenticator / FortiADC)
# --------------------------------------------------------------------------- #
class GuiOps:
    """FortiWebOps for the other products: dry run = the exact request,
    no device contact; apply = before-read, send, ChangeHistory + audit."""

    METHODS = {"create": "POST", "delete": "DELETE"}

    def __init__(self, appliance):
        self.appliance = appliance
        self.ad = adapter(appliance)

    def request(self, op: str, endpoint: str, mkey: str | None, body) -> dict:
        method = self.METHODS.get(op) or self.ad.update_method
        path = self.ad.request_path(self.appliance, op, endpoint, mkey)
        return {"method": method, "path": path, "body": None if op == "delete" else body}

    def run(self, op: str, endpoint: str, mkey: str | None, body, *, dry_run: bool = True) -> dict:
        req = self.request(op, endpoint, mkey, body)
        if not self.ad.writable(endpoint):
            return {"ok": False, "dry_run": dry_run, "request": req,
                    "error": self.ad.refusal(endpoint)
                    or "this page has no API on this build: nothing is sent"}
        if self.ad.product == FORTIADC:
            # an entity the device's build is measured NOT serving (or a name
            # the grammar refuses): refused before the dry run says "ok"
            _base, why = self.ad.base_path(self.appliance, endpoint)
            if why:
                return {"ok": False, "dry_run": dry_run, "request": req,
                        "error": why + ": nothing is sent"}
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


# --------------------------------------------------------------------------- #
# Endpoints a FortiGate / FortiAuthenticator layout may name (pack importer)
# --------------------------------------------------------------------------- #
CLI = "cli:"
#: Where an endpoint stands in a layout: ``read`` (a view, a dialog, a table
#: field: SATOM GETs it), ``write`` (a dialog's ``write``/``writes``, a field's
#: ``bind``: SATOM sends it) and ``gui_write`` (the FortiAuthenticator form post
#: the crawl observed: informational, SATOM never replays it).
READ, WRITE, GUI_WRITE = "read", "write", "gui_write"
#: FortiGate cmdb path after ``/api/v2/cmdb/``: ``firewall/address``,
#: ``system.dhcp/server``, the sub-table ``router/ospf/area``.
_FGT_CMDB = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)*(/[a-z0-9_-]+){1,3}", re.I)
_FGT_MONITOR = re.compile(r"monitor:[a-z0-9_-]+(\.[a-z0-9_-]+)*(/[a-z0-9_-]+){1,4}", re.I)
#: FortiAuthenticator REST resource after ``/api/v1/`` (``localusers``) or its
#: registry logical (``auth_local_users``), and a CLI object (``cli:system/dns``).
_FAC_REST = re.compile(r"[a-z][a-z0-9_-]{0,63}", re.I)
_FAC_CLI = re.compile(r"cli:[a-z0-9_-]+(/[a-z0-9_-]+){0,3}", re.I)
#: A GUI page path (``gui:/admin/fac_auth/iamuser/<id>/change/``): no ``..``.
_GUI_PATH = re.compile(r"gui:/((<id>|[a-z0-9_-][a-z0-9_.-]*)/)*([a-z0-9_-][a-z0-9_.-]*)?", re.I)
#: Device actions, at the start of a word of the path (FortiWeb's list,
#: ``vendor/satom_guikit``, without its secret words: the cmdb and ``/api/v1/``
#: trees are configuration whose secrets the adapters scrub, and Password
#: Policy, FortiToken or Certificates are configuration pages; nor ``action``:
#: cmdb ``system/automation-action`` is a config table). At a word start so FAC
#: ``tacacsshellcommand`` (TACACS+ shell command sets) is not ``shell``.
#: Measured 2026-10-10 over the FortiGate 8.0.1 build245 (53 pages) and FAC
#: 8.0.3 build99 (93 pages) crawls, it hits two: FortiGate User & Authentication
#: > FortiTokens (its dialog names cmdb ``system/device-upgrade`` and
#: ``system/federated-upgrade``, the objects that schedule the device's and the
#: Fabric's firmware upgrade) and FAC Scheduled Backups (``gui:/system/
#: scheduled_backup/``: the device ships its whole configuration to a server).
_ACTION = re.compile(r"(?<![a-z])(reboot|shutdown|restart|restore|upgrade|firmware|factory|reset|"
                     r"backup|logout|disconnect|revoke|purge|wipe|erase|flush|delete|clear|exec|"
                     r"shell|debug|diagnose|upload|download|import|maintenance)", re.I)
#: FortiAuthenticator REST resources that ARE actions (authenticate, push).
_FAC_ACTION_REST = frozenset({"auth", "pushauth", "pushauthresp"})


def unsafe_endpoint(product: str, ep, role: str = READ) -> str:
    """Why ``ep`` may not stand at ``role`` in a ``product`` layout ("" = it may).

    FortiADC: a REST entity (``load_balance_virtual_server``) anywhere,
    ``gui:<path>`` only where SATOM reads, no crawled form post.
    FortiGate: a cmdb path anywhere; ``monitor:<path>`` and ``gui:<path>``
    only where SATOM reads (the monitor tree holds status and the device's
    actions, never configuration: one in a write or a bind is an action
    route). FortiAuthenticator: a REST resource anywhere; ``cli:<object>`` and
    ``gui:<path>`` only where SATOM reads; a crawled form post (``gui_writes``)
    only as ``gui:<path>``. Never a path naming a device action, whatever the
    method or the role (a GET can act). FortiWeb keeps ``gui_bound.safe_api``."""
    if ep in (None, ""):
        return ""
    if not isinstance(ep, str):
        return "not an endpoint"
    if product == FORTIGATE:
        if role == WRITE and (is_monitor(ep) or is_gui_only(ep)):
            return "a %s path in a write is a device action route" % ep.split(":", 1)[0]
        ok = _FGT_CMDB.fullmatch(ep) or (role == READ and (_FGT_MONITOR.fullmatch(ep)
                                                           or _GUI_PATH.fullmatch(ep)))
        if not ok:
            return "not a cmdb path (after /api/v2/cmdb/)" + (
                "" if role == WRITE else ", monitor: or gui: path")
    elif product == FORTIADC:
        # the bare REST entity anywhere; ``gui:<path>`` only where SATOM reads
        if role == READ:
            ok = _ADC_ENTITY.fullmatch(ep) or _ADC_GET_HELPER.fullmatch(ep) \
                or _GUI_PATH.fullmatch(ep)
        elif role == WRITE:
            ok = _ADC_ENTITY.fullmatch(ep)
        else:
            ok = None   # no crawled form post is ever replayed on a FortiADC
        if not ok:
            return "not a %s" % ("REST entity (after /api/)" if role == WRITE
                                 else "REST entity or gui: path" if role == READ
                                 else "FortiADC endpoint for %s" % role)
    elif product == FORTIAUTH:
        if role == GUI_WRITE:
            ok = _GUI_PATH.fullmatch(ep)
        elif role == WRITE:
            ok = _FAC_REST.fullmatch(ep)
        else:
            ok = _FAC_REST.fullmatch(ep) or _FAC_CLI.fullmatch(ep) or _GUI_PATH.fullmatch(ep)
        if not ok:
            return "not a %s" % {GUI_WRITE: "gui: path", WRITE: "REST resource (after /api/v1/)"}.get(
                role, "REST resource, cli: object or gui: path")
        if ep.lower() in _FAC_ACTION_REST:
            return "an authentication action resource"
    else:
        return "no endpoint grammar for product %r" % product
    if _ACTION.search(ep.split(":", 1)[1] if ":" in ep else ep):
        return "names a device action"
    return ""


def drift(sent: dict, after: dict | None) -> list | None:
    """[{key, sent, now}] of the fields the device stored differently from
    what was sent (compared in the form's text, so ``[{"name": "a"}]`` and
    ``"a"`` agree); None when the object could not be read back."""
    if after is None:
        return None
    # a nested object is compared field by field (``ipv6.ip6-mode``)
    sent, after = flat_dicts(sent), flat_dicts(after)
    out = []
    for k, v in (sent or {}).items():
        if k not in after or isinstance(v, dict):
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


# --------------------------------------------------------------------------- #
# Inline tables: where a dialog's table takes its rows from
# --------------------------------------------------------------------------- #
#: Row keys a FortiOS / Tastypie table row is addressed by, best first.
ROW_KEYS = ("q_origin_key", "id", "name", "seq-num", "policyid")


def row_id(row: dict) -> str:
    for k in ROW_KEYS:
        v = (row or {}).get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def table_source(product: str, dialog: dict, field: dict, dialogs: dict | None = None) -> dict:
    """Where the rows of one inline table come from, as the template measured it.

    ``{"kind": "field", "field": name}`` -- a table INSIDE the dialog's object
    (FortiGate ``router/ospf/area`` is the ``area`` field of ``router/ospf``;
    a FortiAuthenticator table whose key was measured): its rows come with the
    object and a row is saved by writing the parent object with the changed
    row. ``{"kind": "collection", "endpoint": ep}`` -- the table lists another
    cmdb table (SNMP communities on the SNMP form: ``system.snmp/community``):
    a row is an object of its own. ``{"kind": "monitor", "endpoint": ep}`` --
    status rows, read-only. ``{"kind": None}`` -- the crawl did not tie the
    table to anything: its rows cannot be listed."""
    ep = str(field.get("endpoint") or "")
    rd = (dialogs or {}).get(field.get("row_dialog") or "") or {}
    rd_ep = str(rd.get("endpoint") or "")
    dlg_ep = str(dialog.get("endpoint") or "")
    if product == FORTIAUTH:
        if field.get("key") and field.get("key_from") in ("measured", "name"):
            return {"kind": "field", "field": field["key"]}
        return {"kind": None}
    if product == FORTIADC:
        # ``{"kind": "child", "endpoint": ep}`` -- a FortiADC child table
        # (``<parent>_child_<table>``): its rows belong to ONE parent object
        # and are read with ``?pkey=<parent mkey>``; read-only on these pages
        cand = ep if ep and ep != dlg_ep else (rd_ep if rd_ep and rd_ep != dlg_ep else "")
        if not cand or is_gui_only(cand) or not _ADC_ENTITY.fullmatch(cand):
            return {"kind": None}
        if ADC_CHILD in cand:
            return {"kind": "child", "endpoint": cand}
        return {"kind": "collection", "endpoint": cand}
    if is_monitor(ep):
        return {"kind": "monitor", "endpoint": ep}
    cand = ep if ep and ep != dlg_ep else (rd_ep if rd_ep and rd_ep != dlg_ep else "")
    if not cand:
        # the crawl named the dialog's own object (OSPF summary addresses
        # measured as ``router/ospf``): not a table of it
        return {"kind": None}
    if dlg_ep and cand.startswith(dlg_ep + "/") and "/" not in cand[len(dlg_ep) + 1:]:
        return {"kind": "field", "field": cand[len(dlg_ep) + 1:]}
    if is_monitor(cand) or is_gui_only(cand):
        return {"kind": None}
    return {"kind": "collection", "endpoint": cand}


def singleton_table(obj: dict, columns: list) -> str | None:
    """The table field of a settings object a LIST view shows, when the crawl
    named the settings object instead of its table (FortiGate IPAM Rules
    measured as ``system/ipam``, which answers one object whose ``rules``
    field holds the rows). Tied by the columns the crawl did match to REST
    keys: every one of them must be a key of that field's rows, and exactly
    one table field may qualify -- otherwise None (no guess)."""
    want = {c.get("id") for c in columns or [] if isinstance(c, dict) and c.get("id")
            and not c.get("unmatched") and not c.get("computed")
            and not str(c.get("id")).startswith("q_")}
    if not want or not isinstance(obj, dict):
        return None
    hits = []
    for k, v in obj.items():
        if isinstance(v, list) and v and all(isinstance(r, dict) for r in v):
            keys = set().union(*(set(r) for r in v))
            if want <= keys:
                hits.append(k)
    return hits[0] if len(hits) == 1 else None


def table_write(orig: dict, field: str, op: str, sub_id: str | None, row_body: dict) -> tuple:
    """``(body, row_before)``: the parent object's write that changes ONE row
    of its table ``field`` -- the table as the device served it with the row
    replaced (``update``: the row's fields merged), appended (``create``) or
    left out (``delete``). Bookkeeping keys (``q_*``) are not sent back.
    Raises ValueError when the row is not in the table."""
    rows = [r for r in (orig or {}).get(field) or [] if isinstance(r, dict)]
    clean = (lambda r: {k: v for k, v in r.items() if not str(k).startswith("q_")})  # noqa: E731
    out, before = [], None
    for r in rows:
        if op != "create" and sub_id not in (None, "") and row_id(r) == str(sub_id):
            before = r
            if op == "delete":
                continue
            merged = clean(r)
            for k, v in (row_body or {}).items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
            out.append(merged)
        else:
            out.append(clean(r))
    if op == "create":
        out.append(dict(row_body or {}))
    elif before is None:
        raise ValueError("row %s is not in the table %s" % (sub_id, field))
    return {field: out}, before


#: Keys a clone never copies: the source's identity and the device's own
#: bookkeeping (FortiOS gives a new object a new ``uuid``; Tastypie a new id).
_CLONE_DROP = ("uuid", "resource_uri", "id", "policyid", "seq-num", "_edit", "q_origin_key")


def clone_body(product: str, src: dict, src_key: str, new_name: str) -> dict:
    """The create body of a copy of ``src`` named ``new_name``: every field of
    the source as the device served it (secrets were never read, so they are
    not copied), its identity replaced. The name field is the one holding the
    source's key (``name``; FortiAuthenticator users: ``username``; FortiADC:
    ``mkey``)."""
    body = {k: v for k, v in (src or {}).items()
            if not str(k).startswith("q_") and k not in _CLONE_DROP}
    # FortiADC names an object by ``mkey``: the copy gets the new one
    names = ("name", "username", "label", "mkey")
    ident = next((k for k in names if str((src or {}).get(k)) == str(src_key)),
                 None) or next((k for k in names if k in (src or {})), "name")
    body[ident] = new_name
    return body


__all__ = ["PRODUCTS", "LABELS", "FORTIWEB", "FORTIGATE", "FORTIAUTH", "FORTIADC", "ADC_CHILD",
           "product_of", "label",
           "is_gui_only", "is_monitor", "read_only_endpoint", "gui_only_fields",
           "strip_fortiweb_refs", "lib_key", "adapter", "GuiOps", "drift", "Adapter",
           "unsafe_endpoint", "READ", "WRITE", "GUI_WRITE", "flat_dicts", "is_cli",
           "cli_object", "table_source", "singleton_table", "table_write", "clone_body",
           "row_id"]
