"""Fields a FortiWeb dialog writes OUTSIDE the collection it edits.

The GUI templates name, for every control, the endpoint and key the GUI was
measured writing (harvester ``gui_bind``: the dialog saved into a gate that
failed the request in the browser). Most write the dialog's own cmdb
collection. Two cases do not:

* a settings form whose GUI writes a **GUI API** endpoint, not cmdb --
  Global / Other Log Settings (``POST log/logconfig.*``), Admin Settings
  (``PUT system/admin.settings``), FortiGuard (``system/config.fortiguard``).
  The template names it ``api:<path>``; SATOM reads it with GET on the same
  path (the REST token is accepted there) and writes it the way the GUI does:
  the current object, the changed keys set by path
  (``passwordPolicy.min-length``), sent with the GUI's method.
* a control bound to ANOTHER endpoint than its dialog (``bind``: Admin
  Settings' FortiCloud SSO login lives in cmdb ``system/global``). Its value
  is read from there and drawn under a composite key ``@<endpoint>#<key>``,
  so it never collides with a key of the dialog's own object; Save sends it to
  its own endpoint.

Fields with several controls (Log Type = Event / Attack / Traffic log) list
the extra ones in ``more``; their values are plain keys of the same object.
"""
from __future__ import annotations

import copy
import json
import re

API = "api:"
_SEG = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def is_api(ep: str | None) -> bool:
    return (ep or "").startswith(API)


def safe_api(ep: str | None) -> bool:
    """True for a GUI API configuration endpoint SATOM may read and write --
    the ONE rule the harvester also applies (vendored satom_guikit.safe_api):
    never a path naming a device action or a secret, whatever a layout says
    (layouts may come from a harvester SATOM does not run)."""
    from ..vendor import satom_guikit
    return satom_guikit.safe_api(ep)


def rest_path(ep: str) -> str:
    """The REST path of a template endpoint (``api:`` or a cmdb collection)."""
    from . import objform
    if is_api(ep):
        return "/api/v2.0/" + ep[len(API):].lstrip("/")
    return objform.rest_path(ep)


def is_subtable(ep: str | None) -> bool:
    """A cmdb table inside a parent object (more than ``module/object``)."""
    return not is_api(ep) and (ep or "").count("/") >= 2


def bound_key(ep: str, key: str) -> str:
    return "@%s#%s" % (ep, key)


def split_bound(k: str):
    """``@<endpoint>#<key>`` -> (endpoint, key); a plain key -> None."""
    if isinstance(k, str) and k.startswith("@") and "#" in k:
        ep, key = k[1:].split("#", 1)
        return ep, key
    return None


# --------------------------------------------------------------------------- #
# key paths (``passwordPolicy.min-length``, ``ip_list[0].ip``)
# --------------------------------------------------------------------------- #

def _segs(path: str) -> list:
    return [int(i) if i else n for n, i in _SEG.findall(path or "")]


def get_path(obj, path: str):
    cur = obj
    for s in _segs(path):
        if isinstance(s, int):
            if not isinstance(cur, list) or s >= len(cur):
                return None
            cur = cur[s]
        else:
            if not isinstance(cur, dict) or s not in cur:
                return None
            cur = cur[s]
    return cur


def _typed(old, value):
    """A form value (always text) in the type the device served: a number
    stays a number, a boolean a boolean; anything else is sent as typed."""
    if isinstance(old, bool):
        return str(value).lower() in ("1", "true", "yes", "on", "enable")
    if isinstance(old, int) and re.fullmatch(r"-?\d+", str(value).strip() or "x"):
        return int(str(value).strip())
    if isinstance(old, float):
        try:
            return float(value)
        except (TypeError, ValueError):
            return value
    return value


def set_path(obj: dict, path: str, value) -> None:
    """Set a key path in place, creating missing objects / list rows."""
    segs = _segs(path)
    if not segs:
        return
    cur = obj
    for i, s in enumerate(segs[:-1]):
        nxt = segs[i + 1]
        if isinstance(s, int):
            while len(cur) <= s:
                cur.append({} if not isinstance(nxt, int) else [])
            cur = cur[s]
        else:
            if not isinstance(cur.get(s), (dict, list)):
                cur[s] = [] if isinstance(nxt, int) else {}
            cur = cur[s]
    last = segs[-1]
    if isinstance(last, int):
        while len(cur) <= last:
            cur.append(None)
        cur[last] = _typed(cur[last], value)
    else:
        cur[last] = _typed(cur.get(last), value)


def flatten(obj, pre: str = "") -> dict:
    """{key path: value} of nested objects (lists of objects by row index);
    top-level keys keep their plain name."""
    out: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (pre, k) if pre else k
            if isinstance(v, dict) or (isinstance(v, list) and v and all(isinstance(x, dict) for x in v)):
                out.update(flatten(v, p))
            else:
                out[p] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(flatten(v, "%s[%d]" % (pre, i)))
    return out


# --------------------------------------------------------------------------- #
# device
# --------------------------------------------------------------------------- #

def unwrap(body):
    """The object of a GUI API / cmdb answer: ``{"results": {...}}``, a bare
    object, or the first row of a list. An error answer is None."""
    if isinstance(body, dict) and "results" in body:
        body = body["results"]
    if isinstance(body, list):
        body = next((x for x in body if isinstance(x, dict)), None)
    if not isinstance(body, dict):
        return None
    if set(body) <= {"errcode", "message"} and body.get("errcode") not in (None, 0):
        return None
    return body


def read(appliance, ep: str, client=None):
    """The ONE object of an endpoint from the device (None when unreachable or
    refused). GUI API endpoints are never cached by SATOM: read live."""
    from ..clients.fortiweb import FortiWebClient
    if is_api(ep) and not safe_api(ep):
        return None
    try:
        client = client or FortiWebClient(appliance)
        resp = client.api_call("GET", rest_path(ep))
        if resp is None or resp.status_code >= 400:
            return None
        return unwrap(resp.json())
    except Exception:  # noqa: BLE001 -- unreachable: drawn as unknown, said so
        return None


#: How an object is sent: ``{"data": {...}}`` (cmdb, Admin Settings) or bare
#: (the log settings forms). An endpoint answers 200 to the other shape and
#: changes nothing -- the layout carries the shape the GUI was measured using.
BODIES = ("data", "bare")


def body_of(obj: dict, shape: str | None):
    return obj if shape == "bare" else {"data": obj}


def bound_endpoints(dialog: dict) -> dict:
    """{endpoint: {"method", "body"}} of the dialog's fields bound elsewhere."""
    out: dict = {}
    for b in dialog.get("blocks") or []:
        for f in b.get("fields") or []:
            bd = f.get("bind")
            if bd and bd.get("endpoint") and not is_subtable(bd["endpoint"]):
                out.setdefault(bd["endpoint"], {"method": bd.get("method") or "PUT",
                                                "body": bd.get("body") or "data"})
    return out


def prepare(tpl: dict, key: str, row: dict | None, appliance, *, read_device: bool = True,
            client=None):
    """(template, row, groups) ready for ``gui_template.dialog_view``:

    * fields bound elsewhere carry the composite key ``@<endpoint>#<key>`` and
      the row their value, read from that endpoint;
    * nested keys of the row are reachable by path (``passwordPolicy.min-length``);
    * ``groups`` {endpoint: method} -- where Save sends the bound fields.

    The template is copied; the caller's is never changed."""
    d0 = (tpl.get("dialogs") or {}).get(key)
    row2 = dict(row or {})
    for k, v in flatten(row or {}).items():
        row2.setdefault(k, v)
    if not d0:
        return tpl, row2, {}
    groups = bound_endpoints(d0)
    if not any(f.get("bind") for b in d0.get("blocks") or [] for f in b.get("fields") or []):
        return tpl, row2, {}
    t2 = dict(tpl)
    t2["dialogs"] = dict(tpl["dialogs"])
    d = copy.deepcopy(d0)
    t2["dialogs"][key] = d
    objs: dict = {}
    for ep in groups:
        if not read_device:
            objs[ep] = None
            continue
        if is_api(ep):
            objs[ep] = read(appliance, ep, client=client)
        else:
            from . import gui_pages
            rows, _m = gui_pages.rows(appliance.id, ep)
            objs[ep] = rows[0] if rows else read(appliance, ep, client=client)
    for b in d["blocks"]:
        for f in b["fields"]:
            bd = f.get("bind")
            if not bd:
                continue
            if is_subtable(bd["endpoint"]):
                # a sub-table row needs its parent's key, which this field
                # does not have: shown, never written (the harvester does not
                # emit such a bind; a layout from elsewhere might)
                f["kind"], f["bound_unread"] = "display", True
                continue
            ck = bound_key(bd["endpoint"], bd["key"])
            obj = objs.get(bd["endpoint"])
            f["key"] = ck
            f["bound_to"] = bd["endpoint"]
            if obj is None:
                f["bound_unread"] = True
            else:
                row2[ck] = get_path(obj, bd["key"])
    return t2, row2, groups


def merged(current: dict, fields: dict) -> dict:
    """The object Save sends to a GUI API endpoint: the current one with the
    changed key paths set (types kept), its bookkeeping (``q_*``, ``can_*``)
    left as the device served it -- the GUI sends the whole object back."""
    out = copy.deepcopy(current or {})
    for k, v in (fields or {}).items():
        set_path(out, k, v)
    return out


def changes(current: dict, new: dict) -> list:
    """[{key, was, now}] between two objects, by key path."""
    a, b = flatten(current or {}), flatten(new or {})
    out = []
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            out.append({"key": k, "was": a.get(k), "now": b.get(k)})
    return out


def dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True)
