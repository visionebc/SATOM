"""API pack item kinds added in 3.0 (docs/api-library.md §12, contract C3).

Each kind has three functions, called by ``api_pack``:

* ``validate_<kind>(run, item)`` -> payload, or ``ItemInvalid`` with the reason
  (the item is rejected, the rest of the pack still imports);
* ``state_<kind>(run, item, payload)`` -> what importing it would do
  (``new`` / ``update`` / ``present`` / ``local``), writing nothing;
* ``import_<kind>(run, item, payload, state)`` -> what it wrote.

Every row written carries the pack's provenance (``pack:<lane>:<pack>``) in
the column the target already has for "who wrote this" (``captured_from``,
``origin``, ``promoted_by``). C6 holds for every kind: a row this node wrote
itself is never replaced, a pack row is replaced only by a pack that outranks
it (``api_pack.outranks``).
"""
from __future__ import annotations

import base64
import binascii
import gzip
import io
import json
import re
from datetime import datetime

from ..extensions import db
from . import firmware_versions as fv
from .api_pack import (PROV_PREFIX, ST_LOCAL, ST_NEW, ST_PRESENT, ST_UPDATE, ItemInvalid,
                       _product_of, _rollup, outranks)

#: A decompressed factory payload larger than this is refused (a predefined
#: profile tree is a few hundred KB).
MAX_FACTORY_PAYLOAD = 64 * 1024 * 1024

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,160}$")
_SIG_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")


def _is_pack(origin: str) -> bool:
    return str(origin or "").startswith(PROV_PREFIX)


def _str(data: dict, key: str, *, required: bool = True, limit: int = 255) -> str:
    v = data.get(key)
    if v is None and not required:
        return ""
    if isinstance(v, int) and not isinstance(v, bool):
        v = str(v)
    if not isinstance(v, str) or (required and not v.strip()):
        raise ItemInvalid("%r must be a non-empty string" % key)
    if len(v) > limit:
        raise ItemInvalid("%r is longer than %d characters" % (key, limit))
    return v.strip()


def _payload(run, item) -> dict:
    data = run.read(item)
    if not isinstance(data, dict):
        raise ItemInvalid("payload is not an object")
    return data


def _version(data: dict, key: str) -> str:
    v = fv.normalize(_str(data, key, limit=64))
    if not v:
        raise ItemInvalid("%r %r is not a firmware version" % (key, data.get(key)))
    return v


# ---------------------------------------------------------------------------
# factory-wpp -> factory_catalog
# ---------------------------------------------------------------------------

def _build_no(value) -> str:
    """``116`` from ``0116`` / ``build0116`` / ``116`` / ``""`` (the catalog's
    own spelling: ``factory_catalog.build_no_of``)."""
    s = str(value if value is not None else "").strip()
    s = re.sub(r"(?i)^build\s*", "", s)
    if s and not s.isdigit():
        raise ItemInvalid("build %r is not a build number" % (value,))
    return s.lstrip("0") or ("0" if s else "")


def validate_factory(run, item) -> dict:
    from . import factory_catalog as fc
    data = _payload(run, item)
    product = _product_of(item, data)
    firmware = _version(data, "firmware")
    if fv.is_line_only(firmware):
        raise ItemInvalid("firmware %r is a line, not a build" % firmware)
    kind = data.get("kind")
    if kind not in (fc.KIND_INLINE, fc.KIND_OFFLINE):
        raise ItemInvalid("kind %r is not %s or %s" % (kind, fc.KIND_INLINE, fc.KIND_OFFLINE))
    name = _str(data, "name")
    sha = _str(data, "content_sha", limit=64)
    if not _SHA_RE.match(sha):
        raise ItemInvalid("content_sha is not a sha256")
    try:
        # base64 of the EXACT bytes the catalog stores (gzip JSON); stored as is
        raw = base64.b64decode(_str(data, "payload_b64gz", limit=1 << 30), validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            blob = gz.read(MAX_FACTORY_PAYLOAD + 1)
        if len(blob) > MAX_FACTORY_PAYLOAD:
            raise ItemInvalid("payload larger than %d MB" % (MAX_FACTORY_PAYLOAD >> 20))
        body = json.loads(blob.decode("utf-8"))
    except (binascii.Error, OSError, EOFError, ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, ItemInvalid):
            raise
        raise ItemInvalid("payload_b64gz is not base64(gzip(JSON)) (%s)" % exc)
    if not isinstance(body, dict) or not isinstance(body.get("tree"), (dict, list)) \
            or not isinstance(body.get("top"), list) or not isinstance(body.get("reads"), list):
        raise ItemInvalid("payload must be {tree, top, reads} as the factory catalog stores it")
    if not all(isinstance(r, list) and len(r) == 4 for r in body["reads"]):
        raise ItemInvalid("payload reads must be [kind, urn, key, answer] rows")
    try:
        got = fc.sha(body["tree"])
    except Exception as exc:  # noqa: BLE001 — a tree the normaliser cannot read
        raise ItemInvalid("payload tree cannot be hashed (%s)" % exc)
    if got != sha:
        raise ItemInvalid("content_sha does not match the payload tree (%s...)" % got[:12])
    top_sha = fc.sha(body["top"])
    if data.get("top_sha") not in (None, "", top_sha):
        raise ItemInvalid("top_sha does not match the payload top rows")
    captured = None
    if data.get("captured_at"):
        try:
            captured = datetime.fromisoformat(str(data["captured_at"]).replace("Z", "")[:19])
        except ValueError:
            raise ItemInvalid("captured_at %r is not an ISO timestamp" % data["captured_at"])
    for k in ("node_count", "read_count"):
        if data.get(k) is not None and (isinstance(data[k], bool) or not isinstance(data[k], int)
                                        or data[k] < 0):
            raise ItemInvalid("%s must be a non-negative integer" % k)
    return {"product": product, "firmware": firmware, "build_no": _build_no(data.get("build")),
            "api_version": _str(data, "api_version", required=False, limit=16),
            "kind": kind, "name": name[:255], "content_sha": sha, "top_sha": top_sha,
            "urn": _str(data, "urn", required=False), "body": body, "blob": raw,
            "node_count": data.get("node_count"), "read_count": data.get("read_count"),
            "captured_at": captured,
            "witness": _str(data, "witness", required=False, limit=128)}


def _factory_rows(p: dict) -> list:
    from ..models_factory import FactoryObject as FO
    return FO.query.filter_by(product=p["product"], firmware=p["firmware"],
                              build_no=p["build_no"], api_version=p["api_version"],
                              kind=p["kind"], name=p["name"]).all()


def state_factory(run, item, p: dict) -> dict:
    rows = _factory_rows(p)
    same = [r for r in rows if r.content_sha == p["content_sha"]]
    if same:
        return {"state": ST_PRESENT,
                "current": same[0].captured_from if _is_pack(same[0].captured_from) else "local"}
    if any(not _is_pack(r.captured_from) for r in rows):
        return {"state": ST_LOCAL, "current": "local",
                "note": "captured on this node; a pack never replaces it"}
    if not rows:
        return {"state": ST_NEW}
    for r in rows:
        ok, why = outranks(run.meta, r.captured_from)
        if not ok:
            return {"state": ST_PRESENT, "current": r.captured_from, "note": why}
    return {"state": ST_UPDATE, "current": rows[0].captured_from}


def import_factory(run, item, p: dict, st: dict) -> dict:
    from . import factory_catalog as fc
    from ..models_factory import FactoryObject as FO
    replaced = 0
    if st["state"] == ST_UPDATE:
        for r in _factory_rows(p):
            if _is_pack(r.captured_from):
                db.session.delete(r)
                replaced += 1
        db.session.flush()
    body = p["body"]
    # Verified "as of" the capture on the lab box (else the snapshot): fresh ->
    # replayed within the reverify window; older -> the next sweep reads it
    # in full once and confirms it.
    when = p["captured_at"] or run.built_at
    row = FO(product=p["product"], firmware=p["firmware"], build_no=p["build_no"],
             api_version=p["api_version"], kind=p["kind"], name=p["name"], urn=p["urn"],
             content_sha=p["content_sha"], top_sha=p["top_sha"], payload=p["blob"],
             node_count=p["node_count"] if p["node_count"] is not None
             else fc.count_nodes(body["tree"]),
             read_count=p["read_count"] if p["read_count"] is not None else len(body["reads"]),
             captured_from_id=None, captured_from=run.provenance[:128],
             captured_at=when, last_verified_at=when,
             last_verified_from=(p["witness"] or run.provenance)[:128], verify_count=1,
             status=FO.STATUS_OK)
    db.session.add(row)
    db.session.commit()
    return {"factory_id": row.id, "replaced": replaced}


# ---------------------------------------------------------------------------
# field-map -> api_lib_field_map (status candidate)
# ---------------------------------------------------------------------------

def validate_field_map(run, item) -> dict:
    data = _payload(run, item)
    product = _product_of(item, data)
    endpoint = _str(data, "endpoint", limit=160)
    if not _NAME_RE.match(endpoint.replace("/", "_")):
        raise ItemInvalid("endpoint %r is not a name" % endpoint)
    frm, to = _version(data, "from_build"), _version(data, "to_build")
    renames = data.get("renames")
    if not isinstance(renames, list) or not renames:
        raise ItemInvalid("'renames' must be a non-empty list")
    good, bad = [], 0
    for r in renames:
        if not isinstance(r, dict):
            bad += 1
            continue
        old, new = r.get("old"), r.get("new")
        conf, cli_id = r.get("confidence"), r.get("cli_id")
        if not (isinstance(old, str) and isinstance(new, str) and _NAME_RE.match(old)
                and _NAME_RE.match(new) and old != new) \
                or (conf is not None and (isinstance(conf, bool)
                                          or not isinstance(conf, (int, float))
                                          or not 0 <= conf <= 1)) \
                or (cli_id is not None and (isinstance(cli_id, bool)
                                            or not isinstance(cli_id, int))):
            bad += 1
            continue
        good.append({"old": old, "new": new, "confidence": conf, "cli_id": cli_id})
    if not good:
        raise ItemInvalid("no valid rename (old, new names; confidence 0..1; cli_id int)")
    return {"product": product, "endpoint": endpoint, "from": frm, "to": to,
            "renames": good, "bad": bad}


def _map_rows(p: dict, old: str) -> list:
    from ..models_apilib import ApiLibFieldMap as FM
    return FM.query.filter_by(product=p["product"], endpoint=p["endpoint"],
                              from_version=p["from"], to_version=p["to"],
                              from_field=old).all()


def _map_state(run, p: dict, r: dict) -> tuple:
    rows = _map_rows(p, r["old"])
    if any(not _is_pack(m.origin) for m in rows):
        return ST_LOCAL, None
    live = [m for m in rows if m.retired_at is None]
    if any(m.to_field == r["new"] for m in live):
        return ST_PRESENT, None
    if not live:
        return ST_NEW, None
    for m in live:
        ok, why = outranks(run.meta, m.origin)
        if not ok:
            return ST_PRESENT, why
    return ST_UPDATE, None


def state_field_map(run, item, p: dict) -> dict:
    states, notes = {}, {}
    for r in p["renames"]:
        st, why = _map_state(run, p, r)
        states["%s->%s" % (r["old"], r["new"])] = st
        if why:
            notes[r["old"]] = why
    out = _rollup(states, {"endpoint": p["endpoint"], "from_build": p["from"],
                           "to_build": p["to"], "renames": len(p["renames"])})
    if p["bad"]:
        out["warning"] = "%d malformed rename(s) skipped" % p["bad"]
    if out["local_units"]:
        out.setdefault("note", "%d rename(s) kept: an operator mapping exists"
                       % len(out["local_units"]))
    if notes:
        out["notes"] = notes
        out["note"] = "; ".join(sorted(set(notes.values())))[:300]
    return out


def import_field_map(run, item, p: dict, st: dict) -> dict:
    from ..models_apilib import ApiLibFieldMap as FM
    now = datetime.utcnow()
    added, retired = 0, 0
    for r in p["renames"]:
        state, _why = _map_state(run, p, r)
        if state not in (ST_NEW, ST_UPDATE):
            continue
        if state == ST_UPDATE:
            for m in _map_rows(p, r["old"]):
                if m.retired_at is None and _is_pack(m.origin):
                    m.retired_at = now
                    m.retired_by = run.provenance[:64]
                    retired += 1
        bits = ["proposed by %s" % run.provenance]
        if r["cli_id"] is not None:
            bits.append("cli_id %s" % r["cli_id"])
        if r["confidence"] is not None:
            bits.append("confidence %.2f" % r["confidence"])
        db.session.add(FM(product=p["product"], endpoint=p["endpoint"],
                          from_version=p["from"], from_field=r["old"],
                          to_version=p["to"], to_field=r["new"],
                          note="; ".join(bits)[:500], created_by=run.provenance[:64],
                          created_at=now, status=FM.STATUS_CANDIDATE,
                          origin=run.provenance[:128]))
        added += 1
    db.session.commit()
    return {"candidates": added, "retired": retired}


# ---------------------------------------------------------------------------
# baseline -> api_lib_baseline (method "pack", never active)
# ---------------------------------------------------------------------------

def _names_by_urn(product: str) -> dict:
    """``{urn: [registry name...]}`` from this node's registry and the shipped
    baseline artifact, keyed by the URN and by its canonical path too."""
    from . import api_baseline as ab
    from . import api_library as lib
    from ..models import RegistryEndpoint
    pairs = set(ab.artifact_map(product).items())
    pairs |= {(r.name, r.urn) for r in RegistryEndpoint.query.filter_by(product=product).all()}
    out: dict = {}
    for name, urn in pairs:
        for k in {urn, lib.urn_key(urn)}:
            if k:
                out.setdefault(k, set()).add(name)
    return out


def _baseline_entries(data: dict, version: str, product: str) -> tuple:
    from . import api_baseline as ab
    from . import api_library as lib
    raw, bad = [], 0
    if isinstance(data.get("entries"), list):
        raw = data["entries"]
    elif isinstance(data.get("endpoints"), dict):
        # Harvester spelling: {rest_path: {method, urn, fields}}. A REST path
        # is not a registry name: each one is mapped to the registry name(s)
        # serving the same URN; a path no name serves is skipped and counted.
        names = _names_by_urn(product)
        for k, v in data["endpoints"].items():
            v = v if isinstance(v, dict) else {}
            urn = v.get("urn") or (k if str(k).startswith("/") else "")
            if not isinstance(urn, str) or not urn:
                bad += 1
                continue
            if v.get("name"):
                raw.append({"name": v["name"], "urn": urn})
                continue
            hits = names.get(urn) or names.get(lib.urn_key(urn)) or set()
            if not hits:
                bad += 1
            raw += [{"name": n, "urn": urn} for n in sorted(hits)]
    else:
        raise ItemInvalid("baseline needs 'entries' (list) or 'endpoints' (object)")
    out, seen = [], set()
    for e in raw:
        if not isinstance(e, dict):
            bad += 1
            continue
        name, urn = e.get("name"), e.get("urn")
        prov = e.get("provenance") or ab.PROV_MEASURED
        if not (isinstance(name, str) and name and "/" not in name and len(name) <= 160
                and isinstance(urn, str) and urn.startswith("/") and len(urn) <= 255
                and prov in ab.PROVENANCES) or name in seen:
            bad += 1
            continue
        seen.add(name)
        out.append({"name": name, "urn": urn, "provenance": prov,
                    "measured_on": str(e.get("measured_on") or version)[:32]})
    return sorted(out, key=lambda e: e["name"]), bad


def validate_baseline(run, item) -> dict:
    from . import api_baseline as ab
    data = _payload(run, item)
    product = _product_of(item, data)
    if product not in ab.products():
        raise ItemInvalid("%s has no endpoint registry, so no baseline" % product)
    version = _version(data, "build")
    entries, bad = _baseline_entries(data, version, product)
    if not entries:
        raise ItemInvalid("no valid baseline entry ({name, urn}; name without '/', "
                          "urn starting with '/')")
    api_version = _str(data, "api_version", required=False, limit=16) \
        or ab.api_version_of(product)
    return {"product": product, "version": version, "api_version": api_version,
            "entries": entries, "bad": bad,
            "sha256": ab.seal(product, version, api_version, entries)}


def _baseline_rows(p: dict) -> list:
    from ..models_apilib import ApiLibBaseline
    return ApiLibBaseline.query.filter_by(product=p["product"], version=p["version"]).all()


def state_baseline(run, item, p: dict) -> dict:
    from . import api_baseline as ab
    rows = _baseline_rows(p)
    out = {"build": p["version"], "entries": len(p["entries"])}
    if p["bad"]:
        out["warning"] = ("%d baseline entr(ies) skipped (malformed, or a REST path no "
                          "registry name serves)" % p["bad"])
    if any(r.method != ab.METHOD_PACK for r in rows):
        return dict(out, state=ST_LOCAL, current="local",
                    note="this node has its own baseline for %s" % p["version"])
    if any(r.sha256 == p["sha256"] for r in rows):
        return dict(out, state=ST_PRESENT, current=rows[0].promoted_by)
    if not rows:
        return dict(out, state=ST_NEW)
    for r in rows:
        ok, why = outranks(run.meta, r.promoted_by)
        if not ok:
            return dict(out, state=ST_PRESENT, current=r.promoted_by, note=why)
    return dict(out, state=ST_UPDATE, current=rows[0].promoted_by)


def import_baseline(run, item, p: dict, st: dict) -> dict:
    from . import api_baseline as ab
    from ..models_apilib import ApiLibBaselineEntry
    replaced = 0
    if st["state"] == ST_UPDATE:
        for r in _baseline_rows(p):
            if r.method == ab.METHOD_PACK:
                ApiLibBaselineEntry.query.filter_by(baseline_id=r.id).delete()
                db.session.delete(r)
                replaced += 1
        db.session.flush()
    row, created = ab._store(p["product"], p["version"], p["api_version"], p["entries"],
                             method=ab.METHOD_PACK, actor=run.provenance,
                             note="imported from %s; reference only, never active"
                                  % run.provenance,
                             promoted_at=run.built_at)
    db.session.commit()
    return {"baseline_id": row.id, "created": created, "replaced": replaced}


# ---------------------------------------------------------------------------
# signature-meta -> knowledge_signature_meta
# ---------------------------------------------------------------------------

def _str_list(v, limit: int = 200) -> list:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError("not a list of strings")
    return [x.strip()[:512] for x in v if x.strip()][:limit]


def _sig_entry(v) -> dict:
    if not isinstance(v, dict):
        raise ValueError("not an object")
    out = {}
    for k, limit in (("name", 255), ("severity", 32), ("category", 128), ("url", 512)):
        x = v.get(k, "")
        if x is None:
            x = ""
        if not isinstance(x, str):
            raise ValueError("%s is not a string" % k)
        out[k] = x.strip()[:limit]
    if out["url"] and not re.match(r"^https?://", out["url"]):
        raise ValueError("url is not http(s)")
    s = v.get("summary", "") or ""
    if not isinstance(s, str):
        raise ValueError("summary is not a string")
    out["summary"] = s.strip()[:8000]
    out["cve"] = _str_list(v.get("cve"))
    out["references"] = _str_list(v.get("references"))
    return out


def validate_sigmeta(run, item) -> dict:
    data = _payload(run, item)
    product = _product_of(item, data)
    sigs = data.get("signatures")
    if not isinstance(sigs, dict) or not sigs:
        raise ItemInvalid("'signatures' must be a non-empty object {id: {...}}")
    good, bad = {}, 0
    for sid, v in sigs.items():
        sid = str(sid).strip()
        try:
            if not _SIG_ID_RE.match(sid):
                raise ValueError("bad id")
            good[sid] = _sig_entry(v)
        except ValueError:
            bad += 1
    if not good:
        raise ItemInvalid("no valid signature entry")
    return {"product": product, "db_version": str(data.get("db_version") or "")[:64],
            "signatures": good, "bad": bad}


_SIG_COLS = ("name", "severity", "category", "url", "summary", "cve", "references")


def _sig_rows(p: dict) -> dict:
    from ..models_knowledge import KnowledgeSignatureMeta as KS
    return {r.sig_id: r for r in KS.query.filter_by(product=p["product"]).all()}


def _sig_state(run, row, entry) -> tuple:
    if row is None:
        return ST_NEW, ""
    if all((getattr(row, c) or ([] if c in ("cve", "references") else "")) == entry[c]
           for c in _SIG_COLS):
        return ST_PRESENT, ""
    if not _is_pack(row.origin):
        return ST_LOCAL, ""
    ok, why = outranks(run.meta, row.origin)
    return (ST_UPDATE, "") if ok else (ST_PRESENT, why)


def state_sigmeta(run, item, p: dict) -> dict:
    rows = _sig_rows(p)
    states = {sid: _sig_state(run, rows.get(sid), e)[0] for sid, e in p["signatures"].items()}
    out = _rollup(states, {"db_version": p["db_version"], "signatures": len(states)})
    # thousands of ids: keep counts, not lists, in what inspect shows
    for k in ("new", "update", "local", "present"):
        out["%s_count" % k] = len(out["%s_units" % k])
    out.pop("update_units", None)
    out["update_units"] = []
    if p["bad"]:
        out["warning"] = "%d malformed signature entr(ies) skipped" % p["bad"]
    return out


def import_sigmeta(run, item, p: dict, st: dict) -> dict:
    from ..models_knowledge import KnowledgeSignatureMeta as KS
    rows = _sig_rows(p)
    now = datetime.utcnow()
    added = updated = 0
    for sid, e in p["signatures"].items():
        row = rows.get(sid)
        state, _why = _sig_state(run, row, e)
        if state == ST_NEW:
            db.session.add(KS(product=p["product"], sig_id=sid, origin=run.provenance[:128],
                              imported_at=now, **e))
            added += 1
        elif state == ST_UPDATE:
            for c in _SIG_COLS:
                setattr(row, c, e[c])
            row.origin = run.provenance[:128]
            row.imported_at = now
            updated += 1
    db.session.commit()
    return {"added": added, "updated": updated}


# ---------------------------------------------------------------------------
# gui-template -> data/gui-templates/<product>/<page>/<version>-<build>.json
# ---------------------------------------------------------------------------

#: Code from a GUI bundle never enters a node (texts may: Fortinet's labels and
#: help are part of the template by decision of 2026-10-08).
_GUI_CODE_RX = re.compile(r"function\s*\(|=>\s*\{|<\s*/?\s*(div|span|script|form|input|f-[a-z-]+)\b"
                          r"|\bng-(if|model|click|show|hide|repeat|class)\b|\$ctrl\.|\$scope\.")
MAX_GUI_PAYLOAD = 8 * 1024 * 1024


def _gui_code(node, path="") -> str:
    if isinstance(node, dict):
        for k, v in node.items():
            hit = _gui_code(v, "%s/%s" % (path, k))
            if hit:
                return hit
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hit = _gui_code(v, "%s/%d" % (path, i))
            if hit:
                return hit
    elif isinstance(node, str) and _GUI_CODE_RX.search(node):
        return "%s: %s" % (path, node[:60])
    return ""


def _gui_endpoints(data: dict) -> list:
    """``(role, endpoint)`` of every endpoint a layout names (gui_products
    READ / WRITE / GUI_WRITE). Measured on the 8.0.1 build245 FortiGate and
    8.0.3 build99 FortiAuthenticator crawls: the page, its views (and a FAC
    view's ``also_endpoints``), dialogs and table fields are read; a dialog's
    ``write`` / ``writes`` and a field's ``bind`` are written; a FAC dialog's
    ``gui_writes`` are the form posts the crawl observed."""
    from .gui_products import GUI_WRITE, READ, WRITE
    out = [(READ, data.get("endpoint"))]
    for v in data.get("views") or []:
        out.append((READ, v.get("endpoint")))
        out.extend((READ, e) for e in v.get("also_endpoints") or [])
    for d in (data.get("dialogs") or {}).values():
        out.append((READ, d.get("endpoint")))
        out.append((WRITE, (d.get("write") or {}).get("endpoint")))
        out.extend((WRITE, w.get("endpoint")) for w in d.get("writes") or [])
        out.extend((GUI_WRITE, w.get("endpoint")) for w in d.get("gui_writes") or [])
        for b in d.get("blocks") or []:
            for f in b.get("fields") or []:
                out.append((READ, f.get("endpoint")))
                out.append((WRITE, (f.get("bind") or {}).get("endpoint")))
    return out


def _gui_unsafe_endpoint(data: dict, product: str | None = None) -> str:
    """The first endpoint a layout may not name, "" when none.

    FortiWeb: a GUI API endpoint (``api:...``) that is not a configuration
    object (gui_bound.safe_api); its cmdb paths are its own. FortiGate and
    FortiAuthenticator: every endpoint follows its product's grammar and names
    no device action (gui_products.unsafe_endpoint); the answer is
    ``<endpoint> (<role>: <why>)``."""
    from . import gui_bound, gui_products
    product = product or data.get("product") or gui_products.FORTIWEB
    for role, ep in _gui_endpoints(data):
        if product == gui_products.FORTIWEB:
            if isinstance(ep, str) and gui_bound.is_api(ep) and not gui_bound.safe_api(ep):
                return ep
            continue
        why = gui_products.unsafe_endpoint(product, ep, role)
        if why:
            return "%s (%s: %s)" % (ep, role, why)
    return ""


def _gui_action(product: str, role: str, ep) -> bool:
    """Whether ``ep`` at ``role`` is refused because it names an ACTION (a
    reboot, a backup sent off the device, an authentication), as opposed to
    breaking the product's grammar (``../``, an unknown prefix): an action is
    pruned out of a page, a grammar break refuses the page."""
    from . import gui_bound, gui_products
    if product == gui_products.FORTIWEB:
        return isinstance(ep, str) and gui_bound.is_api(ep) and not gui_bound.safe_api(ep)
    return "action" in gui_products.unsafe_endpoint(product, ep, role)


def _gui_prune(data: dict, product: str):
    """``(layout, dropped)``: the layout without the dialogs and views that
    name an action endpoint, or ``(data, None)`` when nothing usable is left.

    One tab of a page may be an action while the rest is configuration
    (FortiADC 7.6.7 System > Settings: Basic, System Time, Services and Sync
    List, plus Backup & Restore on ``system_auto_backup``, which ships the
    configuration off the device). The whole dialog goes -- never one field of
    it -- and so does every view that opens it or reads an action. No view
    left refuses the page (FAC Scheduled Backups: its one list opens the
    dialog that posts the backup); the page's own endpoint is never cut, so
    the caller's second check refuses a page that is itself an action."""
    import copy
    from .gui_products import GUI_WRITE, READ, WRITE

    def act(role, ep):
        return _gui_action(product, role, ep)
    out, dropped = copy.deepcopy(data), []
    dialogs = out.get("dialogs") if isinstance(out.get("dialogs"), dict) else {}
    for key, d in list(dialogs.items()):
        if not isinstance(d, dict):
            continue
        eps = [(READ, d.get("endpoint")), (WRITE, (d.get("write") or {}).get("endpoint"))]
        eps += [(WRITE, w.get("endpoint")) for w in d.get("writes") or []]
        eps += [(GUI_WRITE, w.get("endpoint")) for w in d.get("gui_writes") or []]
        for b in d.get("blocks") or []:
            for f in (b.get("fields") or []) if isinstance(b, dict) else []:
                eps += [(READ, f.get("endpoint")), (WRITE, (f.get("bind") or {}).get("endpoint"))]
        if any(act(r, e) for r, e in eps):
            del dialogs[key]
            dropped.append("dialog %s" % key)
    gone = {x.split(" ", 1)[1] for x in dropped}
    keep = []
    for i, v in enumerate(out.get("views") or []):
        refs = {x.get("dialog") if isinstance(x, dict) else x
                for k in ("dialogs", "create_menu") for x in v.get(k) or []}
        # a view that opened a dropped dialog goes too: its list would still
        # offer Clone / Delete on the collection whose write was the action
        if (act(READ, v.get("endpoint")) or refs & gone
                or any(act(READ, e) for e in v.get("also_endpoints") or [])):
            dropped.append("view %d %s" % (i, v.get("label") or v.get("endpoint")))
            continue
        keep.append(v)
    if out.get("views") and not keep:
        return data, None
    if "views" in out:
        out["views"] = keep
    return out, dropped


def validate_gui(run, item) -> dict:
    """A ``satom.gui-template/2`` page layout of one exact build. The importer
    does not assume who measured it (decision 4: a customer-run harvester may
    publish templates too) — it checks the shape, the identity and that no
    bundle code rides along."""
    from ..vendor import satom_guikit as guikit
    from . import gui_products, gui_store
    data = _payload(run, item)
    if data.get("schema") != guikit.SCHEMA_V2:
        raise ItemInvalid("schema %r is not %s" % (data.get("schema"), guikit.SCHEMA_V2))
    if len(json.dumps(data)) > MAX_GUI_PAYLOAD:
        raise ItemInvalid("template larger than %d bytes" % MAX_GUI_PAYLOAD)
    ident = guikit.identity(data)
    product = _product_of(item, data)
    if product != ident["product"]:
        raise ItemInvalid("item product %r but template product %r" % (product, ident["product"]))
    if product not in gui_products.PRODUCTS:
        # no endpoint grammar to check its layout against: refused, not filed
        raise ItemInvalid("no GUI engine for product %r" % product)
    version = fv.normalize(ident["version"])
    if not version or version != ident["version"] or not ident["build"].isdigit():
        raise ItemInvalid("template does not name an exact build (%r build %r)"
                          % (ident["version"], ident["build"]))
    try:
        path = gui_store.file_for(product, ident["page"], version, ident["build"])
    except ValueError as exc:
        raise ItemInvalid(str(exc))
    hit = _gui_code(data)
    if hit:
        raise ItemInvalid("template carries GUI bundle code (%s)" % hit)
    pruned = []
    bad = _gui_unsafe_endpoint(data, product)
    if bad:
        # an action tab is cut out and the rest of the page imports; what is
        # left is checked again, and a grammar break still refuses the page
        trimmed, dropped = _gui_prune(data, product)
        if not dropped or _gui_unsafe_endpoint(trimmed, product):
            raise ItemInvalid("template names an endpoint SATOM never reads or writes (%s)" % bad)
        data, pruned = trimmed, dropped
    dialogs = data.get("dialogs")
    # a FortiGate / FortiAuthenticator page may be a list and nothing else
    # (FAC 8.0.3 build99: the SAML and system template editors, GUI-only lists)
    list_only = (product != gui_products.FORTIWEB and dialogs == {}
                 and isinstance(data.get("views"), list) and bool(data["views"]))
    if (not isinstance(dialogs, dict) or not (dialogs or list_only)
            or not isinstance(data.get("list"), dict)):
        raise ItemInvalid("template has no dialogs / list")
    return {"product": product, "page": ident["page"], "version": version,
            "build": ident["build"], "path": path, "template": data,
            "pruned": pruned, "pruned_for": bad if pruned else "",
            "sha256": guikit.content_hash(data) + ":" + _canon(data)}


def _canon(data: dict) -> str:
    import hashlib
    body = {k: v for k, v in data.items() if k != "_import"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def _gui_unit(p: dict) -> str:
    return "gui-template/%s/%s/%s-%s" % (p["product"], p["page"], p["version"], p["build"])


def _gui_current(p: dict):
    path = p["path"]
    if not path.is_file():
        return None
    try:
        cur = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unreadable"
    from ..vendor import satom_guikit as guikit
    cur = {k: v for k, v in cur.items() if k != "_import"}   # what this node added
    return guikit.content_hash(cur) + ":" + _canon(cur)


def state_gui(run, item, p: dict) -> dict:
    c = run.claim(_gui_unit(p), _gui_current(p), p["sha256"])
    out = dict(c, page=p["page"], build="%s build%s" % (p["version"], p["build"]),
               not_in_gui=len(p["template"].get("not_in_gui") or []))
    if p.get("pruned"):
        out["warning"] = ("imported without what names an action endpoint (%s): %s"
                          % (p["pruned_for"], ", ".join(p["pruned"])))
    return out


def import_gui(run, item, p: dict, st: dict) -> dict:
    from .api_pack import _write_json
    body = dict(p["template"])
    body["_import"] = {"provenance": run.provenance, "built_at": str(run.built_at)}
    if p.get("pruned"):
        body["_import"]["pruned"] = p["pruned"]
    replaced = p["path"].is_file()
    _write_json(p["path"], body)
    run.ledger.set(_gui_unit(p), run.provenance)
    return {"file": str(p["path"].name), "replaced": replaced}


# ---------------------------------------------------------------------------
# capacity-limits -> capacity_factory (models_capacity)
# ---------------------------------------------------------------------------

_CAP_SCOPES = ("GLOBAL", "VDOM", "INSTANCE")
_CAP_KEY_RE = re.compile(r"^[A-Za-z0-9 _.:\-]{1,128}$")
_CAP_PID_RE = re.compile(r"^(?:\*|[A-Z0-9]{1,32})$")
#: A published ceiling above this is a parsing accident, not a limit.
_CAP_MAX = 10_000_000
_CAP_OPS = ("<", "<=", ">", ">=")


def _cap_int(v) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= _CAP_MAX:
        raise ValueError("%r is not a count" % (v,))
    return v


def _cap_rule(r) -> dict:
    """A FortiWeb-VM rule, rebuilt from known keys only."""
    if not isinstance(r, dict):
        raise ValueError("vm rule is not an object")
    kind = r.get("rule")
    tiers = []
    for t in r.get("tiers") or []:
        if not isinstance(t, dict) or t.get("op") not in _CAP_OPS:
            raise ValueError("bad vm tier")
        tiers.append({"op": t["op"], "gb": _cap_int(t.get("gb")),
                      "value": _cap_int(t.get("value"))})
    if kind == "fixed":
        return {"rule": "fixed", "value": _cap_int(r.get("value"))}
    if kind == "tiers" and tiers:
        return {"rule": "tiers", "tiers": tiers}
    if kind == "linear":
        return {"rule": "linear", "base": _cap_int(r.get("base")),
                "per_gb": _cap_int(r.get("per_gb")), "from_gb": _cap_int(r.get("from_gb", 1)),
                "cap": _cap_int(r.get("cap")), "tiers": tiers}
    raise ValueError("unknown vm rule %r" % (kind,))


def _cap_object(o) -> dict:
    if not isinstance(o, dict) or o.get("scope") not in _CAP_SCOPES:
        raise ValueError("bad scope")
    values = {}
    for pid, v in (o.get("values") or {}).items():
        if not isinstance(pid, str) or not _CAP_PID_RE.match(pid):
            raise ValueError("bad model %r" % (pid,))
        values[pid] = _cap_int(v)
    out = {"scope": o["scope"], "values": values,
           "label": str(o.get("label") or "")[:128],
           "source": str(o.get("source") or "")[:32]}
    if o.get("vm") is not None:
        out["vm"] = _cap_rule(o["vm"])
    doubt = [d for d in (o.get("doubtful") or []) if isinstance(d, str) and _CAP_PID_RE.match(d)]
    if doubt:
        out["doubtful"] = sorted(set(doubt))
    if not values and "vm" not in out:
        raise ValueError("no value")
    return out


def validate_capacity(run, item) -> dict:
    """These numbers become caps that BLOCK creates: every value is re-checked
    here and a malformed table is dropped (counted), never half-read."""
    data = _payload(run, item)
    product = _product_of(item, data)
    firmware = _version(data, "firmware")
    if firmware.count(".") != 2:
        raise ItemInvalid("firmware %r is not an exact build" % firmware)
    objs = data.get("objects")
    if not isinstance(objs, dict) or not objs:
        raise ItemInvalid("'objects' must be a non-empty object {cli table: {...}}")
    good, bad = {}, 0
    for k, o in objs.items():
        try:
            if not isinstance(k, str) or not _CAP_KEY_RE.match(k):
                raise ValueError("bad table name")
            good[k] = _cap_object(o)
        except ValueError:
            bad += 1
    if not good:
        raise ItemInvalid("no valid capacity table")
    models = {str(k)[:32]: str(v)[:64] for k, v in (data.get("models") or {}).items()
              if isinstance(k, str) and _CAP_PID_RE.match(k)}
    sources = [{"kind": str(s.get("kind") or "")[:32], "url": str(s.get("url") or "")[:512]}
               for s in (data.get("sources") or []) if isinstance(s, dict)
               and re.match(r"^https?://", str(s.get("url") or ""))]
    warnings = [str(w)[:500] for w in (data.get("warnings") or []) if isinstance(w, str)][:200]
    doc = {"objects": good, "models": models, "sources": sources, "warnings": warnings}
    return {"product": product, "firmware": firmware, "document": doc, "bad": bad,
            "sha": _cap_sha(doc)}


def _cap_sha(doc: dict) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def _cap_row(p: dict):
    from ..models_capacity import CapacityFactory
    return CapacityFactory.query.filter_by(product=p["product"], firmware=p["firmware"]).first()


def _cap_state(run, row, p: dict) -> tuple:
    if row is None:
        return ST_NEW, ""
    if row.content_sha == p["sha"]:
        return ST_PRESENT, ""
    if not _is_pack(row.origin):
        return ST_LOCAL, ""
    ok, why = outranks(run.meta, row.origin)
    return (ST_UPDATE, "") if ok else (ST_PRESENT, why)


def state_capacity(run, item, p: dict) -> dict:
    state, why = _cap_state(run, _cap_row(p), p)
    out = _rollup({p["firmware"]: state}, {"tables": len(p["document"]["objects"])})
    if why:
        out["note"] = why
    if p["bad"]:
        out["warning"] = "%d malformed capacity table(s) skipped" % p["bad"]
    return out


def import_capacity(run, item, p: dict, st: dict) -> dict:
    from ..models_capacity import CapacityFactory
    row = _cap_row(p)
    state, _why = _cap_state(run, row, p)
    if state not in (ST_NEW, ST_UPDATE):
        return {"firmware": p["firmware"], "written": False}
    if row is None:
        row = CapacityFactory(product=p["product"], firmware=p["firmware"])
        db.session.add(row)
    row.document = p["document"]
    row.content_sha = p["sha"]
    row.origin = run.provenance[:128]
    row.imported_at = datetime.utcnow()
    db.session.commit()
    return {"firmware": p["firmware"], "written": True,
            "tables": len(p["document"]["objects"])}
