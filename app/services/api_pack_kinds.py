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
