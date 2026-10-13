"""Schema harvest: one appliance's build, read through BOTH channels.

What it does for one appliance (:func:`harvest`):

1. **CLI schema** — SSH ``tree`` (the one schema command ``ssh_ops`` lets
   through, :func:`ssh_ops.assert_schema_command`) -> :func:`cli_schema.parse_tree`
   -> ``cli_tree`` evidence. The raw text is kept with the evidence row (a
   schema, not configuration).
2. **CLI names** — ``show full-configuration``: the newest usable vault dump
   of THIS appliance when it is fresh (younger than
   ``rediscovery.CLI_CAPTURE_MAX_AGE_H``) and taken on the SAME build,
   otherwise a fresh SSH capture (``backup.ssh_config_backup``, the vault's
   own reader). -> ``cli_full`` evidence: field NAMES only, hidden fields
   marked against the tree. The dump itself is never stored here: it is
   configuration, and the vault is where configuration lives.
3. **REST shape probe** — for the tree objects the library's REST evidence
   does not cover on this build (never asked, errored, or blind), one GET each
   classified by SHAPE (``rediscovery._probe_fortiweb``), ingested as
   sweep-like evidence keyed by the REST path. Values never leave the probe:
   only field names and JSON types (``api_library._fields_from_rows``), and a
   ``?mkey=`` that names a configured row is not recorded.

Read-only against the box: GETs and the three read commands; no ``config``.
FortiWeb is verified end to end; FortiADC's ``tree``, dump and CLI->REST rule
are verified on fortiadc10 7.6.7 (``schema_adapters.fortiadc``), and its REST
probe (:func:`_probe_rest_adc`) reads the tree objects the rediscovery sweep
does not: top-level objects and tables one table deep (``?pkey=``).
"""
from __future__ import annotations

import logging
from datetime import datetime

from . import api_library as lib
from . import cli_schema
from . import firmware_versions as fv

_log = logging.getLogger(__name__)

#: Products the harvester runs on. FortiADC: SSH session, ``tree`` and the
#: path rule verified on fortiadc10 7.6.7 (``cli_schema.PATH_RULE_STATUS``).
SUPPORTED = ("fortiweb", "fortiadc")
#: Products whose REST shape probe is implemented (the FortiWeb parent-fallback
#: rule is FortiWeb's; FortiADC reads through the sweep's own probe,
#: :func:`_probe_rest_adc`).
PROBED = ("fortiweb", "fortiadc")
PRODUCT_ADC = "fortiadc"
#: GETs one harvest may send for the shape probe (each probe of a nested path
#: may cost a second GET for the parent). Reported when reached, never silent.
DEFAULT_PROBE_BUDGET = 400
#: ``origin_ref`` prefix of every row a schema harvest writes. The probe's
#: sweep-like evidence is PARTIAL: ``apilib_harvest.needs_harvest`` and the
#: pack's "local measurement wins" rule must not take it for a full sweep.
ORIGIN_PREFIX = "schema_harvest:"

ACTION_KEY = "schema_harvest"


def _device(appliance) -> dict:
    return {"appliance_id": getattr(appliance, "id", None),
            "name": str(getattr(appliance, "name", "") or ""),
            "serial": str(getattr(appliance, "serial", "") or ""),
            "model": str(getattr(appliance, "model", "") or ""),
            "hw_type": str(getattr(appliance, "hw_type", "") or ""),
            "firmware_raw": str(getattr(appliance, "firmware", "") or "")}


def _fresh_vault_dump(appliance, version: str, now: datetime) -> tuple[str, dict | None]:
    """``(text, record)`` of a usable vault dump of THIS box on THIS build,
    younger than the capture budget; ``("", None)`` otherwise."""
    from . import cli_coverage, rediscovery
    rec = rediscovery._latest_usable_dump(appliance.id)
    if rec is None or (rec.get("version") or "") != version:
        return "", None
    age = rediscovery._dump_age_hours(rec, now)
    if age is None or age >= rediscovery.CLI_CAPTURE_MAX_AGE_H:
        return "", None
    text, rec2 = cli_coverage.read_dump(rec["backup_id"])
    return (text, rec2 or rec) if text else ("", None)


def _ssh_full(appliance) -> str:
    from .backup import ssh_config_backup
    return ssh_config_backup(appliance).decode("utf-8", "replace")


def _rest_candidates(product: str, version: str, tree_doc: dict) -> list:
    """Tree objects whose REST side this build's evidence does not cover.

    Never asked first (no REST evidence at all), then errored, then blind
    (answered, fields never revealed). Each: ``(key, urn, parent_key, fields)``.
    """
    view = lib.channels_at(product, version)
    eps = view["endpoints"]
    objects = (tree_doc.get("summary") or {}).get("objects") or {}
    out = []
    for key, info in tree_doc.get("endpoints", {}).items():
        ep = eps.get(key) or {}
        verdict = ep.get("rest_verdict")
        if verdict is None:
            rank = 0
        elif verdict == lib.VERDICT_ERROR:
            rank = 1
        elif verdict == lib.VERDICT_OK and not ep.get("rest_fields_known"):
            rank = 2
        else:
            continue
        meta = objects.get(key) or {}
        out.append((rank, key, info.get("urn") or "", meta.get("parent") or "",
                    sorted(info.get("fields") or {})))
    out.sort()
    return [t[1:] for t in out]


def _table_ancestors(objects: dict, parent_key: str) -> list:
    """The TABLE objects above an object, nearest first (``summary.objects``)."""
    out, seen = [], set()
    k = parent_key
    while k and k not in seen:
        seen.add(k)
        meta = objects.get(k) or {}
        if meta.get("kind") == cli_schema.KIND_TABLE:
            out.append(k)
        k = meta.get("parent") or ""
    return out


def _probe_rest(appliance, product: str, candidates: list, tree_doc: dict, *,
                client=None, budget: int = DEFAULT_PROBE_BUDGET) -> dict:
    """Shape-probe the candidates. ``{"endpoints", "skipped", "spent"}``.

    FortiADC goes through :func:`_probe_rest_adc` (``client`` is then a
    ``probe(entry) -> (rows, verdict, detail)`` callable)."""
    if product == "fortiadc":
        return _probe_rest_adc(appliance, candidates, tree_doc, probe=client, budget=budget)
    from urllib.parse import quote

    from ..clients.base import DeviceAuthError
    from . import rediscovery
    if client is None:
        from ..clients.fortiweb import FortiWebClient
        client = FortiWebClient(rediscovery._client_snapshot(appliance), timeout=20.0)
    objects = (tree_doc.get("summary") or {}).get("objects") or {}
    spent = 0
    first_row: dict = {}
    endpoints: dict = {}
    skipped: dict = {}

    def _skip(key, why):
        skipped.setdefault(why, []).append(key)

    def _parent_mkey(parent_key: str):
        """The key value of the parent table's first row, or None (empty)."""
        nonlocal spent
        if parent_key in first_row:
            return first_row[parent_key]
        pmeta = objects.get(parent_key) or {}
        value = None
        spent += 1
        resp = client.get(cli_schema.urn_for(product, parent_key))
        if resp.status_code == 200 and client._errcode(resp) is None:
            rows = client._results_list(resp.json())
            if rows and isinstance(rows[0], dict):
                r0 = rows[0]
                value = r0.get(pmeta.get("mkey") or "name", r0.get("name", r0.get("id")))
        first_row[parent_key] = value
        return value

    for key, urn, parent, fields in candidates:
        if spent >= budget:
            _skip(key, "budget")
            continue
        query = ""
        tables = _table_ancestors(objects, parent)
        if len(tables) > 1:
            _skip(key, "nested more than one table deep")
            continue
        if tables:
            mk = _parent_mkey(tables[0])
            if mk is None:
                _skip(key, "parent table empty: needs a row to probe")
                continue
            # The row's key is configuration: it rides in the request only and
            # is never recorded (the evidence keeps the bare URN).
            query = "?mkey=" + quote(str(mk), safe="")
        spent += 2 if parent else 1
        try:
            rows, verdict, detail = rediscovery._probe_fortiweb(
                client, {"urn": urn + query, "expected_fields": fields})
        except DeviceAuthError:
            raise
        except Exception as exc:  # noqa: BLE001 — one path, not the harvest
            rows, verdict, detail = [], lib.VERDICT_ERROR, "%s: %s" % (type(exc).__name__, exc)
        endpoints[key] = {
            "urn": urn, "section": key.split("/", 1)[0], "verdict": verdict,
            "rows": len(rows) if verdict == lib.VERDICT_OK else None,
            # Names and JSON types only; ``None`` (blind) for an empty table.
            "fields": lib._fields_from_rows(rows) if verdict == lib.VERDICT_OK else None,
        }
    return {"endpoints": endpoints, "spent": spent,
            "skipped": {k: sorted(v) for k, v in skipped.items()}}


def _probe_rest_adc(appliance, candidates: list, tree_doc: dict, *, probe=None,
                    budget: int = DEFAULT_PROBE_BUDGET) -> dict:
    """FortiADC's shape probe: one GET per candidate, READ-only.

    The reads and their verdicts are the rediscovery sweep's own
    (``adc_ops.make_probe``: HTTP 404 = absent, a negative payload = error).
    Measured on fortiadc10 7.6.7 (2026-10-14, 300 GETs):

    * a top-level object is ``GET /api/<key>``;
    * a table inside a table is ``GET /api/<parent>_child_<table>?pkey=<the
      mkey of a parent row>`` (the depth capture's read); the row's key rides
      in the request only, the evidence keeps the bare URN. A child answer
      whose field names are exactly the parent row's is the parent echoed:
      ``error``, never fields;
    * a table inside a singleton is ``GET /api/<singleton>_child_<table>``
      (21 of 23 answered; the two with rows carry the tree's fields);
    * a 404 at a CHILD path is NOT recorded: FortiADC serves some children only
      inside the parent row (``system_addrgrp_child_member`` answers 404 while
      the ``system_addrgrp`` row carries ``member-list``), so "absent" there
      would turn served fields into false "CLI only". Listed in ``skipped``.

    Not probed either (``skipped``): a path :func:`adc_ops.side_effect_path`
    names (FortiADC reboots and resets through GETs), a key that is not a REST
    path (the tree's ``(4508) integer`` entries), anything nested more than
    one table deep or under a singleton inside a table, a child of an empty
    table.
    """
    import re

    from ..clients.base import DeviceAuthError
    from . import adc_ops
    if probe is None:
        from . import rediscovery
        probe = adc_ops.make_probe(rediscovery._client_snapshot(appliance))
    objects = (tree_doc.get("summary") or {}).get("objects") or {}
    spent = 0
    first_row: dict = {}
    endpoints: dict = {}
    skipped: dict = {}

    def _skip(key, why):
        skipped.setdefault(why, []).append(key)

    def _read(urn: str, params=None):
        nonlocal spent
        spent += 1
        try:
            rows, verdict, detail = probe({"urn": urn, "params": params})
        except DeviceAuthError:
            raise
        except Exception as exc:  # noqa: BLE001 — one path, not the harvest
            return [], lib.VERDICT_ERROR, "%s: %s" % (type(exc).__name__, exc)
        if verdict != lib.VERDICT_OK:
            return [], verdict, detail
        return [r for r in rows or [] if isinstance(r, dict)], verdict, detail

    def _parent_row(parent_key: str):
        """``(mkey, field names)`` of the parent table's first row, or ``(None, ...)``."""
        if parent_key not in first_row:
            mk, names = None, frozenset()
            purn = cli_schema.urn_for(PRODUCT_ADC, parent_key)
            if not adc_ops.side_effect_path(purn):
                rows, verdict, _detail = _read(purn)
                if verdict == lib.VERDICT_OK and rows:
                    mk, names = rows[0].get("mkey"), frozenset(rows[0])
            first_row[parent_key] = (None if mk in (None, "") else mk, names)
        return first_row[parent_key]

    for key, urn, parent, _fields in candidates:
        if spent >= budget:
            _skip(key, "budget")
            continue
        if not re.fullmatch(r"[A-Za-z0-9_]+", key or ""):
            _skip(key, "not a REST path")
            continue
        urn = urn or cli_schema.urn_for(PRODUCT_ADC, key)
        if adc_ops.side_effect_path(urn):
            _skip(key, "a GET with side effects: never read")
            continue
        params, parent_names = None, frozenset()
        if parent:
            tables = _table_ancestors(objects, parent)
            if len(tables) > 1:
                _skip(key, "nested more than one table deep")
                continue
            if tables and tables != [parent]:
                _skip(key, "nested under a singleton inside a table")
                continue
            if tables:
                mk, parent_names = _parent_row(parent)
                if mk is None:
                    _skip(key, "parent table empty: needs a row to probe")
                    continue
                params = {"pkey": str(mk)}
        rows, verdict, _detail = _read(urn, params)
        if parent and verdict == lib.VERDICT_ABSENT:
            _skip(key, "404 at a child path: maybe served inside the parent row")
            continue
        if parent_names and rows and all(frozenset(r) == parent_names for r in rows):
            rows, verdict = [], lib.VERDICT_ERROR
        endpoints[key] = {
            "urn": urn, "section": key.split("_", 1)[0], "verdict": verdict,
            "rows": len(rows) if verdict == lib.VERDICT_OK else None,
            # Names and JSON types only; ``None`` (blind) for an empty table.
            "fields": lib._fields_from_rows(rows) if verdict == lib.VERDICT_OK else None,
        }
    return {"endpoints": endpoints, "spent": spent,
            "skipped": {k: sorted(v) for k, v in skipped.items()}}


def _probe_doc(product, version, build, device, probe: dict, captured: str) -> dict:
    eps = probe["endpoints"]
    errs = sum(1 for e in eps.values() if e["verdict"] == lib.VERDICT_ERROR)
    healthy, reason = True, ""
    if not eps:
        healthy, reason = False, "nothing was probed"
    elif errs / max(len(eps), 1) > lib.MAX_ERROR_RATIO:
        healthy, reason = False, ("%d/%d probes errored; the device is unhealthy, not "
                                  "the catalog" % (errs, len(eps)))
    return {"product": product, "source": lib.SOURCE_SWEEP, "captured_at": captured,
            "origin_ref": "%sprobe:%s@%s" % (ORIGIN_PREFIX, device.get("appliance_id"), version),
            "device": device, "scope": {"kind": "build", "version": version, "build": build},
            "healthy": healthy, "skip_reason": reason, "endpoints": eps,
            "summary": {"probe": "schema_harvest",
                        "skipped": {k: len(v) for k, v in probe["skipped"].items()}}}


def harvest(appliance, *, lab: bool = False, probe: bool = True,
            tree_reader=None, full_reader=None, rest_client=None,
            probe_budget: int = DEFAULT_PROBE_BUDGET, now: datetime | None = None) -> dict:
    """Harvest one appliance's build through both channels. NEVER raises.

    Returns ``{"ok", "msg", "product", "version", "tree", "full", "probe",
    "channels"}``; ``ok`` = a HEALTHY ``cli_tree`` row is stored for the build.
    ``lab=True`` records lab defaults (``cli_full`` + ``summary.lab``): only for
    a lab box whose rows were freshly created. ``tree_reader(appliance) ->
    (text, complete)``, ``full_reader(appliance) -> text`` and ``rest_client``
    are injectable (tests; default: SSH and the FortiWeb REST client).
    """
    now = now or datetime.utcnow()
    product = getattr(appliance, "kind", "") or ""
    name = getattr(appliance, "name", "") or "?"
    out = {"ok": False, "appliance": name, "product": product, "version": "",
           "tree": None, "full": None, "probe": None, "channels": None}
    if product not in SUPPORTED:
        return dict(out, reason="unsupported",
                    msg="no CLI schema harvester for %s" % (product or "this appliance"))
    raw_fw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
    version = fv.normalize(raw_fw)
    if not version or fv.is_line_only(version):
        return dict(out, reason="firmware_unknown",
                    msg="the running build of %s is unknown; run a firmware check first" % name)
    out["version"] = version
    build = lib._build_token(getattr(appliance, "firmware", "") or raw_fw)
    device = _device(appliance)
    captured = now.isoformat(timespec="seconds")
    origin = "%s%s@%s" % (ORIGIN_PREFIX, getattr(appliance, "id", ""), version)
    try:
        from . import ssh_ops
        reader = tree_reader or ssh_ops.run_tree
        # 1. tree ----------------------------------------------------------
        try:
            text, complete = reader(appliance)
            err = ""
        except Exception as exc:  # noqa: BLE001 — recorded as a failed harvest
            text, complete, err = "", False, "%s: %s" % (type(exc).__name__, exc)
        parsed = cli_schema.parse_tree(text)
        tree_doc = cli_schema.evidence_from_cli_tree(
            product, version, build, text, device, origin + ":tree",
            captured_at=captured, truncated=not complete, parsed=parsed)
        if err:
            tree_doc.update(healthy=False, skip_reason=("SSH tree failed: %s" % err)[:500],
                            endpoints={})
        res = lib.ingest(tree_doc, raw={"doc": tree_doc, "tree_text": text})
        out["tree"] = {"evidence_id": res["evidence_id"], "created": res["created"],
                       "healthy": tree_doc["healthy"], "skip_reason": tree_doc["skip_reason"],
                       "counts": (tree_doc.get("summary") or {}).get("counts") or {}}

        # 2. show full-configuration ----------------------------------------
        try:
            if full_reader is not None:
                full_text, source = full_reader(appliance), "ssh"
            else:
                full_text, rec = _fresh_vault_dump(appliance, version, now)
                source = "vault #%s" % rec["backup_id"] if rec else "ssh"
                if not full_text:
                    full_text = _ssh_full(appliance)
            ferr = ""
        except Exception as exc:  # noqa: BLE001
            full_text, source, ferr = "", "ssh", "%s: %s" % (type(exc).__name__, exc)
        full_doc = cli_schema.evidence_from_cli_full(
            product, version, build, full_text, device, origin + ":full",
            captured_at=captured, tree=parsed if tree_doc["healthy"] else None, lab=lab)
        if lab:
            full_doc["summary"]["lab"] = True
        if ferr:
            full_doc.update(healthy=False,
                            skip_reason=("show full-configuration failed: %s" % ferr)[:500],
                            endpoints={})
        # raw=None ON PURPOSE: the stored blob is the names-only document,
        # never the dump (configuration stays in the vault).
        fres = lib.ingest(full_doc, raw=None)
        out["full"] = {"evidence_id": fres["evidence_id"], "created": fres["created"],
                       "healthy": full_doc["healthy"], "skip_reason": full_doc["skip_reason"],
                       "source": source, "counts": full_doc["summary"].get("counts") or {}}

        # 3. REST shape probe ------------------------------------------------
        if probe and product in PROBED and tree_doc["healthy"]:
            cands = _rest_candidates(product, version, tree_doc)
            pres = _probe_rest(appliance, product, cands, tree_doc, client=rest_client,
                               budget=probe_budget)
            pdoc = _probe_doc(product, version, build, device, pres, captured)
            pr = lib.ingest(pdoc, raw=None) if pres["endpoints"] else {}
            out["probe"] = {"candidates": len(cands), "probed": len(pres["endpoints"]),
                            "spent": pres["spent"], "healthy": pdoc["healthy"],
                            "evidence_id": pr.get("evidence_id"),
                            "skipped": {k: len(v) for k, v in pres["skipped"].items()},
                            "verdicts": {v: sum(1 for e in pres["endpoints"].values()
                                                if e["verdict"] == v)
                                         for v in (lib.VERDICT_OK, lib.VERDICT_ABSENT,
                                                   lib.VERDICT_ERROR)}}
        elif probe and product not in PROBED:
            out["probe"] = {"skipped_reason": "no REST shape probe for %s" % product}
        out["channels"] = lib.channels_at(product, version)["summary"]
    except Exception as exc:  # noqa: BLE001 — a harvest never raises
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log.warning("schema_harvest of %s failed: %s", name, exc, exc_info=True)
        return dict(out, reason="error", msg=("%s: %s" % (type(exc).__name__, exc))[:300])
    tree = out["tree"] or {}
    if not tree.get("healthy"):
        return dict(out, reason="unhealthy",
                    msg="CLI schema of %s stored as unhealthy: %s"
                        % (name, tree.get("skip_reason") or "unknown reason"))
    ch = out["channels"] or {}
    return dict(out, ok=True, msg=(
        "schema harvest of %s (%s %s): tree evidence #%s, %d objects; "
        "channels both=%d cli_only=%d hidden=%d rest_only=%d unknown=%d"
        % (name, product, version, tree.get("evidence_id"),
           (tree.get("counts") or {}).get("objects", 0), ch.get("both", 0),
           ch.get("cli_only", 0), ch.get("hidden", 0), ch.get("rest_only", 0),
           ch.get("unknown", 0))))


__all__ = ["SUPPORTED", "PROBED", "DEFAULT_PROBE_BUDGET", "ORIGIN_PREFIX", "ACTION_KEY",
           "harvest"]
