"""Live FortiGate ``?action=schema`` harvest -> API library evidence document.

The parser already exists: ``schema_adapters.fortigate`` turns per-table
``?action=schema`` answers into a ``source == "schema"`` evidence document
(the pack and ``flask apilib schema-import`` use it). This module is only the
live half: one registered FortiGate appliance, its ``FortiGateClient``, GET
only, and the same document. ``api_library.ingest`` is the only writer;
nothing here touches the database except to READ the table list.

Measured on fgt02 (FortiGate-VM64-KVM, FortiOS 8.0.1 build0245, read-only
API token, 2026-10-07/10):

1. **The build comes from the box, not the inventory row.**
   ``GET /api/v2/monitor/system/status`` answers ``version: "v8.0.1"``,
   ``build: 245`` (and every other answer carries them too). The row is
   refreshed by a probe and can trail an upgrade; evidence filed under the
   wrong build is worse than none.
2. **The global index is 403 to a read-only token** while every per-table
   read answers 200, so the tables are read one by one from a list SATOM
   already holds (:func:`table_keys`). A token whose profile does read the
   index gets the whole cmdb in one answer and no list is needed.
3. **404 = absent, 400 = unknown.** A ``get``-only CLI object
   (``system/status``) answers 404: a measured absence. A made-up path and a
   hardware table the VM cannot serve both answer a bare 400, so a 400 stays
   ``error``; the hardware ones are named ``platform`` exceptions by the
   adapter (``schema_adapters.fortigate.PLATFORM_TABLES``).

On fgt02 a pass is ~780 GETs (624 tables served, 98 absent, 54 errored, all
of those 54 hardware or platform features except three).
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import parse_qsl

from . import firmware_versions
from .apilib_fac import device_block, status_from_error
from .schema_adapters import fortigate as adapter

PRODUCT = adapter.PRODUCT
SOURCE = "schema"
STATUS_PATH = "/api/v2/monitor/system/status"


# --------------------------------------------------------------------------- #
#  The table list                                                              #
# --------------------------------------------------------------------------- #
def _keys_of(endpoints: dict) -> set:
    from . import api_library
    out = set()
    for name, ep in (endpoints or {}).items():
        urn = (ep or {}).get("urn") or ""
        key = api_library.urn_key(urn) if urn.startswith(adapter.URN_PREFIX) else name
        if key.count("/") == 1:          # ``a.b/c``: a table, never a nested path
            out.add(key)
    return out


def table_keys(version: str) -> list:
    """The cmdb tables to ask ``version`` about, one by one (rule 2).

    The union of what the library already names: the build's own endpoints
    (an earlier pass or import of the same build) and its ``cli_tree``
    objects, plus the endpoints of the newest library build BELOW it (the
    vendor collection or the previous measured build) -- a new build mostly
    keeps its predecessor's tables, and one it dropped answers 404 or 400,
    never a false "ok". A table that only the new build has and no source
    names yet is missed until its ``tree`` is imported.
    """
    from . import api_library
    from . import firmware_versions as fv
    keys = set(_keys_of(api_library.endpoints_at(PRODUCT, version)))
    _measured, tree = api_library._tree_specs(PRODUCT, version)
    keys |= set(k for k in tree if k.count("/") == 1)
    target = fv.sort_key(version)
    lower = [b["version"] for b in api_library.builds(PRODUCT)
             if b.get("measured") and not b.get("line_only")
             and fv.sort_key(b["version"]) < target]
    if lower:
        keys |= _keys_of(api_library.endpoints_at(PRODUCT, max(lower, key=fv.sort_key)))
    return sorted(keys)


# --------------------------------------------------------------------------- #
#  Live harvest                                                                #
# --------------------------------------------------------------------------- #
def _getter(client, log: dict):
    """``get(url) -> (status, json)`` for ``adapter.capture``, and the ONLY way
    this module reaches the device: a GET through ``FortiGateClient.api_call``
    (which refuses any other verb). Every answer's status is logged so a
    capture can be re-derived and the test fake can prove the verb."""
    def get(url: str):
        path, _, query = url.partition("?")
        params = dict(parse_qsl(query, keep_blank_values=True))
        payload, err = client.api_call("GET", path, **params)
        status = status_from_error(err) if err else 200
        log[url] = status
        return status, payload
    return get


def _live_build(client, log: dict) -> tuple[str, str, dict]:
    """``(version, build token, status results)`` from the box (rule 1)."""
    status, payload = _getter(client, log)(STATUS_PATH)
    if status != 200 or not isinstance(payload, dict):
        return "", "", {}
    ver = str(payload.get("version") or "")
    build = payload.get("build")
    token = "build%04d" % build if isinstance(build, int) else ""
    res = payload.get("results") if isinstance(payload.get("results"), dict) else {}
    out = dict(res)
    if payload.get("serial"):
        out["serial"] = payload["serial"]
    return firmware_versions.normalize(ver), token, out


def harvest(appliance, client=None, keys=None, raw: dict | None = None) -> dict:
    """Live FortiGate appliance -> evidence document (``source="schema"``).

    ``client`` and ``keys`` are injectable for tests (``keys`` replaces
    :func:`table_keys`). Pass a dict as ``raw`` to receive the raw capture --
    ``api_library.ingest`` stores it gzipped beside the evidence. Never
    writes to the device; raises only on a programming error.
    """
    if client is None:
        client = appliance.build_client()
    log: dict = {}
    captured_at = datetime.utcnow().replace(microsecond=0).isoformat()
    device = device_block(appliance)
    origin = "live:%s:%s" % (device.get("name") or "?", adapter.URN_PREFIX)
    version, build, status = _live_build(client, log)
    if status.get("serial") and not device.get("serial"):
        device["serial"] = status["serial"]
    if status.get("model_name") or status.get("model_number"):
        device["model"] = "-".join(x for x in (status.get("model_name"),
                                               status.get("model_number")) if x)
    if version:
        device["firmware_raw"] = "v%s,%s" % (version, build) if build else "v" + version

    def _sick(reason: str, answers=None, errors=None) -> dict:
        doc = adapter.evidence_from_schema(answers or {}, version, build, device, origin,
                                           captured_at=captured_at, errors=errors)
        doc.update(healthy=False, skip_reason=reason[:300])
        return doc

    if not version or firmware_versions.is_line_only(version):
        # scope.kind == "build" promises a full version (the FAC rule).
        doc = _sick("firmware version not readable from %s (HTTP %s)"
                    % (STATUS_PATH, log.get(STATUS_PATH)))
    else:
        wanted = list(keys) if keys is not None else table_keys(version)
        try:
            answers, errors = adapter.capture(_getter(client, log), fallback_keys=wanted)
        except adapter.SchemaGated as exc:
            answers, errors, doc = {}, {}, _sick(
                "schema refused: %s%s" % (exc, "" if wanted else
                                          " (and the library names no table to read one by one)"))
        except RuntimeError as exc:
            answers, errors, doc = {}, {}, _sick("schema read failed: %s" % exc)
        else:
            doc = adapter.evidence_from_schema(answers, version, build, device, origin,
                                               captured_at=captured_at, errors=errors)
        if raw is not None:
            raw.update({"captured_at": captured_at, "status": log,
                        "answers": answers, "errors": errors, "asked": wanted})
    if raw is not None and "status" not in raw:
        raw.update({"captured_at": captured_at, "status": log})
    return doc


__all__ = ["PRODUCT", "SOURCE", "STATUS_PATH", "harvest", "table_keys"]
