"""Live FortiAnalyzer syntax walk -> API library evidence document.

The walk and the parser already exist: ``schema_adapters.fortianalyzer``
asks JSON-RPC ``get`` with ``option: ["syntax"]`` object by object
(:func:`~app.services.schema_adapters.fortianalyzer.measure`) and turns the
answers into a ``source == "schema"`` evidence document
(:func:`~app.services.schema_adapters.fortianalyzer.evidence_from_syntax`).
This module is only the live half the incremental harvest
(``services.apilib_harvest``) runs: one registered FortiAnalyzer, ONE
JSON-RPC session, ``get`` only, and the same document -- healthy or not.
``api_library.ingest`` is the only writer; nothing here touches the database
except to READ the catalog of objects to ask about.

Rules, each from a real FortiAnalyzer-VM64-KVM 7.6.7 build3737 (faz02):

1. **The build comes from the box, not the inventory row.** ``get /sys/status``
   answers ``Version: "v7.6.7-build3737 260601 (GA.M)"`` (the firmware probe's
   read). The row is refreshed by a probe and can trail an upgrade; evidence
   filed under the wrong build is worse than none.
2. **Healthy means objects were read.** A walk is healthy only when at least
   one object answered its syntax. A walk that read nothing (every object
   ``-3``/refused, an empty catalog, a refused login, a transport failure
   mid-walk) is stored UNHEALTHY with the reason: the record of a failed read
   is evidence too, but it measured nothing, so the build still needs a
   harvest.
3. **Refusals are not absences.** ``-3`` is absent on this build; ``-11`` (no
   permission) and every other code are ``error`` -- never measured. A pass
   where more than a quarter of the asked objects were refused is stored
   unhealthy (the FortiAuthenticator / sweep error-ratio rule): a box whose
   admin cannot read half the tree must not read as "measured" and stop
   ``needs_harvest`` from asking again once the permission is fixed.
4. **Read-only.** The only calls are the session login/logout the client
   makes itself and JSON-RPC ``get`` (with or without the syntax option).
   Row data a table's children need (its first row key) is dropped by the
   walk; ``/sys/status`` contributes the version, serial and model only.
"""
from __future__ import annotations

from datetime import datetime

from . import firmware_versions
from .apilib_fac import ERROR_RATIO_LIMIT, device_block
from .schema_adapters import fortianalyzer as adapter

PRODUCT = adapter.PRODUCT
SOURCE = "schema"
STATUS_URL = "/sys/status"


class _NoClient(Exception):
    pass


def _result(resp) -> tuple:
    """``(status code, data)`` of one legacy-dialect JSON-RPC answer."""
    res = resp.get("result") if isinstance(resp, dict) else None
    res = res[0] if isinstance(res, list) and res else res
    res = res if isinstance(res, dict) else {}
    return (res.get("status") or {}).get("code"), res.get("data")


def _getter(client, log: dict, counter: list):
    """``get(url, syntax) -> raw answer`` for ``adapter.measure``, and the ONLY
    way this module reaches the device: a JSON-RPC ``get`` through
    ``FortiAnalyzerClient.rpc``. Every answer's status code is logged (never
    its data) so the test fake can prove the verb and a capture can say what
    was asked."""
    def get(url: str, syntax: bool):
        counter[0] += 1
        resp = client.rpc("get", url, **({"option": ["syntax"]} if syntax else {}))
        log["%s%s" % (url, " [syntax]" if syntax else "")] = _result(resp)[0]
        return resp
    return get


def _live_build(get) -> tuple:
    """``(version, build token, status data, error)`` from the box (rule 1)."""
    from . import api_library
    try:
        resp = get(STATUS_URL, False)
    except Exception as exc:  # noqa: BLE001 -- login refused, transport
        return "", "", {}, "%s: %s" % (type(exc).__name__, exc)
    code, data = _result(resp)
    if code not in (0, None) or not isinstance(data, dict):
        return "", "", {}, "code %s" % code
    raw = str(data.get("Version") or data.get("version") or "")
    if not raw:
        return "", "", data, "no Version in the answer"
    return firmware_versions.normalize(raw), api_library._build_token(raw), data, ""


def _verdicts(doc: dict) -> dict:
    out = {"ok": 0, "absent": 0, "error": 0}
    for ep in (doc.get("endpoints") or {}).values():
        v = (ep or {}).get("verdict")
        if v in out:
            out[v] += 1
    return out


def harvest(appliance, client=None, catalog=None, raw: dict | None = None,
            max_requests: int = adapter.MAX_REQUESTS, now=None) -> dict:
    """Live FortiAnalyzer appliance -> evidence document (``source="schema"``).

    ``client`` and ``catalog`` are injectable for tests (``catalog`` replaces
    ``adapter.known_urls()``). Pass a dict as ``raw`` to receive the raw
    capture -- ``api_library.ingest`` stores it gzipped beside the evidence.
    ALWAYS returns a document; ``healthy`` is True only for a walk that read
    objects (rule 2), and ``skip_reason`` says why when it is not;
    ``summary.failure`` names the case for callers (``no_client``,
    ``firmware_unknown``, ``no_catalog``, ``walk_failed``, ``no_objects``,
    ``refused``). Never writes to the device; raises only on a programming
    error. This is the ONE FortiAnalyzer harvest: the incremental harvest
    (``apilib_harvest``) and the adapter's own harvest (Schema builds,
    ``schema_harvest``) both run it.
    """
    own = client is None
    log: dict = {}
    counter = [0]
    captured_at = (now or datetime.utcnow()).replace(microsecond=0).isoformat()
    device = device_block(appliance)
    origin = "live:%s:%s" % (device.get("name") or "?", adapter.URL_PREFIX)
    version, build, wanted = "", "", []
    answers: dict = {}
    not_probed: dict = {}

    def _sick(failure: str, reason: str) -> dict:
        doc = adapter.evidence_from_syntax(answers, version, build, device, origin,
                                           captured_at=captured_at, not_probed=not_probed)
        doc.update(healthy=False, skip_reason=reason[:300])
        doc["summary"]["failure"] = failure
        return doc

    try:
        if own:
            try:
                client = appliance.build_client()
            except Exception as exc:  # noqa: BLE001 -- e.g. an undecryptable secret
                client = None
                raise _NoClient("%s: %s" % (type(exc).__name__, exc)) from exc
        get = _getter(client, log, counter)
        version, build, status, err = _live_build(get)
        if status.get("Serial Number") and not device.get("serial"):
            device["serial"] = str(status["Serial Number"])
        if status.get("Platform Full Name"):
            device["model"] = str(status["Platform Full Name"])
        if version:
            device["firmware_raw"] = str(status.get("Version") or status.get("version"))
        if not version or firmware_versions.is_line_only(version):
            # scope.kind == "build" promises a full version (the FAC rule).
            doc = _sick("firmware_unknown", "firmware version not readable from %s (%s)"
                        % (STATUS_URL, err or "line-only %r" % version))
        else:
            wanted = adapter.catalog_urls(adapter.known_urls() if catalog is None
                                          else catalog)
            if not wanted:
                doc = _sick("no_catalog", "SATOM knows no FortiAnalyzer /cli/global object to ask "
                            "about (import the fortianalyzer API library or registry first)")
            else:
                try:
                    answers, not_probed = adapter.measure(get, wanted,
                                                          max_requests=max_requests)
                except Exception as exc:  # noqa: BLE001 -- transport mid-walk
                    doc = _sick("walk_failed", "syntax walk failed after %d request(s): %s: %s"
                                % (counter[0], type(exc).__name__, exc))
                else:
                    doc = adapter.evidence_from_syntax(
                        answers, version, build, device, origin,
                        captured_at=captured_at, not_probed=not_probed)
                    doc = _judge(doc, len(wanted))
    except _NoClient as exc:
        doc = _sick("no_client", "no FortiAnalyzer client: %s" % exc)
    finally:
        if own and client is not None:
            try:
                client.logout()
            except Exception:  # noqa: BLE001 -- the session dies with the client
                pass
    summary = doc.setdefault("summary", {})
    summary["requests"] = counter[0]
    if raw is not None:
        raw.update({"captured_at": captured_at, "status": log, "answers": answers,
                    "not_probed": not_probed, "catalog": wanted,
                    "requests": counter[0]})
    return doc


def _judge(doc: dict, asked: int) -> dict:
    """Rules 2 and 3 on a document the walk produced."""
    objects = len((doc.get("summary") or {}).get("objects") or {})
    v = _verdicts(doc)
    total = sum(v.values())
    if objects == 0:
        doc["summary"]["failure"] = "no_objects"
        doc.update(healthy=False, skip_reason=(
            "the syntax walk read no object (%d catalog object(s) asked: %d absent, "
            "%d refused, %d not asked)" % (asked, v["absent"], v["error"],
                                           len((doc.get("summary") or {})
                                               .get("not_probed") or {})))[:300])
    elif total and v["error"] / total > ERROR_RATIO_LIMIT:
        doc["summary"]["failure"] = "refused"
        doc.update(healthy=False, skip_reason=(
            "%d of %d objects refused (> %d%%): check the admin's rpc-permit and "
            "profile" % (v["error"], total, ERROR_RATIO_LIMIT * 100)))
    else:
        doc.update(healthy=True, skip_reason="")
    return doc


__all__ = ["PRODUCT", "SOURCE", "STATUS_URL", "harvest"]
