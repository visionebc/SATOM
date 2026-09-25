"""Live FortiAuthenticator schema harvest -> API library evidence document.

FortiAuthenticator is the one product in the fleet that DESCRIBES its own API.
Its REST layer is Django Tastypie, and Tastypie publishes two read-only views
that the other products do not have:

* ``GET /api/v1/`` -- the directory: every resource with its ``list_endpoint``
  and ``schema`` URL (58 resources on the fleet's 8.0.3 build0099 unit);
* ``GET /api/v1/<resource>/schema/`` -- per-field ``type``, ``nullable``,
  ``blank``, ``readonly``, ``default``, ``unique``, related target, plus the
  HTTP verbs the resource accepts.

So for FAC the library does not have to infer fields from whatever rows
happen to exist (FortiWeb's ``blind`` problem): the device states them. This
module turns one live pass over those views into the evidence document
defined in ``docs/api-library.md`` (``source == "schema"``,
``scope.kind == "build"``). ``api_library.ingest`` is the only writer; nothing
here touches the database.

Two functions, split so the rules can be tested without a device:

* :func:`harvest` -- talks to the appliance, **GET only**, and records every
  response (including refusals) in a raw capture;
* :func:`evidence_from_capture` -- pure: raw capture + device block -> document.

Rules this module is shaped around, each measured on a live 8.0.3 unit:

1. **A schema 500 is not a missing resource.** Tastypie's introspection
   crashes on the non-ORM singletons (``systeminfo``, ``logsettings``, ...)
   while their GET serves real data. The verdict is keyed on the LIST
   response; the schema only supplies fields. For those singletons the field
   names come from the one object the device returned, with ``required`` left
   ``None`` -- a row says a field exists, not whether a write needs it.
2. **405 on GET means "served, not readable".** ``auth``, ``system``,
   ``upgrade`` and friends are POST-only actions. They exist on this build, so
   they are ``ok`` with ``rows=None``; the schema's method lists (kept under
   ``methods``) say what the endpoint accepts. Calling them ``absent`` would
   make the library claim a build dropped an API it still serves.
3. **"absent" needs a measured directory.** A registry endpoint is ``absent``
   only when ``/api/v1/`` answered and did not list it, or the resource itself
   answered 404. If the directory fails, the document is ``healthy=False`` and
   claims nothing.
4. **Required is computed, not guessed.** Tastypie's hydrate rejects a
   missing field only when it is not ``readonly``, not ``blank``, not
   ``nullable`` and has no default -- that is exactly the rule used here
   (``"No default provided."`` is Tastypie's "no default" sentinel). The
   brief's shorter rule (not nullable, not readonly, no default) would mark
   ``blank`` fields such as the primary key required, which the device does
   not enforce.
"""
from __future__ import annotations

import re
from datetime import datetime

from . import firmware_versions

PRODUCT = "fortiauthenticator"
SOURCE = "schema"
API_ROOT = "/api/v1/"

#: Tastypie renders ``NOT_PROVIDED`` as this literal string in schema output.
#: It means "no default", not a default whose value is that sentence.
NO_DEFAULT = "No default provided."

#: Mirrors the sweep's error-ratio rule (``api_library.evidence_from_sweep``):
#: a pass where more than a quarter of the resources errored is stored but
#: never folded into facts, because a half-refused pass would read as a build
#: that lost half its API.
ERROR_RATIO_LIMIT = 0.25

#: Section for directory resources the registry does not name. Registry names
#: carry their section as a prefix (``auth_local_users`` -> ``auth``).
UNREGISTERED_SECTION = "other"

_STATUS_RE = re.compile(r"^(?:HTTP )?([1-5]\d\d)\b")
_BUILD_RE = re.compile(r"build\s*0*(\d+)", re.I)

# JSON value -> Tastypie type vocabulary, for fields only a row revealed.
_JSON_TYPES = ((bool, "boolean"), (int, "integer"), (float, "float"),
               (str, "string"), (list, "list"), (dict, "dict"))


# --------------------------------------------------------------------------- #
#  Small pure helpers                                                          #
# --------------------------------------------------------------------------- #
def _resource_urn(path: str) -> str:
    """``/api/v1/auth`` or ``/api/v1/auth/`` -> ``/api/v1/auth/``.

    The directory lists paths without the trailing slash and the registry
    stores them with it; both are normalised so a URN match is exact.
    """
    p = "/" + (path or "").strip().strip("/")
    return p + "/"


def _url(path: str, **params) -> str:
    """Capture key for a request: path plus sorted query string."""
    if not params:
        return path
    q = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    return "%s?%s" % (path, q)


def status_from_error(err) -> int | None:
    """HTTP status carried by the client's error string, or None.

    ``FortiAuthenticatorClient._call`` reports refusals as text
    (``"405 method not allowed ..."``, ``"HTTP 500: ..."``). Transport
    failures (``"ConnectTimeout: ..."``) carry no status and stay None, which
    evidence_from_capture treats as an error, never as absence.
    """
    if not err:
        return None
    m = _STATUS_RE.match(str(err))
    return int(m.group(1)) if m else None


def parse_build(firmware_raw) -> str:
    """``"FACVMKVM v8.0.3, build0099 (GA)"`` -> ``"build0099"``; "" if none.

    Re-padded to four digits, the form FAC prints, so the same build read from
    two differently formatted strings is one build.
    """
    m = _BUILD_RE.search(str(firmware_raw or ""))
    return "build%04d" % int(m.group(1)) if m else ""


def _json_type(value) -> str | None:
    for py, name in _JSON_TYPES:
        if isinstance(value, py):
            return name
    return None


def _default_of(spec: dict):
    d = spec.get("default", NO_DEFAULT)
    return None if d == NO_DEFAULT else d


def _required(spec: dict) -> bool:
    """Rule 4 of the module docstring -- Tastypie's own hydrate condition."""
    return (not spec.get("nullable", False)
            and not spec.get("readonly", False)
            and not spec.get("blank", False)
            and spec.get("default", NO_DEFAULT) == NO_DEFAULT)


def _options(spec: dict):
    """Enumerated values from ``choices`` when the schema publishes them.

    Django serialises choices as ``[[value, label], ...]``; a flat list or a
    ``{value: label}`` map is accepted too. Values are kept, labels dropped:
    the value is what a payload must carry.
    """
    choices = spec.get("choices")
    if not choices:
        return None
    if isinstance(choices, dict):
        return list(choices)
    out = []
    for c in choices:
        out.append(c[0] if isinstance(c, (list, tuple)) and c else c)
    return out


def _schema_field(spec: dict) -> dict:
    return {"type": spec.get("type"),
            "options": _options(spec),
            "default": _default_of(spec),
            "required": _required(spec)}


def _row_field(value) -> dict:
    # A row proves the field is served; it says nothing about writes, so
    # ``required`` is unknown rather than False (unknown is never "optional").
    return {"type": _json_type(value), "options": None, "default": None,
            "required": None}


def _registry_by_urn(registry: dict) -> dict:
    """URN -> registry name. On a duplicate URN the first name (sorted) wins,
    so the mapping is deterministic whatever order the registry came in."""
    out: dict = {}
    for name in sorted(registry or {}):
        out.setdefault(_resource_urn(registry[name]), name)
    return out


def _derived_name(resource: str, taken: set) -> str:
    """Name for a directory resource the registry does not know.

    ``localgroup-memberships`` -> ``localgroup_memberships``. Suffixed if it
    would collide with a registry name bound to a different URN, so an
    unregistered resource can never overwrite a registered one's history.
    """
    base = re.sub(r"[^0-9a-z]+", "_", resource.lower()).strip("_") or "resource"
    name = base
    while name in taken:
        name += "_res"
    return name


def _section(name: str, registered: bool) -> str:
    return name.split("_", 1)[0] if registered else UNREGISTERED_SECTION


# --------------------------------------------------------------------------- #
#  Pure normaliser                                                             #
# --------------------------------------------------------------------------- #
def _endpoint(resource: str, urn: str, responses: dict) -> dict:
    """One directory resource -> endpoint entry (without name/section)."""
    lst = responses.get(_url(urn, limit=1)) or {}
    sch = responses.get(urn + "schema/") or {}
    status = lst.get("status")
    body = lst.get("json")

    if status == 200:
        verdict = "ok"
    elif status == 405:
        verdict = "ok"          # rule 2: served, POST-only
    elif status == 404:
        verdict = "absent"
    else:
        verdict = "error"       # 401/403/500 or transport: we do not know

    rows = None
    sample = None
    if status == 200:
        if isinstance(body, dict) and isinstance(body.get("objects"), list) \
                and isinstance(body.get("meta"), dict):
            total = body["meta"].get("total_count")
            rows = int(total) if isinstance(total, int) else len(body["objects"])
            sample = body["objects"][0] if body["objects"] else None
        elif isinstance(body, dict):
            rows, sample = 1, body          # singleton: one bare object
        elif body is None:
            rows = 0

    fields = None
    origin = ""
    methods = None
    schema = sch.get("json") if sch.get("status") == 200 else None
    if isinstance(schema, dict) and isinstance(schema.get("fields"), dict):
        fields = {k: _schema_field(v if isinstance(v, dict) else {})
                  for k, v in schema["fields"].items()}
        origin = "schema"
        methods = {"list": sorted(schema.get("allowed_list_http_methods") or []),
                   "detail": sorted(schema.get("allowed_detail_http_methods") or [])}

    row_check = None
    if isinstance(sample, dict):
        keys = set(sample)
        if fields is None:
            # rule 1: schema crashed, the row is the only field evidence.
            fields = {k: _row_field(sample[k]) for k in sorted(keys)}
            origin = "row"
        else:
            extra = sorted(keys - set(fields))
            row_check = {"missing_in_row": sorted(set(fields) - keys),
                         "extra_in_row": extra}
            for k in extra:
                # Served but undeclared: still a field of this build.
                fields[k] = _row_field(sample[k])
            if extra:
                origin = "schema+row"

    ep = {"urn": urn, "verdict": verdict, "rows": rows, "fields": fields,
          "resource": resource, "http_status": status,
          "schema_status": sch.get("status"), "field_origin": origin or None}
    if methods is not None:
        ep["methods"] = methods
    if row_check is not None:
        ep["row_check"] = row_check
    if verdict == "error":
        ep["error"] = (lst.get("error") or "")[:200]
    return ep


def evidence_from_capture(capture: dict, device: dict) -> dict:
    """Raw capture (see :func:`harvest`) + device block -> evidence document.

    ``capture`` shape::

        {"captured_at": "...", "registry": {name: urn},
         "responses": {"<path[?query]>": {"status": int|None,
                                          "json": ..., "error": str|None}}}

    Refusals are kept in ``responses`` on purpose: a 405 and a 404 lead to
    opposite verdicts, and a capture that only kept successes could not tell
    them apart when re-normalised later.
    """
    device = dict(device or {})
    responses = capture.get("responses") or {}
    registry = capture.get("registry") or {}
    by_urn = _registry_by_urn(registry)

    # The running firmware as the device reports it wins over the inventory
    # row: the row is refreshed by a probe and can trail an upgrade, and
    # evidence filed under the wrong build is worse than none.
    live = (responses.get(_url("/api/v1/systeminfo/", limit=1)) or {}).get("json")
    live = live if isinstance(live, dict) else {}
    if live.get("firmware"):
        device["firmware_raw"] = live["firmware"]
    if not device.get("serial") and live.get("sn"):
        device["serial"] = live["sn"]
    fw = device.get("firmware_raw") or ""
    version = firmware_versions.normalize(fw)

    doc = {
        "product": PRODUCT,
        "source": SOURCE,
        "captured_at": capture.get("captured_at") or "",
        "origin_ref": "live:%s:%s" % (device.get("name") or "?", API_ROOT),
        "device": device,
        "scope": {"kind": "build", "version": version, "build": parse_build(fw)},
        "healthy": True,
        "skip_reason": "",
        "endpoints": {},
    }

    root = responses.get(API_ROOT) or {}
    directory = root.get("json") if root.get("status") == 200 else None
    if not isinstance(directory, dict) or not directory:
        doc["healthy"] = False
        doc["skip_reason"] = ("resource directory %s unavailable: %s"
                              % (API_ROOT, root.get("error") or "empty"))
        return doc
    if not version or firmware_versions.is_line_only(version):
        # scope.kind == "build" promises a full version; a line-only or
        # missing one would file this evidence under a build nobody runs.
        doc["healthy"] = False
        doc["skip_reason"] = "firmware version not resolvable from %r" % fw

    endpoints: dict = {}
    taken = set(registry)
    for resource in sorted(directory):
        meta = directory[resource] if isinstance(directory[resource], dict) else {}
        urn = _resource_urn(meta.get("list_endpoint") or (API_ROOT + resource))
        name = by_urn.get(urn)
        registered = name is not None
        if not registered:
            name = _derived_name(resource, taken)
            taken.add(name)
        ep = _endpoint(resource, urn, responses)
        ep["section"] = _section(name, registered)
        ep["registered"] = registered
        endpoints[name] = ep

    # Rule 3: registry endpoints the measured directory does not list.
    listed = {e["urn"] for e in endpoints.values()}
    for urn, name in sorted(by_urn.items()):
        if urn in listed:
            continue
        endpoints[name] = {"urn": urn, "verdict": "absent", "rows": None,
                           "fields": None, "resource": urn.strip("/").rsplit("/", 1)[-1],
                           "http_status": None, "schema_status": None,
                           "field_origin": None, "section": _section(name, True),
                           "registered": True}

    doc["endpoints"] = endpoints
    errored = sum(1 for e in endpoints.values() if e["verdict"] == "error")
    if doc["healthy"] and errored / len(endpoints) > ERROR_RATIO_LIMIT:
        doc["healthy"] = False
        doc["skip_reason"] = ("%d of %d resources errored (> %d%%)"
                              % (errored, len(endpoints), ERROR_RATIO_LIMIT * 100))
    return doc


# --------------------------------------------------------------------------- #
#  Live harvest                                                                #
# --------------------------------------------------------------------------- #
def device_block(appliance) -> dict:
    """Identity copied into the evidence so it outlives the appliance row."""
    return {"appliance_id": getattr(appliance, "id", None),
            "name": getattr(appliance, "name", "") or "",
            "serial": getattr(appliance, "serial", "") or "",
            "model": getattr(appliance, "model", "") or "",
            "hw_type": getattr(appliance, "hw_type", "") or "",
            "firmware_raw": getattr(appliance, "firmware", "") or ""}


def _get(client, responses: dict, path: str, **params):
    """The ONLY way this module reaches the device, and it is a GET.

    Harvesting must never change device state; funnelling every request
    through one line makes that auditable and lets the test fake prove it.
    """
    payload, err = client.api_call("GET", path, **params)
    status = status_from_error(err) if err else 200
    responses[_url(path, **params)] = {"status": status, "json": payload,
                                       "error": err}
    return payload, status


def capture(appliance, client=None, registry: dict | None = None) -> dict:
    """Raw capture of the directory, every schema and one row per resource.

    ``?limit=1`` is enough: ``meta.total_count`` gives the row count and one
    object is enough to cross-check keys. Walking whole collections would
    copy directory data (users, groups) into evidence for no gain.
    """
    if client is None:
        client = appliance.build_client()
    if registry is None:
        from ..registry import loader
        registry = dict(loader.load_fac_registry())
    responses: dict = {}
    directory, status = _get(client, responses, API_ROOT)
    if status == 200 and isinstance(directory, dict):
        for resource in sorted(directory):
            meta = directory[resource] if isinstance(directory[resource], dict) else {}
            urn = _resource_urn(meta.get("list_endpoint") or (API_ROOT + resource))
            _get(client, responses, urn + "schema/")
            _get(client, responses, urn, limit=1)
    return {"captured_at": datetime.utcnow().replace(microsecond=0).isoformat(),
            "registry": registry, "responses": responses}


def harvest(appliance, client=None, registry: dict | None = None,
            raw: dict | None = None) -> dict:
    """Live appliance -> evidence document (``source="schema"``).

    ``client`` and ``registry`` are injectable for tests. Pass a dict as
    ``raw`` to receive the raw capture too -- ``api_library.ingest`` stores it
    gzipped beside the evidence so the document can be re-derived later.
    """
    cap = capture(appliance, client=client, registry=registry)
    if raw is not None:
        raw.update(cap)
    return evidence_from_capture(cap, device_block(appliance))


__all__ = ["harvest", "capture", "evidence_from_capture", "device_block",
           "parse_build", "status_from_error"]
