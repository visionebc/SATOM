"""File-backed WAF objects: read them off a device, keep them, push them back.

Seven API-Protection object types carry no content in the configuration. Their
cmdb record is a NAME and nothing else, so the generic tree-clone engine — which
copies configuration — produces an object that exists and is EMPTY. Measured on
FortiWeb 7.6.8, in both directions, against two live appliances:

===========================================  ==========================
what is linked to ``waf/xml-validation.rule``  device answer
===========================================  ==========================
a file uploaded WITH content                  ``200``, ``schema-file_val`` resolves
a cmdb object created from ``{"name": …}``    ``500 errcode -7694``
a name that does not exist at all             ``500 errcode -651``
===========================================  ==========================

``-7694`` therefore means exactly *"the object is there and it is empty"*, which
is the state today's planner would create. Worse than the loud failure is the
quiet one: if the referencing rule already exists at the destination, the shell
lands and the policy runs with that validation switched OFF, and nothing says so.

Two halves, and only one of them is solved by the firmware:

**Writing** works for all seven, with the SAME ``Authorization`` header the rest
of SATOM already uses — no browser, no session cookie, no ``X-CSRFTOKEN`` (both
were tried; both 200). The upload endpoints are not under ``/cmdb/`` and the
multipart FIELD NAME differs per type; that field name is the whole trick, and
getting it wrong is what produces the ``-3000`` this module's first draft
concluded was a wall.

**Reading** works for four. XML Schema, WSDL and gRPC IDL answer ``-20005
invalid HTTP method`` on every shape, expose ``can_view: 0``, have no ``*-view``
GUI component, and their tab offers only *Create New | Delete*. They are also
absent from ``execute backup full-config`` (7.5 MB, emits ``edit "xsd-order"`` /
``next`` and no bytes) while certificates in the SAME backup travel whole — the
omission is a product decision, not a gap we can route around.

So for those three a device→device clone of the CONTENT cannot exist, and the
only correct architecture is the one here: **SATOM keeps the artifact**. It is
captured whenever a device does allow the read, or uploaded by an operator, and
pushed from the store to any destination.

``can_view`` is NOT the predictor and must not be used as one: scripting objects
report ``can_view: 0`` and read back byte-identical.
"""
from __future__ import annotations

import gzip
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

# --------------------------------------------------------------------------- #
#  The catalogue                                                                #
# --------------------------------------------------------------------------- #
# Every entry is a measured recipe, not a documented one. ``read=None`` records
# a probe that FAILED, which is a fact worth keeping: without it the next reader
# re-derives "unreadable" by repeating the same six requests.
#
#   urn        the dependency-map urn (services.clone classifies plan items by it)
#   read       {"path", "key"} — private read endpoint + the response field
#   field      multipart field name for the upload (the whole trick)
#   upload     upload endpoint (NOT under /cmdb/)
#   extra      extra multipart form fields
#   name_field form field carrying the object name (JSON Schema only; every
#              other type takes the name from the multipart FILENAME)
#   ext        extensions the firmware is known to accept in the name
KINDS: dict[str, dict[str, Any]] = {
    "xml_schema": {
        "label": "XML Schema (XSD)",
        "urn": "cmdb/waf/xml-schema.file",
        "read": None,          # -20005 invalid HTTP method (6 shapes tried)
        "upload": "/api/v2.0/waf/xmlprotection.xmlschemafile",
        "field": "xmlfile",
    },
    "xml_dtd": {
        "label": "XML DTD",
        "urn": "cmdb/waf/xml-dtd.file",
        "read": {"path": "/api/v2.0/waf/xmlprotection.xmldtdfile?mkey={name}",
                 "key": "file_content"},
        "upload": "/api/v2.0/waf/xmlprotection.xmldtdfile",
        "field": "dtdfile",
        # The read over-runs its buffer and appends 2 bytes of junk. See
        # trim_device_tail: without it every hop through a device compounds.
        "trim_tail": True,
    },
    "wsdl": {
        "label": "WSDL",
        "urn": "cmdb/waf/xml-wsdl.file",
        "read": None,          # -20005
        "upload": "/api/v2.0/waf/xmlprotection.wsdlfile",
        "field": "xmlfile",
    },
    "openapi": {
        "label": "OpenAPI schema",
        "urn": "cmdb/waf/openapi-file",
        # Re-emitted as alphabetically sorted YAML even when JSON was uploaded:
        # a semantic round-trip, never a byte-identical one.
        "read": {"path": "/api/v2.0/waf/openapi.schemafileview?mkey={name}",
                 "key": "htmlArray", "lines": True},
        "upload": "/api/v2.0/waf/openapi.openapischemafile",
        "field": "openapifile",
        # The ONLY kind whose name the firmware validates: no extension and
        # ".txt" both answer -20007. The name IS the filename, so a clone that
        # renames an OpenAPI object can break it.
        "ext": (".json", ".yaml"),
    },
    "grpc_idl": {
        "label": "gRPC IDL",
        "urn": "cmdb/waf/grpc-idl.file",
        "read": None,          # -20005
        "upload": "/api/v2.0/waf/grpc.idlfile",
        "field": "idlfile",
    },
    "json_schema": {
        "label": "JSON Schema",
        "urn": "cmdb/waf/json-schema.file",
        "read": {"path": "/api/v2.0/waf/jsonprotection.jsonschemafile?mkey={name}",
                 "key": "buf"},
        "upload": "/api/v2.0/waf/jsonprotection.jsonschemafile",
        "field": "jsonfile",
        "name_field": "name",
        "extra": {"json-schema-version": "auto-identify"},
        # MEASURED on fortiweb13 (7.6.8), 2026-08-27: this kind is the INVERSE
        # of OpenAPI. ``sa-j1.json``, ``sa-j3.txt`` and ``sa-j4.schema`` are
        # all refused with -61 "Input is not as expected."; the same bytes
        # under ``sa-j2`` upload and read back byte-identical. The natural
        # name for a JSON schema is the one the device will not take, so this
        # is the rule an operator is most likely to trip.
        "no_ext": True,
    },
    "scripting": {
        "label": "Lua scripting",
        "urn": "cmdb/server-policy/scripting",
        "read": {"path": "/api/v2.0/policy/policy.scripting.file?name={name}",
                 "key": "text", "vdom": True},
        # Not multipart: a JSON body, then the cmdb object that names it.
        "put_text": "/api/v2.0/policy/policy.scripting.text?name={name}",
        "cmdb": "/api/v2.0/cmdb/server-policy/scripting",
        "cmdb_ref": "scripting-name",
    },
}

#: ``{urn: kind}`` — how a clone plan item is recognised as file-backed.
URN_KINDS: dict[str, str] = {v["urn"]: k for k, v in KINDS.items()}

#: The three with no read path. Named as a set because the distinction drives
#: every operator-facing message: "SATOM has no copy" is recoverable by
#: uploading one; "the device will not give it back" is not.
UNREADABLE = frozenset(k for k, v in KINDS.items() if not v.get("read"))


def kind_for_urn(urn: str) -> str:
    return URN_KINDS.get((urn or "").strip(), "")


def kind_for_collection(collection: str) -> str:
    """Artifact kind behind a registry COLLECTION (``waf/xml-wsdl.file``).

    Section Config knows a leaf by its collection; this catalogue knows it by
    its urn, and the urn is the collection with a ``cmdb/`` prefix. Deriving
    the join keeps ONE list: a hand-written second map would need extending
    every time a leaf or a kind is added, and forgetting is SILENT — the
    create/upload affordance would simply not appear, which reads as "this
    object type cannot be created" rather than as a missing row.
    """
    coll = (collection or "").strip().strip("/")
    if not coll:
        return ""
    return URN_KINDS.get("cmdb/" + coll, "") or URN_KINDS.get(coll, "")


def is_artifact_urn(urn: str) -> bool:
    return bool(kind_for_urn(urn))


def label(kind: str) -> str:
    return (KINDS.get(kind) or {}).get("label", kind or "?")


def is_readable(kind: str) -> bool:
    return bool((KINDS.get(kind) or {}).get("read"))


def name_warning(kind: str, name: str) -> str:
    """Non-fatal complaint about an object NAME, or ``""``.

    TWO kinds have a rule and they point in OPPOSITE directions, which is
    exactly why this is a table and not an ``if``: OpenAPI REQUIRES ``.json``
    or ``.yaml`` (-20007 otherwise), JSON Schema requires NO extension at all
    (-61 otherwise). Both were measured against a live 7.6.8; the other four
    file kinds were measured too and accept any name, so they are silent on
    purpose rather than by omission.

    The name IS the filename for every kind here, so a rename during a clone
    is a rename of the file -- which is what makes a name rule worth a warning
    instead of a comment.
    """
    spec = KINDS.get(kind) or {}
    if not name:
        return ""
    if spec.get("no_ext"):
        # A dot in a leading path-ish segment is not an extension; only a
        # trailing suffix is what the firmware objects to.
        tail = name.rsplit("/", 1)[-1]
        if "." in tail.strip("."):
            return ("%s names must carry NO extension — the device answers "
                    "-61 for %s. Drop the suffix." % (label(kind), name))
        return ""
    exts = spec.get("ext")
    if not exts:
        return ""
    low = name.lower()
    if any(low.endswith(e) for e in exts):
        return ""
    return ("%s names are filenames — %s has no %s extension and the device "
            "answers -20007 for those" % (label(kind), name, "/".join(exts)))


# --------------------------------------------------------------------------- #
#  Device I/O                                                                   #
# --------------------------------------------------------------------------- #
#: Trailing bytes the DTD read appends past the end of the real content: the
#: U+FFFD produced when the JSON layer decodes the firmware's invalid byte, plus
#: whatever control character followed it. Newline/CR/TAB are NEVER stripped —
#: a file legitimately ends with one and eating it would make every round-trip
#: lossy in a way no test on the FIRST hop would notice.
_TAIL_KEEP = ("\n", "\r", "\t")


def trim_device_tail(text: str) -> str:
    """Drop the firmware's buffer over-run from the end of a read.

    Measured on both lab appliances: the XML DTD read returns the file plus two
    junk bytes (a different second byte per device, so it is uninitialised
    memory rather than a marker). Left in place they are re-uploaded, and the
    NEXT read appends two more — the corruption compounds per hop, and the
    first hop looks perfect.
    """
    if not text:
        return text
    out = text
    while out and out[-1] not in _TAIL_KEEP and (
            out[-1] == "�" or ord(out[-1]) < 0x20 or ord(out[-1]) == 0x7F):
        out = out[:-1]
    return out


def _decode_json(body: bytes):
    """Parse a device response that may not be valid UTF-8.

    ``httpx``'s ``.json()`` raises ``UnicodeDecodeError`` on the XML DTD read,
    because the buffer over-run documented in :func:`trim_device_tail` puts a
    raw invalid byte INSIDE the JSON string. Strict decoding therefore loses
    the whole document over two bytes of firmware junk — a working endpoint
    that reads as a dead one. Decoding with replacement turns that byte into
    U+FFFD, which ``trim_device_tail`` then removes; every other kind decodes
    identically either way.

    ``strict=False`` is set for the same reason one layer up: the junk can also
    be a raw control character, which strict JSON rejects outright. Both
    tolerances only ever affect bytes that :func:`trim_device_tail` then
    removes, and every other kind parses identically with or without them.
    """
    import json as _json
    try:
        return _json.loads(body.decode("utf-8"), strict=False)
    except UnicodeDecodeError:
        return _json.loads(body.decode("utf-8", "replace"), strict=False)


def _envelope(raw: Any) -> dict:
    """The ``results`` object, or ``{}`` for any error envelope.

    FortiWeb spells the key ``results`` here and ``resutls`` in
    ``system/state``; both are checked because the typo is the firmware's and
    guessing which endpoint has which is how a working read reads as empty.
    """
    if not isinstance(raw, dict):
        return {}
    res = raw.get("results", raw.get("resutls", raw.get("data")))
    if isinstance(res, dict):
        return res
    if isinstance(res, list):
        return {"_list": res}
    return {}


def _err_of(raw: Any) -> str:
    if not isinstance(raw, dict):
        return ""
    for holder in (raw, _envelope(raw)):
        if not isinstance(holder, dict):
            continue
        code = holder.get("errcode")
        if code not in (None, 0, "0"):
            return "errcode %s%s" % (code, (": %s" % holder["message"])
                                     if holder.get("message") else "")
    return ""


def fetch(client, kind: str, name: str, *, vdom: str = "") -> tuple[bytes | None, str]:
    """Read one artifact's content off a device.

    Returns ``(blob, "")`` or ``(None, reason)``. NEVER raises: a device that
    is down and a device that refuses the read are both "no content", and the
    caller has to tell the operator which — so the reason is prose, not a flag.
    """
    spec = KINDS.get(kind) or {}
    read = spec.get("read")
    if not read:
        return None, ("%s cannot be read back from any FortiWeb (7.6.8 answers "
                      "-20005 on every shape) — only a copy SATOM already holds "
                      "can be pushed" % label(kind))
    if not name:
        return None, "no object name"
    path = read["path"].format(name=quote(str(name), safe=""))
    if read.get("vdom"):
        path += "&vdom=%s" % quote(str(vdom or ""), safe="")
    try:
        resp = client.api_call("GET", path)
        raw = _decode_json(resp.content)
    except Exception as exc:  # noqa: BLE001 — transport/parse are both "no content"
        return None, "read failed: %s: %s" % (type(exc).__name__, exc)
    err = _err_of(raw)
    if err:
        return None, "device refused the read (%s)" % err
    body = _envelope(raw).get(read["key"])
    if read.get("lines"):
        # htmlArray: the schema re-emitted line by line — and each element
        # ALREADY ends with its newline. Joining on "\n" without stripping that
        # doubles every blank line, which for YAML is not cosmetic: the file
        # round-trips, parses, and is not the same document.
        if not isinstance(body, list):
            return None, "unexpected response shape for %s" % kind
        body = "\n".join(str(x).rstrip("\r\n") for x in body)
    if body is None:
        return None, "response carried no %r field" % read["key"]
    text = body if isinstance(body, str) else str(body)
    if spec.get("trim_tail"):
        text = trim_device_tail(text)
    return text.encode("utf-8"), ""


def push(client, kind: str, name: str, blob: bytes, *, vdom: str = "") -> tuple[bool, str]:
    """Create the object at a destination WITH its content.

    This is what makes a clone of a file-backed object real. Verified for all
    seven kinds against two live appliances using only the ``Authorization``
    header SATOM already sends.
    """
    spec = KINDS.get(kind) or {}
    if not spec:
        return False, "unknown artifact kind %r" % kind
    if not name:
        return False, "no object name"
    try:
        if spec.get("put_text"):
            return _push_text(client, spec, name, blob, vdom=vdom)
        return _push_multipart(client, spec, name, blob)
    except Exception as exc:  # noqa: BLE001 — a dead device is a result, not a crash
        return False, "%s: %s" % (type(exc).__name__, exc)


def _push_multipart(client, spec: dict, name: str, blob: bytes) -> tuple[bool, str]:
    # The object's mkey is the multipart FILENAME for every kind except JSON
    # Schema, which carries an explicit ``name`` form field instead.
    files = {spec["field"]: (name, blob, "application/octet-stream")}
    data = dict(spec.get("extra") or {})
    if spec.get("name_field"):
        data[spec["name_field"]] = name
    resp = client.upload(spec["upload"], files=files, data=(data or None))
    return _upload_result(resp)


def _push_text(client, spec: dict, name: str, blob: bytes, *, vdom: str) -> tuple[bool, str]:
    # Two calls, and the ORDER matters: the cmdb object may only name a script
    # body that already exists, so the text goes first.
    path = spec["put_text"].format(name=quote(str(name), safe=""))
    path += "&vdom=%s" % quote(str(vdom or ""), safe="")
    resp = client.api_call("PUT", path,
                           {"data": {"text": blob.decode("utf-8", "replace")}})
    ok, err = _upload_result(resp)
    if not ok:
        return False, err
    resp2 = client.api_call("POST", spec["cmdb"],
                            {"data": {"name": name, spec["cmdb_ref"]: name}})
    ok2, err2 = _upload_result(resp2)
    if not ok2 and "-3" not in err2:      # -3 = already there; the body still landed
        return False, err2
    return True, ""


def _upload_result(resp) -> tuple[bool, str]:
    try:
        raw = resp.json()
    except Exception:  # noqa: BLE001 — some successes answer with no JSON body
        raw = None
    err = _err_of(raw)
    if err:
        return False, err
    code = getattr(resp, "status_code", 200)
    if code >= 400:
        return False, "HTTP %s" % code
    return True, ""


# --------------------------------------------------------------------------- #
#  The store — content-addressed blobs + a version index                        #
# --------------------------------------------------------------------------- #
def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def store_dir() -> Path:
    """``data/artifacts`` — deliberately under ``data/``.

    ``satom-ha-datasync`` rsyncs that tree to the standby and the system-backup
    bundles include it, so the artifact store inherits both without a new
    replication path. Putting it anywhere else would create the one copy of the
    three unreadable kinds that nothing backs up.
    """
    d = Path(os.environ.get("SATOM_ARTIFACT_DIR") or (_repo_root() / "data" / "artifacts"))
    (d / "objects").mkdir(parents=True, exist_ok=True)
    return d


def blob_path(sha: str) -> Path:
    return store_dir() / "objects" / sha[:2] / ("%s.gz" % sha)


def sha_of(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load(sha: str) -> bytes | None:
    p = blob_path(sha)
    if not p.exists():
        return None
    try:
        with gzip.open(p, "rb") as fh:
            return fh.read()
    except Exception:  # noqa: BLE001
        return None


def put(kind: str, name: str, blob: bytes, *, appliance_id: int | None = None,
        source: str = "uploaded", by: str = "", note: str = ""):
    """Store one artifact version. Returns ``(row, created: bool)``.

    The hash is the identity, exactly as in :mod:`services.sot_store`: capturing
    an artifact that has not changed advances ``last_seen_at`` and writes no
    bytes and no row. Re-deriving that rule here rather than importing it keeps
    the two stores independent, but the SHAPE is deliberately identical so an
    operator reading one understands the other.
    """
    from ..models import db
    from ..models_artifacts import WafArtifact

    sha = sha_of(blob)
    p = blob_path(sha)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".gz.tmp")
        with gzip.open(tmp, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, p)      # atomic: a reader never sees a half blob
    now = datetime.utcnow()
    newest = (WafArtifact.query
              .filter_by(kind=kind, name=name, appliance_id=appliance_id)
              .order_by(WafArtifact.created_at.desc(), WafArtifact.id.desc())
              .first())
    if newest is not None and newest.sha256 == sha:
        newest.last_seen_at = now
        db.session.commit()
        return newest, False
    row = WafArtifact(kind=kind, name=name, appliance_id=appliance_id,
                      sha256=sha, size=len(blob), source=source,
                      note=(note or "")[:500], created_by=(by or "")[:64],
                      created_at=now, last_seen_at=now)
    db.session.add(row)
    db.session.commit()
    return row, True


def latest(kind: str, name: str, appliance_id: int | None = None):
    from ..models_artifacts import WafArtifact
    return (WafArtifact.query
            .filter_by(kind=kind, name=name, appliance_id=appliance_id)
            .order_by(WafArtifact.created_at.desc(), WafArtifact.id.desc())
            .first())


def resolve(kind: str, name: str,
            appliance_id: int | None = None) -> tuple[bytes | None, str, str]:
    """Best stored copy of ``(kind, name)`` — ``(blob, origin, store_error)``.

    ``store_error`` exists because "the store holds no copy" and "the store
    could not be read" lead to opposite actions and would otherwise be the same
    answer. The first is fixed by uploading a file; the second means the index
    or the blob directory is broken, and telling an operator to upload
    something they already uploaded is how a database outage gets diagnosed as
    a missing file.

    Search order, narrowest first — the specificity is the point. Two appliances
    can hold different content under one name (that is exactly the drift a
    clone is supposed to carry), so the device's own copy wins, then the
    library-wide one an operator uploaded, then any other device's — and that
    last one is REPORTED by name, because "some other box had a file with this
    name" is a guess the operator has to be allowed to refuse.
    """
    try:
        from ..models_artifacts import WafArtifact

        tried: list[tuple[int | None, str]] = []
        if appliance_id is not None:
            tried.append((appliance_id, "this device's stored copy"))
        tried.append((None, "the SATOM artifact library"))
        for appl_id, origin in tried:
            row = latest(kind, name, appl_id)
            if row is not None:
                blob = load(row.sha256)
                if blob is not None:
                    return blob, "%s (%s, %s)" % (origin, (row.sha256 or "")[:12],
                                                  row.source), ""
        row = (WafArtifact.query
               .filter_by(kind=kind, name=name)
               .order_by(WafArtifact.created_at.desc(), WafArtifact.id.desc())
               .first())
        if row is not None:
            blob = load(row.sha256)
            if blob is not None:
                return blob, "another appliance's stored copy (appliance #%s, %s)" % (
                    row.appliance_id, (row.sha256 or "")[:12]), ""
    except Exception as exc:  # noqa: BLE001 — a broken store is not "no copy"
        return None, "", "the artifact store could not be read (%s: %s)" % (
            type(exc).__name__, exc)
    return None, "", ""


# --------------------------------------------------------------------------- #
#  Plan integration                                                             #
# --------------------------------------------------------------------------- #
def plan_artifacts(items) -> list[dict]:
    """The file-backed objects a clone plan carries, deduplicated by identity.

    Items whose destination verdict is not ``create`` are kept, not filtered:
    "the destination already has an object with this name" is the single most
    important row on the checklist, because it is the case where nothing is
    copied AND nothing is wrong — and dropping it would leave the operator
    unable to tell that from "we never looked".
    """
    seen: dict[tuple[str, str], dict] = {}
    for it in items or []:
        if getattr(it, "kind", "") != "object":
            continue
        kind = kind_for_urn(getattr(it, "urn", ""))
        if not kind:
            continue
        name = str(getattr(it, "mkey", "") or "")
        if not name:
            continue
        key = (kind, name)
        row = {"kind": kind, "name": name, "label": label(kind),
               "urn": getattr(it, "urn", ""), "status": getattr(it, "status", ""),
               "readable": is_readable(kind),
               "name_warning": name_warning(kind, name)}
        prev = seen.get(key)
        # "create" outranks every other verdict: one plan can legitimately
        # reach the same file twice (two rules sharing a schema), and the copy
        # is needed if ANY of those occurrences needs it.
        if prev is None or (row["status"] == "create" and prev["status"] != "create"):
            seen[key] = row
    return [seen[k] for k in sorted(seen)]


def content_for(kind: str, name: str, *, src_client=None, src_vdom: str = "",
                source_appliance_id: int | None = None, capture: bool = False,
                by: str = "") -> tuple[bytes | None, str, str]:
    """The bytes to push for one artifact — ``(blob, origin, reason)``.

    Order: the SOURCE DEVICE first, the store second. The device wins because
    it is the object being cloned; a stored copy is a snapshot of some earlier
    moment, and silently preferring it would clone a version that no longer
    exists. For the three unreadable kinds the first step cannot run at all,
    which is the entire reason the store exists.

    ``capture=True`` writes what it read into the store, so the next clone of
    the same object works even from a device that has since gone dark. It is
    OFF by default: the pre-flight is read-only and a checklist that mutates
    SATOM's own state while claiming to be read-only is a lie the next reader
    inherits.
    """
    if src_client is not None and is_readable(kind):
        blob, err = fetch(src_client, kind, name, vdom=src_vdom)
        if blob is not None:
            if capture:
                try:
                    put(kind, name, blob, appliance_id=source_appliance_id,
                        source="captured", by=by,
                        note="captured during a clone of %s" % name)
                except Exception:  # noqa: BLE001 — capture must never sink a clone
                    pass
            return blob, "read live off the source device", ""
        reason = err
    else:
        reason = ("%s cannot be read back from any FortiWeb — SATOM must already "
                  "hold a copy" % label(kind)) if not is_readable(kind) else \
                 "no source device to read from"
    blob, origin, store_err = resolve(kind, name, source_appliance_id)
    if blob is not None:
        return blob, origin, ""
    # A store that FAILED outranks the device's reason in the message: telling
    # an operator to upload a file they already uploaded is how a broken index
    # gets diagnosed as a missing artifact.
    return None, "", store_err or reason


def is_empty(blob) -> bool:
    """Content that carries nothing, whatever its byte count.

    ``None`` is NOT empty here — it is ABSENT, and the two must stay apart.
    An absence is reported as "SATOM holds no copy" and can be fixed by a
    capture or an upload; an EMPTY copy answers every "is it held?" check in
    this module and then gets created, empty, at the destination of the next
    clone — an object the device shows as configured while the rule bound to
    it enforces nothing.

    Whitespace-only counts as empty. A file holding one newline has a size, a
    sha and a version row, and configures nothing: it is the empty object
    wearing a byte count.
    """
    return blob is not None and not blob.strip()


def resolve_for_plan(items, *, src_client=None, src_vdom: str = "",
                     source_appliance_id: int | None = None) -> list[dict]:
    """Read-only report: for every file-backed object in the plan, can its
    CONTENT be supplied? Never captures (see :func:`content_for`)."""
    out = []
    for a in plan_artifacts(items):
        rec = dict(a, resolved=False, origin="", reason="", size=0,
                   empty=False)
        if a["status"] != "create":
            rec.update(resolved=True, origin="destination",
                       reason="already present on the destination — not copied, "
                              "and its content is whatever the destination holds")
            out.append(rec)
            continue
        blob, origin, reason = content_for(
            a["kind"], a["name"], src_client=src_client, src_vdom=src_vdom,
            source_appliance_id=source_appliance_id, capture=False)
        if blob is None:
            rec.update(resolved=False, reason=reason or "SATOM holds no copy")
        elif is_empty(blob):
            # Resolved-but-EMPTY was reported as content available: the
            # pre-flight counted it under "will be copied WITH content" and the
            # apply uploaded it. `resolved` is the field every caller reads to
            # decide whether the object can travel, so the empty case belongs
            # on the same side of it as the absent one — with its own reason,
            # because the fix is different (re-author the file, not capture it).
            rec.update(resolved=False, empty=True, origin=origin,
                       size=len(blob),
                       reason="the copy SATOM holds is EMPTY (%d bytes, "
                              "nothing once whitespace is discarded) — "
                              "uploading it would create an object that looks "
                              "configured and enforces nothing" % len(blob))
        else:
            rec.update(resolved=True, origin=origin, size=len(blob))
        out.append(rec)
    return out


def history(kind: str = "", name: str = "", limit: int = 200,
            scope_id: int | None = None) -> list[dict]:
    """Recent versions. ``scope_id`` narrows to what ONE (device, ADOM) reads —
    its own copies plus the library-wide ones, the same set ``resolve()`` walks.

    The filter is applied in the QUERY, before ``limit``: narrowing the 200 rows
    that came back would let another pair's versions eat this pair's places and
    report the remainder as everything there is.
    """
    from sqlalchemy import or_

    from ..models_artifacts import WafArtifact
    q = WafArtifact.query
    if kind:
        q = q.filter_by(kind=kind)
    if name:
        q = q.filter_by(name=name)
    if scope_id is not None:
        q = q.filter(or_(WafArtifact.appliance_id == scope_id,
                         WafArtifact.appliance_id.is_(None)))
    rows = q.order_by(WafArtifact.created_at.desc(), WafArtifact.id.desc()).limit(limit).all()
    return [r.to_dict() for r in rows]


def stats() -> dict:
    """Store health for the library page: rows, distinct objects, blob bytes."""
    from ..models_artifacts import WafArtifact
    try:
        rows = WafArtifact.query.count()
        distinct = len({(r.kind, r.name, r.appliance_id)
                        for r in WafArtifact.query.all()})
    except Exception:  # noqa: BLE001 — table may not exist yet
        rows, distinct = 0, 0
    total, count = 0, 0
    objects = store_dir() / "objects"
    if objects.exists():
        for p in objects.glob("*/*.gz"):
            try:
                total += p.stat().st_size
                count += 1
            except OSError:
                pass
    return {"versions": rows, "objects": distinct, "blobs": count, "bytes": total}
