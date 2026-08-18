"""Guards for the WAF artifact store and the clone path that uses it.

The behaviours pinned here are the ones whose failure is SILENT — where the
clone reports success and the destination is quietly less protected than the
source:

  * a file-backed object whose bytes are unavailable is SKIPPED, never created
    as an empty shell (an empty object satisfies every "the object exists"
    check and answers ``-7694`` only if a rule is bound in the same apply);
  * a real apply REFUSES unless the operator accepted that consequence, and
    refuses BEFORE the first device write;
  * a migrate does NOT disable the source when anything was skipped — the
    accepted risk is an incomplete copy, not an unprotected cutover;
  * the multipart FIELD NAME per kind, which is the entire difference between
    a working upload and the ``-3000`` this feature spent a session believing
    was a firmware wall.

No Flask, no network, no device: everything below drives the engine with
in-memory fakes, except the pure catalogue assertions.
"""
import json

import pytest

from app.registry import dependencies as deps
from app.services import clone, policy_ops
from app.services import waf_artifacts as wa


# --- fakes ------------------------------------------------------------------
class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.content = (payload if isinstance(payload, bytes)
                        else json.dumps(payload).encode("utf-8"))
        self.status_code = status_code

    def json(self):
        return json.loads(self.content.decode("utf-8", "replace"))


class FakeClient:
    """Records api_call/upload; answers from a canned map."""

    def __init__(self, reads=None, ok=True):
        self.reads = reads or {}
        self.ok = ok
        self.calls = []
        self.uploads = []

    def api_call(self, method, path, data=None):
        self.calls.append((method, path, data))
        if method == "GET":
            for frag, payload in self.reads.items():
                if frag in path:
                    return FakeResponse(payload)
            return FakeResponse({"results": {"errcode": -20005,
                                             "message": "invalid HTTP method"}})
        return FakeResponse({"results": {"status": "success"}}
                            if self.ok else {"results": {"errcode": -3000}})

    def upload(self, path, files, data=None, timeout=None):
        self.uploads.append((path, files, data))
        return FakeResponse({"results": {"status": "success"}}
                            if self.ok else {"results": {"errcode": -3000,
                                                         "message": "Internal error"}})


class FakeOps:
    def __init__(self, appliance_name="dst"):
        self.calls = []
        self.client = FakeClient()

        class _A:
            name = appliance_name
        self.appliance = _A()

    class _R(dict):
        @property
        def ok(self):
            return bool(self.get("ok"))

    def create(self, endpoint, data, *, mkey=None, dry_run=True):
        self.calls.append(("create", endpoint, mkey, data))
        return self._R(ok=True, error="")

    def update(self, endpoint, mkey, data, *, dry_run=True, sub_mkey=None):
        self.calls.append(("update", endpoint, mkey, data))
        return self._R(ok=True, error="")


class FakePlanner:
    def __init__(self, items):
        self._items = items
        self.dst = None

    def plan(self, root, mkey, *, new_name="", **kw):
        return list(self._items)


def _item(urn, mkey, status="create", kind="object", depth=1, label="X"):
    return clone.CloneItem(label=label, urn=urn, logical=None, mkey=mkey,
                           parent_mkey="", kind=kind, depth=depth,
                           payload={"name": mkey}, status=status)


def _root():
    return clone.CloneItem(label="Server Policy", urn=clone.ROOT_SERVER_POLICY.urn,
                           logical="server_policy", mkey="pol", parent_mkey="",
                           kind="object", depth=0,
                           payload={"name": "pol", "status": "enable"})


XSD_URN = wa.KINDS["xml_schema"]["urn"]
DTD_URN = wa.KINDS["xml_dtd"]["urn"]


def _ctx(**kw):
    base = {"enabled": True, "src_client": None, "src_vdom": "",
            "source_appliance_id": None, "accept_missing": False, "by": "t"}
    base.update(kw)
    return base


# --- catalogue --------------------------------------------------------------
def test_every_kind_has_a_write_recipe():
    """A kind SATOM can neither read nor write is a row that only produces
    empty shells — the exact failure this module exists to remove."""
    for key, spec in wa.KINDS.items():
        assert spec.get("upload") or spec.get("put_text"), key
        if spec.get("upload"):
            assert spec.get("field"), key


def test_unreadable_set_is_exactly_the_three_measured_ones():
    assert wa.UNREADABLE == frozenset({"xml_schema", "wsdl", "grpc_idl"})
    for k in wa.UNREADABLE:
        assert wa.KINDS[k]["read"] is None
        assert wa.is_readable(k) is False


def test_multipart_field_names_are_the_measured_ones():
    """Pinned per kind, not as a shape. A wrong field name is answered with
    ``-3000 Internal error``, which reads like a firmware fault rather than a
    request fault — so a silent drift here costs a whole debugging session."""
    assert {k: v.get("field") for k, v in wa.KINDS.items()} == {
        "xml_schema": "xmlfile", "xml_dtd": "dtdfile", "wsdl": "xmlfile",
        "openapi": "openapifile", "grpc_idl": "idlfile",
        "json_schema": "jsonfile", "scripting": None,
    }


def test_every_artifact_urn_exists_in_the_dependency_map():
    """The urns are how a plan item is recognised. If ``dependencies.py``
    renames one, this table silently stops matching and every file-backed
    object goes back to being cloned as an empty shell — with no error."""
    seen = set()

    def walk(node):
        seen.add(node.urn)
        for child in getattr(node, "children", ()) or ():
            walk(child)

    for root in (deps.SERVER_POLICY, deps.WEB_PROTECTION_PROFILE):
        walk(root)
    for key, spec in wa.KINDS.items():
        if key == "scripting":
            continue      # reachable from the policy, not a WPP child
        assert spec["urn"] in seen, key


# --- byte fidelity ----------------------------------------------------------
def test_trim_device_tail_drops_junk_but_keeps_a_real_newline():
    assert wa.trim_device_tail("<!ELEMENT a>\n�\x13") == "<!ELEMENT a>\n"
    # A file that legitimately ends with a newline must keep it: eating it makes
    # every round-trip lossy in a way the FIRST hop still looks perfect after.
    assert wa.trim_device_tail("body\n") == "body\n"
    assert wa.trim_device_tail("") == ""


def test_decode_json_survives_the_dtd_reads_invalid_byte():
    """httpx's .json() raises UnicodeDecodeError here, which turns a WORKING
    endpoint into an apparently dead one over two bytes of firmware junk."""
    body = b'{"results": {"file_content": "<!ELEMENT a>\\n\xf1\x13"}}'
    with pytest.raises(UnicodeDecodeError):
        body.decode("utf-8")
    got = wa._decode_json(body)
    assert got["results"]["file_content"].startswith("<!ELEMENT a>")


def test_fetch_openapi_does_not_double_blank_lines():
    """htmlArray elements already carry their newline. Joining on "\\n" without
    stripping doubles every line break — the YAML still parses and is not the
    same document."""
    c = FakeClient(reads={"openapi.schemafileview":
                          {"results": {"htmlArray": ["info:\n", "  title: x\n"]}}})
    blob, err = wa.fetch(c, "openapi", "a.json")
    assert err == "" and blob == b"info:\n  title: x"


def test_fetch_trims_the_dtd_tail():
    c = FakeClient(reads={"xmldtdfile": {"results": {"file_content": "<!ELEMENT a>\n�"}}})
    blob, _ = wa.fetch(c, "xml_dtd", "d")
    assert blob == b"<!ELEMENT a>\n"


def test_fetch_on_an_unreadable_kind_never_touches_the_device():
    """The three unreadable kinds are refused from the catalogue, not by asking:
    six request shapes were measured returning -20005, and re-issuing them per
    clone adds latency to every plan for a certain failure."""
    c = FakeClient()
    for kind in sorted(wa.UNREADABLE):
        blob, err = wa.fetch(c, kind, "x")
        assert blob is None and "cannot be read back" in err
    assert c.calls == []


# --- push -------------------------------------------------------------------
def test_push_sends_the_object_name_as_the_multipart_filename():
    c = FakeClient()
    ok, err = wa.push(c, "xml_schema", "xsd-order", b"<xs:schema/>")
    assert ok and err == ""
    path, files, data = c.uploads[0]
    assert path == "/api/v2.0/waf/xmlprotection.xmlschemafile"
    assert files["xmlfile"][0] == "xsd-order"
    assert files["xmlfile"][1] == b"<xs:schema/>"
    assert data is None


def test_push_json_schema_carries_name_and_version_fields():
    """JSON Schema is the one kind that does NOT take its name from the
    filename; without these two form fields the device answers -61."""
    c = FakeClient()
    assert wa.push(c, "json_schema", "json-order", b"{}") == (True, "")
    _p, _f, data = c.uploads[0]
    assert data == {"json-schema-version": "auto-identify", "name": "json-order"}


def test_push_scripting_writes_the_body_before_the_cmdb_object():
    """Order is load-bearing: the cmdb object may only name a script body that
    already exists."""
    c = FakeClient()
    assert wa.push(c, "scripting", "s1", b"when HTTP_REQUEST {}", vdom="root") == (True, "")
    methods = [(m, p.split("?")[0]) for m, p, _d in c.calls]
    assert methods == [("PUT", "/api/v2.0/policy/policy.scripting.text"),
                       ("POST", "/api/v2.0/cmdb/server-policy/scripting")]
    assert "vdom=root" in c.calls[0][1]


def test_push_reports_a_device_errcode_instead_of_claiming_success():
    c = FakeClient(ok=False)
    ok, err = wa.push(c, "grpc_idl", "idl", b"syntax = \"proto3\";")
    assert ok is False and "-3000" in err


def test_openapi_name_without_a_known_extension_is_flagged():
    """The device answers -20007 for those, and because the name IS the
    filename a clone that renames an OpenAPI object breaks it."""
    assert wa.name_warning("openapi", "oas-partner") != ""
    assert wa.name_warning("openapi", "oas-partner.txt") != ""
    assert wa.name_warning("openapi", "oas-partner.json") == ""
    assert wa.name_warning("openapi", "oas-partner.yaml") == ""
    # Only OpenAPI validates its name; flagging the rest would be noise.
    assert wa.name_warning("xml_schema", "xsd-order") == ""


# --- plan integration -------------------------------------------------------
def test_plan_artifacts_finds_objects_and_ignores_subrows():
    items = [_root(),
             _item(XSD_URN, "xsd-order"),
             _item(DTD_URN, "dtd-order", kind="subrow"),
             _item("cmdb/server-policy/server-pool", "pool-x")]
    rows = wa.plan_artifacts(items)
    assert [(r["kind"], r["name"]) for r in rows] == [("xml_schema", "xsd-order")]


def test_plan_artifacts_prefers_create_over_a_duplicate_that_exists():
    """One plan can reach the same schema twice (two rules sharing it). The
    copy is needed if ANY occurrence needs it."""
    items = [_item(XSD_URN, "s", status="exists"), _item(XSD_URN, "s", status="create")]
    assert wa.plan_artifacts(items)[0]["status"] == "create"


def test_unresolvable_artifact_is_skipped_not_created_empty():
    items = [_root(), _item(XSD_URN, "xsd-order")]
    blobs, missing = policy_ops._resolve_artifacts(items, _ctx(), dry_run=True)
    assert blobs == {} and len(missing) == 1
    assert items[1].status == "no-content"
    assert "EMPTY" in items[1].note


def test_real_apply_refuses_before_any_write_when_not_accepted():
    items = [_root(), _item(XSD_URN, "xsd-order")]
    with pytest.raises(RuntimeError) as e:
        policy_ops._resolve_artifacts(items, _ctx(), dry_run=False)
    assert "xsd-order" in str(e.value) and "EMPTY" in str(e.value)


def test_dry_run_never_refuses_so_the_preview_can_warn():
    """A preview that cannot be produced is a preview that cannot warn — the
    operator would see an error instead of the choice they are being asked to
    make."""
    items = [_root(), _item(XSD_URN, "xsd-order")]
    blobs, missing = policy_ops._resolve_artifacts(items, _ctx(), dry_run=True)
    assert missing and blobs == {}


def test_accepting_lets_the_real_apply_proceed():
    items = [_root(), _item(XSD_URN, "xsd-order")]
    blobs, missing = policy_ops._resolve_artifacts(
        items, _ctx(accept_missing=True), dry_run=False)
    assert len(missing) == 1 and items[1].status == "no-content"


def test_push_artifact_helper_uploads_without_a_cmdb_create():
    ops = FakeOps()
    item = _item(XSD_URN, "xsd-order")
    policy_ops._push_artifact(ops, item, "xml_schema", b"<xs:schema/>", {})
    assert ops.calls == []                      # no cmdb create
    assert ops.client.uploads[0][1]["xmlfile"][1] == b"<xs:schema/>"


def test_clone_uploads_the_artifact_and_never_posts_its_cmdb_object():
    """Driven through ``clone_policy``, not through the helper.

    The helper being correct proves nothing on its own: what stops the empty
    shell is the EARLY RETURN in ``_write`` after the upload. Testing only the
    helper leaves that return unguarded, and falling through to ``ops.create``
    would post ``{"name": …}`` over the file that was just uploaded."""
    js_urn = wa.KINDS["json_schema"]["urn"]
    items = [_root(), _item(js_urn, "json-order", label="JSON Schema File")]
    ops = FakeOps()
    src = FakeClient(reads={"jsonschemafile": {"results": {"buf": "{\"a\":1}"}}})
    out = policy_ops.clone_policy(FakePlanner(items), ops, "pol", new_name="pol2",
                                  dry_run=False, artifacts=_ctx(src_client=src))
    # The file went up as multipart...
    assert ops.client.uploads[0][1]["jsonfile"][1] == b'{"a":1}'
    # ...and NOTHING posted its cmdb object.
    assert not any("json-schema" in (c[1] or "") for c in ops.calls), ops.calls
    art = [i for i in out if i.urn == js_urn][0]
    assert art.applied is True and art.result == "created"


def test_artifact_kind_is_not_claimed_when_the_feature_is_off():
    """Legacy callers pass no context; they must keep the old path exactly."""
    item = _item(XSD_URN, "x")
    assert policy_ops._artifact_kind(item, None) == ""
    assert policy_ops._artifact_kind(item, {"enabled": False}) == ""
    assert policy_ops._artifact_kind(item, _ctx()) == "xml_schema"


def test_store_read_failure_is_not_reported_as_a_missing_file(monkeypatch):
    """"No copy held" and "the store could not be read" lead to opposite
    actions. Collapsing them tells an operator to upload a file they already
    uploaded, which is how a broken index gets diagnosed as a missing artifact.
    Called with no Flask app context, which is exactly how the ORM fails."""
    blob, origin, err = wa.resolve("xml_schema", "xsd-order", 7)
    assert blob is None and origin == ""
    assert "could not be read" in err

    _blob, _origin, reason = wa.content_for("xml_schema", "xsd-order",
                                            source_appliance_id=7)
    assert "could not be read" in reason


def test_content_for_says_no_copy_when_the_store_is_readable_and_empty(monkeypatch):
    monkeypatch.setattr(wa, "resolve", lambda *a, **k: (None, "", ""))
    _b, _o, reason = wa.content_for("wsdl", "wsdl-orders")
    assert "cannot be read back" in reason and "could not be read" not in reason


def test_content_for_prefers_the_source_device_over_a_stored_copy(monkeypatch):
    """A stored copy is a snapshot of some earlier moment. Silently preferring
    it would clone a version of the schema that no longer exists on the box."""
    monkeypatch.setattr(wa, "resolve", lambda *a, **k: (b"OLD", "store", ""))
    c = FakeClient(reads={"jsonschemafile": {"results": {"buf": "NEW"}}})
    blob, origin, _r = wa.content_for("json_schema", "j", src_client=c)
    assert blob == b"NEW" and "source device" in origin


# --- summary + migrate safety ----------------------------------------------
def test_clone_summary_counts_no_content_apart_from_failures():
    items = [_root(), _item(XSD_URN, "s", status="no-content")]
    items[1].result = "no-content"
    s = policy_ops.clone_summary(items)
    assert s["no_content"] == 1
    assert s["failed"] == 0          # an accepted skip is a decision, not a defect
    assert s["skipped"] >= 1


def test_migrate_keeps_the_source_enabled_when_an_artifact_was_skipped():
    """THE invariant. ``failed == 0`` does not cover this: the referencing rule
    only fails when it is itself in the plan, and it is not when the
    destination already has it — so without this check a migrate would disable
    a working policy in favour of a copy that enforces less."""
    root, art = _root(), _item(XSD_URN, "xsd-order")
    planner, dst_ops, src_ops = FakePlanner([root, art]), FakeOps(), FakeOps("src")
    out = policy_ops.migrate_policy(
        planner, dst_ops, src_ops, "pol", new_name="pol2", dry_run=False,
        artifacts=_ctx(accept_missing=True))
    assert out["summary"]["no_content"] == 1
    assert out["source_disabled"] is False
    assert "left ENABLED" in out["source_kept_reason"]
    assert not any(c[0] == "update" for c in src_ops.calls)


def test_migrate_still_disables_the_source_on_a_complete_clone():
    """The guard above must not have turned migrate into a no-op."""
    root = _root()
    planner, dst_ops, src_ops = FakePlanner([root]), FakeOps(), FakeOps("src")
    out = policy_ops.migrate_policy(planner, dst_ops, src_ops, "pol",
                                    new_name="pol2", dry_run=False)
    assert out["summary"]["no_content"] == 0
    assert out["source_disabled"] is True


# --- the pre-flight gate ----------------------------------------------------
def _rows(**kw):
    base = {"kind": "xml_schema", "name": "xsd-order", "label": "XML Schema (XSD)",
            "urn": XSD_URN, "status": "create", "readable": False,
            "name_warning": "", "resolved": False, "origin": "", "reason": "",
            "size": 0}
    base.update(kw)
    return [base]


def test_gate_says_nothing_to_check_rather_than_success():
    chk, sg = policy_ops._artifact_gate([], dest_name="d", accepted=False)
    assert chk["level"] == "ok" and "No file-backed objects" in chk["label"]
    assert sg["artifacts_need_ack"] is False


def test_gate_is_ok_when_every_artifact_resolves():
    chk, sg = policy_ops._artifact_gate(
        _rows(resolved=True, origin="the SATOM artifact library", size=12),
        dest_name="d", accepted=False)
    assert chk["level"] == "ok" and sg["artifacts_need_ack"] is False


def test_gate_warns_and_demands_acknowledgement_when_content_is_missing():
    chk, sg = policy_ops._artifact_gate(_rows(), dest_name="fwb2", accepted=False)
    assert chk["level"] == "warn"
    assert sg["artifacts_need_ack"] is True
    assert "-651" in chk["detail"] and "SKIPPED" in chk["detail"]


def test_gate_never_blocks():
    """Product decision: the operator is shown the consequence and chooses."""
    for accepted in (False, True):
        chk, _ = policy_ops._artifact_gate(_rows(), dest_name="d", accepted=accepted)
        assert chk["level"] != "block"


def test_gate_stays_warn_after_acceptance():
    """A checklist that turns green because someone ticked a box has stopped
    describing the device."""
    chk, sg = policy_ops._artifact_gate(_rows(), dest_name="d", accepted=True)
    assert chk["level"] == "warn"
    assert chk["label"].startswith("ACCEPTED")
    assert sg["artifacts_need_ack"] is True


def test_gate_reports_objects_already_on_the_destination_instead_of_hiding_them():
    chk, sg = policy_ops._artifact_gate(
        _rows(status="exists", resolved=True), dest_name="fwb2", accepted=False)
    assert chk["level"] == "ok" and "already on fwb2" in chk["label"]
    assert sg["artifacts_need_ack"] is False
