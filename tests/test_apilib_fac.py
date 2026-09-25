"""FortiAuthenticator schema harvest -> API library evidence document.

The fixture is a trimmed copy of a real capture from a FAC 8.0.3 build0099
(identity and row values scrubbed). It keeps one resource of every shape the
normaliser has to tell apart: a collection with rows, an empty collection, a
singleton whose schema crashes (500), POST-only actions (405, with and without
a schema), and refusals (403, 500 on the list itself).
"""
from __future__ import annotations

import copy
import json
import pathlib
from types import SimpleNamespace

import pytest

from app.services import apilib_fac as fac

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "apilib_fac_capture.json"

DEVICE = {"appliance_id": 7, "name": "fac-test", "serial": "FACVMTEST000000",
          "model": "FortiAuthenticator-FACVMKVM", "hw_type": "vm",
          "firmware_raw": "FACVMKVM v8.0.3, build0099 (GA)"}


@pytest.fixture
def capture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def doc(capture):
    return fac.evidence_from_capture(capture, DEVICE)


# --------------------------------------------------------------------------- #
#  Document envelope                                                           #
# --------------------------------------------------------------------------- #
def test_envelope_matches_the_ingest_contract(doc, capture):
    assert doc["product"] == "fortiauthenticator"
    assert doc["source"] == "schema"
    assert doc["scope"] == {"kind": "build", "version": "8.0.3", "build": "build0099"}
    assert doc["origin_ref"] == "live:fac-test:/api/v1/"
    assert doc["captured_at"] == capture["captured_at"]
    assert doc["healthy"] is True and doc["skip_reason"] == ""
    assert doc["device"]["serial"] == "FACVMTEST000000"
    assert doc["device"]["appliance_id"] == 7
    json.dumps(doc, sort_keys=True)  # must be hashable as canonical JSON


def test_device_block_is_not_mutated(capture):
    dev = dict(DEVICE, firmware_raw="stale")
    fac.evidence_from_capture(capture, dev)
    assert dev["firmware_raw"] == "stale"


def test_live_firmware_wins_over_a_stale_inventory_row(capture):
    d = fac.evidence_from_capture(capture, dict(DEVICE, firmware_raw="FACVMKVM v6.6.1, build1234"))
    assert d["scope"]["version"] == "8.0.3"
    assert d["scope"]["build"] == "build0099"
    assert d["device"]["firmware_raw"] == "FACVMKVM v8.0.3, build0099 (GA)"


def test_row_firmware_used_when_systeminfo_did_not_answer(capture):
    del capture["responses"]["/api/v1/systeminfo/?limit=1"]
    d = fac.evidence_from_capture(capture, dict(DEVICE, firmware_raw="8.0.4,build0120"))
    assert d["scope"] == {"kind": "build", "version": "8.0.4", "build": "build0120"}


def test_unresolvable_firmware_is_unhealthy(capture):
    del capture["responses"]["/api/v1/systeminfo/?limit=1"]
    d = fac.evidence_from_capture(capture, dict(DEVICE, firmware_raw=""))
    assert d["healthy"] is False and "firmware" in d["skip_reason"]


def test_failed_directory_claims_nothing(capture):
    capture["responses"]["/api/v1/"] = {"status": None, "json": None,
                                        "error": "ConnectTimeout: timed out"}
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["healthy"] is False
    assert d["endpoints"] == {}      # nothing may be called absent
    assert "ConnectTimeout" in d["skip_reason"]


def test_error_ratio_over_a_quarter_is_unhealthy(capture):
    for url, r in capture["responses"].items():
        if url.endswith("?limit=1") and "systeminfo" not in url:
            r.update(status=403, json=None, error="403 forbidden")
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["healthy"] is False and "errored" in d["skip_reason"]


# --------------------------------------------------------------------------- #
#  Names and verdicts                                                          #
# --------------------------------------------------------------------------- #
def test_every_directory_resource_is_recorded_under_registry_or_derived_name(doc):
    assert set(doc["endpoints"]) == {
        "auth_user_groups", "radius_clients", "system_info", "auth_iam_accounts",
        "auth", "csv", "emergencytoken", "recovery"}
    assert doc["endpoints"]["auth_user_groups"]["urn"] == "/api/v1/usergroups/"
    assert doc["endpoints"]["auth_user_groups"]["section"] == "auth"
    assert doc["endpoints"]["auth_user_groups"]["registered"] is True
    assert doc["endpoints"]["auth"]["section"] == "other"
    assert doc["endpoints"]["auth"]["registered"] is False
    assert doc["endpoints"]["auth"]["urn"] == "/api/v1/auth/"


def test_derived_name_never_overwrites_a_registry_name(capture):
    # A registry name equal to an unregistered resource's derived name, bound
    # to a different URN, must survive untouched.
    capture["registry"]["csv"] = "/api/v1/usergroups-old/"
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["endpoints"]["csv"]["urn"] == "/api/v1/usergroups-old/"
    assert d["endpoints"]["csv"]["verdict"] == "absent"
    assert d["endpoints"]["csv_res"]["urn"] == "/api/v1/csv/"


def test_verdicts(doc):
    v = {n: e["verdict"] for n, e in doc["endpoints"].items()}
    assert v == {"auth_user_groups": "ok", "radius_clients": "ok",
                 "system_info": "ok", "auth_iam_accounts": "ok",
                 "auth": "ok",            # 405: POST-only, still served
                 "emergencytoken": "ok",  # 405 and schema 500
                 "csv": "error",          # 403
                 "recovery": "error"}     # 500 on the list
    assert doc["endpoints"]["csv"]["error"].startswith("403")


def test_registry_endpoint_missing_from_directory_is_absent(capture):
    capture["registry"]["auth_gone"] = "/api/v1/goneresource/"
    d = fac.evidence_from_capture(capture, DEVICE)
    ep = d["endpoints"]["auth_gone"]
    assert ep["verdict"] == "absent"
    assert ep["fields"] is None and ep["rows"] is None
    assert ep["section"] == "auth"


def test_404_on_the_list_is_absent(capture):
    capture["responses"]["/api/v1/usergroups/?limit=1"] = {
        "status": 404, "json": None, "error": "HTTP 404: not found"}
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["endpoints"]["auth_user_groups"]["verdict"] == "absent"


def test_transport_failure_is_error_not_absent(capture):
    capture["responses"]["/api/v1/usergroups/?limit=1"] = {
        "status": None, "json": None, "error": "ReadTimeout: timed out"}
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["endpoints"]["auth_user_groups"]["verdict"] == "error"


# --------------------------------------------------------------------------- #
#  Rows and fields                                                             #
# --------------------------------------------------------------------------- #
def test_rows_come_from_total_count_not_the_page(doc):
    eps = doc["endpoints"]
    assert eps["radius_clients"]["rows"] == 3        # page held 1 object
    assert eps["auth_iam_accounts"]["rows"] == 0
    assert eps["system_info"]["rows"] == 1           # singleton
    assert eps["auth"]["rows"] is None               # not readable
    assert eps["csv"]["rows"] is None


def test_schema_fields_and_required_rule(doc):
    f = doc["endpoints"]["auth_user_groups"]["fields"]
    assert set(f) == {"id", "name", "password_policy", "resource_uri", "users"}
    assert f["name"] == {"type": "string", "options": None, "default": None,
                         "required": True}
    assert f["id"]["required"] is False              # blank primary key
    assert f["resource_uri"]["required"] is False    # readonly
    assert f["users"]["required"] is False           # nullable
    assert f["users"]["type"] == "related"
    assert f["password_policy"]["default"] == "Default"
    assert f["password_policy"]["required"] is False  # has a default
    assert doc["endpoints"]["auth_user_groups"]["field_origin"] == "schema"


def test_blank_alone_makes_a_field_optional(capture):
    # Tastypie's hydrate skips an omitted ``blank`` field even with no default
    # and null disallowed, so blank on its own must clear ``required``.
    spec = capture["responses"]["/api/v1/usergroups/schema/"]["json"]["fields"]["name"]
    assert spec["default"] == fac.NO_DEFAULT and not spec["nullable"]
    spec["blank"] = True
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["endpoints"]["auth_user_groups"]["fields"]["name"]["required"] is False


def test_empty_collection_still_has_schema_fields(doc):
    ep = doc["endpoints"]["auth_iam_accounts"]
    assert ep["rows"] == 0
    assert ep["fields"] and ep["field_origin"] == "schema"


def test_choices_become_options(capture):
    spec = capture["responses"]["/api/v1/usergroups/schema/"]["json"]["fields"]["password_policy"]
    spec["choices"] = [["Default", "Default policy"], ["Strict", "Strict policy"]]
    d = fac.evidence_from_capture(capture, DEVICE)
    assert d["endpoints"]["auth_user_groups"]["fields"]["password_policy"]["options"] == [
        "Default", "Strict"]


def test_schema_500_singleton_takes_fields_from_its_row(doc):
    ep = doc["endpoints"]["system_info"]
    assert ep["schema_status"] == 500
    assert ep["field_origin"] == "row"
    assert ep["fields"]["firmware"] == {"type": "string", "options": None,
                                        "default": None, "required": None}
    assert ep["fields"]["users_usage_detail"]["type"] == "dict"


def test_action_without_schema_is_blind_not_empty(doc):
    ep = doc["endpoints"]["emergencytoken"]
    assert ep["fields"] is None       # blind, never {}


def test_action_with_schema_keeps_fields_and_methods(doc):
    ep = doc["endpoints"]["auth"]
    assert ep["fields"] and ep["field_origin"] == "schema"
    assert "get" not in ep["methods"]["list"]


def test_row_cross_check_records_write_only_fields(doc):
    rc = doc["endpoints"]["radius_clients"]["row_check"]
    assert rc == {"missing_in_row": ["secret"], "extra_in_row": []}
    assert "secret" in doc["endpoints"]["radius_clients"]["fields"]


def test_undeclared_row_key_is_added_as_a_field(capture):
    obj = capture["responses"]["/api/v1/usergroups/?limit=1"]["json"]["objects"][0]
    obj["new_field"] = True
    d = fac.evidence_from_capture(capture, DEVICE)
    ep = d["endpoints"]["auth_user_groups"]
    assert ep["fields"]["new_field"]["type"] == "boolean"
    assert ep["row_check"]["extra_in_row"] == ["new_field"]
    assert ep["field_origin"] == "schema+row"


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("err,status", [
    ("405 method not allowed — this resource ...", 405),
    ("403 forbidden — the API key ...", 403),
    ("401 unauthorized — FortiAuthenticator ...", 401),
    ('HTTP 500: {"error_message": "x"}', 500),
    ("ConnectTimeout: timed out", None),
    ("unparseable response body: '<html>'", None),
    (None, None),
])
def test_status_from_error(err, status):
    assert fac.status_from_error(err) == status


@pytest.mark.parametrize("raw,build", [
    ("FACVMKVM v8.0.3, build0099 (GA)", "build0099"),
    ("8.0.4,build120", "build0120"),
    ("FACVMKVM v8.0.3", ""),
    ("", ""),
])
def test_parse_build(raw, build):
    assert fac.parse_build(raw) == build


# --------------------------------------------------------------------------- #
#  Live path: GET only                                                         #
# --------------------------------------------------------------------------- #
class _RecordingClient:
    """Serves the fixture and records every verb the harvester used."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def api_call(self, method, path, data=None, **params):
        self.calls.append((method, path, data, params))
        r = self.responses.get(fac._url(path, **params))
        if r is None:
            return None, "HTTP 404: not in fixture"
        return r["json"], r["error"]


def test_harvest_only_issues_gets_and_matches_the_normaliser(capture):
    client = _RecordingClient(capture["responses"])
    appliance = SimpleNamespace(**{k: DEVICE[k] for k in ("name", "serial", "model", "hw_type")},
                                id=7, firmware=DEVICE["firmware_raw"])
    raw = {}
    d = fac.harvest(appliance, client=client, registry=capture["registry"], raw=raw)

    assert client.calls, "harvest made no requests"
    assert {c[0] for c in client.calls} == {"GET"}
    assert all(c[2] is None for c in client.calls)          # no bodies
    # Every request was one the fixture answers: nothing outside the plan.
    assert {fac._url(c[1], **c[3]) for c in client.calls} == set(capture["responses"])

    expected = fac.evidence_from_capture(dict(capture, captured_at=raw["captured_at"]), DEVICE)
    assert d == expected
    assert raw["responses"].keys() == capture["responses"].keys()


def test_fixture_names_no_internal_infrastructure():
    from app.services import doc_publication as pubdoc
    text = FIXTURE.read_text(encoding="utf-8")
    assert pubdoc.scan(text, FIXTURE.name) == []
    assert "visionebc" not in text.lower()
