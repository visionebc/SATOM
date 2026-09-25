"""The API versions page, read from the API library (SATOM 2.2.0).

What these guard is silent when it breaks. A retired box's evidence that drops
off the page leaves a table that still renders — with one build fewer. A
FortiGate page that builds the whole matrix document still renders — seconds
later. A comparison that files "never measured" under "removed" still renders
— and tells an operator that an upgrade deletes an endpoint it does not.
"""
from __future__ import annotations

import re

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import api_library as lib
from app.services import api_matrix as am
from app.views import _apiversions as V
from tests.conftest import admin_user_id, login

PAGE = "/web/registry/versions"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _box(name, firmware, kind="fortiweb"):
    a = Appliance(name=name, kind=kind, host="%s.test" % name, port=443,
                  username="admin", verify_ssl=False, firmware=firmware)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _ep(verdict="ok", fields=None, urn="/api/v2.0/cmdb/x"):
    return {"urn": urn, "section": "S", "verdict": verdict, "rows": None, "fields": fields}


def _sweep(version, endpoints, device, appliance_id=None, product="fortiweb"):
    return lib.ingest({
        "product": product, "source": "sweep", "captured_at": "2026-09-01T00:00:00",
        "origin_ref": "test:%s@%s" % (device, version),
        "device": {"appliance_id": appliance_id, "name": device, "serial": "",
                   "model": "", "hw_type": "vm", "firmware_raw": version},
        "scope": {"kind": "build", "version": version, "build": ""},
        "healthy": True, "skip_reason": "", "endpoints": endpoints,
    })


def _fortigate(versions=("7.4.4", "7.6.0", "7.6.4")):
    """A small vendor catalogue with one field that arrives and one that goes."""
    return lib.ingest({
        "product": "fortigate", "source": "vendor_doc", "captured_at": "2026-01-01",
        "origin_ref": "ansible:fortinet.fortios:9.9.9", "device": None,
        "scope": {"kind": "spans", "versions": list(versions)},
        "healthy": True, "skip_reason": "",
        "endpoints": {
            "firewall_policy": {
                "urn": "/api/v2/cmdb/firewall/policy", "section": "firewall",
                "rows": None, "spans": [[versions[0], ""]],
                "fields": {"name": {"type": "string", "spans": [[versions[0], ""]]},
                           "fresh": {"type": "integer", "spans": [["7.6.0", ""]]},
                           "gone": {"type": "string", "spans": [[versions[0], "7.4.4"]]}}},
            "system_old": {"urn": "/api/v2/cmdb/system/old", "section": "system",
                           "rows": None, "spans": [[versions[0], "7.4.4"]],
                           "fields": {"a": {"type": "string"}}},
        },
        "summary": {"min_version": versions[0], "max_version": versions[-1]},
    })


def _get(client, app, url):
    login(client, admin_user_id(app))
    r = client.get(url)
    assert r.status_code == 200, r.get_data(as_text=True)[:2000]
    return r.get_data(as_text=True)


def _section(body, element_id):
    """One element's markup, bounded by its own closing table/div.

    A page-level ``in body`` is satisfied by the selector, a tooltip or the
    other card, which is the false pass this repository keeps paying for.
    """
    i = body.find('id="%s"' % element_id)
    assert i != -1, "no element %s on the page" % element_id
    end = body.find("</table>", i)
    return body[i:end if end != -1 else len(body)]


@pytest.fixture()
def spy_matrix_doc(monkeypatch):
    calls = []
    real = lib.matrix_doc

    def spy(product, versions=None):
        calls.append((product, versions))
        return real(product, versions=versions)

    monkeypatch.setattr(lib, "matrix_doc", spy)
    return calls


# --------------------------------------------------------------------------
# retired devices keep their evidence — on the page, not only in the table
# --------------------------------------------------------------------------

def test_a_retired_devices_build_is_still_on_the_page(app, client, session):
    """fortiweb16/17 measured 8.0.3 and were deleted; the file store dropped
    their build. The library keeps it, and the builds table lists it with the
    retired box as its witness."""
    live = _box("fw-live", "7.6.8")
    _sweep("7.6.8", {"admin": _ep(fields={"name": {}})}, "fw-live", live.id)
    _sweep("8.0.3", {"admin": _ep(fields={"name": {}, "fortiai": {}})}, "fw-gone", 9999)
    body = _get(client, app, PAGE)
    table = _section(body, "fwVersions")
    row = re.search(r"<tr>\s*<td><code>8\.0\.3</code>.*?</tr>", table, re.S)
    assert row, "the retired device's build vanished from the builds table"
    assert "fw-gone" in row.group(0)
    assert "measured" in row.group(0)
    assert "in fleet" not in row.group(0), "nothing in the fleet runs 8.0.3 today"


def test_the_builds_table_carries_the_library_columns(app, client, session):
    live = _box("fw-live", "7.6.8")
    _sweep("7.6.8", {"admin": _ep(fields={"name": {}})}, "fw-live", live.id)
    table = _section(_get(client, app, PAGE), "fwVersions")
    row = re.search(r"<tr>\s*<td><code>7\.6\.8</code>.*?</tr>", table, re.S).group(0)
    cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
    assert ">sweep<" in cells[2], "the source the build rests on is not named"
    assert "in fleet" in cells[2]
    assert cells[3].strip() == "1", "evidence count: one sweep document"
    assert re.search(r"\d{4}-\d\d-\d\d", cells[10]), "first/last seen missing"


# --------------------------------------------------------------------------
# FortiGate: every product is selectable, and the big one stays fast
# --------------------------------------------------------------------------

def test_the_selector_offers_every_library_product(app, client, session):
    sel = _get(client, app, PAGE)
    i = sel.find('id="apilibProducts"')
    block = sel[i:sel.find("</div>", i)]
    for p in lib.PRODUCTS:
        if p != "fortiweb":
            assert "product=%s" % p in block, "no way to reach %s's library" % p
    assert "product=fortiweb" not in block, \
        "the mount's own product is the page default and never spelled out"


def test_the_fortigate_page_renders_without_the_whole_matrix(app, client, session,
                                                              spy_matrix_doc):
    _fortigate()
    body = _get(client, app, PAGE + "?product=fortigate")
    assert spy_matrix_doc == [], \
        "the FortiGate page built a matrix document: %r" % spy_matrix_doc
    builds = _section(body, "apilibBuilds")
    for v in ("7.4.4", "7.6.0", "7.6.4"):
        assert "<code>%s</code>" % v in builds
    assert "vendor only" in builds
    assert "apilib-vendor" in builds, "vendor_doc provenance not labelled"
    # none of the matrix-backed half: it describes appliances FortiGate lacks
    assert 'id="fwVersions"' not in body and 'id="versionDelta"' not in body


def test_a_default_fortigate_comparison_labels_vendor_provenance(app, client, session):
    _fortigate()
    body = _get(client, app, PAGE + "?product=fortigate&base=7.4.4&target=7.6.4")
    changes = _section(body, "apilibEndpointChanges")
    assert "system_old" in changes and "removed" in changes
    assert "apilib-vendor" in changes
    fields = _section(body, "apilibFieldChanges")
    row = re.search(r"<tr><td><a[^>]*><code>firewall_policy</code>.*?</tr>", fields, re.S)
    assert row, "the field delta of firewall_policy is missing"
    assert "fresh" in row.group(0) and "gone" in row.group(0)
    assert "vendor_doc" in row.group(0)


def test_the_default_library_pair_is_the_two_newest_measured_builds():
    rows = [{"version": v, "measured": m, "line_only": lo}
            for v, m, lo in (("7.4.4", True, False), ("7.6", True, True),
                             ("7.6.0", True, False), ("7.6.4", True, False),
                             ("7.6.9", False, False))]
    assert V._lib_pick(rows) == ("7.6.0", "7.6.4")
    assert V._lib_pick(rows[:1]) == ("", "")


def test_the_three_build_statuses_are_distinct():
    assert V._build_status({"vendor_only": True, "measured": True}) == "vendor_only"
    assert V._build_status({"vendor_only": False, "measured": True}) == "measured"
    assert V._build_status({"vendor_only": False, "measured": False}) == "unmeasured"


def test_a_scoped_preflight_never_builds_every_build(app, session, spy_matrix_doc):
    """``api_matrix`` answering one question about FortiGate must ask the
    library for the builds that question reads, never for all of them."""
    _fortigate()
    out = am.preflight("fortigate", "7.6.4", "firewall_policy", ["name"])
    assert out["status"] == am.STATUS_OK
    assert spy_matrix_doc and all(v for _p, v in spy_matrix_doc), spy_matrix_doc
    assert set(spy_matrix_doc[0][1]) == {"7.6.0", "7.6.4"}
    d = am.diff("fortigate", "7.4.4", "7.6.4")
    assert [r["endpoint"] for r in d["endpoints_removed"]] == ["system_old"]
    assert d["fields_changed"][0]["origin"] == "vendor_doc", \
        "a vendor field delta must not be labelled as a sweep"
    assert all(v for _p, v in spy_matrix_doc)


def test_an_unnamed_scope_is_not_a_request_for_everything(app, session, spy_matrix_doc):
    _fortigate()
    assert am.preflight("fortigate", "", "x", [])["status"] == am.STATUS_UNMEASURED
    assert spy_matrix_doc == []


# --------------------------------------------------------------------------
# unknown is never removed
# --------------------------------------------------------------------------

def test_the_comparison_keeps_unknown_apart_from_removed(app, client, session):
    _sweep("7.6.8", {"kept": _ep(fields={"a": {}}), "gone": _ep(),
                     "onlybase": _ep()}, "boxA", 1001)
    _sweep("8.0.5", {"kept": _ep(fields={"a": {}, "b": {"type": "str"}}),
                     "gone": _ep("absent")}, "boxB", 1002)
    body = _get(client, app, PAGE + "?base=7.6.8&target=8.0.5")
    changes = _section(body, "apilibEndpointChanges")
    assert "<code>gone</code>" in changes
    assert "onlybase" not in changes, "a side nobody measured was reported as a change"
    unknown = _section(body, "apilibUnknownEndpoints")
    assert "<code>onlybase</code>" in unknown
    assert "not measured" in unknown
    totals = body[body.find('id="apilibTotals"'):]
    totals = totals[:totals.find("</div>")]
    assert "endpoints removed: 1" in re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", totals))
    assert "endpoints unknown: 1" in re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", totals))
    fields = _section(body, "apilibFieldChanges")
    assert "<code>kept</code>" in fields and "b" in fields


def test_fields_known_on_one_side_only_are_unknown_not_removed(app, client, session):
    _sweep("7.6.8", {"blindside": _ep(fields={"a": {}, "b": {}})}, "boxA", 1001)
    _sweep("8.0.5", {"blindside": _ep(fields=None)}, "boxB", 1002)
    body = _get(client, app, PAGE + "?base=7.6.8&target=8.0.5")
    assert 'id="apilibFieldChanges"' not in body, \
        "a blind side was subtracted into a field removal"
    unknown = _section(body, "apilibUnknownFields")
    assert "<code>blindside</code>" in unknown
    assert "one side only" in unknown


# --------------------------------------------------------------------------
# the drill-down
# --------------------------------------------------------------------------

def test_the_drill_down_lists_fields_and_answers_since_which_build(app, client, session):
    _sweep("7.6.8", {"admin": _ep(fields={"name": {"type": "str"}})}, "boxA", 1001)
    _sweep("8.0.5", {"admin": _ep(fields={"name": {"type": "str"},
                                          "fortiai": {"type": "str"}})}, "boxB", 1002)
    body = _get(client, app, PAGE + "?ep=admin&at=8.0.5&field=fortiai")
    fields = _section(body, "apilibFields")
    assert "<code>fortiai</code>" in fields and "<code>name</code>" in fields
    assert "since which build?" in fields
    i = body.find('id="apilibHistory"')
    hist = body[i:body.find("</table>", i)]
    assert re.search(r'apilib-first">8\.0\.5<', hist), "fortiai first appears on 8.0.5"
    assert 'apilib-fstatus">measured<' in body


def test_a_blind_endpoint_is_not_shown_as_having_no_fields(app, client, session):
    _sweep("8.0.5", {"empty": _ep(fields=None)}, "boxB", 1002)
    body = _get(client, app, PAGE + "?ep=empty&at=8.0.5")
    assert 'apilib-fstatus"' in body
    assert re.search(r'apilib-fstatus"[^>]*>blind<', body)
    assert 'id="apilibFields"' not in body


def test_an_unknown_product_falls_back_to_the_mount(app, client, session):
    body = _get(client, app, PAGE + "?product=nonsense")
    assert 'id="fwVersions"' in body
