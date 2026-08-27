"""Guards: the Fleet → WAF export bundle.

The properties this area has to hold, and why each one is a guard rather than
a code review note:

1. **Provenance travels with the data.** Every page under ``/waf/`` carries a
   scope-and-freshness banner because its figures are only as fresh as the last
   harvest. A spreadsheet in someone's mail has no banner, so the bundle has to
   carry the same four facts in the manifest, the workbook's first sheet and
   the PDF's first page — and a scope that never reported has to be NAMED, not
   folded into a denominator as a device with zero policies.

2. **Nothing selected is not an empty export.** A zero-content ZIP downloads
   perfectly happily and reads as "the fleet had nothing", which is a claim
   about the estate rather than about the form.

3. **The bundle is what THIS console may see.** Same rule as every other
   ``/waf/*`` page, and for the same reason: on ``/artifacts/*`` the services
   were correct the whole time the defect was live and it was the page that
   leaked (safeguards §122). These guards go through the ROUTE.

4. **Exceptions are desired state.** ``models.WppException`` has no column
   recording whether a carve-out was ever pushed, so no artefact in the bundle
   may imply that it was — and a scope with no snapshot answers *unknown*
   about its profiles, never *missing*.

5. **A chart that travels is its series, not a picture.** The drawing in the
   PDF and the (label, value) rows in the CSV/workbook come from ONE
   ``ChartSpec``; if they could drift, the export would ship a graph that
   disagrees with the numbers printed beside it.
"""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id
from tests.test_waf_fleet import _appl, _policy, _profile, _record, _snapshot

REPO = Path(__file__).resolve().parents[1]
CHASSIS = "192.0.2.1"


# ---------------------------------------------------------------------------
# fixture: a small fleet with every state the guards need to tell apart
# ---------------------------------------------------------------------------
def _exception(appliance_id, *, wpp, policies=(), exc_type="signature_exception_item",
               category="signature", name="", payload=None, author="tester"):
    from app import db
    from app.models import WppException, WppExceptionPolicy

    exc = WppException(
        appliance_id=appliance_id, wpp_mkey=wpp, category=category,
        exc_type=exc_type, name=name,
        payload=json.dumps(payload or {"signature_id": "060190001"}),
        reason="false positive on the ERP upload form", author=author)
    db.session.add(exc)
    db.session.flush()
    for pol in policies:
        db.session.add(WppExceptionPolicy(exception_id=exc.id, server_policy=pol))
    db.session.commit()
    return exc


def _artifact_edge(aid, policy, kind, name, wpp="wpp-a"):
    """One walked edge + its scan. Without these the artifacts dataset is
    EMPTY, and a guard whose body is a ``for`` over its rows asserts nothing
    while passing — which is how the policy-count guard first went vacuous."""
    from datetime import datetime

    from app import db
    from app.models_artifact_refs import WafArtifactRef, WafArtifactScan

    now = datetime.utcnow()
    db.session.add(WafArtifactRef(appliance_id=aid, policy_mkey=policy,
                                  kind=kind, name=name, wpp_mkey=wpp, urn="",
                                  derived_from="test", first_seen_at=now,
                                  seen_at=now))
    db.session.add(WafArtifactScan(appliance_id=aid, policy_mkey=policy,
                                   ok=True, error="", refs=1, scanned_at=now))
    db.session.commit()


def _artifact_blob(aid, kind, name, size=128):
    from datetime import datetime

    from app import db
    from app.models_artifacts import WafArtifact

    now = datetime.utcnow()
    db.session.add(WafArtifact(kind=kind, name=name, appliance_id=aid,
                               sha256="a" * 64, size=size, source="uploaded",
                               created_by="tester", created_at=now,
                               last_seen_at=now))
    db.session.commit()


@pytest.fixture()
def fleet(app):
    with app.app_context():
        wpp_a = _profile("wpp-a", on=("signature-rule", "bot-mitigate-policy"))
        wpp_b = _profile("wpp-b", on=("signature-rule",))
        web1 = _appl("web1", host=CHASSIS)
        _record(web1, _snapshot(
            [_policy("pol-1", **{"web-protection-profile": "wpp-a"}),
             _policy("pol-2", **{"web-protection-profile": "wpp-a",
                                 "ssl": "enable", "tls-v10": "enable",
                                 "certificate": "cert-1"})],
            inline=[wpp_a, wpp_b]))

        web2 = _appl("web2", host="192.0.2.2")
        _record(web2, _snapshot([_policy("pol-web2")],
                                inline=[_profile("wpp-web2", on=("signature-rule",))]))

        # Registered, NEVER harvested. Everything this scope is asked about has
        # to answer "unknown" — the whole point of guard 4.
        never = _appl("web-never", host="192.0.2.5")

        # Another product. Must be absent from every byte of the bundle.
        adc = _appl("adc1", host="192.0.2.3", kind="fortiadc", vdom=None)
        _record(adc, _snapshot([_policy("adc-secret-policy")]))

        # Two edges on one policy and a held copy for one of them, so the
        # artifacts dataset has both a "held" row and an unheld one.
        _artifact_edge(web1.id, "pol-1", "openapi", "api.yaml")
        _artifact_edge(web1.id, "pol-2", "xml_schema", "orders.xsd")
        _artifact_blob(web1.id, "openapi", "api.yaml")

        _exception(web1.id, wpp="wpp-a", policies=["pol-1"], name="exc-resolved")
        _exception(web1.id, wpp="wpp-ghost", policies=["pol-1"],
                   name="exc-dangling-profile")
        _exception(web1.id, wpp="wpp-a", policies=["pol-deleted"],
                   name="exc-dangling-policy")
        _exception(never.id, wpp="wpp-unknowable", policies=["whatever"],
                   name="exc-in-the-dark")
        _exception(adc.id, wpp="adc-profile", policies=["adc-secret-policy"],
                   name="exc-on-another-product")
        yield {"web1": web1.id, "web2": web2.id, "never": never.id,
               "adc": adc.id}


ALL_SETS = ("overview", "policies", "profiles", "coverage", "artifacts",
            "exceptions")


def _get(client, url, uid, product="fortiweb"):
    """Log in as *uid* and GET *url*, session CLEARED first.

    ``conftest.login`` writes ``_user_id`` over whatever is already in the
    session and flask-login keeps serving the FIRST identity, so a test that
    switches user mid-body silently re-asserts the previous one — which is how
    the control half of a permission guard passes for the wrong reason.
    """
    with client.session_transaction() as sess:
        sess.clear()
    login(client, uid, product=product)
    return client.get(url)


def _query(sets=ALL_SETS, fmts=("csv", "xlsx", "pdf"), **extra):
    parts = ["set=%s" % s for s in sets] + ["fmt=%s" % f for f in fmts]
    parts += ["%s=%s" % kv for kv in extra.items()]
    return "/waf/export?" + "&".join(parts)


def _bundle(client, uid, **kw):
    resp = _get(client, _query(**kw), uid)
    assert resp.status_code == 200, resp.status_code
    return zipfile.ZipFile(io.BytesIO(resp.get_data()))


def _name_ending(zf, suffix):
    hits = [n for n in zf.namelist() if n.endswith(suffix)]
    assert hits, "no %s in %s" % (suffix, zf.namelist())
    return hits[0]


def _csv_rows(zf, filename):
    raw = zf.read(_name_ending(zf, "csv/" + filename)).decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(raw)))


def _sheets(zf):
    """``{sheet name: [[cell, ...], ...]}`` read back out of the workbook.

    Deliberately parsed from the XML rather than trusted: the workbook is
    hand-written by ``services/xlsx_writer``, and a guard that asserts against
    the structure we handed the writer would pass even if the writer emitted a
    file Excel refuses to open.
    """
    import xml.etree.ElementTree as ET

    wb = zipfile.ZipFile(io.BytesIO(zf.read(_name_ending(zf, ".xlsx"))))
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    names = [el.get("name") for el in
             ET.fromstring(wb.read("xl/workbook.xml")).find("m:sheets", ns)]
    out = {}
    for i, name in enumerate(names, start=1):
        root = ET.fromstring(wb.read("xl/worksheets/sheet%d.xml" % i))
        rows = []
        for row in root.iter("{%s}row" % ns["m"]):
            rows.append(["".join(t.text or "" for t in c.iter("{%s}t" % ns["m"]))
                         for c in row])
        out[name] = rows
    return names, out


def _pdf_text(zf) -> str:
    """Uncompressed text operators out of the PDF's content streams.

    reportlab wraps page content in ``/Filter [/ASCII85Decode /FlateDecode]``,
    so a naive substring search over the raw bytes finds nothing — and a guard
    written that way passes on an EMPTY document. Both filters have to be
    undone, in that order.
    """
    import base64
    import zlib

    raw = zf.read(_name_ending(zf, ".pdf"))
    out = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        chunk = match.group(1).strip()
        if chunk.endswith(b"~>"):
            try:
                chunk = base64.a85decode(chunk, adobe=True)
            except ValueError:
                pass
        try:
            chunk = zlib.decompress(chunk)
        except zlib.error:
            pass
        out.append(chunk.decode("latin-1", "replace"))
    body = "\n".join(out)
    # Text is emitted as (...)Tj / [(..)..]TJ — pull the literals out. The
    # provenance block is rendered with &nbsp; to keep its columns aligned, so
    # normalise those back or every phrase in it is unsearchable.
    text = " ".join(re.findall(r"\((?:\\.|[^\\()])*\)", body)) + body
    return text.replace("\xa0", " ")


# ---------------------------------------------------------------------------
# 1 — nothing selected is not an empty export
# ---------------------------------------------------------------------------
def test_no_dataset_selected_redirects_with_a_message_instead_of_an_empty_zip(
        app, client, fleet):
    resp = _get(client, "/waf/export?fmt=csv", admin_user_id(app))
    assert resp.status_code == 302
    assert "/waf/" in resp.headers["Location"]


def test_no_format_selected_redirects_too(app, client, fleet):
    resp = _get(client, "/waf/export?set=policies", admin_user_id(app))
    assert resp.status_code == 302


def test_an_unknown_dataset_name_is_not_quietly_treated_as_a_selection(
        app, client, fleet):
    resp = _get(client, "/waf/export?set=everything&fmt=csv", admin_user_id(app))
    assert resp.status_code == 302, "a typo must not produce a bundle"


def test_the_export_is_behind_a_login(client, fleet):
    resp = client.get(_query())
    assert resp.status_code in (302, 401), resp.status_code


def test_back_is_validated_against_a_literal_list_of_pages(app, client, fleet):
    """``back`` picks the page an empty selection lands on. It is an endpoint
    KEY resolved against a tuple, never a URL — a form whose only job is to
    produce a download is still a form, and an open redirect is still an open
    redirect."""
    resp = _get(client, "/waf/export?fmt=csv&back=https://evil.example/x",
                admin_user_id(app))
    assert resp.status_code == 302
    assert "evil.example" not in resp.headers["Location"]


# ---------------------------------------------------------------------------
# 2 — provenance travels
# ---------------------------------------------------------------------------
def test_the_manifest_names_the_scope_that_never_reported(app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    manifest = zf.read(_name_ending(zf, "MANIFEST.txt")).decode("utf-8")
    assert "Never harvested : web-never" in manifest
    assert "not devices with zero policies" in manifest


def test_every_format_carries_the_same_scope_block(app, client, fleet):
    """Three artefacts, ONE ``provenance()`` call. A workbook whose first sheet
    is four thousand policies is a workbook whose reader never learns that one
    of the scopes never reported."""
    zf = _bundle(client, admin_user_id(app))
    manifest = zf.read(_name_ending(zf, "MANIFEST.txt")).decode("utf-8")
    names, sheets = _sheets(zf)
    assert names[0] == "Scope & freshness", names
    first = "\n".join(c for row in sheets[names[0]] for c in row)
    pdf = _pdf_text(zf)
    # Both needles are provenance-ONLY, and that took two goes to get right:
    # "web-never" also appears in the exceptions table (a carve-out lives in
    # that scope) and "Device/ADOM scopes visible" is a row LABEL in the
    # figures table. A mutation deleting the PDF's whole provenance page
    # survived both.
    for needle in ("Never harvested : web-never",
                   "scopes visible to the exporting console"):
        assert needle in manifest, needle
        assert needle in first, needle
        assert needle in pdf, needle


def test_the_scope_file_ships_whatever_was_ticked(app, client, fleet):
    """It is the denominator. A folder of data files with no scope file cannot
    be audited three weeks later."""
    zf = _bundle(client, admin_user_id(app), sets=("policies",), fmts=("csv",))
    scopes = _csv_rows(zf, "scopes.csv")
    assert {r["Device / ADOM"] for r in scopes} >= {"web1 / root", "web2 / root"}
    assert [r for r in scopes if r["Snapshot"] == "never harvested"]


def test_the_manifest_row_counts_match_the_files_beside_them(app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    manifest = zf.read(_name_ending(zf, "MANIFEST.txt")).decode("utf-8")
    claimed = dict((m.group(1), int(m.group(2))) for m in
                   re.finditer(r"^\* (.+?) \((\d+) rows\)$", manifest, re.M))
    assert claimed, manifest
    files = {"Server policies": "server-policies.csv",
             "Web protection profiles": "protection-profiles.csv",
             "Protection coverage": "protection-coverage.csv",
             "Artifacts (file-backed objects)": "artifacts.csv",
             "Exceptions with their profiles": "exceptions.csv"}
    for label, filename in files.items():
        assert claimed[label] == len(_csv_rows(zf, filename)), label


# ---------------------------------------------------------------------------
# 3 — the bundle is what this console may see
# ---------------------------------------------------------------------------
def test_another_products_device_is_in_no_byte_of_the_bundle(app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    for name in zf.namelist():
        blob = zf.read(name)
        assert b"adc-secret-policy" not in blob, name
        assert b"exc-on-another-product" not in blob, name


def test_the_global_console_still_counts_only_the_fortiwebs(app, client, fleet):
    """The guard above cannot see the ``kind`` narrowing: in a FortiWeb session
    ``visible_appliances()`` has already dropped the FortiADC. Global is the
    console where the fleet really is every product."""
    resp = _get(client, _query(sets=("policies",), fmts=("csv",)),
                admin_user_id(app), product="global")
    zf = zipfile.ZipFile(io.BytesIO(resp.get_data()))
    assert b"adc-secret-policy" not in zf.read(
        _name_ending(zf, "server-policies.csv"))


def test_an_operator_who_cannot_see_a_device_does_not_export_it(app, client, fleet):
    with app.app_context():
        from app import db
        from app.models import Appliance
        db.session.get(Appliance, fleet["web2"]).maintenance = True
        db.session.commit()
    ro = make_user(app, username="ro-export", role="readonly",
                   profile_id=profile_id(app, "readonly"))
    zf = _bundle(client, ro, sets=("policies",), fmts=("csv",))
    scopes = {r["Device / ADOM"] for r in _csv_rows(zf, "server-policies.csv")}
    assert "web2 / root" not in scopes, scopes


# NOTE — split from the guard above rather than being its second half: see
# ``_get``'s docstring. A body that logs in twice re-asserts the first identity.
def test_the_same_maintenance_device_is_exported_for_an_admin(app, client, fleet):
    with app.app_context():
        from app import db
        from app.models import Appliance
        db.session.get(Appliance, fleet["web2"]).maintenance = True
        db.session.commit()
    zf = _bundle(client, admin_user_id(app), sets=("policies",), fmts=("csv",))
    scopes = {r["Device / ADOM"] for r in _csv_rows(zf, "server-policies.csv")}
    assert "web2 / root" in scopes, scopes


# ---------------------------------------------------------------------------
# 4 — exceptions are desired state
# ---------------------------------------------------------------------------
def test_the_bundle_never_claims_a_carve_out_was_deployed(app, client, fleet):
    """Verified against the model, not assumed: ``WppException`` has no column
    recording a push, and ``exception_inject.apply_injection`` returns its steps
    to the caller and stores nothing. A row that reads as "deployed" would be a
    claim SATOM cannot make."""
    zf = _bundle(client, admin_user_id(app))
    manifest = zf.read(_name_ending(zf, "MANIFEST.txt")).decode("utf-8")
    assert "DESIRED STATE" in manifest
    # Collapsed, not raw: the manifest is hard-wrapped to fit a terminal, so an
    # assertion on any sentence long enough to be worth asserting would fail
    # against a PERFECT artefact. The same trap §7f documents for LICENSE.
    assert ("no record of whether any carve-out was pushed to a device"
            in " ".join(manifest.split()).lower())
    headers = _csv_rows(zf, "exceptions.csv")[0].keys()
    for banned in ("Deployed", "Pushed", "On device", "Applied"):
        assert banned not in headers, banned


def test_an_exception_in_an_unharvested_scope_answers_unknown_not_missing(
        app, client, fleet):
    """The strongest trap in this dataset. We have no snapshot for that scope,
    so we have no evidence either way — printing "NOT in snapshot" would send
    an operator to re-author a carve-out that is perfectly fine."""
    zf = _bundle(client, admin_user_id(app))
    rows = {r["Name"]: r for r in _csv_rows(zf, "exceptions.csv")}
    dark = rows["exc-in-the-dark"]
    assert "unknown" in dark["Profile in snapshot"], dark["Profile in snapshot"]
    assert "NOT in snapshot" not in dark["Profile in snapshot"]
    assert "unknown" in dark["Policies in snapshot"]


def test_an_exception_naming_a_profile_the_snapshot_lacks_is_reported(
        app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    rows = {r["Name"]: r for r in _csv_rows(zf, "exceptions.csv")}
    assert rows["exc-dangling-profile"]["Profile in snapshot"] == "NOT in snapshot"
    assert rows["exc-resolved"]["Profile in snapshot"] == "present"


def test_an_exception_authored_for_a_policy_that_is_gone_is_reported(
        app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    rows = {r["Name"]: r for r in _csv_rows(zf, "exceptions.csv")}
    assert "pol-deleted" in rows["exc-dangling-policy"]["Policies in snapshot"]
    assert rows["exc-resolved"]["Policies in snapshot"] == "all present"


def test_the_carve_out_carries_the_blast_radius_of_its_shared_profile(
        app, client, fleet):
    """A WPP is usually SHARED — that is the entire reason the Exceptions page
    exists. "How many policies does this profile serve" is the number that
    turns a carve-out from a local edit into a fleet change."""
    zf = _bundle(client, admin_user_id(app))
    rows = {r["Name"]: r for r in _csv_rows(zf, "exceptions.csv")}
    assert rows["exc-resolved"]["Policies binding that profile"] == "2"


def test_the_carve_out_payload_travels(app, client, fleet):
    """An export that drops the payload cannot be used to re-author one, which
    is most of what somebody takes an exceptions export away to do."""
    zf = _bundle(client, admin_user_id(app))
    rows = {r["Name"]: r for r in _csv_rows(zf, "exceptions.csv")}
    assert "060190001" in rows["exc-resolved"]["Payload"]


# ---------------------------------------------------------------------------
# 5 — charts travel as their series
# ---------------------------------------------------------------------------
def test_the_drawing_and_the_series_table_read_one_spec(app, client, fleet):
    from app.services import waf_export as wx

    with app.app_context():
        from app.models import User
        b = wx.Bundle(user=User.query.get(admin_user_id(app)))
        table = wx.chart_rows(b, ALL_SETS)
        for spec in wx.CHARTS:
            labels, values, _c = spec.series(b)
            mine = [r for r in table if r["chart"] == spec.title]
            assert [r["label"] for r in mine] == list(labels), spec.key
            assert [r["value"] for r in mine] == list(values), spec.key


def test_every_chart_colours_one_for_one_with_its_values(app, fleet):
    """A palette indexed by POSITION paints "blocking" whatever colour the
    fourth slot happens to be. The on-screen chart maps posture to colour by
    KEY (waf.js) and so must the PDF."""
    from app.services import waf_export as wx

    with app.app_context():
        from app.models import User
        b = wx.Bundle(user=User.query.get(admin_user_id(app)))
        for spec in wx.CHARTS:
            labels, values, colours = spec.series(b)
            assert len(labels) == len(values), spec.key
            if spec.viz == "line":
                assert len(colours) == 1, spec.key
            else:
                assert len(colours) == len(values), spec.key


def test_the_export_palette_is_the_same_one_the_screen_draws(app):
    """A constant cannot cross the Python/JS boundary, so the two copies are
    held together by this guard instead of by a comment claiming they match.
    These are the ``.fw-badge-*`` values, calibrated against WHITE — the
    fleet's dark-theme pastels drop to ~1.4:1 on this product (§9m)."""
    from app.services.waf_export import BADGE

    js = (REPO / "app/static/js/waf.js").read_text(encoding="utf-8")
    block = js[js.index("var C = {"):js.index("};", js.index("var C = {"))]
    found = dict(re.findall(r"(\w+):\s*'(#[0-9A-Fa-f]{6})'", block))
    assert found, block
    assert found == BADGE, (found, BADGE)


def test_the_chart_series_reach_the_csv_and_the_workbook(app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    rows = _csv_rows(zf, "chart-series.csv")
    assert {r["Chart"] for r in rows} >= {"Enforcement posture",
                                          "Transport security"}
    names, sheets = _sheets(zf)
    assert "Chart series" in names
    assert len(sheets["Chart series"]) == len(rows) + 1


# ---------------------------------------------------------------------------
# 6 — selection is honoured in every format
# ---------------------------------------------------------------------------
def test_an_unticked_dataset_reaches_no_file_in_any_format(app, client, fleet):
    zf = _bundle(client, admin_user_id(app), sets=("policies",))
    assert not [n for n in zf.namelist() if "exceptions" in n]
    names, _sheet = _sheets(zf)
    assert "Exceptions" not in names
    assert "exc-resolved" not in _pdf_text(zf)


def test_a_ticked_dataset_reaches_every_ticked_format(app, client, fleet):
    zf = _bundle(client, admin_user_id(app), sets=("exceptions",))
    assert _csv_rows(zf, "exceptions.csv")
    names, sheets = _sheets(zf)
    assert "Exceptions" in names
    assert "exc-resolved" in _pdf_text(zf)


def test_an_unticked_format_produces_no_file_of_that_kind(app, client, fleet):
    zf = _bundle(client, admin_user_id(app), fmts=("csv",))
    assert not [n for n in zf.namelist() if n.endswith((".pdf", ".xlsx"))]


def test_the_workbook_data_sheets_start_with_their_column_header(
        app, client, fleet):
    """``xlsx_writer`` bolds and freezes row 0. A prose line above the header
    would freeze the prose and let the real header scroll away."""
    zf = _bundle(client, admin_user_id(app))
    _names, sheets = _sheets(zf)
    assert sheets["Server policies"][0][0] == "Device / ADOM"
    assert sheets["Exceptions"][0][0] == "Device / ADOM"


def test_the_page_filters_do_not_narrow_the_bundle(app, client, fleet):
    """The per-table CSV link exports "exactly the rows you filtered" and says
    so. A ZIP that also narrowed — invisibly, because nobody can see the filter
    bar the file came from — is the §119 drift with a longer fuse."""
    plain = _bundle(client, admin_user_id(app), sets=("policies",), fmts=("csv",))
    filtered = _bundle(client, admin_user_id(app), sets=("policies",),
                       fmts=("csv",), scope="web1+/+root", posture="disabled",
                       q="nothing-matches-this")
    assert (len(_csv_rows(plain, "server-policies.csv"))
            == len(_csv_rows(filtered, "server-policies.csv")) > 0)


# ---------------------------------------------------------------------------
# 7 — the artefacts are real files, and truncation is never silent
# ---------------------------------------------------------------------------
def test_the_archive_and_the_workbook_inside_it_are_valid(app, client, fleet):
    zf = _bundle(client, admin_user_id(app))
    assert zf.testzip() is None
    wb = zipfile.ZipFile(io.BytesIO(zf.read(_name_ending(zf, ".xlsx"))))
    assert wb.testzip() is None
    assert "xl/workbook.xml" in wb.namelist()
    assert zf.read(_name_ending(zf, ".pdf")).startswith(b"%PDF")


def test_a_pdf_table_that_stopped_early_says_where_the_rest_is(app, client, fleet):
    """A table that stops at 40 rows without saying so is a table claiming the
    fleet has 40 of these."""
    from app.services import waf_export as wx

    zf = _bundle(client, admin_user_id(app))
    text = _pdf_text(zf)
    biggest = max(len(_csv_rows(zf, "protection-coverage.csv")),
                  len(_csv_rows(zf, "protection-profiles.csv")))
    assert biggest > wx.PDF_TABLE_ROWS, "fixture too small to exercise the cap"
    assert "first %d shown" % wx.PDF_TABLE_ROWS in text
    assert "ZIP hold all of them" in text


def test_the_csv_opens_as_utf8_in_excel(app, client, fleet):
    """Without the BOM, Excel on Windows reads UTF-8 as latin-1 and every
    accented device comment arrives mojibake."""
    zf = _bundle(client, admin_user_id(app))
    assert zf.read(_name_ending(zf, "csv/server-policies.csv")).startswith(
        b"\xef\xbb\xbf")


# ---------------------------------------------------------------------------
# 8 — the shared primitives, and the module they came out of
# ---------------------------------------------------------------------------
def test_db_reports_still_renders_its_pdf_through_the_shared_flowables():
    """The extraction moved live code. This is the regression that says the
    module it came out of still works — a chart in a DB report is drawn by the
    very function the WAF export uses."""
    from app.services import db_reports

    result = {"name": "R", "generated_at": "now", "widgets": [
        {"title": "bar", "viz": "bar", "columns": ["a", "b"],
         "rows": [["x", 1], ["y", 2]], "labels": ["x", "y"], "values": [1, 2],
         "row_count": 2, "x_col": "a", "y_col": "b"},
        {"title": "table", "viz": "table", "columns": ["a"],
         "rows": [["<&>"]], "row_count": 1},
    ]}
    assert db_reports.build_pdf(result, author="t").startswith(b"%PDF")


def test_an_empty_series_says_so_on_the_canvas(app):
    """On a chart, "no data" and "all zeroes" look identical and mean opposite
    things — the rule waf.js follows on screen (its rule 2)."""
    from app.services import pdf_kit
    from reportlab.graphics.shapes import String

    for viz in ("pie", "bar", "line"):
        drawing = pdf_kit.chart_flowable({"labels": [], "values": []}, viz, 400)
        strings = [s for s in drawing.contents if isinstance(s, String)]
        assert any("no numeric data" in s.text for s in strings), viz


def test_a_cell_with_xml_hostile_characters_survives_every_format(
        app, client, fleet):
    """FortiWeb comments routinely carry ``&`` and ``<``. One unescaped
    ampersand makes Excel refuse the whole workbook with "unreadable content"
    and no indication of which cell is at fault."""
    with app.app_context():
        _exception(fleet["web1"], wpp="wpp-a", policies=["pol-1"],
                   name="ampersand & <angle> test")
    zf = _bundle(client, admin_user_id(app), sets=("exceptions",))
    assert zf.testzip() is None
    names = {r["Name"] for r in _csv_rows(zf, "exceptions.csv")}
    assert "ampersand & <angle> test" in names
    _n, sheets = _sheets(zf)
    assert any("ampersand & <angle> test" in c
               for row in sheets["Exceptions"] for c in row)


# ---------------------------------------------------------------------------
# 9 — coverage keeps the distinction the screen paints as a grey dash
# ---------------------------------------------------------------------------
def test_the_coverage_export_keeps_not_applicable_apart_from_switched_off(
        app, client, fleet):
    """A slot the profile does not HAVE is not a slot switched off. Collapsing
    the two invents a fleet-wide gap nobody can close — which is why the screen
    paints a grey dash there and never a red zero."""
    zf = _bundle(client, admin_user_id(app), sets=("coverage",), fmts=("csv",))
    rows = _csv_rows(zf, "protection-coverage.csv")
    verdicts = {r["Verdict"] for r in rows}
    assert "not applicable here" in verdicts
    for row in rows:
        if row["Verdict"] == "not applicable here":
            assert row["Applicable"] == "0" and row["% of applicable"] == ""


def test_the_overview_figures_carry_the_artifact_tiles_when_both_are_ticked(
        app, client, fleet):
    """The overview dataset is the only one whose content depends on ANOTHER
    tick — which is the whole reason every builder takes the selection. Its
    artifact half is only honest when that universe was actually collected."""
    zf = _bundle(client, admin_user_id(app),
                 sets=("overview", "artifacts"), fmts=("csv",))
    groups = {r["Section"] for r in _csv_rows(zf, "fleet-figures.csv")}
    assert any(g.startswith("Artifacts — ") for g in groups), groups


def test_the_overview_figures_claim_nothing_about_artifacts_when_unticked(
        app, client, fleet):
    zf = _bundle(client, admin_user_id(app), sets=("overview",), fmts=("csv",))
    groups = {r["Section"] for r in _csv_rows(zf, "fleet-figures.csv")}
    assert not any(g.startswith("Artifacts — ") for g in groups), groups


def test_the_artifact_export_keeps_its_policy_count_a_count(app, client, fleet):
    """``policies`` is a NUMBER on /waf/artifacts. An export that overwrites it
    with a joined list gives one column two meanings across two surfaces."""
    zf = _bundle(client, admin_user_id(app), sets=("artifacts",), fmts=("csv",))
    rows = _csv_rows(zf, "artifacts.csv")
    # Without this the loop below asserts NOTHING and the guard passes on an
    # empty dataset — which it did, until a surviving mutation said so.
    assert rows, "fixture produced no artifact rows"
    for row in rows:
        assert row["Policies naming it"].isdigit(), row
    assert any(row["Which policies"] for row in rows), "names column never filled"
