"""One row per DEVICE, sections per family, and a filter that lives in the URL.

Why this file exists
--------------------
Nothing failed before this change either. ``/adom-assets/`` rendered 200 in
every ADOM — and rendered **FortiWeb** in every ADOM, because ``_scope()``
asked ``branding.get_product(None)`` and ``None`` is not "the current one":
``get_product`` falls straight through to ``DEFAULT_PRODUCT``. So the Global
console showed 14 FortiWeb rows and FortiADC, FortiAnalyzer and
FortiAuthenticator appeared nowhere at all, under a heading that said Global.
A wrong answer wearing the right chrome is the failure mode this whole file is
pointed at.

The second half is the fold. A FortiWeb in ADOM mode is one appliance row per
ADOM and ONE ``execute backup`` for the whole box, so its ADOM rows can never
have a backup folder of their own — they printed a permanent *never pushed*
line each (six of this fleet's twelve) for devices that were pushing fine.
Folding them is only safe under two rules, and both are guarded below:

* **the numbers are ADDED, never dropped** — a fold that loses a version count
  is a different lie from the one it fixed; and
* **nothing merges on a guess.** The chassis comes from the appliance row the
  operator authored (via ``models.appliance_name_parts``, the product's one
  answer) or from a hostname the DEVICE reported in its own snapshot — and a
  hostname naming no known device of that family identifies nothing, so it
  folds nothing. Merging two boxes reports one device's backups as another's.
"""
from __future__ import annotations

import pathlib
import re
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
TPL = ROOT / "app" / "templates" / "adom_assets" / "index.html"


# --------------------------------------------------------------- helpers --

def _appl(db, name, *, kind="fortiweb", host="192.0.2.9", vdom=None):
    from app.models import Appliance
    a = Appliance(name=name, kind=kind, host=host, username="u",
                  password_enc="x", vdom=vdom)
    db.session.add(a)
    db.session.commit()
    return a


def _server(monkeypatch, devices):
    from app.services import backup_server
    monkeypatch.setattr(backup_server, "inventory", lambda: {
        "configured": True, "reachable": True, "host": "fm.example",
        "error": "", "firmware": [], "devices": devices})


def _folder(slug, count=3, latest=None, files=()):
    latest = latest or datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    return {"device": slug, "count": count, "latest": latest,
            "files": list(files)}


def _rows(data, prefix):
    return [r for r in data["rows"] if r["slug"].startswith(prefix)]


# ================================================================ scope ====

def test_the_scope_follows_the_request_adom_and_not_the_default(app):
    """``get_product(None)`` answers DEFAULT_PRODUCT, which is why this page
    showed FortiWeb inside the FortiADC console. ``g.product`` is the only
    thing that knows which ADOM the REQUEST is in."""
    from flask import g
    from app.views.adom_assets import _scope
    with app.test_request_context("/adom-assets/"):
        g.product = "fortiadc"
        assert _scope() == "fortiadc"
    with app.test_request_context("/adom-assets/"):
        g.product = "global"
        assert _scope() == "", "Global must mean every family, not one"
    with app.test_request_context("/adom-assets/"):
        assert _scope() == "", "no ADOM resolved must not silently pick one"


def test_the_global_console_holds_every_family(app, monkeypatch):
    """The bug this file opens with, stated as a fact about the data."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "gw01", kind="fortiweb"))
        device_identity.observe(_appl(db, "ga01", kind="fortiadc"))
        _server(monkeypatch, [])
        keys = {s["key"] for s in adom_assets.collect("")["sections"]}
        assert {"fortiweb", "fortiadc"} <= keys, \
            "the console scope dropped a device family"
        only = adom_assets.collect("fortiadc")
        assert {s["key"] for s in only["sections"]} == {"fortiadc"}


# =============================================================== the fold ==

def test_the_adom_rows_fold_onto_their_chassis(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "fold01", vdom="root"))
        for adom in ("adom_dev", "adom_prod"):
            device_identity.observe(_appl(db, "fold01@" + adom, vdom=adom))
        _server(monkeypatch, [_folder("fold01", count=5)])
        rows = _rows(adom_assets.collect("fortiweb"), "fold01")
        assert len(rows) == 1, "the ADOM rows were listed as separate devices"
        assert rows[0]["slug"] == "fold01" and rows[0]["backups"] == 5
        assert rows[0]["state"] == "ok", \
            "the chassis inherited an ADOM row's 'never pushed'"


def test_the_fold_adds_the_version_counts_it_absorbs(app, monkeypatch):
    """A fold that quietly drops the siblings' change log replaces a visible
    wrong number with an invisible one."""
    from app.extensions import db
    from app.services import adom_assets, device_identity, sot_store
    with app.app_context():
        device_identity.observe(_appl(db, "sum01", vdom="root"))
        device_identity.observe(_appl(db, "sum01@adom_dev", vdom="adom_dev"))
        sot_store.record("sum01", {"sections": {"S": {"e": [{"n": 1}]}}})
        sot_store.record("sum01-adom_dev",
                         {"sections": {"S": {"e": [{"n": 2}]}}})
        sot_store.record("sum01-adom_dev",
                         {"sections": {"S": {"e": [{"n": 3}]}}})
        _server(monkeypatch, [])
        row = _rows(adom_assets.collect("fortiweb"), "sum01")[0]
        assert row["sot_versions"] == 3, \
            "the folded ADOM rows' versions were dropped, not added"


def test_a_folder_a_sibling_pushes_under_is_still_listed(app, monkeypatch):
    """The fold must never make a real folder unreachable: a sibling that IS
    pushing under its own name has files somebody has to be able to open."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "two01", vdom="root"))
        device_identity.observe(_appl(db, "two01@adom_dev", vdom="adom_dev"))
        _server(monkeypatch, [_folder("two01", count=2),
                              _folder("two01-adom_dev", count=4)])
        row = _rows(adom_assets.collect("fortiweb"), "two01")[0]
        assert row["backups"] == 6
        assert sorted(f["slug"] for f in row["folders"]) == \
            ["two01", "two01-adom_dev"], "a real folder became unreachable"


def test_a_chassis_is_graded_by_its_freshest_folder(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    old = (datetime.utcnow() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M")
    with app.app_context():
        device_identity.observe(_appl(db, "fresh01", vdom="root"))
        device_identity.observe(_appl(db, "fresh01@adom_dev", vdom="adom_dev"))
        _server(monkeypatch, [_folder("fresh01", count=1),
                              _folder("fresh01-adom_dev", count=1, latest=old)])
        row = _rows(adom_assets.collect("fortiweb"), "fresh01")[0]
        assert row["state"] == "ok", \
            "a device pushing today was painted red by a folder it abandoned"


def test_a_chassis_is_retired_only_when_every_row_is(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "ret01", vdom="root"))
        device_identity.observe(_appl(db, "ret01@adom_dev", vdom="adom_dev"))
        device_identity.retire("ret01-adom_dev")
        _server(monkeypatch, [])
        row = _rows(adom_assets.collect("fortiweb"), "ret01")[0]
        assert row["retired"] is False, \
            "hardware still in service was greyed out as de-registered"


def test_an_unresolved_row_is_its_own_chassis(app):
    """Never a blank key: every unresolved row sharing one empty chassis
    merges unrelated devices into a single line."""
    from app.models_identity import DeviceIdentity
    row = DeviceIdentity(slug="lonely01", name="lonely01")
    assert row.chassis == "lonely01"


# ------------------------------------------------ how a chassis is decided --

def test_the_chassis_comes_from_the_hostname_the_device_reported(app):
    from app.services import device_identity
    snap = {"sections": {"System": {"global": [{"hostname": "boxA"}]}}}
    assert device_identity.chassis_from_snapshot(snap) == "boxA"
    assert device_identity.chassis_from_snapshot({}) == ""
    assert device_identity.chassis_from_snapshot(
        {"sections": {"System": {"global": [{"hostname": ""}]}}}) == ""
    # An empty first entry must be SKIPPED, not accepted: with one entry
    # "return the blank" and "keep looking" are indistinguishable, and that is
    # the only shape the guard used to cover.
    assert device_identity.chassis_from_snapshot(
        {"sections": {"System": {"global": [{"hostname": ""},
                                            {"hostname": "boxB"}]}}}) == "boxB"


def test_the_name_split_is_delegated_and_refused_when_it_strips_nothing(app):
    """``vdom`` is 'root' on every FortiWeb, ADOM mode or not, so its presence
    proves nothing. Only a name the vdom actually explains is an ADOM row."""
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        plain = _appl(db, "split01", vdom="root")
        assert device_identity.chassis_from_appliance(plain) == ("", "")
        lying = _appl(db, "split02@adom_dev", vdom="adom_prod")
        assert device_identity.chassis_from_appliance(lying) == ("", ""), \
            "the text after '@' was trusted over the vdom"
        real = _appl(db, "split03@adom_dev", vdom="adom_dev")
        assert device_identity.chassis_from_appliance(real) == \
            ("split03", "adom_dev")


def test_a_hostname_naming_no_known_device_folds_nothing(app):
    """Two chassis with one hostname is a real configuration. Silently merging
    them reports one box's backups as another's."""
    from app.extensions import db
    from app.models_identity import DeviceIdentity
    from app.services import device_identity, sot_store
    with app.app_context():
        db.session.add(DeviceIdentity(slug="ghost01", name="ghost01",
                                      product="fortiweb", names='["ghost01"]'))
        db.session.commit()
        sot_store.record("ghost01", {"sections": {
            "System": {"global": [{"hostname": "a-box-nobody-registered"}]}}})
        device_identity._resolve_chassis()
        assert device_identity.for_slug("ghost01").chassis_slug == "ghost01"


def test_a_hostname_of_another_family_folds_nothing(app):
    from app.extensions import db
    from app.models_identity import DeviceIdentity
    from app.services import device_identity, sot_store
    with app.app_context():
        db.session.add_all([
            DeviceIdentity(slug="xfam01", name="xfam01", product="fortiadc",
                           names='["xfam01"]', chassis_slug="xfam01"),
            DeviceIdentity(slug="xfam01-adom_dev", name="xfam01-adom_dev",
                           product="fortiweb", names='["xfam01-adom_dev"]'),
        ])
        db.session.commit()
        sot_store.record("xfam01-adom_dev",
                         {"sections": {"System": {"global":
                                                  [{"hostname": "xfam01"}]}}})
        device_identity._resolve_chassis()
        assert device_identity.for_slug("xfam01-adom_dev").chassis_slug == \
            "xfam01-adom_dev", "rows of two different families were merged"


def test_the_chassis_outlives_the_appliance_row(app, monkeypatch):
    """The whole reason it is STORED: by the time anybody asks about a
    de-registered device, the appliance row that carried ``vdom`` is gone."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "gone01", vdom="root"))
        a = _appl(db, "gone01@adom_dev", vdom="adom_dev")
        device_identity.observe(a)
        db.session.delete(a)
        db.session.commit()
        device_identity.retire("gone01-adom_dev")
        _server(monkeypatch, [])
        assert len(_rows(adom_assets.collect("fortiweb"), "gone01")) == 1


def test_a_live_rename_out_of_an_adom_drops_the_old_chassis(app):
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        a = _appl(db, "moved01@adom_dev", vdom="adom_dev")
        device_identity.observe(a)
        ident = device_identity.for_slug("moved01-adom_dev")
        assert ident.chassis_slug == "moved01"
        a.name, a.vdom = "moved01-adom_dev", "root"
        device_identity.observe(a)
        assert device_identity.for_slug("moved01-adom_dev").chassis_slug == \
            "moved01-adom_dev", "a stale chassis survived a live observation"


# ============================================================== filtering ==

def _fixture(db, monkeypatch, device_identity):
    device_identity.observe(_appl(db, "flt-web", kind="fortiweb"))
    device_identity.observe(_appl(db, "flt-adc", kind="fortiadc"))
    device_identity.observe(_appl(db, "flt-old", kind="fortiweb"))
    device_identity.retire("flt-old")
    # A second FortiWeb that has never pushed, so the never-count of the whole
    # ADOM and the never-count of a FortiADC-only filter cannot coincide.
    device_identity.observe(_appl(db, "flt-mute", kind="fortiweb"))
    old = (datetime.utcnow() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M")
    _server(monkeypatch, [_folder("flt-web", count=1),
                          _folder("flt-old", count=1, latest=old)])


def test_the_type_filter_keeps_only_that_family(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
        got = _rows(adom_assets.collect("", device_type="fortiadc"), "flt-")
        assert [r["slug"] for r in got] == ["flt-adc"]


def test_an_unknown_filter_value_narrows_nothing(app, monkeypatch, client):
    """A typo in a hand-edited URL must not look like an empty ADOM."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
        assert len(_rows(adom_assets.collect("", device_type=""), "flt-")) == 4
    # Global, because that is the only ADOM in which a FortiADC row can be
    # expected on this page at all -- and the scope now decides that, which
    # is the fix this file opens with. conftest.login() defaults to fortiweb.
    login(client, admin_user_id(app), product="global")
    r = client.get("/adom-assets/?type=nonsense&state=nonsense")
    assert r.status_code == 200
    assert "flt-adc" in r.get_data(as_text=True), \
        "an unrecognised filter value emptied the table"


def test_stale_spans_both_graded_ages_and_never_is_not_one_of_them(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
        stale = _rows(adom_assets.collect("", state="stale"), "flt-")
        assert [r["slug"] for r in stale] == ["flt-old"]
        never = {r["slug"] for r in _rows(
            adom_assets.collect("", state="never"), "flt-")}
        assert never == {"flt-adc", "flt-mute"}, \
            "a device that never pushed was not reported as such"
        assert "flt-old" not in never, \
            "'stopped pushing' and 'never pushed' were merged again"


def test_the_free_text_filter_finds_a_name_the_device_was_renamed_away_from(app, monkeypatch):
    """The searched-for string is in NO other field.

    A rename keeps the slug, so searching for the name a device was renamed
    away from is answered by the slug — through a field that has nothing to do
    with the name history. The former name here shares no substring with the
    slug, the display name, the host or the model, so only ``name_history`` can
    produce the match.
    """
    from app.extensions import db
    from app.models_identity import DeviceIdentity
    from app.services import adom_assets, device_identity
    with app.app_context():
        db.session.add(DeviceIdentity(
            slug="hs01", name="hs01", product="fortiweb", chassis_slug="hs01",
            host="192.0.2.200", names='["zebra-crossing", "hs01"]'))
        db.session.commit()
        _server(monkeypatch, [])
        for field in ("hs01", "192.0.2.200"):
            assert "zebra-crossing" not in field
        got = _rows(adom_assets.collect("", q="zebra-crossing"), "hs01")
        assert len(got) == 1, "the only record of the old name was ignored"
        assert not _rows(adom_assets.collect("", q="zebra-crossing-nope"),
                         "hs01"), "the free-text filter matched too loosely"


def test_hide_retired_hides_only_the_de_registered(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
        got = {r["slug"] for r in _rows(
            adom_assets.collect("", hide_retired=True), "flt-")}
        assert got == {"flt-web", "flt-adc", "flt-mute"}


def test_the_tiles_describe_the_adom_and_not_the_filter(app, monkeypatch):
    """A count that shrinks when you type is a claim about the estate."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
        wide = adom_assets.collect("")
        narrow = adom_assets.collect("", device_type="fortiadc")
        assert narrow["totals"] == wide["totals"]
        for key in wide["totals"]:
            assert narrow["totals"][key] == wide["totals"][key], \
                "the %s tile was computed from the filtered rows" % key
        assert narrow["totals"]["no_backup"] > \
            sum(1 for r in narrow["rows"] if r["state"] == "never"), \
            "the fixture cannot tell a filtered total from an ADOM total"
        assert narrow["filters"]["shown"] < narrow["filters"]["of"]
        assert narrow["filters"]["active"] is True


def test_hide_retired_is_wired_to_its_own_query_parameter(app, client, monkeypatch):
    """``collect(hide_retired=True)`` proves the service. Only a real request
    proves the VIEW reads ``retired=hide`` — and a checkbox posts its own
    value, so a view reading ``== "1"`` would silently never hide anything."""
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
    login(client, admin_user_id(app), product="global")
    plain = client.get("/adom-assets/").get_data(as_text=True)
    assert "flt-old" in plain
    hidden = client.get("/adom-assets/?retired=hide").get_data(as_text=True)
    assert "flt-old" not in hidden, "retired=hide did not reach the view"
    assert "flt-web" in hidden, "it hid more than the de-registered devices"


def test_the_filter_is_the_url(app, client, monkeypatch):
    """Server-side and authoritative: the narrowing is shareable and there is
    exactly one authority for which rows exist."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _fixture(db, monkeypatch, device_identity)
    login(client, admin_user_id(app), product="global")
    html = client.get("/adom-assets/?type=fortiadc").get_data(as_text=True)
    assert "flt-adc" in html and "flt-web" not in html, \
        "the filter did not reach the render"


# =============================================================== sections ==

def test_the_sections_follow_the_adom_registry_order(app, monkeypatch):
    from app.branding import all_adoms
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "ord-web", kind="fortiweb"))
        device_identity.observe(_appl(db, "ord-adc", kind="fortiadc"))
        _server(monkeypatch, [])
        keys = [s["key"] for s in adom_assets.collect("")["sections"]]
        declared = [a["key"] for a in all_adoms()
                    if a["key"] not in ("", "global")]
        assert keys == [k for k in declared if k in keys], \
            "the page and the ADOM switcher disagree on the order"


def test_every_row_lands_in_exactly_one_section(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "sec-web", kind="fortiweb"))
        device_identity.observe(_appl(db, "sec-adc", kind="fortiadc"))
        _server(monkeypatch, [])
        data = adom_assets.collect("")
        placed = [r["slug"] for s in data["sections"] for r in s["rows"]]
        assert sorted(placed) == sorted(r["slug"] for r in data["rows"])
        assert len(placed) == len(set(placed))


def test_a_family_that_could_not_be_established_gets_its_own_section(app, monkeypatch):
    """"We could not tell" and "FortiWeb" are different answers, and only one
    of them is actionable."""
    from app.extensions import db
    from app.models_identity import DeviceIdentity
    from app.services import adom_assets, device_identity
    with app.app_context():
        db.session.add(DeviceIdentity(slug="una01", name="una01", product="",
                                      names='["una01"]', chassis_slug="una01"))
        db.session.commit()
        _server(monkeypatch, [])
        data = adom_assets.collect("")
        sec = [s for s in data["sections"]
               if any(r["slug"] == "una01" for r in s["rows"])]
        assert sec, "an unidentified device fell out of every section"
        assert sec[0]["key"] == adom_assets.UNASSIGNED
        # ...and it is FILTERABLE as such, or the section is a label with no
        # handle: the unassigned bucket is the one an operator has to work
        # through, so it needs to be selectable on its own.
        picked = adom_assets.collect("", device_type=adom_assets.UNASSIGNED)
        assert "una01" in {r["slug"] for r in picked["rows"]}
        assert all(not r["product"] for r in picked["rows"])


# =============================================================== the page ==

def test_the_page_carries_the_adom_pin_through_the_filter_form(app):
    """A GET cannot send the X-ADOM header, so without the hidden field a
    filtered reload falls back to the session and changes ADOM under the
    operator (see _product_gate)."""
    tpl = TPL.read_text()
    form = re.search(r'<form method="get".*?</form>', tpl, re.S)
    assert form, "the filter form is gone"
    assert 'name="_adom"' in form.group(0), \
        "the ADOM pin does not survive the filter"


def test_the_delete_form_addresses_the_folder_the_file_is_in(app):
    """A single chassis slug would point delete and download at a path that
    does not hold the file."""
    tpl = TPL.read_text()
    body = re.sub(r"{#.*?#}", "", tpl, flags=re.S)   # a comment is not code
    assert 'name="device" value="{{ fv.slug }}"' in body
    assert 'device=fv.slug' in body


def test_the_table_names_no_adom(app, client, monkeypatch):
    """The ask this change came from: backups are per device, so the ADOM a
    device happens to have is not a column on this page."""
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "noadom01", vdom="root"))
        device_identity.observe(_appl(db, "noadom01@adom_dev", vdom="adom_dev"))
        from app.services import backup_server
        monkeypatch.setattr(backup_server, "inventory", lambda: {
            "configured": True, "reachable": True, "host": "fm.example",
            "error": "", "firmware": [], "devices": []})
    login(client, admin_user_id(app))
    html = client.get("/adom-assets/").get_data(as_text=True)
    table = html[html.find("noadom01"):] if "noadom01" in html else ""
    assert "noadom01" in html
    assert "@adom_dev" not in table and "noadom01-adom_dev" not in table, \
        "a per-ADOM row is still listed as a device"


def test_the_page_still_renders_light(app, client, monkeypatch):
    from app.services import backup_server
    monkeypatch.setattr(backup_server, "inventory", lambda: {
        "configured": True, "reachable": True, "host": "fm.example",
        "error": "", "devices": [], "firmware": []})
    login(client, admin_user_id(app))
    html = client.get("/adom-assets/?state=stale").get_data(as_text=True)
    for dark in ("#080d1a", "backdrop-filter", "rgba(30,41,59"):
        assert dark not in html, "dark-theme chrome leaked onto a light page"


def test_the_new_columns_are_declared_exactly_once_in_the_migration(app):
    """A repeated key in the ``_ensure_columns`` literal collapses in SILENCE
    (Python keeps the last) and every column under the earlier copy is never
    created. That is how ``appliances.serial`` went missing, and the comment
    in that very entry warns about it."""
    src = (ROOT / "app" / "__init__.py").read_text()
    assert src.count("'device_identity': [") == 1, \
        "a duplicate device_identity key silently drops columns"
    entry = src.split("'device_identity': [", 1)[1].split("],", 1)[0]
    assert "chassis_slug" in entry and "adom" in entry
