"""One card per ARTEFACT, and the four artefacts are not copies of each other.

Why this file exists
--------------------
``/adom-assets/`` used to be one table whose columns mixed two unrelated
artefacts: "21 backups" sat beside "11 versions" in the same row, which invites
exactly the wrong reading — that one is a copy of the other. They are not. A
config backup is a file the APPLIANCE wrote and pushed to the backup server. A
SoT version is a snapshot SATOM recorded itself, de-duplicated by content hash,
under its own retention policy. A device that has never pushed a backup file
can hold a hundred recorded versions, and a device pushing daily can have no
history at all. Splitting them into cards makes that difference legible;
splitting them WITHOUT splitting the filter would have hidden it again, which
is the single most important guard here:

    the backup-state filter grades the backup server, so it narrows the
    backups card and deliberately does NOT narrow the SoT card.

Filter "never pushed", and the SoT card must still show the whole ADOM — those
are precisely the devices somebody filtering that way came to look at.

The fourth card is SATOM's own bundle set. It is console-wide by construction:
one bundle is a dump of every ADOM at once. Rendering it inside an ADOM would
assert that it belongs to that ADOM, so ``bundles.shown`` is false everywhere
except Global and the template is guarded for it too — a service that returns
nothing and a template that would have drawn it anyway is one refactor away
from leaking.
"""
from __future__ import annotations

import pathlib
import re
from datetime import datetime, timedelta

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


def _server(monkeypatch, devices, *, firmware=()):
    from app.services import backup_server
    monkeypatch.setattr(backup_server, "inventory", lambda: {
        "configured": True, "reachable": True, "host": "fm.example",
        "error": "", "firmware": list(firmware), "devices": devices})


def _folder(slug, count=3, latest=None):
    latest = latest or datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    return {"device": slug, "count": count, "latest": latest, "files": []}


def _bundles(monkeypatch, rows):
    from app.services import system_backup
    monkeypatch.setattr(system_backup, "all_bundles", lambda: list(rows))


def _bundle(name, *, size=10, local=True, off_box=True, size_match=True):
    return {"name": name, "size": size, "created": "2026-08-30T00:00:00",
            "local": local, "off_box": off_box, "size_match": size_match}


def _fw(db, product, version, *, size=1048576, filename=None):
    from app.models_firmware import FirmwareImage
    img = FirmwareImage(product=product, version=version, image_kind="upgrade",
                        filename=filename or ("%s-%s.out" % (product, version)),
                        stored_path="/tmp/%s-%s" % (product, version),
                        size_bytes=size)
    db.session.add(img)
    db.session.commit()
    return img


def _estate(db, monkeypatch, device_identity):
    """Four devices whose two artefacts DISAGREE on purpose.

    ``art-mute`` is the load-bearing one: it has never pushed a backup file and
    it has a change history. Every guard about the filter asymmetry needs a row
    that one card would keep and the other would drop; a fixture where the two
    artefacts agree cannot fail either way.
    """
    from app.services import sot_store
    old = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%d %H:%M")
    device_identity.observe(_appl(db, "art-web", vdom="root"))
    device_identity.observe(_appl(db, "art-old", vdom="root"))
    device_identity.observe(_appl(db, "art-mute", vdom="root"))
    device_identity.observe(_appl(db, "art-adc", kind="fortiadc", vdom="root"))
    for slug in ("art-web", "art-old", "art-mute"):
        sot_store.record(slug, {"sections": {"S": {"e": [{"n": slug}]}}})
    device_identity.retire("art-old")
    _server(monkeypatch, [_folder("art-web", count=2),
                          _folder("art-old", count=1, latest=old)])


def _slugs(sections, prefix="art-"):
    return [r["slug"] for s in sections for r in s["rows"]
            if r["slug"].startswith(prefix)]


# ======================================================= the four cards ====

def test_the_page_offers_one_grouping_per_artefact(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        data = adom_assets.collect("")
    for key in ("sections", "sot_sections", "firmware_sections", "bundles"):
        assert key in data, "the %s card has no data of its own" % key


def test_a_device_sits_under_the_same_family_in_both_device_cards(app, monkeypatch):
    """Two grouping functions over one row set is how a device ends up under
    FortiWeb in one card and under unassigned in the next."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        data = adom_assets.collect("")
    where = lambda secs: {r["slug"]: s["key"] for s in secs for r in s["rows"]}
    assert where(data["sections"]) == where(data["sot_sections"])


# ============================================ the filter asymmetry (core) ==

def test_the_backup_state_filter_does_not_narrow_the_sot_card(app, monkeypatch):
    """The whole point of the split. ``art-mute`` has never pushed a file and
    HAS a change history; a state filter that reached the SoT table would hide
    the device the operator is filtering for."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        data = adom_assets.collect("", state="ok")
    assert _slugs(data["sections"]) == ["art-web"], \
        "the backups card stopped honouring the state filter"
    assert set(_slugs(data["sot_sections"])) == \
        {"art-web", "art-old", "art-mute", "art-adc"}, \
        "the backup state filter narrowed a table about a different artefact"


def test_the_sot_card_still_honours_the_device_filters(app, monkeypatch):
    """Family, name and de-registered describe the DEVICE, so they apply to
    every card. Exempting them would make the filter bar a lie in half the
    page."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        by_type = adom_assets.collect("", device_type="fortiadc")
        by_name = adom_assets.collect("", q="art-mute")
        no_retired = adom_assets.collect("", hide_retired=True)
    assert _slugs(by_type["sot_sections"]) == ["art-adc"]
    assert _slugs(by_name["sot_sections"]) == ["art-mute"]
    assert "art-old" not in _slugs(no_retired["sot_sections"])
    assert "art-web" in _slugs(no_retired["sot_sections"]), \
        "hide_retired hid more than the de-registered devices"


def test_the_two_counters_are_reported_separately(app, monkeypatch):
    """One "showing N of M" for two tables that hold different numbers of rows
    is a wrong number on whichever card it does not describe."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        f = adom_assets.collect("", state="ok")["filters"]
    assert f["shown"] == 1 and f["shown_sot"] == 4 and f["of"] == 4


# ===================================================== the section totals ==

def test_a_section_adds_the_sot_numbers_of_the_rows_it_holds(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        data = adom_assets.collect("")
    for s in data["sot_sections"]:
        assert s["sot_versions"] == sum(r["sot_versions"] for r in s["rows"])
        assert s["sot_bytes"] == sum(r["sot_bytes"] for r in s["rows"])


def test_a_device_with_no_history_at_all_is_counted_by_name(app, monkeypatch):
    """"No configuration history has ever been recorded" is an event, exactly
    like "never pushed" is on the other card — and a zero in a cell is the one
    way to state it that nobody reads."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        data = adom_assets.collect("")
    adc = next(s for s in data["sot_sections"] if s["key"] == "fortiadc")
    assert adc["sot_none"] == 1, "a device with no history was not reported"
    web = next(s for s in data["sot_sections"] if s["key"] == "fortiweb")
    assert web["sot_none"] == 0
    assert data["totals"]["sot_none"] == 1


# ============================================================= firmware ====

def test_firmware_is_grouped_by_family_in_the_registry_order(app, monkeypatch):
    """Three families on purpose. With only FortiWeb and FortiADC the registry
    order and reverse-alphabetical order COINCIDE, so an implementation that
    sorted by name instead of following the registry would satisfy this guard
    while being wrong — the input has to be able to exhibit the defect before
    the assertion means anything."""
    from app.branding import all_adoms
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _fw(db, "fortianalyzer", "7.6.2")
        _fw(db, "fortiadc", "7.4.1")
        _fw(db, "fortiweb", "8.0.5")
        keys = [s["key"] for s in adom_assets.collect("")["firmware_sections"]]
    order = [a["key"] for a in all_adoms() if a["key"] not in ("", "global")]
    expected = [k for k in order if k in keys]
    assert sorted(keys, reverse=True) != expected, \
        "the fixture cannot tell registry order from alphabetical order"
    assert keys == expected, \
        "the firmware card orders families differently from the device cards"


def test_the_type_filter_narrows_the_firmware_card_too(app, monkeypatch):
    """The filter bar sits above every card. A family filter that left the
    firmware table wide would show FortiADC images under a FortiWeb heading."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _fw(db, "fortiadc", "7.4.1")
        _fw(db, "fortiweb", "8.0.5")
        data = adom_assets.collect("", device_type="fortiadc")
    assert [s["key"] for s in data["firmware_sections"]] == ["fortiadc"]
    assert [i.version for s in data["firmware_sections"]
            for i in s["rows"]] == ["7.4.1"]


def test_the_firmware_tile_describes_the_adom_and_not_the_filter(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _fw(db, "fortiadc", "7.4.1", size=2097152)
        _fw(db, "fortiweb", "8.0.5", size=1048576)
        wide = adom_assets.collect("")["totals"]
        narrow = adom_assets.collect("", device_type="fortiadc")["totals"]
    assert wide["firmware"] == 2 and narrow["firmware"] == 2, \
        "the firmware tile was computed from the filtered images"
    assert narrow["firmware_bytes"] == wide["firmware_bytes"] == 3145728


def test_an_image_for_no_family_gets_its_own_section(app, monkeypatch):
    """"We could not tell which appliance line this is for" and "FortiWeb" are
    different answers, and only one of them is safe to install."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _fw(db, "", "0.0.1")
        keys = [s["key"] for s in adom_assets.collect("")["firmware_sections"]]
    assert adom_assets.UNASSIGNED in keys


# ================================================== SATOM's own bundles ====

def test_the_bundle_card_is_global_only(app, monkeypatch):
    """A bundle is a dump of EVERY ADOM. Rendering it inside one says it
    belongs to that one."""
    from app.services import adom_assets
    with app.app_context():
        _bundles(monkeypatch, [_bundle("fmw-backup-20260830-000000.tar.gz")])
        for adom in ("fortiweb", "fortiadc", "fortianalyzer"):
            view = adom_assets.bundles_view(adom)
            assert view["shown"] is False and view["rows"] == [], \
                "%s was offered the console's own backup" % adom
        assert adom_assets.bundles_view("")["shown"] is True


def test_a_bundle_held_in_one_place_only_is_named_as_such(app, monkeypatch):
    """Off-box-only and local-only both mean "no redundancy", and they fail
    differently: one dies with the backup server, the other with the node it
    is backing up."""
    from app.services import adom_assets
    with app.app_context():
        _bundles(monkeypatch, [_bundle("a", local=False, off_box=True)])
        v = adom_assets.bundles_view("")
        assert v["only_off_box"] is True and v["only_local"] is False
        _bundles(monkeypatch, [_bundle("a", local=True, off_box=False)])
        v = adom_assets.bundles_view("")
        assert v["only_local"] is True and v["only_off_box"] is False
        _bundles(monkeypatch, [_bundle("a", local=True, off_box=True)])
        v = adom_assets.bundles_view("")
        assert v["only_local"] is False and v["only_off_box"] is False


def test_no_bundles_at_all_is_not_a_redundancy_verdict(app, monkeypatch):
    """``off_box == 0`` is vacuously true of an empty list. A warning banner
    fired by emptiness would say "the backup server is a single point of
    failure" about a console that has no backups at all — which is a different
    and worse fact, stated wrongly."""
    from app.services import adom_assets
    with app.app_context():
        _bundles(monkeypatch, [])
        v = adom_assets.bundles_view("")
    assert v["count"] == 0
    assert v["only_local"] is False and v["only_off_box"] is False


def test_a_size_that_disagrees_between_the_copies_is_named(app, monkeypatch):
    """Same name, two sizes, is what a truncated upload looks like — and the
    name is the only thing that lets an operator go and check which one."""
    from app.services import adom_assets
    with app.app_context():
        _bundles(monkeypatch, [_bundle("good"),
                               _bundle("torn", size_match=False),
                               _bundle("solo", off_box=False,
                                       size_match=False)])
        v = adom_assets.bundles_view("")
    assert v["mismatch"] == ["torn"], \
        "a bundle that exists in one place cannot disagree with itself"


def test_an_unreadable_inventory_is_reported_and_not_swallowed(app, monkeypatch):
    """"We could not look" must never render as "there are none" — that is the
    reading under which somebody creates a bundle they already had, or worse,
    stops looking for the one they need."""
    from app.services import adom_assets, system_backup

    def boom():
        raise RuntimeError("sftp is down")

    with app.app_context():
        monkeypatch.setattr(system_backup, "all_bundles", boom)
        v = adom_assets.bundles_view("")
    assert v["shown"] is True and v["rows"] == []
    assert "sftp is down" in v["error"]


def test_the_bundle_totals_are_the_bundles(app, monkeypatch):
    from app.services import adom_assets
    with app.app_context():
        _bundles(monkeypatch, [_bundle("a", size=3, local=True, off_box=True),
                               _bundle("b", size=4, local=False)])
        v = adom_assets.bundles_view("")
    assert v["count"] == 2 and v["bytes"] == 7
    assert v["local"] == 1 and v["off_box"] == 2


# ============================================================== rendered ====

def test_global_renders_all_four_sections(app, client, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _fw(db, "fortiweb", "8.0.5")
        _bundles(monkeypatch, [_bundle("fmw-backup-20260830-000000.tar.gz")])
        assert adom_assets  # the module under test is the one imported above
    login(client, admin_user_id(app), product="global")
    html = client.get("/adom-assets/").get_data(as_text=True)
    for anchor in ('id="sec-backups"', 'id="sec-sot"', 'id="sec-firmware"',
                   'id="sec-satom"'):
        assert anchor in html, "%s never reached the page" % anchor
    assert "fmw-backup-20260830-000000.tar.gz" in html


def test_an_adom_renders_three_sections_and_never_the_console_bundle(app, client, monkeypatch):
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _bundles(monkeypatch, [_bundle("fmw-backup-20260830-000000.tar.gz")])
    login(client, admin_user_id(app), product="fortiweb")
    html = client.get("/adom-assets/").get_data(as_text=True)
    assert 'id="sec-backups"' in html and 'id="sec-sot"' in html
    assert 'id="sec-firmware"' in html
    assert 'id="sec-satom"' not in html, \
        "an ADOM was shown the whole console's backup"
    assert "fmw-backup-" not in html


def test_the_state_filter_is_visibly_scoped_on_the_page(app, client, monkeypatch):
    """The asymmetry is correct AND surprising, so the page has to say it.
    A SoT table that silently ignores the filter above it reads as broken."""
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
    login(client, admin_user_id(app), product="global")
    html = client.get("/adom-assets/?state=never").get_data(as_text=True)
    assert "backup state not applied here" in html
    assert "art-web" in html, \
        "a device excluded from the backups card vanished from the SoT card"


def test_every_table_declares_as_many_columns_as_its_section_header_spans(app):
    """A ``colspan`` left behind after a column is removed does not fail: the
    browser silently stretches the header past the table and the family
    heading lands over the wrong column. This walks the template's real
    theads instead of trusting the number written next to them."""
    body = re.sub(r"{#.*?#}", "", TPL.read_text(), flags=re.S)
    theads = list(re.finditer(r"<thead>(.*?)</thead>", body, flags=re.S))
    assert len(theads) >= 4, "the four cards no longer declare four tables"
    checked = 0
    for m in theads:
        columns = len(re.findall(r"<th\b", m.group(1)))
        rest = body[m.end():m.end() + 1200]
        span = re.search(r'colspan="(\d+)"', rest)
        if not span:
            continue
        checked += 1
        assert int(span.group(1)) == columns, (
            "a section header spans %s of %s columns"
            % (span.group(1), columns))
    assert checked >= 3, "no section header was actually inspected"


def test_the_page_still_renders_light(app, client, monkeypatch):
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _bundles(monkeypatch, [_bundle("fmw-backup-20260830-000000.tar.gz",
                                       local=False)])
    login(client, admin_user_id(app), product="global")
    html = client.get("/adom-assets/").get_data(as_text=True)
    for dark in ("#080d1a", "backdrop-filter", "rgba(30,41,59"):
        assert dark not in html, "dark-theme chrome leaked onto a light page"


def test_the_bundle_card_offers_no_way_to_write(app, client, monkeypatch):
    """Read-only by design: create, restore and retention live on the System
    Backup page, which is the one place allowed to overwrite a database. A
    delete button here would be a second authority over the same files."""
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _bundles(monkeypatch, [_bundle("fmw-backup-20260830-000000.tar.gz")])
    login(client, admin_user_id(app), product="global")
    html = client.get("/adom-assets/").get_data(as_text=True)
    # Bounded at the card's own table. Slicing to the end of the document
    # would drag in the page chrome's forms and the guard would fail on a
    # correct card — which is the same class of mistake as an assertion that
    # matches its own comment.
    start = html.find('id="sec-satom"')
    assert start != -1, "the bundle card did not render"
    card = html[start:html.index("</table>", start)]
    assert "<form" not in card, "the bundle card grew a write path"
    # "no <button> at all" was too coarse: the card header now carries a
    # collapse toggle, which changes nothing but what is on screen. What must
    # stay impossible is a button that can SUBMIT, so the rule is about the
    # type and not about the tag.
    for m in re.finditer(r"<button([^>]*)>", card):
        attrs = m.group(1)
        assert 'type="button"' in attrs, attrs
        assert "fw-sec-toggle" in attrs, "a button here that is not the fold: %s" % attrs
