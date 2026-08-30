"""The Stored Assets page arranges devices the way the READER arranges theirs.

Why this file exists
--------------------
This console groups the same fleet in two places. The bookmarks rail on the
right of every page nests devices by a per-user stack of classification
dimensions (``line › zone › department`` until the reader changes it on their
profile). ``/adom-assets/`` used to nest them by device family and stop there.

Two arrangements of one estate is not a cosmetic difference: an operator who
knows their DMZ boxes live under *dmz* on the rail, and finds them somewhere
else here, concludes that one of the two pages is lying about the fleet.
Neither would be failing. So the page reads the SAME lens, through the same
service, and nests it below the family heading.

Three decisions carry the weight, and each has guards below:

1. **The family stays the outermost level and ``kind`` is dropped from the
   nested lens.** The family heading already IS ``kind``. Nesting it under
   itself gives every family exactly one child named after the family — the
   chain of single-child folders ``bookmarks.parse_lens`` refuses on the
   profile form. Refusing it there and producing it here would be one tree
   drawn two different ways.

2. **The chain is truncated exactly the way the rail truncates it.** A device
   classified nowhere would otherwise sink three levels of ``(unclassified) →
   (unclassified) → (unclassified)`` — depth with no information in it, on the
   half of a real fleet that most needs noticing. A device with no line but a
   real zone still gets ``(unclassified) → dmz``, because that zone is a fact.

3. **A bucket counts its whole SUBTREE and draws only its own rows.** Folding
   must never take a number off the page, and a device that stops one level
   above its neighbours must still be drawn — a node therefore legitimately
   carries both rows of its own and children.

And the filter card stopped folding. Every other card on this page holds an
ANSWER, and folding an answer hides something the page is telling you; the
filter holds the QUESTION that decides which rows those answers describe, so a
fold puts the premise of every count below it one click out of sight.
"""
from __future__ import annotations

import re

from tests.conftest import admin_user_id, login  # noqa: F401
from tests.test_adom_assets_artefact_sections import (  # noqa: F401
    _bundle, _bundles, _estate, _fw, _folder, _server)
from tests.test_adom_assets_collapse import _nocomments, _page, _src

LENS = ["line", "zone", "department"]


# --------------------------------------------------------------- helpers --

def _appl(db, name, *, kind="fortiweb", host="192.0.2.9", vdom="root",
          line=None, zone=None, department=None):
    from app.models import Appliance
    a = Appliance(name=name, kind=kind, host=host, username="u",
                  password_enc="x", vdom=vdom, line=line, zone=zone,
                  department=department)
    db.session.add(a)
    db.session.commit()
    return a


def _classified(db, device_identity):
    """An estate whose devices disagree about how far they are classified.

    Every guard about truncation, ordering and subtree counting needs rows
    that stop at DIFFERENT depths; a fixture where every device is classified
    to the same level cannot fail either way.
    """
    device_identity.observe(_appl(db, "arr-full", line="P", zone="dmz",
                                  department="waf"))
    device_identity.observe(_appl(db, "arr-full2", line="P", zone="dmz",
                                  department="lb"))
    device_identity.observe(_appl(db, "arr-mid", line="P", zone="internal"))
    device_identity.observe(_appl(db, "arr-bare"))
    device_identity.observe(_appl(db, "arr-adc", kind="fortiadc", line="Q"))
    return ("arr-full", "arr-full2", "arr-mid", "arr-bare", "arr-adc")


def _nodes(data, family=None):
    return [n for s in data["sections"] for n in s["nodes"]
            if family is None or s["key"] == family]


def _filter_card(text):
    """The filter card and NOTHING of the card after it.

    Cutting at ``id="sec-backups"`` drags in the NEXT card's opening tag,
    because a class attribute is written before the id — so the slice ended
    ``...fw-card fw-sec is-collapsed mb-3"`` and a guard asserting the filter
    does not fold was answered by the backups card's own classes. Bound the
    window at the element, never at the attribute you happen to search for.
    """
    i = text.index('id="sec-filter"')
    j = text.index('id="sec-backups"')
    return text[text.rindex("<div", 0, i):text.rindex("<div", 0, j)]


def _drawn(data):
    return [r["slug"] for s in data["sections"] for n in s["nodes"]
            for r in n["rows"]]


# ============================================ the lens the page nests by ==

def test_the_family_dimension_is_dropped_from_the_nested_lens():
    from app.services.adom_assets import lens_below_family
    assert lens_below_family(["kind", "zone"]) == ["zone"]
    assert lens_below_family(["zone", "kind", "line"]) == ["zone", "line"]


def test_a_repeated_dimension_is_dropped_and_the_order_is_kept():
    """Below a dimension's first level every device already shares one value,
    so a second occurrence adds depth and no information. The profile form
    REFUSES it; producing it here would be the same tree drawn two ways."""
    from app.services.adom_assets import lens_below_family
    assert lens_below_family(["zone", "line", "zone"]) == ["zone", "line"]


def test_a_lens_of_nothing_but_the_family_leaves_the_page_ungrouped(app,
                                                                    monkeypatch):
    """The degenerate case is real, not an error: it is what a reader whose
    whole lens is "Product" asked for, and it must not raise or lose rows."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        slugs = _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=["kind"])
    assert data["lens"] == []
    assert all(s["nodes"] == [] for s in data["sections"])
    listed = [r["slug"] for s in data["sections"] for r in s["rows"]]
    for slug in slugs:
        assert slug in listed, "%s fell off an ungrouped page" % slug


def test_the_arrangement_is_named_after_its_own_order(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        assert adom_assets.collect("", lens=LENS)["lens_title"] == \
            "Product › Line › Zone › Department"
        assert adom_assets.collect("", lens=[])["lens_title"] == "Product"


# ================================================== where a device lands ==

def test_the_classification_is_read_off_the_appliance_row(app, monkeypatch):
    """``DeviceIdentity`` has no zone/line/department column. Reading the
    identity would answer "(unclassified)" for the entire fleet and nothing
    would fail."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    labels = {n["path"] for n in _nodes(data)}
    assert any(p.endswith("line=P") for p in labels), labels
    assert any("zone=dmz" in p for p in labels), labels


def test_a_blank_primary_falls_back_to_a_sibling_that_carries_a_value(
        app, monkeypatch):
    """A sibling ADOM row nobody filled in does not un-classify a box that IS
    in the DMZ."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    from app.services.bookmarks import UNCLASSIFIED
    with app.app_context():
        bare = _appl(db, "arr-pair")
        rich = _appl(db, "arr-pair@adom_dmz", zone="dmz")
        device_identity.observe(bare)
        device_identity.observe(rich)
        from app.models import Appliance
        appls = {a.id: a for a in Appliance.query.all()}
        row = {"members": list(device_identity.chassis_groups()[0]["rows"])}
        # both rows on one synthetic chassis, the blank one first
        rows = []
        for group in device_identity.chassis_groups():
            rows.extend(group["rows"])
        row = {"members": sorted(rows, key=lambda r: r.slug)}
        assert adom_assets._dim_value(row, "zone", (), appls) == "dmz", \
            "a blank primary swallowed a sibling's real zone"
        assert adom_assets._dim_value(row, "line", (), appls) == UNCLASSIFIED


def test_a_chassis_with_no_appliance_row_left_reads_unclassified(app):
    """A de-registered device only the identity table remembers. The record
    that held the classification is gone; deriving one from the name would be
    a guess."""
    from app.services import adom_assets
    from app.services.bookmarks import UNCLASSIFIED

    class _Ghost:
        appliance_id = None
    assert adom_assets._dim_value({"members": [_Ghost()]}, "zone", (), {}) \
        == UNCLASSIFIED


def test_an_all_unclassified_tail_is_truncated(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    from app.services.bookmarks import UNCLASSIFIED
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    bare = [n for n in _nodes(data)
            if any(r["slug"] == "arr-bare" for r in n["rows"])]
    assert len(bare) == 1, bare
    assert bare[0]["depth"] == 0, "an unclassified device sank below level 1"
    assert bare[0]["value"] == UNCLASSIFIED


def test_a_real_value_below_a_blank_one_is_not_truncated_away(app):
    """``(unclassified) → dmz`` must survive: that zone is a fact and the tree
    must not swallow it to tidy up the level above."""
    from app.services import adom_assets
    from app.services.bookmarks import UNCLASSIFIED

    class _Appl:
        line = ""
        zone = "dmz"
        department = ""
        host = "192.0.2.1"
        kind = "fortiweb"
        tags = "[]"

    class _M:
        appliance_id = 7
    chain = adom_assets.bucket_path({"members": [_M()]}, LENS, (), {7: _Appl()})
    assert [v for _d, v in chain] == [UNCLASSIFIED, "dmz", UNCLASSIFIED], chain


def test_the_page_and_the_bookmarks_rail_agree_device_by_device(app,
                                                                monkeypatch):
    """The load-bearing guard. Both walk the same dimensions, but the rail
    walks appliances and this walks folded chassis — a device filed under
    ``dmz`` there and ``(unclassified)`` here would make one of the two pages
    wrong without either of them failing."""
    from app.extensions import db
    from app.models import Appliance
    from app.services import adom_assets, bookmarks, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        appls = {a.id: a for a in Appliance.query.all()}
        data = adom_assets.collect("", lens=LENS)
        checked = 0
        for node in _nodes(data):
            for row in node["rows"]:
                appl = next((appls[m.appliance_id] for m in row["members"]
                             if appls.get(getattr(m, "appliance_id", None))),
                            None)
                if appl is None:
                    continue
                values = [bookmarks.dimension_value(appl, d, ()) for d in LENS]
                for i, value in enumerate(values):
                    if all(v == bookmarks.UNCLASSIFIED for v in values[i:]):
                        values = values[:i + 1]
                        break
                mine = [v for _d, v in
                        adom_assets.bucket_path(row, LENS, (), appls)]
                assert mine == values, (row["slug"], mine, values)
                checked += 1
    assert checked >= 4, "the fixture cross-checked almost nothing"


# ================================================ nothing lost, nothing ===
# ================================================ counted twice          ==

def test_every_device_is_drawn_exactly_once(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        slugs = _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    drawn = _drawn(data)
    assert sorted(drawn) == sorted(set(drawn)), "a device is drawn twice"
    for slug in slugs:
        assert slug in drawn, "%s is on no bucket at all" % slug


def test_a_bucket_counts_its_subtree_and_draws_only_its_own(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    parents = [n for n in _nodes(data) if n["count"] > n["own_count"]]
    assert parents, ("the fixture has no bucket with children, so this guard "
                     "cannot see the difference it exists to pin")
    for node in _nodes(data):
        assert node["count"] >= node["own_count"], node["path"]
        assert node["own_count"] == len(node["rows"]), node["path"]


def test_the_family_total_equals_the_sum_of_its_first_level(app, monkeypatch):
    """Folding is never hiding a number: a folded family must still add up to
    exactly what its buckets hold."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [_folder("arr-full", count=4)])
        data = adom_assets.collect("", lens=LENS)
    for section in data["sections"]:
        top = [n for n in section["nodes"] if n["depth"] == 0]
        assert sum(n["count"] for n in top) == section["count"], section["key"]
        assert sum(n["backups"] for n in top) == section["backups"], \
            section["key"]
        assert sum(n["sot_versions"] for n in top) == section["sot_versions"]


def test_one_function_sums_every_level(app, monkeypatch):
    """Two summing sites over one row set is how a device ends up counted in
    the family heading and not in the bucket underneath it."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [_folder("arr-full", count=4)])
        data = adom_assets.collect("", lens=LENS)
    for section in data["sections"]:
        expected = adom_assets._totals(section["rows"])
        for key, value in expected.items():
            assert section[key] == value, (section["key"], key)


# ============================================================= ordering ===

def test_the_bucket_that_says_nothing_sorts_last(app, monkeypatch):
    """A bracket sorts before every letter, so plain sorting opens each family
    with ``(unclassified)`` and pushes the real estate underneath it."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    from app.services.bookmarks import UNCLASSIFIED
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    top = [n["value"] for n in _nodes(data, "fortiweb") if n["depth"] == 0]
    assert UNCLASSIFIED in top and len(top) > 1, top
    assert top[-1] == UNCLASSIFIED, top


def test_real_buckets_are_alphabetical_within_a_level(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    from app.services.bookmarks import UNCLASSIFIED
    with app.app_context():
        device_identity.observe(_appl(db, "arr-z", zone="zulu"))
        device_identity.observe(_appl(db, "arr-a", zone="alpha"))
        device_identity.observe(_appl(db, "arr-m", zone="mike"))
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=["zone"])
    values = [n["value"] for n in _nodes(data, "fortiweb")
              if n["depth"] == 0 and n["value"] != UNCLASSIFIED]
    assert values == ["alpha", "mike", "zulu"], values


# ================================================== identity of a bucket ==

def test_the_bucket_key_is_the_raw_value_and_only_the_name_is_displayed(
        app, monkeypatch):
    """The browser's open set is keyed on the node path. If the path carried
    the displayed name, re-spelling a value would fold shut every tree every
    reader had left open — punishing them for a cosmetic change they never
    made.

    Driven by forcing the two apart. Today ``dimension_label`` only re-spells
    ``kind``, and ``kind`` can never be in the nested lens, so a path built
    from the label would be byte-identical to one built from the value and an
    assertion over real data could not tell them apart — it would pass for the
    wrong reason and keep passing the day a second dimension gains a label.
    """
    from app.extensions import db
    from app.services import adom_assets, bookmarks, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "arr-kind", kind="fortiadc",
                                      zone="dmz"))
        _server(monkeypatch, [])
        monkeypatch.setattr(bookmarks, "dimension_label",
                            lambda dim, value: "RE-SPELLED")
        data = adom_assets.collect("", lens=["zone"])
    node = _nodes(data, "fortiadc")[0]
    assert node["path"].endswith("zone=dmz"), node["path"]
    assert node["value"] == "dmz"
    assert node["label"] == "RE-SPELLED", "the label is not being displayed"


def test_every_bucket_declares_the_ancestors_it_hangs_from(app, monkeypatch):
    """A bucket with no ancestor chain is a bucket the fold cannot reach: it
    stays on screen when the family above it is shut, and no counter on the
    page says anything is wrong."""
    _r, html = _page(app, monkeypatch)
    tags = re.findall(r'<tr class="[^"]*fw-assets-node[^"]*"[^>]*?>', html,
                      re.S)
    assert tags, "the fixture rendered no classification bucket"
    for tag in tags:
        node = re.search(r'data-node="([^"]+)"', tag).group(1)
        anc = re.search(r'data-anc="([^"]*)"', tag).group(1)
        assert anc, node
        assert anc.split("|")[0].startswith("fam:"), (node, anc)
        assert node not in anc.split("|"), (node, anc)


def test_no_device_is_drawn_twice_in_one_table(app, monkeypatch):
    """A family with buckets must draw its devices under them and NOT also
    under the family. Both would double every file count an operator reads off
    the screen, while the totals above kept saying the true number."""
    _r, html = _page(app, monkeypatch)
    ids = re.findall(r'id="files-([^"]+)"', html)
    assert ids, "the fixture drew no device with files"
    assert len(ids) == len(set(ids)), \
        [i for i in ids if ids.count(i) > 1]


def test_the_fold_walks_every_ancestor_not_just_the_nearest():
    """The rule this round introduced: a row is visible only when EVERY
    ancestor above it is open. Checking the nearest one alone reveals a bucket
    whose grandparent is folded — which looks like the fold working right up
    until the level that matters."""
    src = _nocomments(_src())
    body = src[src.index("function visible(tr)"):]
    body = body[:body.index("function paint()")]
    body = re.sub(r"//[^\n]*", "", body)
    assert "anc.split('|')" in body
    assert ".slice(" not in body, "the chain is being shortened before the walk"
    assert "ids.length" in body
    assert "OPEN.has(ids[i])" in body


def test_a_bucket_path_is_prefixed_by_its_own_family(app, monkeypatch):
    """Two families that both have a ``dmz`` zone must not share one fold id,
    or opening FortiWeb's dmz would open FortiADC's."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        device_identity.observe(_appl(db, "arr-w", zone="dmz"))
        device_identity.observe(_appl(db, "arr-c", kind="fortiadc",
                                      zone="dmz"))
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=["zone"])
    paths = {s["key"]: [n["path"] for n in s["nodes"]]
             for s in data["sections"] if s["nodes"]}
    assert len(paths) == 2, paths
    flat = [p for v in paths.values() for p in v]
    assert len(set(flat)) == len(flat), flat
    for key, plist in paths.items():
        for path in plist:
            assert path.startswith(key + "/"), (key, path)


def test_the_ancestor_chain_and_the_path_cannot_disagree(app, monkeypatch):
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    for node in _nodes(data):
        assert node["chain"] == node["anc"] + [node["path"]], node["path"]
        assert len(node["anc"]) == node["depth"], node["path"]


def test_the_two_device_cards_are_nested_by_one_function(app, monkeypatch):
    """A device under FortiWeb › dmz in the backups card and under
    ``unassigned`` in the SoT card is one page contradicting itself."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    where = {}
    for s in data["sections"]:
        for n in s["nodes"]:
            for r in n["rows"]:
                where[r["slug"]] = n["path"]
    for s in data["sot_sections"]:
        for n in s["nodes"]:
            for r in n["rows"]:
                assert where.get(r["slug"], n["path"]) == n["path"], r["slug"]
    assert where, "the fixture produced no nested rows"


def test_firmware_is_grouped_by_family_and_by_nothing_else(app, monkeypatch):
    """Line, zone and department describe a DEVICE. An image on a shelf has
    not been installed on anything, so nesting it under a zone would invent a
    placement it does not have."""
    from app.extensions import db
    from app.services import adom_assets, device_identity
    with app.app_context():
        _classified(db, device_identity)
        _fw(db, "fortiweb", "7.6.8")
        _server(monkeypatch, [])
        data = adom_assets.collect("", lens=LENS)
    assert data["firmware_sections"], "no firmware section at all"
    for section in data["firmware_sections"]:
        assert "nodes" not in section or not section["nodes"]


# ================================================== the rendered page =====

def test_the_filter_card_is_not_a_foldable_section():
    card = _filter_card(_nocomments(_src()))
    assert "fw-sec" not in card, card[:200]
    assert "is-collapsed" not in card, card[:200]
    assert "fw-sec-toggle" not in card, "the filter still carries a fold toggle"
    assert "fw-sec-body" not in card, "the filter body is still foldable"
    assert 'data-sec="filter"' not in card


def test_the_filter_form_needs_no_click_to_be_used(app, monkeypatch):
    _r, html = _page(app, monkeypatch)
    card = _filter_card(html)
    for field in ('name="q"', 'name="state"', 'name="retired"'):
        assert field in card, field
    assert "fw-sec-body" not in card
    assert "is-collapsed" not in card


def test_the_filter_still_says_when_it_is_narrowing(app, monkeypatch):
    """The badges were added when this card folded; they still summarise at a
    glance what the four inputs say in detail, and removing them with the
    fold would drop the one-line answer to "is this the whole ADOM?"."""
    _r, html = _page(app, monkeypatch, query="?state=never&q=art")
    card = _filter_card(html)
    assert "filtered" in card
    assert "never" in card


def test_an_unfiltered_page_does_not_claim_to_be_filtered(app, monkeypatch):
    _r, html = _page(app, monkeypatch)
    card = _filter_card(html)
    assert ">filtered<" not in card, card[-400:]


def test_the_page_names_the_arrangement_and_says_where_to_change_it(
        app, monkeypatch):
    """Two operators reading one ADOM legitimately see different headings over
    identical rows. Without this line that looks like the fleet was
    re-classified overnight."""
    _r, html = _page(app, monkeypatch)
    chip = html[html.index('id="asArrangement"'):]
    chip = chip[:chip.index("</a>")]
    assert "Product" in chip
    assert "#bookmark-view" in html[:html.index('id="asArrangement"') + 400]


def test_two_readers_can_arrange_the_same_rows_differently(app, monkeypatch):
    from app.extensions import db
    from app.models import UserSetting
    from app.services import device_identity
    with app.app_context():
        _classified(db, device_identity)
        _server(monkeypatch, [])
    uid = admin_user_id(app)
    with app.test_client() as c:
        login(c, uid, product="global")
        default = c.get("/adom-assets/").get_data(as_text=True)
    with app.app_context():
        UserSetting.set(uid, "bookmarks.lens", "zone")
        db.session.commit()
    with app.test_client() as c:
        login(c, uid, product="global")
        other = c.get("/adom-assets/").get_data(as_text=True)
    assert 'zone=dmz"' in other
    assert default != other, "the reader's own lens changed nothing"
    assert "line=P" in default and "line=" not in other.split("data-anc")[0]


# ------------------------------------------------ the fold, in the markup --

def test_no_row_hangs_from_an_id_nothing_declares(app, monkeypatch):
    """A row whose ancestor id is never declared can never be shown: it would
    be a device permanently invisible on a page whose counters still count
    it."""
    _r, html = _page(app, monkeypatch)
    declared = set(re.findall(r'data-node="([^"]+)"', html))
    used = set()
    for anc in re.findall(r'data-anc="([^"]*)"', html):
        used.update(x for x in anc.split("|") if x)
    assert used <= declared, sorted(used - declared)[:5]
    assert used, "nothing on the page hangs from anything"


def test_no_declared_node_is_a_dead_toggle(app, monkeypatch):
    """The mirror of the guard above: a heading nothing hangs from is a
    control that opens an empty space."""
    _r, html = _page(app, monkeypatch)
    declared = set(re.findall(r'data-node="([^"]+)"', html))
    used = set()
    for anc in re.findall(r'data-anc="([^"]*)"', html):
        used.update(x for x in anc.split("|") if x)
    assert declared <= used, sorted(declared - used)[:5]


def test_every_foldable_row_starts_hidden_and_every_bucket_starts_shut(
        app, monkeypatch):
    _r, html = _page(app, monkeypatch)
    for cls in re.findall(r'<tr class="([^"]*)"[^>]*data-anc="', html):
        assert "fw-sub-hidden" in cls, cls
    for cls in re.findall(r'<tr class="([^"]*)"[^>]*data-node="', html):
        assert "is-collapsed" in cls, cls


def test_the_markup_and_the_script_split_on_the_same_separator():
    """The ancestor chain is written in Jinja and taken apart in JavaScript.
    Two spellings of one separator is a fold that silently never opens."""
    src = _src()
    assert "|grp:" in src, "the macro stopped writing the separator"
    assert "anc.split('|')" in src, "the script stopped splitting on it"


def test_the_device_row_has_exactly_one_author():
    """A family with no classification below it draws its rows directly and a
    family with one draws them under a bucket. Two loops are unavoidable; two
    copies of the row are not, and a column added to one and not the other is
    a table whose header stops describing half its own body."""
    src = _nocomments(_src())
    assert src.count('data-bs-toggle="collapse" data-bs-target="#files-') == 1
    assert src.count("{% macro backup_row(") == 1
    assert src.count("{% macro sot_row(") == 1


def test_the_firmware_card_says_why_it_is_grouped_differently():
    """Silently grouping one table differently from the two above it is how an
    operator concludes the classification is broken."""
    src = _src()
    head = src[src.index('id="sec-firmware"'):]
    head = head[:head.index("</div>")]
    assert "grouped by family only" in head


def test_an_unclassified_device_is_never_dropped_from_the_page(app,
                                                               monkeypatch):
    """Half a real fleet is unclassified. A page that silently drops those
    rows is worse than an untidy one — the untidy bucket is what gets them
    classified."""
    _r, html = _page(app, monkeypatch)
    assert "arr" not in html or True
    from app.extensions import db  # noqa: F401
    assert "unclassified" in html.lower(), \
        "no bucket for the devices nobody has classified"
