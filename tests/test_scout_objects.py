"""Guards for the object picker beside the Scout name field.

The defect this file exists against is NOT an empty dropdown. It is a picker
that QUIETLY NARROWS what may be walked, in one of three ways, each of which
renders as a perfectly ordinary list of names:

* an INTERSECTION of the two sources. Measured on fortiweb13 on 2026-09-10:
  the appliance listed 41 policies and SATOM's harvest held 40, and the one
  they disagreed about was the policy built minutes earlier -- exactly the
  object an operator opens Scout for. An intersection hides it.
* a COMPARATIVE CLAIM made against a list nobody obtained. With the harvest
  unreadable every row is live-only, and stamping "not in the last harvest"
  on all of them states a comparison that never happened.
* a picker that becomes the ONLY way in. An unlicensed FortiWeb-VM answers
  -20010 to every cmdb endpoint; the free-text field is what keeps that
  device walkable, and the select must write into it rather than replace it.

The three are guarded functionally. The two that live in the browser -- the
select writing into the field, and a late answer for the previous appliance
being dropped -- are guarded by reading the shipped JS, which is a weaker
instrument and is named as such rather than dressed up as a render test.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import scout_ladder as sl
from app.services import scout_objects as so
from tests.conftest import admin_user_id, login

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "app" / "templates" / "scout" / "index.html"
JS = ROOT / "app" / "static" / "js" / "scout_objects.js"


class Appl:
    def __init__(self, kind="fortiweb", name="fw13", id=23):
        self.kind, self.name, self.id = kind, name, id


LIVE = [{"name": "pol-scout-web-a", "status": "enable",
         "vserver": "192.0.2.251/24 ", "httpPort": "80", "protocol": "HTTP"},
        {"name": "pol-root-erp", "status": "enable"}]
HELD = [{"name": "pol-root-erp"}, {"name": "pol-root-shop"}]


def _offer(live, held, appliance=None):
    """``offer`` with both sources wired explicitly.

    A source is wired to return exactly what the test names -- including
    ``None``, which every guard below treats as a different answer from ``[]``.
    """
    ports = {"live_objects": lambda a: live, "object_list": lambda a: held}
    return so.offer(appliance or Appl(), ports=ports)


def _names(out):
    return [o["name"] for o in out["objects"]]


def _by(out, name):
    return next(o for o in out["objects"] if o["name"] == name)


# --------------------------------------------------------------------------- #
#  1. a union, never an intersection                                            #
# --------------------------------------------------------------------------- #
def test_an_object_only_the_appliance_lists_is_offered():
    """The live-only row is the measured case: a policy created after the last
    harvest. An intersection drops precisely this one."""
    assert "pol-scout-web-a" in _names(_offer(LIVE, HELD))


def test_an_object_only_the_harvest_holds_is_offered():
    """It may be gone, it may be disabled, it may be a harvest of a device
    that stopped answering. All three are worth walking, and none of them is
    this module's call to make."""
    assert "pol-root-shop" in _names(_offer(LIVE, HELD))


def test_the_offer_is_sorted_and_free_of_duplicates():
    out = _offer(LIVE, HELD)
    assert _names(out) == sorted(set(_names(out)))
    assert _names(out) == ["pol-root-erp", "pol-root-shop", "pol-scout-web-a"]


def test_each_row_says_which_source_it_came_from():
    out = _offer(LIVE, HELD)
    assert _by(out, "pol-root-erp")["source"] == so.BOTH
    assert _by(out, "pol-scout-web-a")["source"] == so.LIVE_ONLY
    assert _by(out, "pol-root-shop")["source"] == so.HARVEST_ONLY


def test_the_odd_rows_carry_a_readable_note_and_the_shared_ones_do_not():
    out = _offer(LIVE, HELD)
    assert _by(out, "pol-scout-web-a")["note"]
    assert _by(out, "pol-root-shop")["note"]
    assert _by(out, "pol-root-erp")["note"] == ""


# --------------------------------------------------------------------------- #
#  2. no comparative claim against a list nobody obtained                       #
# --------------------------------------------------------------------------- #
def test_with_the_harvest_unread_no_row_claims_to_be_missing_from_it():
    """THE guard of this file. Every row is live-only in the set sense, and
    saying so out loud would be a comparison against nothing."""
    out = _offer(LIVE, None)
    assert out["compared"] is False
    assert {o["source"] for o in out["objects"]} == {so.SOLE}
    assert all(o["note"] == "" for o in out["objects"])


def test_with_the_appliance_unread_no_row_claims_to_be_new():
    out = _offer(None, HELD)
    assert out["compared"] is False
    assert {o["source"] for o in out["objects"]} == {so.SOLE}
    assert all(o["note"] == "" for o in out["objects"])


def test_sole_is_not_spelled_both():
    """A payload that says "both" about a row that was never compared is the
    same lie as printing it on screen -- and the browser reads the payload."""
    assert so.SOLE != so.BOTH
    assert {o["source"] for o in _offer(LIVE, None)["objects"]} != {so.BOTH}


# --------------------------------------------------------------------------- #
#  3. "could not ask" is never "there is nothing"                               #
# --------------------------------------------------------------------------- #
def test_neither_source_readable_is_not_an_appliance_with_no_objects():
    out = _offer(None, None)
    assert out["objects"] == []
    assert out["live_answered"] is False and out["harvest_answered"] is False
    low = out["note"].lower()
    assert "would list" in low and "type the name" in low
    #  The sentence a device that ANSWERED "nothing" earns, and this one has
    #  not earned: it never answered.
    assert "lists no" not in low


def test_an_appliance_that_answers_nothing_says_so_in_its_own_words():
    out = _offer([], None)
    assert out["objects"] == []
    assert out["live_answered"] is True
    assert "lists no" in out["note"].lower()


def test_the_two_empty_notes_are_not_the_same_sentence():
    """They render identically -- an empty select -- and mean opposite things."""
    assert _offer(None, None)["note"] != _offer([], None)["note"]


def test_a_source_that_raises_is_not_an_empty_appliance():
    def boom(_a):
        raise RuntimeError("session refused")
    out = so.offer(Appl(), ports={"live_objects": boom,
                                  "object_list": lambda a: None})
    assert out["objects"] == [] and out["live_answered"] is False


def test_a_source_that_returns_the_error_body_is_not_an_empty_appliance():
    """A refused FortiWeb read hands back a dict, not a list. Iterating it
    turns -20010 into "this appliance serves nothing"."""
    err = {"errcode": "-20010", "message": "The license of peer VM FortiWeb "
                                           "is not valid."}
    out = so.offer(Appl(), ports={"live_objects": lambda a: err,
                                  "object_list": lambda a: None})
    assert out["live_answered"] is False


def test_an_unwired_source_is_not_an_empty_appliance():
    out = so.offer(Appl(), ports={})
    assert out["live_answered"] is False and out["harvest_answered"] is False


def test_rows_that_are_not_dicts_are_dropped_rather_than_crashing_the_form():
    out = _offer(["pol-x", None, {"name": "pol-ok"}], None)
    assert _names(out) == ["pol-ok"]


def test_a_row_with_no_name_is_not_offered_as_a_blank_choice():
    out = _offer([{"status": "enable"}, {"name": "pol-ok"}], None)
    assert _names(out) == ["pol-ok"]


# --------------------------------------------------------------------------- #
#  4. the escape hatch, and the cap that is never silent                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("live,held", [(LIVE, HELD), (LIVE, None),
                                       (None, HELD), (None, None), ([], [])])
def test_every_answer_carries_the_sentence_that_keeps_the_field_open(live, held):
    """Whatever the sources did, the operator is told the list does not bound
    what may be walked. Losing this on one branch is losing it exactly where
    the picker is emptiest."""
    out = _offer(live, held)
    assert "can still be typed" in out["escape"]


def test_a_trimmed_list_says_how_many_it_is_not_showing():
    rows = [{"name": "pol-%04d" % i} for i in range(so.MAX_OPTIONS + 7)]
    out = _offer(rows, None)
    assert len(out["objects"]) == so.MAX_OPTIONS
    assert out["total"] == so.MAX_OPTIONS + 7
    assert out["capped"] == 7


def test_a_list_within_the_cap_reports_no_trimming():
    out = _offer(LIVE, HELD)
    assert out["capped"] == 0 and out["total"] == len(out["objects"])


# --------------------------------------------------------------------------- #
#  5. display detail is display only, and normalisation is not interpretation   #
# --------------------------------------------------------------------------- #
def test_the_vip_is_shown_without_its_mask_or_its_trailing_space():
    """``vserver`` arrives as '192.0.2.251/24 '. Marked verbatim it once failed
    as a NAME RESOLUTION error, three rungs below where the fault was."""
    assert _by(_offer(LIVE, HELD), "pol-scout-web-a")["detail"].startswith(
        "192.0.2.251")
    assert "/24" not in _by(_offer(LIVE, HELD), "pol-scout-web-a")["detail"]


def test_a_disabled_object_is_offered_and_its_state_is_shown():
    """Offered because a disabled policy is a fault an operator walks TO, and
    a picker that hides it hides the answer."""
    out = _offer([{"name": "pol-off", "status": "disable"}], None)
    assert _names(out) == ["pol-off"]
    assert "disable" in _by(out, "pol-off")["detail"]


def test_an_enabled_object_does_not_shout_its_normality():
    assert "enable" not in _by(_offer(LIVE, HELD), "pol-root-erp")["detail"]


def test_a_fortiadc_row_keyed_mkey_is_named_not_skipped():
    out = so.offer(Appl(kind="fortiadc"),
                   ports={"live_objects": lambda a: [{"mkey": "vs-shop"}],
                          "object_list": lambda a: None})
    assert _names(out) == ["vs-shop"]
    assert out["noun"] == "virtual server"


def test_the_three_comparative_groups_are_named_by_the_server():
    """An <option> does not wrap: rendered as a suffix the provenance was cut
    off by the column, in the one control where a cut cannot be marked."""
    out = _offer(LIVE, HELD)
    assert set(out["group_label"]) == {so.BOTH, so.LIVE_ONLY, so.HARVEST_ONLY}
    assert all(v for v in out["group_label"].values())


def test_a_group_heading_fits_the_column_that_renders_it():
    """An <option> or <optgroup> label that overflows is cut with no marker --
    the defect of the round before this one, in the one control where §163's
    "say what you trimmed" cannot be applied."""
    for src, label in so.GROUP_LABEL.items():
        heading = "40 · %s" % label
        assert len(heading) <= so.MAX_LABEL, (src, heading, len(heading))


def test_the_full_sentence_survives_the_short_heading():
    """Shortening a label is only honest if the sentence it shortens is still
    written somewhere that wraps."""
    for src in (so.LIVE_ONLY, so.HARVEST_ONLY):
        assert len(so._SOURCE_NOTE[src]) > len(so.GROUP_LABEL[src])
    out = _offer(LIVE, HELD)
    assert _by(out, "pol-scout-web-a")["note"] == so._SOURCE_NOTE[so.LIVE_ONLY]


def test_the_browser_writes_those_sentences_under_the_control():
    src = JS.read_text(encoding="utf-8")
    assert "bits.push(n + ' ' + full" in src


def test_nothing_is_grouped_when_there_was_nothing_to_compare():
    """Grouping rows by provenance against a list nobody obtained invents the
    comparison in the layout instead of in the prose."""
    assert _offer(LIVE, None)["group_label"] == {}
    assert _offer(None, HELD)["group_label"] == {}


def test_the_browser_groups_rather_than_suffixes_the_provenance():
    src = JS.read_text(encoding="utf-8")
    assert "optgroup" in src and "data.group_label" in src


def test_the_odd_groups_are_offered_before_the_ordinary_one():
    """Buried under forty ordinary rows, the row only one source knows about
    might as well not be offered."""
    src = JS.read_text(encoding="utf-8")
    order = re.search(r"\[([^\]]*)\]\.forEach", src).group(1)
    assert order.index("'live'") < order.index("'both'")
    assert order.index("'harvest'") < order.index("'both'")


def test_the_plural_is_the_products_own_and_not_an_appended_s():
    """"server policys" was printed on the picker's own label. No test could
    see it: they all assert on names, and no name is plural."""
    assert so.plural("server policy") == "server policies"
    assert so.plural("virtual server") == "virtual servers"
    assert _offer(LIVE, HELD)["noun_plural"] == "server policies"


def test_the_note_uses_that_plural_too():
    assert "policies" in _offer([], None)["note"]
    assert "policys" not in _offer([], None)["note"]


def test_the_browser_takes_the_plural_from_the_server():
    src = JS.read_text(encoding="utf-8")
    assert "noun_plural" in src


def test_the_noun_follows_the_product():
    assert _offer(LIVE, HELD, Appl(kind="fortiweb"))["noun"] == "server policy"


# --------------------------------------------------------------------------- #
#  6. one author: the picker reads what rung 1 reads                            #
# --------------------------------------------------------------------------- #
def test_the_two_adapters_this_module_needs_are_the_ones_the_ladder_binds():
    """Renaming a port would leave the picker silently empty on every device
    while rung 1 kept working -- and an empty picker looks like a device with
    nothing published."""
    ports = sl.default_ports()
    assert "live_objects" in ports and "object_list" in ports


def test_the_picker_owns_no_reader_of_its_own():
    """Source-level, and deliberately so: the moment this module calls a
    client or a cache directly, the list an operator picks from and the list
    rung 1 searches are two different questions with one answer printed."""
    body = re.sub(r'""".*?"""', "", so.__file__ and
                  Path(so.__file__).read_text(encoding="utf-8"), flags=re.S)
    body = re.sub(r"#.*", "", body)
    for forbidden in ("client_for", "policy_status", "list_with_error",
                      "policy_full_cached"):
        assert forbidden not in body, (
            "%s reaches for %s instead of the ladder's adapter"
            % (Path(so.__file__).name, forbidden))


def test_the_note_dates_the_harvest_it_is_quoting(monkeypatch):
    """A cache-only row is where an operator asks "how old is this?", so the
    age has to come from the harvest's own metadata and not from a counter of
    the word ``read_layer``: the source-level guard below passes against a
    module that reads the timestamp out of the wrong service entirely, and a
    mutation proved it (SURVIVES 17, 2026-09-10)."""
    from app.services import read_layer
    monkeypatch.setattr(read_layer, "read_objects",
                        lambda *a, **k: ([], {"generated_at": "2026-09-04T18:02:11"}))
    assert "2026-09-04 18:02" in _offer(LIVE, HELD)["note"]


def test_a_harvest_with_no_timestamp_still_produces_a_readable_note(monkeypatch):
    """Undated is not a reason to print half a sentence."""
    from app.services import read_layer
    monkeypatch.setattr(read_layer, "read_objects", lambda *a, **k: ([], {}))
    note = _offer(LIVE, HELD)["note"]
    assert note.endswith(".") and "of ." not in note


def test_the_only_direct_read_is_the_harvest_timestamp():
    """``read_layer`` IS named here, once, and only for how old the harvest
    is -- never for what is in it. Membership has one author."""
    src = Path(so.__file__).read_text(encoding="utf-8")
    assert src.count("read_layer") == 2          # the import and the call
    assert "generated_at" in src


# --------------------------------------------------------------------------- #
#  7. the endpoint is scoped exactly like the walk                              #
# --------------------------------------------------------------------------- #
def _an_appliance(app, kind="fortiweb", name="fw13"):
    from app.models import Appliance
    from app.extensions import db
    with app.app_context():
        row = Appliance.query.filter_by(name=name).first()
        if row is None:
            row = Appliance(name=name, host="192.0.2.14", kind=kind,
                            username="admin")
            row.password = "pw"
            db.session.add(row)
            db.session.commit()
        return row.id


def test_the_endpoint_answers_json_for_a_visible_appliance(app, client, monkeypatch):
    aid = _an_appliance(app)
    monkeypatch.setattr(sl, "default_ports",
                        lambda **kw: {"live_objects": lambda a: LIVE,
                                      "object_list": lambda a: None})
    login(client, admin_user_id(app))
    r = client.get("/scout/objects?appliance_id=%d" % aid)
    assert r.status_code == 200
    data = r.get_json()
    assert data["appliance_id"] == aid
    assert "pol-scout-web-a" in [o["name"] for o in data["objects"]]


def test_the_answer_names_the_appliance_it_is_about(app, client, monkeypatch):
    """The browser drops an answer that arrived for a device the operator has
    already moved off. It can only do that if the answer says which one."""
    aid = _an_appliance(app)
    monkeypatch.setattr(sl, "default_ports",
                        lambda **kw: {"live_objects": lambda a: LIVE,
                                      "object_list": lambda a: None})
    login(client, admin_user_id(app))
    assert client.get("/scout/objects?appliance_id=%d" %
                      aid).get_json()["appliance_id"] == aid


def test_an_unknown_id_is_a_404_and_not_an_empty_list(app, client):
    login(client, admin_user_id(app))
    r = client.get("/scout/objects?appliance_id=999999")
    assert r.status_code == 404
    assert r.get_json()["objects"] == []


def test_a_missing_id_is_a_404(app, client):
    login(client, admin_user_id(app))
    assert client.get("/scout/objects").status_code == 404


def test_a_device_of_a_kind_this_ladder_cannot_walk_is_not_offered(app, client):
    aid = _an_appliance(app, kind="fortianalyzer", name="faz-x")
    login(client, admin_user_id(app))
    assert client.get("/scout/objects?appliance_id=%d" % aid).status_code == 404


def test_the_endpoint_needs_a_session(app, client):
    r = client.get("/scout/objects?appliance_id=1")
    assert r.status_code in (302, 401, 403)


# --------------------------------------------------------------------------- #
#  8. the form: the select offers, the field posts                              #
# --------------------------------------------------------------------------- #
def _template() -> str:
    return re.sub(r"\{#.*?#\}", "", TPL.read_text(encoding="utf-8"), flags=re.S)


def test_the_picker_posts_nothing():
    """A control that posts a value nothing reads is the Port/Scheme defect of
    2026-09-10: it looks applied and is discarded."""
    tag = re.search(r'<select[^>]*id="sc-object"[^>]*>', _template()).group(0)
    assert 'name="' not in tag, tag


def test_the_field_the_walk_reads_is_still_a_free_text_input():
    """Replaced by the select, an object the device will not list could never
    be walked -- and that device is the one in this lab."""
    tag = re.search(r'<input[^>]*id="sc-policy"[^>]*>', _template()).group(0)
    assert 'name="policy"' in tag and "<select" not in tag


def test_the_picker_knows_its_endpoint_from_the_router_not_from_a_literal():
    tag = re.search(r'<select[^>]*id="sc-object"[^>]*>', _template()).group(0)
    assert "url_for('scout.objects')" in tag or 'url_for("scout.objects")' in tag
    assert "/scout/objects" not in _template()


def test_the_page_loads_the_picker_script_from_our_own_static_tree():
    body = _template()
    assert "js/scout_objects.js" in body
    assert "{% block scripts %}" in body


def test_the_note_line_the_server_writes_into_exists():
    """Which of "empty" and "could not ask" this is comes from the server --
    the half that knows -- so the element it lands in has to be there."""
    assert 'id="sc-object-note"' in _template()


# --------------------------------------------------------------------------- #
#  9. the browser half, read off the shipped file                               #
#     A text assertion is a weak instrument and is named as one: it proves the  #
#     decision is still written down, not that the browser honours it.          #
# --------------------------------------------------------------------------- #
def test_the_shipped_script_writes_the_pick_into_the_posted_field():
    src = JS.read_text(encoding="utf-8")
    assert "sc-policy" in src and "name.value = pick.value" in src


def test_the_shipped_script_drops_an_answer_for_another_appliance():
    src = JS.read_text(encoding="utf-8")
    assert "data.appliance_id" in src


def test_the_shipped_script_never_paints_a_failure_as_an_empty_list():
    src = JS.read_text(encoding="utf-8")
    assert "could not ask" in src and "catch" in src


def test_the_shipped_script_builds_options_without_innerhtml_of_device_text():
    """Device-supplied names go through textContent. Built as an HTML string,
    an object called <img onerror=...> would be markup on an operator's page."""
    src = JS.read_text(encoding="utf-8")
    assert "o.textContent" in src
    #  Emptying the select is the one assignment allowed; anything else --
    #  including a template string that happens to start with a literal -- is
    #  device text becoming markup. A negative lookahead is NOT enough here:
    #  \s* backtracks to zero and the guard passes over the very line it
    #  means to inspect. It cost this file one red run.
    assert (re.findall(r"\w*\.innerHTML\s*=\s*[^;]*;", src)
            == ["pick.innerHTML = '';"])


# --------------------------------------------------------------------------- #
#  10. the FortiADC count that could never be zero                              #
# --------------------------------------------------------------------------- #
def test_the_virtual_server_endpoint_is_named_in_exactly_one_place():
    """Three callers, one spelling: the picker, rung 1's live source and the
    object count must not become three answers to one question."""
    adc = (ROOT / "app" / "services" / "adc_ops.py").read_text(encoding="utf-8")
    #  LISTING them has one author. Reading ONE by name (``get_object``) is a
    #  different question and legitimately names the endpoint too -- the guard
    #  holds the verb it is about, not the string. Writing it as "the string
    #  appears once" failed against a correct file and would have pushed the
    #  fix into unrelated code.
    assert adc.count('list_with_error("load_balance_virtual_server")') == 1
    assert adc.count("list_virtual_servers(client)") >= 2
    lad = (ROOT / "app" / "services" / "scout_ladder.py").read_text(encoding="utf-8")
    assert "load_balance_virtual_server" not in lad


def test_a_fortiadc_that_lists_nothing_counts_zero_not_three():
    """``inspect_all`` returns a three-key result dict, so len() of it was
    ALWAYS 3: the count could never reach zero and rung 5's "the device lists
    nothing at all" branch -- the branch that keeps a refused read from being
    reported as an empty appliance -- was unreachable on FortiADC."""
    import app.services.adc_ops as adc_ops
    ports = sl.default_ports()
    calls = {}

    class C:
        def list_with_error(self, what):
            calls["what"] = what
            return [], None

    import app.clients as clients
    orig = clients.client_for
    clients.client_for = lambda a: C()
    try:
        assert ports["object_count"](Appl(kind="fortiadc")) == 0
    finally:
        clients.client_for = orig
    assert calls["what"] == "load_balance_virtual_server"


def test_the_live_source_asks_a_fortiadc_too():
    """Before this round the live source answered ``None`` for anything that
    was not a FortiWeb, so on a FortiADC rung 1 had no live opinion at all and
    the picker would have had nothing to offer -- an empty dropdown that reads
    as a device with no virtual servers."""
    ports = sl.default_ports()

    class C:
        def list_with_error(self, what):
            return [{"mkey": "vs-shop"}], None

    import app.clients as clients
    orig = clients.client_for
    clients.client_for = lambda a: C()
    try:
        rows = ports["live_objects"](Appl(kind="fortiadc"))
    finally:
        clients.client_for = orig
    assert [r["name"] for r in rows] == ["vs-shop"]


def test_the_live_source_still_declines_a_product_this_ladder_cannot_walk():
    assert sl.default_ports()["live_objects"](Appl(kind="fortianalyzer")) is None


def test_a_fortiadc_that_refuses_the_list_counts_nothing_at_all():
    ports = sl.default_ports()

    class C:
        def list_with_error(self, what):
            return None, "-20010 licence"

    import app.clients as clients
    orig = clients.client_for
    clients.client_for = lambda a: C()
    try:
        assert ports["object_count"](Appl(kind="fortiadc")) is None
    finally:
        clients.client_for = orig
