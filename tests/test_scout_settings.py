"""Guards for Scout's Admin Console section — the site knobs and the criteria.

Two failures are guarded here, and NEITHER of them breaks anything visibly.

1.  A knob that is RENDERED AND NEVER READ.  This product has already shipped
    one (``metrics.vm_url``, unconfigurable for months behind a wrong accessor
    name and a broad ``except``): the operator edits the field, saves, sees the
    success flash, and the behaviour does not move.  Nothing fails.  The guards
    below therefore drive the real page — set the store, walk the ladder,
    CAPTURE what the engine was handed — rather than asserting that a field
    exists.

2.  A CRITERION that drifts, or becomes editable.  The decision constants say
    what a verdict means.  Displayed as re-typed literals they go stale in
    silence, and the page then explains a product nobody is running; made
    editable they give every archived report a second author, with nothing on
    the report recording which rules produced it.  So: the values are read off
    the live module (proved by moving the module attribute and watching the
    page follow), and the save endpoint is proved to refuse them.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import faz_logs
from app.services import scout_config as sc
from app.services import scout_ladder as sl
from tests.conftest import admin_user_id, login

ROOT = Path(__file__).resolve().parents[1]
NAV = ROOT / "app" / "templates" / "settings" / "_nav.html"
CONSOLE = ROOT / "app" / "templates" / "settings" / "index.html"


# --------------------------------------------------------------------------- #
#  the catalog                                                                  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("spec", sc.SPEC, ids=[s["key"] for s in sc.SPEC])
def test_every_knob_carries_a_label_a_summary_and_a_long_answer(spec):
    """A knob documented only by its own label is a knob to be guessed at."""
    for field in ("label", "help", "hint"):
        assert spec.get(field), "%s has no %s" % (spec["key"], field)
    assert spec["group"] in dict(sc.GROUPS)
    assert spec["kind"] in ("bool", "int", "float", "str")
    assert "default" in spec


def test_the_window_default_and_ceiling_come_from_the_engine():
    """Re-typed here, they would disagree with the code the day it changed —
    and a form whose default is not the code's default documents a product
    nobody is running."""
    win = next(s for s in sc.SPEC if s["key"] == "window_minutes")
    assert win["default"] == sl.DEFAULT_WINDOW_MIN
    assert win["max"] == sl.MAX_WINDOW_MIN


def test_the_border_query_size_and_patience_come_from_faz_logs():
    lim = next(s for s in sc.SPEC if s["key"] == "faz_limit")
    tmo = next(s for s in sc.SPEC if s["key"] == "faz_timeout")
    assert lim["default"] == faz_logs.DEFAULT_LIMIT
    assert lim["max"] == faz_logs.MAX_LIMIT
    assert tmo["default"] == faz_logs.DEFAULT_TIMEOUT


def test_no_criterion_is_also_a_setting():
    """The two catalogs must not overlap.  A judgement constant that acquires a
    SPEC entry becomes editable without anyone deciding that it should."""
    keys = {s["key"] for s in sc.SPEC}
    for _g, _lbl, rows in sc.criteria():
        for row in rows:
            tail = row["symbol"].rsplit(".", 1)[-1].lower()
            assert tail not in keys, "%s is offered as a setting" % row["symbol"]


# --------------------------------------------------------------------------- #
#  the store                                                                    #
# --------------------------------------------------------------------------- #
def test_values_survive_a_round_trip(app):
    with app.app_context():
        sc.set_value("faz_adom", "border")
        sc.set_value("window_minutes", 45)
        sc.set_value("probe_timeout", 12.5)
        sc.set_value("use_ssh", True)
        assert sc.get("faz_adom") == "border"
        assert sc.get("window_minutes") == 45
        assert sc.get("probe_timeout") == 12.5
        assert sc.get("use_ssh") is True


def test_a_switch_can_be_turned_back_off(app):
    with app.app_context():
        sc.set_value("use_ssh", True)
        sc.set_value("use_ssh", False)
        assert sc.get("use_ssh") is False


def test_values_are_clamped_not_trusted(app):
    with app.app_context():
        sc.set_value("window_minutes", 10 ** 6)
        assert sc.get("window_minutes") == sl.MAX_WINDOW_MIN
        sc.set_value("faz_limit", 10 ** 6)
        assert sc.get("faz_limit") == faz_logs.MAX_LIMIT
        sc.set_value("probe_timeout", 0)
        assert sc.get("probe_timeout") == 1.0


def test_unparseable_stored_text_falls_back_to_the_shipped_default(app):
    """A row hand-edited to nonsense must not take the page down; it must run
    on the value a fresh install runs on."""
    from app.services import settings_store
    with app.app_context():
        settings_store.set_str(sc.PREFIX + "window_minutes", "not a number")
        assert sc.get("window_minutes") == sl.DEFAULT_WINDOW_MIN


def test_an_unknown_key_raises_rather_than_inventing_a_default():
    with pytest.raises(KeyError):
        sc.get("no_such_knob")
    with pytest.raises(KeyError):
        sc.set_value("no_such_knob", 1)


def test_walk_defaults_covers_every_knob(app):
    with app.app_context():
        got = sc.walk_defaults()
    assert set(got) == {s["key"] for s in sc.SPEC}


def test_walk_defaults_degrades_instead_of_denying_the_ladder(monkeypatch):
    """Scout is opened during an incident.  A settings table that cannot be
    read is not a reason to refuse an operator the walk."""
    monkeypatch.setattr(sc, "all_values",
                        lambda: (_ for _ in ()).throw(RuntimeError("no db")))
    got = sc.walk_defaults()
    assert got["window_minutes"] == sl.DEFAULT_WINDOW_MIN
    assert set(got) == {s["key"] for s in sc.SPEC}


# --------------------------------------------------------------------------- #
#  the criteria are READ, never typed                                           #
# --------------------------------------------------------------------------- #
def test_a_criterion_follows_the_engine_constant(monkeypatch):
    monkeypatch.setattr(sl, "DOMINANT_SHARE", 0.4242)
    flat = {r["label"]: r["value"] for _g, _l, rows in sc.criteria()
            for r in rows}
    assert "0.4242" in flat["Dominant-phase share"]


def test_a_border_ceiling_follows_faz_logs(monkeypatch):
    monkeypatch.setattr(faz_logs, "MAX_LIMIT", 4321)
    flat = {r["label"]: r["value"] for _g, _l, rows in sc.criteria()
            for r in rows}
    assert "4321" in flat["Rows per border query (ceiling)"]


def test_a_tuple_criterion_follows_the_engine_and_keeps_its_order(monkeypatch):
    monkeypatch.setattr(sl, "PATH_ORDER", ("zeta", "alpha"))
    flat = {r["label"]: r["value"] for _g, _l, rows in sc.criteria()
            for r in rows}
    assert flat["Border verdict precedence"] == "zeta > alpha"


def test_a_set_criterion_is_not_drawn_as_a_precedence(monkeypatch):
    """Arrows mean "resolved in this order".  SAFE_METHODS and
    BLOCKING_SIGNALS are sets: drawing them with arrows tells the reader that
    GET outranks HEAD, which is an ordering nobody wrote and the reader has no
    way to check."""
    monkeypatch.setattr(sl, "SAFE_METHODS", ("GET", "HEAD"))
    monkeypatch.setattr(sl, "BLOCKING_SIGNALS", ("capacity", "probe"))
    flat = {r["label"]: r["value"] for _g, _l, rows in sc.criteria()
            for r in rows}
    assert flat["Methods Scout will send"] == "GET, HEAD"
    assert flat["Signals that BLOCK the walk"] == "capacity, probe"


def test_only_the_precedence_criteria_are_flagged_as_ordered():
    ordered = {r["label"] for _g, _l, rows in sc.criteria()
               for r in rows if r["ordered"]}
    assert ordered == {"Border verdict precedence",
                       "Verdict precedence (worst first)"}


@pytest.mark.parametrize("row", [r for _g, _l, rows in sc.criteria()
                                 for r in rows],
                         ids=[r["label"] for _g, _l, rows in sc.criteria()
                              for r in rows])
def test_every_criterion_names_its_source_and_says_why(row):
    assert "." in row["symbol"], "%s has no source symbol" % row["label"]
    assert len(row["why"]) > 40, "%s has no argument" % row["label"]
    assert row["value"] != ""


# --------------------------------------------------------------------------- #
#  the page READS the settings — the unread-knob guard                          #
# --------------------------------------------------------------------------- #
class _Appl:
    kind, name, host, id = "fortiweb", "fw13", "192.0.2.14", 1


@pytest.fixture()
def walked(app, client, monkeypatch):
    """POST a walk and hand back what the ENGINE was actually given."""
    seen = {}

    def fake_run(target, opts, ports, **kw):
        seen["opts"] = opts
        return {"verdict": sl.PASS, "layers": [], "summary": "",
                "blind": 0, "target": {}}

    def fake_ports(**kw):
        seen["ports"] = kw
        return {}

    monkeypatch.setattr(sl, "run", fake_run)
    monkeypatch.setattr(sl, "default_ports", fake_ports)

    def go(form=None, store=None):
        from app.models import Appliance
        from app.extensions import db
        with app.app_context():
            for k, v in (store or {}).items():
                sc.set_value(k, v)
            row = Appliance.query.first()
            if row is None:
                row = Appliance(name="fw13", host="192.0.2.14",
                                kind="fortiweb", username="admin")
                row.password = "pw"
                db.session.add(row)
                db.session.commit()
            aid = row.id
        login(client, admin_user_id(app))
        body = {"appliance_id": str(aid), "policy": "pol-x",
                "hostname": "svc.example.test"}
        body.update(form or {})
        client.post("/scout/", data=body)
        return seen

    return go


def test_the_walk_uses_the_configured_window(walked):
    seen = walked(store={"window_minutes": 77})
    assert seen["opts"].window_minutes == 77


def test_the_walk_uses_the_configured_probe_timeout(walked):
    seen = walked(store={"probe_timeout": 17.0})
    assert seen["opts"].timeout == 17.0


def test_the_walk_uses_the_configured_border_selector(walked):
    seen = walked(store={"faz_adom": "border", "faz_devid": "FGT-1",
                         "faz_vdom": "edge"})
    assert seen["opts"].faz_adom == "border"
    assert seen["opts"].faz_devid == "FGT-1"
    assert seen["opts"].faz_vdom == "edge"
    assert seen["ports"]["faz_adom"] == "border"


def test_the_walk_uses_the_configured_border_size_and_patience(walked):
    seen = walked(store={"faz_limit": 750, "faz_timeout": 55.0})
    assert seen["ports"]["faz_limit"] == 750
    assert seen["ports"]["faz_timeout"] == 55.0


def test_a_typed_window_beats_the_site_default(walked):
    """The site sets the STARTING point, never the answer: an operator who
    types a window is diagnosing something the default does not cover."""
    seen = walked(store={"window_minutes": 77}, form={"window_minutes": "5"})
    assert seen["opts"].window_minutes == 5


def test_a_cleared_ssh_box_stays_cleared_even_when_the_site_pre_ticks_it(walked):
    """An unticked checkbox POSTs nothing.  Falling back to the site default on
    a POST would make the box impossible to clear — the switch that can be
    turned on and never off, one form up."""
    seen = walked(store={"use_ssh": True})
    assert seen["opts"].use_ssh is False


def test_the_form_is_prefilled_from_the_store(app, client):
    with app.app_context():
        sc.set_value("faz_adom", "border")
        sc.set_value("window_minutes", 77)
        sc.set_value("use_ssh", True)
    login(client, admin_user_id(app))
    html = client.get("/scout/").get_data(as_text=True)
    assert 'value="border"' in html
    assert 'value="77"' in html


# --------------------------------------------------------------------------- #
#  the save endpoint                                                            #
# --------------------------------------------------------------------------- #
def _save(client, app, data):
    login(client, admin_user_id(app))
    return client.post("/settings/scout", data=data, follow_redirects=False)


def test_saving_persists_a_knob(app, client):
    _save(client, app, {"faz_adom": "border", "window_minutes": "45"})
    with app.app_context():
        assert sc.get("faz_adom") == "border"
        assert sc.get("window_minutes") == 45


def test_saving_clamps_instead_of_storing_an_impossible_window(app, client):
    _save(client, app, {"window_minutes": "999999"})
    with app.app_context():
        assert sc.get("window_minutes") == sl.MAX_WINDOW_MIN


def test_a_switch_is_cleared_only_when_the_form_says_it_was_on_the_page(app, client):
    with app.app_context():
        sc.set_value("use_ssh", True)
    # posted WITHOUT the presence marker: the field was not on this form
    _save(client, app, {"faz_adom": "root"})
    with app.app_context():
        assert sc.get("use_ssh") is True
    # posted WITH the marker and no box: the operator cleared it
    _save(client, app, {"use_ssh__present": "1"})
    with app.app_context():
        assert sc.get("use_ssh") is False


def test_the_endpoint_refuses_to_write_a_criterion(app, client):
    """The page renders them read-only; the handler has to agree.  A lock on
    the door and none on the window is not a lock."""
    before = sl.DOMINANT_SHARE
    _save(client, app, {"DOMINANT_SHARE": "0.1", "dominant_share": "0.1",
                        "CERT_WARN_DAYS": "999", "PATH_ORDER": "accept"})
    assert sl.DOMINANT_SHARE == before
    from app.services import settings_store
    with app.app_context():
        assert settings_store.get_str(sc.PREFIX + "DOMINANT_SHARE") is None
        assert settings_store.get_str(sc.PREFIX + "dominant_share") is None


# --------------------------------------------------------------------------- #
#  the menu and the panes                                                       #
# --------------------------------------------------------------------------- #
def _nav_groups() -> list:
    """Parsed from the template that RENDERS the menu, never re-typed."""
    import ast
    src = NAV.read_text()
    m = re.search(r"\{%\s*set nav_groups\s*=\s*(\[.*?\])\s*%\}", src, re.S)
    assert m, "nav_groups literal not found"
    body = re.sub(r"_\(\s*('([^']*)'|\"([^\"]*)\")\s*\)", r"\1", m.group(1))
    return ast.literal_eval(body.replace("true", "True").replace("false", "False"))


def test_scout_is_its_own_group_directly_below_sentinel():
    keys = [g["key"] for g in _nav_groups()]
    assert keys[-1] == "scout", "Scout must be the last group; menu is %s" % keys
    assert keys[keys.index("scout") - 1] == "sentinel"


def test_the_scout_group_offers_settings_and_architecture_as_panes():
    g = next(x for x in _nav_groups() if x["key"] == "scout")
    assert [i["t"] for i in g["items"]] == ["tab-scout", "tab-scout-docs"]
    # `ep` would draw the leaving arrow and replace the whole page.  Neither
    # of these does.
    assert not any("ep" in i for i in g["items"])
    assert g["admin"] is True


@pytest.mark.parametrize("target", ["tab-scout", "tab-scout-docs"])
def test_every_scout_menu_target_has_a_pane_to_switch_to(target):
    """A menu row whose pane does not exist highlights, folds the accordion and
    then shows nothing — the failure a tab cannot report."""
    assert 'id="%s"' % target in CONSOLE.read_text()


# --------------------------------------------------------------------------- #
#  the rendered panes                                                           #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def console(app, client):
    login(client, admin_user_id(app))
    return client.get("/settings/").get_data(as_text=True)


def test_the_settings_pane_renders_every_knob(console):
    for spec in sc.SPEC:
        assert 'name="%s"' % spec["key"] in console, \
            "%s is not on the page" % spec["key"]
        assert "scout.%s" % spec["key"] in console


def test_the_criteria_table_shows_the_live_constant(app, client, monkeypatch):
    """Rendered through the accessor, not typed into the template: move the
    engine's constant and the page has to move with it."""
    monkeypatch.setattr(sl, "DOMINANT_SHARE", 0.4242)
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert "0.4242" in html


def test_the_criteria_are_not_offered_as_inputs(console):
    """Read-only means no widget.  A disabled-looking value that is in fact an
    input is a control an operator will try to use."""
    pane = console.split('id="tab-scout"', 1)[1].split('id="tab-scout-docs"', 1)[0]
    for symbol in ("DOMINANT_SHARE", "BLOCKING_SIGNALS", "PATH_ORDER",
                   "SAFE_METHODS"):
        assert 'name="%s"' % symbol not in pane


def test_the_architecture_pane_draws_the_ladder_the_engine_walks(console):
    pane = console.split('id="tab-scout-docs"', 1)[1]
    for layer in sl.LADDER:
        assert layer.title in pane, "rung %s is missing" % layer.key
        assert layer.question in pane


def test_the_architecture_pane_follows_a_change_to_the_ladder(app, client,
                                                              monkeypatch):
    """Derived, not transcribed: a rung added to the engine appears here in the
    same commit, and a document that disagrees with the engine is read to
    decide whether a report is complete."""
    extra = sl.Layer("X", "Invented rung", "does the derivation hold?",
                     sl.V_SATOM, lambda ctx: None)
    monkeypatch.setattr(sl, "LADDER", tuple(sl.LADDER) + (extra,))
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert "Invented rung" in html


# --------------------------------------------------------------------------- #
#  the border query's size never arrives as zero                                #
# --------------------------------------------------------------------------- #
def _border(monkeypatch, **kw):
    seen = {}
    monkeypatch.setattr(faz_logs, "reachable", lambda a: (True, ""))
    monkeypatch.setattr(faz_logs, "search",
                        lambda *a, **k: (seen.update(k), ([], ""))[1])
    monkeypatch.setattr(faz_logs, "device_selector", lambda d, v: [])
    ports = sl.default_ports(analyzer=object(), **kw)
    ports["border_logs"](src="1.1.1.1", dst="2.2.2.2", minutes=5)
    return seen


def test_an_unset_size_means_the_shipped_default_not_zero_rows(monkeypatch):
    assert _border(monkeypatch)["limit"] == faz_logs.DEFAULT_LIMIT


def test_a_zero_size_is_read_as_unset_rather_than_asked_for(monkeypatch):
    """Asking the analyzer for no rows would make rung 7 report UNKNOWN for a
    border that answered perfectly."""
    seen = _border(monkeypatch, faz_limit=0, faz_timeout=0)
    assert seen["limit"] == faz_logs.DEFAULT_LIMIT
    assert seen["timeout"] == faz_logs.DEFAULT_TIMEOUT


def test_a_configured_size_and_patience_reach_the_analyzer(monkeypatch):
    seen = _border(monkeypatch, faz_limit=750, faz_timeout=55.0)
    assert seen["limit"] == 750
    assert seen["timeout"] == 55.0
