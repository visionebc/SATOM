"""Guards for the "?" beside every control on the Scout walk form.

The defect this file exists against is NOT a missing tooltip. It is a form
that grows a thirteenth control and ships it MUTE: nothing raises, the page
renders, and the one field an operator most needs explained is the one with no
explanation. Help rots silently by construction, so the guard is a two-way
identity between the template's own control list and the catalog -- a new
control with no entry fails, and an entry for a control that was removed fails
too.

The second class guarded here is help that is WRONG, which is worse than help
that is absent: an operator who reads "type the port here" and types one into
a walk that derives its front door has been told to do something the engine
ignores. The texts that describe a dependency are held to naming it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from markupsafe import escape

from app.services import scout_config as sc
from app.services import scout_ladder as sl
from tests.conftest import admin_user_id, login

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "app" / "templates" / "scout" / "index.html"
HINT_MACRO = ROOT / "app" / "templates" / "partials" / "_hint.html"

#: Posted by the form but not typed by a human.
NOT_A_FIELD = {"csrf_token"}


def _template() -> str:
    """The template WITHOUT its Jinja comments.

    Its header comment discusses ``<style>`` and ``<script>`` by name and
    quotes prose about the fields. Asserting over the raw file is how a guard
    ends up matching its own documentation -- this repo has shipped that
    mistake nine times.
    """
    return re.sub(r"\{#.*?#\}", "", TPL.read_text(encoding="utf-8"), flags=re.S)


def _controls() -> set:
    """Every control inside the walk form, read off the template.

    A control declares itself either by the ``name`` it posts or by an
    explicit ``data-fw-control`` key. The second half exists because the
    object picker posts NOTHING -- it loads a list and writes into the field
    beside it, deliberately, since a control that posts a value nothing reads
    is the Port/Scheme defect one round earlier. Matching on ``name`` alone
    made a nameless control invisible to the identity below, which is exactly
    how a control ships mute.
    """
    body = _template()
    names = set(re.findall(r'<(?:input|select|textarea)\b[^>]*\bname="([^"]+)"',
                           body))
    names |= set(re.findall(
        r'<(?:input|select|textarea)\b[^>]*\bdata-fw-control="([^"]+)"', body))
    return names - NOT_A_FIELD


def test_no_control_can_hide_from_the_identity():
    """A control with neither a posted name nor a declared key is unreachable
    by both directions above: it could ship with no explanation and nothing
    would fail. This is the guard on the guard."""
    tags = re.findall(r'<(?:input|select|textarea)\b[^>]*>', _template())
    silent = [t for t in tags
              if 'name="' not in t and 'data-fw-control="' not in t]
    assert not silent, (
        "controls that declare neither a name nor a data-fw-control key, and "
        "so cannot be held to having help: %s" % silent)


# --------------------------------------------------------------------------- #
#  the two-way identity — the guard that actually stops the rot                 #
# --------------------------------------------------------------------------- #
def test_every_control_on_the_form_has_an_explanation():
    """A control added later cannot ship without help."""
    missing = sorted(_controls() - set(sc.WALK_HELP))
    assert not missing, "walk-form controls with no entry in WALK_HELP: %s" % missing


def test_every_explanation_belongs_to_a_control_that_exists():
    """And an entry for a field that was removed is help for a page nobody
    sees -- it reads as coverage while explaining nothing."""
    orphans = sorted(set(sc.WALK_HELP) - _controls())
    assert not orphans, "WALK_HELP entries with no control: %s" % orphans


def test_the_form_actually_has_controls():
    """The two tests above both pass against a template that was emptied, or
    against a regex that stopped matching. This is the one that notices."""
    assert len(_controls()) >= 13


@pytest.mark.parametrize("key", sorted(sc.WALK_HELP))
def test_each_entry_carries_a_label_and_a_text(key):
    row = sc.WALK_HELP[key]
    assert row.get("label"), "%s has no label" % key
    assert len(row.get("text", "")) > 80, "%s has no real explanation" % key


@pytest.mark.parametrize("key", sorted(sc.WALK_HELP))
def test_the_label_still_matches_the_one_on_the_page(key):
    """A hint that names a field by a caption the page stopped using is help
    for a product nobody is running -- the same rot the criteria table is
    written to avoid, one layer up."""
    body = _template()
    label = sc.WALK_HELP[key]["label"]
    assert ">%s</label>" % label in body, (
        "no <label> reading %r on the page for %s" % (label, key))


@pytest.mark.parametrize(
    "key", sorted(k for k, v in sc.WALK_HELP.items() if v.get("default_from")))
def test_a_named_site_default_is_a_real_setting(key):
    """``default_from`` is the LINK between the two catalogs. Pointing it at a
    key SPEC does not have would print the 'pre-filled from Settings' promise
    over a setting that is not there."""
    assert sc.WALK_HELP[key]["default_from"] in {s["key"] for s in sc.SPEC}


def test_exactly_the_prefilled_controls_claim_a_site_default():
    """The five the view pre-fills from the store, and no others. Claiming it
    for a control the site does not back sends an operator to a settings page
    that has no such field."""
    claimed = {k for k, v in sc.WALK_HELP.items() if v.get("default_from")}
    assert claimed == {"window_minutes", "use_ssh",
                       "faz_adom", "faz_devid", "faz_vdom"}


# --------------------------------------------------------------------------- #
#  the finished text                                                            #
# --------------------------------------------------------------------------- #
def test_the_window_ceiling_is_the_engine_s_and_is_substituted():
    """Re-typed, the ceiling in the prose disagrees with the clamp the day
    MAX_WINDOW_MIN moves. Left unsubstituted, the operator reads the literal
    '%(max)s'."""
    text = sc.walk_help()["window_minutes"]
    assert str(sl.MAX_WINDOW_MIN) in text
    assert "%(max)s" not in text


def test_the_window_ceiling_follows_the_module(monkeypatch):
    """Read at call time off the live attribute, not frozen at import."""
    monkeypatch.setattr(sl, "MAX_WINDOW_MIN", 777)
    assert "777" in sc.walk_help()["window_minutes"]


def test_the_site_default_sentence_is_appended_once_and_only_where_claimed():
    out = sc.walk_help()
    for key, row in sc.WALK_HELP.items():
        n = out[key].count(sc.DEFAULT_SENTENCE.strip())
        assert n == (1 if row.get("default_from") else 0), (
            "%s: site-default sentence appears %d times" % (key, n))


def test_walk_help_covers_every_entry():
    assert set(sc.walk_help()) == set(sc.WALK_HELP)


def test_walk_help_degrades_instead_of_raising(monkeypatch):
    """This is the help on a page opened during an incident. A catalog that
    cannot be finished must not take the ladder away."""
    monkeypatch.delattr(sl, "MAX_WINDOW_MIN")
    out = sc.walk_help()
    assert set(out) == set(sc.WALK_HELP)


# --------------------------------------------------------------------------- #
#  help that would be WRONG                                                     #
# --------------------------------------------------------------------------- #
def test_port_and_scheme_say_they_are_ignored_without_a_typed_host():
    """_endpoint() consults target.port and target.scheme ONLY on the branch
    where a hostname was typed; on the derived branch both arrive off the
    device and the typed values are dropped. Help that does not say so tells
    the operator to set something the walk ignores."""
    for key in ("port", "scheme"):
        text = sc.walk_help()[key]
        assert "only" in text.lower() and "Published host" in text, (
            "%s does not state the typed-host dependency" % key)


def test_the_border_fields_refuse_to_call_an_empty_result_clean():
    """Zero rows from a wrong ADOM, a wrong devid or an absent collector are
    indistinguishable from zero rows because nothing happened. Rung 7 reports
    UNKNOWN for exactly that reason, and the help must not promise otherwise."""
    out = sc.walk_help()
    for key in ("faz_adom", "faz_devid"):
        assert "UNKNOWN" in out[key], "%s does not name the UNKNOWN verdict" % key
    assert "never reports a clean path" in out["analyzer_id"]


def test_the_ssh_field_keeps_the_two_vantages_apart():
    """The one sentence that makes rung 6 worth reading: this node's path is
    not the appliance's path."""
    text = sc.walk_help()["use_ssh"]
    assert "management network" in text
    assert "SATOM cannot reach" in text and "WAF cannot reach" in text


def test_no_explanation_promises_that_scout_writes():
    """Scout is read only on every rung. A hint that says otherwise is the one
    kind of wrong text that gets someone to run it during a change freeze."""
    for key, text in sc.walk_help().items():
        low = text.lower()
        for verb in ("will fix", "repairs", "applies the change", "writes to"):
            assert verb not in low, "%s promises a write: %r" % (key, verb)


# --------------------------------------------------------------------------- #
#  the rendered page                                                            #
# --------------------------------------------------------------------------- #
def _page(app, client) -> str:
    login(client, admin_user_id(app))
    r = client.get("/scout/")
    assert r.status_code == 200
    return r.get_data(as_text=True)


@pytest.mark.parametrize("key", sorted(sc.WALK_HELP))
def test_the_page_renders_a_question_mark_carrying_that_text(app, client, key):
    """Drives the real view. The catalog existing is not the deliverable --
    the page carrying it is, and a context variable renamed on one side of
    that hand-off renders an EMPTY hint, which the macro drops silently."""
    html = _page(app, client)
    text = sc.walk_help()[key]
    # ESCAPED, and that is the point: the text lands in an attribute, so an
    # apostrophe is &#39; and the arrow is &#8594;. Probing with the raw
    # string reported a missing hint for `policy` against a page that was
    # rendering it correctly.
    probe = str(escape(text.split(".")[0][:60]))
    assert probe in html, "no rendered hint for %s" % key


def test_the_page_renders_one_question_mark_per_control(app, client):
    html = _page(app, client)
    assert html.count("data-fw-hint") == len(sc.WALK_HELP)


def test_every_question_mark_is_reachable_without_a_mouse(app, client):
    """Hover-only help does not exist on a phone, and a <span> is not
    focusable. The macro's contract; asserted here because THIS page is where
    it would be silently lost by hand-written markup."""
    html = _page(app, client)
    assert html.count('type="button" class="fw-hint"') == len(sc.WALK_HELP)
    assert html.count("aria-label=") >= len(sc.WALK_HELP)


def test_the_page_uses_the_shared_macro_rather_than_its_own_markup():
    """Six lines of copied markup per page is how this product ended up with
    two spellings of the same chrome before."""
    assert '{% from "partials/_hint.html" import hint %}' in _template()
    assert HINT_MACRO.exists()


def test_the_template_still_ships_no_inline_style_or_script():
    """Under this CSP an un-nonced <style> renders the page with NO css and an
    un-nonced <script> loses its behaviour -- both have shipped that way. The
    "?" needs neither: fw_hints.js is loaded once in <head> for every page."""
    body = _template()
    assert "<style" not in body
    #  An EXTERNAL file is served from 'self' and is not the hazard this guard
    #  was written for; an inline block is, and it fails in silence. The rule
    #  is therefore the real one -- no inline script, and no origin but our
    #  own -- rather than the proxy "no script tag at all", which was written
    #  before this page had any behaviour to load and would now be satisfied
    #  by deleting the picker.
    for tag in re.findall(r"<script\b[^>]*>", body):
        assert " src=" in tag, (
            "inline <script> in a template whose CSP drops un-nonced blocks "
            "without a word: %s" % tag)
        assert "url_for('static'" in tag or 'url_for("static"' in tag, (
            "script loaded from something other than this app's own static "
            "tree: %s" % tag)
