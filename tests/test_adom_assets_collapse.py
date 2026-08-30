"""Every section and subsection folds, and folds SHUT by default.

Why this file exists
--------------------
``/adom-assets/`` holds four unrelated artefact cards, each of them grouped
again by device family. Fully expanded that is one very long page, and the
operator asked for it folded. Folding a page by default is cheap to write and
easy to get subtly wrong, and the three ways it goes wrong are all silent:

1.  **A folded page that cannot open.** The folded state has to be in the
    MARKUP, or the browser paints the whole estate and then collapses it. But
    markup-folded plus a stylesheet that hides the bodies means a page whose
    only way back is JavaScript — and this console serves a nonce'd CSP. So the
    rule and the toggle script are pinned to the SAME ``csp_nonce`` from the
    same response: CSP admits both or drops both, and dropped-both renders
    everything expanded, which is usable. A rule living in ``fortiweb.css``
    would survive a dropped script and leave the page shut for good.

2.  **A warning folded out of sight.** Card 4 raises "every bundle lives on the
    backup server and none on this node — the backup server is a single point
    of failure for SATOM's own recovery". A default-collapsed card that hides
    it silently retracts the warning the card was built to raise. The alerts
    are rendered OUTSIDE the collapsible body.

3.  **An invisible narrowing.** With the filter card folded too, a filtered URL
    would look exactly like an unfiltered one, and "3 devices" stops being a
    statement about the search box and becomes a statement about the estate.
    The folded filter header names every active filter.

The store holds the set of OPEN ids, never the closed ones: an empty set by
default IS "everything folded" with no first-run flag to keep in sync, and a
stored closed-set later read as an open-set would expand exactly the sections
the operator had folded. That mistake has a name here — it is why the probe
cards use ``satom.probecards.open.`` and not the older ``...collapsed.`` key.
"""
from __future__ import annotations

import pathlib
import re

from tests.conftest import admin_user_id, login  # noqa: F401
from tests.test_adom_assets_artefact_sections import (  # noqa: F401
    _bundle, _bundles, _estate, _fw)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TPL = ROOT / "app" / "templates" / "adom_assets" / "index.html"
CSS = ROOT / "app" / "static" / "css" / "fortiweb.css"

#: The cards that fold. ``filter`` is NOT one of them, and its absence is
#: deliberate rather than an oversight: every card listed here holds an ANSWER,
#: and folding an answer hides something the page is telling you. The filter
#: holds the QUESTION that decides which rows those answers describe, so a fold
#: would put the premise of every count below it one click out of sight. The
#: exclusion is pinned by
#: ``test_adom_assets_arrangement.test_the_filter_card_is_not_a_foldable_section``
#: — an omission nothing asserts is one edit away from coming back.
SECTIONS = ("backups", "unclaimed", "sot", "firmware", "satom")


def _src():
    return TPL.read_text(encoding="utf-8")


def _nocomments(text):
    """Jinja and HTML comments stripped.

    Every guard over source text runs through this. The prose in this template
    explains the very invariants being asserted, so a naive substring check is
    answered by the comment that describes it — the eighteenth time that has
    happened in this codebase.
    """
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def _page(app, monkeypatch, query="", product="global"):
    """Render the page for real. Every guard below that talks about what an
    operator SEES goes through here: the folded state is a property of the
    response, and a template-source test cannot tell a class that is written
    from a class that is rendered."""
    from app.extensions import db
    from app.services import device_identity
    with app.app_context():
        _estate(db, monkeypatch, device_identity)
        _fw(db, "fortiweb", "7.6.8")
    uid = admin_user_id(app)
    _bundles(monkeypatch, [_bundle("b1.tar.gz", local=False)])
    with app.test_client() as c:
        login(c, uid, product=product)
        r = c.get("/adom-assets/" + query)
        assert r.status_code == 200, r.status_code
        return r, r.get_data(as_text=True)


# ------------------------------------------------- folded in the markup --

def test_every_section_card_declares_itself_a_foldable_section():
    src = _nocomments(_src())
    found = dict(re.findall(r'<div class="fw-card[^"]*"[^>]*id="sec-([a-z]+)"'
                            r'[^>]*data-sec="([a-z]+)"', src))
    assert set(found) == set(SECTIONS), found
    assert all(k == v for k, v in found.items()), found


def test_every_section_card_renders_collapsed_in_the_markup():
    """Not folded by JS after paint: that flashes the whole estate first."""
    src = _nocomments(_src())
    for key in SECTIONS:
        m = re.search(r'<div class="(fw-card[^"]*)"[^>]*id="sec-%s"' % key, src)
        assert m, key
        assert "fw-sec" in m.group(1), key
        assert "is-collapsed" in m.group(1), (key, m.group(1))


def test_every_section_has_a_body_the_header_points_at():
    src = _nocomments(_src())
    for key in SECTIONS:
        assert 'id="body-%s"' % key in src, key
        assert 'aria-controls="body-%s"' % key in src, key


def test_the_collapse_rule_hides_the_body_and_only_the_body():
    src = _nocomments(_src())
    assert ".fw-sec.is-collapsed > .fw-sec-body { display: none; }" in src


# ------------------------------------------------------- the CSP pairing --

def test_the_collapse_css_and_the_toggle_script_share_one_nonce():
    src = _src()
    styles = re.findall(r'<style nonce="\{\{ csp_nonce \}\}">', src)
    scripts = re.findall(r'<script nonce="\{\{ csp_nonce \}\}">', src)
    assert len(styles) == 1, styles
    assert len(scripts) == 1, scripts


def test_a_real_response_serves_the_same_nonce_it_declares(app, monkeypatch):
    """Comparing against the CSP header of the SAME response. A substring test
    over the page proves nothing: any nonce-looking string satisfies it."""
    r, html = _page(app, monkeypatch)
    header = set(re.findall(r"'nonce-([^']+)'",
                            r.headers.get("Content-Security-Policy", "")))
    assert len(header) == 1, header
    assert set(re.findall(r'<style nonce="([^"]+)"', html)) == header
    assert set(re.findall(r'<script nonce="([^"]+)"', html)) == header


def test_the_collapse_rule_is_not_in_the_shared_stylesheet():
    """It must die with the script, not outlive it. A rule in fortiweb.css
    survives a dropped <script> and leaves the page folded shut forever."""
    assert "fw-sec-body" not in CSS.read_text(encoding="utf-8")


# ------------------------------------------------ nothing important hides --

def test_the_single_point_of_failure_warning_is_outside_the_folded_body():
    src = _nocomments(_src())
    card = src[src.index('id="sec-satom"'):]
    head = card[:card.index('id="body-satom"')]
    assert "single point of failure" in head


def test_a_rendered_warning_survives_the_fold(app, monkeypatch):
    r, html = _page(app, monkeypatch)
    card = html[html.index('id="sec-satom"'):]
    head = card[:card.index('id="body-satom"')]
    assert "single point of failure" in head
    assert 'class="fw-card fw-sec is-collapsed" id="sec-satom"' in html


def test_the_folded_filter_header_names_every_active_filter(app, monkeypatch):
    r, html = _page(
        app, monkeypatch,
        "?state=never&q=art-mute&retired=hide&type=fortiweb")
    head = html[html.index('id="sec-filter"'):html.index('id="body-filter"')]
    assert "filtered" in head
    for token in ("never", "art-mute", "fortiweb"):
        assert token in head, (token, head[-500:])
    assert "de-registered hidden" in head


def test_an_unfiltered_page_does_not_claim_to_be_filtered(app, monkeypatch):
    r, html = _page(app, monkeypatch)
    head = html[html.index('id="sec-filter"'):html.index('id="body-filter"')]
    assert "filtered" not in head, head[-400:]


def test_a_filter_does_not_unfold_the_page(app, monkeypatch):
    """Collapsed by default means collapsed; the header carries the news."""
    r, html = _page(app, monkeypatch, "?state=never")
    for key in SECTIONS:
        m = re.search(r'<div class="(fw-card[^"]*)"[^>]*id="sec-%s"' % key,
                      html)
        if m:
            assert "is-collapsed" in m.group(1), key


# ------------------------------------------------------------ subsections --

def test_every_family_header_is_a_collapsed_subsection(app, monkeypatch):
    """Families and the classification buckets under them are the same kind of
    thing to the fold: a row that owns an id others hang from. One attribute
    (``data-node``) for both, so a level added below can never be the level
    nobody wired up."""
    r, html = _page(app, monkeypatch)
    fams = re.findall(r'<tr class="([^"]*fw-assets-section[^"]*)"\s+'
                      r'data-sec="([a-z]+)"\s+data-node="fam:[a-z]+:([^"]+)"',
                      html)
    assert fams
    assert all("is-collapsed" in cls for cls, _, _ in fams), fams
    assert len({sec for _, sec, _ in fams}) >= 2, fams


def test_every_foldable_row_starts_hidden(app, monkeypatch):
    r, html = _page(app, monkeypatch)
    rows = re.findall(r'<tr class="([^"]*fw-sub-row[^"]*)"', html)
    assert rows
    assert all("fw-sub-hidden" in cls for cls in rows), rows


def test_no_row_is_stranded_and_no_toggle_is_dead(app, monkeypatch):
    """A row whose ancestors nothing declares can never be opened; a heading
    nothing hangs from opens onto nothing.

    Rewritten for the nested arrangement. The old version compared
    ``data-fam`` pairs; once the rows moved to an ancestor CHAIN both sides
    matched empty and the guard passed while measuring nothing at all — which
    is exactly the failure mode it was written to catch, one level up.
    """
    r, html = _page(app, monkeypatch)
    declared = set(re.findall(r'data-node="([^"]+)"', html))
    used = set()
    for anc in re.findall(r'data-anc="([^"]*)"', html):
        used.update(x for x in anc.split("|") if x)
    assert declared, "nothing on the page declares a fold id"
    assert used, "nothing on the page hangs from a fold id"
    assert declared == used, sorted(declared ^ used)[:6]


def test_the_empty_state_row_is_never_marked_hidden(app, monkeypatch):
    """"No device matches this filter" lives outside any family. Marked
    foldable it would be hidden by the default, so a filter that matched
    nothing would open onto a blank table with no explanation."""
    r, html = _page(app, monkeypatch, "?q=zzz-matches-nothing")
    assert "No device matches this filter." in html
    idx = html.index("No device matches this filter.")
    row = html.rindex("<tr", 0, idx)
    assert "fw-sub-hidden" not in html[row:idx], html[row:idx]


def test_the_counts_stay_in_the_header_where_folding_cannot_hide_them(
        app, monkeypatch):
    """A folded section still has to say what it holds."""
    r, html = _page(app, monkeypatch)
    head = html[html.index('id="sec-backups"'):html.index('id="body-backups"')]
    assert "file(s)" in head


# ---------------------------------------------------------- the controls --

def test_the_toggles_are_real_buttons():
    """role="button" on a div would mean hand-rolling Enter and Space, and a
    <th role="button"> also stops being a column header for a screen reader."""
    src = _nocomments(_src())
    assert 'role="button"' not in src
    assert src.count('<button type="button" class="fw-sec-toggle"') == len(SECTIONS)
    # Three family headings, one per table, plus the single macro that writes
    # EVERY classification bucket in all three. A fourth hand-written one
    # would be a second author for the same control.
    assert src.count('<button type="button" class="fw-sub-toggle"') == 4


def test_every_toggle_starts_out_declaring_itself_closed():
    src = _nocomments(_src())
    n = src.count('class="fw-sec-toggle"') + src.count('class="fw-sub-toggle"')
    assert src.count('aria-expanded="false"') == n, n


def test_bootstrap_is_not_driving_the_sections():
    """data-bs-toggle would open sections behind the store's back, so the two
    would disagree the moment either changed."""
    src = _nocomments(_src())
    for m in re.finditer(r'data-bs-toggle="collapse"[^>]*data-bs-target="([^"]+)"',
                         src):
        assert m.group(1).startswith("#files-"), m.group(1)


def test_expand_and_collapse_all_exist():
    src = _nocomments(_src())
    assert 'id="asExpandAll"' in src and 'id="asCollapseAll"' in src


# --------------------------------------------------------------- the store --

def test_the_store_holds_the_open_set_and_defaults_to_empty():
    src = _nocomments(_src())
    assert "'satom.assets.open.' +" in src
    assert "localStorage.getItem(KEY) || '[]'" in src
    assert "JSON.stringify(Array.from(OPEN))" in src


def test_the_store_key_is_not_a_reused_one():
    """Reading a stored closed-set as an open-set expands exactly what the
    operator had folded — the reason the probe page minted a new key too."""
    src = _nocomments(_src())
    assert "satom.assets.collapsed" not in src
    assert "probecards" not in src


def test_the_store_is_scoped_to_the_adom():
    """Global lists every family; a choice made there is not a choice about
    FortiWeb."""
    src = _nocomments(_src())
    assert "'satom.assets.open.' + {{ (product_key or 'global') | tojson }}" in src


def test_two_adoms_do_not_share_a_store_key(app, monkeypatch):
    r, glob = _page(app, monkeypatch, product="global")
    assert "'satom.assets.open.' + \"global\"" in glob


def test_a_family_row_beats_a_bootstrap_collapse_nested_in_it():
    """An open Files table inside a family being folded must go with it; the
    family is the outer container and its rule has to win."""
    src = _nocomments(_src())
    assert "tr.fw-sub-hidden { display: none !important; }" in src


def test_rows_are_matched_by_attribute_not_by_a_built_selector():
    """A zone name is DATA. Interpolating it into a CSS selector makes it
    code, and a zone spelled with a bracket or a dot would then select
    something else — or nothing."""
    src = _nocomments(_src())
    assert "getAttribute('data-anc')" in src
    assert "anc.split('|')" in src
    assert "[data-anc=\"' +" not in src
    assert "[data-node=\"' +" not in src
    assert "[data-fam=\"' +" not in src
