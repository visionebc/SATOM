"""Guards for the Concept Map (/map) — safeguards §74.

The map's whole value is a claim: *"this is every page in the console, and
here is what each one is for."* Nothing in the product fails when that claim
stops being true — a page added next month simply never appears, and the map
still LOOKS complete. That is the failure mode these tests exist to make loud.

Three properties, in descending order of how quietly they would rot:

1. **Coverage.** Every parameterless GET endpoint is either mapped or excluded
   with a reason. A new page fails this test until someone spends one line.
2. **No second source of truth.** URLs come from ``url_for``; the required
   permission is read off the view function, never re-declared in the
   registry. A copied permission drifts and the map starts advertising 403s.
3. **Reachability.** The map is registered in every ADOM allowlist and linked
   from the footer — an index nobody can open is not an index.
"""
from __future__ import annotations

import ast
import re

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

from app.services import concept_map as cmap


# --------------------------------------------------------------------------
# 1 — coverage: the URL map is the authority
# --------------------------------------------------------------------------
def test_every_page_endpoint_is_mapped_or_excluded_with_a_reason(app):
    """The guard that makes the map's coverage claim TRUE rather than hopeful.

    A page added without an entry lands here, not in a user's confusion.
    """
    with app.app_context():
        live = cmap.page_endpoints(app)
    mapped = {p["endpoint"] for p in cmap.PAGES}
    orphans = sorted(live - mapped - set(cmap.EXCLUDED))
    assert not orphans, (
        "These endpoints exist but are neither on the concept map nor excluded. "
        "Add them to PAGES (with a concept + search keywords) or to EXCLUDED "
        f"with a one-word reason: {orphans}")


def test_no_mapped_entry_points_at_an_endpoint_that_is_gone(app):
    with app.app_context():
        live = cmap.page_endpoints(app)
    dangling = sorted({p["endpoint"] for p in cmap.PAGES} - live)
    assert not dangling, f"mapped endpoints that no longer exist: {dangling}"


def test_every_exclusion_carries_a_non_empty_reason():
    blank = [k for k, v in cmap.EXCLUDED.items() if not (v or "").strip()]
    assert not blank, f"exclusions without a reason: {blank}"


def test_coverage_counts_add_up(app):
    """``coverage()`` is printed on the page — it must describe the real map."""
    with app.app_context():
        cov = cmap.coverage(app)
    assert cov["unmapped"] == []
    assert cov["dangling"] == []
    assert cov["mapped"] + cov["excluded"] == cov["live"]


def test_coverage_reports_a_hole_instead_of_hiding_it(app, monkeypatch):
    """A map that quietly omits pages reads exactly like a complete one.

    Mutation target: making ``coverage()`` return ``unmapped: []`` unconditionally
    must fail here.
    """
    with app.app_context():
        real = cmap.page_endpoints(app)
        monkeypatch.setattr(cmap, "page_endpoints",
                            lambda a=None: real | {"ghost.page"})
        cov = cmap.coverage(app)
    assert "ghost.page" in cov["unmapped"]


# --------------------------------------------------------------------------
# 2 — structure and identity
# --------------------------------------------------------------------------
def test_every_page_declares_a_known_concept():
    unknown = sorted({p["concept"] for p in cmap.PAGES} - set(cmap.CONCEPT_KEYS))
    assert not unknown, f"pages point at concepts that do not exist: {unknown}"


def test_every_concept_has_at_least_one_page():
    used = {p["concept"] for p in cmap.PAGES}
    empty = [k for k in cmap.CONCEPT_KEYS if k not in used]
    assert not empty, f"concept clusters with no page behind them: {empty}"


def test_concept_keys_are_unique_and_endpoints_appear_once():
    keys = [c["key"] for c in cmap.CONCEPTS]
    assert len(keys) == len(set(keys))
    eps = [p["endpoint"] for p in cmap.PAGES]
    dupes = sorted({e for e in eps if eps.count(e) > 1})
    assert not dupes, f"an endpoint listed twice shows up twice on the map: {dupes}"


def test_the_concept_key_is_structural_identity_and_is_not_translated():
    """Same rule as ``data-nav-group`` (§68): translating an identifier breaks
    every consumer keyed on it — here, the ``?c=`` deep link and the SVG's
    per-cluster dimming."""
    src = open(cmap.__file__).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if name in ("_", "gettext", "lazy_gettext", "ngettext"):
                pytest.fail("concept_map.py must not translate registry values — "
                            "keys are identity, and labels are translated at render")


def test_every_page_has_search_keywords_and_a_blurb():
    """The keywords ARE the search surface. A page with none is on the map but
    unfindable — which is the failure the map exists to fix."""
    thin = [p["endpoint"] for p in cmap.PAGES
            if len((p["keywords"] or "").split()) < 3 or not (p["blurb"] or "").strip()]
    assert not thin, f"pages that search cannot reach: {thin}"


def test_the_registry_never_declares_a_permission_itself():
    """Mutation target: adding a ``permission`` column to PAGES.

    A hand-copied permission is a second source of truth; it drifts from the
    decorator, and a drifted map sends people to a 403.
    """
    stray = [p["endpoint"] for p in cmap.PAGES if "permission" in p]
    assert not stray, ("PAGES must not carry a permission — it is read off the "
                       f"view function by required_permission(): {stray}")


# --------------------------------------------------------------------------
# 3 — the permission stamp, and what it is for
# --------------------------------------------------------------------------
def test_require_permission_stamps_the_gate_it_enforces():
    from app.auth.decorators import require_permission

    @require_permission("some.perm")
    def view():  # pragma: no cover — never called
        return "ok"

    assert getattr(view, "__required_permission__", None) == "some.perm"


def test_the_stamp_does_not_replace_the_gate(app, client):
    """Mutation target: a decorator that only stamps and stops checking.

    Reading the permission off the wrapper must never become the *only* place
    the permission is honoured.
    """
    with app.app_context():
        uid = make_user(app, username="nobody", role="readonly")
    login(client, uid, product="global")
    assert client.get("/users/").status_code == 403


def test_required_permission_reads_the_view_not_the_registry(app):
    with app.app_context():
        assert cmap.required_permission("users.index", app) == "user_manage"
        assert cmap.required_permission("search.index", app) is None


def test_a_user_without_the_permission_never_sees_the_page(app):
    """The map must not advertise a door this user cannot open."""
    class _User:
        is_authenticated = True

        def can(self, perm):
            return False

    with app.test_request_context():
        clusters = cmap.build(_User(), app)
        shown = {p["endpoint"] for c in clusters for p in c["pages"]}
    assert "users.index" not in shown, "a gated page leaked into a read-only map"
    assert "search.index" in shown, "an ungated page must still be listed"


def test_a_cluster_with_no_visible_page_is_dropped(app, monkeypatch):
    """An empty heading is a promise the console does not keep.

    Every real concept currently holds at least one ungated page, so a plain
    "user who can do nothing" NEVER empties a cluster and an assertion built on
    one cannot fail. The registry is narrowed to a single fully-gated concept
    so the branch is actually exercised.
    """
    class _User:
        is_authenticated = True

        def can(self, perm):
            return False

    gated = tuple(p for p in cmap.PAGES if p["concept"] == "access")
    monkeypatch.setattr(cmap, "PAGES", gated)
    with app.test_request_context():
        visible = {p["endpoint"] for c in cmap.build(_User(), app) for p in c["pages"]}
        # 'auth.profile' and 'audit.index' carry no decorator permission, so
        # 'access' still has pages even for a user who can do nothing.
        assert visible == {"auth.profile", "audit.index"}

        monkeypatch.setattr(cmap, "PAGES", tuple(
            p for p in gated if p["endpoint"] not in ("auth.profile", "audit.index")))
        clusters = cmap.build(_User(), app)
    assert clusters == [], "a concept whose every page is hidden must not render a heading"


def test_an_odd_user_object_hides_the_row_instead_of_500ing(app):
    class _Broken:
        is_authenticated = True

        def can(self, perm):
            raise RuntimeError("no profile")

    with app.test_request_context():
        clusters = cmap.build(_Broken(), app)
        shown = {p["endpoint"] for c in clusters for p in c["pages"]}
    assert "users.index" not in shown
    assert "search.index" in shown


# --------------------------------------------------------------------------
# 4 — reachability: an index nobody can open is not an index
# --------------------------------------------------------------------------
@pytest.mark.parametrize("adom", ["global", "fortiweb", "fortiadc",
                                  "fortianalyzer", "fortiauthenticator"])
def test_the_map_answers_in_every_adom(app, client, adom):
    """The ADOM gate is an allowlist. Forget one entry and the index of the
    product is invisible from that console — silently, with a redirect."""
    login(client, admin_user_id(app), product=adom)
    r = client.get("/map/")
    assert r.status_code == 200, f"the concept map is unreachable from {adom}"


def test_the_footer_links_to_the_map(app):
    src = open("app/templates/base.html").read()
    assert "url_for('concept_map.index')" in src, \
        "the footer link is the only global entry point to the map"


def test_the_footer_link_is_rendered_for_a_signed_in_user(app, client):
    login(client, admin_user_id(app), product="global")
    body = client.get("/map/").get_data(as_text=True)
    assert "fw-footer-link" in body
    assert "/map/" in body


def test_the_footer_link_is_not_offered_to_anonymous_visitors(app):
    """The map is ``login_required``; advertising it to a signed-out visitor
    sends them to a redirect loop.

    Asserted on the FOOTER BLOCK of base.html, not by fetching /auth/login:
    the login page is standalone and does not extend base.html, so a body check
    there passes whatever the footer says — an assertion that cannot fail.
    """
    src = open("app/templates/base.html").read()
    start = src.index('<footer id="fw-footer"')
    footer = src[start:src.index("</footer>", start)]
    link_at = footer.index("url_for('concept_map.index')")
    guard = footer[:link_at]
    assert "current_user.is_authenticated" in guard, (
        "the concept-map link must sit inside an is_authenticated guard in the "
        "footer block")


# --------------------------------------------------------------------------
# 5 — the page itself
# --------------------------------------------------------------------------
def test_the_map_page_is_light_theme(app, client):
    """This product has no dark mode (§9m). A translucent slate card renders as
    an opaque grey slab on white, and pale pastel text as ~1.4:1."""
    login(client, admin_user_id(app), product="global")
    body = client.get("/map/").get_data(as_text=True).lower()
    for literal in ("#080d1a", "rgba(30,41,59", "#0e1626", "backdrop-filter",
                    "#6ee7b7", "#fcd34d", "#fca5a5", "#93c5fd", "#cbd5e1"):
        assert literal not in body, f"dark-theme literal on a white page: {literal}"


def test_the_json_feed_and_the_rendered_list_describe_the_same_pages(app, client):
    """One search box drives both views. If the two disagree, toggling the view
    silently changes the result set."""
    login(client, admin_user_id(app), product="global")
    feed = client.get("/map/data").get_json()
    from_feed = {p["href"] for c in feed["clusters"] for p in c["pages"]}
    body = client.get("/map/").get_data(as_text=True)
    from_html = set(re.findall(r'<a class="cm-node" href="([^"]+)"', body))
    assert from_feed == from_html


def test_the_map_needs_a_session(app, client):
    r = client.get("/map/")
    assert r.status_code in (302, 401)


def test_the_renderer_treats_a_failed_fetch_as_an_error_not_an_empty_canvas():
    """On a white board an empty canvas and a failed query look identical and
    mean opposite things (the lesson from the metrics boards)."""
    js = open("app/static/js/concept_map.js").read()
    body = js[js.index(".catch(function (err)"):]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)   # comments explain the rule; they are not the rule
    assert "exclamation-octagon" in body or "Could not draw" in body


# --------------------------------------------------------------------------
# 4 — display text: two rows the operator cannot tell apart
# --------------------------------------------------------------------------
def test_no_two_pages_share_a_label():
    """A map whose rows have the same name fails at the one question it answers.

    ``/waf/artifacts`` (fleet-wide) and ``/artifacts/`` (the one device+ADOM
    the session stands on) were BOTH called "WAF Artifacts", in two different
    clusters. Searching the map for "artifacts" returned two identical names
    and the operator had to open both to learn which was which.

    :func:`test_concept_keys_are_unique_and_endpoints_appear_once` cannot see
    this: the endpoints differ, so that guard is green. Only the display text
    collides, and display text is the entire search surface.
    """
    from collections import Counter

    counts = Counter(p["label"] for p in cmap.PAGES)
    dupes = {label: n for label, n in counts.items() if n > 1}
    assert not dupes, (
        "Two pages on the map carry the same label, so a search result cannot "
        f"tell them apart. Name what makes them different (usually SCOPE): {dupes}")


def test_no_two_pages_resolve_to_the_same_url(app):
    """The mirror defect: two rows, one page.

    Distinct endpoints can still build the same path (an alias, a legacy name
    kept alive). That inflates the coverage count the page prints out loud and
    offers the operator a choice that is not one.
    """
    from collections import defaultdict

    with app.test_request_context("/map/"):
        from flask import url_for

        by_href = defaultdict(list)
        for page in cmap.PAGES:
            by_href[url_for(page["endpoint"])].append(page["endpoint"])
    dupes = {href: eps for href, eps in by_href.items() if len(eps) > 1}
    assert not dupes, f"several map rows point at one URL: {dupes}"


def test_a_page_and_its_fleet_wide_twin_each_declare_their_scope():
    """Scope is what separates these two pages, so each blurb must state it.

    Renaming alone would fix the collision and leave the harder question --
    "which one is the whole estate?" -- answered nowhere on the map. Asserted
    on the blurbs because the blurb is what a searcher reads under the name.
    """
    blurbs = {p["endpoint"]: p["blurb"] for p in cmap.PAGES}
    assert "FLEET-WIDE" in blurbs["waf.artifacts"], (
        "the estate-wide artifacts page no longer says it is estate-wide")
    assert "(device, ADOM)" in blurbs["artifacts.index"], (
        "the device-scoped artifacts page no longer says what it is scoped to")


# --------------------------------------------------------------------------
# 6 — the index is the page: default view, anchors, per-row explanation
# --------------------------------------------------------------------------
def _js():
    """The script with its comments stripped.

    Eight guards in this repo have passed against a broken product because the
    comment EXPLAINING the rule contained the words the assertion looked for.
    The comments are not the rule.
    """
    js = open("app/static/js/concept_map.js").read()
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


def _fn(js, name):
    """The body of one 4-space-indented function declaration inside init()."""
    start = js.index("function " + name + "(")
    end = js.index("\n    }", start)
    return js[start:end]


def _css(body):
    """Only the <style> block of the page, never the markup it styles."""
    return "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", body, flags=re.S))


def _cls_in_markup(body, token):
    """The class TOKEN appears in a rendered class attribute.

    A bare substring match passes against a mutant that renames the class to
    ``cm-jump-chip-gone``; ``\b`` does not save you either, because a hyphen is
    already a word boundary.
    """
    return re.search(r'class="[^"]*\b' + re.escape(token) + r'(?![\w-])', body) is not None


def _selector(css, token):
    """The stylesheet actually CONSULTS that class name."""
    return re.search(r"\." + re.escape(token) + r"(?![\w-])", css) is not None


def test_the_index_is_the_default_view_and_the_diagram_is_opt_in(app, client):
    """The scrollable index must be what the page SERVES, not what a click reveals.

    The list view existed for a month and nobody had seen it: it was rendered
    with ``hidden`` and only the "List" button took it off. Everyone who opened
    /map got the SVG diagram, which needs panning and zooming to read a name.
    Asserted on the served markup, so the index survives with JavaScript off.
    """
    login(client, admin_user_id(app), product="global")
    body = client.get("/map/").get_data(as_text=True)

    list_tag = re.search(r"<div id=\"cm-list\"[^>]*>", body).group(0)
    assert "hidden" not in list_tag, (
        "the index is served hidden again — a page nobody sees is not a default")

    map_tag = re.search(r"<div[^>]*id=\"cm-map-card\"[^>]*>", body).group(0)
    assert "hidden" in map_tag, "the diagram is the default view again"

    btn = re.search(r"<button[^>]*id=\"cm-view-list\"[^>]*>", body).group(0)
    assert "active" in btn, "the toggle disagrees with what is on screen"


def test_the_stored_preference_is_the_open_choice_not_the_closed_one():
    """Storing "is the diagram closed?" would send a fresh profile, a wiped
    profile and a private window back to the diagram. Only an explicit stored
    "map" may opt out of the index."""
    js = _js()
    assert "satom.map.view" in js, "the chosen view is not persisted at all"
    assert 'var pref = "list"' in js, "the default is no longer the index"
    assert re.search(r'getItem\(STORE\) === "map"', js), (
        "the stored value is no longer read as an explicit opt-IN to the diagram")
    assert "setItem(STORE" in _fn(js, "show"), "the choice is read but never written"


def test_every_concept_offers_a_jump_chip_that_lands_on_its_section(app, client):
    """An index whose entry points nowhere is worse than no index.

    Checks both halves: the chip exists for every cluster, and the anchor it
    names exists on the section. A chip with a dead href still LOOKS complete.
    """
    login(client, admin_user_id(app), product="global")
    body = client.get("/map/").get_data(as_text=True)
    with app.test_request_context("/map/"):
        clusters = cmap.build(None, app)

    assert clusters, "no clusters to index"
    for c in clusters:
        assert f'href="#cm-c-{c["key"]}"' in body, f"no index entry for {c['key']}"
        assert f'id="cm-c-{c["key"]}"' in body, f"index entry for {c['key']} lands nowhere"

    assert _cls_in_markup(body, "cm-jump-chip")
    assert _selector(_css(body), "cm-jump-chip"), (
        "the chips are emitted but the stylesheet no longer consults that name")


def test_the_index_chip_says_what_is_in_the_section(app, client):
    """The whole point of the index: what would I find in there, without
    scrolling to it first. The chip carries the cluster's own blurb."""
    login(client, admin_user_id(app), product="global")
    body = client.get("/map/").get_data(as_text=True)
    with app.test_request_context("/map/"):
        clusters = cmap.build(None, app)

    nav = re.search(r"<nav class=\"cm-jump\".*?</nav>", body, flags=re.S).group(0)
    for c in clusters:
        assert c["blurb"][:40] in nav, f"the {c['key']} chip explains nothing"


def test_every_listed_page_carries_its_own_mini_explanation(app, client):
    """Each row states what is behind it. A bare list of 107 names is a menu
    with extra steps; the blurb is the reason the map beats the sidebar."""
    login(client, admin_user_id(app), product="global")
    body = client.get("/map/").get_data(as_text=True)

    rows = re.findall(r'<a class="cm-node".*?</a>', body, flags=re.S)
    assert rows, "no page rows rendered"
    blurbs = re.findall(r'<span class="cm-node-blurb">(.*?)</span>', body, flags=re.S)
    assert len(blurbs) == len(rows), (
        f"{len(rows)} rows but {len(blurbs)} explanations — some row says nothing")
    assert all(b.strip() for b in blurbs), "an empty explanation is not an explanation"

    for c in re.findall(r'<p class="text-muted cm-cluster-blurb">(.*?)</p>', body, flags=re.S):
        assert c.strip(), "a section heading promises a topic and explains nothing"


def test_a_filtered_out_row_is_really_removed_not_just_outlined(app, client):
    """``node.hidden = true`` does NOT hide ``.cm-node``.

    The UA rule ``[hidden]{display:none}`` loses to the author declaration
    ``.cm-node{display:flex}`` — author beats user-agent, and there is no other
    ``[hidden]`` rule in this product's stylesheets. So searching the list
    outlined the matches and left every non-match on screen. Invisible while
    the list was hidden behind a toggle; the first thing you meet now.
    """
    login(client, admin_user_id(app), product="global")
    css = _css(client.get("/map/").get_data(as_text=True))

    assert re.search(r"\.cm-node\s*\{[^}]*display\s*:\s*flex", css), (
        "the premise changed: re-check whether the [hidden] override is still needed")
    assert re.search(r"\.cm-node\[hidden\]\s*\{[^}]*display\s*:\s*none", css), (
        "filtered-out rows stay on screen: nothing overrides .cm-node's display")
    assert re.search(r"\.cm-jump-chip\[hidden\]\s*\{[^}]*display\s*:\s*none", css), (
        "chips for filtered-out sections stay clickable and lead nowhere")


def test_the_anchor_target_clears_the_topbar_and_the_sticky_index(app, client):
    """Both bars are position-fixed/sticky, so an un-offset anchor drops the
    section heading UNDERNEATH them — the jump looks like it missed."""
    login(client, admin_user_id(app), product="global")
    css = _css(client.get("/map/").get_data(as_text=True))
    assert re.search(r"\.cm-cluster\s*\{[^}]*scroll-margin-top", css), (
        "anchors land under the sticky index")
    assert re.search(r"\.cm-jump\s*\{[^}]*position\s*:\s*sticky", css), (
        "the index scrolls away, so a long page needs a trip back to the top")


def test_the_diagram_is_drawn_only_when_it_is_opened():
    """107 rows laid out on every visit to fill a card nobody opened."""
    js = _js()
    assert "fetch(" in _fn(js, "ensureMap"), "the diagram fetch left ensureMap"
    assert re.search(r'if \(which === "map"\) ensureMap\(\)', _fn(js, "show")), (
        "the build is no longer gated on the diagram actually being opened — an "
        "unconditional call in show() fetches it on every visit again")
    outside = js.replace(_fn(js, "ensureMap"), "")
    assert "fetch(" not in outside, "the diagram is still fetched eagerly"


def test_the_status_line_keeps_the_server_translation(app, client):
    """The server renders a translated summary; filter() used to overwrite it
    on load with English built in JS, so es/de/fr/it lost it on first paint."""
    js = _js()
    body = _fn(js, "filter")
    assert "statusBase" in body, "the server's translated summary is not restored"
    assert "pages · " not in body, "an untranslated summary is built in JS again"
