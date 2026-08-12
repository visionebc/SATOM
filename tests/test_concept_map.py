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
