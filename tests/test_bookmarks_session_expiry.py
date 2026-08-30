"""Guards for the two ways the bookmarks rail used to die in silence.

Both defects rendered *perfectly* — no exception, no error page, no failing
test — and both were permanent for the rest of the session because the rail is
``data-turbo-permanent``: the element the browser is looking at is the one
minted with the FIRST page load, on every page, until a full reload.

1.  **A 200 that is not the panel.** The CSRF error handler answers a POST
    that does not declare itself an XHR with a *302 to the referring page*.
    ``fetch`` follows redirects, so the rail received a whole console page with
    ``r.ok`` true and pasted 60 KB of ``<!DOCTYPE html>`` into a 300px column.
    Every control in the rail died with it. The trigger is not exotic: the
    rail's CSRF token is minted once and ``WTF_CSRF_TIME_LIMIT`` is an hour, so
    the *first* click on any bookmark control an hour into a session did it —
    expanding a folder is enough, because that persists the open set.

2.  **A class on a body Turbo throws away.** ``bm-open`` lives on ``<body>``,
    which Turbo replaces on every visit, while the rail itself survives. The
    one line that restored the state from ``localStorage`` sat *below* the
    ``dataset.bmWired`` early-return — which the surviving element makes true
    forever. So the rail shut itself on every navigation, and a navigation is
    what clicking a bookmark IS.

Two conventions this file keeps, both learned the hard way in this repo:

*   **Comments are stripped before any assertion over the template.** The code
    being guarded explains itself using the very identifiers asserted on, so an
    assertion can otherwise be answered by the comment that describes it.
*   **The marker string is compared ACROSS the two files that use it**, never
    asserted twice. Two authors of one literal is how a contract drifts while
    both halves keep passing.
"""
from __future__ import annotations

import os
import re

import pytest

from tests.conftest import admin_user_id, login


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------

def _base_html(app) -> str:
    path = os.path.join(app.root_path, "templates", "base.html")
    return open(path, encoding="utf-8").read()


def _view_src(app) -> str:
    path = os.path.join(app.root_path, "views", "bookmarks.py")
    return open(path, encoding="utf-8").read()


def _rail_js(app) -> str:
    """The rail's inline script, with comments removed.

    Without the strip, ``assert "X-Requested-With" in js`` is satisfied by the
    comment that explains why the header is there — the seventeenth time an
    assertion in this repo was answered by its own documentation.
    """
    src = _base_html(app)
    start = src.index("var rail = document.getElementById('fw-bookmarks');")
    end = src.index("</script>", start)
    body = src[start:end]
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in body.splitlines())


def _fn(js: str, name: str) -> str:
    """One function of the rail script, bounded by the NEXT declaration.

    Bounding by a character count is how a guard ends up reading its
    neighbour's body and passing on the strength of code it does not defend.
    """
    start = js.index("function %s(" % name)
    nxt = js.find("\n  function ", start + 1)
    return js[start:(nxt if nxt > 0 else len(js))]


# --------------------------------------------------------------------------
# The server marks the fragment
# --------------------------------------------------------------------------

def test_the_panel_declares_itself_a_panel(app, client):
    """CLAIM: the panel fragment is identifiable WITHOUT reading its markup.

    The client cannot tell a panel from a followed redirect by status code —
    both are 200 with ``text/html``. A header can.
    """
    login(client, admin_user_id(app))
    r = client.get("/bookmarks/panel")
    assert r.status_code == 200
    assert r.headers.get("X-SATOM-Panel") == "bookmarks"


def test_a_whole_page_does_not_carry_the_panel_marker(app, client):
    """CLAIM: the marker separates the panel from every other 200 this app
    serves. A marker every response carried would separate nothing."""
    login(client, admin_user_id(app))
    page = client.get("/", follow_redirects=True)
    assert page.status_code == 200
    assert page.headers.get("X-SATOM-Panel") is None


def test_the_marker_has_one_author(app):
    """CLAIM: the value the server sets and the value the rail checks are the
    SAME string, read from the two files that use it.

    Asserting the literal twice would let the two drift apart while both
    assertions kept passing — the failure mode this repo has shipped before.
    """
    view = re.search(r"headers\['X-SATOM-Panel'\]\s*=\s*'([^']+)'", _view_src(app))
    assert view, "the view no longer sets X-SATOM-Panel"
    js = re.search(r"headers\.get\('X-SATOM-Panel'\)\s*===\s*'([^']+)'",
                   _rail_js(app))
    assert js, "the rail no longer checks X-SATOM-Panel"
    assert view.group(1) == js.group(1)


@pytest.mark.parametrize("url,data", [
    ("/bookmarks/prefs", {"open": "[]"}),
    ("/bookmarks/create", {"kind": "folder", "label": "guard-folder"}),
])
def test_every_mutation_answers_with_a_marked_panel(app, client, url, data):
    """CLAIM: the marker is on the MUTATION answers too, not only on the GET.

    The mutations are the ones whose answer gets pasted into the panel."""
    login(client, admin_user_id(app))
    r = client.post(url, data=data)
    assert r.status_code == 200, r.status_code
    assert r.headers.get("X-SATOM-Panel") == "bookmarks"


# --------------------------------------------------------------------------
# The server hands back a fresh token
# --------------------------------------------------------------------------

def test_the_panel_hands_the_rail_a_fresh_csrf_token(app, client):
    """CLAIM: every panel answer carries a usable CSRF token.

    The rail is ``data-turbo-permanent``: the token in its markup is minted
    once per FULL page load and never again, while the token's life is an hour.
    Without this header the rail is guaranteed to go stale on a long session,
    and the operator's only clue is that nothing happens.
    """
    login(client, admin_user_id(app))
    r = client.get("/bookmarks/panel")
    token = r.headers.get("X-CSRF-Token")
    assert token and len(token) > 20, token


def test_the_fresh_token_actually_validates(app, client):
    """CLAIM: the handed-back token is the real thing, not a decorative string.

    A header carrying a token that CSRF then rejects would be worse than no
    header: it would look like the fix while reintroducing the failure.
    """
    login(client, admin_user_id(app))
    token = client.get("/bookmarks/panel").headers["X-CSRF-Token"]
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        r = client.post("/bookmarks/prefs",
                        data={"open": "[]", "csrf_token": token})
        assert r.status_code == 200, r.status_code
        assert r.headers.get("X-SATOM-Panel") == "bookmarks"
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


def test_mutations_hand_back_a_token_too(app, client):
    """CLAIM: the refresh survives a chain of mutations.

    A token refreshed only by the GET would go stale in exactly the session
    that never reloads the panel by hand — which is every session.
    """
    login(client, admin_user_id(app))
    r = client.post("/bookmarks/prefs", data={"open": "[]"})
    assert r.headers.get("X-CSRF-Token")


# --------------------------------------------------------------------------
# A stale token is REFUSED, never redirected
# --------------------------------------------------------------------------

def test_a_stale_token_from_an_xhr_is_refused_as_json(app, client):
    """CLAIM: declaring the request an XHR turns the 302 into a 400.

    This is the whole reason the rail sends ``X-Requested-With``. The handler
    branch already existed; the rail simply never asked for it.
    """
    login(client, admin_user_id(app))
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        r = client.post("/bookmarks/prefs",
                        data={"open": "[]", "csrf_token": "stale-token"},
                        headers={"X-Requested-With": "XMLHttpRequest"})
        assert r.status_code == 400, r.status_code
        assert r.is_json
        assert r.get_json()["ok"] is False
        assert r.headers.get("X-SATOM-Panel") is None
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


def test_a_stale_token_without_the_xhr_header_still_redirects(app, client):
    """CLAIM (documents the TRAP, does not bless it): a plain POST with a dead
    token is answered with a REDIRECT.

    Followed, that redirect is a 200 full page. This is the response the rail
    used to render into itself, and it is why the client-side guard is a header
    check rather than a status check — the status is 200 and it is fine.
    """
    login(client, admin_user_id(app))
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        r = client.post("/bookmarks/prefs",
                        data={"open": "[]", "csrf_token": "stale-token"})
        assert r.status_code in (301, 302, 303, 307, 308), r.status_code
        followed = client.post("/bookmarks/prefs",
                               data={"open": "[]", "csrf_token": "stale-token"},
                               follow_redirects=True)
        assert followed.status_code == 200
        assert followed.headers.get("X-SATOM-Panel") is None, (
            "a followed redirect must not look like a panel")
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


# --------------------------------------------------------------------------
# The rail asks for the refusal, and refuses to paint anything else
# --------------------------------------------------------------------------

def test_the_rail_declares_its_fetches_to_be_xhr(app):
    """CLAIM: BOTH the mutation path and the load path send the header.

    ``load()`` needs it for the same reason: an expired login answers that GET
    with the login page, and a login form pasted into a 300px column reads as
    a broken widget rather than as a lapsed session.
    """
    js = _rail_js(app)
    for name in ("post", "load"):
        assert "'X-Requested-With': 'XMLHttpRequest'" in _fn(js, name), name


def test_the_rail_paints_only_a_marked_panel(app):
    """CLAIM: neither path renders a response that has not identified itself."""
    js = _rail_js(app)
    for name in ("post", "load"):
        assert "isPanel(r)" in _fn(js, name), name


def test_the_rail_adopts_the_token_it_is_handed(app):
    """CLAIM: the refreshed token reaches BOTH the closure and the markup.

    The closure is what the next POST reads; the attribute is what a future
    reader (and any code that re-reads the dataset) sees. Refreshing only one
    leaves the two disagreeing about the same token.
    """
    js = _rail_js(app)
    adopt = _fn(js, "adoptToken")
    assert "X-CSRF-Token" in adopt
    assert "CSRF = t" in adopt
    assert "rail.dataset.bmCsrf = t" in adopt
    for name in ("post", "load"):
        assert "adoptToken" in _fn(js, name), name


def test_a_non_json_400_still_speaks(app):
    """CLAIM: the 400 branch cannot die inside ``r.json()``.

    A 400 whose body is HTML used to reject the parse promise with nobody
    listening — the click did nothing, said nothing, and logged nothing.
    """
    js = _rail_js(app)
    post = _fn(js, "post")
    assert re.search(
        r"r\.json\(\)\.then\(.*?function\s*\(\s*\)\s*\{\s*return null", post, re.S), (
            "r.json() has no rejection handler — a non-JSON 400 fails in silence")


# --------------------------------------------------------------------------
# The open state survives the body Turbo throws away
# --------------------------------------------------------------------------

def test_the_open_state_is_reapplied_after_every_turbo_render(app):
    """CLAIM: the rail's open/closed state is restored on every visit.

    Turbo replaces ``<body>`` on each navigation, so the class goes with it.
    The rail element survives — and that survival is precisely why the
    one-shot restore never runs again.
    """
    js = _rail_js(app)
    assert "document.addEventListener('turbo:render', applyOpen)" in js
    assert "document.addEventListener('turbo:load', applyOpen)" in js


def test_the_restore_listens_on_the_document_not_the_body(app):
    """CLAIM: the listener outlives the swap it exists to survive.

    Registered on ``document.body`` it would be discarded with the body — the
    guard would read as satisfied and the bug would be untouched.
    """
    js = _rail_js(app)
    assert "document.body.addEventListener('turbo:" not in js


def test_reading_the_preference_does_not_write_it(app):
    """CLAIM: ``applyOpen`` is a READ.

    The old restore ran the value back through ``setOpen``, which persists.
    Re-applying on every navigation through a writer would have the rail
    rewriting the operator's preference on every page they open.
    """
    apply_fn = _fn(_rail_js(app), "applyOpen")
    assert "setItem" not in apply_fn
    assert "localStorage.setItem" not in _fn(_rail_js(app), "isOpen")


def test_the_open_class_is_not_applied_where_there_is_no_rail(app):
    """CLAIM: a page without the rail does not get a 300px hole.

    ``body.bm-open .fw-main`` reserves the column. Applied on a page the rail
    is not on, it is margin for nothing.
    """
    apply_fn = _fn(_rail_js(app), "applyOpen")
    assert "getElementById('fw-bookmarks')" in apply_fn
    assert re.search(r"toggle\('bm-open',\s*!!\w+\s*&&", apply_fn), apply_fn


def test_the_rail_still_starts_closed(app, client):
    """CLAIM: none of the above changed the DEFAULT.

    Open-by-default on a hundred-device fleet is a wall of text over the page
    the operator navigated to.
    """
    login(client, admin_user_id(app))
    body = client.get("/", follow_redirects=True).get_data(as_text=True)
    assert "bm-open" not in body.split("<script")[0]
    js = _rail_js(app)
    assert "applyOpen();" in js
