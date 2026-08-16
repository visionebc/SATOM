"""Guards for the URL a saved LINK bookmark is allowed to carry.

A link bookmark is free text one person types and everybody renders. Share it
with the team and it becomes an ``href`` in every colleague's sidebar, on every
page of the console, for as long as it exists — including for the read-only
users who cannot delete it.

``javascript:`` in that ``href`` runs in this origin on one click, with the
session cookie. That is stored XSS whose only entry requirement is the
permission to save a bookmark, and nothing about the rendered panel looks
wrong: the row is a row, the name is the name, and the trap is one click away.

Two checks, not one, and they defend different things:

*   :func:`create` refuses on the way IN, so the row is never stored and the
    author is told why while they are still looking at the form.
*   the panel refuses on the way OUT, because ``create`` is not the only writer
    that can reach this table — a bundle restore and a Postgres replica both
    land rows without passing through it. Checking only at write time trusts
    every row this process did not write.

None of these assert on a substring the panel would contain anyway: the panel
is full of the word ``https``, and ``"javascript" not in body`` passes against
a panel that dropped the row entirely, which is a different bug.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import User
from app.models_bookmarks import Bookmark, KIND_LINK, SCOPE_PERSONAL
from app.services import bookmarks as bk

from tests.conftest import admin_user_id, login


# --- claim: the scheme is checked, and it is checked on the parsed value ----

@pytest.mark.parametrize("url", [
    "https://runbook.example/fw",
    "http://runbook.example/fw",
    "https://192.0.2.13:8443/ui/",
    "/appliances/1",                      # a page of this console
    "/monitoring/services/?q=fw",
])
def test_an_http_or_internal_url_is_accepted(url):
    assert bk.safe_link_url(url) == (url, "")


@pytest.mark.parametrize("url", [
    "javascript:alert(document.cookie)",  # the whole reason this exists
    "JaVaScRiPt:alert(1)",                # scheme comparison is case folded
    "  javascript:alert(1)  ",            # stripped before it is read
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "about:blank",
    "blob:https://example.test/abc",
])
def test_a_dangerous_scheme_is_refused(url):
    got, why = bk.safe_link_url(url)
    assert got is None, "%r survived as %r" % (url, got)
    assert why


@pytest.mark.parametrize("url", [
    # `//` opens a JavaScript line comment and `%0a` closes it: this is an
    # EXECUTABLE javascript: URL that also parses with a host, which is exactly
    # why it is the payload people reach for.
    "javascript://evil.example/%0aalert(document.cookie)",
    "data://evil.example/x",
    "ftp://files.example/x",
    "ws://evil.example/x",
])
def test_a_dangerous_scheme_WITH_A_HOST_is_refused_by_the_allowlist(url):
    """CLAIM: the allowlist is what refuses these, and it is load-bearing.

    Every value in the test above happens to have **no host**, so all of them
    are also refused by the no-host check further down — which means that test
    passes unchanged with `javascript` put back into ``LINK_SCHEMES``. It was
    proving a rule nobody was writing about. These four parse with a netloc, so
    the allowlist is the only thing standing between them and an ``href``.
    """
    got, why = bk.safe_link_url(url)
    assert got is None, "%r survived as %r" % (url, got)
    assert why


def test_the_parser_normalises_the_scheme_and_the_allowlist_RELIES_on_that():
    """CLAIM, stated because it is a dependency and not an opinion:
    ``urlsplit`` lower-cases the scheme and removes TAB, CR and LF before
    parsing it. That is what makes ``JaVaScRiPt:`` and ``java\tscript:``
    comparable against a lower-case allowlist at all.

    Pinned by a test rather than by a mutation because no input can distinguish
    a redundant ``.lower()`` from a necessary one — but a stdlib that stopped
    normalising would silently reopen both bypasses, and this fails loudly the
    day that happens.
    """
    from urllib.parse import urlsplit
    assert urlsplit("JaVaScRiPt:alert(1)").scheme == "javascript"
    assert urlsplit("java\tscript:alert(1)").scheme == "javascript"
    assert urlsplit("  https://ok.example/  ").scheme == "https"


@pytest.mark.parametrize("url", [
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "java\rscript:alert(1)",
    "javascript\x00:alert(1)",
])
def test_a_scheme_smuggled_past_a_control_character_is_refused(url):
    """CLAIM: the check reads the same string the browser will.

    Browsers delete NUL, TAB, CR and LF from a URL *before* reading the scheme,
    so every value here navigates as ``javascript:``. ``urlsplit`` happens to
    remove the same characters, so these are caught by the allowlist as well —
    which is belt and braces, not a reason to drop either. The rule that only
    the control-character check defends is the test below.
    """
    got, why = bk.safe_link_url(url)
    assert got is None, "%r survived as %r" % (url, got)
    assert why


@pytest.mark.parametrize("url", [
    "https://ok.example/a\nb",
    "https://ok.example/a\rb",
    "https://ok.example/a\tb",
    "https://ok.example/a\x00b",
])
def test_a_control_character_inside_an_OTHERWISE_VALID_url_is_refused(url):
    """CLAIM: this is the case only the control-character rule catches.

    Scheme and host are both fine here, so the allowlist and the no-host check
    both wave it through; delete the control-character rule and the raw value
    is returned and written into an ``href`` attribute. A newline in an
    attribute is how a value stops being one value, and nothing about the
    stored string looks wrong in the form that accepted it.
    """
    got, why = bk.safe_link_url(url)
    assert got is None, "%r survived as %r" % (url, got)
    assert why


def test_a_protocol_relative_url_is_refused_even_though_it_starts_with_a_slash():
    """CLAIM: ``//evil.example`` is not an internal path. It LOOKS like one —
    it is the single character difference between "a page of this console" and
    "somebody else's server", and the panel renders both identically."""
    got, why = bk.safe_link_url("//evil.example/steal")
    assert got is None and why


def test_a_scheme_less_relative_url_is_refused():
    """CLAIM: not a security refusal, a correctness one. ``docs/runbook``
    resolves against whatever page the panel is drawn on, and the panel is
    drawn on every page — so the same bookmark points somewhere different
    depending on where the operator happened to be standing."""
    got, why = bk.safe_link_url("docs/runbook")
    assert got is None and why


def test_the_accepted_value_comes_back_STRIPPED():
    """CLAIM: what is returned is what gets stored and rendered, so the padding
    has to be gone by then. ``urlsplit`` ignores surrounding whitespace when it
    parses, so a version that never strips still ACCEPTS this — it just hands
    back a URL with spaces in it, and the row then renders an href nobody
    asserted on."""
    assert bk.safe_link_url("  https://ok.example/fw  ") == (
        "https://ok.example/fw", "")


def test_an_http_url_with_no_host_is_refused():
    got, why = bk.safe_link_url("https:///nothing")
    assert got is None and why


def test_an_empty_url_is_refused():
    got, why = bk.safe_link_url("   ")
    assert got is None and why


def test_url_and_reason_are_never_both_set_and_never_both_empty():
    for url in ("https://ok.example/", "javascript:alert(1)", "", "//x.example",
                "/internal", "docs/x", "java\tscript:alert(1)"):
        got, why = bk.safe_link_url(url)
        assert bool(got) != bool(why), (url, got, why)


def test_every_refusal_reason_is_a_sentence_not_a_code():
    """CLAIM: the reason reaches the person who typed the URL. ``bad_url``
    sends them to somebody who can read the source; a sentence sends them back
    to the field, which is where the fix is."""
    for url in ("javascript:alert(1)", "//evil.example", "docs/x", ""):
        _, why = bk.safe_link_url(url)
        assert " " in why and len(why) > 12, (url, why)


def test_the_refusals_are_told_APART_not_merged_into_one_message():
    """CLAIM: "you left it blank", "that scheme is not allowed" and "that is
    another server" are three different mistakes with three different fixes.
    One shared message for all of them is a message that helps with none."""
    reasons = {bk.safe_link_url(u)[1] for u in
               ("", "javascript:alert(1)", "//evil.example", "docs/x",
                "https://ok.example/a\nb", "https:///nohost")}
    assert len(reasons) == 6, reasons


# --- claim: create() refuses on the way in ---------------------------------

def _user(session, username="alice"):
    u = User(username=username, role="operator", is_active=True)
    u.set_password("pw")
    session.add(u)
    session.commit()
    return u


def test_create_refuses_a_javascript_link_and_stores_nothing(session):
    u = _user(session)
    with pytest.raises(bk.BookmarkDenied) as exc:
        bk.create(u, KIND_LINK, url="javascript:alert(document.cookie)")
    assert exc.value.reason == "bad_url"
    assert Bookmark.query.count() == 0


def test_create_still_reports_an_EMPTY_url_as_missing_not_as_bad(session):
    """CLAIM: the pre-existing ``missing_url`` answer survives. Folding "you
    left it blank" into the new scheme refusal would change what the form says
    to somebody who simply has not typed yet."""
    u = _user(session)
    with pytest.raises(bk.BookmarkDenied) as exc:
        bk.create(u, KIND_LINK, url="   ")
    assert exc.value.reason == "missing_url"


def test_create_still_accepts_an_ordinary_https_link(session):
    u = _user(session)
    bm = bk.create(u, KIND_LINK, url="  https://runbook.example/fw  ")
    assert bm.url == "https://runbook.example/fw"


def test_the_create_ROUTE_refuses_it_too_and_names_the_rule(app, client):
    """CLAIM: the guard is in the service, so the HTTP surface inherits it. A
    check written in the view would be one the CLI and every other caller
    walks straight past."""
    login(client, admin_user_id(app))
    r = client.post("/bookmarks/create",
                    data={"kind": "link", "label": "pwn",
                          "url": "javascript:alert(1)"})
    assert r.status_code == 400
    assert r.get_json()["reason"] == "bad_url"
    with app.app_context():
        assert Bookmark.query.count() == 0


# --- claim: the panel refuses on the way out too ---------------------------

def _panel(client):
    r = client.get("/bookmarks/panel")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def _link_bookmark_then_corrupt(app, client, url):
    """A row that reached the table WITHOUT passing through ``create`` — which
    is what a bundle restore and a replica both do."""
    login(client, admin_user_id(app))
    r = client.post("/bookmarks/create",
                    data={"kind": "link", "label": "runbook",
                          "url": "https://runbook.example/fw"})
    assert r.status_code == 200
    with app.app_context():
        bm = Bookmark.query.filter_by(kind=KIND_LINK).one()
        bm.url = url
        db.session.commit()
        return bm.id


def test_a_stored_javascript_url_never_becomes_an_href(app, client):
    _link_bookmark_then_corrupt(app, client, "javascript:alert(document.cookie)")
    body = _panel(client)
    assert 'href="javascript:' not in body
    assert "alert(document.cookie)" not in body


def test_the_refused_row_is_still_SHOWN_with_its_reason(app, client):
    """CLAIM: the row keeps its place and states why. A row that silently loses
    its href reads as a UI bug, and nobody goes and fixes the URL — which is
    the only thing that ends the problem."""
    _link_bookmark_then_corrupt(app, client, "javascript:alert(1)")
    body = _panel(client)
    assert "runbook" in body, "the row vanished instead of being defused"
    assert "bm-link-off" in body


def test_a_good_stored_url_is_STILL_rendered_as_a_link(app, client):
    """CLAIM: the way-out check refuses the bad ones and only those. A guard
    that also dropped the legitimate links would pass every test above."""
    login(client, admin_user_id(app))
    r = client.post("/bookmarks/create",
                    data={"kind": "link", "label": "runbook",
                          "url": "https://runbook.example/fw"})
    assert r.status_code == 200
    body = _panel(client)
    assert 'href="https://runbook.example/fw"' in body
    assert "bm-link-off" not in body


def test_the_rendered_href_is_the_CHECKED_value_not_the_raw_column(app, client):
    """CLAIM: the template reads ``it.link_url``, never ``it.bm.url``.

    Today the two agree whenever the link renders at all, so reaching past the
    check costs nothing *yet* — which is precisely why it needs pinning now.
    The day somebody loosens the surrounding condition, a template already
    wired to the raw column puts the unchecked value straight into the href,
    and no test in this file would notice. A stored value with padding makes
    the two observably different without changing what the link means.
    """
    _link_bookmark_then_corrupt(app, client, "  https://runbook.example/fw  ")
    body = _panel(client)
    assert 'href="https://runbook.example/fw"' in body
    assert 'href="  https://runbook.example/fw' not in body


def test_a_shared_row_cannot_carry_it_into_a_colleagues_sidebar(app, client):
    """CLAIM: this is the case that matters. A personal ``javascript:`` row is
    a trap its own author set; a TEAM one is a trap in the sidebar of every
    colleague who never touched it, including the read-only users who cannot
    delete it."""
    bid = _link_bookmark_then_corrupt(app, client, "javascript:alert(1)")
    with app.app_context():
        bm = Bookmark.query.get(bid)
        bm.scope = "team"
        db.session.commit()
    from tests.conftest import make_user
    login(client, make_user(app, username="ro", role="readonly"))
    body = _panel(client)
    assert 'href="javascript:' not in body
    assert "runbook" in body


def test_a_personal_scope_row_is_the_only_thing_create_makes(session):
    """Belt and braces on the surrounding contract: nothing is created straight
    into the team scope, so a refused-then-fixed link cannot appear in anybody
    else's panel without the separate, audited share."""
    u = _user(session)
    bm = bk.create(u, KIND_LINK, url="https://ok.example/")
    assert bm.scope == SCOPE_PERSONAL
