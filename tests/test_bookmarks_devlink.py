"""Guards for the DIRECT LINK TO THE DEVICE.

A panel row now carries two destinations: the NAME opens what SATOM knows
about the device, the ARROW opens the device itself. Three properties hold
that up, and each of them fails silently — the panel renders perfectly in
every one of the broken states below.

*   **A refused link is a STATED refusal, never a missing button.** The
    retired appliances in this fleet are parked on ``.invalid`` hosts, which
    RFC 6761 guarantees never resolve. A link built from one of those looks
    live and dies in the browser, and the operator then debugs the appliance
    instead of the record.

*   **The host is validated before it is allowed to be an authority.**
    ``Appliance.host`` is free text an administrator types, and the link is
    rendered for everyone, read-only users included. ``fw1@evil.example`` is a
    legal-looking value that navigates somewhere else entirely, because
    everything before the ``@`` is userinfo. Interpolating the field straight
    into ``https://`` turns the inventory form into an open redirect that
    every colleague sees in their sidebar.

*   **A tab opened at an appliance under audit can neither steer this tab nor
    be handed the console URL.** ``rel`` must carry BOTH ``noopener`` and
    ``noreferrer``; either alone leaves half of it open.

None of these assert on a substring the template would contain anyway — the
panel is full of the word ``https``, and ``"link" in body`` passes against a
panel with no device link at all.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Appliance
from app.models_bookmarks import Bookmark
from app.services import bookmarks as bk

from tests.conftest import admin_user_id, login, make_user


# --- helpers ---------------------------------------------------------------

class _Row:
    """The two fields ``device_link`` is allowed to read, and nothing else. A
    real ``Appliance`` would let a mutation pass by reading some other column
    and still producing a plausible URL."""

    def __init__(self, host, port=443):
        self.host = host
        self.port = port


def _appl(app, name, host="192.0.2.13", **kw):
    with app.app_context():
        a = Appliance(name=name, kind=kw.pop("kind", "fortiweb"), host=host,
                      port=kw.pop("port", 443), username="admin",
                      password_enc="x", verify_ssl=False, **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _panel(client):
    r = client.get("/bookmarks/panel")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def _row_of(body, bm_id):
    """The markup of the ONE row belonging to bookmark *bm_id*.

    Scoped on purpose. A bookmarked device is rendered TWICE -- once as its
    bookmark under Folders, once as itself in the inventory lens -- and the two
    item dicts are built by two different pieces of code. An unscoped
    ``'href="https://..." in body`` therefore passes from the lens copy while
    the bookmark row has quietly lost its link, which is exactly the state the
    mutation harness produced and no test noticed.
    """
    i = body.index('data-bm-id="%d"' % bm_id)
    start = body.rindex('<div class="bm-row', 0, i)
    nxt = body.find('<div class="bm-row', i)
    return body[start:nxt if nxt != -1 else len(body)]


# --- claim: the URL is derived, and it is derived correctly ----------------

def test_an_ip_host_on_443_gets_a_bare_https_url():
    assert bk.device_link(_Row("192.0.2.13")) == ("https://192.0.2.13", "")


def test_a_non_default_port_is_carried_into_the_url():
    assert bk.device_link(_Row("192.0.2.13", 8443)) == (
        "https://192.0.2.13:8443", "")


def test_the_scheme_is_https_even_when_the_client_does_not_verify_the_cert():
    """CLAIM: ``verify_ssl`` records whether WE trust the certificate. A
    self-signed appliance is still an HTTPS appliance, and deriving the scheme
    from that flag would send the operator to ``http://`` on a box that only
    speaks TLS."""
    row = _Row("192.0.2.13")
    row.verify_ssl = False
    url, _ = bk.device_link(row)
    assert url.startswith("https://")


def test_an_ipv6_host_is_bracketed():
    """CLAIM: unbracketed, the colons of the address are read as the port
    separator and the link points at a host that does not exist."""
    assert bk.device_link(_Row("2001:db8::1", 8443)) == (
        "https://[2001:db8::1]:8443", "")


def test_a_hostname_survives_unchanged():
    assert bk.device_link(_Row("fw-a1.example.net")) == (
        "https://fw-a1.example.net", "")


def test_a_trailing_root_dot_is_accepted_and_dropped():
    url, _ = bk.device_link(_Row("fw-a1.example.net."))
    assert url == "https://fw-a1.example.net"


# --- claim: a refusal is explicit, and it names its reason -----------------

def test_a_reserved_invalid_host_gets_no_link():
    """CLAIM: RFC 6761 names under ``.invalid`` never resolve. In THIS fleet
    that is four of ten devices, so it is the common case."""
    url, why = bk.device_link(_Row("retired-fw6.invalid"))
    assert url is None
    assert "invalid" in why


def test_the_invalid_refusal_survives_case_and_subdomains():
    url, why = bk.device_link(_Row("mgmt.RETIRED.INVALID"))
    assert url is None and why


def test_an_empty_host_gets_no_link():
    url, why = bk.device_link(_Row(""))
    assert url is None and why


def test_a_MISSING_host_is_reported_as_missing_not_as_malformed():
    """CLAIM: the two refusals stay apart.

    "nobody has filled this field in" and "somebody typed it wrong" send the
    operator to two different actions, and only one of them is a correction.
    Delete the empty-host guard and an empty host still gets refused -- it
    falls through to the hostname branch and is reported as a malformed
    address, which sends its reader looking for a typo in a field that is
    blank. Every other test in this file passes in that state, because they
    all assert only that SOME reason came back.
    """
    _, missing = bk.device_link(_Row(""))
    _, malformed = bk.device_link(_Row("fw1@evil.example"))
    assert missing != malformed, (missing, malformed)
    assert "not a hostname" not in missing, missing


def test_a_missing_appliance_gets_no_link():
    url, why = bk.device_link(None)
    assert url is None and why


@pytest.mark.parametrize("host", [
    "fw1@evil.example",       # userinfo — navigates to evil.example
    "192.0.2.13/../admin",     # a path smuggled into the authority
    "192.0.2.13:8443",         # a port smuggled into the host field
    "evil.example?x=1",
    "evil.example#frag",
    "fw1 .example",           # whitespace
    "-leading.example",       # a label may not start with a hyphen
    "trailing-.example",
    "javascript:alert(1)",
    "//evil.example",
    "fw1..example",           # empty label
])
def test_a_host_that_is_not_a_host_gets_no_link(host):
    """CLAIM: the field is parsed, not pasted. Every value here produces a URL
    that renders as "the device" and resolves to something else."""
    url, why = bk.device_link(_Row(host))
    assert url is None, "%r became %r" % (host, url)
    assert why


def test_a_port_out_of_range_gets_no_link():
    url, why = bk.device_link(_Row("192.0.2.13", 70000))
    assert url is None and why


def test_every_refusal_reason_is_a_sentence_not_a_code():
    """CLAIM: the reason reaches the operator in a tooltip. ``bad_host`` sends
    them to somebody who can read the source; a sentence sends them to the
    inventory record, which is where the fix is."""
    for host in ("", "retired-fw6.invalid", "fw1@evil.example"):
        _, why = bk.device_link(_Row(host))
        assert " " in why and len(why) > 12, (host, why)


def test_url_and_reason_are_never_both_set_and_never_both_empty():
    for host in ("192.0.2.13", "", "retired-fw6.invalid", "x@y.example"):
        url, why = bk.device_link(_Row(host))
        assert bool(url) != bool(why), (host, url, why)


# --- claim: the panel renders both destinations ----------------------------

def test_the_panel_renders_a_direct_link_for_a_reachable_device(app, client):
    aid = _appl(app, "fw-live", host="192.0.2.13")
    login(client, admin_user_id(app))
    assert 'href="https://192.0.2.13"' in _panel(client)
    assert aid  # the row exists; the link is not coming from somewhere else


def test_the_direct_link_opens_a_new_tab_with_BOTH_rel_tokens(app, client):
    """CLAIM: ``noopener`` stops the appliance steering this tab through
    ``window.opener``; ``noreferrer`` stops it being handed the console URL,
    which carries device ids, in the ``Referer`` header. Neither alone."""
    _appl(app, "fw-live", host="192.0.2.13")
    login(client, admin_user_id(app))
    body = _panel(client)
    i = body.index('href="https://192.0.2.13"')
    tag = body[i:body.index(">", i)]
    assert 'target="_blank"' in tag, tag
    assert "noopener" in tag and "noreferrer" in tag, tag


def test_the_device_name_still_points_INSIDE_satom(app, client):
    """CLAIM: BOTH destinations are present. A change that pointed the row
    itself at the appliance GUI would satisfy every other test in this file
    and would quietly take the console out of the operator's path."""
    aid = _appl(app, "fw-live", host="192.0.2.13")
    login(client, admin_user_id(app))
    assert 'href="/appliances/%d"' % aid in _panel(client)


def test_an_unreachable_device_renders_the_reason_and_no_href(app, client):
    """CLAIM: no href, and the slot is still there carrying why. A silently
    absent control reads as "this device has no GUI"."""
    _appl(app, "fw-retired", host="retired-fw6.invalid")
    login(client, admin_user_id(app))
    body = _panel(client)
    assert "https://retired-fw6.invalid" not in body
    assert "bm-dev-off" in body
    # The row is present — the device is not missing from the panel, only its
    # outbound link is. Without this the test would also pass on a panel that
    # dropped retired devices entirely.
    assert "retired-fw6.invalid" in body


def test_a_device_nobody_bookmarked_still_gets_its_link(app, client):
    """CLAIM: the link describes the DEVICE, so it does not wait for a
    bookmark. Rendering it only after somebody stars the row would hide it on
    exactly the devices nobody is watching."""
    _appl(app, "fw-live", host="192.0.2.13")
    login(client, admin_user_id(app))
    with app.app_context():
        assert Bookmark.query.count() == 0
    assert 'href="https://192.0.2.13"' in _panel(client)


def test_a_BOOKMARKED_device_row_carries_the_link_ON_THAT_ROW(app, client):
    """CLAIM: the mirror of the test above, and it needs its own assertion.

    That one proves a device with NO bookmark still gets its arrow, and it is
    satisfied by the inventory lens alone. This one proves the bookmark row --
    a different item dict, built in a different function -- carries it too. The
    check is scoped to the row itself, because the same device is also drawn by
    the lens two roots away and would answer for it.
    """
    aid = _appl(app, "fw-live", host="192.0.2.13")
    uid = admin_user_id(app)
    login(client, uid)
    r = client.post("/bookmarks/adopt", data={"appliance_id": aid})
    assert r.status_code == 200
    with app.app_context():
        bid = Bookmark.query.one().id
    row = _row_of(_panel(client), bid)
    assert 'href="https://192.0.2.13"' in row, row
    # ...and the row still points INSIDE the console with its name, so this
    # cannot be satisfied by a row that became a link to the appliance GUI.
    assert 'href="/appliances/%d"' % aid in row, row


def test_a_readonly_user_gets_the_link_too(app, client):
    """CLAIM: opening the device is not an edit. A gate here would be a
    permission invented by the sidebar that the rest of the console does not
    have."""
    _appl(app, "fw-live", host="192.0.2.13")
    login(client, make_user(app, username="ro", role="readonly"))
    assert 'href="https://192.0.2.13"' in _panel(client)


def test_the_appliance_detail_page_uses_THE_SAME_url(app, client):
    """CLAIM: one function, two surfaces. A second expression is how two pages
    start disagreeing about where a device lives after a re-IP."""
    aid = _appl(app, "fw-live", host="192.0.2.13", port=8443)
    login(client, admin_user_id(app))
    r = client.get("/appliances/%d" % aid)
    assert r.status_code == 200
    url, _ = bk.device_link(_Row("192.0.2.13", 8443))
    assert 'href="%s"' % url in r.get_data(as_text=True)


def test_the_link_follows_a_re_ip_with_no_write_to_the_bookmark(app, client):
    """CLAIM: derived, never stored. This is the whole reason there is no
    ``mgmt_url`` column: the stored copy is the one that survives the move."""
    aid = _appl(app, "fw-live", host="192.0.2.13")
    login(client, admin_user_id(app))
    assert 'href="https://192.0.2.13"' in _panel(client)
    with app.app_context():
        a = Appliance.query.get(aid)
        a.host = "192.0.2.90"
        db.session.commit()
    body = _panel(client)
    assert 'href="https://192.0.2.90"' in body
    assert 'href="https://192.0.2.13"' not in body
