"""Page CHROME has to be reachable from every ADOM, and say so honestly.

Reported 2026-08-30, in the reader's own words: *"Your session expired —
reload the page to use bookmarks."* — the message the rail paints where the
tree would be. The session was fine.

``base.html`` renders the bookmarks rail into **every** page of **every**
ADOM, but ``bookmarks`` was missing from all three per-ADOM allowlists in the
product gate, so in the ADC / FortiAnalyzer / FortiAuthenticator consoles the
rail's own ``GET /bookmarks/panel`` was answered with a **302 to the ADOM
home**. ``fetch`` follows redirects, the answer carried no
``X-SATOM-Panel`` header, and the rail reported the only failure it knew how
to name. Two distinct defects, and each one is guarded below:

1.  **The gate refused the chrome.** Fixed as ONE authority
    (:data:`app.CHROME_BPS`) rather than a fourth copy of the same list: this
    is the fifth entry to be forgotten by the per-ADOM sets (``docs``,
    ``change_requests``, ``scheduled_actions``, then ``advisor`` and
    ``adom_assets`` earlier the same day). ``tests/test_adom_menu_reachability``
    walks every rendered *sidebar link*; the rail is not a link, it is a
    ``data-`` attribute the script fetches — which is why that sweep could not
    see this. The sweep here reads those attributes off the rendered element.

2.  **The rail called a routing bounce an expiry.** A wrong diagnosis is worse
    than none: it sends the reader to re-authenticate over a bug that
    re-authenticating cannot touch. Only an answer that actually came from the
    login page may be called an expiry now.
"""
from __future__ import annotations

import re

import pytest

from conftest import admin_user_id, login

HOME = {
    "global": "/",
    "fortiweb": "/web/",
    "fortiadc": "/adc/",
    "fortianalyzer": "/faz/",
    "fortiauthenticator": "/fac/",
}

#: Any URL the rail element hands to the script. Read off the RENDERED tag, so
#: the next chrome fetch added to it is covered without naming it here.
_RAIL_URL = re.compile(r'="(/[^"]*)"')


def _adom_keys():
    from app.services.product_scope import GLOBAL, concrete_products
    return sorted(concrete_products() | {GLOBAL})


def _mk(kind, name):
    """A device whose host never resolves — nothing here performs a live read,
    and a real host would make a failure look like a hang."""
    from app.models import Appliance
    a = Appliance(name=name, kind=kind, host=name + ".invalid",
                  username="u", password_enc="")
    a.password = "pw"
    return a


def _method_for(app, url):
    """The method this URL actually accepts. A GET at a POST-only route never
    resolves an endpoint, so the gate sees no blueprint and bounces it — the
    rail posts, so probing with GET would fail a URL that works."""
    from werkzeug.exceptions import MethodNotAllowed
    adapter = app.url_map.bind("localhost")
    try:
        adapter.match(url, method="GET")
        return "GET"
    except MethodNotAllowed as exc:
        return "POST" if "POST" in (exc.valid_methods or []) else "GET"


def _chrome_urls(client, adom):
    """The URLs the bookmarks rail is wired to, in this ADOM's console."""
    r = client.get(HOME[adom] + "?_adom=" + adom, follow_redirects=True)
    assert r.status_code == 200, f"{adom} home returned {r.status_code}"
    html = r.get_data(as_text=True)
    i = html.find('id="fw-bookmarks"')
    assert i > 0, f"the bookmarks rail is not rendered in the {adom} console"
    j = html.find(">", i)
    assert j > i
    return sorted({u for u in _RAIL_URL.findall(html[i:j]) if u.startswith("/")})


# ── 1. the gate must not refuse the chrome ──────────────────────────────────
@pytest.mark.parametrize("adom", _adom_keys())
def test_the_bookmarks_panel_is_reachable_in_every_adom(app, client, adom):
    """The reported defect, named: every console draws this rail, so every
    console has to be able to fill it."""
    login(client, admin_user_id(app), product=adom)
    r = client.get("/bookmarks/panel?_adom=" + adom)
    assert r.status_code == 200, (
        f"{adom}: the rail's own panel answered {r.status_code} "
        f"{r.headers.get('Location', '')}")
    assert r.headers.get("X-SATOM-Panel") == "bookmarks", (
        f"{adom}: a 200 that is not the panel — the rail cannot paint it")


@pytest.mark.parametrize("adom", _adom_keys())
def test_no_chrome_fetch_url_bounces_back_to_its_own_adom_home(app, client, adom):
    """The generic sweep. The gate's refusal signature is a redirect to the
    ADOM's OWN home; a 405 here is a PASS (the URL was reached, the method was
    wrong), which is the point — reachability is what the gate decides."""
    login(client, admin_user_id(app), product=adom)
    urls = _chrome_urls(client, adom)
    home = HOME[adom].rstrip("/")
    bounced = []
    for u in urls:
        m = _method_for(app, u)
        r = client.open(u, method=m, headers={"X-ADOM": adom},
                        data={"_adom": adom} if m == "POST" else None)
        if r.status_code in (301, 302) and \
                r.headers.get("Location", "").rstrip("/") == home:
            bounced.append(u)
    assert not bounced, (
        f"{adom}: the page chrome fetches {len(bounced)} URL(s) the product "
        f"gate then refuses, redirecting to {home}/: {bounced}")


@pytest.mark.parametrize("adom", _adom_keys())
def test_the_sweep_actually_finds_the_chrome_urls(app, client, adom):
    """A sweep that finds nothing passes for the wrong reason — and would go
    on passing after somebody renames the attributes it reads."""
    login(client, admin_user_id(app), product=adom)
    urls = _chrome_urls(client, adom)
    assert len(urls) >= 4, f"{adom}: only {len(urls)} chrome URL(s) found: {urls}"
    assert "/bookmarks/panel" in urls


@pytest.mark.parametrize("adom", ["fortiadc", "fortianalyzer", "fortiauthenticator"])
def test_the_rails_mutations_answer_the_panel_in_every_adom(app, client, adom):
    """Reaching the tree is half of it: persisting an expanded folder is a
    POST, and the rail renders whatever that POST answers."""
    login(client, admin_user_id(app), product=adom)
    r = client.post("/bookmarks/prefs", data={"open": "[]", "_adom": adom})
    assert r.status_code == 200, (
        f"{adom}: prefs answered {r.status_code} "
        f"{r.headers.get('Location', '')}")
    assert r.headers.get("X-SATOM-Panel") == "bookmarks"


@pytest.mark.parametrize("adom", ["fortiadc", "fortianalyzer", "fortiauthenticator"])
def test_the_device_picker_is_reachable_in_every_adom(app, client, adom):
    login(client, admin_user_id(app), product=adom)
    r = client.get("/bookmarks/devices?_adom=" + adom)
    assert r.status_code == 200, f"{adom}: picker answered {r.status_code}"
    assert "devices" in r.get_json()


# ── 2. one authority, not a fourth copy of the same list ────────────────────
def test_the_page_chrome_is_declared_once():
    from app import CHROME_BPS
    assert "bookmarks" in CHROME_BPS


def test_the_chrome_is_not_repeated_in_the_per_adom_allowlists():
    """Four hand-kept copies is HOW this recurs: the three per-ADOM sets have
    now forgotten five different blueprints between them. Chrome belongs to
    the gate's own always-allowed path, so a reviewer adding the next ADOM
    cannot forget it — there is nothing to remember."""
    import pathlib
    import app as app_pkg
    src = pathlib.Path(app_pkg.__file__).read_text()
    body = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    start, end = "adc_bps = {", "if bp_name not in fac_bps"
    assert body.count(start) == 1 and body.count(end) == 1
    region = body[body.index(start):body.index(end)]
    assert "'bookmarks'" not in region and '"bookmarks"' not in region, (
        "the chrome was allow-listed per ADOM again — that is the shape of "
        "the bug, not the fix")


# ── 3. reachable everywhere must NOT mean visible everywhere ────────────────
def test_the_panel_still_shows_only_this_adoms_devices(app, client):
    """The rail lists the live inventory. Reaching it from four consoles is
    only correct while each console keeps seeing its own devices."""
    from app.extensions import db
    with app.app_context():
        db.session.add(_mk("fortiweb", "guardweb01"))
        db.session.add(_mk("fortianalyzer", "guardfaz01"))
        db.session.commit()
    login(client, admin_user_id(app), product="fortianalyzer")
    html = client.get("/bookmarks/panel?_adom=fortianalyzer").get_data(as_text=True)
    assert "guardfaz01" in html, "the FAZ console cannot see its own device"
    assert "guardweb01" not in html, (
        "the FAZ console's rail is listing a FortiWeb device")


# ── 4. the message has to be true ───────────────────────────────────────────
def _js_slice(first: str, last: str) -> str:
    import pathlib
    import app as app_pkg
    p = pathlib.Path(app_pkg.__file__).parent / "templates" / "base.html"
    src = p.read_text()
    assert src.count(first) == 1, f"anchor {first!r} is not unique"
    i = src.index(first)
    j = src.index(last, i)
    # A guard that reads the comments is answered by its own explanation.
    return "\n".join(l for l in src[i:j].splitlines()
                     if not l.strip().startswith("//"))


def test_only_a_login_answer_may_be_called_an_expired_session():
    js = _js_slice("function whyNotPanel", "function post(")
    assert "/auth/login" in js, (
        "the rail calls every non-panel answer an expiry again — a gate "
        "redirect then tells the reader to re-authenticate over a routing bug")
    assert "EXPIRED" in js


def test_a_failure_that_is_not_an_expiry_still_names_itself():
    js = _js_slice("function whyNotPanel", "function post(")
    assert "r.status" in js, (
        "the fallback message must carry the status — 'it did not work' is "
        "what made this report take a browser session to diagnose")


def test_the_mutation_path_does_not_hardcode_the_expiry_message():
    """post() is the OTHER caller, and it is the one a reader reaches by
    clicking. Guarding load() alone left this one free to go on lying."""
    js = _js_slice("function post(url, data)", "function render(")
    assert "whyNotPanel" in js
    assert "EXPIRED" not in js, (
        "post() decides the message itself again — two authorities for one "
        "diagnosis is how they drift apart")


def test_a_bookmark_stamped_for_another_adom_never_reaches_this_panel(app, client):
    """The rail is reachable from four consoles now, which makes the ROW scope
    the thing standing between them. Guarded on a BOOKMARK, not only on the
    inventory lens: the lens is scoped by ``visible_appliances`` and would go
    on passing while every saved link leaked."""
    from app.extensions import db
    from app.models_bookmarks import Bookmark, KIND_LINK
    uid = admin_user_id(app)
    with app.app_context():
        db.session.add(Bookmark(owner_user_id=uid, kind=KIND_LINK,
                                url="/web/", label="guardweblink",
                                product="fortiweb"))
        db.session.add(Bookmark(owner_user_id=uid, kind=KIND_LINK,
                                url="/faz/", label="guardfazlink",
                                product="fortianalyzer"))
        db.session.commit()
    login(client, uid, product="fortianalyzer")
    html = client.get("/bookmarks/panel?_adom=fortianalyzer").get_data(as_text=True)
    assert "guardfazlink" in html, "the FAZ console lost its own bookmark"
    assert "guardweblink" not in html, (
        "a FortiWeb bookmark is showing in the FortiAnalyzer console")


def test_the_tree_loader_does_not_hardcode_the_expiry_message():
    js = _js_slice("function load(", "function openNodes(")
    assert "whyNotPanel" in js
    assert "EXPIRED" not in js, (
        "load() decides the message itself again — two authorities for one "
        "diagnosis is how they drift apart")
