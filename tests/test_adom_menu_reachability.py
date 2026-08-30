"""Every ADOM's menu has to REACH the pages it draws, and keep its own device.

Three defects closed here on 2026-08-30, reported together as "only the Global
and FortiWeb menus work — ADC, FortiAuth and Analyzer do not". None of them
raised; each made a console quietly answer the wrong thing.

1. **The device slot was hardcoded, three slots for four device ADOMs.**
   ``device_context`` matched ``fortiadc`` and ``fortianalyzer`` by name and
   let everything else fall through to the FortiWeb slot, so
   ``fortiauthenticator`` SHARED FortiWeb's. Both directions were live: a
   FortiWeb pick blanked the FAC console (its whole menu answered "No
   FortiAuthenticator is selected") and a FAC pick made a FortiAuthenticator
   the FortiWeb ADOM's implicit device — ``/web/workspace/`` opened fac01's
   workspace. It is the failure :mod:`app.services.product_scope` documents
   for its own key set: a new ADOM is a registry row, so the slot must be
   DERIVED from the row, not typed out beside it.

2. **The single-appliance fallback lived on two dashboards only.** ``faz.index``
   and ``fac.index`` each carried ``header_dev = current or fleet[0]``. So the
   FAC front page rendered the live unit's firmware, CPU and licence counters
   while every menu page in the same ADOM said no device was selected. Two
   authorities for one rule, and the pages disagreed. It is one authority now
   (``device_context._sole_device``).

3. **``advisor`` and ``adom_assets`` were missing from the per-ADOM
   allowlists.** Both are rendered into EVERY sidebar by a shared partial, and
   in the ADC/FAZ/FAC consoles the product gate redirected them to the ADOM
   home — a live-looking entry that goes nowhere. Exactly what
   ``scheduled_actions`` did on 2026-08-10 and ``change_requests`` the day
   before, which is why the reachability guard below walks the WHOLE rendered
   sidebar rather than naming the entry of the week.
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

#: Links whose whole job is to LEAVE this ADOM. They redirect by design.
_ADOM_JUMP = "/product/"

_HREF = re.compile(r'href="([^"]+)"')


def _adom_keys():
    """Derived from the registry — a hardcoded list is the bug being guarded."""
    from app.services.product_scope import GLOBAL, concrete_products
    return sorted(concrete_products() | {GLOBAL})


def _device_adoms():
    from app.services.product_scope import concrete_products
    return sorted(concrete_products())


def _mk(kind, name, host=None, maintenance=False):
    """A device whose host NEVER resolves, so the live read a menu page does
    fails instantly instead of hanging on a TCP connect. The password goes
    through the real setter: a literal ``password_enc`` is fine for rows that
    are only ever queried, but a page that builds a CLIENT decrypts it, and an
    InvalidToken there would look like the bug under test."""
    from app.models import Appliance
    a = Appliance(name=name, kind=kind, host=host or (name + ".invalid"),
                  username="u", password_enc="", maintenance=maintenance)
    a.password = "pw"
    return a


def _sidebar_links(client, adom):
    r = client.get(HOME[adom] + "?_adom=" + adom, follow_redirects=True)
    assert r.status_code == 200, f"{adom} home returned {r.status_code}"
    html = r.get_data(as_text=True)
    i = html.find("fw-nav-top")
    assert i > 0, f"no sidebar rendered in the {adom} console"
    j = html.find("</nav>", i)
    side = html[i:j if j > i else len(html)]
    out, seen = [], set()
    for h in _HREF.findall(side):
        if h.startswith("/") and h not in seen:
            seen.add(h)
            out.append(h)
    return out


# ── 3. every link the sidebar draws must not bounce ─────────────────────────
@pytest.mark.parametrize("adom", _adom_keys())
def test_no_sidebar_entry_bounces_back_to_its_own_adom_home(app, client, adom):
    """The gate's refusal signature is a redirect to the ADOM's OWN home.

    Asserted over the WHOLE rendered sidebar, because the two entries that
    broke this time were added to shared partials months after the allowlists
    were written — no test that names features can cover an entry that does
    not exist yet.
    """
    login(client, admin_user_id(app), product=adom)
    links = _sidebar_links(client, adom)
    assert len(links) > 10, f"{adom} sidebar produced only {len(links)} links"
    home = HOME[adom]
    bounced = []
    for href in links:
        if href.startswith(_ADOM_JUMP):
            continue           # leaving the ADOM is this link's purpose
        r = client.get(href, headers={"X-ADOM": adom})
        if r.status_code in (301, 302) and r.headers.get("Location", "").rstrip("/") == home.rstrip("/"):
            bounced.append(href)
    assert not bounced, (
        f"{adom}: the sidebar draws {len(bounced)} entr(y/ies) the product "
        f"gate then refuses, redirecting to {home}: {bounced}")


@pytest.mark.parametrize("adom", ["fortiadc", "fortianalyzer", "fortiauthenticator"])
def test_the_shared_partial_entries_are_reachable_in_every_adom(app, client, adom):
    """Named explicitly as well: these two are what the report was about, and
    a future refactor of the sweep above must not quietly stop covering them."""
    login(client, admin_user_id(app), product=adom)
    for url in ("/advisor/", "/adom-assets/"):
        r = client.get(url + "?_adom=" + adom)
        assert r.status_code == 200, (
            f"{adom} console cannot reach {url} ({r.status_code} "
            f"{r.headers.get('Location','')}) — it is in its sidebar")


# ── 1. one slot per ADOM ────────────────────────────────────────────────────
def test_every_device_adom_gets_its_own_session_slot(app):
    """Derived, and the point is the COUNT: four ADOMs, four distinct slots."""
    from app.services.device_context import _slot_for_product
    with app.app_context():
        keys = _device_adoms()
        slots = {k: _slot_for_product(k) for k in keys}
    assert len(set(slots.values())) == len(keys), (
        f"two ADOMs share a device slot: {slots}")


def test_the_legacy_slot_names_are_unchanged(app):
    """A renamed key blanks the device context of every console open at
    deploy time — the session cookie already names these three."""
    from app.services.device_context import _slot_for_product
    with app.app_context():
        assert _slot_for_product("fortiweb") == "appliance_id"
        assert _slot_for_product("fortiadc") == "appliance_id_adc"
        assert _slot_for_product("fortianalyzer") == "appliance_id_faz"
        # global has always read FortiWeb's slot
        assert _slot_for_product("global") == "appliance_id"


def test_a_kind_no_adom_claims_stays_in_the_legacy_slot(app):
    """The Global console is the only place such a device is manageable, and
    Global reads the legacy slot — giving the stray kind a slot of its own
    would make the Global map's pick unreadable one request later. Same rule
    product_scope applies to the unscoped rows."""
    from app.services.device_context import _slot_for_product
    with app.app_context():
        assert _slot_for_product("fortigate-not-an-adom") == "appliance_id"


def test_an_unresolved_adom_gets_no_slot(app):
    """Fail closed: an unknown ADOM must not land on FortiWeb's device."""
    from app.services.device_context import _slot_for_product
    from app.services.product_scope import UNRESOLVED
    with app.app_context():
        assert _slot_for_product(UNRESOLVED) != "appliance_id"


def test_a_pick_in_one_adom_never_disturbs_another(app):
    """The reported symptom, over every ORDERED PAIR of device ADOMs."""
    from app.extensions import db
    from app.services import device_context

    with app.app_context():
        kinds = _device_adoms()
        for k in kinds:
            db.session.add(_mk(k, "dev-" + k))
        db.session.commit()
        ids = {}
        from app.models import Appliance
        for k in kinds:
            ids[k] = Appliance.query.filter_by(name="dev-" + k).one().id

    cookie: dict = {}
    for k in kinds:                      # pick one device in every ADOM, in turn
        with app.test_request_context("/", headers={"X-ADOM": k}):
            from flask import session
            session.update(cookie)
            device_context.set_current(ids[k])
            cookie = dict(session)
    # …now every ADOM must still hold ITS OWN.
    for k in kinds:
        with app.test_request_context("/", headers={"X-ADOM": k}):
            from flask import session
            session.update(cookie)
            got = device_context.current_appliance()
            assert got is not None and got.id == ids[k], (
                f"{k} lost its device to another ADOM's pick "
                f"(got {got.name if got else None}, wanted dev-{k})")


# ── 2. one authority for the single-appliance context ───────────────────────
@pytest.mark.parametrize("kind,url,denial", [
    ("fortianalyzer", "/faz/m/devices", "No FortiAnalyzer selected"),
    ("fortiauthenticator", "/fac/m/dashboard", "No FortiAuthenticator is selected"),
])
def test_a_lone_appliance_is_the_context_on_menu_pages_too(app, client, kind, url, denial):
    """Not just on the dashboard. The ``.invalid`` host keeps the live read
    failing instantly — the page must show the DEVICE and its error, which is
    a different answer from "no device selected"."""
    from app.extensions import db
    with app.app_context():
        db.session.add(_mk(kind, "solo-" + kind))
        db.session.commit()
    login(client, admin_user_id(app), product=kind)
    r = client.get(url, headers={"X-ADOM": kind})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert denial not in body, f"{url} denies the ADOM's only appliance"
    assert "solo-" + kind in body, f"{url} does not name the appliance it used"


def test_two_appliances_are_a_real_choice_and_are_not_auto_picked(app):
    """The fallback is "no choice to make", not "guess". Two devices is a
    choice; auto-picking one would silently point the console at a device the
    operator never selected."""
    from app.extensions import db
    from app.services import device_context
    with app.app_context():
        db.session.add(_mk("fortianalyzer", "faz-a"))
        db.session.add(_mk("fortianalyzer", "faz-b"))
        db.session.commit()
    with app.test_request_context("/", headers={"X-ADOM": "fortianalyzer"}):
        assert device_context.current_appliance() is None


def test_the_global_console_never_auto_picks(app):
    """Global sees every product; "everything" is never "one"."""
    from app.extensions import db
    from app.services import device_context
    with app.app_context():
        db.session.add(_mk("fortianalyzer", "faz-only"))
        db.session.commit()
    with app.test_request_context("/", headers={"X-ADOM": "global"}):
        assert device_context.current_appliance() is None


def test_the_implicit_context_does_not_write_the_session(app):
    """A GET must not record a choice the operator did not make — the picker's
    Select button would become a no-op it cannot undo."""
    from app.extensions import db
    from app.services import device_context
    with app.app_context():
        db.session.add(_mk("fortiauthenticator", "solo-fac"))
        db.session.commit()
    with app.test_request_context("/", headers={"X-ADOM": "fortiauthenticator"}):
        from flask import session
        assert device_context.current_appliance() is not None
        assert not [k for k in session if k.startswith("appliance_id")], (
            f"the implicit context wrote the session: {dict(session)}")


def test_a_maintenance_only_adom_stays_empty_for_a_user_who_cannot_see_it(app):
    """"Exactly one" is counted in the same terms the picker shows, so the
    fallback cannot hand a hidden device to someone the gate excludes."""
    from app.extensions import db
    from app.services import device_context
    with app.app_context():
        db.session.add(_mk("fortianalyzer", "faz-hidden", maintenance=True))
        db.session.commit()
    with app.test_request_context("/", headers={"X-ADOM": "fortianalyzer"}):
        assert device_context.current_appliance() is None
