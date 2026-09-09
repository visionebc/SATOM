"""Guards for the Automations / System Automations split (2026-09-09).

Everything here defends ONE property: a scheduled row belongs to exactly one
surface, and the surfaces cannot reach into each other. Every failure mode below
renders as a page that looks perfectly correct —

  * a row that falls out of BOTH lists keeps firing on its schedule and is
    visible nowhere;
  * a row that appears on both is edited from two places with two permissions;
  * a by-id route that answers across the split makes the lower-permission page
    a back door to the higher-permission rows, while the LIST still looks
    correctly filtered;
  * a create form that offers the other half writes a row that vanishes from the
    page that created it.

None of those raise. That is why they are asserted.
"""
from __future__ import annotations

import json
import re

import pytest

from conftest import admin_user_id, login, make_user


# --------------------------------------------------------------------------- #
#  Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk(app, name, action, scope=None, product="fortiweb", enabled=True):
    """Persist one ScheduledAction and return its id.

    ``scope`` is written RAW so a test can construct the disagreement between
    the stored column and the catalog that ``effective_scope`` exists to settle.
    """
    from app.extensions import db
    from app.models import ScheduledAction

    with app.app_context():
        row = ScheduledAction(
            name=name, action=action, product=product, enabled=enabled,
            scope=(scope if scope is not None else "admin"),
            targets="[]", params="{}", schedule_kind="daily",
            schedule=json.dumps({"time": "03:00"}))
        db.session.add(row)
        db.session.commit()
        return row.id


def _operator(app):
    """A user holding config_write but NOT user_manage — the role the user
    surface exists for, and the one the system surface must refuse."""
    return make_user(app, username="op", role="operator")


def _admin(app):
    return admin_user_id(app)


def _split_chrome(html):
    """``(sidebar, page)`` — the two halves an assertion must not confuse.

    Four guards in this file used to survive their own mutation because the
    string they looked for was supplied by the OTHER half of the same document:
    ``">Automations<"`` is in the sidebar AND in the page's own <h1>, and
    ``"/web/scheduled-actions/"`` is in every calendar page's menu whether or
    not a single event points there. So "the menu offers this" passed with the
    menu entry deleted, and "the calendar links per row" passed with the
    endpoint hardcoded. Split first, then assert against the half that carries
    the claim.
    """
    marker = '<aside id="fw-sidebar"'
    if marker not in html:          # 403/redirect bodies have no chrome at all
        return "", html
    start = html.index(marker)
    end = html.index("</aside>", start) + len("</aside>")
    return html[start:end], html[:start] + html[end:]


def _sidebar(html):
    return _split_chrome(html)[0]


def _page(html):
    return _split_chrome(html)[1]


# --------------------------------------------------------------------------- #
#  1. Two surfaces exist, and they are distinct                                 #
# --------------------------------------------------------------------------- #
def test_both_blueprints_are_registered(app):
    names = {bp for bp in app.blueprints}
    assert "scheduled_actions" in names
    assert "automations" in names


def test_the_two_surfaces_have_distinct_urls(app):
    rules = {r.endpoint: str(r) for r in app.url_map.iter_rules()}
    assert rules["scheduled_actions.index"] != rules["automations.index"]
    assert rules["automations.index"].endswith("/automations/")


def test_every_route_exists_on_both_surfaces(app):
    """A surface missing a route is a dead button, not a missing feature."""
    eps = {r.endpoint for r in app.url_map.iter_rules()}
    for verb in ("index", "new", "edit", "toggle", "delete", "run_now", "history"):
        assert f"scheduled_actions.{verb}" in eps, verb
        assert f"automations.{verb}" in eps, verb


# --------------------------------------------------------------------------- #
#  2. effective_scope — the catalog decides, and the partition has no hole      #
# --------------------------------------------------------------------------- #
def test_user_catalog_action_is_user_scope(app):
    from app.views import scheduled_actions as v
    from app.models import ScheduledAction

    with app.app_context():
        row = ScheduledAction(name="x", action="policy_set_status", scope="admin")
        # The COLUMN says admin and the CATALOG says user. The catalog wins:
        # the column is a copy taken at write time, so re-scoping a spec must
        # move old rows rather than strand them on a page that no longer owns
        # them.
        assert v.effective_scope(row) == "user"


def test_admin_catalog_action_is_admin_scope(app):
    from app.views import scheduled_actions as v
    from app.models import ScheduledAction

    with app.app_context():
        row = ScheduledAction(name="x", action="system_backup", scope="user")
        assert v.effective_scope(row) == "admin"


def test_orphan_action_falls_back_to_the_stored_column(app):
    from app.views import scheduled_actions as v
    from app.models import ScheduledAction

    with app.app_context():
        row = ScheduledAction(name="x", action="no_such_action", scope="user")
        assert v.effective_scope(row) == "user"


@pytest.mark.parametrize("raw", ["", None, "admin", "SYSTEM", "user ", "0"])
def test_every_unrecognised_scope_lands_on_the_system_surface(app, raw):
    """The partition is EXHAUSTIVE. Anything the user filter does not claim is
    claimed by the admin — never by nobody. A row visible on no page still
    fires."""
    from app.views import scheduled_actions as v
    from app.models import ScheduledAction

    with app.app_context():
        row = ScheduledAction(name="x", action="gone_from_catalog", scope=raw)
        assert v.effective_scope(row) == "admin"


def test_effective_scope_only_ever_answers_two_values(app):
    from app.views import scheduled_actions as v
    from app.services import scheduled_actions as sa
    from app.models import ScheduledAction

    with app.app_context():
        for key in sa.ALL_ACTIONS:
            row = ScheduledAction(name="x", action=key, scope="")
            assert v.effective_scope(row) in ("user", "admin"), key


def test_endpoint_for_names_the_owning_blueprint(app):
    from app.views import scheduled_actions as v
    from app.models import ScheduledAction

    with app.app_context():
        assert v.endpoint_for(
            ScheduledAction(name="a", action="policy_set_status")) == "automations"
        assert v.endpoint_for(
            ScheduledAction(name="b", action="system_backup")) == "scheduled_actions"


# --------------------------------------------------------------------------- #
#  3. The lists partition the table                                            #
# --------------------------------------------------------------------------- #
def test_the_two_lists_partition_every_row(app, client):
    """Union == all rows, intersection == empty. Asserted over a set that
    includes the odd scopes, because a hole opens for exactly those."""
    ids = {
        "sys": _mk(app, "AAA nightly backup", "system_backup", scope="admin"),
        "usr": _mk(app, "BBB cutover", "policy_set_status", scope="user"),
        "orphan_admin": _mk(app, "CCC ghost", "gone", scope=""),
        "orphan_user": _mk(app, "DDD ghost", "gone2", scope="user"),
    }
    login(client, _admin(app))
    sys_html = client.get("/web/scheduled-actions/").get_data(as_text=True)
    usr_html = client.get("/web/automations/").get_data(as_text=True)

    on_sys = {k for k, _ in ids.items()
              if _label(k) in sys_html}
    on_usr = {k for k, _ in ids.items()
              if _label(k) in usr_html}
    assert on_sys | on_usr == set(ids), "a row is on NEITHER page"
    assert not (on_sys & on_usr), "a row is on BOTH pages"
    assert on_usr == {"usr", "orphan_user"}


def _label(key):
    return {"sys": "AAA nightly backup", "usr": "BBB cutover",
            "orphan_admin": "CCC ghost", "orphan_user": "DDD ghost"}[key]


def test_system_list_hides_user_rows(app, client):
    _mk(app, "ZZZ cutover", "policy_set_status", scope="user")
    login(client, _admin(app))
    html = client.get("/web/scheduled-actions/").get_data(as_text=True)
    assert "ZZZ cutover" not in html


def test_user_list_hides_system_rows(app, client):
    _mk(app, "ZZZ nightly backup", "system_backup", scope="admin")
    login(client, _admin(app))
    html = client.get("/web/automations/").get_data(as_text=True)
    assert "ZZZ nightly backup" not in html


def test_an_orphan_row_is_labelled_as_one(app, client):
    """It still fires. An unlabelled orphan reads as a normal action."""
    _mk(app, "QQQ ghost action", "retired_in_a_past_version", scope="admin")
    login(client, _admin(app))
    html = client.get("/web/scheduled-actions/").get_data(as_text=True)
    assert "QQQ ghost action" in html
    assert "unknown action" in html


# --------------------------------------------------------------------------- #
#  4. Permissions — the split is what makes the user surface reachable          #
# --------------------------------------------------------------------------- #
def test_operator_can_open_automations(app, client):
    login(client, _operator(app))
    assert client.get("/web/automations/").status_code == 200


def test_operator_cannot_open_system_automations(app, client):
    login(client, _operator(app))
    assert client.get("/web/scheduled-actions/").status_code == 403


def test_admin_can_open_both(app, client):
    login(client, _admin(app))
    assert client.get("/web/automations/").status_code == 200
    assert client.get("/web/scheduled-actions/").status_code == 200


# --------------------------------------------------------------------------- #
#  5. The by-id guard — without it the split is decoration                      #
# --------------------------------------------------------------------------- #
def test_operator_cannot_delete_a_system_row_through_the_user_surface(app, client):
    """THE security case. /automations/ answers on config_write, which the
    operator role holds; the nightly system backup must not be one URL away."""
    from app.models import ScheduledAction

    rid = _mk(app, "nightly system backup", "system_backup", scope="admin")
    login(client, _operator(app))
    resp = client.post(f"/web/automations/{rid}/delete")
    assert resp.status_code == 404
    with app.app_context():
        assert ScheduledAction.query.get(rid) is not None


def test_operator_cannot_run_a_system_row_through_the_user_surface(app, client):
    rid = _mk(app, "nightly system backup", "system_backup", scope="admin")
    login(client, _operator(app))
    assert client.post(f"/web/automations/{rid}/run-now").status_code == 404


def test_operator_cannot_toggle_a_system_row_through_the_user_surface(app, client):
    from app.models import ScheduledAction

    rid = _mk(app, "nightly system backup", "system_backup", scope="admin")
    login(client, _operator(app))
    assert client.post(f"/web/automations/{rid}/toggle").status_code == 404
    with app.app_context():
        assert ScheduledAction.query.get(rid).enabled is True


def test_the_system_surface_refuses_a_user_row_by_id(app, client):
    """Symmetric on purpose: 'admins may reach everything' would put user rows
    on a page that does not list them, editable from a form whose catalog does
    not contain their action."""
    rid = _mk(app, "cutover", "policy_set_status", scope="user")
    login(client, _admin(app))
    assert client.get(f"/web/scheduled-actions/{rid}/edit").status_code == 404


def test_each_surface_reaches_its_own_rows_by_id(app, client):
    sys_id = _mk(app, "nightly", "system_backup", scope="admin")
    usr_id = _mk(app, "cutover", "policy_set_status", scope="user")
    login(client, _admin(app))
    assert client.get(f"/web/scheduled-actions/{sys_id}/edit").status_code == 200
    assert client.get(f"/web/automations/{usr_id}/edit").status_code == 200
    assert client.get(f"/web/automations/{usr_id}/history").status_code == 200


def test_the_guard_is_404_not_403(app, client):
    """Do not confirm the row exists to somebody who may not open it."""
    rid = _mk(app, "nightly", "system_backup", scope="admin")
    login(client, _operator(app))
    assert client.get(f"/web/automations/{rid}/edit").status_code == 404


# --------------------------------------------------------------------------- #
#  6. Creating across the split                                                 #
# --------------------------------------------------------------------------- #
def _form(action, name="new one"):
    return {"name": name, "action": action, "schedule_kind": "daily",
            "daily_time": "04:00", "enabled": "on"}


def test_a_system_action_cannot_be_created_on_the_user_surface(app, client):
    from app.models import ScheduledAction

    login(client, _admin(app))
    client.post("/web/automations/new", data=_form("system_backup"),
                follow_redirects=True)
    with app.app_context():
        assert ScheduledAction.query.filter_by(name="new one").first() is None


def test_the_refusal_names_the_page_that_owns_the_action(app, client):
    """A refusal without a destination is a dead end — and the operator cannot
    go looking, because the other page 403s for them."""
    login(client, _admin(app))
    html = _page(client.post("/web/automations/new", data=_form("system_backup"),
                             follow_redirects=True).get_data(as_text=True))
    # The sidebar carries the words "System Automations" on every page, so the
    # menu must be out of the document before this can mean anything.
    assert "System Automations" in html


def test_a_user_action_cannot_be_created_on_the_system_surface(app, client):
    from app.models import ScheduledAction

    login(client, _admin(app))
    client.post("/web/scheduled-actions/new", data=_form("policy_set_status"),
                follow_redirects=True)
    with app.app_context():
        assert ScheduledAction.query.filter_by(name="new one").first() is None


def test_each_surface_creates_its_own_actions(app, client):
    from app.models import ScheduledAction

    login(client, _admin(app))
    client.post("/web/scheduled-actions/new", data=_form("system_backup", "sysone"),
                follow_redirects=True)
    client.post("/web/automations/new", data=_form("policy_set_status", "usrone"),
                follow_redirects=True)
    with app.app_context():
        a = ScheduledAction.query.filter_by(name="sysone").first()
        b = ScheduledAction.query.filter_by(name="usrone").first()
        assert a is not None and a.scope == "admin"
        assert b is not None and b.scope == "user"


# --------------------------------------------------------------------------- #
#  7. The form offers one half only                                            #
# --------------------------------------------------------------------------- #
def test_user_form_offers_only_user_actions(app, client):
    login(client, _admin(app))
    html = client.get("/web/automations/new").get_data(as_text=True)
    assert 'value="policy_set_status"' in html
    assert 'value="system_backup"' not in html


def test_system_form_offers_only_admin_actions(app, client):
    login(client, _admin(app))
    html = client.get("/web/scheduled-actions/new").get_data(as_text=True)
    assert 'value="system_backup"' in html
    assert 'value="policy_set_status"' not in html


def test_the_other_half_is_not_rendered_disabled_either(app, client):
    """Absent, not greyed: a disabled option that lives elsewhere teaches
    nothing and invites a POST the server has to refuse."""
    login(client, _admin(app))
    html = client.get("/web/automations/new").get_data(as_text=True)
    for key in ("device_sync", "deep_capture", "metrics_scrape", "custom_rest"):
        assert f'value="{key}"' not in html, key


# --------------------------------------------------------------------------- #
#  8. Navigation                                                               #
# --------------------------------------------------------------------------- #
def test_fortiweb_sidebar_shows_both_entries_to_an_admin(app, client):
    login(client, _admin(app), product="fortiweb")
    nav = _sidebar(client.get("/web/automations/").get_data(as_text=True))
    assert ">Automations<" in nav
    assert ">System Automations<" in nav


def test_the_two_entries_point_at_different_pages(app, client):
    login(client, _admin(app), product="fortiweb")
    nav = _sidebar(client.get("/web/automations/").get_data(as_text=True))
    # The menu carries the ADOM on the link (``?_adom=fortiweb``), so match the
    # index href WITH its optional query rather than the bare path: the plain
    # substring either misses it or also matches a by-id route.
    index_hrefs = set(re.findall(r'href="(/web/[a-z-]+/)(?:\?[^"]*)?"', nav))
    assert "/web/automations/" in index_hrefs
    assert "/web/scheduled-actions/" in index_hrefs


def test_operator_sidebar_shows_only_the_entry_they_can_open(app, client):
    """A sidebar link that leads to a 403 is a bug report waiting to be filed."""
    login(client, _operator(app), product="fortiweb")
    nav = _sidebar(client.get("/web/automations/").get_data(as_text=True))
    assert ">Automations<" in nav
    assert ">System Automations<" not in nav


def test_the_automations_entry_is_not_offered_where_its_catalog_is_empty(app, client):
    """Every user action is products=('fortiweb',). In the FortiADC ADOM the
    page could only render an empty picker, which reads as 'this fleet has
    nothing to schedule' rather than 'this stage does not apply here'."""
    login(client, _admin(app), product="fortiadc")
    nav = _sidebar(client.get("/adc/").get_data(as_text=True))
    assert nav, "no sidebar in this response — the guard would be vacuous"
    assert ">Automations<" not in nav
    assert ">System Automations<" in nav      # the other half IS offered here


def test_the_open_group_follows_the_user_surface(app, client):
    """Landing on a page whose menu group is COLLAPSED is a navigation that
    lies about where you are."""
    login(client, _admin(app), product="fortiweb")
    html = client.get("/web/automations/").get_data(as_text=True)
    i = html.index('data-nav-group="Automation"')
    assert "open" in html[max(0, i - 120):i]


# --------------------------------------------------------------------------- #
#  9. The calendar links each row to the surface that owns it                   #
# --------------------------------------------------------------------------- #
#: NOTE the parameter is ``kind``, singular (``request.args.getlist("kind")``).
#: The first draft of these tests sent ``kinds=`` — silently ignored, so every
#: kind was drawn and the tests passed for a reason they did not state.
CAL = "/calendar/?kind=automation"


def test_calendar_points_a_user_row_at_the_user_surface(app, client):
    _mk(app, "CAL cutover", "policy_set_status", scope="user")
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "/web/automations/" in page


def test_calendar_points_a_system_row_at_the_system_surface(app, client):
    _mk(app, "CAL nightly", "system_backup", scope="admin")
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "/web/scheduled-actions/" in page


def test_the_calendar_grid_never_sends_a_user_row_to_the_system_page(app, client):
    """The whole point, stated as the negative: with ONLY a user-scope row on
    the grid, no event may point at the page that 404s for it."""
    _mk(app, "CAL only cutover", "policy_set_status", scope="user")
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "/web/automations/" in page
    assert "/web/scheduled-actions/" not in page


def test_calendar_run_history_links_follow_the_owning_surface(app, client):
    """Run events carry their own url. It was a second hardcoded endpoint, and
    it is the link an operator clicks to ask 'did my cutover fire?'."""
    from app.extensions import db
    from app.models import ScheduledActionRun

    rid = _mk(app, "CAL ran", "policy_set_status", scope="user")
    with app.app_context():
        db.session.add(ScheduledActionRun(action_id=rid, status="ok",
                                          trigger="schedule"))
        db.session.commit()
    login(client, _admin(app))
    page = _page(client.get("/calendar/?kind=run").get_data(as_text=True))
    assert "/web/automations/%d/history" % rid in page
    assert "/web/scheduled-actions/%d/history" % rid not in page


def test_a_run_whose_action_is_gone_falls_back_to_the_system_surface(app):
    """``None`` must answer with the HIGHER-permission page: the by-id route
    404s either way, and sending an operator to a page they cannot open turns a
    stale link into a permission error."""
    from app.views.calendar import _owner_endpoint

    assert _owner_endpoint(None) == "scheduled_actions"


def test_calendar_does_not_hardcode_one_endpoint(app):
    """The lambda must ask per row. A single hardcoded endpoint makes every
    user-scope automation on the grid look deleted to the operator who
    scheduled it (404 there, 403 on the page it points to)."""
    import inspect

    from app.views import calendar as cal_view

    src = inspect.getsource(cal_view)
    # Strip comments first: the note EXPLAINING this rule names the endpoint.
    body = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    assert 'url_for("scheduled_actions.index")' not in body
    assert "_owner_endpoint" in body


# --------------------------------------------------------------------------- #
#  10. The surface resolver                                                     #
# --------------------------------------------------------------------------- #
def test_an_unknown_blueprint_resolves_to_the_system_surface(app):
    """A wiring bug must not default to the page with the LOWER permission."""
    from app.views import scheduled_actions as v

    with app.test_request_context("/"):
        assert v._surface()["scope"] == "admin"


def test_every_surface_names_a_real_other_page(app):
    from app.views import scheduled_actions as v

    for name, surface in v.SURFACES.items():
        other, label = surface["other"]
        assert other in v.SURFACES and other != name
        assert label == v.SURFACES[other]["title"]


def test_the_two_surfaces_cover_both_scopes_exactly_once(app):
    from app.views import scheduled_actions as v

    scopes = sorted(s["scope"] for s in v.SURFACES.values())
    assert scopes == ["admin", "user"]


# --------------------------------------------------------------------------- #
#  11. The new page is discoverable                                            #
# --------------------------------------------------------------------------- #
def test_both_surfaces_are_in_the_concept_map(app):
    """A page missing from the map is unfindable by search while looking
    perfectly present in the menu — the split's user half is the one an
    operator would go looking for."""
    from app.services.concept_map import PAGES

    endpoints = {p["endpoint"] for p in PAGES}
    assert "automations.index" in endpoints
    assert "scheduled_actions.index" in endpoints


def test_the_two_map_entries_do_not_describe_the_same_thing(app):
    """Two entries with one description is a map that cannot route a search."""
    from app.services.concept_map import PAGES

    by_ep = {p["endpoint"]: p for p in PAGES}
    a, b = by_ep["automations.index"], by_ep["scheduled_actions.index"]
    assert a["label"] != b["label"]
    assert a["blurb"] != b["blurb"]
