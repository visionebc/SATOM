"""A change window is a property of the DEVICE, not of one product.

Until 2026-08-09 the Change Request form disagreed with its own product on two
counts, and neither failed anything — they just quietly narrowed what could be
put under change control:

1. **Targets.** ``views/change_requests.new`` hard-filtered the device picker to
   ``kind='fortiweb'``. FortiADC, FortiAnalyzer and FortiAuthenticator are
   first-class appliances in this product — each with its own client, its own
   pages and its own firmware — and not one of them could be named in a change.

2. **Actions.** ``CR_ACTIONS`` was a hand-written list of TWO entries while the
   automation catalog already registered ``policy_set_status``,
   ``backend_set_status``, ``backend_set_config``, ``swap_certificate``,
   ``cert_lifecycle`` and ``custom_rest`` — every one of them a device-mutating
   change that belongs inside a window. A hand-kept list is precisely how
   ``upgrade_prep`` came to be offered by the form while the executor's gate
   honoured only ``upgrade``: destructive, on the menu, ungated.

A third hole sat between them: targets are resolved by ``spec.products``, so a
CR naming a FortiADC for a FortiWeb-only action would save happily, then resolve
to ZERO targets at fire time and report ``skipped`` — which the lifecycle grades
as **failed**, hours after anyone could act on it. Cross-validation at the form
is the only place that can still say no.

And the new ``reboot`` action carries the rule that made it safe to write: a
reboot URN is not guessable. On FortiWeb the neighbouring maintenance op reboots
the box EVEN ON GET, so a wrong guess is an outage, not a 404. Only a URN read
off that product's own device ships; every other product is refused BY NAME.
"""
from __future__ import annotations

import ast
import os

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA_PATH = os.path.join(REPO, "app", "services", "scheduled_actions.py")
VIEW_PATH = os.path.join(REPO, "app", "views", "change_requests.py")


def _func(path, name):
    """One function's AST. ast never sees comments — which is the point: a guard
    asserted against raw text can be satisfied by the comment explaining it."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name}() not found in {os.path.basename(path)}")


def _src(node):
    return ast.dump(node)


# --------------------------------------------------------------------------- #
#  1. the action menu is DERIVED, and covers everything dangerous               #
# --------------------------------------------------------------------------- #
def test_every_dangerous_targeted_action_is_change_controlled():
    """The desync guard. A new dangerous action must not be able to ship
    outside change control just because nobody edited a second list."""
    from app.services import scheduled_actions as sa
    from app.views.change_requests import cr_action_keys

    keys = cr_action_keys()
    missing = [s.key for s in sa.ALL_ACTIONS.values()
               if s.needs_targets and (s.danger or s.scope == "user")
               and s.key not in keys]
    assert not missing, f"dangerous actions outside change control: {missing}"


def test_the_menu_is_not_a_hand_written_literal():
    """cr_actions() must READ the catalog. A literal list is the failure mode
    this whole module exists to prevent, so a literal is what we forbid."""
    node = _func(VIEW_PATH, "_cr_specs")
    dumped = _src(node)
    assert "ALL_ACTIONS" in dumped, "_cr_specs() must read the catalog"
    literals = [n.value for n in ast.walk(node)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "upgrade" not in literals and "upgrade_prep" not in literals, \
        "action keys are hard-coded again"


def test_menu_holds_the_object_ops_that_used_to_be_unreachable():
    from app.views.change_requests import cr_action_keys

    keys = cr_action_keys()
    for key in ("policy_set_status", "backend_set_status", "backend_set_config",
                "swap_certificate", "custom_rest", "upgrade", "upgrade_prep",
                "reboot", "cert_lifecycle"):
        assert key in keys, f"{key} cannot be put under change control"


def test_menu_excludes_actions_that_touch_no_device():
    """A CR without a device has no window to speak of; a fleet-wide file
    writer (stats, system_backup) is not a change to an appliance."""
    from app.views.change_requests import cr_action_keys

    keys = cr_action_keys()
    for key in ("stats", "system_backup", "metrics_scrape", "monitor_report"):
        assert key not in keys


# --------------------------------------------------------------------------- #
#  2. targets: all four products                                                #
# --------------------------------------------------------------------------- #
def test_all_four_forti_products_can_be_targeted():
    from app.views.change_requests import cr_kinds

    kinds = set(cr_kinds())
    assert {"fortiweb", "fortiadc", "fortianalyzer", "fortiauthenticator"} <= kinds


def test_device_picker_is_not_pinned_to_fortiweb():
    """The literal that caused it: ``filter_by(kind='fortiweb')`` in new()."""
    node = _func(VIEW_PATH, "new")
    for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
        fn = call.func
        if isinstance(fn, ast.Attribute) and fn.attr == "filter_by":
            for kw in call.keywords:
                assert not (kw.arg == "kind"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value == "fortiweb"), \
                    "the CR device picker is pinned to FortiWeb again"


def test_kinds_are_derived_from_the_actions_products():
    """cr_kinds() must not be its own hand-kept tuple either."""
    node = _func(VIEW_PATH, "cr_kinds")
    assert "products" in _src(node)


# --------------------------------------------------------------------------- #
#  3. the form refuses a combination that would resolve to no targets           #
# --------------------------------------------------------------------------- #
def _mk_appliance(kind, name):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, host=f"{name}.invalid", kind=kind,
                  username="u", port=443, verify_ssl=False)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _post(client, app, *, product="global", **form):
    """POST the new-CR form from a given ADOM.

    The ADOM matters and is NOT a test detail: appliances are scoped by product
    (``product_scope.scope_appliance_query``), so a FortiWeb console can only
    ever name FortiWeb boxes. Opening the picker to four products means "the
    picker no longer adds a filter of its own", NOT "every session sees every
    device" — a by-id route that served another ADOM's appliance was a real
    defect here on 2026-08-06 and must not come back through this form.
    """
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app), product=product)
    body = {"title": "T", "risk": "medium", "reason": "r"}
    body.update(form)
    return client.post("/change-requests/new", data=body, follow_redirects=False)


def test_the_picker_still_obeys_the_active_adom(app, client):
    """A FortiWeb console must not gain sight of a FortiADC through this form."""
    from tests.conftest import admin_user_id, login

    with app.app_context():
        _mk_appliance("fortiweb", "adom-fwb")
        _mk_appliance("fortiadc", "adom-adc")
        login(client, admin_user_id(app), product="fortiweb")
        body = client.get("/change-requests/new").get_data(as_text=True)
        assert "adom-fwb" in body
        assert "adom-adc" not in body, "cross-ADOM device leak in the CR picker"

        login(client, admin_user_id(app), product="global")
        body = client.get("/change-requests/new").get_data(as_text=True)
        assert "adom-fwb" in body and "adom-adc" in body


def test_naming_another_adoms_device_is_refused(app, client):
    from app.models import ChangeRequest

    with app.app_context():
        adc = _mk_appliance("fortiadc", "adc-other")
        resp = _post(client, app, product="fortiweb", action="upgrade_prep",
                     device_ids=[str(adc.id)])
        assert resp.status_code == 302
        assert ChangeRequest.query.count() == 0


def test_a_fortiweb_only_action_rejects_a_fortiadc_target(app, client):
    from app.models import ChangeRequest

    with app.app_context():
        adc = _mk_appliance("fortiadc", "adc-t1")
        resp = _post(client, app, action="upgrade", device_ids=[str(adc.id)])
        assert resp.status_code == 302
        # rejected == nothing saved. A saved CR here is the silent no-op.
        assert ChangeRequest.query.count() == 0


def test_a_supported_pairing_is_accepted(app, client):
    from app.models import ChangeRequest

    with app.app_context():
        adc = _mk_appliance("fortiadc", "adc-t2")
        resp = _post(client, app, action="upgrade_prep", device_ids=[str(adc.id)])
        assert resp.status_code == 302
        assert ChangeRequest.query.count() == 1
        assert ChangeRequest.query.first().action == "upgrade_prep"


def test_a_fac_can_be_named_in_a_change(app, client):
    """The headline of the whole change: this used to be impossible."""
    from app.models import ChangeRequest

    with app.app_context():
        fac = _mk_appliance("fortiauthenticator", "fac-t1")
        resp = _post(client, app, action="reboot", device_ids=[str(fac.id)])
        assert resp.status_code == 302
        cr = ChangeRequest.query.first()
        assert cr is not None and cr.device_ids_list == [fac.id]


def test_single_target_action_refuses_two_devices(app, client):
    from app.models import ChangeRequest

    with app.app_context():
        a = _mk_appliance("fortiweb", "fwb-t1")
        b = _mk_appliance("fortiweb", "fwb-t2")
        resp = _post(client, app, action="policy_set_status",
                     device_ids=[str(a.id), str(b.id)])
        assert resp.status_code == 302
        assert ChangeRequest.query.count() == 0, \
            "a single_target action would silently run on only the first device"


def test_unknown_action_is_rejected_not_coerced_to_upgrade(app, client):
    """The old code rewrote a glitched form into 'upgrade' — the most
    destructive entry on the menu."""
    from app.models import ChangeRequest

    with app.app_context():
        fwb = _mk_appliance("fortiweb", "fwb-t3")
        resp = _post(client, app, action="not_an_action", device_ids=[str(fwb.id)])
        assert resp.status_code == 302
        assert ChangeRequest.query.count() == 0


def test_a_non_change_controlled_action_cannot_be_smuggled_in(app, client):
    """'backup' is a real catalog key but is not change-controlled; posting it
    must not create a CR bound to it."""
    from app.models import ChangeRequest

    with app.app_context():
        fwb = _mk_appliance("fortiweb", "fwb-t4")
        resp = _post(client, app, action="backup", device_ids=[str(fwb.id)])
        assert resp.status_code == 302
        assert ChangeRequest.query.count() == 0


def _mk_cr_for(app, client, kind, name):
    """Create a CR naming one device of *kind*, from an ADOM that can see it."""
    from app.models import ChangeRequest

    dev = _mk_appliance(kind, name)
    action = "reboot" if kind != "fortiadc" else "upgrade_prep"
    resp = _post(client, app, product="global", action=action,
                 device_ids=[str(dev.id)], title=f"CR for {name}")
    assert resp.status_code == 302
    cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
    assert cr is not None and cr.device_ids_list == [dev.id]
    return cr


def test_a_change_is_listed_only_where_its_device_is_visible(app, client):
    """Opening the page to four products must not open the FLEET to four
    products: a FortiWeb console has no business reading an ADC's window."""
    from tests.conftest import admin_user_id, login

    with app.app_context():
        cr = _mk_cr_for(app, client, "fortiadc", "scope-adc")

        # Drain the 'created' flash first: it echoes the title on the NEXT
        # page and would satisfy the assertion below without the row existing.
        body = client.get("/change-requests/").get_data(as_text=True)
        assert cr.title in body

        login(client, admin_user_id(app), product="fortiweb")
        body = client.get("/change-requests/").get_data(as_text=True)
        assert cr.title not in body, "an ADC change leaked into the FortiWeb ADOM"

        for prod in ("fortiadc", "global"):
            login(client, admin_user_id(app), product=prod)
            body = client.get("/change-requests/").get_data(as_text=True)
            assert cr.title in body, f"the change vanished in the {prod} ADOM"


def test_the_by_id_routes_are_scoped_too_not_just_the_list(app, client):
    """Hiding a row in the list and serving it one URL away is decoration, not
    scoping - the hole closed fleet-wide for appliances on 2026-08-06."""
    from tests.conftest import admin_user_id, login

    with app.app_context():
        cr = _mk_cr_for(app, client, "fortiadc", "scope-adc2")
        login(client, admin_user_id(app), product="fortiweb")

        assert client.get(f"/change-requests/{cr.id}").status_code == 404
        for verb in ("approve", "schedule", "cancel", "mark-notified"):
            r = client.post(f"/change-requests/{cr.id}/{verb}", data={})
            assert r.status_code == 404, f"{verb} served another ADOM's change"

        login(client, admin_user_id(app), product="fortiadc")
        assert client.get(f"/change-requests/{cr.id}").status_code == 200


def test_a_change_naming_no_device_stays_reachable_everywhere(app, client):
    """It belongs to no product; hiding it would make it reachable from no
    console at all."""
    from tests.conftest import admin_user_id, login
    from app.models import ChangeRequest

    with app.app_context():
        resp = _post(client, app, product="global", action="reboot",
                     title="fleet-wide CR")
        assert resp.status_code == 302
        cr = ChangeRequest.query.first()
        for prod in ("fortiweb", "fortiadc", "global"):
            login(client, admin_user_id(app), product=prod)
            assert client.get(f"/change-requests/{cr.id}").status_code == 200


# --------------------------------------------------------------------------- #
#  4. the reboot action                                                         #
# --------------------------------------------------------------------------- #
def test_reboot_is_registered_dangerous_one_shot_and_cr_bound():
    from app.services import scheduled_actions as sa

    spec = sa.get_spec("reboot")
    assert spec is not None
    assert spec.danger is True
    assert spec.forced_schedule_kind == "once"
    assert spec.requires_change_request is True
    assert spec.needs_targets is True


def test_reboot_urn_is_the_one_read_off_the_device():
    from app.services import scheduled_actions as sa

    tr = sa.REBOOT_TRANSPORT["fortiweb"]
    assert tr.endpoint == "/api/v2.0/system/status.systemoperationreboot"
    assert tr.reason_key == "reason" and tr.reason_max == 100
    assert "VERIFIED" in tr.provenance


def test_no_unverified_product_has_a_reboot_urn():
    """The guard that keeps a plausible guess from being added quietly."""
    from app.services import scheduled_actions as sa

    assert set(sa.REBOOT_TRANSPORT) == {"fortiweb"}, (
        "a reboot URN was added — it must be verified against that product's "
        "own device, and this guard updated with the provenance")


class _Boom:
    """Any device call at all is a failure in these tests."""

    def api_call(self, *a, **kw):  # pragma: no cover - must never run
        raise AssertionError("the device was contacted")


class _Appliance:
    def __init__(self, kind, name="dev"):
        self.kind, self.name = kind, name
        self.calls = []

    def build_client(self, *a, **kw):
        self.calls.append((a, kw))
        return _Boom()


@pytest.mark.parametrize("kind", ["fortiadc", "fortianalyzer", "fortiauthenticator"])
def test_reboot_refuses_unverified_products_by_name_without_connecting(kind):
    from app.services import scheduled_actions as sa

    dev = _Appliance(kind, f"{kind}-1")
    out = sa.run_action(sa.get_spec("reboot"), dev, {}, dry_run=False)
    assert out["ok"] is False
    assert kind in out["summary"]
    assert "NOTHING was sent" in out["summary"]
    assert dev.calls == [], "it built a client for a product it refuses"


def test_reboot_dry_run_never_touches_the_box():
    from app.services import scheduled_actions as sa

    dev = _Appliance("fortiweb", "fwb")
    out = sa.run_action(sa.get_spec("reboot"), dev, {}, dry_run=True)
    assert out["ok"] is True
    assert "dry-run" in out["summary"] and "Nothing was sent" in out["summary"]
    assert dev.calls == []


def test_reboot_posts_the_verified_urn_with_the_reason():
    from app.services import scheduled_actions as sa

    seen = {}

    class _C:
        def api_call(self, method, path, data=None):
            seen.update(method=method, path=path, data=data)

            class _R:
                status_code, text = 200, "{}"
            return _R()

    class _A(_Appliance):
        def build_client(self, *a, **kw):
            return _C()

    out = sa.run_action(sa.get_spec("reboot"), _A("fortiweb", "fwb08"),
                        {"reason": "x" * 300}, dry_run=False)
    assert out["ok"] is True
    assert seen["method"] == "POST"
    assert seen["path"] == "/api/v2.0/system/status.systemoperationreboot"
    assert len(seen["data"]["reason"]) == 100, "the 100-char cap is the device's"


def test_reboot_does_not_claim_the_box_came_back():
    """A 2xx says the reboot was ACCEPTED. Reporting 'rebooted' would assert a
    return to service nobody observed."""
    from app.services import scheduled_actions as sa

    class _C:
        def api_call(self, *a, **kw):
            class _R:
                status_code, text = 200, "{}"
            return _R()

    class _A(_Appliance):
        def build_client(self, *a, **kw):
            return _C()

    out = sa.run_action(sa.get_spec("reboot"), _A("fortiweb"), {}, dry_run=False)
    assert "not confirmed" in out["summary"].lower()


def test_reboot_grades_a_device_refusal_as_failure():
    from app.services import scheduled_actions as sa

    class _C:
        def api_call(self, *a, **kw):
            class _R:
                status_code, text = 403, "permission denied"
            return _R()

    class _A(_Appliance):
        def build_client(self, *a, **kw):
            return _C()

    out = sa.run_action(sa.get_spec("reboot"), _A("fortiweb"), {}, dry_run=False)
    assert out["ok"] is False and "403" in out["summary"]


# --------------------------------------------------------------------------- #
#  5. requires_change_request is enforced by the EXECUTOR, declaratively        #
# --------------------------------------------------------------------------- #
def test_unbound_dangerous_action_is_refused_at_fire_time(session):
    """Scheduling a reboot without a CR must not simply run it."""
    import json
    from datetime import datetime

    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import scheduled_actions as sa

    row = ScheduledAction(
        name="rogue reboot", scope="admin", action="reboot", targets="[]",
        params=json.dumps({}), schedule_kind="once",
        schedule=json.dumps({"at": datetime.utcnow().isoformat()}),
        enabled=True, catch_up=True, created_by="tester")
    db.session.add(row)
    db.session.commit()

    run = sa.execute_and_record(row, trigger="manual")
    assert run.status == "skipped"
    assert "change request" in (run.summary or "").lower()


def test_the_gate_reads_the_spec_flag_not_an_action_name():
    """Cabling it to the string 'reboot' is the defect this replaces."""
    node = _func(SA_PATH, "execute_and_record")
    dumped = _src(node)
    assert "requires_change_request" in dumped
    names = [n.value for n in ast.walk(node)
             if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "reboot" not in names, "the gate is cabled to an action name again"
