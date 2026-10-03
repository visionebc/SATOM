"""Create Server Policy: form renders complete validated field set incl. VIP."""
import re
from tests.conftest import login, admin_user_id


def _make_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def test_new_policy_form_renders_all_fields_and_vip(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.get(f"/workspace/{aid}/new-policy")
    assert r.status_code == 200, r.status_code
    h = r.get_data(as_text=True)
    for k in ("vip", "interface", "use-interface-ip"):
        assert ('data-key="%s"' % k) in h, "missing VIP field %s" % k
    n = len(re.findall(r"data-key=", h))
    assert n >= 100, "too few create fields: %d" % n
    for s in ("New Server Policy", "Virtual Server &amp; VIP", "Server Pool", "Policy settings"):
        assert s in h, "missing section %s" % s
    assert "addVip()" in h and "addPs()" in h


def test_create_policy_dryrun_builds_dependency_ordered_bodies(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/create-policy", json={
        "apply": False,
        "policy": {"name": "pol-unittest", "deployment-mode": "server-pool"},
        "vserver_name": "vs-unittest",
        "vips": [{"vip": "192.0.2.9/24", "status": "enable"}],
        "pool_name": "pool-unittest",
        "pool": {"type": "reverse-proxy"},
        "pservers": [{"server-type": "physical", "ip": "192.0.2.50", "port": "80"}],
    })
    assert r.status_code == 200, r.status_code
    j = r.get_json()
    assert j["ok"] and j["dry_run"], j
    labels = [s["label"] for s in j["steps"]]
    assert labels[0] == "Virtual Server"
    assert "VIP 1" in labels and "Server Pool" in labels and "Pool member 1" in labels
    assert labels[-1] == "Server Policy"
    pol = [s for s in j["steps"] if s["label"] == "Server Policy"][0]
    assert pol["body"]["data"]["name"] == "pol-unittest"
    assert pol["body"]["data"]["vserver"] == "vs-unittest"
    assert pol["body"]["data"]["server-pool"] == "pool-unittest"
    # blanks dropped: empty fields must not be sent
    assert "" not in pol["body"]["data"].values()


def test_create_form_selects_match_standalone(client, app):
    """The curated per-object selects ported from the desktop standalone:
    VIP is a device-populated dropdown (system/vip), pool member status is
    tri-state (enable/disable/maintenance), server-type includes sdn, and the
    Server Pool object exposes the full protocol/type/lb-algo vocabularies."""
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    h = client.get(f"/workspace/{aid}/new-policy").get_data(as_text=True)
    # the VIP is shown as a dropdown populated from the device, not as a text box
    assert 'data-ref="system/vip"' in h, "VIP address is not a device dropdown"
    # pool member tri-state + sdn (were missing before the port)
    assert ">maintenance<" in h, "pool member status missing 'maintenance'"
    assert ">sdn<" in h, "pool member server-type missing 'sdn'"
    # Server Pool object selects (rendered via the fld macro from KIND_SPECS)
    assert ">HTTPS<" in h, "pool protocol missing HTTPS"
    assert "true-transparent-proxy" in h, "pool type vocabulary not ported"
    assert "host-domain-hash" in h, "pool lb-algo vocabulary not ported"


def test_cmdb_options_allows_system_vip(client, app):
    from app.services.fortiweb_field_schema import ALL_REF_ENDPOINTS
    assert "system/vip" in ALL_REF_ENDPOINTS


# ── audit 2026-10-03: WPP field and AppID binding ─────────────────────────
def test_the_form_offers_the_web_protection_profile(client, app):
    """The view hoisted the WPP out of the groups and the page never rendered
    it, so a new policy could not be created with a profile."""
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    h = client.get(f"/workspace/{aid}/new-policy").get_data(as_text=True)
    scope = h.split('id="policyScope"', 1)[1]
    assert 'data-key="web-protection-profile"' in scope


def _appid(app, name="APP-001"):
    from app.services import appids
    with app.app_context():
        return appids.create_manual(app_id=name).id


def test_the_appid_picker_lists_the_catalog(client, app):
    aid = _make_appliance(app)
    _appid(app, "APP-CATALOG-1")
    login(client, admin_user_id(app))
    h = client.get(f"/workspace/{aid}/new-policy").get_data(as_text=True)
    assert "APP-CATALOG-1" in h


def test_an_applied_create_binds_the_chosen_appid(client, app, monkeypatch):
    from app.services import appids
    from app.services.fortiweb_ops import FortiWebOps, OpResult
    monkeypatch.setattr(FortiWebOps, "create",
                        lambda self, ep, data, **k: OpResult({"ok": True}))
    aid = _make_appliance(app)
    pk = _appid(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/create-policy", json={
        "apply": True, "policy": {"name": "pol-bound"}, "app_id_pk": str(pk)})
    assert r.status_code == 200 and r.get_json()["ok"], r.get_json()
    with app.app_context():
        row = appids.binding_for(aid, "pol-bound")
        assert row is not None and row.app_id_id == pk


def test_a_dry_run_binds_nothing(client, app):
    from app.services import appids
    aid = _make_appliance(app)
    pk = _appid(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/create-policy", json={
        "apply": False, "policy": {"name": "pol-dry"}, "app_id_pk": str(pk)})
    assert r.get_json()["ok"]
    with app.app_context():
        assert appids.binding_for(aid, "pol-dry") is None


def test_an_operator_cannot_bind_an_appid_through_create(client, app,
                                                        monkeypatch):
    from tests.conftest import make_user
    from app.services.fortiweb_ops import FortiWebOps, OpResult
    calls = []
    monkeypatch.setattr(FortiWebOps, "create",
                        lambda self, ep, data, **k: calls.append(ep)
                        or OpResult({"ok": True}))
    aid = _make_appliance(app)
    pk = _appid(app)
    login(client, make_user(app, username="op1", role="operator"))
    h = client.get(f"/workspace/{aid}/new-policy").get_data(as_text=True)
    assert 'id="appIdSel"' not in h
    r = client.post(f"/workspace/{aid}/create-policy", json={
        "apply": True, "policy": {"name": "pol-x"}, "app_id_pk": str(pk)})
    assert r.status_code == 403
    assert calls == []
