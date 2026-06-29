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
    # el VIP se muestra como dropdown poblado del equipo, no como text box
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
