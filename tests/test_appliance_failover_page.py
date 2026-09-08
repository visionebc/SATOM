"""The failover verb ON the device page (``/appliances/<id>/failover``).

Asked for as "metelo dentro del device ... ahi si es un cluster debera venir la
opcion de hacer un failover". The action itself was already registered and
change-request gated (``tests/test_ha_failover.py``); what is new here is a
SURFACE, and a surface for a disruptive verb fails in ways the executor's own
tests cannot see:

* a page that only HIDES the button is decoration -- the URL is guessable, so
  the refusal has to live on the route;
* the button a human clicks is historically the path that skips the gate the
  headless executor honours (this module already paid for that once, on the
  firmware page: ``_upgrade_authorization`` exists because the live flash button
  went straight to ``push_firmware``);
* a change request approving a FIRMWARE UPGRADE must not authorize a failover of
  the same box, and the gate used to be able to say nothing else because it
  hard-coded one action name.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from tests.conftest import login, make_user, profile_id


# --------------------------------------------------------------------------- #
#  fixtures                                                                    #
# --------------------------------------------------------------------------- #
def _appliance(app, **kw):
    from app.models import Appliance, db
    fields = dict(name="fw1", kind="fortiweb", host="192.0.2.99", port=443,
                  username="admin", verify_ssl=False,
                  firmware="FortiWeb-KVM 8.0.1,build0100(GA),260701")
    fields.update(kw)
    with app.app_context():
        a = Appliance(**fields)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


def _cluster(app, ha_mode="vip"):
    """Node 0 + one member, the shape ``services.ha`` documents."""
    node0 = _appliance(app, name="cl1", is_cluster=True, ha_mode=ha_mode,
                       host="192.0.2.90")
    member = _appliance(app, name="cl1-n1", is_cluster_member=True,
                        parent_id=node0, host="192.0.2.91")
    return node0, member


def _admin(app, client):
    uid = make_user(app, "adm", role="admin", profile_id=profile_id(app, "admin"))
    login(client, uid)
    return uid


def _cr(app, appliance_id, action="ha_failover", status="approved",
        start=None, end=None):
    from app.models import ChangeRequest, db
    import json
    now = datetime.utcnow()
    with app.app_context():
        cr = ChangeRequest(
            title="t", action=action, status=status,
            device_ids=json.dumps([appliance_id]),
            window_start=start if start is not None else now - timedelta(hours=1),
            window_end=end if end is not None else now + timedelta(hours=1),
            ref="CR-TEST")
        db.session.add(cr)
        db.session.commit()
        return cr.id


@pytest.fixture()
def no_device(monkeypatch):
    """Every device transport recorded and neutered.

    ``sent`` staying empty is the assertion most of these tests actually make: a
    refusal that still opened an SSH session to the cluster is not a refusal.
    """
    state = {"sent": [], "reads": [], "role": "primary"}

    def _run_command(appliance, command, *, timeout=15.0):
        state["reads"].append((getattr(appliance, "name", "?"), command))
        return {"primary": "Local: master", "secondary": "Local: slave",
                "standalone": "HA is disabled."}[state["role"]]

    def _run_script(appliance, commands, **kw):
        from app.services.ssh_console import CommandRow, ScriptResult
        state["sent"].append((getattr(appliance, "name", "?"), list(commands)))
        return ScriptResult(
            appliance=getattr(appliance, "name", "?"),
            rows=[CommandRow(command=commands[0], tier="disruptive",
                             status="ok", detail="", output="ok")],
            transcript="ok", error="")

    def _member_role(appliance, timeout=6.0):
        state["reads"].append((getattr(appliance, "name", "?"), "<REST>"))
        return state["role"]

    from app.services import ha as ha_svc, ssh_console, ssh_ops
    monkeypatch.setattr(ssh_ops, "run_command", _run_command)
    monkeypatch.setattr(ssh_console, "run_script", _run_script)
    monkeypatch.setattr(ha_svc, "member_role", _member_role)
    return state


# --------------------------------------------------------------------------- #
#  1. "if it is a cluster" is a ROUTE decision, not a hidden link              #
# --------------------------------------------------------------------------- #
def test_a_standalone_appliance_has_no_failover_page(app, client):
    """The verb is meaningless without a peer, and hiding the button is not a
    refusal: the URL is guessable and the POST siblings share this check."""
    aid = _appliance(app)
    _admin(app, client)
    r = client.get(f"/appliances/{aid}/failover")
    assert r.status_code == 302
    assert f"/appliances/{aid}" in r.headers["Location"]


def test_the_refusal_names_what_to_do_about_it(app, client):
    """A gate that says 'no' without saying where the button went is a dead end
    -- the rule ``require_device_scope`` already states in this module."""
    aid = _appliance(app)
    _admin(app, client)
    r = client.get(f"/appliances/{aid}/failover", follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "not registered as an HA cluster" in body
    assert "member node" in body


def test_a_cluster_node0_gets_the_page(app, client):
    node0, _m = _cluster(app)
    _admin(app, client)
    r = client.get(f"/appliances/{node0}/failover")
    assert r.status_code == 200
    assert "HA Failover" in r.get_data(as_text=True)


def test_a_member_node_gets_the_page_too(app, client):
    """The cluster CARD renders only on node 0, so a member opened directly
    would otherwise have no route to the verb that targets it."""
    _n0, member = _cluster(app)
    _admin(app, client)
    assert client.get(f"/appliances/{member}/failover").status_code == 200


def test_the_button_appears_on_a_cluster_and_not_on_a_standalone(app, client):
    node0, _m = _cluster(app)
    plain = _appliance(app, name="fw-plain", host="192.0.2.92")
    _admin(app, client)
    assert f"/appliances/{node0}/failover" in client.get(
        f"/appliances/{node0}").get_data(as_text=True)
    assert "/failover" not in client.get(
        f"/appliances/{plain}").get_data(as_text=True)


def test_the_member_page_offers_the_button(app, client):
    _n0, member = _cluster(app)
    _admin(app, client)
    assert f"/appliances/{member}/failover" in client.get(
        f"/appliances/{member}").get_data(as_text=True)


# --------------------------------------------------------------------------- #
#  2. the direction is never coerced                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", [None, "", "SET ", "yes", "1", "reboot"])
def test_an_unrecognised_direction_is_refused_not_defaulted(value):
    """Defaulting a missing direction to 'set' turns a glitched form into the
    half of this action that takes a cluster down. ('SET ' is accepted --
    whitespace and case are normalised; the point is that only the two real
    words survive.)"""
    from app.views.appliances import _failover_direction
    assert _failover_direction(value) == (
        "set" if (value or "").strip().lower() in ("set", "unset") else None)


def test_a_live_post_without_a_direction_sends_nothing(app, client, no_device):
    node0, _m = _cluster(app)
    _cr(app, node0)
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover",
                    data={"confirm_name": "cl1"}, follow_redirects=True)
    assert no_device["sent"] == []
    assert "Nothing was sent" in r.get_data(as_text=True)


# --------------------------------------------------------------------------- #
#  3. the button carries the SAME gate as the headless executor                #
# --------------------------------------------------------------------------- #
def test_a_live_failover_without_an_approved_change_sends_nothing(
        app, client, no_device):
    node0, _m = _cluster(app)
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover",
                    data={"direction": "set", "confirm_name": "cl1"},
                    follow_redirects=True)
    assert no_device["sent"] == []
    assert "change control" in r.get_data(as_text=True)


def test_an_approved_upgrade_does_not_authorize_a_failover(
        app, client, no_device):
    """The gate used to hard-code ``action == 'upgrade'``. Reusing it for a
    second verb without parameterising the action would have let a change that
    approves a FIRMWARE FLASH authorize a cluster failover of the same box."""
    node0, _m = _cluster(app)
    _cr(app, node0, action="upgrade")
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover",
                    data={"direction": "set", "confirm_name": "cl1"},
                    follow_redirects=True)
    assert no_device["sent"] == []
    assert "change control" in r.get_data(as_text=True)


def test_an_approved_failover_change_does_not_authorize_an_upgrade(app):
    """The mirror image, asserted on the helper: the parameterisation has to cut
    BOTH ways or it only moved the hole."""
    from app.views.appliances import _upgrade_authorization
    from app.models import Appliance
    node0, _m = _cluster(app)
    _cr(app, node0, action="ha_failover")
    with app.app_context():
        _cr_row, ok, reason = _upgrade_authorization(
            Appliance.query.get(node0))
    assert ok is False
    assert "upgrade" in reason


def test_a_closed_window_refuses_and_sends_nothing(app, client, no_device):
    node0, _m = _cluster(app)
    past = datetime.utcnow() - timedelta(days=2)
    _cr(app, node0, start=past, end=past + timedelta(hours=1))
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover",
                    data={"direction": "set", "confirm_name": "cl1"},
                    follow_redirects=True)
    assert no_device["sent"] == []
    assert "change control" in r.get_data(as_text=True)


def test_the_wrong_typed_name_refuses_even_inside_an_open_window(
        app, client, no_device):
    node0, _m = _cluster(app)
    _cr(app, node0)
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover",
                    data={"direction": "set", "confirm_name": "cl2"},
                    follow_redirects=True)
    assert no_device["sent"] == []
    assert "exact appliance name" in r.get_data(as_text=True)


def test_an_authorised_live_failover_runs_and_closes_the_change(
        app, client, no_device):
    node0, _m = _cluster(app)
    cr_id = _cr(app, node0)
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover",
                    data={"direction": "set", "confirm_name": "cl1"})
    assert r.status_code == 200
    assert [c for _n, cmds in no_device["sent"] for c in cmds] == [
        "execute ha failover set"]
    from app.models import ChangeRequest
    with app.app_context():
        assert ChangeRequest.query.get(cr_id).status == "completed"


def test_a_failed_live_failover_closes_the_change_as_failed(
        app, client, no_device, monkeypatch):
    """A change whose window elapsed with the change NOT happening did not
    succeed, and the record has to say so."""
    node0, _m = _cluster(app)
    cr_id = _cr(app, node0)
    _admin(app, client)
    from app.services import ssh_console

    def _boom(appliance, commands, **kw):
        from app.services.ssh_console import ScriptResult
        no_device["sent"].append((getattr(appliance, "name", "?"), list(commands)))
        return ScriptResult(appliance="cl1", rows=[], transcript="",
                            error="connection refused.")
    monkeypatch.setattr(ssh_console, "run_script", _boom)
    client.post(f"/appliances/{node0}/failover",
                data={"direction": "set", "confirm_name": "cl1"})
    from app.models import ChangeRequest
    with app.app_context():
        assert ChangeRequest.query.get(cr_id).status == "failed"


# --------------------------------------------------------------------------- #
#  4. the readiness check is the action's OWN dry run                          #
# --------------------------------------------------------------------------- #
def test_the_readiness_check_needs_no_change_request_and_sends_nothing(
        app, client, no_device):
    """Gating a dry run would push operators to skip the validation step
    entirely -- the reasoning the firmware page already records."""
    node0, _m = _cluster(app)
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover/preflight",
                    data={"direction": "set"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    assert no_device["sent"] == []
    assert "[dry-run]" in r.get_json()["summary"]


def test_the_readiness_check_reports_a_standby_as_not_ready(
        app, client, no_device):
    node0, _m = _cluster(app)
    no_device["role"] = "secondary"
    _admin(app, client)
    body = client.post(f"/appliances/{node0}/failover/preflight",
                       data={"direction": "set"}).get_json()
    assert body["ok"] is False
    assert "not 'primary'" in body["summary"]
    assert no_device["sent"] == []


def test_the_readiness_check_refuses_a_bad_direction(app, client, no_device):
    node0, _m = _cluster(app)
    _admin(app, client)
    r = client.post(f"/appliances/{node0}/failover/preflight",
                    data={"direction": "sideways"})
    assert r.status_code == 400
    assert no_device["sent"] == [] and no_device["reads"] == []


def test_the_readiness_check_is_refused_on_a_standalone_row(
        app, client, no_device):
    aid = _appliance(app)
    _admin(app, client)
    r = client.post(f"/appliances/{aid}/failover/preflight",
                    data={"direction": "set"})
    assert r.status_code == 409
    assert no_device["reads"] == []


# --------------------------------------------------------------------------- #
#  5. planning it goes through the ONE implementation of "raise a change"      #
# --------------------------------------------------------------------------- #
def test_planning_raises_a_draft_change_carrying_the_direction(app, client):
    """The direction rides on the CHANGE. ``schedule_change_request`` rebuilds
    the bound action from the CR every time it is scheduled, so a direction
    stored only on the action row is reset to the executor default on the next
    reschedule -- which would make 'unset' unschedulable."""
    node0, _m = _cluster(app)
    _admin(app, client)
    now = datetime.utcnow()
    r = client.post(f"/appliances/{node0}/failover/schedule", data={
        "direction": "unset", "title": "give it back",
        "window_start": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
        "window_end": (now + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M"),
    })
    assert r.status_code == 302
    from app.models import ChangeRequest
    with app.app_context():
        cr = ChangeRequest.query.filter_by(action="ha_failover").one()
        assert cr.status == "draft"
        assert cr.params_dict == {"direction": "unset"}
        assert cr.device_ids_list == [node0]


def test_the_planned_direction_survives_scheduling_onto_the_action(app, client):
    """End of the chain: the bound ScheduledAction must carry the direction the
    operator picked, not the executor's default."""
    node0, _m = _cluster(app)
    _admin(app, client)
    now = datetime.utcnow()
    client.post(f"/appliances/{node0}/failover/schedule", data={
        "direction": "unset", "title": "give it back",
        "window_start": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
        "window_end": (now + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M"),
    })
    from app.models import ChangeRequest, ScheduledAction, db
    from app.services import change_requests as crsvc
    with app.app_context():
        cr = ChangeRequest.query.filter_by(action="ha_failover").one()
        cr.status = "approved"
        db.session.commit()
        cr_id = cr.id
        aid = crsvc.schedule_change_request(cr_id, by="t")
        db.session.commit()
        params = ScheduledAction.query.get(aid).params_dict
    assert params["direction"] == "unset"
    assert params["change_request_id"] == cr_id


def test_an_inverted_window_is_refused_and_creates_nothing(app, client):
    node0, _m = _cluster(app)
    _admin(app, client)
    now = datetime.utcnow()
    client.post(f"/appliances/{node0}/failover/schedule", data={
        "direction": "set", "title": "backwards",
        "window_start": (now + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M"),
        "window_end": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
    })
    from app.models import ChangeRequest
    with app.app_context():
        assert ChangeRequest.query.count() == 0


def test_a_caller_cannot_smuggle_its_own_authorization_into_params(app):
    """``params['change_request_id']`` is what the executor reads AS the
    authorization. A caller that could set it would be approving its own
    change."""
    from app.views.change_requests import create_change_request
    node0, _m = _cluster(app)
    with app.app_context():
        cr, error = create_change_request({
            "title": "t", "action": "ha_failover", "device_ids": [node0],
            "params": {"direction": "set", "change_request_id": 999},
        })
        assert error is None or cr is not None
        assert cr.params_dict == {"direction": "set"}


# --------------------------------------------------------------------------- #
#  6. the firmware floor is checked on the box that RECEIVES the command       #
# --------------------------------------------------------------------------- #
def test_the_version_floor_is_read_off_the_resolved_target(app, no_device):
    """A per-node cluster's node 0 is a logical CONTAINER with no host and no
    firmware string (``models.chassis_key`` says so in as many words). Checking
    node 0 refused every per-node cluster as 'no recorded firmware version',
    and a stale string left on node 0 would have cleared a floor the live
    primary does not meet."""
    from app.models import Appliance, db
    from app.services import scheduled_actions as sa
    node0 = _appliance(app, name="cl2", is_cluster=True, ha_mode="per_node",
                       host="", firmware=None)
    _appliance(app, name="cl2-n1", is_cluster_member=True, parent_id=node0,
               host="192.0.2.93",
               firmware="FortiWeb-KVM 8.0.1,build0100(GA),260701")
    with app.app_context():
        db.session.expire_all()
        result = sa.run_action(sa.get_spec("ha_failover"),
                               Appliance.query.get(node0),
                               {"direction": "set"}, dry_run=True)
    assert result["ok"] is True, result["summary"]
    assert no_device["sent"] == []


def test_a_target_below_the_floor_is_refused_by_name(app, no_device):
    from app.models import Appliance, db
    from app.services import scheduled_actions as sa
    node0 = _appliance(app, name="cl3", is_cluster=True, ha_mode="per_node",
                       host="", firmware=None)
    _appliance(app, name="cl3-n1", is_cluster_member=True, parent_id=node0,
               host="192.0.2.94",
               firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    with app.app_context():
        db.session.expire_all()
        result = sa.run_action(sa.get_spec("ha_failover"),
                               Appliance.query.get(node0),
                               {"direction": "set"}, dry_run=True)
    assert result["ok"] is False
    assert "cl3-n1" in result["summary"], (
        "the refusal must name the box that would have received the command, "
        "not the container that never does")
    assert "7.6.8" in result["summary"] and "8.0.0" in result["summary"]
    assert no_device["sent"] == []


# --------------------------------------------------------------------------- #
#  7. permissions                                                              #
# --------------------------------------------------------------------------- #
def test_a_readonly_user_cannot_reach_any_failover_route(app, client):
    node0, _m = _cluster(app)
    ro = make_user(app, "ro", role="readonly", profile_id=profile_id(app, "readonly"))
    login(client, ro)
    assert client.get(f"/appliances/{node0}/failover").status_code == 403
    assert client.post(f"/appliances/{node0}/failover",
                       data={"direction": "set"}).status_code == 403
    assert client.post(f"/appliances/{node0}/failover/preflight",
                       data={"direction": "set"}).status_code == 403
    assert client.post(f"/appliances/{node0}/failover/schedule",
                       data={"direction": "set"}).status_code == 403
