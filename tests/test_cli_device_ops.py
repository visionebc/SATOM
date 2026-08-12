"""Guards for addressing a destructive appliance action BY DEVICE NAME.

Why these exist:

* ``device_ops.select_action`` sits in front of the only two verbs that can
  stop an appliance serving. Every branch in it is a REFUSAL, and a refusal
  that silently stops refusing looks exactly like a refusal that still works —
  right up to the moment a box reboots that nobody approved.
* ``select_action`` must never execute. The whole reason the CLI is allowed to
  address a reboot at all is that it only ever picks an id and hands it to
  ``execute_and_record``, which re-runs the change-request gate. A selector
  that grew a device call would be a second implementation of one
  authorization boundary.
* The ``upgrade`` spec spent its whole life ASSERTING (in its own summary, and
  in ``_do_upgrade``'s docstring) an authorization it never declared. Nothing
  failed, because prose does not run.
"""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "deploy"))

from satom_cli import tree as cli_tree  # noqa: E402


# --------------------------------------------------------------------------- #
#  Fixtures                                                                     #
# --------------------------------------------------------------------------- #
def _mk_appliance(name="fw-dev", kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, kind=kind, host="192.0.2.99", port=443,
                  username="admin", verify_ssl=False)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _mk_cr(status="approved", window=True, **kw):
    from app.extensions import db
    from app.models import ChangeRequest

    now = datetime.utcnow()
    cr = ChangeRequest(
        title="w", action="reboot", status=status, device_ids="[]",
        ref="CR-TEST-1",
        window_start=(now - timedelta(minutes=1)) if window else None,
        window_end=(now + timedelta(hours=2)) if window else None, **kw)
    db.session.add(cr)
    db.session.commit()
    return cr


def _mk_action(action="reboot", targets=(), cr_id=None, name="nightly"):
    from app.extensions import db
    from app.models import ScheduledAction

    params = {} if cr_id is None else {"change_request_id": cr_id}
    row = ScheduledAction(
        name=name, action=action, enabled=True, schedule_kind="once",
        schedule=json.dumps({}), targets=json.dumps(list(targets)),
        params=json.dumps(params))
    db.session.add(row)
    db.session.commit()
    return row


def _reasons(res):
    return " | ".join(r[2] for r in res.get("rejected", []))


# --------------------------------------------------------------------------- #
#  1. The registry: privilege and blast radius are declared, not implied        #
# --------------------------------------------------------------------------- #
def _node(*path):
    node = cli_tree.ROOT
    for part in path:
        assert part in node.children, "missing CLI node: %s" % " ".join(path)
        node = node.children[part]
    return node


def test_reading_a_devices_config_never_requires_root():
    """The read has to work for the operator who is not root yet.

    It answers from the LOCAL store, so it is also the read that still works
    with the appliance unreachable — which is when it is reached for.
    """
    assert _node("get", "device", "config").run is not None
    assert _node("get", "device", "config").needs_root is False


@pytest.mark.parametrize("op", ["reboot", "upgrade"])
def test_device_verbs_are_root_only_and_flagged_dangerous(op):
    node = _node("execute", "device", op)
    assert node.run is not None
    assert node.needs_root is True, "%s must not run unprivileged" % op
    assert node.danger is True, "%s is destructive and must be flagged" % op
    assert "--yes" in node.usage, "%s must demand explicit confirmation" % op


def test_the_confirmation_flag_is_enforced_before_the_app_is_touched(monkeypatch):
    """No --yes must cost nothing: no DB, no app import, no device."""
    from satom_cli import cmd_fix
    from satom_cli.context import Ctx

    def _explode(*a, **kw):
        raise AssertionError("the app was contacted without --yes")

    monkeypatch.setattr(cmd_fix, "_app_stdin", _explode)
    ctx = Ctx()
    res = cmd_fix.device_reboot(ctx, ["fw-dev"])
    assert res.status == "bad"
    assert "--yes" in json.dumps([s for s in res.sections], default=str)


# --------------------------------------------------------------------------- #
#  2. The spec rule the 'upgrade' flag was missing                              #
# --------------------------------------------------------------------------- #
def test_every_fixed_date_destructive_action_declares_the_cr_requirement():
    """danger + a schedule forced to 'once' IS the maintenance-window shape.

    Pinning the RULE rather than the word 'upgrade' is the point: the next
    destructive fixed-date action arrives gated instead of arriving free. That
    is the exact hole through which upgrade_prep once shipped ungated while the
    gate watched only 'upgrade'.
    """
    from app.services import scheduled_actions as sa

    ungated = [s.key for s in sa.ALL_ACTIONS.values()
               if s.danger and s.forced_schedule_kind == "once"
               and not s.requires_change_request]
    assert not ungated, (
        "these actions are destructive, pinned to a fixed date, and can run "
        "with no approved change request: %s" % ungated)


def test_the_gate_reads_the_spec_flag_and_refuses_an_unbound_run(app):
    """Behaviour, not the flag: an unbound destructive action must be skipped.

    Asserting only that the field is True would survive someone deleting the
    check that reads it.
    """
    from app.services import scheduled_actions as sa

    with app.app_context():
        dev = _mk_appliance()
        row = _mk_action(action="upgrade", targets=[dev.id], cr_id=None)
        run = sa.execute_and_record(row, trigger="manual")
        assert run.status == "skipped", run.summary
        assert "change request" in (run.summary or "").lower(), run.summary


# --------------------------------------------------------------------------- #
#  3. select_action refuses, and says which rule refused                        #
# --------------------------------------------------------------------------- #
def test_an_unknown_device_is_named_not_guessed(app):
    from app.services import device_ops

    with app.app_context():
        res = device_ops.select_action("nope", "reboot")
        assert "nope" in res["error"]
        assert "action_id" not in res


def test_an_unverified_product_is_refused_by_name(app):
    """A reboot URN is per product and is never guessed.

    On FortiWeb the neighbouring maintenance op reboots the box even on GET, so
    'try it and see' is not a diagnostic — it is the outage.
    """
    from app.services import device_ops

    with app.app_context():
        _mk_appliance("fac-1", kind="fortiauthenticator")
        res = device_ops.select_action("fac-1", "upgrade")
        assert "action_id" not in res
        assert "fortiweb" in res["error"], res
        assert "fortiauthenticator" in res["error"], res


def test_no_action_at_all_is_a_refusal_with_an_empty_docket(app):
    from app.services import device_ops

    with app.app_context():
        _mk_appliance()
        res = device_ops.select_action("fw-dev", "reboot")
        assert res["refused"] is True
        assert res["runnable"] == [] and res["rejected"] == []


def test_an_action_bound_to_nothing_is_rejected(app):
    from app.services import device_ops

    with app.app_context():
        dev = _mk_appliance()
        _mk_action(targets=[dev.id], cr_id=None)
        res = device_ops.select_action("fw-dev", "reboot")
        assert "action_id" not in res
        assert "not bound to a change request" in _reasons(res)


def test_a_fleet_wide_action_is_never_narrowed_to_one_device(app):
    """Empty targets means EVERY appliance of those kinds.

    Firing it to satisfy 'reboot ONE device' would reboot the fleet; narrowing
    it here would make this module, not the recorded row, decide what an action
    targeted — and the row is what an auditor reads afterwards.
    """
    from app.services import device_ops

    with app.app_context():
        _mk_appliance()
        cr = _mk_cr()
        _mk_action(targets=[], cr_id=cr.id)
        res = device_ops.select_action("fw-dev", "reboot")
        assert "action_id" not in res
        assert "WHOLE fleet" in _reasons(res)


def test_an_action_that_also_hits_other_devices_is_rejected(app):
    from app.services import device_ops

    with app.app_context():
        dev, other = _mk_appliance("fw-a"), _mk_appliance("fw-b")
        cr = _mk_cr()
        _mk_action(targets=[dev.id, other.id], cr_id=cr.id)
        res = device_ops.select_action("fw-a", "reboot")
        assert "action_id" not in res
        assert "also targets 1 other device" in _reasons(res)


@pytest.mark.parametrize("kw,fragment", [
    (dict(status="draft"), "not approved"),
    (dict(status="cancelled"), "cancelled"),
    (dict(status="approved", window=False), "no maintenance window"),
])
def test_the_change_request_state_is_carried_into_the_refusal(app, kw, fragment):
    """The operator must be able to tell these apart at 03:00."""
    from app.services import device_ops

    with app.app_context():
        dev = _mk_appliance()
        cr = _mk_cr(**kw)
        _mk_action(targets=[dev.id], cr_id=cr.id)
        res = device_ops.select_action("fw-dev", "reboot")
        assert "action_id" not in res
        assert fragment in _reasons(res).lower(), _reasons(res)


def test_a_closed_window_refuses_even_though_the_cr_is_approved(app):
    from app.extensions import db
    from app.services import device_ops

    with app.app_context():
        dev = _mk_appliance()
        cr = _mk_cr()
        cr.window_start = datetime.utcnow() - timedelta(hours=4)
        cr.window_end = datetime.utcnow() - timedelta(hours=2)
        db.session.commit()
        _mk_action(targets=[dev.id], cr_id=cr.id)
        res = device_ops.select_action("fw-dev", "reboot")
        assert "action_id" not in res
        assert "after the maintenance window" in _reasons(res)


def test_two_runnable_actions_are_never_silently_disambiguated(app):
    """Picking 'the first' would make which box reboots depend on row order."""
    from app.services import device_ops

    with app.app_context():
        dev = _mk_appliance()
        cr = _mk_cr()
        _mk_action(targets=[dev.id], cr_id=cr.id, name="one")
        _mk_action(targets=[dev.id], cr_id=cr.id, name="two")
        res = device_ops.select_action("fw-dev", "reboot")
        assert "action_id" not in res
        assert len(res["runnable"]) == 2


# --------------------------------------------------------------------------- #
#  4. The one path that says yes — and what it must NOT do                      #
# --------------------------------------------------------------------------- #
def test_an_approved_action_inside_its_window_resolves_to_one_id(app):
    from app.services import device_ops

    with app.app_context():
        dev = _mk_appliance()
        cr = _mk_cr()
        row = _mk_action(targets=[dev.id], cr_id=cr.id)
        res = device_ops.select_action("fw-dev", "reboot")
        assert res["action_id"] == row.id
        assert res["cr"] == cr.id
        assert res["device"] == "fw-dev"


def test_selecting_never_runs_anything(app, monkeypatch):
    """The selector must stay a selector.

    The gate that authorizes a reboot lives in execute_and_record. If selection
    ever executed, that gate would have a second, weaker implementation in
    front of it — and the weaker of two implementations is the one that becomes
    the real one.
    """
    from app.services import device_ops
    from app.services import scheduled_actions as sa

    def _explode(*a, **kw):
        raise AssertionError("select_action executed an action")

    monkeypatch.setattr(sa, "execute_and_record", _explode)
    monkeypatch.setattr(sa, "run_action", _explode)

    with app.app_context():
        dev = _mk_appliance()
        cr = _mk_cr()
        _mk_action(targets=[dev.id], cr_id=cr.id)
        assert device_ops.select_action("fw-dev", "reboot")["action_id"]


# --------------------------------------------------------------------------- #
#  5. Reading a config: resolving a name must never resolve to the wrong thing  #
# --------------------------------------------------------------------------- #
def test_an_ambiguous_section_name_is_refused_not_picked():
    """Two sections start with 'Net'. Choosing one silently would print a
    different section under the heading the operator asked for."""
    from satom_cli.cmd_ops import _sot_match

    keys = ["Network", "Network Security", "System"]
    assert _sot_match(keys, "System")[0] == "System"          # exact
    assert _sot_match(keys, "sys")[0] == "System"             # unique prefix
    assert _sot_match(keys, "network")[0] == "Network"        # exact beats prefix
    key, err = _sot_match(keys, "Net")
    assert key is None and "ambiguous" in err, (key, err)


def test_a_version_id_belonging_to_another_device_is_refused():
    """'--version 42' addresses the store globally, but the heading says the
    device the operator typed. Rendering fortiadc02's config under
    'fortiweb08 — stored configuration' is a config confusion at 03:00."""
    from satom_cli.cmd_ops import _sot_pick

    rows = [["9", "fortiweb08", "aa", "1", "2", "3", "harvest", "t", "t"],
            ["8", "fortiweb08", "bb", "1", "2", "3", "harvest", "t", "t"],
            ["7", "fortiadc02", "cc", "1", "2", "3", "harvest", "t", "t"]]
    assert _sot_pick(rows, "fortiweb08", None)[0][0] == "9"   # newest wins
    row, err = _sot_pick(rows, "fortiweb08", 7)
    assert row is None and "fortiadc02" in err, (row, err)
    row, err = _sot_pick(rows, "nosuch", None)
    assert row is None and "no stored configuration" in err
