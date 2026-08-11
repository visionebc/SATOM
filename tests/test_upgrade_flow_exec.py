"""Phases 2-4 of the bulk upgrade flow: the ticket that leaves, the execution
that can be watched, and the rollout that comes in waves.

Each section guards a defect of the SAME family as phase 1's: nothing raised,
nothing was logged, and the product simply asserted something narrower than the
truth.

1. **The external CRQ carried no evidence and no names.** ``request_crq`` sent
   ``device_ids`` — bare integers meaningless outside this database — plus a
   flat list of policy names. A change-management system received a request to
   take down "[17, 18, 19]" and the N baselines the whole bulk pre-upgrade
   exists to produce never left the product. On a sixty-box window the policy
   list was also tens of thousands of names in one webhook payload.

2. **A multi-target run was unobservable and its record was not durable.**
   Per-device outcomes lived as text lines accumulated in memory and committed
   ONCE, in the finally block. For four hours the console could only say
   ``running``; kill the worker at device 50 of 60 and fifty appliances had
   been changed with no record of which.

3. **Waves would have been a second implementation.** A batched rollout is N
   ordinary changes, and building it a private creation path is exactly the
   defect phase 1 removed — so ``create_change_request`` is the single author
   and this file proves the wave route goes through it.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from conftest import admin_user_id, login


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk_appliance(name, *, kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, host=f"10.0.0.{abs(hash(name)) % 200 + 20}",
                  port=443, kind=kind, username="admin", firmware="7.6.1")
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _mk_prep(appliance, *, ok=True, inventory=None):
    from app.extensions import db
    from app.models import UpgradePrep

    prep = UpgradePrep(
        appliance_id=appliance.id, created_by="operator", ok=ok,
        summary="backup ok, health ok", firmware="7.6.1",
        result=json.dumps({"firmware": "7.6.1",
                           "backup": {"ok": True, "name": f"{appliance.name}.conf"}}),
        inventory=json.dumps(inventory if inventory is not None else
                             [{"device": appliance.name,
                               "device_id": appliance.id, "policy": "shop"}]),
        created_at=datetime.utcnow())
    db.session.add(prep)
    db.session.commit()
    return prep


def _mk_cr(device_ids, *, status="draft", window=True, **kw):
    from app.extensions import db
    from app.models import ChangeRequest

    now = datetime.utcnow()
    cr = ChangeRequest(
        title="window", action="upgrade", status=status,
        device_ids=json.dumps(device_ids), ref="CR-2026-0001",
        window_start=(now - timedelta(minutes=1)) if window else None,
        window_end=(now + timedelta(hours=2)) if window else None, **kw)
    db.session.add(cr)
    db.session.commit()
    return cr


def _capture(monkeypatch):
    from app.services import integration_hooks as IH
    seen = []

    def _fake(event, payload, *, by="system", dry_run=False):
        seen.append((event, payload))
        return [{"slug": "spy", "request_id": "x", "status": "queued"}]

    monkeypatch.setattr(IH, "dispatch", _fake)
    return seen


# =========================================================================== #
#  2. The CRQ payload actually carries the window                              #
# =========================================================================== #
def test_the_ticket_names_every_appliance_not_just_its_id(app, monkeypatch):
    from app.services import cr_orchestrator as orch

    with app.app_context():
        a, b = _mk_appliance("crq-a"), _mk_appliance("crq-b")
        cr = _mk_cr([a.id, b.id])
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        _event, payload = seen[0]

        names = {d["appliance"] for d in payload["devices"]}
        assert names == {"crq-a", "crq-b"}, \
            "an external system cannot resolve a bare appliance id"
        assert payload["device_count"] == 2
        assert all(d.get("kind") and d.get("host") for d in payload["devices"])
        assert payload["cr_ref"] == "CR-2026-0001", \
            "the ticket and the signed document share no identifier"


def test_every_bound_run_travels_with_the_ticket(app, monkeypatch):
    """N devices, N baselines. One piece of evidence for a twenty-box window is
    the phase-1 defect wearing a webhook."""
    from app.services import cr_orchestrator as orch, prep_store

    with app.app_context():
        a, b = _mk_appliance("ev-a"), _mk_appliance("ev-b")
        cr = _mk_cr([a.id, b.id])
        prep_store.bind_many(cr, [_mk_prep(a), _mk_prep(b)])
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        _event, payload = seen[0]

        assert len(payload["evidence"]) == 2, \
            "the ticket carries fewer baselines than the change rests on"
        assert {e["appliance"] for e in payload["evidence"]} == {"ev-a", "ev-b"}
        assert payload["evidence_missing"] == []
        for entry in payload["evidence"]:
            assert entry["ok"] is True
            assert entry["backup"], "a rollback point that exists is not quoted"
            assert entry["prep_id"] and entry["at"]


def test_an_appliance_without_a_baseline_is_named_not_implied(app, monkeypatch):
    from app.services import cr_orchestrator as orch, prep_store

    with app.app_context():
        a, b = _mk_appliance("cov-a"), _mk_appliance("cov-b")
        cr = _mk_cr([a.id, b.id])
        prep_store.bind_many(cr, [_mk_prep(a)])
        seen = _capture(monkeypatch)
        result = orch.request_crq(cr, by="t")
        _event, payload = seen[0]

        assert payload["evidence_missing"] == ["cov-b"], \
            "a receiver counting list lengths cannot tell which box is bare"
        assert result["uncovered"] == ["cov-b"]


def test_the_evidence_carries_the_verdict_not_the_whole_probe_dump(app,
                                                                  monkeypatch):
    """Megabytes of per-service probe rows per appliance must not be shipped
    into somebody else's ticket system, which never asked for the fleet's
    service topology."""
    from app.services import cr_orchestrator as orch, prep_store

    with app.app_context():
        a = _mk_appliance("slim-a")
        cr = _mk_cr([a.id])
        prep_store.bind_many(cr, [_mk_prep(a)])
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        _event, payload = seen[0]

        entry = payload["evidence"][0]
        assert entry["services"] == 1, "the count of affected services is the fact"
        assert "result" not in entry and "inventory" not in entry, \
            "the stored blob leaked into the outbound payload"
        assert "probes" not in json.dumps(entry)


def test_a_huge_policy_list_is_capped_and_says_so(app, monkeypatch):
    """No silent caps. The exact total always travels; a receiver that reads a
    capped list and believes it is the whole outage under-states it by an order
    of magnitude."""
    from app.extensions import db
    from app.services import cr_orchestrator as orch

    with app.app_context():
        a = _mk_appliance("big-a")
        cr = _mk_cr([a.id])
        total = orch.MAX_POLICY_NAMES + 25
        cr.policies = json.dumps([{"device": "big-a", "policy": f"pol-{i}"}
                                  for i in range(total)])
        db.session.commit()
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        _event, payload = seen[0]

        assert len(payload["policies"]) == orch.MAX_POLICY_NAMES
        assert payload["policy_count"] == total, \
            "the true size of the outage did not travel"
        assert payload["policies_truncated"] is True


def test_the_ticket_says_who_holds_the_gate(app, monkeypatch):
    """A receiver never told it holds the approval will not send a verdict, and
    the window elapses with nobody aware they were waited on."""
    from app.services import cr_orchestrator as orch

    with app.app_context():
        a = _mk_appliance("gate-a")
        cr = _mk_cr([a.id], approval_mode="external")
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        assert seen[0][1]["approval_mode"] == "external"


def test_a_re_request_carries_the_existing_reference(app, monkeypatch):
    from app.services import cr_orchestrator as orch

    with app.app_context():
        a = _mk_appliance("dup-a")
        cr = _mk_cr([a.id], crq_ref="CRQ-9911")
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        assert seen[0][1]["crq_ref"] == "CRQ-9911", \
            "a double-clicked button opens a second ticket for one window"


def test_the_payload_still_honours_the_documented_contract(app, monkeypatch):
    """Every key the editor documents must actually be sent — the existing
    contract guard, re-asserted against the enriched payload."""
    from app.services import cr_orchestrator as orch
    from app.services.integration_hooks import EVENTS

    with app.app_context():
        a = _mk_appliance("contract-a")
        cr = _mk_cr([a.id])
        seen = _capture(monkeypatch)
        orch.request_crq(cr, by="t")
        documented = {k for k, desc in EVENTS["change.requested"]["payload"].items()
                      if "optional" not in str(desc).lower()}
        missing = documented - set(seen[0][1])
        assert not missing, f"documented but never sent: {sorted(missing)}"
        undocumented = set(seen[0][1]) - set(EVENTS["change.requested"]["payload"])
        assert not undocumented, \
            f"sent but never documented: {sorted(undocumented)}"


def test_coverage_has_one_author(app):
    """The console, the ticket and the flash message must not each decide
    separately which appliances have a baseline."""
    import inspect

    from app.services import cr_orchestrator as orch

    src = inspect.getsource(orch._evidence_rows)
    body = "\n".join(line for line in src.splitlines()
                     if not line.strip().startswith("#"))
    assert "prep_store.coverage" in body, \
        "the orchestrator recomputes coverage instead of asking prep_store"


# =========================================================================== #
#  3. Execution is observable while it runs, and durable if it dies            #
# =========================================================================== #
def _spec_and_action(app_ctx_names):
    from app.extensions import db
    from app.models import ScheduledAction

    action = ScheduledAction(
        name="win", scope="admin", action="upgrade_prep",
        targets=json.dumps(app_ctx_names), params=json.dumps({}),
        schedule_kind="once", schedule=json.dumps({}), enabled=True,
        created_by="t")
    db.session.add(action)
    db.session.commit()
    return action


def test_progress_is_written_before_the_device_is_touched(app, monkeypatch):
    """The row exists WHILE the device is being worked on. A log assembled in
    memory and committed at the end leaves four hours in which the only
    available answer to 'how far along is it?' is a shrug."""
    from app.extensions import db
    from app.models import ScheduledActionTarget
    from app.services import scheduled_actions as sa

    with app.app_context():
        a, b = _mk_appliance("prog-a"), _mk_appliance("prog-b")
        action = _spec_and_action([a.id, b.id])
        run = _open_run(action)
        seen_mid = {}

        def _fake_run(spec, appliance, params, dry_run=False):
            # Mid-flight: the row for THIS device must already be visible to a
            # separate reader, which is the whole point.
            seen_mid[appliance.name] = [
                (r.appliance, r.status) for r in
                ScheduledActionTarget.query.filter_by(run_id=run.id).all()]
            return {"ok": True, "summary": f"{appliance.name} done"}

        monkeypatch.setattr(sa, "run_action", _fake_run)
        status, summary, _lines = sa._run_targets(
            action, sa.get_spec("upgrade_prep"), {}, trigger="manual", run=run)

        assert status == "ok"
        assert ("prog-a", "running") in seen_mid["prog-a"], \
            "the device being worked on had no progress row while it ran"
        rows = {r.appliance: r for r in
                ScheduledActionTarget.query.filter_by(run_id=run.id).all()}
        assert set(rows) == {"prog-a", "prog-b"}
        assert all(r.status == "ok" for r in rows.values())
        assert all(r.finished_at is not None for r in rows.values())
        assert rows["prog-a"].total == 2 and rows["prog-a"].seq in (1, 2)
        db.session.remove()


def test_a_failed_device_is_recorded_as_failed_and_the_sweep_continues(app,
                                                                      monkeypatch):
    from app.extensions import db
    from app.models import ScheduledActionTarget
    from app.services import scheduled_actions as sa

    with app.app_context():
        a, b = _mk_appliance("fail-a"), _mk_appliance("fail-b")
        action = _spec_and_action([a.id, b.id])
        run = _open_run(action)
        monkeypatch.setattr(sa, "run_action", lambda spec, appliance, params,
                            dry_run=False: {"ok": appliance.name != "fail-a",
                                            "summary": "boom"})
        sa._run_targets(action, sa.get_spec("upgrade_prep"), {},
                        trigger="manual", run=run)
        rows = {r.appliance: r.status for r in
                ScheduledActionTarget.query.filter_by(run_id=run.id).all()}
        assert rows == {"fail-a": "failed", "fail-b": "ok"}, \
            "one dead box either stopped the sweep or vanished from the record"
        db.session.remove()


def test_recording_progress_never_aborts_the_change(app, monkeypatch):
    """Bookkeeping has no veto over work already touching production.

    The failure is injected into the MODEL, not into ``_progress_open``, so the
    ``except`` under test is the shipped one. An earlier version of this test
    monkeypatched ``_progress_open`` itself to raise and asserted the raise —
    which tested the monkeypatch, and let a mutation turning that ``except`` into
    a bare ``raise`` survive untouched.
    """
    import app.models as models
    from app.extensions import db
    from app.services import scheduled_actions as sa

    with app.app_context():
        a = _mk_appliance("veto-a")
        action = _spec_and_action([a.id])
        run = _open_run(action)
        monkeypatch.setattr(sa, "run_action", lambda *args, **kw:
                            {"ok": True, "summary": "changed"})

        def _broken(*_a, **_k):
            raise RuntimeError("progress table gone")

        # _progress_open imports the model at call time, so patching it here is
        # what the shipped code will actually reach for.
        monkeypatch.setattr(models, "ScheduledActionTarget", _broken)
        status, _summary, lines = sa._run_targets(
            action, sa.get_spec("upgrade_prep"), {}, trigger="manual", run=run)

        assert status == "ok", \
            "a progress row that would not insert aborted the change it describes"
        assert any("veto-a" in line for line in lines), \
            "the work did not happen at all"
        db.session.remove()


def test_a_run_that_ends_still_stamps_every_device_it_reached(app, monkeypatch):
    """The close is the other half: an open row that is never updated makes a
    finished device read as interrupted."""
    from app.extensions import db
    from app.models import ScheduledActionTarget
    from app.services import scheduled_actions as sa

    with app.app_context():
        a = _mk_appliance("close-a")
        action = _spec_and_action([a.id])
        run = _open_run(action)
        monkeypatch.setattr(sa, "run_action", lambda *args, **kw:
                            {"ok": True, "summary": "changed"})
        sa._run_targets(action, sa.get_spec("upgrade_prep"), {},
                        trigger="manual", run=run)
        row = ScheduledActionTarget.query.filter_by(run_id=run.id).one()
        assert row.status == "ok" and row.finished_at is not None
        assert row.elapsed_ms is not None, \
            "a finished device reports no duration"
        db.session.remove()


def test_a_device_the_run_never_reported_is_not_graded_failed(app, monkeypatch):
    """The worker died mid-window. Nobody observed the device, and asserting an
    outcome nobody measured is how a box that upgraded fine gets rolled back."""
    from app.extensions import db
    from app.models import ScheduledActionTarget
    from app.views import upgrade_flow as uf

    with app.app_context():
        a, b = _mk_appliance("int-a"), _mk_appliance("int-b")
        cr = _mk_cr([a.id, b.id])
        action = _spec_and_action([a.id, b.id])
        cr.scheduled_action_id = action.id
        db.session.commit()
        run = _open_run(action)
        db.session.add(ScheduledActionTarget(
            run_id=run.id, appliance_id=a.id, appliance="int-a", seq=1, total=2,
            status="running", started_at=datetime.utcnow()))
        run.status = "failed"
        db.session.commit()

        state = uf.execution_state(cr)
        by_name = {t["appliance"]: t["status"] for t in state["targets"]}
        assert by_name["int-a"] == "interrupted", \
            "a device that never reported was graded as an outcome"
        assert by_name["int-b"] == "not_run", \
            "'never reached' and 'never reported' are different facts"
        db.session.remove()


def test_pending_devices_are_listed_from_the_change_not_the_run(app):
    """A window over twenty boxes that has reached the third one must show
    seventeen pending rows; listing only what the run touched renders 15% done
    as complete."""
    from app.extensions import db
    from app.views import upgrade_flow as uf

    with app.app_context():
        devices = [_mk_appliance(f"pend-{i}") for i in range(4)]
        cr = _mk_cr([d.id for d in devices])
        action = _spec_and_action([d.id for d in devices])
        cr.scheduled_action_id = action.id
        db.session.commit()
        run = _open_run(action)
        from app.models import ScheduledActionTarget
        db.session.add(ScheduledActionTarget(
            run_id=run.id, appliance_id=devices[0].id, appliance="pend-0",
            seq=1, total=4, status="ok", started_at=datetime.utcnow(),
            finished_at=datetime.utcnow()))
        db.session.commit()

        state = uf.execution_state(cr)
        assert state["total"] == 4 and state["done"] == 1
        assert state["percent"] == 25, "progress was measured against the wrong set"
        assert sum(1 for t in state["targets"] if t["status"] == "pending") == 3
        db.session.remove()


def test_start_now_refuses_outside_the_window(app, client):
    """The button brings the fire forward; it does not replace the authorization."""
    from app.extensions import db

    with app.app_context():
        a = _mk_appliance("early-a")
        cr = _mk_cr([a.id], status="approved")
        cr.window_start = datetime.utcnow() + timedelta(days=1)
        cr.window_end = cr.window_start + timedelta(hours=2)
        action = _spec_and_action([a.id])
        cr.scheduled_action_id = action.id
        action.next_run = None
        db.session.commit()
        cr_id, action_id = cr.id, action.id

    login(client, admin_user_id(app))
    resp = client.post(f"/web/upgrade-flow/change/{cr_id}/start", data={},
                       follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        from app.models import ScheduledAction
        assert db.session.get(ScheduledAction, action_id).next_run is None, \
            "a change outside its window was brought forward anyway"


# =========================================================================== #
#  4. Waves are ordinary changes                                               #
# =========================================================================== #
def test_waves_chunk_in_order_and_never_drop_a_device():
    from app.views.upgrade_flow import split_waves

    groups = split_waves(list(range(7)), 3)
    assert groups == [[0, 1, 2], [3, 4, 5], [6]]
    assert sum(len(g) for g in groups) == 7, "a wave lost an appliance"
    assert split_waves([1, 2], 0) == [[1], [2]], \
        "a nonsense wave size silently produced zero waves"


def test_wave_windows_never_overlap():
    """Wave k+1 starts at wave k's END plus the gap. Deriving each start from
    the first one gives the same answer only until somebody edits a window."""
    from app.views.upgrade_flow import wave_windows

    start = datetime(2026, 8, 15, 22, 0)
    windows = wave_windows(start, 3, 120, 30)
    assert windows[0] == (start, start + timedelta(hours=2))
    for (_s1, e1), (s2, _e2) in zip(windows, windows[1:]):
        assert s2 >= e1, "two waves share a window"
        assert s2 == e1 + timedelta(minutes=30)


def test_a_wave_plan_with_no_window_invents_none():
    from app.views.upgrade_flow import wave_windows

    assert wave_windows(None, 3, 120, 30) == [(None, None)] * 3, \
        "a time nobody chose was written onto a change"


def test_waves_go_through_the_single_change_creation_path(app):
    """A batched rollout must not grow a private creation path — that is the
    two-implementations defect this whole feature removed."""
    import inspect

    from app.views import upgrade_flow as uf

    src = inspect.getsource(uf.waves)
    body = "\n".join(line for line in src.splitlines()
                     if not line.strip().startswith("#"))
    assert "create_change_request" in body, \
        "the wave route builds change requests by itself"
    assert "ChangeRequest(" not in body, \
        "the wave route constructs the model directly"


def test_a_wave_rollout_creates_one_change_per_wave(app, client):
    from app.extensions import db
    from app.models import ChangeRequest

    with app.app_context():
        devices = [_mk_appliance(f"wv-{i}") for i in range(5)]
        ids = [d.id for d in devices]
        preps = {d.id: _mk_prep(d).id for d in devices}
        before = ChangeRequest.query.count()

    login(client, admin_user_id(app))
    resp = client.post("/web/upgrade-flow/waves", data={
        "title": "Fleet 7.6.2", "wave_size": "2",
        "window_start": "2026-09-01T22:00", "wave_minutes": "60",
        "wave_gap": "15",
        "device_ids": [str(i) for i in ids],
        "prep_pairs": [f"{i}:{preps[i]}" for i in ids],
    }, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        made = (ChangeRequest.query
                .filter(ChangeRequest.wave_group.isnot(None),
                        ChangeRequest.wave_group != "")
                .order_by(ChangeRequest.wave_index).all())
        assert ChangeRequest.query.count() == before + 3, \
            "5 appliances at 2 per wave is 3 changes"
        assert [c.wave_index for c in made] == [1, 2, 3]
        assert {c.wave_total for c in made} == {3}
        assert len({c.wave_group for c in made}) == 1, \
            "the waves of one rollout are not linked to each other"
        assert [len(c.device_ids_list) for c in made] == [2, 2, 1]
        # Each wave cites ONLY its own members' evidence.
        from app.services import prep_store
        for change in made:
            bound = prep_store.preps_for_cr(change)
            assert {p.appliance_id for p in bound} == set(change.device_ids_list), \
                "a wave carries evidence about a box it does not touch"
        # Consecutive, non-overlapping windows.
        starts = [c.window_start for c in made]
        assert starts == sorted(starts) and len(set(starts)) == 3


def test_too_many_waves_is_refused_by_the_number_not_truncated(app, client):
    from app.models import ChangeRequest
    from app.views.upgrade_flow import MAX_WAVES

    with app.app_context():
        ids = [_mk_appliance(f"many-{i}").id for i in range(MAX_WAVES + 1)]
        before = ChangeRequest.query.count()

    login(client, admin_user_id(app))
    resp = client.post("/web/upgrade-flow/waves", data={
        "title": "too many", "wave_size": "1",
        "device_ids": [str(i) for i in ids],
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert str(MAX_WAVES) in resp.get_data(as_text=True)
    with app.app_context():
        assert ChangeRequest.query.count() == before, \
            "a refused wave plan created changes anyway"


# --------------------------------------------------------------------------- #
def _open_run(action):
    from app.extensions import db
    from app.models import ScheduledActionRun

    run = ScheduledActionRun(action_id=action.id, status="running",
                             trigger="manual", started_at=datetime.utcnow(),
                             summary="", log="")
    db.session.add(run)
    db.session.commit()
    return run
