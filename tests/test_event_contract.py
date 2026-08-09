"""What the orchestrator emits must be what the event contract promises.

A hook is written by reading the payload documentation in the editor. If the
emitter sends a different key set, the hook does not crash — it reads `None` and
opens a ticket with an empty title, or skips a device list it thinks is empty.
Nothing fails. The integration is just quietly wrong, which is the failure mode
this whole subsystem is prone to.

Caught for real: `upgrade.finished` documented `to_version` and `duration_ms`,
and the change-request close cannot know either — only the firmware executor
watched the box come back. The fix was NOT to send nulls (a null there is a
measurement nobody took, the same rule as advisor token counts) but to mark
those two keys optional in the contract. This guard is what keeps that honest:
every key NOT marked optional must actually be emitted.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest


def _required_keys(event: str) -> set[str]:
    from app.services.integration_hooks import EVENTS
    payload = EVENTS[event]["payload"]
    return {k for k, desc in payload.items()
            if "optional" not in str(desc).lower()}


def _capture(monkeypatch):
    """Record every dispatch instead of queueing it."""
    from app.services import integration_hooks as IH
    seen = []

    def _fake(event, payload, *, by="system", dry_run=False):
        seen.append((event, payload))
        return [{"slug": "spy", "request_id": "x", "status": "queued"}]

    monkeypatch.setattr(IH, "dispatch", _fake)
    return seen


def _cr(**kw):
    from app.extensions import db
    from app.models import Appliance, ChangeRequest

    dev = Appliance.query.first()
    if dev is None:
        dev = Appliance(name="fw-contract", host="192.0.2.11",
                        username="admin", password_enc="x")
        db.session.add(dev)
        db.session.commit()
    now = datetime.utcnow()
    cr = ChangeRequest(
        title="contract", reason="r", status=kw.pop("status", "in_progress"),
        action="upgrade", params=json.dumps({"image": "img.out"}),
        device_ids=json.dumps([dev.id]),
        policies=json.dumps([{"device": dev.name, "policy": "pol-a"}]),
        window_start=now - timedelta(minutes=1),
        window_end=now + timedelta(minutes=30), **kw)
    db.session.add(cr)
    db.session.commit()
    return cr


def test_change_requested_emits_every_required_key(app, monkeypatch):
    from app.services import cr_orchestrator as orch
    with app.app_context():
        seen = _capture(monkeypatch)
        orch.request_crq(_cr(status="draft"), by="t")
        event, payload = seen[0]
        assert event == "change.requested"
        missing = _required_keys(event) - set(payload)
        assert not missing, f"documented but never sent: {sorted(missing)}"


def test_window_events_emit_every_required_key(app, monkeypatch):
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _cr()
        seen = _capture(monkeypatch)
        orch._dispatch_quiet("window.opening", cr, by="t",
                             extra={"action": cr.action, "policies": []})
        orch._dispatch_quiet("window.closing", cr, by="t",
                             extra={"outcome": "ok", "result_summary": "s"})
        for event, payload in seen:
            missing = _required_keys(event) - set(payload)
            assert not missing, f"{event}: documented but never sent {sorted(missing)}"


@pytest.mark.parametrize("ok,event", [(True, "upgrade.finished"),
                                      (False, "upgrade.failed")])
def test_upgrade_events_emit_every_required_key(app, monkeypatch, ok, event):
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _cr()
        seen = _capture(monkeypatch)
        orch._dispatch_per_device(cr, ok=ok, summary="why", by="t")
        assert seen, "no per-device event emitted"
        for ev, payload in seen:
            assert ev == event
            missing = _required_keys(ev) - set(payload)
            assert not missing, f"{ev}: documented but never sent {sorted(missing)}"


def test_optional_keys_are_absent_rather_than_null(app, monkeypatch):
    """The point of marking them optional: they are OMITTED. A null would claim
    a measurement was taken and came back empty."""
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _cr()
        seen = _capture(monkeypatch)
        orch._dispatch_per_device(cr, ok=True, summary="", by="t")
        _, payload = seen[0]
        assert "to_version" not in payload
        assert "duration_ms" not in payload


def test_upgrade_events_are_emitted_per_appliance(app, monkeypatch):
    """The contract keys them on a single appliance, so one event per device -
    not one event carrying a list, which no hook written from these docs could
    read."""
    from app.extensions import db
    from app.models import Appliance
    from app.services import cr_orchestrator as orch
    import json as _json
    with app.app_context():
        # TWO appliances, created explicitly: _cr() reuses whatever row exists,
        # so seeding one first and asking for "the first two" quietly yields one
        # - the test would then pass its own bug rather than the code's.
        for name, host in (("fw-contract-a", "192.0.2.12"),
                           ("fw-contract-b", "192.0.2.13")):
            if not Appliance.query.filter_by(name=name).first():
                db.session.add(Appliance(name=name, host=host,
                                         username="admin", password_enc="x"))
        db.session.commit()
        ids = [a.id for a in Appliance.query.filter(
            Appliance.name.in_(["fw-contract-a", "fw-contract-b"])).all()]
        assert len(ids) == 2
        cr = _cr()
        cr.device_ids = _json.dumps(ids)
        db.session.commit()
        seen = _capture(monkeypatch)
        orch._dispatch_per_device(cr, ok=True, summary="", by="t")
        assert len(seen) == 2, f"expected one event per appliance, got {len(seen)}"
        assert len({p["appliance_id"] for _, p in seen}) == 2


def test_every_documented_event_has_an_emitter():
    """A documented event nobody emits is the 'state with no writer' defect in
    another costume: the editor offers it, an operator binds a hook to it, and
    the hook never runs."""
    import inspect

    from app.services import cr_orchestrator as orch
    from app.services.integration_hooks import EVENTS

    src = inspect.getsource(orch)
    for name in EVENTS:
        assert f'"{name}"' in src, f"{name} is documented but never emitted"
