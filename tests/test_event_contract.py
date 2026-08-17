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

import ast
import pathlib

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


#: The catalogue module NAMES every event by definition -- counting it as an
#: emitter would make the coverage guard below true no matter what.
CATALOGUE = "integration_hooks.py"


def _dispatches(src: str) -> bool:
    """True for an actual dispatch CALL carrying an event, never for the word.

    Split out of :func:`_emitter_sources` so it can be exercised against
    sources that do not happen to exist in this tree. Two of its clauses were
    unexercised while it was inlined, and both read as tested: nothing under
    ``app/`` makes a zero-argument ``dispatch()`` call, and the catalogue
    module DEFINES ``dispatch`` rather than calling it. A guard whose only
    input is the live tree is answered by the tree, not by the rule.

    A plain text search would fail the other way: it is satisfied by
    hook_starters.py, whose entire job is to NAME events in starter bindings
    while emitting none of them.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:                                  # pragma: no cover
        return False
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "dispatch"
                and node.args):
            return True
    return False


def _emitter_sources(root=None) -> dict:
    """``{path: source}`` for every module that actually calls ``dispatch()``.

    DISCOVERED, never named. The previous version of the guard below read one
    module, because on the day it was written cr_orchestrator WAS every
    emitter there was. The alerting round then began dispatching
    ``alert.fired`` from alerts.py and the guard failed against perfectly
    correct code -- it was measuring the module, not the property.

    ``root`` exists only so the discovery itself can be tested against a tree
    built for the purpose.
    """
    root = root or pathlib.Path(__file__).resolve().parents[1] / "app"
    out = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in str(path) or path.name == CATALOGUE:
            continue
        src = path.read_text(encoding="utf-8")
        if "dispatch" not in src:
            continue
        if _dispatches(src):
            out[path] = src
    return out


#: ``hooks.dispatch("x.y", {})`` -- the shape every real emitter uses.
_REAL_CALL = 'def go(hooks):\n    hooks.dispatch("x.y", {})\n'


def test_defining_dispatch_is_not_dispatching():
    """The catalogue module's whole content is this shape."""
    assert not _dispatches(
        "def dispatch(event, payload, *, by='system'):\n    return 1\n")


def test_naming_an_event_is_not_dispatching():
    """hook_starters.py binds starter hooks TO events without emitting any."""
    assert not _dispatches('STARTERS = {"cr.approved": "run-the-thing"}\n')


def test_a_zero_argument_dispatch_is_not_an_emission():
    """``dispatch()`` with nothing to send names no event at all, so counting
    it would let a module claim coverage of every event in the catalogue."""
    assert not _dispatches("def go(hooks):\n    hooks.dispatch()\n")


def test_a_real_dispatch_call_is_an_emission():
    """The filter cannot be so strict that it finds nobody."""
    assert _dispatches(_REAL_CALL)


def test_the_catalogue_is_skipped_even_when_it_does_dispatch(tmp_path):
    """The skip is load-bearing, not decoration.

    Today the catalogue only defines ``dispatch``, so the AST filter alone
    would exclude it and the skip reads as redundant. The day it dispatches
    something itself -- a retry, a self-test -- it would start answering the
    coverage guard with the very list that guard is checking.
    """
    (tmp_path / CATALOGUE).write_text(_REAL_CALL, encoding="utf-8")
    (tmp_path / "real_emitter.py").write_text(_REAL_CALL, encoding="utf-8")

    found = {p.name for p in _emitter_sources(tmp_path)}

    assert found == {"real_emitter.py"}, found


def test_every_documented_event_has_an_emitter():
    """A documented event nobody emits is the 'state with no writer' defect in
    another costume: the editor offers it, an operator binds a hook to it, and
    the hook never runs."""
    from app.services.integration_hooks import EVENTS

    sources = _emitter_sources()
    assert sources, "found no module that dispatches an event at all"

    blob = "\n".join(sources.values())
    missing = [name for name in EVENTS if f'"{name}"' not in blob]
    assert not missing, (
        "documented but never emitted by any dispatching module: %s "
        "(emitters seen: %s)"
        % (missing, sorted(p.name for p in sources)))


def test_the_catalogue_module_is_not_counted_as_an_emitter():
    """Otherwise the guard above is answered by the documentation it checks."""
    assert CATALOGUE not in {p.name for p in _emitter_sources()}


def test_a_module_that_only_names_events_is_not_an_emitter():
    """hook_starters.py binds starter hooks TO events without emitting any.

    Counting it would make the coverage guard permanently green, which is
    exactly the failure the guard exists to prevent.
    """
    assert "hook_starters.py" not in {p.name for p in _emitter_sources()}


def test_the_emitter_set_is_discovered_not_named():
    """A hardcoded module list is how the guard broke the first time."""
    import inspect

    src = inspect.getsource(_emitter_sources)
    for hardcoded in ("cr_orchestrator", "alerts.py"):
        assert hardcoded not in src.split('"""')[2], \
            "_emitter_sources names a module: %s" % hardcoded
