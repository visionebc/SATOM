"""A change that leaves this product must not be able to lie about itself.

F4 wires a Change Request to systems SATOM does not own: an external change
authority (through a user hook, typically their CRM) and NetBox, which holds
the maintenance window. Three properties decide whether that wiring is safe,
and each one fails silently rather than loudly if it breaks:

1. **Fail-closed approval.** A CR routed through an external approver is
   runnable only when that approver said yes. Every other outcome - down,
   slow, ambiguous, never asked - must land on the un-runnable side. The
   tempting bug is the opposite default: treat "no answer" as "no objection",
   which turns an approval gate into a delay.

2. **The window's state is honest.** ``none`` (we never asked NetBox) and
   ``error`` (we asked and it refused) must stay distinguishable, or an
   integration outage reads as a deliberate decision not to use one - and the
   operator never learns NetBox still shows a device in maintenance.

3. **Nothing external re-grades the change.** NetBox down, a hook erroring,
   SMTP refusing: all recorded, none of them able to turn a completed upgrade
   into a failed one. An upgrade that worked worked whether or not a ticket
   system agreed to write it down.

Plus the timezone rule, which is the one that silently moves a window by hours:
SATOM stores naive UTC and NetBox reads ISO-8601. A naive string handed to
NetBox is interpreted in ITS local zone.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORCH_PATH = os.path.join(REPO, "app", "services", "cr_orchestrator.py")
CR_PATH = os.path.join(REPO, "app", "services", "change_requests.py")
SA_PATH = os.path.join(REPO, "app", "services", "scheduled_actions.py")


def _src(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _mk_cr(status="scheduled", *, window=True, **kw):
    from app.extensions import db
    from app.models import ChangeRequest

    now = datetime.utcnow()
    cr = ChangeRequest(
        title=kw.pop("title", "CR under orchestration"),
        reason=kw.pop("reason", "firmware 7.6.9"),
        status=status,
        action=kw.pop("action", "upgrade"),
        params=json.dumps(kw.pop("params", {})),
        device_ids=json.dumps(kw.pop("device_ids", [])),
        policies=json.dumps(kw.pop("policies", [])),
        window_start=(now - timedelta(minutes=5)) if window else None,
        window_end=(now + timedelta(minutes=55)) if window else None,
        **kw,
    )
    db.session.add(cr)
    db.session.commit()
    return cr


# --------------------------------------------------------------------------- #
#  1. Fail-closed external approval                                             #
# --------------------------------------------------------------------------- #
def test_manual_mode_passes_the_external_gate(app):
    """A CR that was never bound to an external authority must not be gated on
    one. Defaulting every existing CR to 'needs an approval nobody will give'
    would strand all of them."""
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr(approval_mode="manual")
        ok, reason = orch.external_gate(cr)
        assert ok, reason


def test_external_mode_without_a_stamp_is_not_runnable(app):
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr(approval_mode="external")
        ok, reason = orch.external_gate(cr)
        assert not ok
        assert "approval" in reason.lower()


def test_external_mode_with_a_stamp_is_runnable(app):
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr(approval_mode="external")
        orch.record_external_approval(cr, approved=True, by="crm")
        ok, _ = orch.external_gate(cr)
        assert ok


def test_unknown_approval_mode_fails_closed(app):
    """A typo in a config field must not silently downgrade the gate. The
    strict side is the only safe default for a value we cannot interpret."""
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr(approval_mode="externl")     # typo on purpose
        ok, reason = orch.external_gate(cr)
        assert not ok
        assert "externl" in reason


def test_withdrawn_approval_clears_the_stamp(app):
    """Approve then reject must return the CR to un-runnable. A stale timestamp
    would let a withdrawn approval still open a maintenance window."""
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr(approval_mode="external")
        orch.record_external_approval(cr, approved=True, by="crm")
        assert orch.external_gate(cr)[0]
        orch.record_external_approval(cr, approved=False, by="crm",
                                      detail="rejected by CAB")
        assert cr.external_approved_at is None
        assert not orch.external_gate(cr)[0]


def test_cr_runnable_consults_the_external_gate(app):
    """The gate is worthless if the executor's authorization check does not go
    through it. cr_runnable is the ONE function the executor calls."""
    from app.services import change_requests as crs
    with app.app_context():
        cr = _mk_cr(status="approved", approval_mode="external")
        ok, reason = crs.cr_runnable(cr)
        assert not ok, "an unapproved external CR must not be runnable"
        assert "approval" in reason.lower()


def test_cr_runnable_source_actually_calls_external_gate():
    """Structural guard: someone re-ordering cr_runnable must not be able to
    drop the call and still pass the behavioural test above by accident."""
    assert "external_gate" in _src(CR_PATH)


# --------------------------------------------------------------------------- #
#  2. Window state is honest                                                    #
# --------------------------------------------------------------------------- #
def test_window_is_not_opened_when_netbox_is_unconfigured(app, monkeypatch):
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr()
        monkeypatch.setattr(netbox, "is_configured", lambda: False)
        res = orch.open_window(cr)
        assert not res["ok"]
        assert cr.mw_state != "open"
        assert "netbox" in (cr.integration_log or "").lower()


def test_a_refused_window_is_error_not_none(app, monkeypatch):
    """'never asked' and 'asked and refused' are different facts. Collapsing
    them hides an integration outage behind a state that looks deliberate."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        monkeypatch.setattr(netbox, "open_window",
                            lambda *a, **k: {"ok": False, "detail": "connection refused"})
        orch.open_window(cr)
        assert cr.mw_state == "error"
        assert "refused" in (cr.integration_log or "")


def test_opening_an_already_open_window_is_a_noop(app, monkeypatch):
    """A retried fire must not litter NetBox with duplicate windows."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    calls = []
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        cr.mw_state = "open"
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        monkeypatch.setattr(netbox, "open_window",
                            lambda *a, **k: calls.append(1) or {"ok": True, "ref": "journal:1"})
        orch.open_window(cr)
        assert calls == [], "a second window was opened for the same CR"


def test_a_window_we_could_not_close_stays_error(app, monkeypatch):
    """NetBox still showing a device in maintenance is an operational fact the
    operator has to see; reporting 'closed' would bury it."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        cr.mw_state = "open"
        cr.mw_ref = "fw=journal:7"
        monkeypatch.setattr(netbox, "close_window",
                            lambda *a, **k: {"ok": False, "detail": "timeout"})
        orch.close_window(cr, ok=True)
        assert cr.mw_state == "error"


def test_close_window_is_called_with_the_change_outcome_not_its_own(app, monkeypatch):
    """A FAILED upgrade still closes its window - the window is over either way
    - but it must close carrying the failure, not as if the change landed."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    seen = {}
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        cr.mw_state = "open"
        cr.mw_ref = "fw=journal:7"

        def _close(ref, *, ok, summary):
            seen["ok"] = ok
            seen["summary"] = summary
            return {"ok": True, "detail": ""}

        monkeypatch.setattr(netbox, "close_window", _close)
        orch.close_window(cr, ok=False, summary="flash failed")
        assert seen["ok"] is False
        assert seen["summary"] == "flash failed"


# --------------------------------------------------------------------------- #
#  3. Nothing external re-grades the change                                     #
# --------------------------------------------------------------------------- #
def test_netbox_exploding_does_not_change_the_cr_outcome(app, monkeypatch):
    from app.services import change_requests as crs
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(status="in_progress", device_ids=[_an_appliance(app).id])

        def _boom(*a, **k):
            raise RuntimeError("netbox is on fire")

        monkeypatch.setattr(netbox, "close_window", _boom)
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        crs.finish(cr, "ok", summary="upgraded 7.6.9")
        assert cr.status == "completed", "an external failure re-graded the change"


def test_on_start_survives_a_raising_integration(app, monkeypatch):
    """A ticket system being down must never abort an upgrade the operator
    already approved and scheduled."""
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr()
        monkeypatch.setattr(orch, "open_window",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        orch.on_start(cr)          # must not raise
        assert "raised" in (cr.integration_log or "")


def test_finish_closes_the_window_before_notifying(app, monkeypatch):
    """Order matters: nobody may be told service is restored before the window
    covering the outage is closed."""
    from app.services import change_requests as crs
    from app.services import cr_orchestrator as orch
    order = []
    with app.app_context():
        cr = _mk_cr(status="in_progress")
        monkeypatch.setattr(orch, "close_window",
                            lambda *a, **k: order.append("close") or {"ok": True})
        monkeypatch.setattr(crs, "notify_outcome",
                            lambda *a, **k: order.append("notify") or {"sent": False})
        orch.on_finish(cr, "ok", summary="done")
        assert order == ["close", "notify"], order


def test_the_executor_no_longer_double_calls_notify_outcome():
    """finish() now owns the notice. Two callers of one step is how a product
    ends up with two implementations of it.

    Asserted on CODE, never on the file text: the comment that explains why the
    call was removed necessarily names it, so a substring check over the raw
    source fails against a perfectly correct file. (This is the tenth time that
    trap has been hit in this repo - hence the AST.)"""
    import ast

    tree = ast.parse(_src(SA_PATH))
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "notify_outcome" not in called, (
        "the executor calls notify_outcome again - finish() already does")
    assert "finish" in called, "the executor no longer closes the CR at all"


# --------------------------------------------------------------------------- #
#  4. Timezone: the failure that moves a window by hours                        #
# --------------------------------------------------------------------------- #
def test_window_times_carry_an_explicit_utc_offset():
    """SATOM stores naive UTC. A naive ISO string handed to NetBox is read in
    NetBox's local zone - the window silently shifts, and the upgrade runs
    outside the window it claims to be inside."""
    from app.services.cr_orchestrator import _iso
    out = _iso(datetime(2026, 8, 9, 22, 30, 0))
    assert out == "2026-08-09T22:30:00+00:00"
    assert re.search(r"[+-]\d\d:\d\d$", out), "no explicit offset"


def test_iso_of_none_is_none():
    """A CR without an end time must send null, never today's date."""
    from app.services.cr_orchestrator import _iso
    assert _iso(None) is None


def test_no_naive_isoformat_call_reaches_netbox():
    """Structural: the bare .isoformat() of a naive datetime is exactly the
    call this module exists to avoid."""
    src = _src(ORCH_PATH)
    body = re.sub(r"#.*", "", src)
    body = re.sub(r'""".*?"""', "", body, flags=re.S)
    assert ".isoformat()" not in body


# --------------------------------------------------------------------------- #
#  5. Bookkeeping                                                               #
# --------------------------------------------------------------------------- #
def test_mw_states_are_the_documented_four():
    from app.services.cr_orchestrator import MW_STATES
    assert set(MW_STATES) == {"none", "open", "closed", "error"}


def test_crq_reference_is_recorded_on_the_timeline(app):
    from app.models import ChangeRequestEvent
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr()
        orch.record_crq(cr, "CRQ-4711", "https://crm.example/CRQ-4711")
        assert cr.crq_ref == "CRQ-4711"
        kinds = [e.kind for e in ChangeRequestEvent.query.filter_by(cr_id=cr.id).all()]
        assert "crq_created" in kinds


def test_integration_log_is_capped(app):
    """An external system in a retry storm must not grow a TEXT column without
    bound."""
    from app.services import cr_orchestrator as orch
    with app.app_context():
        cr = _mk_cr()
        for i in range(400):
            orch._log(cr, f"line {i} " + "x" * 200)
        assert len(cr.integration_log or "") <= 8000


def test_importing_the_orchestrator_touches_nothing_external():
    """Import must not read the DB, contact NetBox or dispatch a hook - the
    module is imported by cr_runnable, which runs on every gate check."""
    src = _src(ORCH_PATH)
    head = src.split("def ", 1)[0]
    for forbidden in ("netbox_client", "integration_hooks", "requests.", "urlopen"):
        assert forbidden not in head, f"{forbidden} imported at module level"


def _an_appliance(app):
    """A minimal appliance row to target - devices are resolved by id."""
    from app.extensions import db
    from app.models import Appliance
    row = Appliance.query.first()
    if row is not None:
        return row
    row = Appliance(name="fortiweb-test", host="192.0.2.10",
                    username="admin", password_enc="x")
    db.session.add(row)
    db.session.commit()
    return row
