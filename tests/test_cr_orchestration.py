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


def test_a_refusal_that_never_reached_netbox_is_not_a_window_error(app, monkeypatch):
    """The case the honesty rule at the top of this file did not enumerate.

    Besides "never asked" and "asked and refused" there is a third: we never
    asked BECAUSE a LOCAL precondition failed - the appliance is not mapped to
    a NetBox device, the integration is switched off, the window times are
    unusable. Zero bytes leave this process, so NetBox cannot be showing a
    device in maintenance - and the CR page renders ``error`` as exactly that
    claim. This case belongs on the "never asked" side, with ``none``.
    """
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        cr.mw_state = "none"
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        monkeypatch.setattr(netbox, "open_window", lambda *a, **k: {
            "ok": False, "sent": False,
            "detail": "SATOM appliance 32 is not mapped to a NetBox device."})
        res = orch.open_window(cr)
        assert res["ok"] is False
        assert cr.mw_state != "error", (
            "a refusal that never left SATOM was recorded as a NetBox error, "
            "which states on the CR page that a device may be in maintenance "
            "in the customer's NetBox")
        assert "not mapped" in res["detail"]


def test_a_local_refusal_does_not_wipe_the_handle_of_an_earlier_window(app, monkeypatch):
    """``mw_ref`` is the ONLY handle :func:`close_window` accepts. Clearing it
    on a call that never reached NetBox strands a window that IS open there."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        cr.mw_state, cr.mw_ref = "closed", "fw=journal:7"
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        monkeypatch.setattr(netbox, "open_window", lambda *a, **k: {
            "ok": False, "sent": False, "detail": "not mapped"})
        orch.open_window(cr)
        assert cr.mw_ref == "fw=journal:7"


def test_the_window_failure_reason_reaches_the_caller_not_only_the_log(app, monkeypatch):
    """The caller flashes ``detail`` at the operator. Counts alone - "opened 0,
    failed 1" - name neither the cause nor the next step, while the reason this
    function already computed sits in an integration log nobody is sent to.

    Also pins the back-compatible default: a result with no ``sent`` key is
    treated as SENT, so an unknown path errs toward the cautious state."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(device_ids=[_an_appliance(app).id])
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        monkeypatch.setattr(netbox, "open_window",
                            lambda *a, **k: {"ok": False, "detail": "connection refused"})
        res = orch.open_window(cr)
        assert cr.mw_state == "error", "a CONTACTED failure is still an error"
        assert "refused" in res["detail"]


def test_a_change_with_no_devices_is_told_so(app, monkeypatch):
    """Zero devices is not "NetBox failed": it is a change there is nothing to
    open a window for. "opened 0, failed 0" reads as an integration fault."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    with app.app_context():
        cr = _mk_cr(device_ids=[])
        cr.mw_state = "none"
        monkeypatch.setattr(netbox, "is_configured", lambda: True)
        res = orch.open_window(cr)
        assert res["ok"] is False
        assert res["detail"] != "opened 0, failed 0"
        assert "device" in res["detail"].lower()
        assert cr.mw_state != "error"


def test_the_window_button_is_off_when_no_device_is_mapped(app, client, monkeypatch):
    """A configured NetBox is not enough to offer the button.

    With none of the change's appliances in ``device_map`` the press can only
    fail, and before this guard the failure ALSO marked the change as a NetBox
    error. The page must name the appliance rather than let the operator find
    out by pressing."""
    from tests.conftest import admin_user_id, login
    from app.services import netbox_client as netbox
    with app.app_context():
        dev = _an_appliance(app)
        dev_id, dev_name = dev.id, dev.name
        cr = _mk_cr(status="approved", device_ids=[dev_id])
        cr_id = cr.id
    monkeypatch.setattr(netbox, "is_configured", lambda: True)
    monkeypatch.setattr(netbox, "resolve_plan", lambda devices, **k: {
        str(getattr(d, "id", "")): {
            "id": str(getattr(d, "id", "")), "name": getattr(d, "name", ""),
            "device_id": 0, "via": "", "checked": True, "near": "",
            "error": "NetBox does not document it."}
        for d in devices})
    login(client, admin_user_id(app))
    html = client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True)
    start = html.find("NetBox window")
    assert start > 0, "the NetBox row is not on the page"
    row = html[start:start + 4000]
    assert "open-window" in row, "the button vanished instead of being disabled"
    button = row[row.find("open-window"):]
    button = button[:button.find("</form>")]
    assert "disabled" in button, (
        "the button is live for a change whose appliances NetBox does not "
        "document; pressing it can only fail")
    assert dev_name in row, "the page does not name the unmapped appliance"


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


# --------------------------------------------------------------------------- #
#  The change-ticket row: the button, and the hand the product forgot           #
# --------------------------------------------------------------------------- #
# Measured on the live node 2026-09-20: tracker backend "none", and ZERO hooks
# on disk bound to change.requested. Pressing "Raise change ticket" wrote
# `dispatched=0` to the audit log and flashed a warning. For an operator with
# no Jira/OpenProject/Vikunja that button can NEVER do anything -- and the row
# it fills could never be filled at all, because record_crq() had no route.
# Its NetBox sibling, one <dd> further down, was gated on exactly this class of
# dead press earlier the same day; this half was left live.


def _crq_row(html):
    """The rendered 'Change ticket' <dd>, or '' when it is not on the page."""
    start = html.find("Change ticket")
    if start < 0:
        return ""
    end = html.find("NetBox window", start)
    return html[start:end] if end > start else html[start:start + 4000]


def _crq_button(row):
    """Just the raise-ticket <form>, so a `disabled` elsewhere cannot answer."""
    at = row.find("request-crq")
    if at < 0:
        return ""
    rest = row[at:]
    end = rest.find("</form>")
    return rest[:end] if end > 0 else rest


def _wire(monkeypatch, *, tracker=False, hooks=0):
    """Say exactly what is wired behind the button, whatever this node has."""
    from app.services import tracker_client
    from app.services import integration_hooks
    monkeypatch.setattr(tracker_client, "is_configured", lambda: tracker)
    monkeypatch.setattr(tracker_client, "config",
                        lambda: {"backend": "jira", "backend_label": "Jira Cloud"})
    monkeypatch.setattr(integration_hooks, "hooks_for_event",
                        lambda ev: [{"slug": "crm"}] * hooks)


def _a_draft(app, status="draft"):
    from app.extensions import db
    with app.app_context():
        cr = _mk_cr(status=status, device_ids=[_an_appliance(app).id])
        db.session.commit()
        return cr.id


def test_the_ticket_button_is_off_when_nothing_is_wired(app, client, monkeypatch):
    """No tracker backend and no bound hook means the press sends NOTHING.

    SATOM knows that before it draws the button. Offering it anyway teaches the
    operator that the integration is broken, when the fix is a dropdown."""
    from tests.conftest import admin_user_id, login
    cr_id = _a_draft(app)
    _wire(monkeypatch, tracker=False, hooks=0)
    login(client, admin_user_id(app))
    row = _crq_row(client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True))
    assert row, "the change-ticket row is not on the page"
    button = _crq_button(row)
    assert button, "the button vanished instead of being disabled"
    assert "disabled" in button, (
        "the button is live with nothing behind it; the only way to find out "
        "is to press it")


def test_the_dead_button_names_both_ways_to_bring_it_back(app, client, monkeypatch):
    """Two different fixes, in two different places. Naming one sends half the
    operators to the wrong screen."""
    from tests.conftest import admin_user_id, login
    cr_id = _a_draft(app)
    _wire(monkeypatch, tracker=False, hooks=0)
    login(client, admin_user_id(app))
    row = _crq_row(client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True))
    at = row.find("nothing is wired behind it")
    assert at > 0, "the page does not say why the button is off"
    end = row.find("</div>", at)
    why = row[at:end] if end > at else row[at:]
    assert "Integrations" in why, "the settings page that fixes it is not named"
    assert "change.requested" in why, "the hook binding that fixes it is not named"


def test_the_button_is_live_when_a_tracker_backend_is_configured(app, client, monkeypatch):
    """A configured tracker answers inline - that press does real work."""
    from tests.conftest import admin_user_id, login
    cr_id = _a_draft(app)
    _wire(monkeypatch, tracker=True, hooks=0)
    login(client, admin_user_id(app))
    button = _crq_button(_crq_row(
        client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True)))
    assert button, "the button is gone for a change that CAN raise a ticket"
    assert "disabled" not in button, "a working integration was switched off"


def test_the_button_is_live_when_a_hook_is_bound(app, client, monkeypatch):
    """The hook path is the OTHER half. Gating on the tracker alone would kill
    the button for every operator running their own CRM glue."""
    from tests.conftest import admin_user_id, login
    cr_id = _a_draft(app)
    _wire(monkeypatch, tracker=False, hooks=1)
    login(client, admin_user_id(app))
    button = _crq_button(_crq_row(
        client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True)))
    assert button and "disabled" not in button, (
        "a bound change.requested hook is a working channel and was ignored")


def test_the_page_never_says_off_while_the_button_is_on(app, client, monkeypatch):
    """The sentence and the control must not be able to disagree."""
    from tests.conftest import admin_user_id, login
    cr_id = _a_draft(app)
    _wire(monkeypatch, tracker=True, hooks=1)
    login(client, admin_user_id(app))
    row = _crq_row(client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True))
    assert "nothing is wired behind it" not in row


def test_a_reference_can_be_written_by_hand(app, client, monkeypatch):
    """The row exists to carry the change board's ticket id. With no tracker
    and no hook there was NO writer for it at all: record_crq() had no route,
    so 'none recorded' was permanent."""
    from tests.conftest import admin_user_id, login
    from app.models import ChangeRequest
    cr_id = _a_draft(app)
    login(client, admin_user_id(app))
    res = client.post("/web/change-requests/%d/record-crq" % cr_id,
                      data={"crq_ref": "CHG0049211",
                            "crq_url": "https://itsm.example.com/CHG0049211"})
    assert res.status_code == 302
    with app.app_context():
        cr = ChangeRequest.query.get(cr_id)
        assert cr.crq_ref == "CHG0049211"
        assert cr.crq_url == "https://itsm.example.com/CHG0049211"


def test_the_hand_written_form_is_there_precisely_when_nothing_is_wired(app, client, monkeypatch):
    """This is the whole point: the fallback must be present in the state that
    makes it necessary, not only once somebody buys Jira."""
    from tests.conftest import admin_user_id, login
    cr_id = _a_draft(app)
    _wire(monkeypatch, tracker=False, hooks=0)
    login(client, admin_user_id(app))
    row = _crq_row(client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True))
    assert "record-crq" in row, "no way to fill a row that nothing else can fill"
    assert 'name="crq_ref"' in row, "the reference field is missing"


def test_a_blank_submit_does_not_erase_the_reference_on_record(app, client, monkeypatch):
    """An empty field is far more often a fat-fingered Record than an intent to
    delete. Silently clearing would strip the approver's only link to the
    ticket."""
    from tests.conftest import admin_user_id, login
    from app.extensions import db
    from app.models import ChangeRequest
    cr_id = _a_draft(app)
    with app.app_context():
        cr = ChangeRequest.query.get(cr_id)
        cr.crq_ref = "CHG0000001"
        db.session.commit()
    login(client, admin_user_id(app))
    res = client.post("/web/change-requests/%d/record-crq" % cr_id, data={"crq_ref": ""})
    assert res.status_code == 302, "there is no route to record a reference by hand"
    with app.app_context():
        assert ChangeRequest.query.get(cr_id).crq_ref == "CHG0000001"


def test_a_hand_typed_link_must_be_http(app, client, monkeypatch):
    """crq_url is rendered as an <a href>. A javascript: value typed here is a
    click-to-run script for the next person who opens the change."""
    from tests.conftest import admin_user_id, login
    from app.models import ChangeRequest
    cr_id = _a_draft(app)
    login(client, admin_user_id(app))
    res = client.post("/web/change-requests/%d/record-crq" % cr_id,
                      data={"crq_ref": "CHG1", "crq_url": "javascript:alert(1)"})
    assert res.status_code == 302, "there is no route to record a reference by hand"
    with app.app_context():
        cr = ChangeRequest.query.get(cr_id)
        assert "javascript:" not in (cr.crq_url or "")
        assert not (cr.crq_ref or ""), (
            "the reference was saved while its link was refused: the operator "
            "is told nothing was saved and half of it was")


def test_a_closed_change_does_not_take_a_new_reference(app, client, monkeypatch):
    """A cancelled change is a record of what did NOT happen. Writing a live
    ticket id onto it makes it look like it did."""
    from tests.conftest import admin_user_id, login
    from app.models import ChangeRequest
    cr_id = _a_draft(app, status="cancelled")
    login(client, admin_user_id(app))
    res = client.post("/web/change-requests/%d/record-crq" % cr_id,
                      data={"crq_ref": "CHG0099999"})
    assert res.status_code == 302, "there is no route to record a reference by hand"
    with app.app_context():
        assert not (ChangeRequest.query.get(cr_id).crq_ref or "")


def test_the_hand_written_reference_is_attributed_to_the_person(app, client, monkeypatch):
    """'the integration recorded it' and 'admin typed it' are different claims
    about how much the reference can be trusted."""
    from tests.conftest import admin_user_id, login
    from app.models import ChangeRequestEvent
    cr_id = _a_draft(app)
    login(client, admin_user_id(app))
    client.post("/web/change-requests/%d/record-crq" % cr_id,
                data={"crq_ref": "CHG0049212"})
    with app.app_context():
        rows = ChangeRequestEvent.query.filter_by(cr_id=cr_id, kind="crq_created").all()
        assert rows, "recording a reference wrote no event at all"
        who = " ".join((e.by or "") for e in rows)
        assert "admin" in who, "the event does not say who typed it"
        assert "integration" not in who, (
            "a hand-typed reference is attributed to an integration that never ran")


def test_the_appliance_itself_not_its_id_is_handed_to_netbox(app, monkeypatch):
    """An id alone can only be looked up in the explicit device map. Handing
    ``dev.id`` over made the exact-name fallback that Settings -> Integrations
    documents unreachable from the only caller that opens windows in
    production - so a fully configured NetBox still refused every window until
    someone hand-typed device ids."""
    from app.services import cr_orchestrator as orch
    from app.services import netbox_client as netbox
    seen = []
    with app.app_context():
        dev = _an_appliance(app)
        dev_name = dev.name
        cr = _mk_cr(device_ids=[dev.id])
        monkeypatch.setattr(netbox, "is_configured", lambda: True)

        def _capture(appliance, **kwargs):
            seen.append(appliance)
            return {"ok": True, "ref": "journal:1", "detail": "", "sent": True}

        monkeypatch.setattr(netbox, "open_window", _capture)
        orch.open_window(cr)
        # Inside the session on purpose: a detached instance raises on every
        # attribute, which would mask the very difference under test.
        assert seen, "netbox.open_window was never called"
        assert not isinstance(seen[0], (int, str)), (
            "the id was passed instead of the appliance; the name fallback "
            "cannot run without the name")
        assert getattr(seen[0], "name", "") == dev_name


def test_an_unverifiable_netbox_leaves_the_window_button_available(app, client, monkeypatch):
    """NetBox down is UNKNOWN, not "this appliance does not exist". Disabling
    the button on an unknown turns an integration outage into a statement about
    the customer's inventory, and removes the only control that would report
    the real reason."""
    from tests.conftest import admin_user_id, login
    from app.services import netbox_client as netbox
    with app.app_context():
        dev = _an_appliance(app)
        dev_id, dev_name = dev.id, dev.name
        cr = _mk_cr(status="approved", device_ids=[dev_id])
        cr_id = cr.id
    monkeypatch.setattr(netbox, "is_configured", lambda: True)
    monkeypatch.setattr(netbox, "resolve_plan", lambda devices, **k: {
        str(getattr(d, "id", "")): {
            "id": str(getattr(d, "id", "")), "name": getattr(d, "name", ""),
            "device_id": 0, "via": "", "checked": False, "near": "",
            "error": "NetBox did not answer within 3s"}
        for d in devices})
    login(client, admin_user_id(app))
    html = client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True)
    start = html.find("NetBox window")
    assert start > 0
    row = html[start:start + 4000]
    marker = row.find("open-window")
    assert marker > 0, "the button vanished"
    button = row[marker:]
    button = button[:button.find("</form>")]
    assert "disabled" not in button, (
        "an unknown answer disabled the button; only a PROVEN refusal may")
    assert dev_name in row, "the page does not say which appliance is unverified"


def test_the_window_button_gate_asks_the_same_author_the_press_does(app, client, monkeypatch):
    """A resolved appliance must produce a LIVE button. The gate used to ask
    the map-only question while the press resolved by name too, so every
    appliance NetBox documented under its own name got a dead button."""
    from tests.conftest import admin_user_id, login
    from app.services import netbox_client as netbox
    with app.app_context():
        dev = _an_appliance(app)
        dev_id = dev.id
        cr = _mk_cr(status="approved", device_ids=[dev_id])
        cr_id = cr.id
    monkeypatch.setattr(netbox, "is_configured", lambda: True)
    monkeypatch.setattr(netbox, "resolve_plan", lambda devices, **k: {
        str(getattr(d, "id", "")): {
            "id": str(getattr(d, "id", "")), "name": getattr(d, "name", ""),
            "device_id": 42, "via": "name", "checked": True, "near": "",
            "error": ""}
        for d in devices})
    login(client, admin_user_id(app))
    html = client.get("/web/change-requests/%d" % cr_id).get_data(as_text=True)
    row = html[html.find("NetBox window"):][:4000]
    button = row[row.find("open-window"):]
    button = button[:button.find("</form>")]
    assert "disabled" not in button, (
        "the button is dead for an appliance NetBox resolves by name")
