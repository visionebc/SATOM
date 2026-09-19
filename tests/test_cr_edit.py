"""A change request must be CORRECTABLE while it is still open.

``window_start`` is optional when a change is raised and required before it can
run (:func:`app.services.change_requests.cr_runnable` refuses "no maintenance
window"). Until 2026-09-14 the blueprint offered approve / schedule / cancel /
mark-notified and nothing that could write a window — so a change saved with
that field blank was un-runnable FOREVER, and the only remedy was to cancel it
and retype the whole thing. CR-2026-0012 was stored exactly that way: approved,
looking healthy, and unable to fire.

Nothing failed. The Schedule button does not set a window, it binds an action
*to* one, so it refused with "set a maintenance-window start first" and the
record kept looking like a change somebody had approved.

Guarded here, in the order the defects were found:

1. the editor exists, is scoped and permissioned like every other CR route;
2. the window rule has ONE author — raising a change and editing one cannot
   disagree about what a legal window is;
3. an edit that changes what the approver DECIDED ON voids the approval, and
   an edit that does not, does not;
4. the window round-trips through the operator's timezone unshifted;
5. the action and the devices stay fixed;
6. the Cancel control next to the new Edit button stays one line.
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEW_PATH = os.path.join(REPO, "app", "views", "change_requests.py")
SVC_PATH = os.path.join(REPO, "app", "services", "change_requests.py")
# The change VIEW, not the page that frames it: those blocks moved into a
# shared partial when stage 2 of the upgrade flow started rendering the same
# change inline. Left pointing at detail.html this guard would have gone on
# passing against a file that no longer contains what it measures.
DETAIL_TPL = os.path.join(REPO, "app", "templates", "change_requests", "_view.html")
EDIT_TPL = os.path.join(REPO, "app", "templates", "change_requests", "edit.html")
CSS_PATH = os.path.join(REPO, "app", "static", "css", "fortiweb.css")


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _code_only(path: str) -> str:
    """Source with every comment and docstring removed.

    A guard asserted against raw text is satisfied by the COMMENT that explains
    it: the comment above the window check quotes the very sentence the check
    emits. ``ast.unparse`` drops comments outright; docstrings are stripped
    explicitly because unparse keeps them.
    """
    tree = ast.parse(io.open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _mk_cr(app, *, status="draft", window=(None, None), action="upgrade",
           device_ids=None, **kw):
    from app.models import ChangeRequest, db
    with app.app_context():
        cr = ChangeRequest(
            title=kw.pop("title", "CR under edit"),
            reason=kw.pop("reason", "firmware"),
            status=status,
            action=action,
            params="{}",
            device_ids=json.dumps(device_ids or []),
            policies="[]",
            window_start=window[0],
            window_end=window[1],
            risk=kw.pop("risk", "medium"),
            ref=kw.pop("ref", "CR-2026-9999"),
            **kw)
        db.session.add(cr)
        db.session.commit()
        return cr.id


def _cr(app, crid):
    from app.models import ChangeRequest
    with app.app_context():
        return ChangeRequest.query.get(crid)


def _events(app, crid):
    from app.models import ChangeRequestEvent
    with app.app_context():
        return [(e.kind, e.detail or "") for e in
                ChangeRequestEvent.query.filter_by(cr_id=crid)
                .order_by(ChangeRequestEvent.id).all()]


def _audit(app, action="change_request.update"):
    from app.models import AuditLog
    with app.app_context():
        return AuditLog.query.filter_by(action=action).count()


def _form(app, cr, **over):
    """The edit form as the browser submits it — EVERY field, as a real POST
    carries every field. Posting only the one under test would let a handler
    that blanks the untouched fields pass.

    Formatted INSIDE an app context on purpose: to_local degrades to raw UTC
    without one, so a harness that skipped it would post a window two hours off
    and then blame the product for moving it.
    """
    from app.services import settings_store
    with app.app_context():
        def _fv(dt):
            return settings_store.to_local(dt, "%Y-%m-%dT%H:%M") if dt else ""
        data = {
            "title": cr.title or "",
            "risk": cr.risk or "medium",
            "reason": cr.reason or "",
            "window_start": _fv(cr.window_start),
            "window_end": _fv(cr.window_end),
            "rollback": cr.rollback or "",
            "notify_to": cr.notify_to or "",
            "owner": cr.owner or "",
            "doc_lang": cr.doc_lang or "en",
            "approval_mode": cr.approval_mode or "manual",
        }
    data.update(over)
    return data


@pytest.fixture()
def admin(app, client):
    uid = admin_user_id(app)
    login(client, uid)
    return uid


# --------------------------------------------------------------------------- #
#  1. the editor exists, and is gated like every other CR route                  #
# --------------------------------------------------------------------------- #
def test_the_edit_route_is_registered(app):
    rules = {r.endpoint for r in app.url_map.iter_rules()}
    assert "change_requests.edit" in rules


@pytest.mark.parametrize("status", ["draft", "approved", "scheduled", "in_progress"])
def test_every_open_status_can_be_edited(app, client, admin, status):
    crid = _mk_cr(app, status=status)
    r = client.get(f"/change-requests/{crid}/edit")
    assert r.status_code == 200, status
    assert b'name="window_start"' in r.data


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled"])
def test_a_closed_change_is_never_rewritten(app, client, admin, status):
    """A terminal CR is the record of what happened.

    Refused on GET as well as POST: rendering the form and failing on save is
    an invitation to retype a change that was never going to be written."""
    crid = _mk_cr(app, status=status, title="closed")
    r = client.get(f"/change-requests/{crid}/edit")
    assert r.status_code == 302
    r = client.post(f"/change-requests/{crid}/edit",
                    data=_form(app, _cr(app, crid), title="rewritten"),
                    follow_redirects=False)
    assert r.status_code == 302
    assert _cr(app, crid).title == "closed"
    assert _cr(app, crid).status == status


def test_the_writer_itself_refuses_a_closed_change(app):
    """Directly, not through the route.

    The route refuses a terminal CR first, which makes the check inside
    update_change_request unreachable over HTTP — and a mutation that removed it
    SURVIVED the rest of this file. It is not decoration: the function is the
    one implementation of "edit a change", and the next caller (a batched wave,
    an API) will not come through this form."""
    from app.models import ChangeRequest
    from app.views.change_requests import update_change_request
    crid = _mk_cr(app, status="completed", title="history")
    with app.app_context():
        cr = ChangeRequest.query.get(crid)
        changed, error = update_change_request(cr, {"title": "rewritten",
                                                    "risk": "low"}, "tester")
    assert changed == []
    assert "completed" in error
    assert _cr(app, crid).title == "history"


def test_a_reader_cannot_edit(app, client):
    uid = make_user(app, "ro", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    crid = _mk_cr(app, title="untouched")
    assert client.get(f"/change-requests/{crid}/edit").status_code != 200
    client.post(f"/change-requests/{crid}/edit",
                data={"title": "hijacked", "risk": "low"})
    assert _cr(app, crid).title == "untouched"


def test_a_change_outside_this_adom_is_not_editable(app, client, admin):
    """404, never 403 — the same scope the list and the detail route honour.

    Filtering the LIST while a by-id route reads the table raw is decoration,
    not scoping."""
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="adc-elsewhere", kind="fortiadc", host="192.0.2.98",
                      port=443, username="admin", verify_ssl=False)
        a.password = "x"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    crid = _mk_cr(app, device_ids=[aid], title="other adom")
    with client.session_transaction() as sess:
        sess["product"] = "fortiweb"
    assert client.get(f"/change-requests/{crid}/edit").status_code == 404
    r = client.post(f"/change-requests/{crid}/edit",
                    data=_form(app, _cr(app, crid), title="leaked"))
    assert r.status_code == 404
    assert _cr(app, crid).title == "other adom"


# --------------------------------------------------------------------------- #
#  2. the window rule has ONE author                                            #
# --------------------------------------------------------------------------- #
_NOW = datetime(2026, 9, 14, 20, 0)
_WINDOWS = [
    (None, None),                                   # legal: not decided yet
    (_NOW, None),                                   # legal: open-ended
    (None, _NOW),                                   # legal: end without start
    (_NOW, _NOW + timedelta(hours=2)),              # legal
    (_NOW, _NOW),                                   # ILLEGAL: empty
    (_NOW, _NOW - timedelta(days=1)),               # ILLEGAL: inverted (CR-0011)
]


@pytest.mark.parametrize("start,end", _WINDOWS)
def test_creating_and_editing_agree_on_what_a_legal_window_is(app, start, end):
    """The relationship, not a list of cases.

    The rule was written inline in the create path, so every OTHER way of
    putting a window on a change was free to store one that can never contain
    an instant — which is the hole the edit form would have walked straight
    into."""
    from app.views.change_requests import create_change_request, update_change_request
    with app.app_context():
        created, create_err = create_change_request({
            "title": "w", "action": "upgrade", "device_ids": [],
            "window_start": start, "window_end": end})
        target = _mk_cr(app, status="draft")
        from app.models import ChangeRequest
        cr = ChangeRequest.query.get(target)
        _, edit_err = update_change_request(
            cr, {"title": "w", "risk": "medium",
                 "window_start": start, "window_end": end}, "tester")
    assert bool(create_err) == bool(edit_err), (
        f"create said {create_err!r} and edit said {edit_err!r} "
        f"about the same window {start}..{end}")
    if create_err:
        assert created is None
        assert "never fire" in create_err and "never fire" in edit_err


def test_the_window_rule_has_no_second_copy_in_the_view(app):
    """Asserted against CODE, never raw text: the comment that explains the
    rule quotes the sentence it emits, so a text scan matches its own
    documentation."""
    code = _code_only(VIEW_PATH)
    assert "validate_window" in code
    assert "ends at or before it starts" not in code, (
        "the refusal sentence is authored in the service; a copy here is a "
        "second author of the same rule")


def test_validate_window_is_exported_and_pure(app):
    from app.services import change_requests as svc
    assert svc.validate_window(None, None) == ""
    assert svc.validate_window(_NOW, None) == ""
    assert svc.validate_window(_NOW, _NOW + timedelta(minutes=1)) == ""
    assert svc.validate_window(_NOW, _NOW) != ""
    assert svc.validate_window(_NOW, _NOW - timedelta(seconds=1)) != ""
    assert "validate_window" in svc.__all__


# --------------------------------------------------------------------------- #
#  3. THE regression: a change with no window can be given one and then run      #
# --------------------------------------------------------------------------- #
def test_a_windowless_change_becomes_runnable_after_an_edit(app, client, admin):
    """CR-2026-0012, end to end.

    Approved, no window, un-runnable, and before this route existed there was
    no way back: Schedule binds an action TO a window, it does not write one."""
    from app.services import change_requests as svc
    crid = _mk_cr(app, status="approved", window=(None, None),
                  approved_by="mel", approved_at=datetime.utcnow())
    with app.app_context():
        ok, why = svc.cr_runnable(_cr(app, crid))
    assert (ok, why) == (False, "no maintenance window")

    now = datetime.utcnow()
    from app.services import settings_store
    with app.app_context():
        fmt = lambda d: settings_store.to_local(d, "%Y-%m-%dT%H:%M")
        start, end = fmt(now - timedelta(hours=1)), fmt(now + timedelta(hours=3))
    r = client.post(f"/change-requests/{crid}/edit",
                    data=_form(app, _cr(app, crid), window_start=start, window_end=end),
                    follow_redirects=False)
    assert r.status_code == 302

    # The window moved, so the approval it was given under is void.
    assert _cr(app, crid).status == "draft"
    client.post(f"/change-requests/{crid}/approve")
    with app.app_context():
        ok, why = svc.cr_runnable(_cr(app, crid))
    assert ok, why


# --------------------------------------------------------------------------- #
#  4. an approval covers what it was given for, and nothing else                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field,value", [
    ("window_start", "2026-12-01T22:00"),
    ("window_end", "2026-12-01T23:30"),
    ("risk", "high"),
    ("approval_mode", "manual"),
])
def test_changing_what_the_approver_decided_on_voids_the_approval(
        app, client, admin, field, value):
    crid = _mk_cr(app, status="approved",
                  window=(datetime(2026, 12, 1, 20, 0), datetime(2026, 12, 1, 22, 0)),
                  risk="low", approval_mode="external",
                  approved_by="mel", approved_at=datetime.utcnow(),
                  external_approved_by="servicenow",
                  external_approved_at=datetime.utcnow())
    r = client.post(f"/change-requests/{crid}/edit",
                    data=_form(app, _cr(app, crid), **{field: value}))
    assert r.status_code == 302
    row = _cr(app, crid)
    assert row.status == "draft", field
    assert not row.approved_by and row.approved_at is None
    # The foreign authority's yes was given about the old change too.
    assert row.external_approved_at is None and not row.external_approved_by
    kinds = [k for k, _ in _events(app, crid)]
    assert kinds[-2:] == ["edited", "draft"], kinds


@pytest.mark.parametrize("field,value", [
    ("title", "clearer title"),
    ("reason", "because the vendor said so"),
    ("rollback", "restore the config backup"),
    ("notify_to", "ops@example.com"),
    ("owner", "mel"),
])
def test_editing_anything_else_leaves_the_approval_alone(
        app, client, admin, field, value):
    """The other half. A route that voided on every save would train operators
    to re-approve without reading, which is the control failing quietly."""
    now = datetime.utcnow()
    crid = _mk_cr(app, status="approved", window=(now, now + timedelta(hours=2)),
                  approved_by="mel", approved_at=now)
    client.post(f"/change-requests/{crid}/edit",
                data=_form(app, _cr(app, crid), **{field: value}))
    row = _cr(app, crid)
    assert row.status == "approved", field
    assert row.approved_by == "mel"
    assert getattr(row, field) == value


def test_voiding_an_approval_disables_the_bound_one_shot(app, client, admin):
    """The load-bearing half of the revocation.

    A one-shot fires at the window start it was BOUND with. cr_runnable
    re-checks the CURRENT window at fire time, so it cannot run outside the new
    one — but with catch_up it can fire at an instant nobody scheduled if the
    old start happens to fall inside the new window."""
    from app.models import ScheduledAction, db
    now = datetime.utcnow()
    crid = _mk_cr(app, status="scheduled",
                  window=(now + timedelta(hours=1), now + timedelta(hours=3)),
                  approved_by="mel", approved_at=now)
    with app.app_context():
        act = ScheduledAction(
            name="CR one-shot", scope="admin", action="upgrade", targets="[]",
            params=json.dumps({"change_request_id": crid}),
            schedule_kind="once",
            schedule=json.dumps({"at": (now + timedelta(hours=1)).isoformat()}),
            enabled=True, catch_up=True, created_by="tester")
        db.session.add(act)
        db.session.commit()
        aid = act.id
        from app.models import ChangeRequest
        ChangeRequest.query.get(crid).scheduled_action_id = aid
        db.session.commit()

    client.post(f"/change-requests/{crid}/edit",
                data=_form(app, _cr(app, crid), window_start="2027-01-05T02:00",
                           window_end="2027-01-05T04:00"))
    with app.app_context():
        assert ScheduledAction.query.get(aid).enabled is False
    assert _cr(app, crid).status == "draft"


def test_a_draft_edit_writes_no_pointless_revocation_event(app, client, admin):
    crid = _mk_cr(app, status="draft")
    client.post(f"/change-requests/{crid}/edit",
                data=_form(app, _cr(app, crid), window_start="2027-02-01T01:00",
                           window_end="2027-02-01T03:00"))
    kinds = [k for k, _ in _events(app, crid)]
    assert kinds == ["edited"], kinds
    assert _cr(app, crid).status == "draft"


# --------------------------------------------------------------------------- #
#  5. the record of the edit                                                    #
# --------------------------------------------------------------------------- #
def test_an_edit_names_the_fields_it_changed(app, client, admin):
    crid = _mk_cr(app, status="draft", title="old title", risk="low")
    before = _audit(app)
    client.post(f"/change-requests/{crid}/edit",
                data=_form(app, _cr(app, crid), title="new title", risk="high"))
    detail = _events(app, crid)[-1][1]
    assert "title" in detail and "old title" in detail and "new title" in detail
    assert "risk" in detail and "low" in detail and "high" in detail
    assert _audit(app) == before + 1


def test_saving_an_unchanged_form_records_nothing(app, client, admin):
    """'Saved' on a form nobody edited would put a line in the timeline of a
    change under review saying somebody touched it."""
    now = datetime.utcnow().replace(second=0, microsecond=0)
    crid = _mk_cr(app, status="approved", window=(now, now + timedelta(hours=2)),
                  approved_by="mel", approved_at=now)
    before = _audit(app)
    client.post(f"/change-requests/{crid}/edit", data=_form(app, _cr(app, crid)))
    assert _events(app, crid) == []
    assert _audit(app) == before
    assert _cr(app, crid).status == "approved"


def test_a_window_carrying_seconds_is_not_an_edit_nobody_made(app, client, admin):
    """Found by the guard above, not by hand.

    A datetime-local field has MINUTE resolution. A window stored with seconds
    - written by any other path: a batched wave, the API, a restore - cannot be
    typed into it, so comparing the form value to the stored one verbatim
    reports a change on every save and voids the approval of an approved change
    whenever somebody corrects its TITLE."""
    start = datetime(2026, 12, 1, 20, 0, 37, 500000)
    crid = _mk_cr(app, status="approved", window=(start, start + timedelta(hours=2)),
                  title="carries fractional seconds",
                  approved_by="mel", approved_at=datetime.utcnow())
    client.post(f"/change-requests/{crid}/edit",
                data=_form(app, _cr(app, crid), title="corrected title"))
    row = _cr(app, crid)
    assert row.title == "corrected title"
    assert row.status == "approved", "a title edit voided the approval"
    assert [k for k, _ in _events(app, crid)] == ["edited"]
    # By FIELD PREFIX, not by substring: the first version of this line was
    # satisfied by the word 'window' inside the title being edited.
    diffs = [d.split(':')[0] for d in _events(app, crid)[-1][1].split('; ')]
    assert diffs == ["title"], diffs


# --------------------------------------------------------------------------- #
#  6. the window survives the operator's clock                                   #
# --------------------------------------------------------------------------- #
def test_the_prefilled_window_round_trips_through_the_console_timezone(app, client, admin):
    """to_local -> the form -> parse_local must be the identity.

    Typing 22:00 on a Europe/Zurich console once booked a window that opened at
    midnight local. The editor PRE-FILLS from a stored UTC value, so the same
    defect arrives from the other side: a form that formatted with strftime
    would hand the operator their own window back shifted by the offset, and
    re-saving it untouched would walk it two hours every time."""
    from app.services import settings_store
    with app.app_context():
        settings_store.set_str("general.timezone", "Europe/Zurich")
    start = datetime(2026, 12, 1, 21, 0)          # naive UTC, as stored
    crid = _mk_cr(app, status="draft", window=(start, start + timedelta(hours=2)))

    page = client.get(f"/change-requests/{crid}/edit").data.decode()
    value = re.search(r'name="window_start"[^>]*value="([^"]*)"', page)
    if value is None:
        value = re.search(r'value="([^"]*)"[^>]*name="window_start"', page)
    assert value, "the editor must pre-fill the window it is editing"
    shown = value.group(1)
    assert shown == "2026-12-01T22:00", shown   # UTC+1 in December

    client.post(f"/change-requests/{crid}/edit",
                data=_form(app, _cr(app, crid), window_start=shown))
    assert _cr(app, crid).window_start == start, "re-saving walked the window"


# --------------------------------------------------------------------------- #
#  7. what an edit may NOT re-point                                             #
# --------------------------------------------------------------------------- #
def test_the_action_and_the_devices_are_fixed(app, client, admin):
    """The frozen inventory, the bound pre-flight and any printed document all
    describe THOSE devices doing THAT thing."""
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw-frozen", kind="fortiweb", host="192.0.2.97",
                      port=443, username="admin", verify_ssl=False)
        a.password = "x"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    crid = _mk_cr(app, status="draft", action="upgrade", device_ids=[aid])
    client.post(f"/change-requests/{crid}/edit",
                data=dict(_form(app, _cr(app, crid)),
                          action="upgrade_prep", device_ids=["999"]))
    row = _cr(app, crid)
    assert row.action == "upgrade"
    assert row.device_ids_list == [aid]


def test_editable_fields_and_approval_critical_stay_in_step(app):
    """Every approval-critical field must be a field an edit can actually
    write; otherwise the revocation rule guards something unreachable."""
    from app.views.change_requests import APPROVAL_CRITICAL, EDITABLE_FIELDS
    assert set(APPROVAL_CRITICAL) <= set(EDITABLE_FIELDS)
    assert "action" not in EDITABLE_FIELDS and "device_ids" not in EDITABLE_FIELDS
    assert "status" not in EDITABLE_FIELDS
    assert len(EDITABLE_FIELDS) >= 8       # floor: an empty tuple satisfies the above


# --------------------------------------------------------------------------- #
#  8. the two controls that sit next to each other                              #
# --------------------------------------------------------------------------- #
def test_the_detail_page_offers_the_editor_only_while_the_change_is_open(app, client, admin):
    open_id = _mk_cr(app, status="approved")
    closed_id = _mk_cr(app, status="cancelled")
    assert f"/change-requests/{open_id}/edit".encode() in \
        client.get(f"/change-requests/{open_id}").data
    assert f"/change-requests/{closed_id}/edit".encode() not in \
        client.get(f"/change-requests/{closed_id}").data


def test_a_button_label_is_one_phrase(app):
    """Bootstrap 4 shipped .btn{white-space:nowrap}; Bootstrap 5 dropped it, so
    a button squeezed by a flex sibling breaks its LABEL across lines instead of
    staying one control. Measured: the Cancel CR button rendered 80px wide and
    THREE lines tall at 1600px, 1280px and 1024px alike."""
    css = re.sub(r"/\*.*?\*/", "", io.open(CSS_PATH, encoding="utf-8").read(),
                 flags=re.S)
    rule = re.search(r"(?<![\w.-])\.btn\s*\{[^}]*white-space:\s*nowrap", css)
    assert rule, ".btn must not let its label wrap"
    # The comment above the rule quotes it verbatim; without the strip above,
    # this guard passes against a stylesheet where the DECLARATION says
    # `normal`. That mutation survived until the comments came out.
    assert "white-space:nowrap" in re.sub(r"\s+", "", rule.group(0))


def test_the_cancel_control_cannot_squeeze_its_own_button(app):
    """The stylesheet rule alone would only trade a wrapped label for an
    overflowing one: the button was 80px because the reason input beside it
    claimed the whole form."""
    html = io.open(DETAIL_TPL, encoding="utf-8").read()
    form = re.search(r"<form[^>]*change_requests\.cancel.*?</form>", html, re.S)
    assert form, "cancel form not found"
    block = form.group(0)
    assert "flex-shrink-0" in block, "the button must not shrink"
    assert re.search(r'name="reason"[^>]*style="[^"]*flex:\s*0 1 220px', block), \
        "the reason input must have a flex basis instead of width:100%"
    assert "flex-nowrap" in block


def test_the_editor_says_what_a_save_will_do_to_the_approval(app, client, admin):
    now = datetime.utcnow()
    crid = _mk_cr(app, status="approved", window=(now, now + timedelta(hours=1)),
                  approved_by="mel", approved_at=now)
    page = client.get(f"/change-requests/{crid}/edit").data.decode()
    assert "fw-alert-warning" in page
    assert "draft" in page
    draft_id = _mk_cr(app, status="draft")
    assert "fw-alert-warning" not in \
        client.get(f"/change-requests/{draft_id}/edit").data.decode()


def test_the_editor_uses_the_light_chrome_this_product_has(app, client, admin):
    """SATOM has no dark theme (safeguards §9m): a slate card on a white page
    renders as a grey slab."""
    html = io.open(EDIT_TPL, encoding="utf-8").read()
    for banned in ("#0f172a", "#1e293b", "rgba(30,41,59", "backdrop-filter",
                   "#080d1a", "#cbd5e1"):
        assert banned not in html, banned
