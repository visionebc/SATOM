"""Additive mode — "only add what is missing" (standalone 1.27.0, ported).

The web clone had the SAME two write paths into an object the destination
already owns, and only one of them was under an operator's control:

    update  — a row colliding on its unique key was REWRITTEN, governed by
              ``reconcile_rows`` (default ON).
    create  — a row the source has and the destination does not was APPENDED to
              the live object, labelled "missing under an existing parent —
              recreating", governed by nothing at all.

The append is the dangerous one precisely because it reads as housekeeping. A
server pool that GAINS a real server is serving traffic it was not serving a
minute ago; that is as modified as a pool whose member was rewritten. A mode
that only closed the rewrite would have left the pool changed, and reported
green.

So the unit of "the destination already has this" moves from the ROW to the
OBJECT, and every row held back becomes ``untouched`` — a status of its own,
never folded into ``exists``, because "the destination has this row" and "the
destination does NOT have it and we chose not to add it" are opposite facts.

These guards exercise the PLANNER, the WRITER, the SUMMARY, the CUTOVER GATE and
the HTTP default. Where a guard has to read source or markup (the checkbox, the
report section) it asserts the STRUCTURE it depends on, not a passing phrase.
"""
import io
import os

import pytest

from app.services import clone, policy_ops
from app.registry.dependencies import DepNode
from tests.conftest import login, admin_user_id

IPG = "cmdb/server-policy/ip-group"
MEM = IPG + "/members"

ROOT = DepNode("IP Group", IPG, children=(DepNode("IP Group Members", MEM),))

APP = "/opt/satom/app"


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        return [dict(r) for r in self.data.get((urn, mkey), [])]


def _plan(src_rows, dst_rows, *, dst_has_parent=True, additive=True, mkey="ipg1"):
    src = FakeReader({(IPG, mkey): [{"name": mkey}], (MEM, mkey): src_rows})
    dst_data = {(MEM, mkey): dst_rows}
    if dst_has_parent:
        dst_data[(IPG, mkey)] = [{"name": mkey}]
    p = clone.ClonePlanner(src, FakeReader(dst_data))
    return p.plan(ROOT, mkey, additive_only=additive)


def _rows(items):
    return [i for i in items if i.urn == MEM and i.kind == "subrow"]


def _obj(items):
    return next(i for i in items if i.urn == IPG and i.kind == "object")


# --------------------------------------------------------------------------- #
#  Classification — the four cases the mode is defined by                       #
# --------------------------------------------------------------------------- #
def test_an_object_the_destination_lacks_is_still_created_whole():
    # Additive mode is not "write less"; it is "do not write INTO what is
    # already there". A destination missing the object entirely gets the object
    # AND every one of its rows — otherwise the mode would deliver a pool with
    # no members, which serves nothing.
    items = _plan([{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}], [],
                  dst_has_parent=False)
    assert _obj(items).status == "create"
    assert [r.status for r in _rows(items)] == ["create", "create"]


def test_a_row_the_destination_already_has_is_still_exists():
    items = _plan([{"ip": "192.0.2.1"}], [{"ip": "192.0.2.1"}])
    assert [r.status for r in _rows(items)] == ["exists"]


def test_a_missing_row_under_an_existing_parent_is_untouched_not_created():
    # THE QUIET PATH. Without additive mode this is `create` with the note
    # "missing under an existing parent — recreating", and it appends to a live
    # object.
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    row = _rows(items)[0]
    assert row.status == "untouched"
    assert "NOT added" in row.note


def test_a_keyed_collision_under_an_existing_parent_is_untouched_not_updated():
    # `ip` is the measured unique key of this table, so the destination row is
    # ABSENT by content and PRESENT by key: without additive mode this is
    # `update`, a rewrite of a row the destination is serving.
    items = _plan([{"ip": "192.0.2.1", "port": "8080"}],
                  [{"ip": "192.0.2.1", "port": "80", "id": "3"}])
    row = _rows(items)[0]
    assert row.status == "untouched"
    assert "NOT rewritten" in row.note


def test_the_two_held_back_cases_are_told_apart():
    # Same status, different work: one asks "should this row exist here?", the
    # other "which of these two values is right?". A single note for both would
    # send the operator to the wrong question.
    missing = _rows(_plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}]))[0]
    collide = _rows(_plan([{"ip": "192.0.2.1", "port": "8080"}],
                          [{"ip": "192.0.2.1", "port": "80", "id": "3"}]))[0]
    assert missing.note != collide.note


# --------------------------------------------------------------------------- #
#  The mode is a SWITCH — off, the old behaviour is exactly intact              #
# --------------------------------------------------------------------------- #
def test_without_additive_mode_a_missing_row_is_still_created():
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}], additive=False)
    assert _rows(items)[0].status == "create"


def test_without_additive_mode_a_keyed_collision_is_still_an_update():
    items = _plan([{"ip": "192.0.2.1", "port": "8080"}],
                  [{"ip": "192.0.2.1", "port": "80", "id": "3"}], additive=False)
    assert _rows(items)[0].status == "update"


def test_the_planner_default_is_off_so_existing_callers_are_unchanged():
    # `plan()` has callers beyond the clone dialog (wpp_clone_flow, the
    # web_protection blueprint). A default that silently stopped writing would
    # change what THEY deliver without anybody asking.
    src = FakeReader({(IPG, "ipg1"): [{"name": "ipg1"}],
                      (MEM, "ipg1"): [{"ip": "192.0.2.9"}]})
    dst = FakeReader({(IPG, "ipg1"): [{"name": "ipg1"}],
                      (MEM, "ipg1"): [{"ip": "192.0.2.1"}]})
    items = clone.ClonePlanner(src, dst).plan(ROOT, "ipg1")
    assert _rows(items)[0].status == "create"


# --------------------------------------------------------------------------- #
#  The writer                                                                   #
# --------------------------------------------------------------------------- #
def test_apply_clone_never_writes_an_untouched_item():
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    written = []
    clone.apply_clone(items, written.append, dry_run=False)
    assert written == []
    assert all(not i.applied for i in _rows(items))


# --------------------------------------------------------------------------- #
#  Reporting — a held-back row is the only difference that leaves NO trace      #
# --------------------------------------------------------------------------- #
def test_untouched_is_its_own_status_and_is_not_folded_into_exists():
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    counts = clone.summarize(items)
    assert counts.get("untouched") == 1
    # The PARENT object is legitimately `exists` — the destination really does
    # have it, and that is the precondition of the whole mode. What must never
    # be `exists` is the ROW, which the destination does not have.
    assert counts.get("exists") == 1
    assert [r.status for r in _rows(items)] == ["untouched"]


def test_the_summary_counts_untouched_and_keeps_it_out_of_skipped():
    # Everything else in `skipped` is inert. This one means the destination is
    # missing a row the source has, and nothing on the destination records it.
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    s = policy_ops.clone_summary(items)
    assert s["untouched"] == 1
    # `skipped` accounts for the parent object and NOTHING else: the held-back
    # row is not in it. A caller reading only `skipped` must not be told this
    # decision was a no-op.
    assert s["skipped"] == clone.summarize(items)["exists"] == 1


def test_the_outcome_enumerates_the_held_back_rows_not_just_a_count():
    # A count says how many. The operator needs the parent and the key, which is
    # the work.
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    out = clone.outcome(items)
    assert len(out["untouched"]) == 1
    r = out["untouched"][0]
    assert r["parent_mkey"] == "ipg1" and r["note"]


def test_the_plan_text_marks_untouched_apart_from_exists():
    # "=" reads as "the destination already has this" — the one thing this row
    # is not.
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    line = [ln for ln in clone.render_plan(items).splitlines()
            if "IP Group Members" in ln][0]
    assert not line.startswith("=")
    assert line.split()[0] == "/"


# --------------------------------------------------------------------------- #
#  Refusals and gates                                                           #
# --------------------------------------------------------------------------- #
def test_additive_mode_and_compare_and_decide_refute_each_other():
    # Before any device is read: one exists to CHANGE a profile the destination
    # already serves, the other promises not to. Honouring both is honouring
    # neither, and dropping one silently is how an operator ends up believing a
    # run did what the other said.
    class Boom:
        def __getattr__(self, name):
            raise AssertionError("a device was read before the refusal")

    with pytest.raises(RuntimeError) as e:
        policy_ops.clone_policy(Boom(), Boom(), "pol", new_name="pol-copy",
                                dry_run=True, additive_only=True,
                                wpp_decisions={"x": {}})
    assert "additive" in str(e.value).lower()


def test_the_mode_reaches_the_planner():
    # Not the same claim as "the planner honours the mode", and it needs its own
    # guard: every classification test above drives `ClonePlanner.plan` directly,
    # so `clone_policy` could drop the flag on the floor and all of them would
    # still pass while every run through the dialog wrote into live objects.
    seen = {}

    class FakePlanner:
        src = dst = None

        def plan(self, *a, **k):
            seen.update(k)
            return []

    class FakeOps:
        pass

    policy_ops.clone_policy(FakePlanner(), FakeOps(), "pol", new_name="pol-copy",
                            dry_run=True, additive_only=True)
    assert seen.get("additive_only") is True


def test_a_migration_leaves_the_source_enabled_when_rows_were_held_back(monkeypatch):
    # A migration CLAIMS the two are interchangeable. They are not: the copy is
    # knowingly short, so disabling the source would take the only copy of those
    # rows out of service.
    items = _plan([{"ip": "192.0.2.9"}], [{"ip": "192.0.2.1"}])
    items.append(clone.CloneItem(label="x", urn=IPG, logical="ip-group",
                                 mkey="ipg2", parent_mkey="", kind="object",
                                 depth=0, payload={"name": "ipg2"},
                                 status="create"))
    items[-1].applied = True
    monkeypatch.setattr(policy_ops, "clone_policy", lambda *a, **k: items)
    disabled = []
    monkeypatch.setattr(policy_ops, "set_status",
                        lambda *a, **k: disabled.append(a) or type("R", (), {"ok": True})())
    out = policy_ops.migrate_policy(None, None, None, "pol", new_name="pol",
                                    dry_run=False, additive_only=True)
    assert out["ok"] is True
    assert out["source_disabled"] is False
    assert disabled == []
    assert "additive" in out["source_kept_reason"].lower()


def test_a_migration_still_cuts_over_when_nothing_was_held_back(monkeypatch):
    # The gate must key on the HELD-BACK ROWS, not on the mode being on. A
    # migration in additive mode that had nothing to hold back IS a clean swap.
    items = [clone.CloneItem(label="x", urn=IPG, logical="ip-group",
                             mkey="ipg2", parent_mkey="", kind="object",
                             depth=0, payload={"name": "ipg2"}, status="create")]
    items[0].applied = True
    monkeypatch.setattr(policy_ops, "clone_policy", lambda *a, **k: items)
    monkeypatch.setattr(policy_ops, "set_status",
                        lambda *a, **k: type("R", (), {"ok": True})())
    out = policy_ops.migrate_policy(None, None, None, "pol", new_name="pol",
                                    dry_run=False, additive_only=True)
    assert out["source_disabled"] is True


# --------------------------------------------------------------------------- #
#  The HTTP surface                                                             #
# --------------------------------------------------------------------------- #
def _two_fw(app):
    from app.models import Appliance, db
    with app.app_context():
        ids = []
        for n, h in (("fw-src", "192.0.2.98"), ("fw-dst", "192.0.2.97")):
            a = Appliance(name=n, kind="fortiweb", host=h, port=443,
                          username="admin", verify_ssl=False)
            a.password = "secret"
            db.session.add(a)
            db.session.commit()
            ids.append(a.id)
        return ids


def _capture(app, client, monkeypatch, body):
    src, dst = _two_fw(app)
    login(client, admin_user_id(app))
    seen = {}
    monkeypatch.setattr(policy_ops, "preview",
                        lambda *a, **k: seen.update(k.get("opts") or {}) or [])
    payload = {"action": "clone_to", "policies": ["p1"], "dest_id": dst}
    payload.update(body)
    r = client.post(f"/workspace/{src}/policy-action/preview", json=payload)
    assert r.status_code == 200, r.data
    return seen


def test_the_http_layer_defaults_additive_mode_ON(app, client, monkeypatch):
    # The operator-facing surface is where the safe default belongs: a caller
    # that says nothing gets the posture that does not write into live objects.
    assert _capture(app, client, monkeypatch, {})["additive_only"] is True


def test_the_http_layer_honours_an_explicit_off(app, client, monkeypatch):
    # A default that could not be turned off would make a full migration
    # impossible through the dialog.
    assert _capture(app, client, monkeypatch,
                    {"additive_only": False})["additive_only"] is False


def test_the_engine_default_is_OFF_so_library_callers_are_unchanged(monkeypatch):
    seen = {}
    monkeypatch.setattr(policy_ops, "clone_policy",
                        lambda *a, **k: seen.update(k) or [])
    monkeypatch.setattr(policy_ops, "_planner", lambda *a, **k: None)
    monkeypatch.setattr(policy_ops, "_ops", lambda *a, **k: None)
    policy_ops.perform_one("clone_here", source_appl=object(), policy="p",
                           new_name="p-copy", dry_run=True, opts={})
    assert seen["additive_only"] is False


# --------------------------------------------------------------------------- #
#  The markup the operator actually sees                                        #
# --------------------------------------------------------------------------- #
def _read(rel):
    return io.open(os.path.join(APP, rel), encoding="utf-8").read()


def test_the_dialog_offers_the_switch_and_it_starts_ON():
    html = _read("templates/workspace/policies.html")
    i = html.find('id="actionAdditiveOnly"')
    assert i > 0
    tag = html[html.rfind("<input", 0, i):html.find(">", i) + 1]
    assert "checkbox" in tag and "checked" in tag


def test_the_dialog_sends_the_switch_and_shows_it_only_for_clone_actions():
    html = _read("templates/workspace/policies.html")
    assert "p.additive_only = document.getElementById('actionAdditiveOnly').checked" in html
    # Same visibility condition as every other clone-only field: an option that
    # rendered for `delete` would describe a run that cannot honour it.
    assert ("document.getElementById('actionFieldAdditive').classList.toggle('d-none', !isClone)"
            in html)


def test_changing_the_switch_invalidates_the_preview():
    # The plan on screen was classified with the value that was set when Analyse
    # ran. Leaving it there changes nothing except what the operator believes.
    html = _read("templates/workspace/policies.html")
    i = html.find("getElementById('actionAdditiveOnly').addEventListener('change'")
    assert i > 0
    handler = html[i:i + 260]
    assert "previewDone = false" in handler


def test_the_report_lists_the_held_back_rows_in_their_own_section():
    html = _read("templates/workspace/clone_report.html")
    assert "c.untouched" in html
    i = html.find("Rows NOT added")
    assert i > 0
    section = html[i:i + 900]
    # The parent and the reason, not a count: the count is not the work.
    assert "r.parent_mkey" in section and "r.note" in section


def test_the_report_never_paints_untouched_with_the_grey_of_exists():
    html = _read("templates/workspace/clone_report.html")
    i = html.find("r.status=='untouched'")
    assert i > 0
    cell = html[html.rfind("<td", 0, i):html.find("</td>", i)]
    assert "warning" in cell


# --------------------------------------------------------------------------- #
#  Rendered, not read                                                           #
# --------------------------------------------------------------------------- #
def test_the_switch_survives_an_actual_jinja_render(app, client):
    """The markup guards above read the FILE. A file cannot tell a live block
    from one inside a `{% raw %}{# #}{% endraw %}` comment or a `{% raw %}{% if %}{% endraw %}` that never fires — and
    `checked` written in the source could still render absent if it ever became
    a Jinja expression. This one asks the template engine."""
    aid = _two_fw(app)[0]
    login(client, admin_user_id(app))
    r = client.get(f"/workspace/{aid}")
    assert r.status_code == 200, r.status_code
    html = r.get_data(as_text=True)
    assert 'id="actionFieldAdditive"' in html
    i = html.find('id="actionAdditiveOnly"')
    assert i > 0
    tag = html[html.rfind("<input", 0, i):html.find(">", i) + 1]
    assert "checked" in tag, tag
    assert "Only add what is missing" in html
    assert "p.additive_only = document.getElementById('actionAdditiveOnly').checked" in html
