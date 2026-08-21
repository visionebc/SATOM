"""Rows the destination already owns — the unique-key collision (standalone 1.11.0).

Until this port, a by-parent sub-table row was classified by asking "is this
EXACT row already at the destination?" (:func:`clone._subrow_in`). The appliance
does not ask that. It enforces uniqueness on a NATURAL KEY — a SUBSET of the row
— so a destination row carrying the same key with DIFFERENT content is ABSENT to
the planner and PRESENT to the box: the plan says create, the box refuses the
duplicate, and the destination keeps serving the old value under a run that
reports a device error the operator cannot act on.

Measured on FortiWeb 7.6.8 (build 1128), fortiweb12, not inferred:

    certificate.sni/members   {domain: D, local-cert: C}  -> 200
                              {domain: D}                 -> -5 duplicate
                              {domain: D, local-cert: C}  -> -5 duplicate
                              {domain: D2, local-cert: C} -> 200

The key is ``domain`` ALONE — which is exactly why "the host is already listed
but is served no certificate" was unreachable through a create. ``ip-group/
members`` is keyed on ``ip`` and answers a DIFFERENT code (-6014), so nothing
here is built on recognising -5.

These tests exercise the PLANNER and the WRITER, never the presence of a string:
a guard that asserts a phrase is in the source cannot tell a live branch from a
commented-out one.
"""
import pytest

from app.services import clone, policy_ops
from app.registry.dependencies import DepNode

# The vehicle is the IP GROUP, not the SNI policy: the product classifies
# certificate.sni as key material (_CERT_URNS), so an SNI policy never
# travels over REST at all today and its keyed collision is unreachable. That is
# a SEPARATE gap against the standalone (which carries SNI as plain
# configuration since 1.2.0) and it is reported, not silently worked around.
SNI = "cmdb/server-policy/ip-group"
MEM = SNI + "/members"
POOL = "cmdb/server-policy/server-pool"
PSERVER = POOL + "/pserver-list"

ROOT = DepNode("IP Group", SNI, children=(DepNode("IP Group Members", MEM),))
POOL_ROOT = DepNode("Server Pool", POOL,
                    children=(DepNode("Real Servers", PSERVER),))


class FakeReader:
    """Answers ``get_raw(urn, mkey)`` from a dict; nothing else is needed."""

    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        return [dict(r) for r in self.data.get((urn, mkey), [])]


def _plan(src_rows, dst_rows, root=ROOT, urn=SNI, mem=MEM, mkey="ipg1"):
    src = FakeReader({(urn, mkey): [{"name": mkey}], (mem, mkey): src_rows})
    dst = FakeReader({(urn, mkey): [{"name": mkey}], (mem, mkey): dst_rows})
    p = clone.ClonePlanner(src, dst)
    return p.plan(root, mkey)


def _rows(items, urn):
    return [i for i in items if i.urn == urn and i.kind == "subrow"]


# --------------------------------------------------------------------------- #
#  The key table itself                                                         #
# --------------------------------------------------------------------------- #
def test_only_measured_tables_declare_a_key():
    assert clone.subrow_key_fields(MEM) == ("ip",)
    assert clone.subrow_key_fields("cmdb/system/certificate.sni/members") == ("domain",)
    # A sub-table nobody measured keeps the OLD behaviour exactly. Guessing a key
    # here would silently overwrite a row that was never a conflict.
    assert clone.subrow_key_fields(PSERVER) == ()


def test_the_lookup_does_not_miss_on_the_cmdb_prefix():
    # The tree writes urns prefixed; a registry/probe path may not. A lookup that
    # missed on shape would silently disable the whole reconcile.
    assert clone.subrow_key_fields("server-policy/ip-group/members") == ("ip",)


# --------------------------------------------------------------------------- #
#  Classification                                                               #
# --------------------------------------------------------------------------- #
def test_a_row_the_destination_owns_by_key_is_planned_as_an_update():
    items = _plan([{"id": "1", "ip": "192.0.2.1", "port": "8080"}],
                  [{"id": "7", "ip": "192.0.2.1", "port": "9090"}])
    row = _rows(items, MEM)[0]
    assert row.status == "update"
    # Addressed by the DESTINATION row's id — the source's id names an unrelated
    # row on the other box, and using it would be a silent cross-write.
    assert row.dst_row_key == "7"
    assert row.dst_row.get("port") == "9090"


def test_the_note_names_the_key_and_what_the_destination_serves_today():
    items = _plan([{"id": "1", "ip": "192.0.2.1", "port": "8080"}],
                  [{"id": "7", "ip": "192.0.2.1", "port": "9090"}])
    note = _rows(items, MEM)[0].note
    assert "ip=192.0.2.1" in note
    # "a duplicate" says nothing about WHICH of the two is on the wire.
    assert "9090" in note and "8080" in note


def test_a_row_with_no_collision_is_still_a_create():
    items = _plan([{"id": "1", "ip": "192.0.2.9", "port": "c"}],
                  [{"id": "7", "ip": "192.0.2.8", "port": "c"}])
    assert _rows(items, MEM)[0].status == "create"


def test_an_identical_row_is_exists_and_never_an_update():
    # Same key AND same content is `_subrow_in`'s "exists"; calling it a conflict
    # would plan a write that changes nothing on every re-run.
    items = _plan([{"id": "1", "ip": "192.0.2.1", "port": "c"}],
                  [{"id": "7", "ip": "192.0.2.1", "port": "c"}])
    assert _rows(items, MEM)[0].status == "exists"


def test_an_unmeasured_subtable_keeps_the_old_behaviour():
    items = _plan([{"id": "1", "ip": "192.0.2.1", "port": "8080"}],
                  [{"id": "7", "ip": "192.0.2.1", "port": "9090"}],
                  root=POOL_ROOT, urn=POOL, mem=PSERVER, mkey="pool1")
    assert _rows(items, PSERVER)[0].status == "create"


def test_a_blank_key_value_never_collides():
    # A blank is not an identity: two rows that both leave the key empty are not
    # the same row, and pairing them would reconcile an unrelated row.
    assert clone.subrow_conflict({"ip": "", "port": "c"},
                                 [{"id": "7", "ip": "", "port": "x"}],
                                 MEM) == {}


# --------------------------------------------------------------------------- #
#  The minimum edit                                                             #
# --------------------------------------------------------------------------- #
def test_the_update_body_keeps_destination_fields_the_source_never_names():
    body = clone.subrow_update_payload(
        {"id": "1", "ip": "192.0.2.1", "port": "8080"},
        {"id": "7", "ip": "192.0.2.1", "port": "9090",
         "ssl": "disable"}, MEM)
    assert body["port"] == "8080"
    assert body["ssl"] == "disable"


def test_a_blank_on_the_source_does_not_clear_the_destination_field():
    # A blank means "this box does not use this field", not "delete whatever the
    # other box has". Carrying blanks would be a change with no line in the plan.
    body = clone.subrow_update_payload(
        {"id": "1", "ip": "192.0.2.1", "port": ""},
        {"id": "7", "ip": "192.0.2.1", "port": "9090"}, MEM)
    assert body["port"] == "9090"


def test_the_body_carries_the_destination_row_id_not_the_sources():
    body = clone.subrow_update_payload(
        {"id": "1", "ip": "192.0.2.1", "port": "c"},
        {"id": "7", "ip": "192.0.2.1", "port": "x"}, MEM)
    assert body["id"] == "7"


# --------------------------------------------------------------------------- #
#  The write                                                                    #
# --------------------------------------------------------------------------- #
def _update_item():
    return clone.CloneItem(
        label="IP Group Members", urn=MEM, logical=None, mkey="1",
        parent_mkey="ipg1", kind="subrow", depth=1,
        payload={"id": "1", "ip": "192.0.2.1", "port": "8080"},
        status="update", dst_row_key="7",
        dst_row={"id": "7", "ip": "192.0.2.1", "port": "9090"})


def test_apply_clone_writes_update_items_and_says_updated():
    it = _update_item()
    seen = []
    clone.apply_clone([it], lambda x: seen.append(x), dry_run=False)
    assert seen == [it]
    assert it.applied is True and it.result == "updated"


def test_a_dry_run_never_writes_an_update():
    it = _update_item()
    seen = []
    clone.apply_clone([it], lambda x: seen.append(x), dry_run=True)
    assert seen == [] and it.result == "dry-run"


def test_an_update_is_counted_apart_from_a_creation():
    it = _update_item()
    it.applied, it.result = True, "updated"
    made = clone.CloneItem(label="x", urn=SNI, logical=None, mkey="ipg1",
                           parent_mkey="", kind="object", depth=0, payload={},
                           status="create")
    made.applied, made.result = True, "created"
    s = policy_ops.clone_summary([it, made])
    # An operator reading only `created` would be told a row was MADE that was
    # not: it was an edit of a row the destination already served.
    assert s["created"] == 1 and s["updated"] == 1


def test_the_plan_text_marks_an_update_apart_from_create_and_exists():
    it = _update_item()
    line = clone.render_plan([it]).splitlines()[0]
    assert not line.startswith("+") and not line.startswith("=")


# --------------------------------------------------------------------------- #
#  The gate — off REFUSES, it does not skip                                     #
# --------------------------------------------------------------------------- #
class FakePlanner:
    def __init__(self, items):
        self._items, self.dst = items, FakeReader({})

    def plan(self, *a, **kw):
        return list(self._items)


class FakeRes:
    ok = True

    def get(self, k, d=None):
        return d


class FakeOps:
    def __init__(self):
        self.calls = []

    def create(self, ep, data, *, mkey=None, dry_run=True):
        self.calls.append(("create", ep, mkey, None, data))
        return FakeRes()

    def update(self, ep, mkey, data, *, dry_run=True, sub_mkey=None):
        self.calls.append(("update", ep, mkey, sub_mkey, data))
        return FakeRes()


def test_reconciliation_off_refuses_a_real_apply_instead_of_skipping():
    # A skipped row would leave the destination serving the old value under a
    # GREEN run — the failure this whole feature exists to end.
    with pytest.raises(RuntimeError) as e:
        policy_ops.clone_policy(FakePlanner([_update_item()]), FakeOps(), "p1",
                                new_name="p1-copy", dry_run=False,
                                reconcile_rows=False)
    assert "reconciliation is OFF" in str(e.value)


def test_reconciliation_off_on_a_dry_run_says_so_without_raising():
    items = [_update_item()]
    out = policy_ops.clone_policy(FakePlanner(items), FakeOps(), "p1",
                                  new_name="p1-copy", dry_run=True,
                                  reconcile_rows=False)
    assert out[0].status != "update"
    assert "REFUSED" in out[0].note


def test_the_writer_puts_addressed_by_the_destination_row_id():
    ops = FakeOps()
    policy_ops.clone_policy(FakePlanner([_update_item()]), ops, "p1",
                            new_name="p1-copy", dry_run=False, disable=False)
    action, _ep, mkey, sub_mkey, data = ops.calls[0]
    assert action == "update"
    assert mkey == "ipg1"          # the PARENT addresses the sub-table
    assert sub_mkey == "7"         # the DESTINATION row addresses the row
    assert data["data"]["port"] == "8080"


def test_reconciliation_is_on_by_default_for_both_the_dialog_and_the_bulk_job():
    # perform_one is the ONE function the single-policy dialog and the bulk job
    # both call, so the default read there is the default of a 60-policy run.
    import inspect
    src = inspect.getsource(policy_ops.perform_one)
    assert 'opts.get("reconcile_rows", True)' in src
    assert src.count("reconcile_rows=reconcile_rows") == 3


def test_subrow_conflict_does_not_call_an_identical_row_a_conflict():
    # Tested DIRECTLY, and deliberately so. On the planner path the content
    # match (_subrow_in) reaches the same verdict first, so this guard is
    # never exercised there — it is the FUNCTION's contract, not a second gate
    # in front of the same hole, and a contract nothing exercises is a claim
    # nobody can check.
    assert clone.subrow_conflict(
        {"id": "1", "ip": "192.0.2.1", "port": "8080"},
        [{"id": "7", "ip": "192.0.2.1", "port": "8080"}], MEM) == {}
    # ...while a real difference on the same key IS one.
    assert clone.subrow_conflict(
        {"id": "1", "ip": "192.0.2.1", "port": "8080"},
        [{"id": "7", "ip": "192.0.2.1", "port": "9090"}],
        MEM).get("id") == "7"
