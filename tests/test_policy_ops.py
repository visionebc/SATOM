"""Unit tests for the Server-Policy action engine (services.policy_ops).

Drives the per-policy operations with in-memory fakes (no Flask request, no
network, no device) so the behaviours the workspace row/bulk actions rely on are
locked: the exact disable/enable/delete write bodies, that a clone is left
disabled, and — the safety-critical one — that a MIGRATE disables the source only
when the destination clone landed cleanly (never on a failed clone).
"""
from app.services import policy_ops
from app.services import clone
from app.registry.dependencies import DepNode


# --- fakes ------------------------------------------------------------------
class FakeOps:
    """Records every FortiWebOps call; returns an OpResult-shaped object."""

    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    class _R(dict):
        @property
        def ok(self):
            return bool(self.get("ok"))

    def update(self, endpoint, mkey, data, *, dry_run=True, sub_mkey=None):
        self.calls.append(("update", endpoint, mkey, data, dry_run))
        return self._R(ok=self.ok, dry_run=dry_run, request={"body": data}, error="")

    def delete(self, endpoint, mkey, *, dry_run=True, sub_mkey=None):
        self.calls.append(("delete", endpoint, mkey, dry_run))
        return self._R(ok=self.ok, dry_run=dry_run, request={}, error="")

    def create(self, endpoint, data, *, mkey=None, dry_run=True):
        self.calls.append(("create", endpoint, mkey, data, dry_run))
        return self._R(ok=self.ok, dry_run=dry_run, request={"body": data}, error="")


class FakePlanner:
    """Returns a canned clone plan (one create root item)."""

    def __init__(self, items):
        self._items = items

    def plan(self, root, mkey, *, new_name="", **kw):
        return list(self._items)


def _item(status="create", depth=0, kind="object", mkey="pol"):
    return clone.CloneItem(
        label="Server Policy", urn=clone.ROOT_SERVER_POLICY.urn, logical="server_policy",
        mkey=mkey, parent_mkey="", kind=kind, depth=depth,
        payload={"name": mkey, "status": "enable"}, status=status)


# --- disable / enable -------------------------------------------------------
def test_disable_writes_status_disable():
    ops = FakeOps()
    res = policy_ops.set_status(ops, "pol-x", enable=False, dry_run=True)
    assert res.ok
    action, ep, mkey, data, dry = ops.calls[0]
    assert action == "update" and mkey == "pol-x"
    assert data == {"data": {"status": "disable"}} and dry is True


def test_enable_writes_status_enable():
    ops = FakeOps()
    policy_ops.set_status(ops, "pol-x", enable=True, dry_run=False)
    assert ops.calls[0][3] == {"data": {"status": "enable"}}
    assert ops.calls[0][4] is False  # real apply


# --- delete -----------------------------------------------------------------
def test_delete_calls_ops_delete():
    ops = FakeOps()
    policy_ops.delete_policy(ops, "pol-x", dry_run=False)
    assert ops.calls[0][0] == "delete" and ops.calls[0][1] == policy_ops.EP_POLICY
    assert ops.calls[0][2] == "pol-x"


# --- clone (disabled root) --------------------------------------------------
def test_clone_leaves_root_disabled():
    items = [_item(status="create")]
    planner = FakePlanner(items)
    ops = FakeOps()
    out = policy_ops.clone_policy(planner, ops, "pol", new_name="pol-copy",
                                  dry_run=False, disable=True)
    root = next(it for it in out if it.depth == 0)
    assert root.payload.get("status") == "disable"   # disable_root applied
    # a create landed through ops.create
    assert any(c[0] == "create" for c in ops.calls)


def test_clone_reports_created_and_failed_counts():
    planner = FakePlanner([_item(status="create"), _item(status="exists", mkey="dep")])
    ops = FakeOps(ok=True)
    summary = policy_ops.clone_summary(
        policy_ops.clone_policy(planner, ops, "pol", new_name="c", dry_run=False))
    assert summary["created"] == 1 and summary["exists"] == 1 and summary["failed"] == 0


# --- migrate: source disabled ONLY on a clean clone -------------------------
def test_migrate_disables_source_when_clone_clean():
    planner = FakePlanner([_item(status="create")])
    dst_ops = FakeOps(ok=True)
    src_ops = FakeOps(ok=True)
    r = policy_ops.migrate_policy(planner, dst_ops, src_ops, "pol",
                                  new_name="pol", dry_run=False)
    assert r["ok"] and r["source_disabled"] is True
    # the source op was a status=disable update
    assert ("update", policy_ops.EP_POLICY, "pol",
            {"data": {"status": "disable"}}, False) in src_ops.calls


def test_migrate_keeps_source_live_when_clone_fails():
    planner = FakePlanner([_item(status="create")])
    dst_ops = FakeOps(ok=False)   # every dest write fails
    src_ops = FakeOps(ok=True)
    r = policy_ops.migrate_policy(planner, dst_ops, src_ops, "pol",
                                  new_name="pol", dry_run=False)
    assert r["ok"] is False and r["source_disabled"] is False
    assert src_ops.calls == []    # source never touched on a failed clone


def test_migrate_dry_run_never_touches_source():
    planner = FakePlanner([_item(status="create")])
    dst_ops = FakeOps(ok=True)
    src_ops = FakeOps(ok=True)
    r = policy_ops.migrate_policy(planner, dst_ops, src_ops, "pol",
                                  new_name="pol", dry_run=True)
    assert r["source_disabled"] is False and src_ops.calls == []
