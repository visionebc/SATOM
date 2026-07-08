"""Server-side HARD BLOCK: services.policy_ops.clone_policy refuses a REAL
write when the collected source tree is incomplete (a referenced object came
back empty). Dry-run preview is unaffected. Duck-typed fakes — no network."""
import pytest
from app.services import clone, policy_ops


def _item(mkey, payload, urn="u/x", kind="object", depth=1):
    return clone.CloneItem(label=mkey.upper(), urn=urn, logical="l", mkey=mkey,
                           parent_mkey="", kind=kind, depth=depth, payload=payload)


class _FakePlanner:
    def __init__(self, items):
        self._items = items
        self.dst = None

    def plan(self, root, policy, **kw):
        for it in self._items:
            it.status = "create" if it.payload else "empty"
        return self._items


class _FakeOps:
    def create(self, *a, **k):
        class _R(dict):
            ok = True
        return _R()


def test_real_apply_blocks_on_incomplete_tree():
    items = [_item("p1", {"name": "p1"}), _item("hc1", {})]  # hc1 empty = gap
    with pytest.raises(RuntimeError) as ei:
        policy_ops.clone_policy(_FakePlanner(items), _FakeOps(), "pol1",
                                new_name="pol2", dry_run=False, disable=False)
    assert "hc1" in str(ei.value)


def test_dry_run_preview_is_not_blocked():
    items = [_item("p1", {"name": "p1"}), _item("hc1", {})]
    out = policy_ops.clone_policy(_FakePlanner(items), _FakeOps(), "pol1",
                                  new_name="pol2", dry_run=True, disable=False)
    assert out is items  # preview still renders the (incomplete) plan


def test_complete_tree_is_allowed():
    items = [_item("p1", {"name": "p1"}), _item("hc1", {"name": "hc1"})]
    out = policy_ops.clone_policy(_FakePlanner(items), _FakeOps(), "pol1",
                                  new_name="pol2", dry_run=False, disable=False)
    assert out is items
