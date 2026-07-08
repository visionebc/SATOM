"""Unit tests for the clone/migrate policy layer:

* ``services.clone_rules`` — the admin-configurable dummy-IP rule engine
  (10.x → 240.x, 162.x → 241.x by default) + config validation;
* the clone-engine transforms the dialog drives: ``clone.set_vip_ip`` (explicit
  IP and per-VIP transform), ``clone.rename_wpp`` (copy the WPP under a new
  name, re-pointing the policy), and ``ClonePlanner`` WPP pruning
  (``follow_wpp=False`` — "don't copy the Web Protection Profile").

Pure fakes — no Flask app, no network, no device.
"""
import pytest

from app.services import clone, clone_rules
from app.registry.dependencies import DepNode


# --------------------------------------------------------------------------- #
#  Rule engine (pure)                                                           #
# --------------------------------------------------------------------------- #
_CFG = {
    "ip_rules": [{"match": "10", "replace": "240"},
                 {"match": "162", "replace": "241"}],
    "fallback_ip": "203.0.113.9",
    "copy_wpp_default": True,
}


def test_dummy_ip_10_becomes_240():
    assert clone_rules.dummy_ip("192.0.2.1", _CFG) == "240.1.10.1"


def test_dummy_ip_162_becomes_241():
    assert clone_rules.dummy_ip("162.5.0.9", _CFG) == "241.5.0.9"


def test_dummy_ip_no_match_uses_fallback():
    assert clone_rules.dummy_ip("192.168.1.4", _CFG) == "203.0.113.9"


def test_dummy_ip_accepts_cidr_and_garbage():
    assert clone_rules.dummy_ip("192.0.2.226/32", _CFG) == "240.0.0.226"
    assert clone_rules.dummy_ip("", _CFG) == "203.0.113.9"
    assert clone_rules.dummy_ip("not-an-ip", _CFG) == "203.0.113.9"


def test_dummy_ip_multi_octet_rule():
    cfg = {**_CFG, "ip_rules": [{"match": "10.1", "replace": "240.9"}]}
    assert clone_rules.dummy_ip("192.0.2.1", cfg) == "240.9.10.1"
    assert clone_rules.dummy_ip("192.0.2.1", cfg) == "203.0.113.9"  # no match


def test_dummy_ip_first_match_wins():
    cfg = {**_CFG, "ip_rules": [{"match": "10.1", "replace": "250.1"},
                                {"match": "10", "replace": "240"}]}
    assert clone_rules.dummy_ip("192.0.2.3", cfg) == "250.1.2.3"
    assert clone_rules.dummy_ip("192.0.2.3", cfg) == "240.9.2.3"


def test_validate_rule():
    assert clone_rules.validate_rule("10", "240") == ""
    assert clone_rules.validate_rule("10.1", "240.2") == ""
    assert clone_rules.validate_rule("10", "240.1") != ""    # octet count mismatch
    assert clone_rules.validate_rule("300", "240") != ""     # octet out of range
    assert clone_rules.validate_rule("192.0.2.3", "9.9.9.9") != ""  # too long


def test_rules_summary_mentions_every_rule():
    s = clone_rules.rules_summary(_CFG)
    assert "10.x → 240.x" in s and "162.x → 241.x" in s and "203.0.113.9" in s


# --------------------------------------------------------------------------- #
#  set_vip_ip                                                                   #
# --------------------------------------------------------------------------- #
def _vip_item(mkey, ip, status="create"):
    return clone.CloneItem(
        label="VIP", urn=clone._VIP_URN, logical="vip", mkey=mkey,
        parent_mkey="", kind="object", depth=3,
        payload={"name": mkey, "vip": ip, "interface": "port1"}, status=status)


def test_set_vip_ip_explicit_keeps_mask():
    items = [_vip_item("vip-a", "192.0.2.226/32")]
    changed = clone.set_vip_ip(items, ip="240.0.0.226")
    assert items[0].payload["vip"] == "240.0.0.226/32"
    assert changed == ["vip-a: 192.0.2.226 → 240.0.0.226"]


def test_set_vip_ip_transform_per_vip():
    items = [_vip_item("vip-a", "192.0.2.1/32"), _vip_item("vip-b", "162.5.0.9/24")]
    clone.set_vip_ip(items, transform=lambda ip: clone_rules.dummy_ip(ip, _CFG))
    assert items[0].payload["vip"] == "240.1.1.1/32"
    assert items[1].payload["vip"] == "241.5.0.9/24"


def test_set_vip_ip_skips_existing_vips():
    items = [_vip_item("vip-a", "192.0.2.1/32", status="exists")]
    changed = clone.set_vip_ip(items, ip="240.1.1.1")
    assert changed == [] and items[0].payload["vip"] == "192.0.2.1/32"


# --------------------------------------------------------------------------- #
#  rename_wpp                                                                   #
# --------------------------------------------------------------------------- #
def _wpp_item(name):
    return clone.CloneItem(
        label="Web Protection Profile", urn=clone._WPP_INLINE,
        logical="webprotection_profile_inline", mkey=name, parent_mkey="",
        kind="object", depth=1, payload={"name": name, "signature-rule": "sig1"})


def _policy_item(name, wpp):
    return clone.CloneItem(
        label="Server Policy", urn="cmdb/server-policy/policy",
        logical="server_policy", mkey=name, parent_mkey="", kind="object",
        depth=0, payload={"name": name, "web-protection-profile": wpp})


def test_rename_wpp_repoints_policy_reference():
    items = [_wpp_item("wpp1"), _policy_item("pol1", "wpp1")]
    old = clone.rename_wpp(items, "wpp1-fw2")
    assert old == "wpp1"
    assert items[0].mkey == "wpp1-fw2"
    assert items[0].payload["name"] == "wpp1-fw2"
    assert items[1].payload["web-protection-profile"] == "wpp1-fw2"


def test_rename_wpp_noop_without_wpp():
    items = [_policy_item("pol1", "wpp1")]
    assert clone.rename_wpp(items, "x") == ""
    assert items[0].payload["web-protection-profile"] == "wpp1"


# --------------------------------------------------------------------------- #
#  ClonePlanner: follow_wpp pruning + wpp rename/suffix in plan()               #
# --------------------------------------------------------------------------- #
def _node(name, urn, via="", children=()):
    return DepNode(name, urn, via, "", tuple(children))


# Policy-shaped synthetic tree: the policy NAMES a pool and a WPP; the WPP node
# carries its own child so clone._rich never splices the full real profile in.
_WPP_NODE = _node("Web Protection Profile", clone._WPP_INLINE,
                  via="web-protection-profile",
                  children=(_node("Member", clone._WPP_INLINE + "/member"),))
_POLICY = _node("Server Policy", "u/policy",
                children=(_node("Pool", "u/pool", via="server-pool"), _WPP_NODE))

# ClonePlanner._lg keys its index by the NORMALISED collection (objform), so
# real cmdb urns must be indexed through the same normaliser.
_URNS = {clone.objform.collection_of(u): l for u, l in {
    "u/policy": "server_policy", "u/pool": "server_pool",
    clone._WPP_INLINE: "webprotection_profile_inline",
    clone._WPP_INLINE + "/member": "wpp_member"}.items()}

_SRC = {
    ("u/policy", "pol1"): {"name": "pol1", "server-pool": "pool1",
                           "web-protection-profile": "wpp1", "status": "enable"},
    ("u/pool", "pool1"): {"name": "pool1"},
    (clone._WPP_INLINE, "wpp1"): {"name": "wpp1"},
    (clone._WPP_INLINE + "/member", "wpp1"): [{"id": "1"}],
}


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        v = self.data.get((urn, mkey))
        if v is None:
            return []
        return v if isinstance(v, list) else [v]


def _planner(src=None, dst=None):
    p = clone.ClonePlanner(FakeReader(src or _SRC), FakeReader(dst or {}))
    p.urn_index = dict(_URNS)
    return p


def test_plan_carries_wpp_by_default():
    items = _planner().plan(_POLICY, "pol1", new_name="pol2")
    urns = [it.urn for it in items]
    assert clone._WPP_INLINE in urns


def test_plan_follow_wpp_false_prunes_profile_subtree():
    items = _planner().plan(_POLICY, "pol1", new_name="pol2", follow_wpp=False)
    assert all(not it.urn.startswith(clone._WPP_INLINE) for it in items)
    # the copy still NAMES the profile — the checklist guards its presence
    root = next(it for it in items if it.depth == 0)
    assert root.payload["web-protection-profile"] == "wpp1"
    # the pool is untouched by the pruning
    assert any(it.urn == "u/pool" for it in items)


def test_plan_wpp_new_name_renames_and_repoints():
    items = _planner().plan(_POLICY, "pol1", new_name="pol2",
                            wpp_new_name="wpp1-fw2")
    wpp = next(it for it in items if it.urn == clone._WPP_INLINE)
    root = next(it for it in items if it.depth == 0)
    assert wpp.mkey == "wpp1-fw2"
    assert root.payload["web-protection-profile"] == "wpp1-fw2"
    # WPP-owned sub-rows follow the rename
    member = next(it for it in items if it.urn == clone._WPP_INLINE + "/member")
    assert member.parent_mkey == "wpp1-fw2"


def test_plan_wpp_suffix_bulk_mode():
    items = _planner().plan(_POLICY, "pol1", new_name="pol2", wpp_suffix="-fw2")
    wpp = next(it for it in items if it.urn == clone._WPP_INLINE)
    root = next(it for it in items if it.depth == 0)
    assert wpp.mkey == "wpp1-fw2"
    assert root.payload["web-protection-profile"] == "wpp1-fw2"


def test_plan_renamed_wpp_is_create_even_if_original_exists_at_dst():
    dst = {(clone._WPP_INLINE, "wpp1"): {"name": "wpp1"}}
    items = _planner(dst=dst).plan(_POLICY, "pol1", new_name="pol2",
                                   wpp_new_name="wpp1-v2")
    wpp = next(it for it in items if it.urn == clone._WPP_INLINE)
    assert wpp.status == "create"   # the new name does not exist at the dest
