"""The clone/migrate SOURCE gate decision (services.policy_ops._source_gate).

Hard block: a clone may only proceed when the source was read LIVE and the whole
dependency tree resolved. Pure decision — no Flask, no DB, no device."""
from app.services import policy_ops


def test_device_error_is_a_hard_block():
    c = policy_ops._source_gate("pol1", "fw7", live_ok=False,
                                src_err="license of peer VM not valid (-20010)",
                                root_present=False, issues=[])
    assert c["level"] == "block"
    assert "-20010" in c["detail"]
    # never falls back to cache
    assert "cache" in c["detail"].lower()


def test_missing_policy_is_a_hard_block():
    c = policy_ops._source_gate("pol1", "fw7", live_ok=True, src_err="",
                                root_present=False, issues=[])
    assert c["level"] == "block"
    assert "pol1" in c["label"]


def test_incomplete_tree_is_a_hard_block_naming_objects():
    issues = [{"object": "Server Pool", "mkey": "pool-shop-api", "urn": "u/p"},
              {"object": "Health Check", "mkey": "hc-api", "urn": "u/h"}]
    c = policy_ops._source_gate("pol1", "fw7", live_ok=True, src_err="",
                                root_present=True, issues=issues)
    assert c["level"] == "block"
    assert "INCOMPLETE" in c["label"]
    assert "pool-shop-api" in c["detail"]
    assert "hc-api" in c["detail"]


def test_live_and_complete_is_ok():
    c = policy_ops._source_gate("pol1", "fw7", live_ok=True, src_err="",
                                root_present=True, issues=[])
    assert c["level"] == "ok"


def test_no_warn_level_ever():
    # the whole point: the source gate is block-or-ok, never a soft warn.
    for kw in (dict(live_ok=False, src_err="x", root_present=False, issues=[]),
               dict(live_ok=True, src_err="", root_present=False, issues=[]),
               dict(live_ok=True, src_err="", root_present=True,
                    issues=[{"object": "P", "mkey": "m", "urn": "u"}]),
               dict(live_ok=True, src_err="", root_present=True, issues=[])):
        assert policy_ops._source_gate("p", "fw", **kw)["level"] in ("block", "ok")
