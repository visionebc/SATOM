"""Referential-completeness validator over a LIVE-collected clone tree
(services.clone.validate_completeness) — the hard-block gate that refuses to
clone a tree whose source objects didn't fully resolve live on the box."""
from app.services import clone
from app.registry.dependencies import DepNode


def _node(name, urn, via="", children=()):
    return DepNode(name, urn, via, "", tuple(children))


_WPP = _node("Web Protection Profile", "u/wpp",
             children=(_node("Signature Rule", "u/sig", via="signature-rule"),))
_URN_INDEX = {"u/wpp": "wpp_l", "u/sig": "sig_l"}


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        v = self.data.get((urn, mkey))
        if v is None:
            return []
        return v if isinstance(v, list) else [v]


def _planner(src, dst, index=None):
    p = clone.ClonePlanner(src, dst)
    p.urn_index = dict(index or _URN_INDEX)
    return p


def test_complete_tree_has_no_issues():
    src = FakeReader({
        ("u/wpp", "wpp1"): {"name": "wpp1", "signature-rule": "sig1"},
        ("u/sig", "sig1"): {"name": "sig1"},
    })
    items = _planner(src, FakeReader({})).collect(_WPP, "wpp1")
    assert clone.validate_completeness(items) == []


def test_missing_referenced_object_is_a_blocking_issue():
    # the WPP names sig1 but the source has NO such signature object → the
    # collected tree carries an empty-payload item for it → must be flagged.
    src = FakeReader({
        ("u/wpp", "wpp1"): {"name": "wpp1", "signature-rule": "sig1"},
        # ("u/sig", "sig1") intentionally absent
    })
    items = _planner(src, FakeReader({})).collect(_WPP, "wpp1")
    issues = clone.validate_completeness(items)
    assert len(issues) == 1
    assert issues[0]["mkey"] == "sig1"
    assert issues[0]["urn"] == "u/sig"


def test_empty_root_policy_is_flagged():
    # source device is up but the policy itself is gone → root item empty.
    src = FakeReader({})
    items = _planner(src, FakeReader({})).collect(_WPP, "wpp1")
    issues = clone.validate_completeness(items)
    assert any(i["mkey"] == "wpp1" for i in issues)


def test_certificates_do_not_count_as_missing():
    # a referenced cert never carries a payload over REST — it must NOT block.
    wpp = _node("Web Protection Profile", "u/wpp",
                children=(_node("Cert", "cmdb/system/certificate.local",
                                via="certificate"),))
    src = FakeReader({("u/wpp", "wpp1"): {"name": "wpp1", "certificate": "c1"}})
    items = _planner(src, FakeReader({}),
                     index={"u/wpp": "wpp_l",
                            "cmdb/system/certificate.local": "cert_l"}).collect(wpp, "wpp1")
    assert clone.validate_completeness(items) == []


def test_predefined_fallback_is_not_a_gap():
    # a policy names "HTTP": the tree visits BOTH service.predefined (resolves)
    # and service.custom (empty). The same mkey resolved elsewhere ⇒ NOT a gap.
    a = clone.CloneItem(label="Service", urn="cmdb/server-policy/service.predefined",
                        logical="svc_p", mkey="HTTP", parent_mkey="", kind="object",
                        depth=2, payload={"name": "HTTP"})
    b = clone.CloneItem(label="Custom Service", urn="cmdb/server-policy/service.custom",
                        logical="svc_c", mkey="HTTP", parent_mkey="", kind="object",
                        depth=2, payload={})
    assert clone.validate_completeness([a, b]) == []


def test_genuinely_missing_named_object_is_still_a_gap():
    # a pool the policy names but that resolves nowhere ⇒ real gap.
    a = clone.CloneItem(label="Server Pool", urn="cmdb/server-policy/server-pool",
                        logical="pool", mkey="pool-x", parent_mkey="", kind="object",
                        depth=1, payload={})
    issues = clone.validate_completeness([a])
    assert len(issues) == 1 and issues[0]["mkey"] == "pool-x"
