"""Deep-capture walker tests — driven with an in-memory fake reader that
faithfully models clone.ClientReader (get_raw lists a top-level collection;
get_object resolves a logical -> urn via the registry then does the scoped
?mkey= read). No network, no DB."""
from app.services import deep_capture
from app.services.clone import _logical_to_urn
from app.services.objform import collection_of


class FakeReader:
    """Models clone.ClientReader over in-memory data keyed by bare-cmdb urn.

    ``by_urn`` = ``{urn: {parent_mkey_or_"": [rows]}}``. A top-level collection
    lives under the ``""`` key; a by-parent sub-table's rows live under the
    parent's mkey. Everything is matched on the normalised collection so bare
    ``cmdb/...`` urns and full ``/api/v2.0/cmdb/...`` registry paths line up.
    """

    def __init__(self, by_urn):
        self.by_coll = {collection_of(u): v for u, v in by_urn.items()}

    def get_raw(self, urn, mkey=""):
        return list(self.by_coll.get(collection_of(urn), {}).get(mkey or "", []))

    def get_object(self, logical, mkey=""):
        urn = _logical_to_urn(logical)
        if not urn:
            return []
        return self.get_raw(urn, mkey)


def test_collect_server_policy_nests_pool_members():
    reader = FakeReader({
        "cmdb/server-policy/policy": {"": [{"name": "pol-a", "server-pool": "pool-a",
                                            "deployment-mode": "server-pool"}]},
        "cmdb/server-policy/server-pool": {"": [{"name": "pool-a", "type": "round-robin"}]},
        "cmdb/server-policy/server-pool/pserver-list": {
            "pool-a": [{"id": "1", "ip": "192.0.2.5", "port": "443"}]},
    })
    graph = deep_capture.collect_server_policy(reader, "pol-a")
    # the policy row carries its pool as a nested object, members nested under it
    assert graph["name"] == "pol-a"
    pool = graph["_deep"]["server_pool"]
    assert pool["name"] == "pool-a"
    assert pool["_deep"]["pserver-list"][0]["ip"] == "192.0.2.5"


def test_deep_sections_lists_all_policies_and_wpps():
    reader = FakeReader({
        "cmdb/server-policy/policy": {"": [{"name": "pol-a", "server-pool": "pool-a"}]},
        "cmdb/server-policy/server-pool": {"": [{"name": "pool-a"}]},
        "cmdb/waf/web-protection-profile.inline-protection":
            {"": [{"name": "wpp-a", "signature-rule": "sig-a"}]},
        "cmdb/waf/signature": {"": [{"name": "sig-a"}]},
    })
    sections = deep_capture.deep_sections(reader)
    assert "pol-a" in [p["name"] for p in sections["Server Policy"]["server_policy"]]
    assert "wpp-a" in [w["name"]
                       for w in sections["Web Protection"]["web_protection_profile"]]
    # the WPP carries its bound signature set nested under _deep
    wpp = sections["Web Protection"]["web_protection_profile"][0]
    assert "signature" in wpp["_deep"]
