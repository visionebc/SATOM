"""objform — recursive object-editor structure engine (pure, registry-backed)."""
from __future__ import annotations

from app.services import objform


def _segs(urn):
    return {s["seg"] for s in objform.subtables_for(urn)}


def test_collection_normalisation():
    assert objform.collection_of("/api/v2.0/cmdb/server-policy/server-pool") == "server-policy/server-pool"
    assert objform.collection_of("cmdb/server-policy/vserver") == "server-policy/vserver"
    assert objform.collection_of("server-policy/policy?mkey=pol-x") == "server-policy/policy"
    assert objform.collection_of("server-policy/server-pool") == "server-policy/server-pool"


def test_rest_and_scoped_paths():
    assert objform.rest_path("server-policy/server-pool") == "/api/v2.0/cmdb/server-policy/server-pool"
    p = objform.scoped_path("server-policy/server-pool/pserver-list", "pool-x")
    assert p == "/api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey=pool-x"
    p2 = objform.scoped_path("server-policy/server-pool/pserver-list", "pool x", 3)
    assert p2.endswith("&sub_mkey=3")
    assert "mkey=pool%20x" in p2  # parent name url-encoded


def test_object_kind_curated_vs_generic():
    assert objform.object_kind("server-policy/server-pool") == "pool"
    assert objform.object_kind("/api/v2.0/cmdb/server-policy/server-pool/pserver-list") == "pserver"
    assert objform.object_kind("server-policy/vserver/vip-list") == "vip"
    assert objform.object_kind("waf/signature") == "ref"  # generic fallback


def test_subtables_derived_from_registry():
    # pool owns its real-server list; vserver owns its VIP list
    assert "pserver-list" in _segs("server-policy/server-pool")
    assert "vip-list" in _segs("server-policy/vserver")
    assert "health-list" in _segs("server-policy/health")
    # SNI certificate owns its domain→cert members (a dot sub-type WITH a sub-table)
    assert "members" in _segs("system/certificate.sni")


def test_namespace_is_not_a_parent():
    # 'server-policy' is a namespace, not an object → no sub-tables, and the pool
    # is NOT mis-filed as its child
    assert objform.subtables_for("server-policy") == []
    # a '.' sub-type is its own object, never a by-parent row of the base
    assert "server-pool.server-balance-rule" not in _segs("server-policy/server-pool")


def test_object_form_shape():
    form = objform.object_form("server-policy/server-pool",
                               {"name": "p", "type": "reverse-proxy", "health": "hc"})
    assert form["kind"] == "pool"
    assert form["rest_path"].endswith("server-pool")
    assert isinstance(form["groups"], list)
    assert "pserver-list" in {s["seg"] for s in form["subtables"]}


def test_row_label():
    assert objform.row_label({"name": "srv1"}) == "srv1"
    assert objform.row_label({"id": 5}) == "5"
    assert objform.row_label({}) == ""
