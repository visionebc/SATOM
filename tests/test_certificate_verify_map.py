"""The Certificate Verify chain: which collection each verify field names.

Nothing failed while this was wrong -- the field simply named the wrong
collection, and every part of the mistake agreed with every other part. The
field sat in a certificate-name role, the node claimed the certificate
collection, and the node hung on an object that has no such field, so the edge
never fired to contradict either half. These tests exist because that shape
produces no error to notice.

Every pairing below was settled by BINDING on a live FortiWeb (fortiweb12,
7.6.8) -- the only test that distinguishes a datasource from a name that merely
looks similar. `set certificate-verify <a real local certificate>` is REJECTED;
the same field accepts a `certificate.verify`. The two verify collections are
NOT interchangeable: each is rejected in the other's field.
"""
import pytest

from app.registry.dependencies import SERVER_POLICY, _CERT_VERIFY_REFS
from app.services.fortiweb_field_schema import KIND_SPECS, REF_ENDPOINTS, ALL_REF_ENDPOINTS

VERIFY = "cmdb/system/certificate.verify"
SCV = "cmdb/system/certificate.server-certificate-verify"


def _children(urn):
    """The direct children of the first node with this urn, breadth-first."""
    stack = [SERVER_POLICY]
    while stack:
        n = stack.pop(0)
        if n.urn == urn:
            return list(n.children)
        stack.extend(n.children)
    return []


def _edges(urn):
    return {c.via: c.urn for c in _children(urn)}


def test_policy_client_verify_names_the_verify_collection():
    edges = _edges("cmdb/server-policy/policy")
    assert edges.get("ssl-client-verify") == VERIFY


def test_no_node_reaches_a_certificate_through_a_verify_field():
    # The exact shape of the defect: a `*-verify` edge pointing at the
    # certificate collection. It made the audit demand a local certificate whose
    # name is not a certificate and never would be -- a block nothing can clear.
    bad = []
    stack = [SERVER_POLICY]
    while stack:
        n = stack.pop()
        if n.urn == "cmdb/system/certificate.local" and "verify" in (n.via or ""):
            bad.append((n.fortiweb, n.via))
        stack.extend(n.children)
    assert bad == []


def test_certificate_verify_is_not_a_policy_field():
    # It is absent from `set ?` on `server-policy policy`, gated or not. Hung
    # there, the edge never fires -- which is how the wrong collection survived.
    assert "certificate-verify" not in _edges("cmdb/server-policy/policy")


def test_the_real_server_row_carries_both_verify_edges():
    edges = _edges("cmdb/server-policy/server-pool/pserver-list")
    assert edges.get("certificate-verify") == VERIFY
    assert edges.get("server-certificate-verify-policy") == SCV


def test_the_two_verify_edges_are_not_swapped():
    # Pinned as a pair, not as presence: a live appliance rejects each object in
    # the other's field, so a swap is a clone that cannot be applied.
    edges = _edges("cmdb/server-policy/server-pool/pserver-list")
    assert edges["certificate-verify"] != edges["server-certificate-verify-policy"]


@pytest.mark.parametrize("via,urn", [
    ("ca", "cmdb/system/certificate.ca-group"),
    ("crl", "cmdb/system/certificate.crl-group"),
])
def test_a_verify_object_names_GROUPS_not_leaf_certificates(via, urn):
    # `set ca <a ca-group>` is accepted on a live verify object. Pointing this at
    # `certificate.ca` would carry the wrong object and leave the group empty --
    # a verify policy that trusts nothing while reporting success.
    assert {c.via: c.urn for c in _CERT_VERIFY_REFS}[via] == urn


def test_both_groups_carry_their_member_subtable():
    for node in _CERT_VERIFY_REFS:
        assert any(g.urn == node.urn + "/members" for g in node.children), node.urn


def test_the_verify_chain_hangs_off_every_verify_node():
    for urn in ("cmdb/server-policy/policy", "cmdb/server-policy/server-pool/pserver-list"):
        for child in _children(urn):
            if child.urn in (VERIFY, SCV):
                assert {c.urn for c in child.children} == {
                    n.urn for n in _CERT_VERIFY_REFS}, child.fortiweb


def test_the_editor_select_offers_names_the_device_accepts():
    refs = KIND_SPECS["pserver"]["refs"]
    assert refs["certificate-verify"] == "system/certificate.verify"
    assert refs["server-certificate-verify-policy"] == \
        "system/certificate.server-certificate-verify"
    # The real server's own client certificate IS still a local certificate.
    assert refs["certificate"] == "system/certificate.local"


def test_the_policy_level_client_verify_select_is_unchanged():
    # This one was already right; the guard stops a fix here from breaking it.
    assert REF_ENDPOINTS["ssl-client-verify"] == "system/certificate.verify"


def test_the_new_collections_are_reachable_by_the_options_endpoint():
    # A select whose collection is not in the allow-list renders empty, which
    # looks exactly like a collection with no rows.
    assert "system/certificate.verify" in ALL_REF_ENDPOINTS
    assert "system/certificate.server-certificate-verify" in ALL_REF_ENDPOINTS


# --------------------------------------------------------------------------- #
#  Certificate MATERIAL (1.6.0 of the standalone clone; same map defect here)   #
# --------------------------------------------------------------------------- #
INTER_GROUP = "cmdb/system/certificate.intermediate-certificate-group"


def _all_nodes():
    out, stack = [], [SERVER_POLICY]
    while stack:
        n = stack.pop()
        out.append(n)
        stack.extend(n.children)
    return out


def test_every_intermediate_ca_group_node_carries_its_members():
    """A chain group with no members node travels as an EMPTY SHELL.

    Nothing fails when it does: the group object is created at the destination
    and reported created, its member rows are never walked, and the copy serves
    a leaf certificate with no intermediates -- which fails verification on
    exactly the clients that do not already cache the issuer. EVERY node, not
    the first: the group appears in the policy tree and again under the SNI
    member row, and fixing one leaves the other shipping an empty group.
    """
    nodes = [n for n in _all_nodes() if n.urn == INTER_GROUP]
    assert nodes, "the intermediate CA group left the map"
    for n in nodes:
        assert any(c.urn == INTER_GROUP + "/members" for c in n.children), \
            "intermediate CA group node has no members sub-table"


def test_the_map_does_not_claim_a_CA_cannot_be_carried():
    """The -7721 refusal is REST's, not the object's.

    Measured on fortiweb12 (7.6.8): the CLI imports a CA with
    `config system certificate ca ; edit "x" ; set certificate "-----BEGIN..."`
    and the object then reads back over REST. A comment asserting the opposite
    is not cosmetic -- it is the sentence a future reader uses to decide that a
    BLOCK is unavoidable, which is exactly what happened in the clone tool.
    """
    import inspect
    from app.registry import dependencies

    src = inspect.getsource(dependencies)
    assert "is a file upload" not in src
