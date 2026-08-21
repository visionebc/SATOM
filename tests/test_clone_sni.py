"""An SNI policy is configuration, not key material.

``clone._CERT_URNS`` carried ``cmdb/system/certificate.sni`` until this fix, and
the consequence was total: the object read ``cert`` ("SSH-only, not cloned over
REST") and every member row then read ``empty`` ("parent object is not being
created"), so an SNI policy NEVER reached the destination while the copied
server policy landed naming it. From the UI "the SNI hosts did not arrive" and
"the policy was refused" look identical.

Measured on fortiweb12 (7.6.8) with this project's own client before a line was
written — the object holds no PEM and neither does the row:

    POST cmdb/system/certificate.sni     {"name": "zzprobe-sni"}       -> 200
    GET  the object back  -> {"name": …, "sz_members": 1}
    POST …/members?mkey=… {"domain": D, "local-cert": C}               -> 200
    GET  the row back     -> domain / local-cert / inter-group /
                             lets-certificate / verify / multi-local-cert…

and end to end, the two payloads the planner builds POSTed to a clean
fortiweb13: 200 and 200, with ``local-cert`` read back intact.

What the ROWS name IS material (the local certificate), which is why the member
node declares that edge instead of leaving it invisible.

Every test here drives the PLANNER. A guard that asserts a phrase is present in
the source cannot tell a live branch from a commented-out one.
"""
from app.services import clone
from app.registry import dependencies as deps
from app.registry.dependencies import DepNode

SNI = "cmdb/system/certificate.sni"
MEM = SNI + "/members"
LOCAL = "cmdb/system/certificate.local"
LETS = "cmdb/system/certificate.letsencrypt"
INTER = "cmdb/system/certificate.intermediate-certificate-group"


class FakeReader:
    """Serves fixture rows by (urn, mkey); anything unknown is empty."""

    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        return [dict(r) for r in self.data.get((urn, mkey), [])]


def _sni_node():
    """The SNI node AS THE REGISTRY DECLARES IT — never a local rebuild.

    Rebuilding the shape here would make every assertion below true of the test
    and say nothing about the tree the product actually walks.
    """
    node = deps.dep_node_for_urn(SNI)
    assert node is not None, "the tree no longer declares an SNI policy node"
    return node


def _plan(src, dst=None, mkey="sni1"):
    p = clone.ClonePlanner(FakeReader(src), FakeReader(dst or {}))
    return p.plan(_sni_node(), mkey)


def _by_urn(items, urn, kind=None):
    return [i for i in items if i.urn == urn and (kind is None or i.kind == kind)]


# --------------------------------------------------------------------------- #
#  1. the classification itself                                                 #
# --------------------------------------------------------------------------- #
def test_an_sni_policy_is_planned_as_a_create_not_as_a_certificate():
    items = _plan({(SNI, "sni1"): [{"name": "sni1"}]})
    obj = _by_urn(items, SNI, "object")
    assert len(obj) == 1
    assert obj[0].status == "create", obj[0].note


def test_the_two_collections_that_really_are_key_material_stay_that_way():
    # The fix removed ONE urn. Removing the set would be the same test passing
    # for the opposite reason.
    assert LOCAL in clone._CERT_URNS
    assert "cmdb/system/certificate.ocsp-signing-certs" in clone._CERT_URNS
    assert SNI not in clone._CERT_URNS


def test_a_local_certificate_is_still_reported_and_never_written():
    items = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "local-cert": "cert-a"}],
                   (LOCAL, "cert-a"): [{"name": "cert-a"}]})
    cert = _by_urn(items, LOCAL, "object")
    assert len(cert) == 1 and cert[0].mkey == "cert-a"
    assert cert[0].status == "cert"
    assert not cert[0].will_create
    assert cert[0].status != "update"


# --------------------------------------------------------------------------- #
#  2. the member rows travel WITH the policy                                    #
# --------------------------------------------------------------------------- #
def test_the_member_rows_are_created_with_the_policy():
    items = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "local-cert": "cert-a"},
                                   {"id": "2", "domain": "b.example",
                                    "local-cert": "cert-b"}]})
    rows = _by_urn(items, MEM, "subrow")
    assert len(rows) == 2
    assert {r.status for r in rows} == {"create"}
    assert {r.payload["domain"] for r in rows} == {"a.example", "b.example"}


def test_the_policy_object_carries_no_content_of_its_own():
    """Why the members node may never become a leaf again.

    The SNI object's whole payload is its name plus a read-only counter, so a
    tree that declares the policy without its rows lands a table with no hosts —
    complete field for field and totally inert, with nothing reporting the gap.
    """
    node = _sni_node()
    members = [c for c in node.children if c.urn == MEM]
    assert len(members) == 1
    assert members[0].children, "SNI members must keep their reference children"


def test_a_row_that_names_no_certificate_pulls_no_certificate_node():
    # A member with an empty ``local-cert`` is an ordinary row. Emitting a node
    # for "" would report a missing certificate named nothing.
    items = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "local-cert": "", "inter-group": "",
                                    "lets-certificate": ""}]})
    assert _by_urn(items, LOCAL) == []
    assert _by_urn(items, LETS) == []
    assert _by_urn(items, INTER) == []


# --------------------------------------------------------------------------- #
#  3. the field is ``local-cert``                                               #
# --------------------------------------------------------------------------- #
def test_the_certificate_field_is_local_cert_and_not_certificate():
    """The spelling the standalone asserted in a comment for two releases.

    A row whose certificate sits in ``certificate`` must pull NOTHING — that is
    the shape of the bug, and a test that only checks the right spelling works
    would pass just as happily if both did.
    """
    right = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "local-cert": "cert-a"}]})
    wrong = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "certificate": "cert-a"}]})
    assert [i.mkey for i in _by_urn(right, LOCAL)] == ["cert-a"]
    assert _by_urn(wrong, LOCAL) == []


def test_the_chain_and_acme_edges_fire_from_their_own_fields():
    items = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "inter-group": "chain-a",
                                    "lets-certificate": "acme-a"}],
                   (INTER, "chain-a"): [{"name": "chain-a"}],
                   (LETS, "acme-a"): [{"name": "acme-a"}]})
    assert [i.mkey for i in _by_urn(items, INTER, "object")] == ["chain-a"]
    assert [i.mkey for i in _by_urn(items, LETS, "object")] == ["acme-a"]


# --------------------------------------------------------------------------- #
#  4. one author per shape                                                      #
# --------------------------------------------------------------------------- #
def test_the_acme_node_is_shared_because_the_field_is_spelled_the_same():
    """``DepNode`` is frozen, so the SAME node serves every parent that can.

    Two literals of one shape is how they drift: the day one gains a sub-table
    and the other does not, half the tree lands an empty shell.
    """
    members = next(c for c in _sni_node().children if c.urn == MEM)
    assert deps._LETSENCRYPT_REF in members.children


def test_the_chain_group_is_reached_by_a_DIFFERENT_field_from_a_policy():
    """One collection, two spellings — measured, not assumed.

    A policy names it ``intermediate-certificate-group``; an SNI member row
    names it ``inter-group``. Sharing one frozen node would have forced one
    spelling on both and the SNI edge would never fire.
    """
    members = next(c for c in _sni_node().children if c.urn == MEM)
    sni_edge = next(c for c in members.children if c.urn == INTER)
    assert sni_edge.via == "inter-group"
    assert deps._INTER_GROUP_REF.via == "intermediate-certificate-group"


def test_both_spellings_declare_the_SAME_sub_table():
    """What must never drift is the sub-table, not the field name.

    A chain group carried without its members serves a leaf certificate with no
    intermediates — the empty-shell trap this project has already hit twice.
    """
    members = next(c for c in _sni_node().children if c.urn == MEM)
    sni_edge = next(c for c in members.children if c.urn == INTER)
    assert sni_edge.children == deps._INTER_GROUP_REF.children
    assert [c.urn for c in sni_edge.children] == [INTER + "/members"]
    assert [c.urn for c in deps._LETSENCRYPT_REF.children] == [LETS + "/san-list"]


# --------------------------------------------------------------------------- #
#  5. what is deliberately NOT declared                                         #
# --------------------------------------------------------------------------- #
def test_the_multi_certificate_group_is_not_given_a_second_parent_here():
    """``multi-local-cert-group`` is reachable from the policy's own
    ``certificate-group`` edge. Declaring it on the SNI row too would give one
    collection two parents in one tree."""
    node = _sni_node()
    members = next(c for c in node.children if c.urn == MEM)
    assert all(c.via != "multi-local-cert-group" for c in members.children)


def test_the_enum_fields_name_nothing():
    items = _plan({(SNI, "sni1"): [{"name": "sni1"}],
                   (MEM, "sni1"): [{"id": "1", "domain": "a.example",
                                    "domain-type": "plain",
                                    "certificate-type": "disable",
                                    "multi-local-cert": "disable"}]})
    # only the policy and its row — no object was invented from an enum value
    assert {i.kind for i in items} == {"object", "subrow"}
    assert len(items) == 2
