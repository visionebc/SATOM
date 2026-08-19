"""Advanced SSL Settings — the four edges a policy only grows when SSL is on.

Why this file exists at all: on FortiWeb 7.6.8 the fields that name these
objects DO NOT EXIST on a policy whose ``ssl`` is ``disable``.  ``set
hpkp-header ?`` answers ``Parsing error at 'hpkp-header'`` — not an empty
datasource.  Measured on fortiweb12 by flipping ``set ssl enable`` inside a live
edit context and re-running ``set ?``: eleven fields appear that were absent one
command earlier.  So a lab of HTTP policies produces no reference to them, and
their absence from the dependency graph could never be contradicted by cloning.

Everything asserted here was measured on a live appliance, and the shapes are
asserted BY URN rather than by label: a renamed node is cosmetic, a re-pointed
node is a clone that lands naming an object the destination has never had.
"""
import pytest

from app.registry.dependencies import SERVER_POLICY, _CERT_VERIFY_REFS


@pytest.fixture(scope="module")
def edges():
    """via-field -> urn, for the direct children of the server policy."""
    return {c.via: c.urn for c in SERVER_POLICY.children}


@pytest.fixture(scope="module")
def by_urn():
    out = {}
    for c in SERVER_POLICY.children:
        out.setdefault(c.urn, []).append(c)
    return out


# --------------------------------------------------------------------------- #
#  The edges themselves                                                        #
# --------------------------------------------------------------------------- #
def test_https_header_insertion_edge_names_the_hpkp_profile(edges):
    """`hpkp-header` is the HTTPS Header Insertion dropdown."""
    assert edges.get("hpkp-header") == "cmdb/system/certificate.hpkp"


def test_url_certificate_edge_names_the_urlcert_group(edges):
    assert edges.get("urlcert-group") == "cmdb/system/certificate.urlcert"


def test_multi_certificate_edge_names_multi_local_not_certificate_local(edges):
    """The obvious wrong answer is `certificate.local`, and it is wrong.

    Measured: `set certificate-group ?` offers rows tagged
    ``system certificate.multi-local``.  Pointing this edge at the leaf
    collection would make the audit demand a certificate by the GROUP's name --
    a block the operator can never clear.
    """
    assert edges.get("certificate-group") == "cmdb/system/certificate.multi-local"


def test_adfs_verify_reuses_the_client_verify_collection(edges):
    """Settled by BINDING, not by the similarity of the two field names: both
    answer ``<datasource>  SSL client certificate verify`` on a live box."""
    assert (edges.get("adfs-certificate-ssl-client-verify")
            == "cmdb/system/certificate.verify")


# --------------------------------------------------------------------------- #
#  The shapes — measured, so an edit cannot invent structure the box lacks     #
# --------------------------------------------------------------------------- #
def test_urlcert_group_carries_its_list_subtable(by_urn):
    """The empty-shell trap in its purest form.

    `set ?` on a urlcert group answers a parse error -- it has NO scalar fields
    at all -- and `config ?` completes to exactly one sub-table, `list`, whose
    rows are (url, require).  Carried without its rows the group arrives field
    for field complete and totally inert.
    """
    nodes = by_urn.get("cmdb/system/certificate.urlcert", [])
    assert len(nodes) == 1
    assert [g.urn for g in nodes[0].children] == [
        "cmdb/system/certificate.urlcert/list"]


def test_the_hpkp_profile_is_flat_and_names_nothing(by_urn):
    """`config ?` inside an HPKP object is a parse error: no sub-table.

    And it references nothing -- the pins are base64 SPKI fingerprints, plain
    strings, not certificate names.  (`pin-sha256` IS space-separated with a
    trailing space, exactly like `scripting-list`; it is deliberately absent
    from `_LIST_REF_FIELDS`, which is for fields naming OBJECTS.)
    """
    nodes = by_urn.get("cmdb/system/certificate.hpkp", [])
    assert len(nodes) == 1
    assert nodes[0].children == ()


def test_multi_certificate_group_carries_its_three_certificates(by_urn):
    """rsa-cert / ecc-cert / dsa-cert are each their own `<datasource>` onto
    `system certificate.local`.  A group that travels alone lands naming up to
    three certificates the destination has never seen."""
    nodes = by_urn.get("cmdb/system/certificate.multi-local", [])
    assert len(nodes) == 1
    kids = nodes[0].children
    assert [g.urn for g in kids] == ["cmdb/system/certificate.local"]
    named = {t.strip() for t in kids[0].via.split("/") if t.strip()}
    assert named == {"rsa-cert", "ecc-cert", "dsa-cert"}


def test_adfs_verify_carries_the_same_refs_as_the_client_one(by_urn):
    nodes = [c for c in SERVER_POLICY.children
             if c.via == "adfs-certificate-ssl-client-verify"]
    assert len(nodes) == 1
    assert nodes[0].children == _CERT_VERIFY_REFS


# --------------------------------------------------------------------------- #
#  Registry backing — a node the registry cannot resolve is a node that fails  #
#  at fetch time, not at import time                                           #
# --------------------------------------------------------------------------- #
def test_every_new_collection_is_registered(app):
    """The GROUP being registered while its ROWS are not is exactly how a group
    travels as an empty shell.  Three sibling sub-tables were already missing
    when this was written; they are registered in the same change."""
    import yaml, io, os
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "endpoints.yaml")
    urns = set(yaml.safe_load(io.open(path, encoding="utf-8")).values())
    for tail in ("system/certificate.hpkp",
                 "system/certificate.urlcert",
                 "system/certificate.urlcert/list",
                 "system/certificate.multi-local",
                 "system/certificate.ca-group/members",
                 "system/certificate.crl-group/members",
                 "system/certificate.intermediate-certificate-group/members"):
        assert "/api/v2.0/cmdb/" + tail in urns, tail
