"""1.14.0 — the FTP half of a server policy, and the class of object REST
cannot carry.

Every claim here was measured on fortiweb12 (7.6.8) before it was written; the
docstrings say which leg, because the documentation alone was misleading on two
of them (see `test_the_documentation_link_for_the_command_rule_is_wrong`).
"""
import pytest

from app.services import clone
from app.registry import dependencies as deps


FTPP = "cmdb/waf/ftp-protection-profile"
POL = "cmdb/server-policy/policy"


def _node(urn):
    """Find a node by urn anywhere under the server-policy root."""
    def walk(n):
        if n.urn == urn:
            return n
        for kid in getattr(n, "children", ()) or ():
            hit = walk(kid)
            if hit is not None:
                return hit
        return None
    return walk(deps.SERVER_POLICY)


class _ByUrn:
    """A reader that answers per (urn, mkey), so source and destination can
    disagree about exactly one object."""

    def __init__(self, table):
        self._t = table

    def get_raw(self, urn, mkey=""):
        return list(self._t.get((urn, mkey), []))


# ── the map ─────────────────────────────────────────────────────────────────

def test_the_ftp_profile_hangs_off_the_policy_by_its_own_field():
    n = _node(FTPP)
    assert n is not None
    assert n.via == "ftp-protection-profile"


def test_the_ftp_profile_references_point_where_the_cli_reference_says():
    """The mapping is the whole point of this node.

    `ftp-file-check` -> `waf ftp-file-security` and `ftp-geo-ip` ->
    `waf geo-block-list` are NOT the collections their field names suggest, and
    the same-named collections (`cmdb/waf/ftp-file-check`, `cmdb/waf/ftp-geo-ip`)
    DO NOT EXIST — they answer -20001 on fw12. This is the guard that catches
    someone tidying them into the obvious spelling."""
    n = _node(FTPP)
    assert {c.via: c.urn for c in n.children} == {
        "ftp-file-check": "cmdb/waf/ftp-file-security",
        "ftp-geo-ip": "cmdb/waf/geo-block-list",
        "ftp-ip-check": "cmdb/waf/ip-list",
        "ftp-restriction-command-type": "cmdb/waf/ftp-command-restriction-rule",
    }


def test_the_two_shared_references_did_not_duplicate_a_urn():
    """`geo-block-list` and `ip-list` were already in the WPP tree. They add
    EDGES, not URNs — exactly as ADFS did for `certificate.verify`."""
    urns = []

    def walk(n):
        urns.append(n.urn)
        for kid in getattr(n, "children", ()) or ():
            walk(kid)
    for root in deps.ROOTS:
        walk(root)
    assert urns.count("cmdb/waf/geo-block-list") >= 2
    assert urns.count("cmdb/waf/ip-list") >= 2


def test_adfs_certificate_service_names_a_service_not_a_certificate():
    """The field name invites a certificate collection. It is a SERVICE:
    "Select the pre-defined service TLSCLIENTPORT if FortiWeb uses service port
    49443" (7.6 CLI reference), and fw12's service.predefined carries
    TLSCLIENTPORT among its six rows."""
    hit = {c.urn for c in deps.SERVER_POLICY.children
           if "adfs-certificate-service" in (c.via or "")}
    assert hit == {"cmdb/server-policy/service.predefined",
                   "cmdb/server-policy/service.custom"}


def test_the_field_schema_agrees_with_the_tree():
    """Two authors for one mapping is how `index.html` lost its Docs link."""
    from app.services.fortiweb_field_schema import REF_ENDPOINTS as table
    assert table["ftp-protection-profile"] == "waf/ftp-protection-profile"
    assert table["ftp-file-check"] == "waf/ftp-file-security"
    assert table["ftp-geo-ip"] == "waf/geo-block-list"
    assert set(table["adfs-certificate-service"].split("|")) == {
        "server-policy/service.custom", "server-policy/service.predefined"}


# ── the class ───────────────────────────────────────────────────────────────

def test_the_unreachable_table_names_the_profile_and_explains_why():
    assert FTPP in clone._REST_UNREACHABLE
    assert "-20001" in clone._REST_UNREACHABLE[FTPP]


def test_both_empty_payload_exemptions_come_from_one_set():
    assert FTPP in clone._EXEMPT_FROM_GAPS
    assert "cmdb/system/certificate.local" in clone._EXEMPT_FROM_GAPS


def _plan_ftp():
    tree = deps._n("Server Policy", POL, children=[
        deps._n("FTP Protection Profile", FTPP, "ftp-protection-profile")])
    src = _ByUrn({(POL, "pol-ftp"): [{"name": "pol-ftp", "protocol": "FTP",
                                      "ftp-protection-profile": "ftpp-prod"}]})
    return clone.ClonePlanner(src, _ByUrn({})).plan(tree, "pol-ftp")


def test_an_unreachable_reference_classifies_no_rest_not_empty():
    """The set-up IS the failure: neither box can read the collection, so the
    generic path reaches "not found on source" and raises a blocking gap about
    an object that is there. Same emptiness as a genuinely missing object,
    opposite verdict, decided only by the URN."""
    items = [it for it in _plan_ftp() if it.urn == FTPP]
    assert items and items[0].status == "no-rest"


def test_the_unreachable_reference_keeps_the_name_the_policy_gave_it():
    items = [it for it in _plan_ftp() if it.urn == FTPP]
    assert items and items[0].mkey == "ftpp-prod"


def test_an_unreachable_reference_is_not_a_blocking_gap():
    assert clone.validate_completeness(_plan_ftp()) == []


def test_the_classifier_explains_why_the_payload_is_empty():
    items = [it for it in _plan_ftp() if it.urn == FTPP]
    assert items and "-20001" in items[0].note


def test_a_genuinely_missing_object_still_blocks():
    """The other half of the same branch — without it the exemption could be
    widened to everything and nothing would notice."""
    other = "cmdb/server-policy/scripting"
    tree = deps._n("Server Policy", POL, children=[
        deps._n("Web Scripting", other, "scripting-list")])
    src = _ByUrn({(POL, "pol-a"): [{"name": "pol-a", "scripting-list": "lua-a "}]})
    items = clone.ClonePlanner(src, _ByUrn({})).plan(tree, "pol-a")
    assert [g["mkey"] for g in clone.validate_completeness(items)] == ["lua-a"]


def test_a_no_rest_item_is_never_written():
    items = [it for it in _plan_ftp() if it.urn == FTPP]
    assert items and not items[0].will_create


def test_no_rest_has_a_label_of_its_own_distinct_from_no_endpoint():
    """`no-endpoint` means the registry has no writable endpoint for a
    reachable collection. This means the API cannot reach it at all. Folding
    them would tell the operator the wrong thing to do about it."""
    labels = clone.STATUS_LABELS if hasattr(clone, "STATUS_LABELS") else None
    if labels is None:  # name differs across versions; find the dict by content
        labels = next(v for v in vars(clone).values()
                      if isinstance(v, dict) and "no-endpoint" in v
                      and isinstance(v.get("no-endpoint"), str))
    assert labels.get("no-rest") and labels["no-rest"] != labels["no-endpoint"]


def test_the_summary_breaks_no_rest_out_of_skipped():
    """Inside `skipped` it would read as a thing the clone chose not to do,
    next to certs and objects already present, which are inert. This one means
    the destination is missing something the source had."""
    from app.services.policy_ops import clone_summary

    def _it(status):
        i = clone.CloneItem(label="x", urn=FTPP, logical=None, mkey="m",
                            parent_mkey="", kind="object", depth=1, payload={})
        i.status = status
        return i
    # Asserted on the COMPUTED numbers, never on the source text: a window cut
    # out of source by a brace catches the next key too, which is how the first
    # version of this test failed against correct code.
    only_unreachable = clone_summary([_it("no-rest")])
    assert only_unreachable["no_rest"] == 1
    assert only_unreachable["skipped"] == 0
    assert only_unreachable["to_create"] == 0
    # and an inert one still lands in `skipped`, so the two are not swapped
    assert clone_summary([_it("cert")])["skipped"] == 1
    assert clone_summary([_it("cert")])["no_rest"] == 0
