"""Server Objects menu — the menu IS the claim, so the claim is pinned.

Nothing fails when a curated menu drifts from the appliance: the page keeps
rendering, the sidebar keeps linking, and the operator simply never sees the
objects that were never modelled. That is exactly how this menu shipped for
months with 10 Certificate entries against FortiWeb's 12, three of them tabs
promoted to entries, one of them pointing at a collection that answers HTTP 500
on every FortiWeb.

The expectations below are transcribed from TWO independent oracles:

* the appliance's own Angular bundle (``main.<hash>.js``, FortiWeb 7.6.8) — the
  literal menu the box renders, entries + tab routes;
* the 7.6 admin guide's ``Server Objects > …`` GUI paths (554 pages swept).

Every collection listed here was also GET-probed live on fortiweb11 (7.6.8):
all 40 answer HTTP 200; ``system/certificate.intermediate`` answers 500 /
errcode -20001, which is why it is pinned as absent.
"""
import re

import pytest

from app.services import config_sections as cs
from app.services import server_objects as so


# --------------------------------------------------------------------------- #
#  The tree, transcribed from the bundle: (group, [(page, [(logical, tab)])])   #
# --------------------------------------------------------------------------- #
EXPECTED = [
    ("Server", [
        ("Virtual Server", [("vserver", "Virtual Server")]),
        ("Server Pool", [("server_pool", "Server Pool")]),
        ("Health Check", [("server_pool_health_check", "Health Check")]),
        ("Persistence", [("server_pool_persistence", "Persistence")]),
        ("HTTP Content Routing", [("http_content_routing", "HTTP Content Routing")]),
    ]),
    ("Protected Hostnames", [
        ("Protected Hostnames", [("allow_host", "Protected Hostnames")]),
    ]),
    ("Service", [
        ("Service", [("services_predefined", "Predefined"),
                     ("services_custom", "Custom")]),
    ]),
    ("Traffic Mirror", [
        ("Traffic Mirror", [("traffic_mirror_profile", "Traffic Mirror")]),
    ]),
    ("Certificates", [
        ("Local", [("certificate", "Local"),
                   ("system_certificate_multi_local", "Multi-certificate")]),
        ("Let's Encrypt", [("certificate_letsencrypt", "Let's Encrypt")]),
        ("XML Certificate", [("xml_server_certificate", "Server Certificate"),
                             ("xml_client_certificate", "Client Certificate"),
                             ("xml_client_certificate_group", "Client Certificate Group")]),
        ("URL Certificate", [("system_certificate_urlcert", "URL Certificate")]),
        ("SNI", [("certificate_sni", "Inline SNI"),
                 ("system_certificate_offline_sni", "Offline SNI")]),
        ("CA", [("certificate_ca", "CA"),
                ("certificate_tsl_ca", "TSL CA"),
                ("certificate_ca_group", "CA Group")]),
        ("Sign CA", [("system_certificate_sign_ca", "Sign CA")]),
        ("Intermediate CA", [("system_certificate_intermediate_certificate", "Intermediate CA"),
                             ("certificate_intermediate_group", "Intermediate CA Group")]),
        ("CRL", [("certificate_crl", "CRL"),
                 ("system_certificate_crl_group", "CRL Group")]),
        ("Certificate Verify", [("system_certificate_verify", "Certificate Verify"),
                                ("system_certificate_server_certificate_verify",
                                 "Server Certificate Verify")]),
        ("OCSP", [("certificate_ocsp_stapling", "OCSP")]),
        ("Public Key Pinning", [("system_certificate_hpkp", "Public Key Pinning")]),
    ]),
    ("SSL Ciphers", [
        ("SSL Ciphers", [("ssl_cyphers", "Predefined"),
                         ("ssl_cyphers_custom", "Custom")]),
    ]),
    ("Global", [
        ("Global Allow List", [("global_allow_list_predefined", "Predefined"),
                               ("global_allow_list_custom", "Custom")]),
        ("Policy Based Allow List", [("allow_list", "Policy Based Allow List")]),
        ("Data Type", [("data_type_custom", "Data Type")]),
        ("URL Replacer", [("url_replacer_rule", "Replacer Rule"),
                          ("url_replacer_policy", "Replacer Policy")]),
    ]),
    ("X-Forwarded-For", [
        ("X-Forwarded-For", [("x_forwarded_for", "X-Forwarded-For")]),
    ]),
    ("IP Group", [
        ("IP Group", [("ip_group", "IP Group")]),
    ]),
]

#: The collection that does not exist on ANY FortiWeb (500 / -20001) and the one
#: that does. They differ by a suffix, which is how the wrong one survived.
PHANTOM = "system/certificate.intermediate"
REAL_INTERMEDIATE = "system/certificate.intermediate-certificate"


def _menu():
    return so.server_objects_menu()


# --------------------------------------------------------------------------- #
#  Structure                                                                   #
# --------------------------------------------------------------------------- #
def test_top_level_entries_match_the_appliance_menu():
    assert [g.label for g in _menu()] == [g for g, _ in EXPECTED]


def test_certificates_has_twelve_entries_in_gui_order():
    certs = [g for g in _menu() if g.label == "Certificates"][0]
    assert len(certs.items) == 12
    assert [p.label for p in certs.items] == [
        p for p, _ in dict(EXPECTED)["Certificates"]
    ]


@pytest.mark.parametrize("group_label,pages", EXPECTED)
def test_group_pages_and_their_tabs(group_label, pages):
    group = [g for g in _menu() if g.label == group_label]
    assert group, "group %r missing from the menu" % group_label
    got = [(p.label, [(t.logical, t.label) for t in p.tabs]) for p in group[0].items]
    assert got == [(label, list(tabs)) for label, tabs in pages]


def test_every_tab_resolves_to_a_registry_collection():
    for _g, _p, tab in so.iter_tabs():
        assert tab.urn, "%s has no urn" % tab.logical
        assert tab.collection and "/" in tab.collection, tab.collection


def test_no_logical_and_no_collection_is_listed_twice():
    logicals = [t.logical for _g, _p, t in so.iter_tabs()]
    collections = [t.collection for _g, _p, t in so.iter_tabs()]
    assert len(logicals) == len(set(logicals))
    assert len(collections) == len(set(collections))


# --------------------------------------------------------------------------- #
#  The phantom collection                                                      #
# --------------------------------------------------------------------------- #
def test_intermediate_ca_points_at_the_collection_that_exists():
    tab = so.tab_for("system_certificate_intermediate_certificate")
    assert tab is not None
    assert tab.collection == REAL_INTERMEDIATE


def test_phantom_intermediate_collection_is_nowhere_in_the_menu():
    for _g, _p, tab in so.iter_tabs():
        assert tab.logical != "certificate_intermediate"
        assert tab.collection != PHANTOM


def test_phantom_is_suppressed_in_the_generic_browse_too():
    # Fixing only the curated menu would leave the 500 reachable through the
    # Configuration section's "everything else" list.
    assert PHANTOM in cs._PHANTOM_COLLECTIONS


# --------------------------------------------------------------------------- #
#  Virtual IP moved to Network — and did not fall off the UI on the way        #
# --------------------------------------------------------------------------- #
def test_virtual_ip_is_not_a_server_object():
    assert "vip" not in [t.logical for _g, _p, t in so.iter_tabs()]


def test_virtual_ip_is_reachable_from_the_network_section():
    logicals = [i.logical for g in cs.section_menu("network") for i in g.items]
    assert "vip" in logicals


# --------------------------------------------------------------------------- #
#  Page / tab lookup contract                                                  #
# --------------------------------------------------------------------------- #
def test_find_resolves_every_tab_to_its_own_page():
    for _g, page, tab in so.iter_tabs():
        hit = so.find(tab.logical)
        assert hit is not None
        assert hit[0].label == page.label
        assert hit[1].logical == tab.logical


def test_type_for_resolves_a_non_default_tab_to_its_page():
    # ?type=<non-default tab> used to 404: type_for only knew flat leaves.
    page = so.type_for("system_certificate_multi_local")
    assert page is not None and page.label == "Local"


def test_page_logicals_cover_every_tab():
    for _g, page, _t in so.iter_tabs():
        assert set(page.logicals) == {t.logical for t in page.tabs}


def test_page_mirrors_its_first_tab():
    for _g, page, _t in so.iter_tabs():
        head = page.tabs[0]
        assert (page.logical, page.urn, page.collection, page.read_only) == (
            head.logical, head.urn, head.collection, head.read_only)


def test_tabbed_only_when_more_than_one_collection():
    for _g, page, _t in so.iter_tabs():
        assert page.tabbed == (len(page.tabs) > 1)


def test_flat_groups_are_the_ones_fortiweb_renders_flat():
    flat = {g.label for g in _menu() if g.flat}
    assert flat == {"Protected Hostnames", "Service", "Traffic Mirror",
                    "SSL Ciphers", "X-Forwarded-For", "IP Group"}


def test_single_tab_page_repeats_its_own_label():
    for _g, page, _t in so.iter_tabs():
        if not page.tabbed:
            assert page.tabs[0].label == page.label


def test_predefined_tabs_are_read_only():
    ro = {t.logical for _g, _p, t in so.iter_tabs() if t.read_only}
    assert ro == {"services_predefined", "ssl_cyphers",
                  "global_allow_list_predefined"}


# --------------------------------------------------------------------------- #
#  The Configuration section reuses the SAME menu — flattened, not truncated   #
# --------------------------------------------------------------------------- #
def test_configuration_browse_lists_every_tab():
    # The section also appends every OTHER top-level object the registry files
    # here (server_pool_rule…), so this is containment, not equality — what must
    # never happen is a curated tab going missing from the browse.
    menu = cs.section_menu("server_objects")
    listed = {i.logical for g in menu for i in g.items}
    assert {t.logical for _g, _p, t in so.iter_tabs()} <= listed


def test_configuration_browse_qualifies_multi_tab_labels():
    menu = cs.section_menu("server_objects")
    labels = {i.logical: i.label for g in menu for i in g.items}
    assert labels["system_certificate_multi_local"] == "Local — Multi-certificate"
    assert labels["certificate"] == "Local"          # tab == page → not doubled
    assert labels["ip_group"] == "IP Group"


# --------------------------------------------------------------------------- #
#  Template/view wiring — the halves that no data test can see                 #
# --------------------------------------------------------------------------- #
def _strip_comments(text, jinja=True):
    """Comments name the very identifiers these guards forbid/require."""
    if jinja:
        text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return re.sub(r"^\s*#.*$", "", text, flags=re.M)


def _read(rel):
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()


def test_sidebar_matches_on_every_logical_of_an_entry():
    html = _strip_comments(_read("app/templates/base.html"))
    block = html[html.index("fw-so-nav"):html.index("fw-so-nav") + 4000]
    assert "request.args.get('type') in item.logicals" in block
    # The old equality check leaves the sidebar dead on a non-default tab.
    assert "request.args.get('type') == item.logical" not in block


def test_overview_renders_a_tab_strip_only_for_tabbed_pages():
    html = _strip_comments(_read("app/templates/server_objects/overview.html"))
    assert "page.tabbed" in html
    assert "for t in page.tabs" in html
    assert "t.logical == selected.logical" in html


def test_view_passes_the_page_and_selects_by_tab():
    src = _strip_comments(_read("app/views/server_objects.py"), jinja=False)
    assert "so.find(logical)" in src
    assert "page=page" in src
