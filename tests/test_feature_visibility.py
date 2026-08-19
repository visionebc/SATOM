"""``system feature-visibility`` gating guards.

FortiWeb hides a whole menu branch for every feature-visibility toggle left
``disable`` — all 19 are ``disable`` on a stock 7.6.8 unit — and until 2026-08-19
this port read the object but never obeyed it, so the sidebar offered API Gateway,
Web Cache, Padding Oracle Protection, Mobile API Protection, System → Firewall,
ICAP Server and reCAPTCHA on appliances whose own GUI shows none of them.

Nothing FAILS when a gate goes stale — the menu simply stops matching the
appliance, silently, which is precisely how the gap survived. So the guards fix
the three properties that carry real consequence:

* the gate table can only name toggles that were MEASURED and logicals that
  EXIST (a typo in either is a gate that quietly never fires);
* unknown evidence must SHOW, never hide (a never-synced device must not lose
  its menu);
* ``feature_visibility`` itself must stay reachable — it is the operator's only
  way to turn a feature back on, so gating it would be a one-way door.
"""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
#  Gate-table integrity                                                        #
# --------------------------------------------------------------------------- #
def test_every_gate_names_a_measured_toggle():
    from app.services import feature_visibility as fv

    unknown = sorted(set(fv.GATES) - fv.TOGGLES)
    assert unknown == [], (
        "GATES names toggles absent from the live-measured TOGGLES set: %s. A "
        "misspelt toggle never matches a device payload, so its gate is dead "
        "and the menu keeps showing a branch FortiWeb hides." % unknown)


def test_every_toggle_is_either_gated_or_recorded_as_unmapped():
    """A toggle in neither table is an oversight wearing the same face as a
    decision. ``wad`` (anti-defacement) has no object in this registry — that is
    a FACT worth recording, not a blank to leave."""
    from app.services import feature_visibility as fv

    accounted = set(fv.GATES) | fv.UNMAPPED_TOGGLES
    assert sorted(fv.TOGGLES - accounted) == []
    assert not (set(fv.GATES) & fv.UNMAPPED_TOGGLES), (
        "a toggle cannot be both mapped and recorded as unmapped")


def test_every_gated_logical_exists_in_the_registry(app):
    from app.registry import loader
    from app.services import feature_visibility as fv

    with app.app_context():
        names = {e["name"] for e in loader.get_all_endpoints()
                 if isinstance(e, dict) and e.get("name")}
    missing = sorted(l for s in fv.GATES.values() for l in s if l not in names)
    assert missing == [], (
        "GATES names logicals no endpoint provides: %s" % missing)


def test_feature_visibility_is_never_itself_gated():
    """The escape hatch. Hiding this leaf would leave an operator with no way,
    inside SATOM, to turn a feature back on — the menu could only ever shrink."""
    from app.services import feature_visibility as fv

    assert "feature_visibility" in fv.NEVER_GATED
    for toggle, logicals in fv.GATES.items():
        assert "feature_visibility" not in logicals, toggle


def test_gates_carry_only_top_level_cmdb_objects(app):
    """Only TOP-LEVEL cmdb leaves are gated. A sub-table is reached by drilling
    into its parent's editor, and rows vanishing mid-editor is a different
    behaviour from FortiWeb hiding a menu branch; a non-cmdb urn is a live-status
    read that no menu ever offers, so gating one is a gate that cannot fire.
    (``wvs_threat_weight`` is exactly that — ``/api/v2.0/wvs/threat-weight``,
    no ``/cmdb/`` — and this guard is what caught it.)"""
    from app.registry import loader
    from app.services import feature_visibility as fv
    from app.services.config_sections import _is_subrow, _collection_of

    with app.app_context():
        urns = {e["name"]: (e.get("urn") or e.get("path") or "")
                for e in loader.get_all_endpoints()
                if isinstance(e, dict) and e.get("name")}
    gated = sorted(l for s in fv.GATES.values() for l in s)
    non_cmdb = [l for l in gated if "/cmdb/" not in urns.get(l, "")]
    assert non_cmdb == [], non_cmdb
    subrows = [l for l in gated if _is_subrow(_collection_of(urns.get(l, "")))]
    assert subrows == [], subrows


# --------------------------------------------------------------------------- #
#  Reading the cached toggles                                                  #
# --------------------------------------------------------------------------- #
def _seed(app, payload, *, appliance_name="fw-test"):
    """Create an appliance carrying one cached feature_visibility row."""
    from app.extensions import db
    from app.models import Appliance
    from app.models_cache import DeviceObject

    with app.app_context():
        appl = Appliance(name=appliance_name, host="192.0.2.1", port=443,
                         kind="fortiweb", username="admin")
        appl.password = "pw"
        db.session.add(appl)
        db.session.flush()
        if payload is not None:
            db.session.add(DeviceObject(
                appliance_id=appl.id, layer="config", section="System",
                logical_name="feature_visibility",
                urn="/api/v2.0/cmdb/system/feature-visibility",
                payload=payload, depth=0, idx=0))
        db.session.commit()
        return appl.id


def test_unknown_device_hides_nothing(app):
    """Fail OPEN. An appliance that was never synced, a device id that does not
    exist, no device at all — each must yield the pre-gating menu. Guessing
    "hidden" on absent evidence takes pages away from an operator because a
    sync has not run yet."""
    from app.services import feature_visibility as fv

    aid = _seed(app, None)
    with app.app_context():
        assert fv.hidden_logicals(aid) == frozenset()
        assert fv.hidden_logicals(None) == frozenset()
        assert fv.hidden_logicals(9_999_999) == frozenset()
        assert fv.toggles_for(aid) == {}


def test_only_the_literal_word_disable_hides(app):
    """``enable`` shows. So does a value this code has never seen: the only safe
    reading of "I do not understand this" is "leave it visible"."""
    from app.services import feature_visibility as fv

    aid = _seed(app, {
        "api-gateway": "disable", "api-gateway_val": "0",
        "web-cache": "enable", "web-cache_val": "1",
        "firewall": "somethingelse",
        "padding-oracle": "DISABLE",       # case is not signal
    })
    with app.app_context():
        off = fv.disabled_features(aid)
        assert "api-gateway" in off
        assert "padding-oracle" in off
        assert "web-cache" not in off
        assert "firewall" not in off
        hidden = fv.hidden_logicals(aid)
        assert "api_policy" in hidden
        assert "web_cache_policy" not in hidden
        assert "system_firewall_address" not in hidden


def test_the_val_twins_are_not_mistaken_for_toggles(app):
    """The wire payload doubles every key with a numeric ``<key>_val``. Reading
    those as toggles would invent 19 features that do not exist."""
    from app.services import feature_visibility as fv

    aid = _seed(app, {"api-gateway": "disable", "api-gateway_val": "0"})
    with app.app_context():
        assert set(fv.toggles_for(aid)) == {"api-gateway"}


# --------------------------------------------------------------------------- #
#  The menus actually obey                                                     #
# --------------------------------------------------------------------------- #
_ALL_OFF = {t: "disable" for t in (
    "ftp-security", "ztna", "traffic-mirror", "mobile-app-identification",
    "adfs-policy", "acceleration-policy", "web-cache", "support-ajax-requests",
    "wccp-mode", "wvs", "api-gateway", "firewall", "padding-oracle", "wad",
    "fortigate-integration", "support-icap-server", "debug-log", "recaptcha",
    "cryptographic-key")}


@pytest.mark.parametrize("section,group", [
    ("api_protection", "API Gateway"),
    ("api_protection", "Mobile API Protection"),
    ("system", "Firewall"),
])
def test_a_fully_gated_group_drops_out_of_the_section_menu(app, section, group):
    from app.services import config_sections as cs, feature_visibility as fv

    aid = _seed(app, dict(_ALL_OFF))
    with app.app_context():
        hidden = fv.hidden_logicals(aid)
        before = {g.label for g in cs.section_menu(section, complete=False)}
        after = {g.label for g in cs.section_menu(section, complete=False,
                                                  hidden=hidden)}
        assert group in before
        assert group not in after


def test_gating_never_removes_the_feature_visibility_leaf(app):
    from app.services import config_sections as cs, feature_visibility as fv

    aid = _seed(app, dict(_ALL_OFF))
    with app.app_context():
        hidden = fv.hidden_logicals(aid)
        leaves = {i.logical for g in cs.section_menu("system", hidden=hidden)
                  for i in g.items}
        assert "feature_visibility" in leaves


def test_web_protection_drops_padding_oracle_only(app):
    from app.services import feature_visibility as fv, wp_menu

    aid = _seed(app, dict(_ALL_OFF))
    with app.app_context():
        hidden = fv.hidden_logicals(aid)
        wp_menu._registry_index.cache_clear()
        wp_menu.menu.cache_clear()
        before = {it.key for g in wp_menu.menu() for it in g.items}
        after = {it.key for g in wp_menu.menu(hidden) for it in g.items}
        assert before - after == {"padding-oracle"}


def test_server_objects_drops_traffic_mirror(app):
    from app.services import feature_visibility as fv, server_objects as so

    aid = _seed(app, dict(_ALL_OFF))
    with app.app_context():
        hidden = fv.hidden_logicals(aid)
        before = {g.label for g in so.server_objects_menu()}
        after = {g.label for g in so.server_objects_menu(hidden=hidden)}
        assert before - after == {"Traffic Mirror"}


def test_no_gated_collection_hides_behind_a_second_logical(app):
    """The PREMISE the bucket suppression rests on, guarded rather than
    defended against. ``_remaining_types`` drops a hidden object by its LOGICAL
    name; that is only sufficient while no gated collection is also reachable
    under a second, non-gated logical. Measured 2026-08-19: zero such aliases.

    If this ever fires, the fix is to suppress the bucket by COLLECTION too —
    not to relax this assert. An earlier draft of this change shipped that
    collection-level suppression pre-emptively; it was removed because no
    mutation could distinguish working code from dead code, which is the exact
    defect class the rest of this file exists to prevent."""
    from app.services import config_catalog as cc, config_sections as cs
    from app.services import feature_visibility as fv

    with app.app_context():
        gated = {l for s in fv.GATES.values() for l in s}
        eps = cs._endpoint_index()
        by_coll = {}
        for logical in gated:
            ep = eps.get(logical)
            if ep:
                by_coll[cs._norm_coll(cs._collection_of(
                    ep.get("urn") or ep.get("path") or ""))] = logical
        aliases = []
        for sk in cs.curated_sections():
            try:
                catalog = cc.section_catalog(sk)
            except Exception:  # noqa: BLE001 - uncatalogued section
                continue
            for o in catalog:
                coll = cs._norm_coll(cs._collection_of(
                    o.get("urn") or o.get("path") or ""))
                if coll in by_coll and o.get("logical") not in gated:
                    aliases.append((sk, coll, o.get("logical")))
    assert aliases == [], aliases


def test_a_gated_leaf_does_not_reappear_in_the_other_objects_bucket(app):
    """A leaf removed from the curated groups frees its collection, and the
    trailing "everything else" bucket is fed by the whole registry catalog — so
    without an explicit skip the gate would hide an entry from one part of the
    section menu and hand it straight back in another."""
    from app.services import config_sections as cs, feature_visibility as fv

    aid = _seed(app, dict(_ALL_OFF))
    with app.app_context():
        hidden = fv.hidden_logicals(aid)
        colls = set()
        for section in ("api_protection", "application_delivery", "system"):
            for g in cs.section_menu(section, complete=True, hidden=hidden):
                colls |= {cs._norm_coll(i.collection) for i in g.items}
        for gated in ("waf/api-policy", "waf/web-cache-policy",
                      "waf/cache-policy", "system/firewall.address"):
            assert gated not in colls, gated


def test_the_page_resolvers_stay_ungated(app):
    """feature-visibility is a MENU control on FortiWeb, not an access control:
    the objects stay readable and writable over CLI/REST with the feature off.
    So the section page must go on resolving a gated type — otherwise flipping a
    toggle breaks every bookmark and deep link into it, which FortiWeb does not
    do."""
    from app.services import config_sections as cs, wp_menu

    with app.app_context():
        assert cs.type_for("system", "system_firewall_address") is not None
        assert cs.group_of("api_protection", "api_policy") is not None
        wp_menu.menu.cache_clear()
        assert wp_menu.item_for("padding-oracle") is not None
