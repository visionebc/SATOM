"""The menu-SET guard: nothing may leave the WAF menus silently.

``test_wp_parity`` asserts tab ORDER and COLUMNS for five hand-picked items. It
cannot see a deletion: drop "Advanced Protection" from ``wp_menu._TREE``, or the
whole "XML Protection" group from ``config_sections``, and every test in this
repo still passes. That is the same failure shape ``test_license_consistency``
was written for — nothing fails when an artefact goes stale, the claim just
quietly stops being true — except here the artefact is the operator's map of the
appliance.

So this guard freezes the WHOLE curated set: every group label and every leaf, for
``wp_menu`` and for each curated section of ``config_sections``. The baseline lives
in ``tests/fixtures/menu_inventory.json``.

Regenerating that fixture is meant to be a DELIBERATE act, so the totals below are
hard-coded in this file rather than derived from the fixture. A blind regeneration
that silently drops entries still trips :func:`test_inventory_totals` — the point
of the second copy is precisely that it does not move when the first one does.

Scope: labels and logical names only. Icons are cosmetic and would make this
fixture churn on every restyle for no protection.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "menu_inventory.json"

# Independently maintained totals — see the module docstring. Bump these ONLY
# when a menu really changed, and say why in the commit.
EXPECTED_WP_GROUPS = 7
EXPECTED_WP_ITEMS = 22
EXPECTED_SECTIONS = 12
EXPECTED_SECTION_GROUPS = 66
EXPECTED_SECTION_LEAVES = 210


def _baseline() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _live_wp(app) -> dict[str, list[str]]:
    from app.services import wp_menu
    with app.app_context():
        wp_menu._registry_index.cache_clear()
        wp_menu.menu.cache_clear()
        return {g.label: [it.label for it in g.items] for g in wp_menu.menu()}


def _live_sections(app) -> dict[str, dict[str, list[str]]]:
    from app.services import config_sections as cs
    with app.app_context():
        return {sk: {g.label: [i.logical for i in g.items]
                     for g in cs.section_menu(sk, complete=False)}
                for sk in sorted(cs.curated_sections())}


def test_web_protection_menu_set_is_unchanged(app):
    assert _live_wp(app) == _baseline()["wp"]


def test_config_section_menu_sets_are_unchanged(app):
    live = _live_sections(app)
    base = _baseline()["sections"]
    assert sorted(live) == sorted(base), "a whole section appeared or vanished"
    for key in sorted(base):
        assert live[key] == base[key], "section %r drifted" % key


def test_inventory_totals(app):
    """The redundant count. Its only job is to survive a blind re-baseline of
    the fixture — so it is written here, by hand, and not read from it."""
    wp = _live_wp(app)
    sec = _live_sections(app)
    assert len(wp) == EXPECTED_WP_GROUPS
    assert sum(len(v) for v in wp.values()) == EXPECTED_WP_ITEMS
    assert len(sec) == EXPECTED_SECTIONS
    assert sum(len(g) for g in sec.values()) == EXPECTED_SECTION_GROUPS
    assert sum(len(v) for g in sec.values() for v in g.values()) == \
        EXPECTED_SECTION_LEAVES


# --------------------------------------------------------------------------- #
#  The promoted-areas single source                                            #
# --------------------------------------------------------------------------- #
def test_machine_learning_and_tracking_are_waf_areas():
    """FortiWeb files these two alongside the other five protection areas — the
    7.6.4 guide puts ML Based Anomaly Detection inside the Web Protection
    chapter. In this port they sat in the generic Configuration bucket next to
    System / Network / Log & Report until 2026-08-19."""
    from app.services import config_sections as cs

    assert set(cs.WAF_AREA_KEYS) == {
        "application_delivery", "api_protection", "bot_mitigation",
        "dos_protection", "ip_protection", "machine_learning", "tracking"}
    assert cs.WAF_AREA_KEYS == tuple(k for k, _l, _i in cs.WAF_AREAS)


def test_the_promoted_area_list_has_exactly_one_author():
    """The list used to exist three times — the nav builder's exclusion set, the
    nav builder's render loop and a literal in base.html. Promoting an area then
    meant editing three places, and a miss showed the area twice (or left the
    sidebar group collapsed on the very page the operator had just opened)."""
    from app.services import config_sections as cs

    root = Path(__file__).resolve().parents[1]
    keys = list(cs.WAF_AREA_KEYS)
    for rel in ("app/__init__.py", "app/templates/base.html"):
        text = (root / rel).read_text(encoding="utf-8")
        # Strip comments/Jinja comments first: the comment that EXPLAINS this
        # rule legitimately names the areas, and an assert that matches its own
        # rationale is the eighth of its kind in this repo.
        body = "\n".join(l for l in text.splitlines()
                         if not l.lstrip().startswith("#"))
        body = body.replace("{#", "\n{#")
        body = "\n".join(chunk.split("#}", 1)[-1] if chunk.startswith("{#") else chunk
                         for chunk in body.split("\n"))
        quoted = sum(1 for k in keys
                     if ("'%s'" % k) in body or ('"%s"' % k) in body)
        assert quoted <= 2, (
            "%s quotes %d of the promoted-area keys literally; the list must "
            "come from config_sections.WAF_AREAS" % (rel, quoted))


def test_base_html_takes_the_area_keys_from_the_context(app):
    root = Path(__file__).resolve().parents[1]
    body = (root / "app/templates/base.html").read_text(encoding="utf-8")
    assert "waf_section_keys" in body


@pytest.mark.parametrize("key", ["machine_learning", "tracking"])
def test_promoted_areas_are_not_also_in_the_configuration_submenu(app, key):
    """Promoted areas render in the WAF group; leaving them in the admin
    Configuration submenu too would show each of them twice."""
    from app.services import config_catalog as cc, config_sections as cs

    promoted = set(cs.WAF_AREA_KEYS)
    cfg_keys = [s.key for s in cc.CONFIG_SECTIONS
                if cs.has_menu(s.key) and s.key not in (promoted | {"server_objects"})]
    assert key in promoted
    assert key not in cfg_keys
