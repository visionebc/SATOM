"""TDD for the granular permission catalog + legacy back-compat mapping."""
from __future__ import annotations

import re


def test_catalog_keys_are_area_dot_action_and_reference_known_areas():
    from app import permissions as P
    assert P.AREAS, "AREAS must be non-empty"
    area_keys = {a["key"] for a in P.AREAS}
    for perm in P.GRANULAR_PERMISSIONS:
        assert re.fullmatch(r"[a-z_]+\.[a-z_]+", perm["key"]), perm["key"]
        assert perm["area"] in area_keys, f"{perm['key']} -> unknown area {perm['area']}"


def test_catalog_contains_expected_keys():
    from app import permissions as P
    keys = P.all_keys()
    for expected in (
        "monitoring.view", "protection.edit", "protection.apply",
        "network.edit", "backups.create", "backups.restore",
        "registry.edit", "audit.view", "appliances.apply",
        "users.manage", "profiles.manage",
    ):
        assert expected in keys, expected


def test_derive_coarse_maps_granular_to_legacy_keys():
    from app import permissions as P
    assert "view" in P.derive_coarse({"monitoring.view"})
    assert "config_write" in P.derive_coarse({"protection.edit"})
    assert "config_write" in P.derive_coarse({"appliances.apply"})
    assert "backup" in P.derive_coarse({"backups.create"})
    assert "registry_edit" in P.derive_coarse({"registry.edit"})
    assert "user_manage" in P.derive_coarse({"users.manage"})
    assert P.derive_coarse(set()) == set()
    # a pure read profile derives only 'view'
    assert P.derive_coarse({"monitoring.view", "audit.view"}) == {"view"}


def test_system_profiles_reproduce_legacy_role_sets_exactly():
    """The whole back-compat contract: expanding a system profile derives the
    exact same legacy coarse set the old ROLE_PERMISSIONS map had."""
    from app import permissions as P
    ro = P.derive_coarse(P.SYSTEM_PROFILES["readonly"])
    op = P.derive_coarse(P.SYSTEM_PROFILES["operator"])
    ad = P.derive_coarse(P.SYSTEM_PROFILES["admin"])
    assert ro == {"view"}
    assert op == {"view", "backup", "config_write"}
    assert ad == {"view", "backup", "config_write", "registry_edit", "user_manage"}


def test_coarse_to_granular_round_trips_admin_capabilities():
    from app import permissions as P
    g = P.coarse_to_granular({"user_manage"})
    assert "users.manage" in g
    g_view = P.coarse_to_granular({"view"})
    assert any(k.endswith(".view") for k in g_view)


def test_admin_capabilities_constant():
    from app import permissions as P
    assert P.ADMIN_CAPABILITIES == {"users.manage", "profiles.manage"}
    assert P.ADMIN_CAPABILITIES <= set(P.SYSTEM_PROFILES["admin"])
    assert not (P.ADMIN_CAPABILITIES & set(P.SYSTEM_PROFILES["operator"]))
