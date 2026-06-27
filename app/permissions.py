"""Granular permission catalog + legacy (coarse) compatibility mapping.

The app historically had five coarse permission keys (``view``, ``backup``,
``config_write``, ``registry_edit``, ``user_manage``) baked into a fixed
3-role table. Profiles introduce a fine-grained ``area.action`` catalog that
admins compose freely, while the five coarse keys remain the *enforcement*
vocabulary used by every existing decorator and template.

A profile stores a set of GRANULAR keys. ``derive_coarse`` projects that set
onto the legacy coarse keys so the old gates light up unchanged — that is the
entire back-compat contract (see ``tests/test_permissions.py``).
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Areas (display order + labels for the matrix UI)
# ---------------------------------------------------------------------------

AREAS: list[dict] = [
    {"key": "monitoring", "label": "Monitoring", "icon": "bi-search",
     "desc": "Search, status dashboards, fleet overview"},
    {"key": "protection", "label": "Web Protection", "icon": "bi-shield-shaded",
     "desc": "WAF profiles, signatures, exceptions"},
    {"key": "network", "label": "Network", "icon": "bi-hdd-network",
     "desc": "Server objects, virtual servers, architecture & analysis"},
    {"key": "operations", "label": "Operations", "icon": "bi-gear-wide-connected",
     "desc": "Provisioning, templates, structure, scheduled actions, change requests"},
    {"key": "backups", "label": "Backups", "icon": "bi-database",
     "desc": "Download, restore and import configuration backups"},
    {"key": "registry", "label": "API Registry", "icon": "bi-box-seam",
     "desc": "Endpoint registry & API explorer"},
    {"key": "audit", "label": "Audit Log", "icon": "bi-journal-text",
     "desc": "Read the application audit trail"},
    {"key": "appliances", "label": "Appliances", "icon": "bi-hdd-rack",
     "desc": "Device inventory and appliance actions (console, rediscovery, upgrade)"},
    {"key": "users", "label": "Users", "icon": "bi-people",
     "desc": "Manage application users"},
    {"key": "profiles", "label": "Profiles", "icon": "bi-person-badge",
     "desc": "Define permission profiles (administrative)"},
]

_AREA_LABELS = {a["key"]: a["label"] for a in AREAS}


def _p(key: str, label: str, desc: str, admin_only: bool = False) -> dict:
    return {"key": key, "area": key.split(".", 1)[0], "action": key.split(".", 1)[1],
            "label": label, "desc": desc, "admin_only": admin_only}


# ---------------------------------------------------------------------------
# Granular permission catalog
# ---------------------------------------------------------------------------

GRANULAR_PERMISSIONS: list[dict] = [
    _p("monitoring.view", "View monitoring", "See search, status and dashboards"),

    _p("protection.view", "View protection", "Browse WAF profiles, signatures, exceptions"),
    _p("protection.edit", "Edit protection", "Author/stage web-protection changes"),
    _p("protection.apply", "Apply protection", "Push web-protection changes to a device"),

    _p("network.view", "View network", "Browse server objects, virtual servers, topology"),
    _p("network.edit", "Edit network", "Author/stage network-object changes"),
    _p("network.apply", "Apply network", "Push network-object changes to a device"),

    _p("operations.view", "View operations", "See provisioning, templates, schedules, change requests"),
    _p("operations.apply", "Run operations", "Provision, apply templates, run scheduled actions"),

    _p("backups.view", "View backups", "List existing backups"),
    _p("backups.create", "Create backups", "Download configuration backups"),
    _p("backups.restore", "Restore backups", "Import/restore a configuration backup"),

    _p("registry.view", "View registry", "Browse the endpoint registry & API explorer"),
    _p("registry.edit", "Edit registry", "Modify the endpoint registry"),

    _p("audit.view", "View audit log", "Read the application audit trail"),

    _p("appliances.view", "View appliances", "See the appliance inventory"),
    _p("appliances.edit", "Edit appliances", "Add, edit or delete appliances"),
    _p("appliances.apply", "Run appliance actions",
       "Console, rediscovery, policy inspector, upgrade preparation & upgrade"),

    _p("users.view", "View users", "See the user list"),
    _p("users.manage", "Manage users",
       "Create, edit, delete, reset and re-profile users", admin_only=True),

    _p("profiles.manage", "Manage profiles",
       "Create, edit, clone and delete permission profiles", admin_only=True),
]


def all_keys() -> set[str]:
    return {p["key"] for p in GRANULAR_PERMISSIONS}


def is_valid_key(key: str) -> bool:
    return key in all_keys()


# ---------------------------------------------------------------------------
# Coarse (legacy) projection — the enforcement vocabulary used everywhere.
# ---------------------------------------------------------------------------

COARSE_KEYS = ("view", "backup", "config_write", "registry_edit", "user_manage")

# legacy coarse key  <-  any of these granular keys (presence implies the coarse)
_DERIVE: dict[str, set[str]] = {
    "view": {
        "monitoring.view", "protection.view", "network.view", "operations.view",
        "backups.view", "registry.view", "audit.view", "appliances.view",
    },
    "backup": {"backups.create", "backups.restore"},
    "config_write": {
        "protection.edit", "protection.apply",
        "network.edit", "network.apply",
        "operations.apply",
        "appliances.edit", "appliances.apply",
    },
    "registry_edit": {"registry.edit"},
    "user_manage": {"users.manage"},
}


def derive_coarse(granular: set[str]) -> set[str]:
    """Project a set of granular keys onto the legacy coarse keys."""
    g = set(granular)
    out: set[str] = set()
    for coarse, triggers in _DERIVE.items():
        if g & triggers:
            out.add(coarse)
    return out


def coarse_to_granular(coarse: set[str]) -> set[str]:
    """Inverse of :func:`derive_coarse` — used only as a fallback for users
    that still have a legacy ``role`` and no assigned profile, so that newer
    granular gates keep working for them too."""
    out: set[str] = set()
    for c in coarse:
        out |= _DERIVE.get(c, set())
    return out


def expand(granular: set[str]) -> set[str]:
    """Effective permission set for a granular profile: the granular keys plus
    the legacy coarse keys they imply."""
    g = set(granular)
    return g | derive_coarse(g)


# ---------------------------------------------------------------------------
# System profiles — reproduce the legacy 3-role behavior EXACTLY when expanded.
# ---------------------------------------------------------------------------

_READ_KEYS = {
    "monitoring.view", "protection.view", "network.view", "operations.view",
    "backups.view", "registry.view", "audit.view", "appliances.view",
}

_OPERATOR_EXTRA = {
    "backups.create", "backups.restore",
    "protection.edit", "protection.apply",
    "network.edit", "network.apply",
    "operations.apply",
    "appliances.edit", "appliances.apply",
}

SYSTEM_PROFILES: dict[str, set[str]] = {
    "readonly": set(_READ_KEYS),
    "operator": set(_READ_KEYS) | set(_OPERATOR_EXTRA),
    "admin": all_keys(),
}

# Human-facing descriptions for the seeded system profiles.
SYSTEM_PROFILE_META = {
    "readonly": "Read-only access to every section. Cannot change anything.",
    "operator": "Read everything plus manage appliances, protection, network, "
                "backups and operations. No user or registry administration.",
    "admin": "Full access, including user and profile administration.",
}

# The capabilities that let a user administer access itself. Anti-lockout logic
# guarantees at least one ACTIVE user always retains BOTH of these.
ADMIN_CAPABILITIES: set[str] = {"users.manage", "profiles.manage"}


def role_to_profile_name(role: str) -> str:
    """Map a legacy role string to its seeded system-profile name."""
    return role if role in SYSTEM_PROFILES else "readonly"


def coarse_for_role_label(effective: set[str]) -> str:
    """Best-effort legacy ``role`` string for an effective permission set, so
    role-based UI (badges, counters) keeps rendering sensibly."""
    if "user_manage" in effective:
        return "admin"
    if "config_write" in effective:
        return "operator"
    return "readonly"
