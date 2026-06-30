"""System provisioning — bring a fresh/standard FortiWeb to baseline (web port).

Beyond per-policy work, an operator needs to push *system* config (DNS, NTP,
RADIUS + groups, SNMP, admins…) to one box or to the whole fleet. This module
models that as a declarative ``SystemProfile``: an ordered list of
``ProvisionItem``s, each mapping an intent to a **registry logical endpoint** and
a payload. ``apply`` runs them through the shared fleet machinery
(``services.bulk.iter_push_items`` + ``BulkRunner``) so every step is previewed
(dry-run), snapshotted, audited and canary-gated — the same profile drives a
single device or the whole fleet.

A ``SystemProfile`` round-trips to a ``templates`` row (kind
``Template.KIND_SYSTEM`` = ``"system-profile"``) so it can be versioned and
reused. **Secrets** (RADIUS shared secret, admin passwords, SNMPv3 auth/priv)
must be supplied at apply-time and are NEVER stored in the template — the catalog
flags those items ``sensitive`` and :func:`save_profile` strips secret-looking
fields before persisting.

This is the web port of the desktop ``app/services/provisioning.py``. It is pure
logic over the web foundation: the registry is read lazily inside the functions
(no import side effects), and nothing touches a device until :func:`apply` runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- #
#  Catalog data-objects                                                         #
# --------------------------------------------------------------------------- #
@dataclass
class ProvisionSpec:
    """A provisionable system intent the GUI can offer."""

    key: str
    label: str
    endpoint: str | None          # registry logical name; None = not wired yet
    singleton: bool               # True -> PUT whole object (no mkey)
    sensitive: bool = False       # carries secrets -> don't persist in templates
    note: str = ""
    # Server-managed/read-only fields this endpoint returns on a GET that are NOT
    # caught by the generic ``fortiweb_ops.sanitize_payload`` (which strips
    # ``q_*``/``_ref``…) — e.g. NTP's camelCase ``systemTime``/``time``. They are
    # dropped before a PUT so an authored payload seeded from a GET doesn't echo
    # them back.
    readonly_fields: tuple[str, ...] = ()


@dataclass
class ProvisionItem:
    """One concrete provisioning step (an endpoint + the payload to push)."""

    key: str
    endpoint: str
    data: dict[str, Any] = field(default_factory=dict)
    singleton: bool = False
    mkey: str | None = None       # set to update an existing keyed object
    label: str = ""
    sensitive: bool = False       # carries secrets (mirrors the spec) — stripped on save

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "endpoint": self.endpoint,
            "data": self.data,
            "singleton": self.singleton,
            "mkey": self.mkey,
            "label": self.label,
            "sensitive": self.sensitive,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProvisionItem":
        return cls(
            key=d.get("key", ""),
            endpoint=d["endpoint"],
            data=d.get("data") or {},
            singleton=bool(d.get("singleton", False)),
            mkey=d.get("mkey"),
            label=d.get("label", ""),
            sensitive=bool(d.get("sensitive", False)),
        )

    @classmethod
    def from_spec(cls, spec: ProvisionSpec, data: dict[str, Any] | None = None,
                  *, mkey: str | None = None) -> "ProvisionItem":
        """Build an item from a catalog spec (copies its label/singleton/sensitive)."""
        return cls(
            key=spec.key,
            endpoint=spec.endpoint or "",
            data=dict(data or {}),
            singleton=spec.singleton,
            mkey=mkey,
            label=spec.label,
            sensitive=spec.sensitive,
        )


@dataclass
class SystemProfile:
    """An ordered set of provisioning steps; round-trips to a template body."""

    name: str
    items: list[ProvisionItem] = field(default_factory=list)
    line: str = "8.0"               # firmware line the profile was authored against
    scope: dict = field(default_factory=dict)  # {zone, line, department} classification scope

    def to_body(self) -> dict[str, Any]:
        """Faithful round-trip body (``from_body`` is its inverse). Secrets are
        retained here; strip them with :func:`save_profile` before persisting."""
        return {
            "line": self.line,
            "_scope": {
                "zone": (self.scope or {}).get("zone", ""),
                "line": (self.scope or {}).get("line", ""),
                "department": (self.scope or {}).get("department", ""),
            },
            "items": [it.to_dict() for it in self.items],
        }

    @classmethod
    def from_body(cls, name: str, body: dict[str, Any] | None) -> "SystemProfile":
        body = body or {}
        raw_scope = body.get("_scope") or {}
        return cls(
            name=name,
            line=body.get("line") or "8.0",
            scope={
                "zone": raw_scope.get("zone", ""),
                "line": raw_scope.get("line", ""),
                "department": raw_scope.get("department", ""),
            },
            items=[ProvisionItem.from_dict(d) for d in body.get("items", [])
                   if isinstance(d, dict) and d.get("endpoint")],
        )

    @classmethod
    def from_template(cls, template: Any) -> "SystemProfile":
        """Build a profile from a ``models.Template`` row (kind ``system-profile``)."""
        name = getattr(template, "name", "") or ""
        body = getattr(template, "body_dict", None)
        if body is None:
            body = template if isinstance(template, dict) else {}
        return cls.from_body(name, body)


# --------------------------------------------------------------------------- #
#  The baseline catalog — "the basic elements of the new system"                #
# --------------------------------------------------------------------------- #
# Endpoints are registry logical names (see endpoints.yaml). singleton/sensitive
# are best-effort per FortiWeb's cmdb conventions — desired-state authoring, to be
# validated live on a target box (see CLAUDE.md §5). The desktop's endpoint=None
# rows (SMTP, certificate) are intentionally dropped here.
PROVISION_CATALOG: list[ProvisionSpec] = [
    # ── Identity / system ────────────────────────────────────────────────
    ProvisionSpec("global", "Global settings / hostname", "global", True,
                  note="cmdb/system/global — hostname, language, admin timeouts…"),
    ProvisionSpec("dns", "DNS", "dns", True),
    ProvisionSpec("ntp", "NTP / time", "system_time", True,
                  readonly_fields=("systemTime", "time"),
                  note="systemtime: only mode/ntpServer/timeZone are writable; "
                       "systemTime/time are server-managed (read-only) and the PUT "
                       "doesn't echo the object. Validate against the device."),
    ProvisionSpec("fortiguard", "FortiGuard (updates)", "system_fortiguard", True),
    # ── Network ──────────────────────────────────────────────────────────
    ProvisionSpec("interface", "Network interface", "interface", False,
                  note="collection keyed by interface name (port1, …)"),
    ProvisionSpec("static_route", "Static route", "route", False),
    # ── SNMP ─────────────────────────────────────────────────────────────
    ProvisionSpec("snmp_sysinfo", "SNMP (sysinfo)", "system_snmp_sysinfo", True),
    ProvisionSpec("snmp_community", "SNMP community", "system_snmp_community", False),
    ProvisionSpec("snmp_user", "SNMP user (v3)", "snmp_user", False, sensitive=True,
                  note="v3 auth/priv passwords — captured at apply time, not stored"),
    # ── Authentication / administrators ──────────────────────────────────
    ProvisionSpec("radius", "RADIUS server", "user_radius", False, sensitive=True,
                  note="the shared secret is captured at apply time, NOT stored in the template"),
    ProvisionSpec("ldap", "LDAP server", "user_ldap", False, sensitive=True,
                  note="bind password is captured at apply time, not stored"),
    ProvisionSpec("user_group", "User groups", "user_group", False),
    ProvisionSpec("accprofile", "Admin access profile", "accprofile", False,
                  note="cmdb/system/accprofile — administrator permissions"),
    ProvisionSpec("admin", "Administrators", "system_admin", False, sensitive=True),
    # ── Logging ──────────────────────────────────────────────────────────
    ProvisionSpec("syslog", "Syslog", "syslog_policy", False,
                  note="cmdb/log/syslog-policy (+ its server list)"),
    ProvisionSpec("fortianalyzer", "FortiAnalyzer", "fortianalyzer", True),
]

CATALOG_BY_KEY: dict[str, ProvisionSpec] = {s.key: s for s in PROVISION_CATALOG}
# Keyed by registry endpoint so apply()/sanitize can find the per-endpoint
# read-only field set regardless of how an item was authored (curated key vs
# auto-generated name).
CATALOG_BY_ENDPOINT: dict[str, ProvisionSpec] = {
    s.endpoint: s for s in PROVISION_CATALOG if s.endpoint
}


# --------------------------------------------------------------------------- #
#  Sensitivity heuristics + secret hygiene                                      #
# --------------------------------------------------------------------------- #
# Endpoint names/URNs that imply secret-bearing objects (used to auto-flag
# non-curated endpoints in ``all_specs``).
_SENSITIVE_HINTS = (
    "password", "passwd", "secret", "radius", "ldap", "tacacs", "psk",
    "pre-shared", "privkey", "private-key", "credential", "snmp.user",
    "snmp_user", "admin",
)

# Field-name substrings whose VALUES are secret material and must never be
# persisted into a template (stripped by ``save_profile``).
_SECRET_FIELD_HINTS = (
    "password", "passwd", "pwd", "secret", "psk", "passphrase",
    "private-key", "privkey", "credential",
)


def _is_sensitive(name: str, urn: str = "") -> bool:
    blob = f"{name} {urn}".lower()
    return any(h in blob for h in _SENSITIVE_HINTS)


def _item_is_sensitive(item: ProvisionItem) -> bool:
    if item.sensitive:
        return True
    spec = CATALOG_BY_ENDPOINT.get(item.endpoint)
    if spec and spec.sensitive:
        return True
    return _is_sensitive(item.endpoint or "")


def _strip_secret_fields(data: Any) -> Any:
    """Drop secret-looking keys from a payload (recursively). Pure; non-dicts pass through."""
    if not isinstance(data, dict):
        return data
    out: dict[str, Any] = {}
    for k, v in data.items():
        if any(h in str(k).lower() for h in _SECRET_FIELD_HINTS):
            continue  # never persist secret material
        out[k] = _strip_secret_fields(v) if isinstance(v, dict) else v
    return out


def _auto_label(name: str) -> str:
    """Humanise a registry friendly-key into a display label."""
    pretty = name.replace("_", " ").replace("-", " ").replace(".", " ").strip().title()
    return pretty or name


# --------------------------------------------------------------------------- #
#  Write-time payload hygiene                                                    #
# --------------------------------------------------------------------------- #
def sanitize_payload(endpoint: str, data: dict[str, Any] | None) -> dict[str, Any]:
    """Strip server-managed keys before a write.

    Applies the shared ``fortiweb_ops.sanitize_payload`` hygiene (drops
    ``q_*``/``_ref``/``is_default``… that a PUT/POST must not echo) PLUS this
    endpoint's curated :attr:`ProvisionSpec.readonly_fields` (the odd-cased ones
    the generic cleaner can't know, e.g. NTP's ``systemTime``/``time``). Pure;
    safe on any payload.
    """
    from .fortiweb_ops import sanitize_payload as _ops_sanitize

    out = _ops_sanitize(dict(data or {}))
    spec = CATALOG_BY_ENDPOINT.get(endpoint)
    if spec and isinstance(out, dict):
        for f in spec.readonly_fields:
            out.pop(f, None)
    return out if isinstance(out, dict) else {}


# --------------------------------------------------------------------------- #
#  Catalog queries (registry read lazily, no import side effects)               #
# --------------------------------------------------------------------------- #
def _cmdb_endpoints() -> list[dict[str, Any]]:
    """Registry config (``cmdb``) endpoints as loader display dicts (deduped by name)."""
    from ..registry import loader

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for ep in loader.get_all_endpoints():
        name = ep.get("name")
        urn = ep.get("urn") or ep.get("path") or ""
        if not name or name in seen or "/cmdb/" not in urn:
            continue
        seen.add(name)
        out.append(ep)
    return out


def available_specs() -> list[ProvisionSpec]:
    """Curated catalog entries whose endpoint actually exists in the registry."""
    from ..registry import loader

    names = {ep.get("name") for ep in loader.get_all_endpoints()}
    return [s for s in PROVISION_CATALOG if s.endpoint and s.endpoint in names]


def all_specs() -> list[ProvisionSpec]:
    """EVERY config (``cmdb``) endpoint as a provisionable spec, ordered by GUI
    section — so nothing is off-limits ("include everything").

    Curated ``PROVISION_CATALOG`` entries supply the nice label + the correct
    singleton/sensitive flags; every other config object is auto-generated
    (collection by default, ``sensitive`` by name heuristic). Curated baselines
    not present in this registry are still offered (appended last) so the
    recommended set never disappears. The operator adds the ones they want and
    fills values — only those end up in the profile. Monitor/action endpoints
    (non-``cmdb``) are excluded (provisioning = config).
    """
    from ..registry import categories as _categories

    order = {name: i for i, name in enumerate(_categories.SECTION_ORDER)}
    curated = CATALOG_BY_ENDPOINT
    seen: set[str] = set()
    rows: list[tuple[int, str, ProvisionSpec]] = []

    for ep in _cmdb_endpoints():
        name = ep["name"]
        urn = ep.get("urn") or ep.get("path") or ""
        section = ep.get("section") or "Other"
        seen.add(name)
        spec = curated.get(name) or ProvisionSpec(
            key=name, label=_auto_label(name), endpoint=name, singleton=False,
            sensitive=_is_sensitive(name, urn), note=section,
        )
        rows.append((order.get(section, len(order)), spec.label.lower(), spec))

    # Curated baselines absent from this (possibly partial) registry: keep them.
    for spec in PROVISION_CATALOG:
        if spec.endpoint and spec.endpoint not in seen:
            seen.add(spec.endpoint)
            rows.append((len(order) + 1, spec.label.lower(), spec))

    rows.sort(key=lambda r: (r[0], r[1]))
    return [r[2] for r in rows]


def section_for(endpoint: str) -> str:
    """GUI section (e.g. ``Network``) of a registry endpoint, for grouping."""
    from ..registry import loader

    for ep in loader.get_all_endpoints():
        if ep.get("name") == endpoint:
            return ep.get("section") or "Other"
    return "Other"


# --------------------------------------------------------------------------- #
#  Persist a profile as a versioned template (secrets stripped)                 #
# --------------------------------------------------------------------------- #
def save_profile(profile: SystemProfile, *, note: str = "", author: str = "",
                 new_version: bool = True) -> Any:
    """Persist ``profile`` as a ``Template`` (kind ``system-profile``).

    Secret-looking fields are stripped from every sensitive item BEFORE the body
    is written — secrets are entered again at apply-time and never live in the
    template (CLAUDE.md §5). Returns the created ``models.Template`` row.
    """
    from ..models import Template
    from .templates import save_template

    items: list[dict[str, Any]] = []
    for it in profile.items:
        d = it.to_dict()
        if _item_is_sensitive(it):
            d["data"] = _strip_secret_fields(d.get("data") or {})
        items.append(d)
    body = {
        "line": profile.line,
        "_scope": {
            "zone": (profile.scope or {}).get("zone", ""),
            "line": (profile.scope or {}).get("line", ""),
            "department": (profile.scope or {}).get("department", ""),
        },
        "items": items,
    }
    return save_template(Template.KIND_SYSTEM, profile.name, body,
                         note=note, author=author, new_version=new_version)


# --------------------------------------------------------------------------- #
#  Apply (preview / canary fleet write via the shared bulk machinery)           #
# --------------------------------------------------------------------------- #
def _item_to_push_node(item: ProvisionItem) -> dict[str, Any]:
    """Map a ``ProvisionItem`` to a ``{action, endpoint, mkey, data}`` push node.

    Singletons PUT the whole object (``update`` with ``mkey=None``); a keyed item
    with an ``mkey`` updates that object; everything else is created.
    """
    if item.singleton:
        action, mkey = "update", None
    elif item.mkey:
        action, mkey = "update", item.mkey
    else:
        action, mkey = "create", None
    return {
        "action": action,
        "endpoint": item.endpoint,
        "mkey": mkey,
        "data": sanitize_payload(item.endpoint, item.data or {}),
    }


def apply(profile: SystemProfile, device_ids, *, dry_run: bool = True,
          canary: int = 1):
    """Apply ``profile`` to ``device_ids`` via the shared fleet machinery.

    Builds push nodes from the profile's items, flattens them with
    ``services.bulk.iter_push_items`` (which preserves order and emits any
    sub-objects deepest-first), then runs them through ``BulkRunner``:

      * ``dry_run=True`` (default) -> ``BulkRunner.preview(device_ids)`` returns a
        per-device list of would-be requests (no device contact);
      * ``dry_run=False`` -> ``BulkRunner.apply(device_ids, canary=canary)``
        returns ``{"canary": [...], "rest": [...], "aborted": bool}`` — the canary
        subset writes first and aborts the rest on failure.

    Each write snapshots + audits inside ``FortiWebOps``. Must run inside the
    Flask app context (``BulkRunner`` queries ``Appliance`` and writes
    ``ChangeHistory``). Payloads are hygiene-sanitized per endpoint; secrets in
    the items are applied live but are never persisted (see :func:`save_profile`).
    """
    from .bulk import BulkRunner, iter_push_items

    nodes = [_item_to_push_node(it) for it in profile.items if it.endpoint]
    items = iter_push_items(nodes)
    runner = BulkRunner(items)
    if dry_run:
        return runner.preview(device_ids)
    return runner.apply(device_ids, canary=max(1, canary))


__all__ = [
    "ProvisionSpec",
    "ProvisionItem",
    "SystemProfile",
    "PROVISION_CATALOG",
    "CATALOG_BY_KEY",
    "CATALOG_BY_ENDPOINT",
    "sanitize_payload",
    "available_specs",
    "all_specs",
    "section_for",
    "save_profile",
    "apply",
]
