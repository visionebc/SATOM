"""FortiWeb ``system feature-visibility`` — the gate FortiWeb's own left menu obeys.

FortiWeb does not show every feature it ships. ``config system feature-visibility``
carries a per-feature ``enable``/``disable`` flag and the appliance's GUI **hides
the whole menu branch** of every feature left ``disable``. Measured live on fw12
(FortiWeb 7.6.8, 2026-08-19) through :mod:`app.clients.fortiweb`: **all 19 toggles
ship ``disable``**, so a stock unit's menu is markedly shorter than the registry.

Until this module existed the port ignored the object entirely (it was an editable
System leaf, but nothing *read* it), so the sidebar offered API Gateway, Web Cache,
Padding Oracle Protection, Mobile API Protection, the System → Firewall group,
ICAP Server and reCAPTCHA on appliances whose own GUI shows none of them.

Three deliberate negatives
--------------------------
1. **Unknown means SHOW.** A device with no cached ``feature_visibility`` row — a
   never-synced appliance, a non-FortiWeb kind, a DB hiccup — gets an EMPTY hidden
   set, i.e. exactly the pre-gating menu. Hiding on absent evidence would take
   pages away from an operator because a sync had not run yet; the failure mode of
   guessing "hidden" is worse than the failure mode of guessing "shown".
2. **This gates the NAV, never the page.** ``feature-visibility`` is a GUI-menu
   control on FortiWeb, not an access control: the objects stay readable and
   writable over CLI/REST with the feature off. So ``section_config`` keeps serving
   a gated type (deep links and bookmarks survive a toggle flip), and the page's
   own tab bar (``config_sections.group_of``) is deliberately built UNGATED. That
   is why gating is an opt-in argument defaulting to "no gating" rather than a
   global filter.
3. **``feature_visibility`` itself can never be gated.** It is the operator's only
   in-product way back — turn the feature on in SATOM and its menu returns, the
   same escape hatch FortiWeb has. A gate that hid it would be a one-way door.
   :data:`NEVER_GATED` is enforced by a guard, not by care.

Mapping status
--------------
:data:`TOGGLES` is **measured** (read off fw12, not transcribed from a manual).
:data:`GATES` is *curated*, at the same evidence level as the rest of the menu
curation in :mod:`app.services.config_sections`: each entry pairs a toggle with the
top-level objects whose REST collection carries that feature's own name
(``api-gateway`` → ``waf/api-policy`` + ``waf/api-rules`` + ``waf/api-user*``;
``web-cache`` → ``waf/web-cache-policy`` + ``waf/web-cache-rule`` +
``waf/cache-policy``). Toggles whose feature has NO object in this firmware's
registry (``wad``/anti-defacement, ``adfs-policy``, ``support-ajax-requests``,
``debug-log``, ``cryptographic-key``) map to nothing and are listed in
:data:`UNMAPPED_TOGGLES` so their absence is a recorded fact rather than an
oversight. Confirming a mapping leaf-by-leaf needs a toggle flipped on a live
appliance and the GUI diffed — that measurement is outstanding.

**Only TOP-LEVEL menu leaves are ever gated.** A by-parent sub-table is reached by
drilling into its parent's editor, and vanishing rows mid-editor is a different
behaviour from FortiWeb hiding a menu branch.

Reads the cached ``feature_visibility`` row from ``device_objects`` (populated by
the ordinary device sync — see :mod:`app.services.device_sync`), so gating costs
one indexed query per request and never touches the appliance.
"""
from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------- #
#  The toggles, read live off fw12 (FortiWeb 7.6.8) on 2026-08-19.             #
#  7.6.8 ships `cryptographic-key`, which the 7.6.4 CLI reference does not      #
#  list — the set is firmware-dependent, so unknown keys are tolerated at read  #
#  time and only the KNOWN ones may appear in GATES (guarded).                  #
# --------------------------------------------------------------------------- #
TOGGLES: frozenset[str] = frozenset({
    "ftp-security", "ztna", "traffic-mirror", "mobile-app-identification",
    "adfs-policy", "acceleration-policy", "web-cache", "support-ajax-requests",
    "wccp-mode", "wvs", "api-gateway", "firewall", "padding-oracle", "wad",
    "fortigate-integration", "support-icap-server", "debug-log", "recaptcha",
    "cryptographic-key",
})

#: Registry logicals that must stay reachable whatever any toggle says.
NEVER_GATED: frozenset[str] = frozenset({"feature_visibility"})

#: toggle -> the top-level registry logicals its feature owns.
GATES: dict[str, frozenset[str]] = {
    "api-gateway": frozenset({
        "api_policy", "api_policy_rule", "api_user", "api_user_group",
    }),
    "mobile-app-identification": frozenset({
        "mobile_api_protection_policy", "mobile_api_protection_rule",
    }),
    "padding-oracle": frozenset({"padding_oracle"}),
    "web-cache": frozenset({
        "web_cache_policy", "waf_web_cache_rule", "cache_policy",
    }),
    "firewall": frozenset({
        "system_firewall_address", "system_firewall_service",
        "system_firewall_firewall_policy", "system_firewall_snat_policy",
        "system_firewall_dnat_policy", "system_firewall_admin_policy",
        "system_firewall_fwmark_policy",
    }),
    "support-icap-server": frozenset({"system_icapserver"}),
    "recaptcha": frozenset({"system_recaptcha_api", "user_recaptcha_user"}),
    "fortigate-integration": frozenset({"system_fortigate_integration"}),
    "wccp-mode": frozenset({"system_wccp"}),
    "traffic-mirror": frozenset({"traffic_mirror_profile"}),
    # The four below own registry objects that NO menu surfaces yet (measured
    # 2026-08-19). Gating them is a no-op today and correct the day a menu adds
    # them; leaving them out would make the omission look intentional.
    "ztna": frozenset({"ztna_profile"}),
    "acceleration-policy": frozenset({"acceleration_policy",
                                      "acceleration_exception"}),
    "ftp-security": frozenset({"waf_ftp_file_security",
                               "waf_ftp_command_restriction_rule"}),
    # wvs_threat_weight / wvs_top_threats are deliberately absent: their urns
    # carry no `/cmdb/`, so they are live-status reads, never browsable menu
    # leaves. Gating them would be a gate that can never fire.
    "wvs": frozenset({
        "wvs_policy", "wvs_profile", "wvs_template", "wvs_schedule",
        "wvs_limit",
    }),
}

#: Toggles with no object in this registry — recorded, not forgotten.
#: ``wad`` is anti-defacement: 0 of 506 endpoints match, so SATOM has no
#: Anti-Defacement menu. Its absence is CORRECT while ``wad`` is disable and a
#: real gap the moment somebody enables it.
UNMAPPED_TOGGLES: frozenset[str] = frozenset({
    "wad", "adfs-policy", "support-ajax-requests", "debug-log",
    "cryptographic-key",
})


def _row_payload(appliance_id: int, *, session=None) -> dict[str, Any] | None:
    """The cached ``system/feature-visibility`` payload, or ``None``."""
    try:
        from ..extensions import db
        from ..models_cache import DeviceObject
        session = session or db.session
        row = (session.query(DeviceObject)
               .filter_by(appliance_id=appliance_id,
                          logical_name="feature_visibility", depth=0)
               .order_by(DeviceObject.id.desc())
               .first())
    except Exception:  # noqa: BLE001 — no app ctx / no table / DB down
        return None
    if row is None:
        return None
    payload = row.payload
    if isinstance(payload, str):
        import json
        try:
            payload = json.loads(payload)
        except ValueError:
            return None
    return payload if isinstance(payload, dict) else None


def toggles_for(appliance_id: int | None, *, session=None) -> dict[str, str]:
    """``{toggle: "enable"|"disable"}`` as last synced. Empty when unknown.

    The wire payload doubles every key with a ``<key>_val`` numeric twin; those
    are dropped so callers see the toggle names FortiWeb's CLI uses.
    """
    if not appliance_id:
        return {}
    payload = _row_payload(appliance_id, session=session)
    if not payload:
        return {}
    return {k: str(v) for k, v in payload.items()
            if not k.endswith("_val") and isinstance(v, (str, int))}


def disabled_features(appliance_id: int | None, *, session=None) -> frozenset[str]:
    """Toggles the appliance reports as ``disable``. Empty when unknown.

    Only ``disable`` hides. Anything else — ``enable``, an unexpected value, a
    key this firmware does not ship — leaves the branch visible, because the
    only safe reading of "I do not understand this value" is "show it".
    """
    return frozenset(k for k, v in toggles_for(appliance_id, session=session).items()
                     if str(v).strip().lower() == "disable")


def hidden_logicals(appliance_id: int | None, *, session=None) -> frozenset[str]:
    """Registry logicals FortiWeb's own menu would hide on this appliance."""
    off = disabled_features(appliance_id, session=session)
    if not off:
        return frozenset()
    hidden: set[str] = set()
    for toggle in off:
        hidden |= GATES.get(toggle, frozenset())
    return frozenset(hidden - NEVER_GATED)


def gated_toggle_for(logical: str) -> str | None:
    """The toggle that owns ``logical`` (``None`` when it is never gated)."""
    for toggle, logicals in GATES.items():
        if logical in logicals:
            return toggle
    return None


__all__ = ["TOGGLES", "GATES", "NEVER_GATED", "UNMAPPED_TOGGLES",
           "toggles_for", "disabled_features", "hidden_logicals",
           "gated_toggle_for"]
