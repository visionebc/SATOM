"""Device-ADOM menu parity — FortiWeb is the reference menu (2026-10-11).

Operator rule: every device ADOM (FortiADC, FortiAnalyzer, FortiAuthenticator,
FortiGate, and any device ADOM added later) draws the SAME entries as the
FortiWeb ADOM, in the same place. What an entry does inside an ADOM is only
ever about that ADOM's own kind of device. The Global ADOM keeps its own menu
and is not described here.

Same entry everywhere does NOT mean same page everywhere. Most of the entries
FortiWeb had alone were FortiWeb-only because the page behind them only
understands FortiWeb objects (server policies, web-protection profiles, the
FortiWeb backup format). Linking such a page from the FortiGate ADOM would
either render an empty page that reads as "this fleet has nothing", or aim
FortiWeb configuration at a FortiGate. So each entry here answers ONE
question per product: does the page work for this kind of device?

* yes -> the sidebar draws the live link, and :func:`gate_allows` lets the
  product gate in app/__init__.py through, so the link cannot bounce to the
  ADOM home (the defect tests/test_adom_menu_reachability.py exists for);
* no  -> the sidebar draws the entry DISABLED with the reason, the way the
  switched-off Scout entry is drawn. An absent entry reads as "SATOM cannot
  do this"; a disabled one says what is missing and where.

Permissions come FIRST and are unchanged: the templates still ask
``may_open()`` / ``current_user.can()`` before drawing an entry, live or
disabled, so a profile without the permission sees neither.

Where SATOM already records which products a feature serves, the answer is
DERIVED from that record (upgrade_flow.prep_kinds, the automation catalog,
the firmware and naming capabilities, LuaScript.TARGETS, ...). A hand-kept
copy here is how the menu would come to disagree with the page the day the
feature grows a product.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

GLOBAL = "global"


def _fortiweb() -> Iterable[str]:
    return ("fortiweb",)


def _backup_kinds() -> Iterable[str]:
    from .backup import CONFIG_BACKUP_KINDS
    return CONFIG_BACKUP_KINDS


def _upgrade_kinds() -> Iterable[str]:
    from ..views.upgrade_flow import prep_kinds
    return prep_kinds()


def _migration_kinds() -> Iterable[str]:
    from ..views.migration_report import PRODUCTS
    return PRODUCTS


def _automation_kinds() -> Iterable[str]:
    from .scheduled_actions import USER_ACTIONS
    return {p for spec in USER_ACTIONS for p in (spec.products or ())}


def _capacity_kinds() -> Iterable[str]:
    # The object-type catalog (capacity.OBJECT_TYPES) counts FortiWeb
    # objects: server policies, web-protection profiles, certificates, SNI.
    from .capacity import PRODUCT_DEFAULT
    return (PRODUCT_DEFAULT,)


def _firmware_kinds() -> Iterable[str]:
    from ..views.firmware import _PRODUCTS
    return tuple(_PRODUCTS)


def _template_kinds() -> Iterable[str]:
    # Template kinds (web-protection profile, server policy, system profile,
    # structure) exist on FortiWeb and FortiADC only.
    return ("fortiweb", "fortiadc")


def _lua_kinds() -> Iterable[str]:
    from ..models import LuaScript
    return LuaScript.TARGETS


def _every_device() -> Iterable[str] | None:
    return None  # None = every device ADOM


@dataclass(frozen=True)
class Entry:
    key: str
    blueprints: tuple[str, ...]
    kinds: Callable[[], Iterable[str] | None]
    why: str
    #: Endpoint per product when it differs from the FortiWeb one.
    endpoints: tuple[tuple[str, str], ...] = ()


ENTRIES: dict[str, Entry] = {e.key: e for e in (
    # Fleet
    Entry("waf", ("waf", "attack_search", "exceptions", "artifacts"), _fortiweb,
          "the WAF pages read FortiWeb web-protection objects"),
    # Operations
    Entry("reach_batch", ("reach_batch",), _fortiweb,
          "it tests FortiWeb server policies against their back-ends"),
    Entry("config_compare", ("config_compare",), _fortiweb,
          "it compares FortiWeb server policies"),
    Entry("backups", ("backups",), _backup_kinds,
          "SATOM has no configuration-backup transport for this product yet"),
    # Troubleshooting since 2026-10-14: Diagnose Log Collection runs each
    # ADOM's own battery (services/diag_battery.py) on that ADOM's devices.
    Entry("logs", ("logs",), _every_device, ""),
    Entry("import_backup", ("import_backup",), _fortiweb,
          "the offline parser reads FortiWeb configuration files"),
    # Automation
    Entry("upgrade_flow", ("upgrade_flow",), _upgrade_kinds,
          "the staged upgrade flow cannot pre-flight and flash this product end to end"),
    Entry("migration_report", ("migration_report",), _migration_kinds,
          "there is no migration catalog for this product"),
    Entry("automations", ("automations",), _automation_kinds,
          "no operator automation in the catalog targets this product"),
    Entry("provisioning", ("provisioning",), _fortiweb,
          "it composes FortiWeb configuration objects"),
    # Administrator
    Entry("capacity", ("capacity",), _capacity_kinds,
          "the capacity catalog counts FortiWeb object types"),
    Entry("firmware", ("firmware",), _firmware_kinds,
          "firmware image management does not apply to this product"),
    # Every device ADOM: Scheme and Discovery list the same object types —
    # every table the product's configuration sweep reads (views/naming.py).
    Entry("naming", ("naming",), _every_device, ""),
    Entry("segments", ("segments",), _every_device, ""),
    Entry("signatures", ("signatures",), lambda: ("fortiweb", "fortiadc"),
          "SATOM keeps no signature database for this product",
          endpoints=(("fortiweb", "signatures.index"), ("fortiadc", "adc.signatures"))),
    Entry("templates", ("templates",), _template_kinds,
          "the template kinds are FortiWeb and FortiADC objects"),
    # Plugins
    Entry("plugins", ("plugins",), _every_device, ""),
    Entry("lua_studio", ("lua_studio",), _lua_kinds,
          "this product has no scripting object to deploy to"),
)}


@dataclass(frozen=True)
class State:
    on: bool
    reason: str
    endpoint: str | None


def _key_name(product) -> tuple[str, str]:
    if isinstance(product, str):
        return product, product
    # The template's ``product`` is the branding registry entry: a dict.
    get = product.get if isinstance(product, dict) else (lambda k, d=None: getattr(product, k, d))
    key = get("key") or ""
    return key, get("name") or key


def supports(key: str, product_key: str) -> bool:
    """Whether the page behind entry *key* works for *product_key*'s devices."""
    entry = ENTRIES[key]
    if product_key == GLOBAL:
        return False
    try:
        kinds = entry.kinds()
    except Exception:  # noqa: BLE001 - an unreadable record disables, never 500s
        return False
    return True if kinds is None else product_key in set(kinds)


def state(key: str, product) -> State:
    """Sidebar state of entry *key* in *product*'s ADOM (template global
    ``adom_menu``). Unknown keys raise: a typo in a template must fail the
    render tests, not draw a silently disabled entry."""
    entry = ENTRIES[key]
    pkey, pname = _key_name(product)
    on = supports(key, pkey)
    endpoint = dict(entry.endpoints).get(pkey) if entry.endpoints else None
    if on and entry.endpoints and endpoint is None:
        on = False
    reason = "" if on else f"Not available for {pname}: {entry.why}."
    return State(on=on, reason=reason, endpoint=endpoint)


def gate_allows(bp_name: str, product_key: str) -> bool:
    """True when *bp_name* backs an entry that is LIVE in *product_key*'s
    ADOM. The product gate asks this before redirecting, so the allowlists
    in app/__init__.py and this table cannot disagree about a live entry."""
    if product_key in (GLOBAL, "fortiweb"):
        return False
    for entry in ENTRIES.values():
        if bp_name in entry.blueprints and supports(entry.key, product_key):
            if entry.endpoints:
                want = dict(entry.endpoints).get(product_key, "")
                if want.split(".", 1)[0] != bp_name:
                    continue
            return True
    return False
