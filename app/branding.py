"""Product branding registry.

The app ships three "ADOMs" that share the same chrome but differ in
identity and scope:

* ``global``    — the fleet-wide console at ``/`` spanning both products.
* ``fortiweb``  — the full Web Application Firewall manager (under ``/web``).
* ``fortiadc``  — Application Delivery Controller (under ``/adc``).

The selected product lives in ``session['product']`` and is injected into
every template as ``product`` by the app-factory context processor.
"""
from __future__ import annotations

PRODUCTS: dict[str, dict] = {
    "global": {
        "key": "global",
        "name": "Global",
        "title": "Fortinet-Manager",
        "tagline": "Global — all products",
        "mark": "img/global-mark.svg",
        "description": "One console over the whole fleet — dashboards, "
                       "metrics, jobs, certificates and administration "
                       "across FortiWeb and FortiADC.",
    },
    "fortiweb": {
        "key": "fortiweb",
        "name": "FortiWeb",
        "title": "FortiWeb-Manager",
        "tagline": "Web Application Firewall",
        "mark": "img/fortiweb-mark.svg",
        "description": "Manage server policies, web protection, exceptions, "
                       "backups and the full FortiWeb appliance fleet.",
    },
    "fortiadc": {
        "key": "fortiadc",
        "name": "FortiADC",
        "title": "FortiADC-Manager",
        "tagline": "Application Delivery Controller",
        "mark": "img/fortiadc-mark.svg",
        "description": "Manage virtual servers, server/link/global load "
                       "balancing, WAF, network security and the FortiADC "
                       "appliance fleet.",
    },
}

DEFAULT_PRODUCT = "fortiweb"


def get_product(key: str | None) -> dict:
    """Return the branding dict for ``key`` (defaults to FortiWeb)."""
    return PRODUCTS.get(key or "", PRODUCTS[DEFAULT_PRODUCT])


def is_valid(key: str | None) -> bool:
    return key in PRODUCTS
