"""Product branding registry.

The app ships two products that share the same chrome but differ in
identity and (for now) scope:

* ``fortiweb``  — the full Web Application Firewall manager.
* ``fortiadc``  — Application Delivery Controller. Basic structure only.

The selected product lives in ``session['product']`` and is injected into
every template as ``product`` by the app-factory context processor.
"""
from __future__ import annotations

PRODUCTS: dict[str, dict] = {
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
        "description": "Application Delivery Controller management. "
                       "Basic structure — modules coming soon.",
    },
}

DEFAULT_PRODUCT = "fortiweb"


def get_product(key: str | None) -> dict:
    """Return the branding dict for ``key`` (defaults to FortiWeb)."""
    return PRODUCTS.get(key or "", PRODUCTS[DEFAULT_PRODUCT])


def is_valid(key: str | None) -> bool:
    return key in PRODUCTS
