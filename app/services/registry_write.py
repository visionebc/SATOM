"""The ONE writer of the endpoint catalog.

Before this module there were two — ``registry.save`` (FortiWeb) and
``adc_api.registry_save`` (FortiADC) — with the same validation typed twice,
and they had already drifted: the FortiADC one re-checks ``row.product`` before
editing a row by id and the FortiWeb one does not, so a ``registry.save`` POST
carrying the id of a FortiADC row would rewrite that row from the FortiWeb
page. That is the ADOM isolation this app enforces everywhere else, missing in
the one place that writes the catalog every service resolves names through.

The bulk registration the CLI↔API discovery run performs would have been a
THIRD copy. Two authors of one badge is how ``api.js`` and ``main.js`` ended up
disagreeing about appliance status; two authors of a catalog write is worse,
because the disagreement is persisted.

No Flask surface here on purpose: this returns ``(ok, message, row)`` and the
views own the flash, the redirect and the audit line. A helper that flashed
could not be called from a batch loop without spraying one message per row.
"""
from __future__ import annotations

import re

from ..extensions import db
from ..models import RegistryEndpoint
from ..registry import loader

#: A catalog name is a KEY other code types by hand (``loader.resolve``), so it
#: stays in the character set that survives being a Python identifier fragment,
#: a URL segment and a YAML key at once.
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

#: The api_version column a new row takes when the caller does not say. Per
#: product because the two catalogs genuinely differ: FortiWeb's REST is v2.0,
#: FortiADC's is v1. A single default would silently file half the fleet under
#: the wrong version, and ``(product, api_version, name)`` is the uniqueness
#: key — so the wrong default does not collide, it DUPLICATES.
DEFAULT_API_VERSION = {"fortiweb": "v2.0", "fortiadc": "v1"}

#: Products whose catalog this writer will touch. Not a style check: the
#: FortiAnalyzer / FortiAuthenticator catalogs are seeded but have no editor,
#: and silently accepting a write for them would create rows nothing renders.
WRITABLE_PRODUCTS = ("fortiweb", "fortiadc")


def default_api_version(product: str) -> str:
    return DEFAULT_API_VERSION.get(product, "v2.0")


def validate(product: str, name: str, urn: str) -> str:
    """"" when the pair may be written, else the reason it may not."""
    if product not in WRITABLE_PRODUCTS:
        return "%s endpoints are not editable." % (product or "unknown")
    if not name or not urn:
        return "Name and URN are both required."
    if not NAME_RE.match(name):
        return ('Endpoint name may only contain letters, digits, "_", "-" '
                'and ".".')
    if not urn.startswith("/"):
        return ("URN must be an absolute API path "
                "(e.g. /api/v2.0/cmdb/... or /api/load_balance_pool).")
    return ""


def save_endpoint(*, product: str, name: str, urn: str,
                  api_version: str = "", row_id: int | None = None,
                  actor: str = "", commit: bool = True) -> tuple[bool, str, object]:
    """Create (no ``row_id``) or update one catalog row. ``(ok, message, row)``.

    ``commit=False`` lets a batch add many rows and commit once — but the
    duplicate check below still sees them, because it runs against the session,
    not against a snapshot taken before the loop.
    """
    name = (name or "").strip()
    urn = (urn or "").strip()
    product = (product or "").strip().lower()
    api_version = (api_version or "").strip() or default_api_version(product)

    bad = validate(product, name, urn)
    if bad:
        return False, bad, None

    row = None
    if row_id:
        row = db.session.get(RegistryEndpoint, row_id)
        # An edit may only ever touch a row of the product whose page asked.
        # Without this the FortiWeb editor can rewrite a FortiADC entry.
        if row is None or row.product != product:
            return False, "No such %s endpoint." % product, None

    dup = RegistryEndpoint.query.filter_by(
        product=product, api_version=api_version, name=name).first()
    if dup is not None and (row is None or dup.id != row.id):
        return False, 'An endpoint named "%s" already exists (%s).' % (name, dup.urn), None

    created = row is None
    if created:
        row = RegistryEndpoint(product=product, api_version=api_version)
        db.session.add(row)

    row.name, row.urn, row.api_version = name, urn, api_version
    if actor:
        row.updated_by = actor
    if commit:
        db.session.commit()
        invalidate(product)
    return True, ("created" if created else "updated"), row


def invalidate(product: str) -> None:
    """Drop the loader cache for one product.

    Its own function because a batch commits ONCE and must invalidate once —
    and because forgetting it is invisible: the rows are in the database and
    every reader keeps serving the cached catalog from before the run.

    FortiADC has a SECOND cache: ``adc_menu`` groups the catalog into the GUI
    menu the ADC hub renders, and it memoises that grouping. Invalidating only
    the loader would put the new endpoint in the catalog and leave it out of the
    menu — present and invisible, which reads as "the write failed".
    """
    if product == "fortiadc":
        loader.invalidate_adc_cache()
        from . import adc_menu

        adc_menu.invalidate()
    else:
        loader.invalidate_cache()


__all__ = ["NAME_RE", "DEFAULT_API_VERSION", "WRITABLE_PRODUCTS",
           "default_api_version", "validate", "save_endpoint", "invalidate"]
