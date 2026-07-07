"""Client factory — the ONE platform place that maps an appliance's ``kind``
to its product REST client. Business modules must never import a product
client for kind-dispatch; they call :func:`client_for` instead (the import
direction is enforced by ``tests/test_product_separation.py``)."""
from __future__ import annotations


def client_for(appliance):
    """Return the right REST client for the appliance's product kind."""
    if getattr(appliance, "kind", "") == "fortiadc":
        from .fortiadc import FortiADCClient
        return FortiADCClient(appliance)
    from .fortiweb import FortiWebClient
    return FortiWebClient(appliance)
