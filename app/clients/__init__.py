"""Client factory — the ONE platform place that maps an appliance's ``kind``
to its product REST client. Business modules must never import a product
client for kind-dispatch; they call :func:`client_for` instead (the import
direction is enforced by ``tests/test_product_separation.py``)."""
from __future__ import annotations


def client_for(appliance):
    """Return the right REST client for the appliance's product kind."""
    kind = getattr(appliance, "kind", "")
    if kind == "fortiadc":
        from .fortiadc import FortiADCClient
        return FortiADCClient(appliance)
    if kind == "fortianalyzer":
        from .fortianalyzer import FortiAnalyzerClient
        return FortiAnalyzerClient(appliance)
    if kind == "fortiauthenticator":
        from .fortiauthenticator import FortiAuthenticatorClient
        return FortiAuthenticatorClient(appliance)
    # NOTE: an unrecognised kind falls through to FortiWeb rather than raising.
    # That default is load-bearing history, but it is also how a newly added
    # product silently gets the WRONG client: the Appliances "Test" button then
    # runs a FortiWeb status check against it, fails, and pins the device to
    # 'offline' forever. tests/test_fac.py asserts every non-placeholder ADOM
    # has an explicit arm here, so the next product cannot inherit that bug.
    from .fortiweb import FortiWebClient
    return FortiWebClient(appliance)
