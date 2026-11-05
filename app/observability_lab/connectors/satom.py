"""``fortinet_source = satom``: every source inside SATOM is read from SATOM
only — never from the device (operator, 2026-11-05: "Observability must take
the data from SATOM and hold it itself").

The configuration comes from SATOM's device cache, nested tables from its
``deep`` snapshot, and the live numbers from the series SATOM's own collectors
write; what SATOM does not collect is shown as such. See
:mod:`.satom_cache` for the connectors. Observability never decrypts a SATOM
credential and never opens a connection to a device.
"""
from __future__ import annotations

from .satom_cache import (SatomFortiADC, SatomFortiAnalyzer, SatomFortiAuthenticator, SatomFortiGate,
                          SatomFortiWeb)

#: Source.kind stays the product (what the overview, insights and graph key on).
BY_PRODUCT = {"fortiweb": SatomFortiWeb, "fortigate": SatomFortiGate, "fortiadc": SatomFortiADC,
              "fortiauthenticator": SatomFortiAuthenticator, "fortianalyzer": SatomFortiAnalyzer}
