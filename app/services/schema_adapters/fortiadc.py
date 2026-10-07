"""FortiADC: ``tree`` + ``show full-configuration``; no REST probe.

Same implementation as FortiWeb (``services.schema_harvest``). NOTHING here
was checked against a FortiADC: the lab has none. The tree format is assumed
to be the FortiOS-family format ``cli_schema.parse_tree`` detects, and the
CLI -> REST rule (``config load-balance virtual-server`` ->
``/api/load_balance_virtual_server``) is the documented convention
``cli_schema.PATH_RULE_STATUS`` already marks ``unverified``.
"""
from __future__ import annotations

from .. import cli_schema
from . import Adapter, Capabilities, register

#: Shown in the UI next to the adapter; removed only by a check on a real box.
UNVERIFIED = {
    "tree": "no FortiADC in the lab: the tree format is assumed FortiOS-family",
    "show_full": "parsed with the shared dump grammar; never compared with a FortiADC tree",
    "path_rule": "CLI -> REST rule (underscore paths, _child_ for nested tables) is a "
                 "documented convention (cli_schema.PATH_RULE_STATUS = %r)"
                 % cli_schema.PATH_RULE_STATUS.get("fortiadc"),
}


def _harvest(appliance, **kw):
    from .. import schema_harvest
    res = schema_harvest.harvest(appliance, **kw)
    res["unverified"] = sorted(UNVERIFIED)
    return res


ADAPTER = register(Adapter(
    product="fortiadc", label="FortiADC",
    capabilities=Capabilities(tree=True, show_full=True, rest_schema=False, rest_probe=False),
    verified_on=(), unverified=UNVERIFIED, live=True,
    notes="REST paths are underscore paths (/api/load_balance_virtual_server); "
          "no REST probe is run until a FortiADC verifies the rule."),
    _harvest)
