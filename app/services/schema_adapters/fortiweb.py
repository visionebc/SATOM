"""FortiWeb: ``tree`` + ``show full-configuration`` + REST shape probe.

The reference adapter. ``services.schema_harvest`` is the implementation (kb-core);
this module only declares it in the adapter registry.
"""
from __future__ import annotations

from . import Adapter, Capabilities, Verification, register


def _harvest(appliance, **kw):
    from .. import schema_harvest
    return schema_harvest.harvest(appliance, **kw)


ADAPTER = register(Adapter(
    product="fortiweb", label="FortiWeb",
    capabilities=Capabilities(tree=True, show_full=True, rest_schema=False, rest_probe=True),
    verified_on=(Verification("2026-10-07", "fortiweb17 (lab)", "7.6.8"),
                 Verification("2026-10-07", "fortiweb18 (lab)", "8.0.6 build0116")),
    live=True,
    notes="tree prints every object/field with CLI id, type and options; the REST "
          "shape probe classifies each tree object by the SHAPE of its answer "
          "(FortiWeb answers an unknown nested path with the parent's rows)."),
    _harvest)
