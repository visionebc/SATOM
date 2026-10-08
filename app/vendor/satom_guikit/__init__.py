"""satom_guikit — the GUI-template contract shared by the harvester and SATOM.

Standard library only (a guard test walks every import): SATOM vendors this
package by hash, and a future customer-run harvester must be able to produce
templates SATOM reads without anything else from this repository.

* :mod:`.template` — schema versions, exact-build identity (``/1`` -> ``/2``),
  the field keys a layout places, and the content hash;
* :mod:`.strings` — split a template into structure and Fortinet's texts;
* :mod:`.diff` — what changed between the layouts of two builds.
"""
from .diff import diff
from .strings import merge, split
from .template import (SCHEMA_V1, SCHEMA_V2, SCHEMAS, content_hash, identity, layout_keys,
                       not_in_gui, to_v2)

__version__ = "1.0.0"

__all__ = ["SCHEMA_V1", "SCHEMA_V2", "SCHEMAS", "content_hash", "diff", "identity",
           "layout_keys", "merge", "not_in_gui", "split", "to_v2", "__version__"]
