"""Which GUI API endpoints a layout may name for reading and writing.

A layout (``bind``, a settings form's ``write``) can name an endpoint of the
GUI's own API (``api:<path>``) the GUI was measured writing. SATOM reads such
an endpoint with GET and writes it with the GUI's method -- so a layout must
never be able to point it at a device ACTION (a GET can act). Both sides use
this one rule: the harvester never emits an endpoint that fails it, SATOM never
reads or writes one and refuses a layout that names one (layouts may come
from a harvester SATOM does not run). Standard library only.
"""
from __future__ import annotations

import re

API = "api:"
#: Configuration objects of the GUI's own API.
_SAFE_API = re.compile(r"api:(system|log|waf|server|user|network|router|wvs|policy)/[a-z0-9_-]+"
                       r"(\.[a-z0-9_-]+)*", re.I)
#: Device actions and secrets, whatever the namespace.
_ACTION = re.compile(r"reboot|shutdown|restore|upgrade|format|factory|reset|logout|backup|"
                     r"restart|import|upload|execute|exec|action|license|firmware|maintenance|"
                     r"shell|debug|diagnose|password|token|key|secret|cert", re.I)


def is_api(ep) -> bool:
    return isinstance(ep, str) and ep.startswith(API)


def safe_api(ep) -> bool:
    """True for a GUI API configuration endpoint a layout may name."""
    return is_api(ep) and bool(_SAFE_API.fullmatch(ep)) and not _ACTION.search(ep[len(API):])
