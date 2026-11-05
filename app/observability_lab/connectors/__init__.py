"""Connector contract.

A connector reads one source (one device, one inventory, one API) and returns
FACTS: ``(object_ref, layer, key, value)``. The graph and the UI only read
stored facts, so adding a connector (Cisco later) adds facts and changes
nothing else.

Layers: ``device`` (identity/licence), ``L1``, ``L2``, ``L3``, ``L4``, ``L7``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LAYERS = ("device", "L1", "L2", "L3", "L4", "L7")


@dataclass
class FactRow:
    object_ref: str
    layer: str
    key: str
    value: Any


@dataclass
class EndpointResult:
    """Outcome of one read. ``absent`` = the build does not serve this endpoint
    (benign, not an error); ``ok=False`` = the read failed and its facts are ERROR."""
    endpoint: str
    path: str
    layers: tuple
    ok: bool = True
    absent: bool = False
    error: str = ""
    rows: int = 0
    elapsed_ms: int = 0
    facts: list = field(default_factory=list)
    metrics: list = field(default_factory=list)  # (name, labels dict, value)


class Connector:
    kind = ""
    label = ""
    available = True
    #: How the source form asks for the secret.
    secret_label = "Password"
    secret_help = ""
    uses_username = True
    uses_vdom = True

    def __init__(self, source, *, secret: str = "", transport=None):
        self.source = source
        self.secret = secret
        self.transport = transport

    def test(self) -> dict:  # {"ok": bool, "detail": str, "build": str}
        raise NotImplementedError

    def collect(self) -> list[EndpointResult]:
        raise NotImplementedError

    def capabilities(self) -> dict:
        """layer -> list of keys this connector produces (measured on its builds)."""
        return {}


REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    REGISTRY[cls.kind] = cls
    return cls


#: Kinds in the design that are not built yet — listed in the UI, never faked.
PLANNED = {
    "efficientip": "EfficientIP SOLIDserver (DDI)",
    "netbox": "NetBox",
    "api": "Internal API (generic REST)",
}


def _load() -> None:
    from . import fortigate, fortiweb, satom_cache  # noqa: F401 — each registers itself


def get(kind: str) -> type[Connector]:
    _load()
    return REGISTRY[kind]


def kinds() -> dict:
    _load()
    # Inside SATOM every source is read through SATOM (connectors/satom.py).
    return {k: c.label.replace("(direct)", "(from SATOM)") for k, c in REGISTRY.items()}
