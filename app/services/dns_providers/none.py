"""The default 'off' provider — no IPAM configured.

When active, the +DNS Records button is hidden and the CRUD endpoints refuse.
Keeps the rest of the code path (factory, capabilities) uniform.
"""
from __future__ import annotations

from .base import Capabilities, DnsProvider


class NoneProvider(DnsProvider):
    key = "none"
    label = "Disabled"

    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider="none", label="Disabled", can_write=False,
            record_types=[], needs_zone=False, needs_view=False,
            notes="No DNS/IPAM provider configured. Configure one in "
                  "Settings -> DNS Records to manage records from here.",
        )

    def test_connection(self) -> tuple[bool, str]:
        return False, "No provider configured."

    def list_records(self, name: str = "", zone: str = ""):
        return []
