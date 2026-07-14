"""phpIPAM provider — read-oriented; phpIPAM is an IPAM, not a DNS server.

phpIPAM stores a ``hostname``/``dns_name`` per address but does NOT expose DNS
resource-record CRUD through its public REST API. Actual DNS writes require its
PowerDNS integration, whose records are not published as API controllers. This
provider therefore:

* lists matching addresses (hostname/dns_name -> IP) as read-only A records;
* refuses create/update/delete with a clear message (``can_write=False``),
  rather than silently no-op'ing in a customer's IPAM.

Auth: static app-code token in the ``token`` header; ``app_id`` names the API
app. Base URL is the phpIPAM root (``/api/<app_id>/`` is appended).

NOTE (2026-07-14): no phpIPAM instance exists in the fleet -> UNVERIFIED.
"""
from __future__ import annotations

import httpx

from .base import Capabilities, DnsProvider, DnsRecord, ProviderError


class PhpIpamProvider(DnsProvider):
    key = "phpipam"
    label = "phpIPAM"

    def _base(self) -> str:
        base = str(self.cfg.get("base_url") or "").rstrip("/")
        if not base:
            raise ProviderError("phpIPAM base URL is not configured.")
        app = str(self.cfg.get("app_id") or "").strip("/")
        if not app:
            raise ProviderError("phpIPAM API app id is not configured.")
        return f"{base}/api/{app}"

    def _client(self) -> httpx.Client:
        verify = bool(self.cfg.get("verify_ssl", True))
        token = self.cfg.get("secret") or ""
        return httpx.Client(
            base_url=self._base(), verify=verify, timeout=12.0,
            headers={"token": token, "Accept": "application/json"})

    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider="phpipam", label="phpIPAM (IPAM, read-only DNS)",
            can_write=False, record_types=[], needs_zone=False, needs_view=False,
            notes="phpIPAM does not expose DNS record CRUD via its API. Matching "
                  "host/dns_name entries are listed read-only; use the PowerDNS "
                  "server directly (or EfficientIP/netbox-dns) for writes.")

    def test_connection(self) -> tuple[bool, str]:
        try:
            with self._client() as c:
                r = c.get("/sections/")
            if r.status_code in (401, 403):
                return False, "Authentication failed (bad token/app id)."
            if r.status_code >= 400:
                return False, f"HTTP {r.status_code}"
            return True, "Connection OK (read-only DNS)."
        except httpx.HTTPError as exc:
            return False, f"Connection error: {exc}"

    def list_records(self, name: str = "", zone: str = "") -> list[DnsRecord]:
        term = (name or "").rstrip(".")
        if not term:
            return []
        try:
            with self._client() as c:
                r = c.get(f"/addresses/search_hostname/{term}/")
                if r.status_code == 404:
                    return []
                if r.status_code >= 400:
                    raise ProviderError(f"phpIPAM search failed (HTTP {r.status_code}).")
        except httpx.HTTPError as exc:
            raise ProviderError(f"phpIPAM list failed: {exc}") from exc
        rows = (r.json() or {}).get("data") or []
        out = []
        for row in rows if isinstance(rows, list) else []:
            host = str(row.get("hostname") or row.get("dns_name") or "").rstrip(".")
            ip = str(row.get("ip") or "")
            if not (host and ip):
                continue
            out.append(DnsRecord(
                id=str(row.get("id") or ""), name=host, type="A", value=ip,
                extra={"source": "ipam", "read_only": True,
                       "subnetId": row.get("subnetId")}))
        return out
