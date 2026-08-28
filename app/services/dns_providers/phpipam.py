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

from .base import (Address, Capabilities, DnsProvider, DnsRecord,
                   ProviderError, mask_from_prefix)


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

    # No record CRUD in ANY phpIPAM install — its API simply has none.
    may_write = False
    may_allocate = True

    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider="phpipam", label="phpIPAM (IPAM, read-only DNS)",
            can_write=False, record_types=[], needs_zone=False, needs_view=False,
            can_allocate=True, needs_pool=True,
            notes="phpIPAM does not expose DNS record CRUD via its API. Matching "
                  "host/dns_name entries are listed read-only; use the PowerDNS "
                  "server directly (or EfficientIP/netbox-dns) for writes. "
                  "Address ALLOCATION is supported — give a subnet id or CIDR.")

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

    # -- address allocation ----------------------------------------------
    #
    # phpIPAM cannot write DNS records but IS an address pool, which is why
    # ``can_allocate`` is a separate flag from ``can_write``.
    #   GET    /subnets/{id}/            — mask + gateway
    #   GET    /subnets/cidr/{cidr}/     — resolve a CIDR to a subnet id
    #   POST   /addresses/first_free/    — reserve the next free host (atomic
    #                                      on the server; do NOT read-then-write)
    #   DELETE /addresses/{id}/          — hand it back
    #
    # UNVERIFIED end-to-end: no phpIPAM instance exists in the fleet.

    def _json(self, r: httpx.Response) -> dict:
        try:
            data = r.json()
        except Exception:  # noqa: BLE001
            return {}
        return data if isinstance(data, dict) else {}

    def _fail(self, r: httpx.Response, what: str) -> None:
        if r.status_code < 400:
            return
        msg = str(self._json(r).get("message") or f"HTTP {r.status_code}")
        raise ProviderError(f"phpIPAM {what} failed: {msg}")

    def _subnet_id(self, c: httpx.Client, pool: str) -> str:
        pool = (pool or str(self.cfg.get("default_pool") or "")).strip()
        if not pool:
            raise ProviderError(
                "No IPAM subnet given and no default subnet is configured "
                "(Settings -> DNS Records -> Default IPAM pool).")
        if pool.isdigit():
            return pool
        r = c.get(f"/subnets/cidr/{pool}/")
        if r.status_code == 404:
            raise ProviderError(f"phpIPAM: subnet {pool!r} not found.")
        self._fail(r, "subnet lookup")
        rows = self._json(r).get("data") or []
        rows = rows if isinstance(rows, list) else [rows]
        sid = str((rows[0] or {}).get("id") or "") if rows else ""
        if not sid:
            raise ProviderError(f"phpIPAM: subnet {pool!r} not found.")
        return sid

    def allocate_address(self, hostname: str = "", pool: str = "") -> Address:
        try:
            with self._client() as c:
                sid = self._subnet_id(c, pool)
                body = {"subnetId": sid}
                if hostname:
                    body["hostname"] = hostname
                    body["description"] = f"Reserved by SATOM for {hostname}"
                # first_free is a POST on purpose: phpIPAM picks AND writes in
                # one server-side operation. Reading the free address first and
                # POSTing it back races another operator into the same address.
                r = c.post("/addresses/first_free/", data=body)
                self._fail(r, "allocation")
                payload = self._json(r)
                ref = str(payload.get("id") or "")
                data = payload.get("data")
                addr = ""
                if isinstance(data, str):
                    addr = data.strip()
                elif isinstance(data, dict):
                    addr = str(data.get("ip") or data.get("ip_addr") or "")
                    ref = ref or str(data.get("id") or "")
                if not addr:
                    raise ProviderError(
                        f"phpIPAM allocated nothing usable in subnet {sid} "
                        f"(response: {str(payload)[:200]}).")
                sub = {}
                rs = c.get(f"/subnets/{sid}/")
                if rs.status_code < 400:
                    sub = self._json(rs).get("data") or {}
                    sub = sub if isinstance(sub, dict) else {}
        except httpx.HTTPError as exc:
            raise ProviderError(f"phpIPAM allocation failed: {exc}") from exc
        gw = sub.get("gateway")
        prefix = None
        if str(sub.get("mask") or "").isdigit():
            prefix = int(sub["mask"])
        return Address(
            address=addr, ref=ref, prefix_len=prefix,
            netmask=mask_from_prefix(prefix),
            gateway=str((gw or {}).get("ip_addr") or "")
            if isinstance(gw, dict) else str(gw or ""),
            pool=str(sub.get("subnet") or sid),
            extra={"subnetId": sid},
        )

    def release_address(self, address: str, ref: str = "") -> None:
        if not ref:
            raise ProviderError(
                "phpIPAM release needs the address id recorded when "
                f"{address or 'the address'} was taken.")
        try:
            with self._client() as c:
                r = c.delete(f"/addresses/{ref}/")
            if r.status_code == 404:
                return  # already gone — releasing twice is not an error
            self._fail(r, "release")
        except httpx.HTTPError as exc:
            raise ProviderError(f"phpIPAM release failed: {exc}") from exc
