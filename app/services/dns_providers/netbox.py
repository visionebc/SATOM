"""NetBox provider — records via the ``netbox-dns`` plugin when present.

NetBox **core** has no DNS resource records: IPAM only carries a single
``dns_name`` string per IP address (an implicit forward/reverse A/PTR). Real RR
management lives in the community ``netbox-dns`` plugin
(``/api/plugins/netbox-dns/records/``). This provider probes for the plugin at
connect time and adapts:

* plugin present  -> full CRUD over records (A/AAAA/CNAME/MX/TXT/NS/PTR/SRV).
* plugin absent   -> read-only listing of matching IPAM ``dns_name`` entries;
  write verbs refuse with a clear message (``can_write=False``).

Auth: ``Authorization: Token <token>`` header.

NOTE (2026-07-14): written to the documented NetBox 3.x/4.x + netbox-dns API.
No NetBox instance exists in the fleet -> UNVERIFIED end-to-end.
"""
from __future__ import annotations

import httpx

from .base import (Address, Capabilities, DnsProvider, DnsRecord,
                   ProviderError, mask_from_prefix)

_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV"]
_PLUGIN = "/api/plugins/netbox-dns"


class NetBoxProvider(DnsProvider):
    key = "netbox"
    label = "NetBox"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self._plugin: bool | None = None

    # -- http ------------------------------------------------------------
    def _client(self) -> httpx.Client:
        base = str(self.cfg.get("base_url") or "").rstrip("/")
        if not base:
            raise ProviderError("NetBox base URL is not configured.")
        token = self.cfg.get("secret") or ""
        verify = bool(self.cfg.get("verify_ssl", True))
        return httpx.Client(
            base_url=base, verify=verify, timeout=12.0,
            headers={"Authorization": f"Token {token}",
                     "Accept": "application/json",
                     "Content-Type": "application/json"})

    def _has_plugin(self, c: httpx.Client) -> bool:
        if self._plugin is None:
            try:
                r = c.get(f"{_PLUGIN}/records/", params={"limit": 1})
                self._plugin = r.status_code < 400
            except httpx.HTTPError:
                self._plugin = False
        return self._plugin

    # -- introspection ---------------------------------------------------
    def capabilities(self) -> Capabilities:
        try:
            with self._client() as c:
                has = self._has_plugin(c)
        except ProviderError:
            has = False
        if has:
            return Capabilities(
                provider="netbox", label="NetBox (netbox-dns)", can_write=True,
                record_types=_TYPES, needs_zone=True, needs_view=False,
                can_allocate=True, needs_pool=True,
                notes="netbox-dns plugin detected. A zone is required to create "
                      "records; a prefix (id or CIDR) to allocate an address.")
        # Core IPAM cannot write records but CAN hand out addresses — the two
        # flags are independent for exactly this case.
        return Capabilities(
            provider="netbox", label="NetBox (core IPAM)", can_write=False,
            record_types=[], needs_zone=False, needs_view=False,
            can_allocate=True, needs_pool=True,
            notes="netbox-dns plugin not detected. Only IPAM dns_name entries "
                  "are listed (read-only). Install netbox-dns for record CRUD. "
                  "Address ALLOCATION works either way — give a prefix id or "
                  "CIDR.")

    def test_connection(self) -> tuple[bool, str]:
        try:
            with self._client() as c:
                r = c.get("/api/status/")
                if r.status_code == 401 or r.status_code == 403:
                    return False, "Authentication failed."
                if r.status_code >= 400:
                    return False, f"HTTP {r.status_code}"
                has = self._has_plugin(c)
            return True, ("Connected; netbox-dns plugin present."
                          if has else
                          "Connected; netbox-dns plugin NOT present (read-only).")
        except httpx.HTTPError as exc:
            return False, f"Connection error: {exc}"

    # -- helpers ---------------------------------------------------------
    def _zone_id(self, c: httpx.Client, zone: str) -> int:
        r = c.get(f"{_PLUGIN}/zones/", params={"name": zone, "limit": 1})
        if r.status_code >= 400:
            raise ProviderError(f"NetBox zone lookup failed (HTTP {r.status_code}).")
        results = (r.json() or {}).get("results") or []
        if not results:
            raise ProviderError(f"Zone {zone!r} not found in NetBox.")
        return int(results[0]["id"])

    @staticmethod
    def _label(fqdn: str, zone: str) -> str:
        fqdn = fqdn.rstrip(".")
        zone = zone.rstrip(".")
        if zone and fqdn == zone:
            return "@"
        if zone and fqdn.endswith("." + zone):
            return fqdn[: -(len(zone) + 1)]
        return fqdn

    # -- CRUD ------------------------------------------------------------
    def list_records(self, name: str = "", zone: str = "") -> list[DnsRecord]:
        with self._client() as c:
            if self._has_plugin(c):
                params: dict = {"limit": 200}
                if zone:
                    params["zone"] = zone
                r = c.get(f"{_PLUGIN}/records/", params=params)
                if r.status_code >= 400:
                    raise ProviderError(f"NetBox list failed (HTTP {r.status_code}).")
                out = []
                for row in (r.json() or {}).get("results") or []:
                    fqdn = str(row.get("fqdn") or row.get("name") or "").rstrip(".")
                    if name and name.rstrip(".") not in fqdn:
                        continue
                    zobj = row.get("zone") or {}
                    out.append(DnsRecord(
                        id=str(row.get("id") or ""), name=fqdn,
                        type=str(row.get("type") or "").upper(),
                        value=str(row.get("value") or ""),
                        ttl=row.get("ttl"),
                        zone=str(zobj.get("name") if isinstance(zobj, dict) else zobj or ""),
                        extra={"managed": row.get("managed", False)}))
                return out
            # core IPAM fallback: dns_name entries only
            params = {"limit": 200}
            if name:
                params["dns_name__ic"] = name.rstrip(".")
            r = c.get("/api/ipam/ip-addresses/", params=params)
            if r.status_code >= 400:
                raise ProviderError(f"NetBox IPAM list failed (HTTP {r.status_code}).")
            out = []
            for row in (r.json() or {}).get("results") or []:
                dns_name = str(row.get("dns_name") or "").rstrip(".")
                if not dns_name:
                    continue
                addr = str(row.get("address") or "").split("/")[0]
                out.append(DnsRecord(
                    id=str(row.get("id") or ""), name=dns_name, type="A",
                    value=addr, extra={"source": "ipam", "read_only": True}))
            return out

    def create_record(self, rec: DnsRecord) -> DnsRecord:
        with self._client() as c:
            if not self._has_plugin(c):
                raise ProviderError(
                    "netbox-dns plugin not installed; cannot create records.")
            if not rec.zone:
                raise ProviderError("A zone is required to create a record.")
            body = {"zone": self._zone_id(c, rec.zone),
                    "name": self._label(rec.name, rec.zone),
                    "type": rec.type, "value": rec.value}
            if rec.ttl is not None:
                body["ttl"] = rec.ttl
            r = c.post(f"{_PLUGIN}/records/", json=body)
            if r.status_code >= 400:
                raise ProviderError(f"NetBox create failed: {r.text[:200]}")
            rec.id = str((r.json() or {}).get("id") or "")
            return rec

    def update_record(self, rec: DnsRecord) -> DnsRecord:
        with self._client() as c:
            if not self._has_plugin(c):
                raise ProviderError(
                    "netbox-dns plugin not installed; cannot edit records.")
            if not rec.id:
                raise ProviderError("Record id is required to edit.")
            body = {"type": rec.type, "value": rec.value}
            if rec.ttl is not None:
                body["ttl"] = rec.ttl
            r = c.patch(f"{_PLUGIN}/records/{rec.id}/", json=body)
            if r.status_code >= 400:
                raise ProviderError(f"NetBox edit failed: {r.text[:200]}")
            return rec

    def delete_record(self, rec: DnsRecord) -> None:
        with self._client() as c:
            if not self._has_plugin(c):
                raise ProviderError(
                    "netbox-dns plugin not installed; cannot delete records.")
            if not rec.id:
                raise ProviderError("Record id is required to delete.")
            r = c.delete(f"{_PLUGIN}/records/{rec.id}/")
            if r.status_code >= 400:
                raise ProviderError(f"NetBox delete failed (HTTP {r.status_code}).")

    # -- address allocation ----------------------------------------------
    #
    #   GET    /api/ipam/prefixes/?prefix=<cidr>      — resolve CIDR -> id
    #   POST   /api/ipam/prefixes/{id}/available-ips/ — server picks AND writes
    #   DELETE /api/ipam/ip-addresses/{id}/           — hand it back
    #
    # This works on NetBox CORE — the ``netbox-dns`` plugin is irrelevant here.
    # NetBox core does not model a per-prefix gateway, so ``gateway`` comes
    # back EMPTY rather than inferred from ".1": that guess is wrong often
    # enough, and it is written into an appliance's default route.
    #
    # UNVERIFIED end-to-end: no NetBox instance exists in the fleet.

    def _prefix_id(self, c: httpx.Client, pool: str) -> str:
        pool = (pool or str(self.cfg.get("default_pool") or "")).strip()
        if not pool:
            raise ProviderError(
                "No IPAM prefix given and no default prefix is configured "
                "(Settings -> DNS Records -> Default IPAM pool).")
        if pool.isdigit():
            return pool
        r = c.get("/api/ipam/prefixes/", params={"prefix": pool, "limit": 1})
        if r.status_code >= 400:
            raise ProviderError(
                f"NetBox prefix lookup failed (HTTP {r.status_code}).")
        results = (r.json() or {}).get("results") or []
        if not results:
            raise ProviderError(f"Prefix {pool!r} not found in NetBox.")
        return str(results[0].get("id") or "")

    def allocate_address(self, hostname: str = "", pool: str = "") -> Address:
        try:
            with self._client() as c:
                pid = self._prefix_id(c, pool)
                body: dict = {}
                if hostname:
                    body["dns_name"] = hostname
                    body["description"] = f"Reserved by SATOM for {hostname}"
                r = c.post(f"/api/ipam/prefixes/{pid}/available-ips/",
                           json=body)
                if r.status_code == 409:
                    raise ProviderError(
                        f"NetBox prefix {pool or pid} has no free address.")
                if r.status_code >= 400:
                    raise ProviderError(
                        f"NetBox allocation failed: {r.text[:200]}")
        except httpx.HTTPError as exc:
            raise ProviderError(f"NetBox allocation failed: {exc}") from exc
        data = r.json() or {}
        # available-ips returns a single object; older releases return a list
        # of one when ?limit= is used. Normalise instead of assuming.
        if isinstance(data, list):
            data = data[0] if data else {}
        cidr = str(data.get("address") or "")
        addr, _, plen = cidr.partition("/")
        if not addr:
            raise ProviderError(
                "NetBox returned no address for the prefix "
                f"{pool or pid} (response: {str(data)[:200]}).")
        ref = str(data.get("id") or "")
        if not ref:
            raise ProviderError(
                f"NetBox accepted {addr} but returned no id — check the "
                "prefix by hand before retrying.")
        prefix = int(plen) if plen.isdigit() else None
        return Address(address=addr, ref=ref, prefix_len=prefix,
                       netmask=mask_from_prefix(prefix), gateway="",
                       pool=str(pool or pid), extra={"prefix_id": pid})

    def release_address(self, address: str, ref: str = "") -> None:
        if not ref:
            raise ProviderError(
                "NetBox release needs the ip-address id recorded when "
                f"{address or 'the address'} was taken.")
        try:
            with self._client() as c:
                r = c.delete(f"/api/ipam/ip-addresses/{ref}/")
            if r.status_code == 404:
                return  # already gone — releasing twice is not an error
            if r.status_code >= 400:
                raise ProviderError(
                    f"NetBox release failed (HTTP {r.status_code}).")
        except httpx.HTTPError as exc:
            raise ProviderError(f"NetBox release failed: {exc}") from exc
