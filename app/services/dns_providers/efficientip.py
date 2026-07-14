"""EfficientIP SOLIDserver provider — the only true DDI of the three.

SOLIDserver exposes a flat REST API at ``/rest/<class>_<action>`` with HTTP
Basic auth. DNS resource records are first-class:

* ``GET  /rest/dns_rr_list``   — list (WHERE / query-param filtering)
* ``POST /rest/dns_rr_add``    — create (``add_flag=new_only``)
* ``PUT  /rest/dns_rr_add``    — edit   (``rr_id`` + ``add_flag=edit_only``)
* ``DELETE /rest/dns_rr_delete`` — delete by ``rr_id``

Records carry ``rr_id`` (native id used for edit/delete), ``rr_full_name``,
``rr_type``, ``value1..7``, ``ttl``, ``dnszone_name``, ``dnsview_name``.

NOTE (2026-07-14): written to the documented SOLIDserver API. No EfficientIP
appliance exists in the fleet, so this path is UNVERIFIED end-to-end — validate
against a real SOLIDserver before trusting the write verbs in production.
"""
from __future__ import annotations

import httpx

from .base import Capabilities, DnsProvider, DnsRecord, ProviderError

_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV"]


class EfficientIPProvider(DnsProvider):
    key = "efficientip"
    label = "EfficientIP SOLIDserver"

    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider="efficientip", label="EfficientIP SOLIDserver",
            can_write=True, record_types=_TYPES,
            needs_zone=True, needs_view=True,
            notes="Native DDI. A DNS zone (and optionally a view) is required "
                  "to create records.",
        )

    # -- http ------------------------------------------------------------
    def _client(self) -> httpx.Client:
        base = str(self.cfg.get("base_url") or "").rstrip("/")
        if not base:
            raise ProviderError("EfficientIP base URL is not configured.")
        user = self.cfg.get("username") or ""
        pw = self.cfg.get("secret") or ""
        verify = bool(self.cfg.get("verify_ssl", True))
        return httpx.Client(base_url=base, auth=(user, pw), verify=verify,
                            timeout=12.0, headers={"Accept": "application/json"})

    @staticmethod
    def _payload(resp: httpx.Response) -> list:
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            data = None
        return data if isinstance(data, list) else ([] if data is None else [data])

    def _raise_for(self, resp: httpx.Response) -> None:
        if resp.status_code < 400:
            return
        msg = f"HTTP {resp.status_code}"
        for row in self._payload(resp):
            if isinstance(row, dict) and (row.get("errmsg") or row.get("err_msg")):
                msg = str(row.get("errmsg") or row.get("err_msg"))
                break
        raise ProviderError(f"EfficientIP: {msg}")

    # -- introspection ---------------------------------------------------
    def test_connection(self) -> tuple[bool, str]:
        try:
            with self._client() as c:
                r = c.get("/rest/dns_server_list", params={"limit": 1})
            if r.status_code == 401:
                return False, "Authentication failed (401)."
            self._raise_for(r)
            return True, "Connection OK."
        except ProviderError as exc:
            return False, str(exc)
        except httpx.HTTPError as exc:
            return False, f"Connection error: {exc}"

    # -- CRUD ------------------------------------------------------------
    def _to_record(self, row: dict) -> DnsRecord:
        rtype = str(row.get("rr_type") or "").upper()
        value = str(row.get("value1") or "")
        if rtype == "MX" and row.get("value2"):
            value = f"{row.get('value1')} {row.get('value2')}".strip()
        return DnsRecord(
            id=str(row.get("rr_id") or ""),
            name=str(row.get("rr_full_name") or row.get("rr_name") or "").rstrip("."),
            type=rtype, value=value,
            ttl=int(row["ttl"]) if str(row.get("ttl") or "").isdigit() else None,
            zone=str(row.get("dnszone_name") or ""),
            view=str(row.get("dnsview_name") or ""),
            extra={"rr_glue": row.get("rr_glue", "")},
        )

    def list_records(self, name: str = "", zone: str = "") -> list[DnsRecord]:
        params: dict = {"limit": 200}
        wheres = []
        if name:
            wheres.append(f"rr_full_name='{name}'")
        if zone:
            wheres.append(f"dnszone_name='{zone}'")
        view = self.cfg.get("default_view")
        if view:
            wheres.append(f"dnsview_name='{view}'")
        if wheres:
            params["WHERE"] = " AND ".join(wheres)
        try:
            with self._client() as c:
                r = c.get("/rest/dns_rr_list", params=params)
            if r.status_code == 204:
                return []
            self._raise_for(r)
        except httpx.HTTPError as exc:
            raise ProviderError(f"EfficientIP list failed: {exc}") from exc
        return [self._to_record(row) for row in self._payload(r)
                if isinstance(row, dict)]

    def _write_params(self, rec: DnsRecord) -> dict:
        params = {
            "dns_name": self.cfg.get("dns_server") or self.cfg.get("dns_name") or "",
            "dnszone_name": rec.zone or self.cfg.get("default_zone") or "",
            "rr_name": rec.name,
            "rr_type": rec.type,
        }
        view = rec.view or self.cfg.get("default_view")
        if view:
            params["dnsview_name"] = view
        if rec.ttl is not None:
            params["rr_ttl"] = rec.ttl
        if rec.type == "MX":
            prio, _, exch = (rec.value or "").partition(" ")
            params["value1"] = prio.strip() or "10"
            params["value2"] = exch.strip()
        else:
            params["value1"] = rec.value
        return {k: v for k, v in params.items() if v != ""}

    def create_record(self, rec: DnsRecord) -> DnsRecord:
        if not (rec.zone or self.cfg.get("default_zone")):
            raise ProviderError("A DNS zone is required to create a record.")
        params = self._write_params(rec) | {"add_flag": "new_only"}
        try:
            with self._client() as c:
                r = c.post("/rest/dns_rr_add", params=params)
            self._raise_for(r)
        except httpx.HTTPError as exc:
            raise ProviderError(f"EfficientIP create failed: {exc}") from exc
        rows = self._payload(r)
        rid = str(rows[0].get("ret_oid")) if rows and isinstance(rows[0], dict) else ""
        rec.id = rid or rec.id
        return rec

    def update_record(self, rec: DnsRecord) -> DnsRecord:
        if not rec.id:
            raise ProviderError("Record id is required to edit.")
        params = self._write_params(rec) | {"rr_id": rec.id, "add_flag": "edit_only"}
        try:
            with self._client() as c:
                r = c.put("/rest/dns_rr_add", params=params)
            self._raise_for(r)
        except httpx.HTTPError as exc:
            raise ProviderError(f"EfficientIP edit failed: {exc}") from exc
        return rec

    def delete_record(self, rec: DnsRecord) -> None:
        if not rec.id:
            raise ProviderError("Record id is required to delete.")
        try:
            with self._client() as c:
                r = c.delete("/rest/dns_rr_delete", params={"rr_id": rec.id})
            self._raise_for(r)
        except httpx.HTTPError as exc:
            raise ProviderError(f"EfficientIP delete failed: {exc}") from exc
