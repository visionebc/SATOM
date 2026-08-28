"""Create / edit / delete DNS-IPAM backends, and the one-shot migration off
the singleton this package used to be.

Validation lives here rather than in the view because there are two writers —
the Settings page and :func:`migrate_singleton` — and a rule enforced by only
one of them is a rule the other can break.
"""
from __future__ import annotations

from datetime import datetime

from . import FIELD_SPECS, PROVIDERS
from .base import ProviderError  # noqa: F401  (re-exported for callers)

#: Set once the AppSetting singleton has been folded into a row. Kept as its
#: own key rather than inferred from "are there rows?" — an operator who
#: deletes every backend must not have the old config resurrected on the next
#: boot as if they had never removed it.
K_MIGRATED = "dnsrecords.migrated_v2"


class BackendError(ValueError):
    """A save/delete the configuration does not permit."""


def _clean_fields(provider: str, data: dict) -> dict:
    cfg = {"verify_ssl": bool(data.get("verify_ssl", True))}
    for spec in FIELD_SPECS.get(provider, []):
        cfg[spec["key"]] = str(data.get(spec["key"]) or "").strip()[:512]
    return cfg


def save_backend(data: dict, backend_id: object = None):
    """Create or update one backend row. Raises :class:`BackendError`.

    Nothing is written when a rule is broken — a rejected save is not a
    partial save (the rule ``save_segments`` was given on 2026-08-27).
    """
    from ...models_dnsbackend import DnsBackend, split_list
    from ...extensions import db

    name = str(data.get("name") or "").strip()[:64]
    provider = str(data.get("provider") or "").strip()
    if not name:
        raise BackendError("A name is required — it is what run logs and "
                           "audit lines call this backend.")
    if provider not in PROVIDERS or provider == "none":
        raise BackendError(f"{provider!r} is not a DNS/IPAM provider.")

    cls = PROVIDERS[provider]
    role_ipam = bool(data.get("role_ipam"))
    role_dns = bool(data.get("role_dns"))
    if not role_ipam and not role_dns:
        raise BackendError(
            "A backend with neither role can never answer anything. Give it "
            "the IPAM role, the DNS role, or both — or delete it.")
    # A role is a promise. Refused when the provider cannot keep it in ANY
    # install; ALLOWED when it depends on the install (NetBox + netbox-dns),
    # because that is answered live by capabilities() at use time.
    if role_ipam and not getattr(cls, "may_allocate", False):
        raise BackendError(
            f"{cls.label} does not hand out addresses in any installation, so "
            "it cannot carry the IPAM role.")
    if role_dns and not getattr(cls, "may_write", False):
        raise BackendError(
            f"{cls.label} has no DNS record CRUD in any installation, so it "
            "cannot carry the DNS role. Point the DNS role at a backend that "
            "writes records and keep this one for addresses.")

    try:
        priority = int(str(data.get("priority") or 100).strip())
    except (TypeError, ValueError):
        raise BackendError("Priority must be a whole number.") from None

    row = None
    if backend_id not in (None, "", 0, "0"):
        row = DnsBackend.query.get(int(backend_id))
        if row is None:
            raise BackendError("That backend no longer exists.")
    clash = DnsBackend.query.filter(
        DnsBackend.name == name,
        DnsBackend.id != (row.id if row is not None else -1)).first()
    if clash is not None:
        raise BackendError(f"Another backend is already called {name!r}.")

    secret = str(data.get("secret") or "").strip()
    if row is None and not secret:
        raise BackendError("A credential is required to add a backend.")

    if row is None:
        row = DnsBackend(name=name, provider=provider)
        db.session.add(row)
    row.name = name
    row.provider = provider
    row.role_ipam = role_ipam
    row.role_dns = role_dns
    row.enabled = bool(data.get("enabled", True))
    row.priority = priority
    zones = split_list(data.get("zones"), lower=True)
    pools = split_list(data.get("pools"))
    cfg = _clean_fields(provider, data)
    # Scope and default must agree. A default outside the declared scope is a
    # contradiction the software cannot resolve honestly: routing would refuse
    # the zone the provider is about to write into. Refused, not silently
    # rewritten — an operator who typed both meant both.
    dz = str(cfg.get("default_zone") or "").strip().rstrip(".").lower()
    if zones and dz and dz not in zones:
        raise BackendError(
            f"the default zone {dz!r} is not one of the zones this backend "
            f"is scoped to ({', '.join(zones)}) — records would be routed "
            "away from the zone they would be written into. Add it to the "
            "scope, or clear the default.")
    dp = str(cfg.get("default_pool") or "").strip()
    if pools and dp and dp not in pools:
        raise BackendError(
            f"the default pool {dp!r} is not one of the pools this backend "
            f"is scoped to ({', '.join(pools)}).")
    row.zones = "\n".join(zones)
    row.pools = "\n".join(pools)
    row.config = cfg
    # A blank secret on edit KEEPS the stored one. It never means "blank it":
    # an empty password field is how a browser renders "not shown".
    if secret:
        row.secret = secret
    db.session.commit()
    return row


def delete_backend(row) -> None:
    """Remove a backend. Refused while a run holds it as its undo handle.

    A provisioning run records WHICH backend reserved its address and
    published its name, because with several backends a rollback aimed at the
    wrong one either does nothing or frees somebody else's entry. Deleting the
    row would destroy that handle, so the refusal is the same one
    ``hypervisor_delete`` makes for the same reason.
    """
    from ...models_provision import ProvisionRun
    from ...extensions import db

    held = []
    try:
        held = ProvisionRun.query.filter(
            ProvisionRun.status.notin_(("done", "aborted")),
            db.or_(ProvisionRun.ip_backend_id == row.id,
                   ProvisionRun.dns_backend_id == row.id)).all()
    except Exception:  # noqa: BLE001 — columns absent on an old DB
        held = []
    if held:
        raise BackendError(
            f"{len(held)} provisioning run(s) still hold this backend as the "
            "handle for the address or record they created. Finish or abort "
            "them first — deleting it now leaves those with no way back.")
    db.session.delete(row)
    db.session.commit()


def record_test(row, ok: bool, message: str) -> None:
    from ...extensions import db
    row.last_status = "ok" if ok else "error"
    row.last_checked_at = datetime.utcnow()
    row.last_error = "" if ok else (message or "")[:2000]
    db.session.commit()


# ------------------------------------------------------------------ migration

def migrate_singleton() -> object | None:
    """Fold the ``dnsrecords.*`` AppSetting singleton into one row.

    Idempotent and one-shot: guarded by its own flag rather than by "does a
    row exist", so deleting every backend does not resurrect the old config on
    the next boot.

    The row it creates is deliberately UNSCOPED — no zones, no pools — because
    that is what the singleton was: the answer to every question. The old
    ``default_zone``/``default_pool`` are carried across UNCHANGED, as
    defaults, exactly as they were. Promoting them to a scope would have
    narrowed a working install at upgrade time: an operator whose default zone
    was ``example.com`` could still create records in any other zone from the
    modal, and a scope would start refusing those the moment the package was
    updated. An upgrade must not change what an install does.
    """
    from ...models_dnsbackend import DnsBackend
    from ...models import AppSetting
    from ...extensions import db

    if (AppSetting.get(K_MIGRATED) or "") == "1":
        return None
    provider = (AppSetting.get("dnsrecords.provider") or "").strip()
    secret_enc = AppSetting.get("dnsrecords.secret_enc") or ""
    if provider in ("", "none") or provider not in PROVIDERS:
        AppSetting.set(K_MIGRATED, "1")
        db.session.commit()
        return None

    import json
    try:
        cfg = json.loads(AppSetting.get("dnsrecords.config") or "{}")
    except (ValueError, TypeError):
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}

    cls = PROVIDERS[provider]
    name = cls.label[:64]
    if DnsBackend.query.filter_by(name=name).first() is not None:
        name = f"{name} (imported)"[:64]
    row = DnsBackend(
        name=name, provider=provider, enabled=True,
        role_ipam=bool(getattr(cls, "may_allocate", False)),
        role_dns=bool(getattr(cls, "may_write", False)),
        zones="", pools="", priority=100,
        secret_enc=secret_enc,
    )
    row.config = cfg
    db.session.add(row)
    AppSetting.set(K_MIGRATED, "1")
    db.session.commit()
    return row
