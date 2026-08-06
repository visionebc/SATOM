"""Hypervisor registry — one entry per backend, nothing else to edit.

Mirrors ``app/services/dns_providers/``: adding a backend is a module plus a
line in ``BACKENDS``. The views, the Settings form and the provisioning
pipeline all read this mapping, so a new hypervisor cannot end up half-wired
(present in the dropdown but missing from the factory, or the reverse).

Unlike DNS records, this is a **multi-target** registry: a site may run both
Proxmox and ESXi, and more than one of each. Configuration therefore lives in
the ``hypervisor_targets`` table (Fernet-encrypted secrets, same pattern as
``Appliance``) rather than in a single ``app_settings`` key.
"""
from __future__ import annotations

from typing import Any

from .base import (Capabilities, HypervisorClient, HypervisorError, VmRef,
                   VmSpec)
from .esxi import EsxiClient
from .proxmox import ProxmoxClient

BACKENDS: dict[str, type[HypervisorClient]] = {
    "proxmox": ProxmoxClient,
    "esxi": EsxiClient,
}

BACKEND_LABELS = {
    "proxmox": "Proxmox VE",
    "esxi": "VMware ESXi",
}

#: Per-backend form hints for Settings. Rendered generically, so a new backend
#: does not need a template edit.
FIELD_SPECS: dict[str, list[dict[str, Any]]] = {
    "proxmox": [
        {"key": "host", "label": "Host", "ph": "pve.example.com"},
        {"key": "port", "label": "Port", "ph": "8006"},
        {"key": "username", "label": "Username", "ph": "root@pam"},
        {"key": "token_id", "label": "API token id (optional)",
         "ph": "root@pam!satom"},
    ],
    "esxi": [
        {"key": "host", "label": "Host", "ph": "esxi.example.com"},
        {"key": "port", "label": "Port", "ph": "443"},
        {"key": "username", "label": "Username", "ph": "root"},
        {"key": "ssh_user", "label": "Shell username (optional)",
         "ph": "root",
         "help": "Only needed on a free-licensed host, whose vSphere API is "
                 "read-only. SATOM then creates machines over SSH with "
                 "vim-cmd. Requires TSM-SSH enabled on the host."},
        {"key": "ssh_port", "label": "Shell port", "ph": "22"},
    ],
}

DEFAULT_PORTS = {"proxmox": 8006, "esxi": 443}


def is_valid(backend: str) -> bool:
    return (backend or "").strip().lower() in BACKENDS


def build_client(target, *, timeout: int = 30) -> HypervisorClient:
    """Instantiate the client for a ``HypervisorTarget`` row.

    Raises ``HypervisorError`` — not ``KeyError`` — on an unknown backend, so
    a row written by a newer release (restore, replica, hand-edited SQL) fails
    with a sentence the operator can act on instead of a traceback.
    """
    key = (getattr(target, "backend", "") or "").strip().lower()
    cls = BACKENDS.get(key)
    if cls is None:
        raise HypervisorError(
            f"unknown hypervisor backend {key!r}",
            detail="known backends: " + ", ".join(sorted(BACKENDS)))
    kwargs: dict[str, Any] = {
        "host": target.host,
        "username": target.username,
        "password": target.password,
        "verify_ssl": bool(target.verify_ssl),
        "port": target.port or DEFAULT_PORTS.get(key),
        "timeout": timeout,
    }
    if key == "esxi" and getattr(target, "ssh_user", ""):
        # Second write path for a free-licensed host. Absent credentials are a
        # supported state: the client reports "not configured" rather than
        # pretending the API is writable.
        kwargs["ssh_user"] = target.ssh_user
        kwargs["ssh_password"] = target.ssh_password
        kwargs["ssh_port"] = target.ssh_port or 22
    if key == "proxmox" and getattr(target, "token_id", ""):
        kwargs["token_id"] = target.token_id
        kwargs["token_secret"] = target.token_secret
    return cls(**kwargs)


def configured_targets(enabled_only: bool = True) -> list:
    """Rows the provisioning UI may offer. Empty list = feature unavailable.

    The caller must treat an empty list as "hide the entry point", not as
    "show a button that errors": a control the operator cannot action is worse
    than no control (docs/safeguards.md, the jobs-dock lesson).
    """
    from ...models_provision import HypervisorTarget
    q = HypervisorTarget.query
    if enabled_only:
        q = q.filter(HypervisorTarget.enabled.is_(True))
    return q.order_by(HypervisorTarget.name.asc()).all()


def any_configured() -> bool:
    try:
        return bool(configured_targets())
    except Exception:  # noqa: BLE001 — table may not exist yet at first boot
        return False


__all__ = [
    "BACKENDS", "BACKEND_LABELS", "FIELD_SPECS", "DEFAULT_PORTS",
    "Capabilities", "HypervisorClient", "HypervisorError", "VmRef", "VmSpec",
    "build_client", "configured_targets", "any_configured", "is_valid",
]
