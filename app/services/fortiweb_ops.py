"""Dry-run-capable FortiWeb config-write wrapper.

Every structured config mutation (Configuration editor, Provisioning, template
apply, scheduled config/upgrade actions) goes through ``FortiWebOps`` so that:

  * **dry-run** (the default) computes the would-be request WITHOUT contacting
    the device — safe and verifiable headless;
  * a **real apply** snapshots before/after, writes a ``ChangeHistory`` row and
    an audit entry, and never raises on a dead device (returns ok=False + error).

This is the single device-write entry point the higher-level features share.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..clients.fortiweb import FortiWebClient
from ..models import ChangeHistory, db
from .audit import log_action

# Server-managed / read-only keys stripped from any payload before a write.
_STRIP_PREFIXES = ("q_",)
_STRIP_KEYS = {"_ref", "ref", "mkey_ref", "can_view", "is_default"}

_METHOD = {"create": "POST", "update": "PUT", "delete": "DELETE"}


def sanitize_payload(data: Any) -> Any:
    """Drop server-managed/read-only keys so a PUT/POST doesn't echo them back."""
    if not isinstance(data, dict):
        return data
    clean = {}
    for k, v in data.items():
        if k in _STRIP_KEYS or any(k.startswith(p) for p in _STRIP_PREFIXES):
            continue
        clean[k] = sanitize_payload(v) if isinstance(v, dict) else v
    return clean


def _path(endpoint: str, mkey: str | None) -> str:
    ep = (endpoint or "").lstrip("/")
    if mkey:
        sep = "&" if "?" in ep else "?"
        return f"{ep}{sep}mkey={mkey}"
    return ep


def _current_username() -> str:
    try:
        from flask_login import current_user
        if current_user and current_user.is_authenticated:
            return current_user.username
    except Exception:  # noqa: BLE001 — outside a request context
        pass
    return "system"


class OpResult(dict):
    """Plain dict result: ok/action/endpoint/mkey/dry_run/request/before/after/error."""

    @property
    def ok(self) -> bool:
        return bool(self.get("ok"))


class FortiWebOps:
    def __init__(self, appliance):
        self.appliance = appliance
        self._client = None

    @property
    def client(self) -> FortiWebClient:
        if self._client is None:
            self._client = FortiWebClient(self.appliance)
        return self._client

    # -- dry-run (pure, no device contact) --------------------------------
    def preview(self, action: str, endpoint: str, mkey: str | None, data: Any) -> OpResult:
        method = _METHOD.get(action, "POST")
        payload = None if action == "delete" else sanitize_payload(data)
        return OpResult(
            ok=True, action=action, endpoint=endpoint, mkey=mkey, dry_run=True,
            request={"method": method, "path": _path(endpoint, mkey), "body": payload},
            before=None, after=payload, error="",
        )

    # -- real apply (device contact + snapshot + audit) -------------------
    def _record(self, action, endpoint, mkey, before, after, dry_run, error=""):
        try:
            db.session.add(ChangeHistory(
                appliance_id=getattr(self.appliance, "id", None),
                endpoint=endpoint or "", mkey=mkey or "", action=action,
                before=json.dumps(before) if before is not None else "",
                after=json.dumps(after) if after is not None else "",
                dry_run=dry_run, username=_current_username(), ts=datetime.utcnow(),
            ))
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
        log_action(f"config.{action}", target=endpoint or "",
                   appliance_id=getattr(self.appliance, "id", None),
                   detail=f"mkey={mkey} dry_run={dry_run} error={error}")

    def _apply(self, action, endpoint, mkey, data) -> OpResult:
        method = _METHOD.get(action, "POST")
        payload = None if action == "delete" else sanitize_payload(data)
        req = {"method": method, "path": _path(endpoint, mkey), "body": payload}
        before = None
        try:  # best-effort before-snapshot — never fatal
            resp = self.client.api_call("GET", _path(endpoint, mkey))
            before = resp.json() if resp is not None and resp.status_code < 400 else None
        except Exception:  # noqa: BLE001
            before = None
        try:
            resp = self.client.api_call(method, _path(endpoint, mkey), payload)
            ok = resp is not None and resp.status_code < 400
            err = "" if ok else f"HTTP {getattr(resp, 'status_code', '?')}"
            self._record(action, endpoint, mkey, before, payload, False, err)
            return OpResult(ok=ok, action=action, endpoint=endpoint, mkey=mkey,
                            dry_run=False, request=req, before=before, after=payload, error=err)
        except Exception as exc:  # noqa: BLE001
            self._record(action, endpoint, mkey, before, payload, False, str(exc))
            return OpResult(ok=False, action=action, endpoint=endpoint, mkey=mkey,
                            dry_run=False, request=req, before=before, after=payload, error=str(exc))

    def create(self, endpoint, data, *, mkey=None, dry_run=True) -> OpResult:
        return self.preview("create", endpoint, mkey, data) if dry_run else self._apply("create", endpoint, mkey, data)

    def update(self, endpoint, mkey, data, *, dry_run=True) -> OpResult:
        return self.preview("update", endpoint, mkey, data) if dry_run else self._apply("update", endpoint, mkey, data)

    def delete(self, endpoint, mkey, *, dry_run=True) -> OpResult:
        return self.preview("delete", endpoint, mkey, None) if dry_run else self._apply("delete", endpoint, mkey, None)
