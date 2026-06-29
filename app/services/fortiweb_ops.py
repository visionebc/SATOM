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
#
# FortiWeb REJECTS a write that echoes back an auto-assigned id with
# ``errcode 10 "CMDB failed to be saved"`` — the single hardest-won lesson from
# the desktop standalone's clone path. A GET payload carries the object's own
# unique id (``policy-id`` / ``profile-id`` / ``server-pool-id`` / ``vserver-id``
# / ``health-id`` …, all ``*-id``) and the positional ``index`` on system/vip;
# re-POSTing any of them collides in the CMDB. So every write (Configuration,
# Provisioning, template apply, clone, the object editor) must strip them.
#
# Mirrors the standalone ``_clean_for_write``: drop ``q_*``/``_*`` metadata,
# ``*_val`` select-companions, every ``*-id`` and ``index``, plus the explicit
# read-only flags. Plain ``id`` and underscore ``*_id`` (``signature_id`` /
# ``main_class_id`` — real sub-row keys) are KEPT; FortiWeb reassigns a stale
# top-level ``id`` on create. This matches what ``field_schema.is_noise`` already
# hides from the editor, so the write layer can never carry a field the form hid.
_STRIP_PREFIXES = ("q_", "_")
_STRIP_SUFFIXES = ("_val", "-id")
_STRIP_KEYS = {
    "ref", "mkey_ref", "can_view", "can_clone", "is_default", "index",
    "sub_table_id", "sub_table_action", "flag", "seq",
}

_METHOD = {"create": "POST", "update": "PUT", "delete": "DELETE"}


def _is_readonly_key(k: str) -> bool:
    """True if *k* is a server-managed key a write must never echo back."""
    if not isinstance(k, str):
        return False
    if k in _STRIP_KEYS:
        return True
    if any(k.startswith(p) for p in _STRIP_PREFIXES):
        return True
    if any(k.endswith(s) for s in _STRIP_SUFFIXES):
        return True
    return False


def sanitize_payload(data: Any) -> Any:
    """Drop server-managed/read-only keys so a PUT/POST doesn't echo them back.

    Recurses into nested dicts AND into list-of-dict sub-tables (e.g. an inline
    ``pserver-list``), so a cloned/echoed object is clean at every depth.
    """
    if not isinstance(data, dict):
        return data
    clean = {}
    for k, v in data.items():
        if _is_readonly_key(k):
            continue
        if isinstance(v, dict):
            clean[k] = sanitize_payload(v)
        elif isinstance(v, list):
            clean[k] = [sanitize_payload(it) if isinstance(it, dict) else it for it in v]
        else:
            clean[k] = v
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

    @staticmethod
    def _response_ok(resp):
        """``(ok, error)`` for a FortiWeb write response.

        FortiWeb returns HTTP 200 with a body ``errcode`` on logical errors (and
        sometimes HTTP 500 + errcode), so HTTP status alone is not enough: a write
        is OK only when the body ``errcode`` is 0/absent.
        """
        if resp is None:
            return False, "no response"
        status = getattr(resp, "status_code", 0)
        if status >= 400:
            return False, "HTTP %s" % status
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001 - non-JSON 2xx -> ok
            return True, ""
        res = body.get("results") if isinstance(body, dict) else None
        code = res.get("errcode") if isinstance(res, dict) else (
            body.get("errcode") if isinstance(body, dict) else None)
        if code not in (None, 0):
            holder = res if isinstance(res, dict) else (body if isinstance(body, dict) else {})
            return False, ("errcode %s: %s" % (code, holder.get("message", ""))).strip()
        return True, ""

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
            ok, err = self._response_ok(resp)
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
