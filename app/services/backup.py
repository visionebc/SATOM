"""Backup service — wraps FortiWeb local-backup REST API endpoints."""
from __future__ import annotations

import time
from typing import Any


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _post(client: Any, url: str, json: dict | None = None) -> Any:
    """POST via the client's _request helper and raise on non-2xx."""
    resp = client._request("POST", url, json=json or {})
    resp.raise_for_status()
    return resp.json()


def _get(client: Any, url: str) -> Any:
    """GET via the client's _request helper and raise on non-2xx."""
    resp = client._request("GET", url)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_backup(client: Any, name: str | None = None) -> dict[str, Any]:
    """Trigger an on-device local backup.

    ``POST /api/v2.0/system/maintenance/localbackup``

    Args:
        client: An authenticated FortiWeb client instance.
        name:   Optional backup name; defaults to a timestamp-based name.

    Returns:
        The JSON response body from the appliance.
    """
    payload: dict[str, Any] = {}
    if name:
        payload["name"] = name
    else:
        payload["name"] = f"backup_{time.strftime('%Y%m%d_%H%M%S')}"

    return _post(client, "/api/v2.0/system/maintenance/localbackup", json=payload)


def list_backups(client: Any) -> list[dict[str, Any]]:
    """Return the list of local backups stored on the appliance.

    ``GET /api/v2.0/system/maintenance/localbackup``

    Returns:
        List of backup metadata dicts (name, size, date, …).
    """
    data = _get(client, "/api/v2.0/system/maintenance/localbackup")
    # FortiWeb wraps results under a 'results' key
    if isinstance(data, dict):
        return data.get("results", data.get("payload", []))
    return data  # type: ignore[return-value]


def download_backup(client: Any, backup_name: str) -> bytes:
    """Download a named local backup from the appliance.

    ``POST /api/v2.0/system/maintenance/localbackup``  (with name + download flag)

    Args:
        client:      An authenticated FortiWeb client instance.
        backup_name: Exact name of the backup as returned by list_backups().

    Returns:
        Raw backup file bytes.
    """
    payload = {"name": backup_name, "action": "download"}
    resp = client._request(
        "POST",
        "/api/v2.0/system/maintenance/localbackup",
        json=payload,
    )
    resp.raise_for_status()
    return resp.content
