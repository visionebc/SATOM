"""FortiAnalyzer object-form helpers — the FAZ sibling of ``adc_objform``.

Decides which registry endpoints the section pages may WRITE to (JSON-RPC
``add`` / ``update`` / ``delete``), which field addresses a table row (the
CLI ``edit`` mkey), and which endpoints need extra ``get`` parameters. The
allow-list is family-based (``/cli/…`` config tree, ``/dvmdb/…`` object DB,
``/report/…/config/…`` report definitions) with explicit read-only carve-outs
for operational data — logs, alerts, incidents, tasks, UEBA and generated
reports are things the real FAZ GUI does not let you "create" either.

Devices are deliberately read-only here: on the real unit "Add Device" is a
wizard around ``exec /dvm/cmd/add/device`` (device authorization handshake),
not a plain table insert — the API console is the right tool for that today.
"""
from __future__ import annotations

import time


# The CLI `edit` key per table endpoint — only where it is NOT `name`.
_MKEY_OVERRIDES = {
    'admin_user': 'userid',
    'admin_profile': 'profileid',
    'system_route': 'seq_num',
    'system_metadata_admins': 'fieldname',
    'sql_custom_index': 'id',
    'log_forward': 'id',
    'log_fetch_client_profile': 'id',
    'system_mail_server': 'id',
    'report_layouts': 'layout-id',
}

# Operational / list-only endpoints: never editable from the section pages
# (mirrors the real GUI, where these panes have no Create New toolbar).
_READ_ONLY = {
    'dvmdb_device',
    'sys_status', 'sys_ha_status', 'storage_info', 'task_task',
    'logview_logstats', 'logview_logfields', 'logview_logfiles',
    'eventmgmt_alerts', 'eventmgmt_alertlogs', 'incidentmgmt_incidents',
    'ueba_endpoints', 'ueba_endusers', 'report_generated',
    'system_certificate_oftp',  # cert/key blobs — import-only in the GUI too
}

# Editable tables where creating rows makes no sense (fixed hardware list /
# file-upload imports) — Edit stays available.
_NO_CREATE = {
    'system_interface',
    'system_certificate_local', 'system_certificate_ca',
    'system_certificate_crl', 'system_certificate_remote',
}
_NO_DELETE = {'system_interface'}

# Families whose objects the section pages may write to.
_WRITE_FAMILIES = ('/cli/', '/dvmdb/', '/report/adom/root/config/')

# Device-internal keys that must never appear in forms or write payloads.
_NOISE = {'obj flags', 'oid', 'obj_ver', 'dev_ver', 'uuid _scope'}


def is_noise(key: str) -> bool:
    return key.startswith('_') or key in _NOISE


def is_writable(logical: str, urn: str) -> bool:
    """May the section page offer Create/Edit/Delete for this endpoint?"""
    if logical in _READ_ONLY:
        return False
    return urn.startswith(_WRITE_FAMILIES)


def can_create(logical: str) -> bool:
    return logical not in _NO_CREATE


def can_delete(logical: str) -> bool:
    return logical not in _NO_DELETE


def mkey_field(logical: str, rows: list | None = None) -> str:
    """The field addressing a row (CLI ``edit`` key). Explicit override first,
    then detection off the actual rows, then ``name``."""
    if logical in _MKEY_OVERRIDES:
        return _MKEY_OVERRIDES[logical]
    for cand in ('name', 'userid', 'profileid', 'fieldname', 'seq_num', 'id'):
        for r in (rows or [])[:5]:
            if isinstance(r, dict) and cand in r:
                return cand
    return 'name'


def extra_params(logical: str) -> dict:
    """Required ``get`` parameters some endpoints refuse to work without
    (probed live on faz01 7.6.7)."""
    if logical == 'report_generated':
        now = int(time.time())
        return {'state': 'generated',
                'time-range': {'start': now - 30 * 86400, 'end': now}}
    return {}


def clean_fields(fields: dict) -> dict:
    """Scalar, non-noise fields only — sub-tables and device-internal flags
    are never round-tripped through the simple form."""
    return {k: v for k, v in (fields or {}).items()
            if not is_noise(k) and not isinstance(v, (list, dict))}
