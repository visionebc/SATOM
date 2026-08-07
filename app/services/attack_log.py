"""Attack-log read layer — the GUI-session path to a FortiWeb's ``alog``.

Why a GUI session and not the REST API: FortiWeb 7.6.8 exposes **no** documented
REST endpoint for the attack log. Every documented shape (``log/attack``,
``logquery``, ``monitor/log``, …) answers ``-20001 "The REST API has invalid
URL"``, and the CLI has no ``diagnose log`` verb — both verified live against
fortiweb08 (7.6.8 build1128) before this module was written. The appliance's own
GUI reads the log through an *internal* endpoint that only an authenticated GUI
session may call:

    GET /api/v2.0/log/logaccess.attack?log=alog.log&page=N&filter_offset=0&filter=<json>

That path is **undocumented**. It was recovered from the shipped Angular bundle
(``/ng/app/log/log_view/fwb-log-view.js`` → ``URLS_ATTACK``) and the filter shape
from ``Facets.makeFilters`` in ``app.min.js``. The cost is explicit and accepted:
a firmware upgrade may move it. :func:`search_by_msg_id` therefore distinguishes
"the endpoint answered and matched nothing" from "the endpoint is gone", because
those two are the same blank table on screen and mean opposite things — a silent
empty result would read as "no such attack" when the truth is "this integration
broke".

Read-only by construction: the only verbs here are login (POST ``/logincheck``,
which mints a session and mutates nothing) and GET on the log endpoint. Nothing
in this module can write appliance configuration.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

# A GUI session is expensive (a full auth round-trip) and FortiWeb caps concurrent
# admin sessions, so one login is reused across requests. The TTL is deliberately
# far below the appliance's own admin idle timeout: an expired cookie surfaces as
# a *login page* with HTTP 200, which JSON-decodes as garbage rather than as 401.
_SESSION_TTL_S = 300.0

# The log endpoint pages at 100 rows; a msg_id lookup is expected to match one.
_PAGE_SIZE = 100

# ``id-<device>-<msgid>`` — the reference the operator copies off the block page.
# The device segment may itself contain dashes (``id-fw-dmz-01-000000004117``),
# so the msg_id is anchored to the END and the device is whatever is between.
_REF_RE = re.compile(r'^\s*id-(?P<device>.+)-(?P<msg_id>[0-9]+)\s*$', re.IGNORECASE)

# FortiWeb writes msg_id zero-padded to 12 digits. An operator reading one off a
# screen drops the leading zeros; both must find the same row.
_MSG_ID_WIDTH = 12


class AttackLogError(RuntimeError):
    """The device could not be asked. NEVER raised for 'no rows matched'."""


class AttackLogUnavailable(AttackLogError):
    """The internal log endpoint did not answer in its documented shape.

    Distinct from :class:`AttackLogError` because this one means the *integration*
    is broken (firmware moved the endpoint), not that the box is down. The UI says
    so out loud instead of rendering an empty table.
    """


@dataclass
class LogReference:
    """A parsed ``id-<device>-<msgid>`` block-page reference."""

    raw: str
    msg_id: str
    device: str = ''
    #: True when the operator pasted a full reference (so we know the appliance);
    #: False when they typed a bare msg_id and must pick the device themselves.
    has_device: bool = False


@dataclass
class _Session:
    client: httpx.Client
    created: float = field(default_factory=time.monotonic)

    def expired(self) -> bool:
        return (time.monotonic() - self.created) > _SESSION_TTL_S


_sessions: dict[str, _Session] = {}
_sessions_lock = threading.Lock()


def parse_reference(text: str) -> LogReference:
    """Split what the operator pasted into (device, msg_id).

    Accepts the full ``id-fortiweb08-000000004117`` reference, a bare
    ``000000004117``, or an unpadded ``4117``. Anything else raises, because
    guessing at a malformed reference and searching for the wrong thing is worse
    than saying it is malformed.
    """
    s = (text or '').strip()
    if not s:
        raise ValueError('Enter an attack ID.')
    m = _REF_RE.match(s)
    if m:
        return LogReference(raw=s, msg_id=_normalise_msg_id(m.group('msg_id')),
                            device=m.group('device'), has_device=True)
    bare = s.strip()
    if bare.isdigit():
        return LogReference(raw=s, msg_id=_normalise_msg_id(bare))
    raise ValueError(
        'Unrecognised attack ID. Expected "id-<device>-<number>" as shown on the '
        'block page, or the bare numeric MSG ID.')


def _normalise_msg_id(digits: str) -> str:
    """Zero-pad to the width FortiWeb stores, so ``4117`` finds ``000000004117``."""
    d = digits.lstrip('0') or '0'
    return d.zfill(_MSG_ID_WIDTH) if len(d) < _MSG_ID_WIDTH else d


def _login(appliance) -> httpx.Client:
    base = f'https://{appliance.host}:{appliance.port}'
    verify = bool(getattr(appliance, 'verify_ssl', False))
    if verify:
        try:
            from . import trust_store
            verify = trust_store.verify_param()
        except Exception:  # noqa: BLE001 — a trust-store hiccup falls back to public roots
            verify = True
    client = httpx.Client(verify=verify, timeout=httpx.Timeout(30.0, connect=10.0),
                          follow_redirects=True)
    try:
        resp = client.post(base + '/logincheck',
                           data={'username': appliance.username,
                                 'secretkey': appliance.password})
    except Exception as exc:  # noqa: BLE001
        client.close()
        raise AttackLogError(f'Cannot reach {appliance.host}: {exc}') from exc
    # A successful GUI login mints an APSCOOKIE_FWEB_* cookie. Checking the status
    # code alone is not enough: FortiWeb answers 200 with a redirect script for
    # BOTH success and failure, so the cookie is the only honest signal.
    if not any(k.startswith('APSCOOKIE_FWEB') for k in client.cookies.keys()):
        client.close()
        raise AttackLogError(
            f'GUI login rejected by {appliance.host} — check the stored admin '
            f'credentials (the REST token path is unaffected).')
    return client


def _session_for(appliance) -> httpx.Client:
    key = f'{appliance.id}:{appliance.host}:{appliance.port}'
    with _sessions_lock:
        sess = _sessions.get(key)
        if sess is not None and not sess.expired():
            return sess.client
        if sess is not None:
            try:
                sess.client.close()
            except Exception:  # noqa: BLE001
                pass
            _sessions.pop(key, None)
    client = _login(appliance)
    with _sessions_lock:
        _sessions[key] = _Session(client=client)
    return client


def invalidate(appliance) -> None:
    """Drop the cached GUI session (used after an auth failure mid-flight)."""
    key = f'{appliance.id}:{appliance.host}:{appliance.port}'
    with _sessions_lock:
        sess = _sessions.pop(key, None)
    if sess is not None:
        try:
            sess.client.close()
        except Exception:  # noqa: BLE001
            pass


def _make_filter(field_id: str, value: str) -> str:
    """The exact filter envelope the GUI sends.

    Recovered from ``Facets.makeFilters``; verified live — the shorthand
    ``{"id":…, "value":[…]}`` is accepted with HTTP 200 and silently matches
    NOTHING, which is precisely the failure this shape avoids.
    """
    return json.dumps([{'id': field_id,
                        'logic': {'is': {}, 'search': 'string'},
                        'value': [value]}])


def _query(appliance, log_filter: str, page: int = 1) -> dict[str, Any]:
    base = f'https://{appliance.host}:{appliance.port}'
    client = _session_for(appliance)
    params = {'log': 'alog.log', 'page': page, 'filter_offset': 0, 'filter': log_filter}
    try:
        resp = client.get(base + '/api/v2.0/log/logaccess.attack', params=params)
    except Exception as exc:  # noqa: BLE001
        invalidate(appliance)
        raise AttackLogError(f'Attack-log query to {appliance.host} failed: {exc}') from exc

    if resp.status_code == 403 or 'logincheck' in resp.text[:400]:
        # Session died early; one retry with a fresh login, then give up loudly.
        invalidate(appliance)
        client = _session_for(appliance)
        resp = client.get(base + '/api/v2.0/log/logaccess.attack', params=params)

    if resp.status_code != 200:
        raise AttackLogUnavailable(
            f'{appliance.host} answered HTTP {resp.status_code} on the attack-log '
            f'endpoint. On 7.6.8 this path is internal to the GUI; a firmware '
            f'upgrade may have moved it.')
    try:
        body = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise AttackLogUnavailable(
            f'{appliance.host} did not answer JSON on the attack-log endpoint '
            f'(got {len(resp.text)} bytes). The internal path has probably '
            f'changed.') from exc
    results = body.get('results', body)
    if not isinstance(results, dict) or 'payload' not in results:
        raise AttackLogUnavailable(
            f'{appliance.host} answered an unexpected attack-log shape '
            f'(keys: {sorted(results)[:8] if isinstance(results, dict) else type(results).__name__}).')
    return results


def search_by_msg_id(appliance, msg_id: str) -> list[dict[str, Any]]:
    """Every attack-log row whose ``msg_id`` equals *msg_id*.

    An empty list means the device answered and matched nothing — a real,
    reportable answer. A broken integration or an unreachable box raises.
    """
    res = _query(appliance, _make_filter('msg_id', msg_id))
    return list(res.get('payload') or [])


def recent(appliance, limit: int = 20) -> list[dict[str, Any]]:
    """Newest attack-log rows, unfiltered — the 'what does this box see' fallback
    shown when a lookup misses, so an operator with a stale ID is not left staring
    at a blank page with no way to tell a wrong ID from a broken feed."""
    res = _query(appliance, '[]')
    return list(res.get('payload') or [])[:limit]


#: The result-table columns: what an operator triages on before opening anything.
#: One definition, used by BOTH the match table and the "recent entries" fallback
#: — two column lists would let the fallback drift into describing a different
#: thing than the table it stands in for.
TABLE_COLUMNS = [
    ('rel_time', 'Date/Time'),
    ('msg_id', 'MSG ID'),
    ('main_type', 'Attack Type'),
    ('sub_type', 'Sub Type'),
    ('policy', 'Policy'),
    ('src', 'Source IP'),
    ('dst', 'Destination IP'),
    ('action', 'Action'),
]

#: Fields worth showing first in the detail view; the row carries ~80 keys and an
#: undifferentiated dump of all of them is unreadable during an incident.
PRIMARY_FIELDS = [
    ('rel_time', 'Date/Time'), ('msg_id', 'MSG ID'), ('policy', 'Policy'),
    ('main_type', 'Main Type'), ('sub_type', 'Sub Type'), ('action', 'Action'),
    ('threat_level', 'Threat Level'), ('severity_level', 'Severity'),
    ('src', 'Source'), ('src_port', 'Source Port'), ('srccountry', 'Source Country'),
    ('dst', 'Destination'), ('dst_port', 'Destination Port'),
    ('http_host', 'HTTP Host'), ('http_url', 'URL'), ('http_method', 'Method'),
    ('http_agent', 'User Agent'), ('http_refer', 'Referer'),
    ('signature_id', 'Signature ID'), ('signature_subclass', 'Signature Subclass'),
    ('signature_cve_id', 'CVE ID'), ('owasp_top10', 'OWASP Top10'),
    ('server_pool_name', 'Server Pool'), ('backend_service', 'Backend Service'),
    ('monitor_status', 'Monitor Mode'), ('msg', 'Message'),
]
