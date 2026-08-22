"""Pre-write validation of REFERENCE fields against the device that will store
them.

Why this exists
---------------
FortiWeb rejects a cmdb write that names an object which does not exist with
``HTTP 500 / errcode -651: Invalid input value.`` -- and that message names
NEITHER the field nor the value. A PUT carrying three reference fields where one
is wrong is refused ENTIRELY, so the operator sees a mute failure, keeps the two
good values on screen, and has to find the culprit by elimination. That happened
on fortiweb08 (audit entries 1128/1129, 2026-08-09): two attempts, seven seconds
apart, both refused for ``subresource-integrity-policy`` while the operator was
changing ``user-tracking-policy``.

So every operator-facing write resolves each submitted field to the cmdb
collection it selects from and asks the device whether the value is there,
BEFORE the write. The rejection names the field, the value and the collection.

Three states, never two
-----------------------
``FortiWebClient.cmdb_names_checked`` separates ``ok`` / ``absent`` / ``error``
because all three answer with zero names and they mean opposite things:

* ``ok``     - authoritative; an empty list means the collection has no objects,
               so ANY non-empty value is wrong (this is the -651 case).
* ``absent`` - the collection does not exist on this firmware; the field cannot
               be set here at all.
* ``error``  - we could not ask (transport, auth, license lock). We do NOT
               block: refusing a legitimate change because a GET failed would
               make the editor unusable on a flaky box, and the device remains
               the authority -- it will still answer -651 if the value is wrong.
               The caller surfaces the unverified fields as a warning.

And one collection-level exception, which is the same reasoning one level up:
a few collections are resolved by the CLI but REFUSED by REST with -20001, and
-20001 is what the client reads as ``absent``. For those the device's ``absent``
is an artefact of the transport, not a statement about the firmware -- so they
are never a rejection, only an ``unverified`` warning. The set is
:data:`fortiweb_field_schema.REST_UNREADABLE`, shared with the clone so the two
cannot drift.

Scope
-----
Applied at the OPERATOR-facing edit endpoints, not inside ``FortiWebOps``.
Machine-driven writers (clone, exception injection) legitimately bind objects
they are creating in the same batch, and validating there would reject a
half-built tree that is correct by the time it lands.
"""
from __future__ import annotations

from .fortiweb_field_schema import (KIND_SPECS, REF_ENDPOINTS,
                                    REST_UNREADABLE)

# A value that clears the field. FortiWeb accepts an empty string for any
# optional reference, so "not set" is never validated.
_EMPTY = (None, '', [], {})

# How many existing names to quote back. Enough to recognise a typo, short
# enough that a 400 stays readable when the collection holds hundreds.
SAMPLE = 8


def _kind_refs_agreeing() -> dict:
    """Per-object refs that mean the SAME collection whichever object they are
    on, and that the global map does not already cover.

    The generic object editor knows the collection being written, not the
    create-``kind`` KIND_SPECS is keyed by, so without this a field like
    ``ip-list`` or ``certificate-verify`` -- a reference on every object that
    has it -- would go unvalidated. A key whose kinds DISAGREE is left out on
    purpose: guessing which vocabulary applies is how a validator starts
    rejecting valid values.
    """
    seen: dict = {}
    for spec in KIND_SPECS.values():
        for key, ep in (spec.get('refs') or {}).items():
            if key in REF_ENDPOINTS:
                continue
            seen.setdefault(key, set()).add(ep)
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def endpoint_for(key: str, kind: str = '') -> str:
    """The cmdb collection a field selects from ('' when it is not a reference).

    Per-object KIND_SPECS refs win over the global map, mirroring
    ``fortiweb_field_schema.descriptor`` -- if the two disagreed, the dropdown
    and the validator would be reading different collections.
    """
    k_ref = KIND_SPECS.get(kind, {}).get('refs', {}).get(key) if kind else None
    return k_ref or REF_ENDPOINTS.get(key, '') or _kind_refs_agreeing().get(key, '')


def _tokens(value):
    """The object names a submitted value refers to.

    A value is normally one name. A few FortiWeb reference fields carry a
    space- or comma-separated list; each element is a separate object and each
    is checked, so a list with one bad element is rejected naming THAT element.
    """
    s = str(value).strip()
    if not s:
        return []
    if ',' in s:
        parts = [p.strip() for p in s.split(',')]
    elif ' ' in s:
        parts = [p.strip() for p in s.split()]
    else:
        return [s]
    return [p for p in parts if p]



def _rest_unreadable(endpoint: str) -> str:
    """Why this endpoint cannot be checked over REST, or '' when it can.

    An endpoint is only exempt when EVERY collection behind it is unreadable:
    a pair like ``service.custom|service.predefined`` is answerable as long as
    one half answers, and exempting it on the strength of the other would drop
    a check that works.
    """
    parts = [c.strip() for c in (endpoint or '').split('|') if c.strip()]
    if not parts:
        return ''
    whys = [REST_UNREADABLE.get(c, '') for c in parts]
    return whys[0] if all(whys) else ''

def validate(client, fields: dict, kind: str = '') -> tuple[list, list]:
    """(problems, unverified) for the reference fields inside ``fields``.

    ``problems``   - dicts {field, value, endpoint, reason, options} the caller
                     must refuse. Empty means nothing is known to be wrong.
    ``unverified`` - dicts {field, endpoint, error} we could not check. The
                     write proceeds; the caller reports them.

    Only keys PRESENT in ``fields`` cost a read, so a normal one-field save
    makes one extra GET.
    """
    problems, unverified = [], []
    if not isinstance(fields, dict):
        return problems, unverified
    cache = {}
    for key, value in fields.items():
        endpoint = endpoint_for(key, kind)
        if not endpoint or value in _EMPTY:
            continue
        names = _tokens(value)
        if not names:
            continue
        unreadable = _rest_unreadable(endpoint)
        if unreadable:
            unverified.append({'field': key, 'endpoint': endpoint,
                               'error': unreadable})
            continue
        if endpoint not in cache:
            cache[endpoint] = client.cmdb_names_checked(endpoint)
        known, status, err = cache[endpoint]
        if status == 'error':
            unverified.append({'field': key, 'endpoint': endpoint, 'error': err})
            continue
        if status == 'absent':
            problems.append({
                'field': key, 'value': str(value), 'endpoint': endpoint,
                'options': [],
                'reason': ('this firmware has no "%s" collection, so "%s" cannot '
                           'be set on this device' % (endpoint, key)),
            })
            continue
        missing = [n for n in names if n not in known]
        if not missing:
            continue
        if not known:
            reason = ('"%s" has no configured objects on this device, so there '
                      'is nothing "%s" can name yet' % (endpoint, key))
        else:
            reason = ('%s not configured on this device' %
                      ', '.join('"%s"' % m for m in missing))
        problems.append({
            'field': key, 'value': str(value), 'endpoint': endpoint,
            'options': known[:SAMPLE], 'reason': reason,
        })
    return problems, unverified


def message(problems: list) -> str:
    """One operator-readable line per problem, naming field, value and reason.

    This is the sentence the device refuses to write: FortiWeb's -651 says only
    "Invalid input value".
    """
    out = []
    for p in problems:
        line = '%s: "%s" — %s' % (p['field'], p['value'], p['reason'])
        if p.get('options'):
            line += ' (configured: %s)' % ', '.join(p['options'])
        out.append(line)
    return '; '.join(out)


def check(appliance, fields: dict, kind: str = '') -> tuple[list, list]:
    """``validate`` against an Appliance row, building the client here.

    Every caller goes through this so there is ONE place that decides what a
    client we cannot even construct means: nothing is *known* to be wrong, so
    the write proceeds and the device stays the authority.
    """
    from ..clients.fortiweb import FortiWebClient
    try:
        client = FortiWebClient(appliance)
    except Exception:  # noqa: BLE001 - no client: leave the verdict to the device
        return [], []
    return validate(client, fields, kind)
