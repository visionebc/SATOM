"""Enumerate FortiAuthenticator users so they can be imported BEFORE first login.

Why this module exists: **RADIUS cannot be enumerated.** An Access-Request is a
yes/no question about one credential — the protocol has no "list the members of
this group" verb. So when the sign-in backend is RADIUS/FortiAuthenticator, the
user list has to come from a *second* channel. That channel is the FAC's own
REST API, reached through the FortiAuthenticator appliance already registered in
SATOM's inventory (its encrypted API key is reused; no new secret is stored).

Authentication is untouched: logins keep going over RADIUS. This is a read-only
roster feed, nothing more.

TRAP, measured against fac01 (v8.0.3) and the reason this module does not just
read ``/localusers/``: that collection **under-reports**. On a FAC with three
local users it returned exactly one (``meta.total_count: 1``), silently omitting
``admin`` and ``ebc``. ``/localgroup-memberships/`` returned BOTH members of the
group, each with its ``username`` — so memberships are the authoritative roster
and ``/localusers/`` is only ever used to enrich (or as a last-resort fallback
when no group filter is in play).
"""
from __future__ import annotations

_MEMBERSHIPS = '/api/v1/localgroup-memberships/'
_LOCALUSERS = '/api/v1/localusers/'
_USERGROUPS = '/api/v1/usergroups/'


def _norm(value) -> str:
    return (str(value or '')).strip()


def list_group_members(client, group_name: str = '', limit: int = 500):
    """``(ok, users | detail)`` — roster for *group_name* on the FAC.

    *users* is a list of ``{"username", "display_name", "source_group"}``
    dicts, de-duplicated on username and capped at *limit*.

    A blank *group_name* means "every user the FAC exposes" — the union of all
    group memberships and the local-user collection. That union is deliberate:
    neither resource alone is complete on this firmware.

    Never raises: a device refusal comes back as ``(False, detail)`` so the
    caller can show the reason instead of an empty roster, which would read as
    "this group has nobody in it".
    """
    wanted = _norm(group_name).lower()

    rows, err = client.list_path_with_error(_MEMBERSHIPS, limit=0)
    if err:
        return False, f'FortiAuthenticator refused the membership list: {err}'

    if wanted:
        known = {_norm(r.get('group_name')).lower() for r in rows if r.get('group_name')}
        if known and wanted not in known:
            # Naming a group that does not exist is a typo, not an empty group.
            # Saying so beats importing zero users and calling it success.
            return False, (f'No group named {group_name!r} on the appliance. '
                           f'Known group(s): {", ".join(sorted(known)) or "none"}.')

    users: dict[str, dict] = {}
    for row in rows:
        gname = _norm(row.get('group_name'))
        if wanted and gname.lower() != wanted:
            continue
        uname = _norm(row.get('username'))
        if uname:
            users[uname] = {'username': uname, 'display_name': '',
                            'source_group': gname}

    # Enrich from /localusers/ (display name, disabled accounts). This call is
    # allowed to fail: the roster above already stands on its own.
    locals_rows, lerr = client.list_path_with_error(_LOCALUSERS, limit=0)
    if not lerr:
        for row in locals_rows:
            uname = _norm(row.get('username'))
            if not uname:
                continue
            if uname in users:
                users[uname]['display_name'] = _norm(row.get('display_name')) or ' '.join(
                    p for p in (_norm(row.get('first_name')), _norm(row.get('last_name'))) if p)
            elif not wanted:
                users[uname] = {'username': uname,
                                'display_name': _norm(row.get('display_name')),
                                'source_group': ''}

    ordered = sorted(users.values(), key=lambda u: u['username'].lower())
    return True, ordered[:max(1, int(limit))]


def list_groups(client):
    """``(ok, names | detail)`` — group names, for the Settings picker."""
    rows, err = client.list_path_with_error(_USERGROUPS, limit=0)
    if err:
        return False, f'FortiAuthenticator refused the group list: {err}'
    return True, sorted({_norm(r.get('name')) for r in rows if _norm(r.get('name'))})


__all__ = ['list_group_members', 'list_groups']
