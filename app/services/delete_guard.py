"""Pre-delete reference guard: never delete a device object that something else
still names.

Why this is NOT part of ``ref_validate``
---------------------------------------
The two are mirror images of the same concern -- referential integrity against
the device -- but their policy is OPPOSITE on both axes, and a module holding
both would invite reusing the wrong half:

* ``ref_validate`` runs at the operator-facing EDIT views; this runs inside
  ``FortiWebOps.delete`` itself, because a delete reaches the device from
  cascades, bulk jobs, scheduled actions and cert cleanup, not just a form.
* ``ref_validate`` does NOT block when it cannot ask the device: a write that
  names a missing object is refused BY THE DEVICE (``errcode -651``), so a
  failed check costs nothing and blocking would make the editor unusable on a
  flaky box. A delete has no such second authority -- FortiWeb does not
  reliably refuse deleting a referenced object, and when it does not, the
  damage is SILENT: the holders keep pointing at a name that no longer
  resolves, and the operator finds out when traffic breaks. So here an object
  we could not read is an object we do not delete.

What the device tells us
------------------------
Every cmdb row carries FortiWeb's own bookkeeping: ``q_ref`` counts the objects
that name this one, and on some collections ``q_ref_string`` names them, one per
line (``inline-protection(wpp-full-lab)``). Verified live on fortiweb08 (8.0.x)
across ten collections: ``q_ref`` was present on ALL ten, ``q_ref_string`` on
four. So a refusal may always COUNT the holders and may only sometimes NAME
them -- and claiming otherwise would print an empty list as if it meant "none".
"""
from __future__ import annotations

# How many holder names to quote back. Long enough to act on, short enough that
# an object referenced by fifty policies still yields a readable one-liner.
SAMPLE = 6

# The refusal wording is LOAD-BEARING, not cosmetic:
# ``policy_graph._is_in_use_error()`` decides whether a cascade child that would
# not delete is "kept_shared" (benign -- another policy still claims it) or
# "failed" (an alarm) by matching phrases in the error text. A referenced-object
# refusal must match it, and an unverified-object refusal must NOT -- a
# transport failure reported as "safe to leave" is exactly the wrong answer.
# Both directions are pinned in tests/test_delete_guard.py.
_REFERENCED_PHRASE = 'is referenced by'


def _fmt_holders(holders: list) -> str:
    shown = [h for h in holders[:SAMPLE] if h]
    if not shown:
        return ''
    more = len(holders) - len(shown)
    return ', '.join(shown) + (' and %d more' % more if more > 0 else '')


def check(client, endpoint: str, mkey: str) -> tuple[str, dict]:
    """``(reason, info)`` for deleting ``mkey`` from ``endpoint``.

    An empty ``reason`` means the delete may proceed. ``info`` carries
    ``status``/``count``/``holders`` so a caller can render the refusal
    structurally instead of re-parsing the sentence.
    """
    info = {'status': 'error', 'count': 0, 'holders': []}
    if not client or not endpoint or not mkey:
        # Nothing to look up (a sub-row delete addresses its parent's path with
        # no mkey of its own): the caller decides, not this guard.
        return '', {'status': 'skipped', 'count': 0, 'holders': []}
    try:
        count, holders, status, err = client.cmdb_refcount(endpoint, mkey)
    except Exception as exc:  # noqa: BLE001 - a guard must not raise into a write
        count, holders, status, err = 0, [], 'error', str(exc)
    info = {'status': status, 'count': int(count or 0), 'holders': list(holders or [])}

    if status == 'unsupported':
        # This firmware does not report a refcount for this collection. That is
        # a missing CAPABILITY, not a missing answer -- refusing here would make
        # every delete on the collection impossible, forever.
        return '', info
    if status != 'ok':
        return ('refusing to delete "%s": the device did not return it from %s '
                '(%s), so SATOM could not check what still names it. Deleting an '
                'object other objects point at breaks them silently, so the '
                'delete was not attempted.'
                % (mkey, endpoint, err or 'no answer'), info)
    if info['count'] <= 0:
        return '', info

    named = _fmt_holders(info['holders'])
    if named:
        return ('refusing to delete "%s": it %s %d object(s) — %s. Remove those '
                'references first, then delete it.'
                % (mkey, _REFERENCED_PHRASE, info['count'], named), info)
    # Counted but not named: say so, rather than printing an empty list that
    # would read as "referenced by nothing".
    return ('refusing to delete "%s": the device reports it %s %d object(s) but '
            'does not name them for this collection. Find and remove those '
            'references first, then delete it.'
            % (mkey, _REFERENCED_PHRASE, info['count']), info)
