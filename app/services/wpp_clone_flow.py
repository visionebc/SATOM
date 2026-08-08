"""Guided WPP clone — give one Server Policy its own Web Protection Profile.

A carve-out authored on a SHARED profile silently applies to every policy that
binds it, and FortiWeb cannot record which policy a carve-out was meant for. So
SATOM refuses to author on a template-managed WPP (team rule 2) and offers
instead to deep-clone it under the Naming-derived per-policy name
(``wpp-{policy}``), re-bind the Server Policy to the clone, and re-point any
carve-outs already authored against the source.

This module exists because that flow acquired a SECOND caller (2026-08-08): the
Attack-ID investigation page, where an AI-drafted exception has to land on the
right profile just as much as a hand-typed one does. The logic was extracted
from ``views/exceptions.clone_for_policy`` rather than reimplemented — two
copies that agree on the day they are written diverge on the first change, and
the rules that protect a shared profile are not a place to discover that.

Device writes happen ONLY when ``apply=True``. Every other call returns a plan.
"""
from __future__ import annotations

EP_POLICY = '/api/v2.0/cmdb/server-policy/policy'

#: Label recorded on the ``SyncRun`` this flow triggers.
#:
#: ``sync_runs.trigger`` is ``varchar(24)`` — a short enum-ish label
#: (manual|scheduled|write_through|backfill), not a place for a dotted function
#: path. Naming it after the function it was extracted from
#: (``exceptions.clone_for_policy``, 27 chars) overflowed the column and took
#: down the request that had just written to the appliance. Anything assigned
#: here must fit; ``tests/test_sync_trigger_width.py`` enforces that for every
#: ``trigger=`` literal in the tree, so the next one fails a test instead of a
#: production write.
SYNC_TRIGGER = 'wpp.clone_rebind'


def derive_name(policy: str) -> str:
    """The per-policy clone name the Naming catalog dictates.

    Element ``wpp_exception``, default pattern ``wpp-{name}`` where ``{name}``
    is the slugified Server Policy. Read from the catalog rather than
    hard-coded so a site that renamed its scheme gets ITS name, not ours.
    """
    if not policy:
        return ''
    from . import naming as naming_svc
    from . import settings_store as sstore
    scheme = naming_svc.effective_scheme(
        sstore.naming_overrides(naming_svc.PRODUCT_FORTIWEB),
        naming_svc.PRODUCT_FORTIWEB)
    pattern = scheme.get('wpp_exception', 'wpp-{name}')
    return naming_svc.render_one(pattern, naming_svc.slugify(policy) or policy)


def suggestion(appliance, source, policies) -> dict:
    """The guided-clone offer (rule 3): the derived name plus WPP headroom
    (rule 4) checked UP FRONT, so the operator learns the box is full before
    they commit to a plan rather than half-way through applying it."""
    from . import capacity
    pol = next((p for p in (policies or []) if p), '')
    new_name = derive_name(pol)
    try:
        allowed, msg = capacity.check_headroom(appliance, 'web_protection_profile', want=1)
    except Exception:  # noqa: BLE001 — a capacity hiccup never blocks the offer UI
        allowed, msg = True, ''
    return {'source': source, 'policy': pol, 'new_name': new_name,
            'headroom_ok': bool(allowed), 'headroom': msg}


def clone_and_rebind(appliance, *, source: str, policy: str, new_name: str = '',
                     apply: bool = False, actor: str = '') -> dict:
    """Deep-clone ``source`` as ``new_name``, re-bind ``policy`` to it, re-point
    carve-outs. Dry-run unless ``apply``.

    Returns a dict carrying its own HTTP-ish ``code`` so both callers report the
    same failure with the same status. ``ok=False`` never leaves the device
    half-changed on purpose: if any object of the clone fails to write, the
    policy is deliberately NOT re-bound — a policy pointing at a partial profile
    is strictly worse than a policy still pointing at the shared one.
    """
    from . import wpp_exceptions as store
    from . import capacity, clone, objform
    from ..clients.fortiweb import FortiWebClient
    from .fortiweb_ops import FortiWebOps
    from .audit import log_action

    source = (source or '').strip()
    policy = (policy or '').strip()
    new_name = (new_name or '').strip()
    if not source or not policy:
        return {'ok': False, 'code': 400,
                'error': 'source WPP and server policy are required'}
    if not new_name:
        new_name = derive_name(policy)
    if not new_name or new_name == source:
        return {'ok': False, 'code': 400,
                'error': 'could not derive a distinct clone name'}
    if store.template_lock_error(new_name):
        return {'ok': False, 'code': 400,
                'error': '"%s" is itself a template name — pick another' % new_name}

    # Rule 4: never multiply WPPs past the model's capacity.
    allowed, hmsg = capacity.check_headroom(appliance, 'web_protection_profile', want=1)
    if not allowed:
        return {'ok': False, 'code': 409, 'error': hmsg}

    try:
        client = FortiWebClient(appliance)
        reader = clone.ClientReader(client)
        planner = clone.ClonePlanner(reader, reader)
        items = planner.plan(clone.ROOT_WPP, source, new_name=new_name)
    except Exception as exc:  # noqa: BLE001
        return {'ok': False, 'code': 502, 'error': 'device read failed: %s' % exc}

    summary = clone.summarize(items)
    if not apply:
        return {'ok': True, 'code': 200, 'dry_run': True, 'new_name': new_name,
                'summary': summary, 'headroom': hmsg,
                'plan': clone.render_plan(items)}

    if any(it.status == 'create' for it in items):
        ops = FortiWebOps(appliance)

        def _write(item):
            ep = objform.rest_path(item.urn)
            mkey = item.parent_mkey if item.kind == 'subrow' else None
            res = ops.create(ep, {'data': item.payload}, mkey=mkey, dry_run=False)
            if not res.ok:
                raise RuntimeError(res.get('error') or 'write failed')

        clone.apply_clone(items, _write, dry_run=False)
        failed = [it for it in items if (it.result or '').startswith('error')]
        if failed:
            return {'ok': False, 'code': 502,
                    'error': '%d object(s) failed to clone — policy NOT re-bound'
                             % len(failed),
                    'plan': clone.render_plan(items)}
    # else: the clone already exists on the box → just re-bind.

    res = FortiWebOps(appliance).update(
        EP_POLICY, policy, {'data': {'web-protection-profile': new_name}},
        dry_run=False)
    if not res.ok:
        return {'ok': False, 'code': 502, 'new_name': new_name,
                'error': 'clone "%s" is on the device but the policy re-bind '
                         'failed: %s' % (new_name, res.get('error', ''))}

    moved = store.retarget_for_policy(appliance.id, policy, source, new_name)
    log_action('exceptions.clone_for_policy', target='%s/%s' % (appliance.name, policy),
               appliance_id=appliance.id,
               detail='wpp %s -> %s (re-pointed %d carve-out(s))'
                      % (source, new_name, moved))
    # Keep the DB-first pickers current (best-effort — the device write already
    # succeeded; a refresh failure only delays the new name showing in lists).
    #
    # The rollback is the load-bearing line, not the `except`. A refresh that
    # dies mid-flush leaves the SQLAlchemy session in a failed transaction, and
    # swallowing the exception without clearing it hands the CALLER a session
    # that raises PendingRollbackError on its next write. That is not
    # hypothetical: on 2026-08-08 a 27-char ``trigger`` overflowed
    # ``sync_runs.trigger`` (varchar 24), this block swallowed it, and
    # ``save_carveout`` then died on ``store.add`` — so the operator was shown
    # "An unexpected error occurred" for a clone that had ALREADY been written
    # to the appliance and re-bound, and lost the draft they were authoring.
    # Best-effort means the CALLER carries on; it cannot mean the caller
    # inherits a poisoned transaction.
    try:
        from . import device_sync
        device_sync.sync_device(appliance, publish=False, user_label=actor or None,
                                trigger=SYNC_TRIGGER)
    except Exception:  # noqa: BLE001
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001 — nothing left to salvage
            pass
    return {'ok': True, 'code': 200, 'dry_run': False, 'new_name': new_name,
            'rebound': True, 'moved': moved, 'summary': summary}
