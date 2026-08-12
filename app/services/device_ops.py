"""Address a destructive appliance action BY DEVICE, without becoming a second
way to authorize one.

The operator who most needs `reboot` is on SSH, in a maintenance window, on a
node whose web UI may be exactly what is unavailable. What they were missing was
never the privilege — ``execute scheduler run <id>`` has always been able to
fire a reboot action — but the *addressing*: turning "reboot fortiweb08" into
the one action id that is allowed to do it, and, when nothing is, saying which
rule said no.

So this module SELECTS and never EXECUTES. It hands back an action id; the
caller passes that to :func:`scheduled_actions.execute_and_record`, which
re-runs the change-request gate itself. Every check below can therefore only
refuse EARLIER than the gate would - it can never permit something the gate
would have stopped. The alternative (a CLI that calls the device) would be a
second implementation of one authorization boundary, and the weaker of two
implementations is the one that ends up being the real one.
"""
from __future__ import annotations


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def select_action(device_name: str, op: str) -> dict:
    """Pick the single action allowed to run *op* against *device_name*.

    Returns one of::

        {"error": str}                         # cannot even be asked
        {"refused": True, "runnable": [...], "rejected": [...]}
        {"action_id": int, "action": str, "cr": int, "device": str}

    ``rejected`` entries are ``[id, name, reason]`` - the reason is the product,
    not a detail. A bare "not authorized" in the middle of a change window is
    worse than useless: the operator cannot tell a missing action from an
    unapproved CR from a window that closed twenty minutes ago, and the quickest
    way out of an undiagnosable refusal is to go around it.
    """
    from ..models import Appliance, ChangeRequest, ScheduledAction
    from . import change_requests as crmod
    from . import scheduled_actions as sa

    device = Appliance.query.filter_by(name=device_name).first()
    if device is None:
        return {"error": "no appliance named %s" % device_name}
    spec = sa.get_spec(op)
    if spec is None:
        return {"error": "unknown action %s" % op}

    # Product first. A reboot URN is not guessable and a wrong guess is not a
    # 404 - on FortiWeb the neighbouring maintenance op reboots the box even on
    # GET. An unverified product is refused BY NAME here for the same reason
    # the executor refuses it: never guessed.
    products = tuple(spec.products or ())
    if device.kind not in products:
        return {"error": "%s is a %s; %r is only verified for: %s"
                         % (device.name, device.kind, op,
                            ", ".join(products) or "(nothing)")}

    runnable: list = []
    rejected: list = []
    for row in ScheduledAction.query.filter_by(action=op).all():
        ids = [v for v in (_int_or_none(t) for t in row.targets_list)
               if v is not None]
        # An empty target list means "every appliance of these kinds". Firing
        # that to satisfy "reboot ONE device" would reboot the fleet, so it is
        # refused rather than narrowed: narrowing it here would mean this
        # module decides what an action targets, which is the scheduler's job
        # and is recorded on the row an auditor reads afterwards.
        if not ids:
            rejected.append([row.id, row.name,
                             "targets the WHOLE fleet, not one device"])
            continue
        if device.id not in ids:
            continue
        if len(ids) > 1:
            rejected.append([row.id, row.name,
                             "also targets %d other device(s)" % (len(ids) - 1)])
            continue
        cr_id = _int_or_none(row.params_dict.get("change_request_id"))
        if cr_id is None:
            rejected.append([row.id, row.name, "not bound to a change request"])
            continue
        ok, reason = crmod.cr_runnable(ChangeRequest.query.get(cr_id))
        if not ok:
            rejected.append([row.id, row.name, "CR %s: %s" % (cr_id, reason)])
            continue
        runnable.append([row.id, row.name, cr_id])

    # Exactly one, or nothing. Two runnable actions for one device is an
    # ambiguity an operator must resolve by id: picking "the first" would make
    # which appliance reboots depend on row order.
    if len(runnable) != 1:
        return {"refused": True, "device": device.name, "kind": device.kind,
                "runnable": runnable, "rejected": rejected}
    return {"action_id": runnable[0][0], "action": runnable[0][1],
            "cr": runnable[0][2], "device": device.name}
