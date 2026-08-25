"""Which WEB PROTECTION PROFILE carries an artifact into a server policy.

``artifact_refs`` answers *"policy P names artifact A"*. That is the edge a
migration needs, but it is not the edge an operator can ACT on: a FortiWeb
operator does not bind a schema to a policy, they bind it to a rule which sits
inside a **Web Protection Profile**, and the profile is what the policy names.
Reporting only the policy hides the object the operator would actually open.

**The attribution is walked, never assumed.** The obvious shortcut — "the plan
contains exactly one WPP, so every artifact in the plan belongs to it" — is
wrong twice over, and both ways are silent:

1. ``cmdb/server-policy/scripting`` (Lua) hangs off the SERVER POLICY itself.
   It never passes through a profile. Labelling it with the policy's profile
   sends someone to a WPP that does not mention it.
2. A policy with **content routing** can bind SEVERAL profiles — ``clone._visit``
   follows a WPP reference from a content-routing row as well as from the
   policy. ``next(...)`` over the item list would pick whichever came first and
   silently drop the rest.

So the answer here is a *set* per artifact, produced by walking UP the
referrer graph the clone planner already builds (``ClonePlanner._refs``, keyed
``(urn, mkey) -> {(parent urn, parent mkey)}``) until a WPP node is reached.

Three distinct outcomes, and collapsing any two of them is the bug this module
exists to prevent:

``{"wpp-a"}``  reached through that profile.
``set()``     walked, and it reaches the policy WITHOUT a profile (the Lua case).
``None``      NOT WALKED — no referrer graph was available. Rendered as
              *"not attributed"*, never as *"bound directly"*. An edge derived
              before this module existed is in this state, and printing it as
              case 2 would be inventing a fact about every one of them.
"""
from __future__ import annotations

#: Populated from :mod:`services.clone` lazily so importing this module never
#: drags the planner (and its client stack) into a request that only renders.
def wpp_urns() -> tuple:
    from . import clone as _clone

    return tuple(_clone._WPP_URNS)


def wpp_nodes(items) -> set:
    """``{(urn, mkey)}`` for every Web Protection Profile OBJECT in a plan."""
    urns = set(wpp_urns())
    return {(it.urn, it.mkey) for it in (items or [])
            if getattr(it, "kind", "") == "object"
            and getattr(it, "urn", "") in urns
            and getattr(it, "mkey", "")}


def ancestors(refs: dict, start: tuple) -> set:
    """Every node reachable by walking ``refs`` UPWARD from ``start``.

    Cycle-safe by construction (``seen``): the referrer graph of a real
    appliance is not guaranteed acyclic — a rule pair can name each other — and
    an unguarded walk would hang the sweep rather than fail it.
    """
    out: set = set()
    stack = [start]
    seen = {start}
    while stack:
        node = stack.pop()
        for parent in (refs or {}).get(node, ()) or ():
            if parent in seen:
                continue
            seen.add(parent)
            out.add(parent)
            stack.append(parent)
    return out


def attribute(arts, items, refs):
    """Attach a ``wpp`` set to every artifact row of one policy walk.

    Returns a NEW list; the input rows are not mutated, because the same rows
    are handed to the clone pre-flight's own report and a shared dict edited
    here would show up there as a column that page never asked for.

    ``refs is None`` -> every row gets ``wpp=None`` (not walked). That is the
    honest answer for a caller that has no referrer graph, and it is why this
    function does not default the argument to ``{}``: an empty graph and an
    absent graph mean opposite things, and one keyword default would erase the
    difference for every future caller.
    """
    profiles = wpp_nodes(items) if refs is not None else set()
    by_mkey = {}
    for urn, mkey in profiles:
        by_mkey.setdefault((urn, mkey), mkey)
    out = []
    for a in (arts or []):
        row = dict(a)
        if refs is None:
            row["wpp"] = None
        else:
            up = ancestors(refs, (a.get("urn") or "", a.get("name") or ""))
            row["wpp"] = {mkey for node, mkey in by_mkey.items() if node in up}
        out.append(row)
    return out


def expand(arts):
    """One row per (artifact, profile) — the shape the index stores.

    An artifact reached through two profiles is TWO facts, and one row holding
    ``"a, b"`` in a text column is a fact nobody can filter on. Rows whose
    ``wpp`` is an empty set collapse to a single row carrying ``""``; rows
    whose ``wpp`` is ``None`` carry ``None``.
    """
    out = []
    for a in (arts or []):
        wpp = a.get("wpp")
        if wpp is None:
            out.append(dict(a, wpp=None))
        elif not wpp:
            out.append(dict(a, wpp=""))
        else:
            for name in sorted(wpp):
                out.append(dict(a, wpp=name))
    return out


def describe(wpp) -> str:
    """Operator-facing text for one stored ``wpp_mkey`` value."""
    if wpp is None:
        return "not attributed — walked before profiles were recorded"
    if wpp == "":
        return "bound on the server policy itself (no profile in between)"
    return wpp
