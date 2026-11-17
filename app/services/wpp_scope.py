"""Who else stands behind this Web Protection Profile?

A carve-out is authored against a WPP, but it takes effect for every Server
Policy that BINDS that WPP, and FortiWeb records no trace of which policy the
carve-out was meant for. Two independent facts make that dangerous, and until
2026-08-08 SATOM only ever checked one of them:

* **template-managed** — :func:`wpp_exceptions.template_lock_error`. A profile
  the template system owns stays clean, so a carve-out on it is refused
  outright. Enforced since the Exceptions page shipped.
* **shared** — this module. A profile bound by MORE THAN ONE Server Policy
  leaks: authorise a URL for one site and you have authorised it for every
  other site standing behind that profile. **Nothing checked this.** An
  ordinary non-template WPP bound by four policies accepted a carve-out in
  silence and applied it to all four.

The two are independent, and either alone is reason enough to demand the guided
clone: a profile can be shared without being a template (the common case, and
the one that was open), or a template bound by exactly one policy.

**Unknown is not safe.** The binding map is read off the live device; when the
box cannot be read the answer is ``unknown``, never "not shared". A carve-out
that leaks and a carve-out nobody could prove doesn't leak are the same risk to
the policies behind that profile, and only one of those is honest to show.

Where the gate is enforced, and why not everywhere:

* :mod:`views.exceptions` ``save`` — **advisory only**. Authoring a draft in the
  manager DB leaks nothing, and that page is device-free by construction (it
  must keep working against an unreachable box). It gets a banner, not a 403.
* ``attack_search`` accept and :mod:`views.advisor` apply — **gate**. Both
  already hold a live device, and both are one click from a push.
* ``inject`` — **hard gate**. This is where the leak physically happens: the
  moment the row lands on the box it is live for every policy on the profile.
  A device that cannot be read here fails the push rather than passing it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Returned when the device could not be read. Distinct from "not shared".
UNKNOWN = 'unknown'
EXCLUSIVE = 'exclusive'
SHARED = 'shared'


@dataclass
class ScopeVerdict:
    """Everything the caller needs to decide, and to explain the decision."""

    wpp: str = ''
    policy: str = ''
    state: str = UNKNOWN
    #: Other Server Policies binding this WPP — the blast radius, by name.
    shared_with: list[str] = field(default_factory=list)
    template_locked: bool = False
    lock_reason: str = ''
    device_error: str = ''
    clone_name: str = ''

    @property
    def needs_clone(self) -> bool:
        """True when a carve-out must NOT be authored on this profile as-is."""
        return self.state != EXCLUSIVE or self.template_locked

    @property
    def blocking(self) -> bool:
        """Alias kept separate from :attr:`needs_clone` on purpose: a future
        reason to refuse (say, a profile under an open change request) would be
        blocking without a clone being the remedy."""
        return self.needs_clone

    def reasons(self) -> list[str]:
        """Human-readable causes, most specific first. Empty = safe to author."""
        out: list[str] = []
        if self.template_locked and self.lock_reason:
            out.append(self.lock_reason)
        if self.state == SHARED:
            names = ', '.join('"%s"' % p for p in self.shared_with[:6])
            more = (', and %d more' % (len(self.shared_with) - 6)
                    if len(self.shared_with) > 6 else '')
            out.append(
                'Web Protection Profile "%s" is also bound by %s%s. A carve-out '
                'authored on it applies to %s too — FortiWeb cannot scope an '
                'exception to one Server Policy.'
                % (self.wpp, names, more,
                   'those policies' if len(self.shared_with) > 1 else 'that policy'))
        if self.state == UNKNOWN:
            out.append(
                'SATOM could not read the Server Policy bindings from the '
                'appliance%s, so it cannot prove that "%s" belongs to "%s" '
                'alone. An exception on a shared profile applies to every '
                'policy behind it.'
                % (' (%s)' % self.device_error if self.device_error else '',
                   self.wpp, self.policy or 'this policy'))
        return out

    def summary(self) -> str:
        """One line for a badge/banner."""
        if not self.needs_clone:
            return ('"%s" is bound by "%s" alone — a carve-out here affects '
                    'nothing else.' % (self.wpp, self.policy))
        return ' '.join(self.reasons())

    def to_dict(self) -> dict:
        return {
            'wpp': self.wpp, 'policy': self.policy, 'state': self.state,
            'shared_with': list(self.shared_with),
            'template_locked': self.template_locked,
            'lock_reason': self.lock_reason,
            'device_error': self.device_error,
            'needs_clone': self.needs_clone,
            'clone_name': self.clone_name,
            'reasons': self.reasons(),
            'summary': self.summary(),
        }


def bindings(appliance) -> tuple[dict, str]:
    """Live ``{server_policy: wpp}`` off the device, plus a read error.

    Returns ``({}, "<reason>")`` when the box could not be asked — the caller
    MUST treat an empty map with a non-empty error as *unknown*, not as *no
    policies bind anything*. Those two produce the same dict and mean opposite
    things, which is exactly the confusion this signature exists to prevent.
    """
    from ..clients.fortiweb import FortiWebClient
    try:
        client = FortiWebClient(appliance)
        rows = client._results_list(client.list_server_policies())
    except Exception as exc:  # noqa: BLE001 — a dead box is a read failure, not a fact
        return {}, str(exc) or exc.__class__.__name__
    out = {}
    for r in rows:
        if isinstance(r, dict) and r.get('name'):
            out[r['name']] = r.get('web-protection-profile') or ''
    return out, ''


def policies_using(binding_map: dict, wpp: str) -> list[str]:
    """Every Server Policy in *binding_map* that binds *wpp*, sorted."""
    if not wpp:
        return []
    return sorted(p for p, w in (binding_map or {}).items() if w == wpp)


def check(appliance, wpp: str, policy: str = '', *,
          binding_map: dict | None = None,
          device_error: str = '') -> ScopeVerdict:
    """Is it safe to author a carve-out on *wpp* for *policy*?

    *binding_map* / *device_error* let a caller that already paid for the device
    read hand the result in rather than paying again — a page that checks three
    carve-outs should not open three sessions to the same box.
    """
    from . import wpp_exceptions as store
    from . import wpp_clone_flow

    wpp = (wpp or '').strip()
    policy = (policy or '').strip()
    v = ScopeVerdict(wpp=wpp, policy=policy)
    if not wpp:
        # No profile named: nothing to share. The authoring form's own required
        # -field check owns this case; inventing a scope verdict here would put
        # a second, quieter validator in the path.
        v.state = EXCLUSIVE
        return v

    v.lock_reason = store.template_lock_error(wpp)
    v.template_locked = bool(v.lock_reason)

    if binding_map is None:
        binding_map, device_error = bindings(appliance)
    if device_error:
        v.state = UNKNOWN
        v.device_error = device_error
    else:
        users = policies_using(binding_map, wpp)
        others = [p for p in users if p != policy]
        v.shared_with = others
        # One binder that is not our policy still counts as shared: authoring
        # "for" a policy that does not bind this profile would change a
        # different site's behaviour and not our own.
        v.state = EXCLUSIVE if not others else SHARED

    if v.needs_clone and policy:
        v.clone_name = wpp_clone_flow.derive_name(policy)
    return v


def enforce(appliance, wpp: str, policy: str = '', *,
            binding_map: dict | None = None,
            device_error: str = '') -> tuple[ScopeVerdict, str]:
    """:func:`check` plus the refusal text, so callers cannot forget to build one.

    Returns ``(verdict, "")`` when authoring may proceed, ``(verdict, reason)``
    when it may not.
    """
    v = check(appliance, wpp, policy, binding_map=binding_map,
              device_error=device_error)
    return v, ('' if not v.needs_clone else ' '.join(v.reasons()))
