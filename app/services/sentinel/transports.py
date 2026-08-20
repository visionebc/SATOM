"""Executable transports — the only code in Sentinel that writes to a device.

Why this module exists separately from ``actions.py``
-----------------------------------------------------
``actions.py`` decides WHETHER something may happen. This module knows HOW,
and nothing else. The split matters because the two fail differently: a policy
bug refuses a legitimate action (annoying), a transport bug writes the wrong
object on a production appliance (an outage we caused).

Everything here was captured from a live FortiWeb 7.6.8 (fortiweb12, lab) on
2026-08-20 by running it, not by reading the reference manual. That distinction
is not pedantry in this product: 22 of 237 documented FortiWeb configuration
routes answer ``-20001 "invalid URL"``, and this very module's first draft named
``waf/http-access-limit`` for rate limiting — a route that does not exist on
this firmware.

The chain, verified end to end
------------------------------
A server policy does not name an IP list. It names a Web Protection Profile,
and the PROFILE names the list::

    server-policy/policy .web-protection-profile
        -> waf/web-protection-profile.inline-protection .ip-list-policy
            -> waf/ip-list
                -> waf/ip-list/members?mkey=<list>

Which produces the single most important rule in this file:

**Adding a member to a list that no profile references blocks nothing.**
The POST returns 200. ``sz_members`` goes up. The console would show a green
"applied" badge, and the attacker would keep going. That is the ``ca-group``
defect this product already shipped once — an object created, valid, and bound
to nothing — one level further up.

So :meth:`Transport.preflight` READS the profile off the device before every
apply, and refuses with an actionable reason if the binding is absent. And the
incident path never creates or binds anything: arming a policy is a separate,
explicit, human-triggered operation (:func:`arm_policy`). An agent that binds
its own enforcement point mid-incident is an agent that can invent its own
authority.

TTL is enforced twice, on purpose
---------------------------------
The list carries ``action=block-period`` with ``block-period`` in seconds, so
**the appliance expires the block by itself**. Sentinel also deletes the member
when its own TTL runs out. The device-side expiry is the one that matters: it
survives Sentinel being dead, which is precisely the moment a stuck block would
otherwise never be lifted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ...clients.fortiweb import FortiWebClient

#: The list Sentinel writes into. Never a list someone else authored: sharing
#: an operator's list would make our automatic deletions look like their edits
#: disappearing.
SENTINEL_LIST = "satom-sentinel-block"

_CMDB = "/api/v2.0/cmdb"
_IPLIST = _CMDB + "/waf/ip-list"
_WPP = _CMDB + "/waf/web-protection-profile.inline-protection"
_POLICY = _CMDB + "/server-policy/policy"

#: Captured from fortiweb12 (7.6.8) on 2026-08-20. Kept as data so the docs
#: page and the Settings console can render the exact provenance an operator
#: needs in order to trust — or distrust — an automatic action.
PROVENANCE = ("verified on fortiweb12 (FortiWeb 7.6.8) 2026-08-20: create list "
              "200, add member 200 (sz_members 0->1), re-read member present, "
              "delete member 200 (sz_members 1->0), delete list 200, zero "
              "residue")


@dataclass
class TransportResult:
    """Outcome of one device write, with the handle needed to undo it."""

    ok: bool
    detail: str = ""
    handle: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)


def _results(resp):
    try:
        return (resp.json() or {}).get("results")
    except Exception:
        return None


def _err(resp) -> str:
    """A device refusal in words, or '' when the device accepted.

    HTTP 200 is NOT success on this product — ``policy.scripting.text`` answers
    200 with ``"Scripting doesn't contain any event."`` So the envelope is
    inspected too, always.
    """
    res = _results(resp)
    if isinstance(res, dict) and res.get("errcode") not in (None, 0, "0"):
        return f"errcode {res.get('errcode')}: {res.get('message') or ''}".strip()
    if resp.status_code >= 400:
        return f"HTTP {resp.status_code}"
    return ""


class BlockIpTransport:
    """Add one source address to the Sentinel IP list bound to a policy."""

    key = "block_ip"
    provenance = PROVENANCE

    # -- preconditions ---------------------------------------------------- #
    def preflight(self, client: FortiWebClient, params: dict) -> tuple:
        """Is this appliance actually able to enforce a block for this policy?

        Returns ``(ok, reason)``. Every branch names what an operator must DO,
        because "preflight failed" on an incident page at 3am is worthless.
        """
        policy = (params.get("policy") or "").strip()
        if not policy:
            return False, "no server policy on the incident — nothing to bind a block to"

        pol = _results(client.get(f"{_POLICY}?mkey={policy}"))
        if not isinstance(pol, dict) or not pol.get("name"):
            return False, f"server policy '{policy}' does not exist on this appliance"

        wpp = (pol.get("web-protection-profile") or "").strip()
        if not wpp:
            return False, (f"policy '{policy}' has no web protection profile, so it "
                           f"has no place to reference an IP list")

        prof = _results(client.get(f"{_WPP}?mkey={wpp}"))
        if not isinstance(prof, dict) or not prof.get("name"):
            return False, (f"web protection profile '{wpp}' could not be read back "
                           f"from the appliance")

        bound = (prof.get("ip-list-policy") or "").strip()
        if bound != SENTINEL_LIST:
            return False, (
                f"profile '{wpp}' does not reference the Sentinel IP list "
                f"(ip-list-policy={bound or 'empty'}). Adding a member to an "
                f"unreferenced list blocks nothing. Arm this policy first — "
                f"Sentinel will not bind its own enforcement point during an "
                f"incident.")
        return True, f"profile '{wpp}' references '{SENTINEL_LIST}'"

    # -- apply ------------------------------------------------------------- #
    def apply(self, client: FortiWebClient, params: dict) -> TransportResult:
        ip = (params.get("src_ip") or "").strip()
        if not ip:
            return TransportResult(False, "no source address")

        before = self._member_for(client, ip)
        if before:
            return TransportResult(True, f"{ip} was already listed",
                                   handle={"list": SENTINEL_LIST,
                                           "member_id": before.get("id"),
                                           "ip": ip},
                                   evidence={"already_present": True})

        resp = client.post(f"{_IPLIST}/members?mkey={SENTINEL_LIST}",
                           {"data": {"type": "black-ip", "ip": ip}})
        err = _err(resp)
        if err:
            return TransportResult(False, f"appliance refused the member: {err}")

        # The device's own answer is not the proof. Re-read.
        row = self._member_for(client, ip)
        if not row:
            return TransportResult(
                False, f"appliance accepted the write but {ip} is not in the "
                       f"list on re-read")
        return TransportResult(
            True, f"{ip} added to {SENTINEL_LIST}",
            handle={"list": SENTINEL_LIST, "member_id": row.get("id"), "ip": ip},
            evidence={"member_id": row.get("id"),
                      "sz_members": self._size(client)})

    # -- verification and undo --------------------------------------------- #
    def verify_applied(self, client: FortiWebClient, handle: dict) -> tuple:
        """Is the rule ON THE DEVICE right now? Read it; never trust our record."""
        ip = (handle or {}).get("ip") or ""
        row = self._member_for(client, ip)
        return bool(row), (f"{ip} present in {SENTINEL_LIST}" if row
                           else f"{ip} is NOT in {SENTINEL_LIST}")

    def rollback(self, client: FortiWebClient, handle: dict) -> TransportResult:
        ip = (handle or {}).get("ip") or ""
        mid = (handle or {}).get("member_id")
        if not mid:
            row = self._member_for(client, ip)
            mid = row.get("id") if row else None
        if not mid:
            return TransportResult(True, f"{ip} is already absent — nothing to undo")
        resp = client.delete(f"{_IPLIST}/members?mkey={SENTINEL_LIST}&sub_mkey={mid}")
        err = _err(resp)
        if err:
            return TransportResult(False, f"delete refused: {err}")
        still, _ = self.verify_applied(client, handle)
        if still:
            return TransportResult(False, f"{ip} is STILL listed after delete")
        return TransportResult(True, f"{ip} removed from {SENTINEL_LIST}")

    # -- helpers ------------------------------------------------------------ #
    @staticmethod
    def _members(client: FortiWebClient) -> list:
        res = _results(client.get(f"{_IPLIST}/members?mkey={SENTINEL_LIST}"))
        return res if isinstance(res, list) else []

    def _member_for(self, client: FortiWebClient, ip: str) -> dict:
        for row in self._members(client):
            if (row.get("ip") or "").strip() == ip:
                return row
        return {}

    @staticmethod
    def _size(client: FortiWebClient):
        res = _results(client.get(f"{_IPLIST}?mkey={SENTINEL_LIST}"))
        return (res or {}).get("sz_members") if isinstance(res, dict) else None


#: Only transports that have been RUN against a device belong here. An entry
#: added from documentation is the failure this module was built to prevent.
TRANSPORTS: dict = {BlockIpTransport.key: BlockIpTransport()}


def get(action_type: str):
    return TRANSPORTS.get(action_type)


# ---------------------------------------------------------------------------- #
#  Arming — deliberately OUTSIDE the incident path                              #
# ---------------------------------------------------------------------------- #
def arm_status(client: FortiWebClient, policy: str) -> dict:
    """Can this policy be blocked on, and what is missing if not?"""
    ok, reason = BlockIpTransport().preflight(client, {"policy": policy,
                                                       "src_ip": "0.0.0.0"})
    listed = _results(client.get(f"{_IPLIST}?mkey={SENTINEL_LIST}"))
    return {"policy": policy, "armed": ok, "reason": reason,
            "list_exists": isinstance(listed, dict) and bool(listed.get("name")),
            "list": SENTINEL_LIST}


def arm_policy(client: FortiWebClient, policy: str, *, block_period: int = 600) -> dict:
    """Create the Sentinel list and bind it to this policy's profile.

    A human runs this, once, ahead of any incident — never the response engine.
    It is the moment somebody decides "Sentinel may enforce here", and that
    decision must be visible in the audit log as a person's, not as a side
    effect of an attack.
    """
    steps: list = []

    def step(name, ok, detail):
        steps.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    existing = _results(client.get(f"{_IPLIST}?mkey={SENTINEL_LIST}"))
    if isinstance(existing, dict) and existing.get("name"):
        step("list", True, f"{SENTINEL_LIST} already exists")
    else:
        r = client.post(_IPLIST, {"data": {
            "name": SENTINEL_LIST, "action": "block-period",
            "block-period": int(block_period), "severity": "High"}})
        e = _err(r)
        if not step("list", not e, e or f"created {SENTINEL_LIST} "
                                        f"(device-side expiry {block_period}s)"):
            return {"ok": False, "steps": steps}

    pol = _results(client.get(f"{_POLICY}?mkey={policy}"))
    wpp = (pol or {}).get("web-protection-profile") if isinstance(pol, dict) else ""
    if not step("profile", bool(wpp),
                f"policy '{policy}' -> profile '{wpp}'" if wpp
                else f"policy '{policy}' has no web protection profile"):
        return {"ok": False, "steps": steps}

    r = client.put(f"{_WPP}?mkey={wpp}",
                   {"data": {"ip-list-policy": SENTINEL_LIST}})
    e = _err(r)
    if not step("bind", not e, e or f"profile '{wpp}'.ip-list-policy = {SENTINEL_LIST}"):
        return {"ok": False, "steps": steps}

    ok, reason = BlockIpTransport().preflight(client, {"policy": policy,
                                                       "src_ip": "0.0.0.0"})
    step("verify", ok, reason)
    return {"ok": ok, "steps": steps}
