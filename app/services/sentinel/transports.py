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

#: The geo list Sentinel writes into. Same reasoning as SENTINEL_LIST: never a
#: list an operator authored, so our automatic deletions can never look like
#: their entries vanishing.
SENTINEL_GEO_LIST = "satom-sentinel-geo"

_CMDB = "/api/v2.0/cmdb"
_IPLIST = _CMDB + "/waf/ip-list"
_GEO = _CMDB + "/waf/geo-block-list"
_WPP = _CMDB + "/waf/web-protection-profile.inline-protection"
_POLICY = _CMDB + "/server-policy/policy"

#: Captured from fortiweb12 (7.6.8) on 2026-08-20. Kept as data so the docs
#: page and the Settings console can render the exact provenance an operator
#: needs in order to trust — or distrust — an automatic action.
PROVENANCE = ("verified on fortiweb12 (FortiWeb 7.6.8) 2026-08-20: create list "
              "200, add member 200 (sz_members 0->1), re-read member present, "
              "delete member 200 (sz_members 1->0), delete list 200, zero "
              "residue")

#: Captured the same day, same appliance. The child collection is
#: ``country-list`` — NOT ``members`` — and the member key is ``country-name``
#: carrying a full country name. ``{"country": "Andorra"}`` answers
#: ``errcode -7950 "The country name is empty or wrong."`` and ``{"country":
#: "AD"}`` answers the same: this appliance does not take ISO codes.
PROVENANCE_GEO = ("verified on fortiweb12 (FortiWeb 7.6.8) 2026-08-20: create "
                  "geo-block-list 200, POST country-list?mkey=<list> "
                  "{country-name: 'Andorra'} 200 -> id 1, re-read row present, "
                  "DELETE &sub_mkey=1 200, delete list 200, zero residue. "
                  "Rejected shapes recorded: {country: 'Andorra'} and "
                  "{country: 'AD'} both -7950")

#: Also captured on fortiweb12: the profile binding of a live server policy was
#: moved and put back from the value read off the device first.
PROVENANCE_WPP = ("verified on fortiweb12 (FortiWeb 7.6.8) 2026-08-20 against "
                  "policy pol-root-wiki: read web-protection-profile "
                  "'wpp-root-wiki', PUT 'Inline Extended Protection' 200, "
                  "re-read matched, PUT the ORIGINAL back 200, re-read matched "
                  "— restored from the captured value, never from a default")


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


def _child_rows(client, path) -> list:
    """The rows of a child collection, or ``[]`` — never the parent object.

    This appliance answers a WRONG child path with HTTP 200 and the PARENT
    object: ``GET waf/geo-block-list/members?mkey=X`` returns the list record
    itself, complete and successful-looking, instead of an error. Code that
    checked only the status code would happily "verify" a write against an
    endpoint that cannot hold it. Anything that is not a list is no rows.
    """
    res = _results(client.get(path))
    return res if isinstance(res, list) else []


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


class BlockCountryTransport:
    """Add one country to the Sentinel geo list bound to a policy.

    Structurally the same shape as :class:`BlockIpTransport` — an entry in a
    list that a profile must already reference — and operationally nothing
    like it. One address is one attacker; one country is every client in a
    market. That is why :data:`~..actions.CATALOG` caps this action at
    *recommend* no matter what an operator sets, and why the size of the blast
    is written into the action's own description rather than left for someone
    to infer from the name.
    """

    key = "block_country"
    provenance = PROVENANCE_GEO

    def preflight(self, client: FortiWebClient, params: dict) -> tuple:
        policy = (params.get("policy") or "").strip()
        country = (params.get("country") or "").strip()
        if not policy:
            return False, ("no server policy on the incident — nothing to bind "
                           "a geo block to")
        if not country:
            return False, ("the incident carries no source country, so there is "
                           "nothing to block")
        if len(country) <= 3:
            return False, (
                f"'{country}' is a code, and this appliance names countries in "
                f"full — it answers errcode -7950 to anything else. Sentinel "
                f"will not expand a code into a name: the value has to be the "
                f"one the device's own log reported.")

        pol = _results(client.get(f"{_POLICY}?mkey={policy}"))
        if not isinstance(pol, dict) or not pol.get("name"):
            return False, f"server policy '{policy}' does not exist on this appliance"
        wpp = (pol.get("web-protection-profile") or "").strip()
        if not wpp:
            return False, (f"policy '{policy}' has no web protection profile, so "
                           f"it has no place to reference a geo list")
        prof = _results(client.get(f"{_WPP}?mkey={wpp}"))
        if not isinstance(prof, dict) or not prof.get("name"):
            return False, (f"web protection profile '{wpp}' could not be read "
                           f"back from the appliance")
        bound = (prof.get("geo-block-list-policy") or "").strip()
        if bound != SENTINEL_GEO_LIST:
            return False, (
                f"profile '{wpp}' does not reference the Sentinel geo list "
                f"(geo-block-list-policy={bound or 'empty'}). Adding a country "
                f"to an unreferenced list blocks nothing. Arm this policy for "
                f"geo blocking first — Sentinel will not bind its own "
                f"enforcement point during an incident.")
        return True, f"profile '{wpp}' references '{SENTINEL_GEO_LIST}'"

    def apply(self, client: FortiWebClient, params: dict) -> TransportResult:
        country = (params.get("country") or "").strip()
        if not country:
            return TransportResult(False, "no country on the action")

        before = self._row_for(client, country)
        if before:
            return TransportResult(True, f"{country} was already listed",
                                   handle={"list": SENTINEL_GEO_LIST,
                                           "member_id": before.get("id"),
                                           "country": country},
                                   evidence={"already_present": True})

        resp = client.post(f"{_GEO}/country-list?mkey={SENTINEL_GEO_LIST}",
                           {"data": {"country-name": country}})
        err = _err(resp)
        if err:
            return TransportResult(False, f"appliance refused the country: {err}")

        row = self._row_for(client, country)
        if not row:
            return TransportResult(
                False, f"appliance accepted the write but {country} is not in "
                       f"{SENTINEL_GEO_LIST} on re-read")
        return TransportResult(
            True, f"{country} added to {SENTINEL_GEO_LIST}",
            handle={"list": SENTINEL_GEO_LIST, "member_id": row.get("id"),
                    "country": country},
            evidence={"member_id": row.get("id"), "sz_country_list": self._size(client)})

    def verify_applied(self, client: FortiWebClient, handle: dict) -> tuple:
        country = (handle or {}).get("country") or ""
        row = self._row_for(client, country)
        return bool(row), (f"{country} present in {SENTINEL_GEO_LIST}" if row
                           else f"{country} is NOT in {SENTINEL_GEO_LIST}")

    def rollback(self, client: FortiWebClient, handle: dict) -> TransportResult:
        country = (handle or {}).get("country") or ""
        mid = (handle or {}).get("member_id")
        if not mid:
            row = self._row_for(client, country)
            mid = row.get("id") if row else None
        if not mid:
            return TransportResult(True, f"{country} is already absent — nothing to undo")
        resp = client.delete(f"{_GEO}/country-list?mkey={SENTINEL_GEO_LIST}"
                             f"&sub_mkey={mid}")
        err = _err(resp)
        if err:
            return TransportResult(False, f"delete refused: {err}")
        still, _ = self.verify_applied(client, handle)
        if still:
            return TransportResult(False, f"{country} is STILL listed after delete")
        return TransportResult(True, f"{country} removed from {SENTINEL_GEO_LIST}")

    # -- helpers ------------------------------------------------------------ #
    @staticmethod
    def _rows(client: FortiWebClient) -> list:
        return _child_rows(client, f"{_GEO}/country-list?mkey={SENTINEL_GEO_LIST}")

    def _row_for(self, client: FortiWebClient, country: str) -> dict:
        for row in self._rows(client):
            if (row.get("country-name") or "").strip() == country:
                return row
        return {}

    @staticmethod
    def _size(client: FortiWebClient):
        res = _results(client.get(f"{_GEO}?mkey={SENTINEL_GEO_LIST}"))
        return (res or {}).get("sz_country-list") if isinstance(res, dict) else None


class RaiseProtectionTransport:
    """Move a server policy onto a pre-approved hardened protection profile.

    Two properties make this the most dangerous entry in the catalog, and both
    are answered here rather than in policy:

    * **The blast radius is every client of the policy**, not one source. A
      hardened profile that blocks a legitimate integration is an outage we
      caused while defending.
    * **The undo is a write, not an expiry.** There is no device-side timer to
      fall back on the way ``block-period`` covers a blocked address. So the
      previous profile is READ OFF THE DEVICE before the change and carried in
      the handle, and :meth:`rollback` refuses to write an empty binding — an
      unbound policy would leave every client of it unprotected, which is a
      worse state than the one being undone.

    Sentinel never invents the target. It must be named in Settings → Sentinel
    → "Hardened web protection profiles" by a person, and it must already exist
    on the appliance. Creating a profile mid-incident is how a policy ends up
    bound to an empty one — the ca-group defect this product already shipped.
    """

    key = "raise_protection"
    provenance = PROVENANCE_WPP

    @staticmethod
    def approved() -> list:
        from . import config as _config
        raw = _config.get("hardened_profiles") or ""
        return [p.strip() for p in str(raw).replace(",", "\n").splitlines()
                if p.strip()]

    def _target(self, params: dict) -> str:
        """The profile to move to: the operator's, or the first approved one."""
        named = (params.get("profile") or "").strip()
        if named:
            return named
        approved = self.approved()
        return approved[0] if approved else ""

    @staticmethod
    def _current(client: FortiWebClient, policy: str) -> str:
        pol = _results(client.get(f"{_POLICY}?mkey={policy}"))
        if not isinstance(pol, dict):
            return ""
        return (pol.get("web-protection-profile") or "").strip()

    def preflight(self, client: FortiWebClient, params: dict) -> tuple:
        policy = (params.get("policy") or "").strip()
        if not policy:
            return False, "no server policy on the incident — nothing to raise"

        approved = self.approved()
        if not approved:
            return False, (
                "no hardened profile has been approved. Settings -> Sentinel -> "
                "'Hardened web protection profiles' is empty, and Sentinel will "
                "not choose one: that profile IS the security posture of every "
                "client on the policy.")

        target = self._target(params)
        if target not in approved:
            return False, (f"'{target}' is not an approved hardened profile "
                           f"(approved: {', '.join(approved)})")

        pol = _results(client.get(f"{_POLICY}?mkey={policy}"))
        if not isinstance(pol, dict) or not pol.get("name"):
            return False, f"server policy '{policy}' does not exist on this appliance"

        current = (pol.get("web-protection-profile") or "").strip()
        if not current:
            return False, (f"policy '{policy}' has no profile bound right now, so "
                           f"there is no previous value to restore afterwards")
        if current == target:
            return False, (f"policy '{policy}' is already on '{target}' — "
                           f"nothing to raise")

        prof = _results(client.get(f"{_WPP}?mkey={target}"))
        if not isinstance(prof, dict) or not prof.get("name"):
            return False, (f"approved profile '{target}' does not exist on this "
                           f"appliance. Create it there first; Sentinel does not "
                           f"author protection profiles.")
        return True, f"policy '{policy}': '{current}' -> '{target}' (approved)"

    def apply(self, client: FortiWebClient, params: dict) -> TransportResult:
        policy = (params.get("policy") or "").strip()
        target = self._target(params)
        previous = self._current(client, policy)
        if not previous:
            return TransportResult(
                False, "refusing to raise a policy whose current profile could "
                       "not be read — the undo would have nothing to restore")

        resp = client.put(f"{_POLICY}?mkey={policy}",
                          {"data": {"web-protection-profile": target}})
        err = _err(resp)
        if err:
            return TransportResult(False, f"appliance refused the change: {err}")

        now = self._current(client, policy)
        if now != target:
            return TransportResult(
                False, f"appliance accepted the write but policy '{policy}' "
                       f"reads back '{now}'")
        return TransportResult(
            True, f"policy '{policy}' moved '{previous}' -> '{target}'",
            handle={"policy": policy, "profile": target, "previous": previous},
            evidence={"previous": previous, "profile": target})

    def verify_applied(self, client: FortiWebClient, handle: dict) -> tuple:
        policy = (handle or {}).get("policy") or ""
        target = (handle or {}).get("profile") or ""
        now = self._current(client, policy)
        return now == target and bool(target), (
            f"policy '{policy}' is on '{now}'" if now
            else f"policy '{policy}' could not be read back")

    def rollback(self, client: FortiWebClient, handle: dict) -> TransportResult:
        policy = (handle or {}).get("policy") or ""
        previous = (handle or {}).get("previous") or ""
        if not policy:
            return TransportResult(False, "no policy in the handle — cannot undo")
        if not previous:
            return TransportResult(
                False, "the handle carries no previous profile. Refusing to "
                       "write an empty binding: unbinding the profile removes "
                       "protection from every client of this policy, which is "
                       "worse than the raised profile it would be undoing. "
                       "Restore this one by hand.")
        if self._current(client, policy) == previous:
            return TransportResult(True, f"policy '{policy}' is already back on "
                                         f"'{previous}'")
        resp = client.put(f"{_POLICY}?mkey={policy}",
                          {"data": {"web-protection-profile": previous}})
        err = _err(resp)
        if err:
            return TransportResult(False, f"restore refused: {err}")
        now = self._current(client, policy)
        if now != previous:
            return TransportResult(
                False, f"restore accepted but policy '{policy}' reads back "
                       f"'{now}', not '{previous}'")
        return TransportResult(True, f"policy '{policy}' restored to '{previous}'")


#: Only transports that have been RUN against a device belong here. An entry
#: added from documentation is the failure this module was built to prevent.
TRANSPORTS: dict = {
    BlockIpTransport.key: BlockIpTransport(),
    BlockCountryTransport.key: BlockCountryTransport(),
    RaiseProtectionTransport.key: RaiseProtectionTransport(),
}


def get(action_type: str):
    return TRANSPORTS.get(action_type)


# ---------------------------------------------------------------------------- #
#  Arming — deliberately OUTSIDE the incident path                              #
# ---------------------------------------------------------------------------- #
def arm_status(client: FortiWebClient, policy: str) -> dict:
    """Can this policy be enforced on, per mechanism, and what is missing?

    Reported per mechanism rather than as one boolean: a policy armed for
    address blocking and not for geo blocking is the normal case, and a single
    "armed: true" would hide which of the two an incident can actually use.
    """
    ok, reason = BlockIpTransport().preflight(client, {"policy": policy,
                                                       "src_ip": "0.0.0.0"})
    listed = _results(client.get(f"{_IPLIST}?mkey={SENTINEL_LIST}"))
    geo_ok, geo_reason = BlockCountryTransport().preflight(
        client, {"policy": policy, "country": "Andorra"})
    geo_listed = _results(client.get(f"{_GEO}?mkey={SENTINEL_GEO_LIST}"))
    return {"policy": policy, "armed": ok, "reason": reason,
            "list_exists": isinstance(listed, dict) and bool(listed.get("name")),
            "list": SENTINEL_LIST,
            "geo_armed": geo_ok, "geo_reason": geo_reason,
            "geo_list_exists": isinstance(geo_listed, dict)
                               and bool(geo_listed.get("name")),
            "geo_list": SENTINEL_GEO_LIST}


def arm_geo_policy(client: FortiWebClient, policy: str, *,
                   block_period: int = 600) -> dict:
    """Create the Sentinel geo list and bind it to this policy's profile.

    Separate from :func:`arm_policy` on purpose. Arming address blocking and
    arming country blocking are different decisions with different blast radii,
    and one button that quietly did both would make the larger one a side
    effect of asking for the smaller.
    """
    steps: list = []

    def step(name, ok, detail):
        steps.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    existing = _results(client.get(f"{_GEO}?mkey={SENTINEL_GEO_LIST}"))
    if isinstance(existing, dict) and existing.get("name"):
        step("list", True, f"{SENTINEL_GEO_LIST} already exists")
    else:
        r = client.post(_GEO, {"data": {
            "name": SENTINEL_GEO_LIST, "action": "block-period",
            "block-period": int(block_period), "severity": "High"}})
        e = _err(r)
        if not step("list", not e, e or f"created {SENTINEL_GEO_LIST} "
                                        f"(device-side expiry {block_period}s)"):
            return {"ok": False, "steps": steps}

    pol = _results(client.get(f"{_POLICY}?mkey={policy}"))
    wpp = (pol or {}).get("web-protection-profile") if isinstance(pol, dict) else ""
    if not step("profile", bool(wpp),
                f"policy '{policy}' -> profile '{wpp}'" if wpp
                else f"policy '{policy}' has no web protection profile"):
        return {"ok": False, "steps": steps}

    r = client.put(f"{_WPP}?mkey={wpp}",
                   {"data": {"geo-block-list-policy": SENTINEL_GEO_LIST}})
    e = _err(r)
    if not step("bind", not e,
                e or f"profile '{wpp}'.geo-block-list-policy = {SENTINEL_GEO_LIST}"):
        return {"ok": False, "steps": steps}

    ok, reason = BlockCountryTransport().preflight(client, {"policy": policy,
                                                            "country": "Andorra"})
    step("verify", ok, reason)
    return {"ok": ok, "steps": steps}


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
