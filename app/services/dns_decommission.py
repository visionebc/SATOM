"""Hostname decommission — planned from the DNS & LB Lookup page.

The operator finds a name in *DNS Lookup*, sees which FortiWeb server policy or
FortiADC virtual server serves it, and retires the WHOLE service in one guarded
pass: the LB object and its exclusively-owned dependencies, the SNI member, the
certificate, the WAF profile, the WPP carve-outs, and the DNS records that
point at it.

What this module is NOT
----------------------
It is not a second delete engine. Every destructive step is executed by the
module that already owns it — ``policy_graph`` for the server-policy cascade,
``cert_manager.remove_device_certificate`` for a certificate,
``exception_lifecycle.on_server_policy_deleted`` for carve-outs,
``FortiWebOps.delete`` (which runs ``delete_guard``) for everything else. This
module decides only WHAT to hand them, in what ORDER, and refuses to hand them
anything the operator has not been shown first. A second author for "may this
object be deleted" is exactly how a shared object dies alongside a service that
merely happened to reference it.

Three rules the plan never breaks
---------------------------------
1. **Nothing is deleted that was not previewed.** :func:`apply` re-plans and
   compares :func:`fingerprint` against the one the operator confirmed. A
   mismatch is a REFUSAL with the new plan attached, not a "close enough" —
   between preview and confirmation another session may have bound the
   certificate to a second policy, and that binding is the whole question.
2. **Unverifiable means kept, never deleted.** A device read that fails leaves
   the object with ``action=keep`` and a reason that says so. The one thing an
   operator must never get is a plan that reads "certificate: delete" because
   the box was unreachable while we asked who else uses it.
3. **Self-references are discounted, foreign ones are not.** The policy being
   deleted is itself a holder of its certificate and its WAF profile; counting
   it would make every certificate look shared and nothing would ever be
   cleaned up. So the holders THIS plan removes are subtracted — and only
   those. Anything left standing keeps the object.

Warnings vs blockers
--------------------
A **warning** needs an explicit acknowledgement and then proceeds; a
**blocker** cannot be acknowledged away. The distinction is the operator's
right to decide with their eyes open: a certificate that also fronts other
names through an SNI policy, or an alias whose CNAME chain leaves this service,
is a judgement call. A device we could not interrogate is not a judgement call
at all — it never reaches the plan as a delete.

The FortiADC certificate chain
------------------------------
FortiADC does not bind a certificate to a virtual server. The chain is
``virtual server → client-SSL profile → local-cert group → certificate``
(live-verified shape in ``cert_adc._bindings``; the captured ``fadc`` config
confirms a virtual server carries ``client_ssl_profile`` and no
``ssl-certificate`` field at all). So the ADC leg plans the two intermediate
objects as well — each kept the moment anything else names it — and deletes
them in chain order, because ``remove_device_certificate`` re-runs its own
fail-closed binder check and would rightly refuse a certificate still held by
a group.
"""
from __future__ import annotations

import hashlib
import json
import re

# --------------------------------------------------------------------------- #
#  Vocabulary                                                                   #
# --------------------------------------------------------------------------- #

DELETE = "delete"
KEEP = "keep"
UNBIND = "unbind"          # a member/binding removed, its container survives

#: (key, title) in EXECUTION order. The UI renders the same order, so what the
#: operator reads top-to-bottom is what the box receives first-to-last.
STAGES: tuple[tuple[str, str], ...] = (
    ("dns", "DNS records"),
    ("policy", "Server Policy / Virtual Server"),
    ("sni", "SNI"),
    ("certificate", "Certificate"),
    ("wpp", "WAF Policy"),
    ("exceptions", "Carve-outs"),
)

# Warning codes — stable identifiers, so the UI, the audit line and the tests
# all name the same thing the plan does.
W_SNI_SHARED = "sni_shared"
W_CERT_MULTI_NAME = "cert_multi_name"
W_ALIAS_FOREIGN = "alias_foreign"
W_READ_FAILED = "read_failed"
W_NO_DNS_BACKEND = "no_dns_backend"

SERVER_POLICY_EP = "/api/v2.0/cmdb/server-policy/policy"
SNI_EP = "/api/v2.0/cmdb/system/certificate.sni"
SNI_MEMBERS_EP = SNI_EP + "/members"
WPP_EP = "/api/v2.0/cmdb/waf/web-protection-profile.inline-protection"
WPP_COLL = "waf/web-protection-profile.inline-protection"

# FortiADC logical endpoints (the client speaks logical names, not paths).
ADC_VS = "load_balance_virtual_server"
ADC_POOL = "load_balance_pool"
ADC_WAF = "security_waf_profile"
ADC_SSL_PROFILE = "load_balance_client_ssl_profile"
ADC_CERT_GROUP = "system_certificate_local_cert_group"
ADC_CERT_GROUP_MEMBERS = "system_certificate_local_cert_group_child_group_member"


def _item(stage: str, kind: str, label: str, action: str, reason: str = "",
          **extra) -> dict:
    row = {"stage": stage, "kind": kind, "label": label, "action": action,
           "reason": reason, "mkey": "", "sub_mkey": "", "endpoint": "",
           "holders": []}
    row.update(extra)
    return row


def _norm(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


def _covers(pattern: str, name: str) -> bool:
    """Does certificate/DNS name *pattern* cover *name*? Wildcard-aware.

    ``*.a.com`` covers ``x.a.com`` but NOT ``a.com`` nor ``y.x.a.com`` — one
    label, exactly, which is what TLS says and what an operator expects when
    the plan claims a certificate "covers" the name being retired.
    """
    p, n = _norm(pattern), _norm(name)
    if not p or not n:
        return False
    if p == n:
        return True
    if p.startswith("*."):
        rest = p[2:]
        return n.endswith("." + rest) and n[: -(len(rest) + 1)].count(".") == 0
    return False


def _warn(code: str, text: str, blocking: bool = False) -> dict:
    return {"code": code, "text": text, "blocking": bool(blocking)}


# --------------------------------------------------------------------------- #
#  Fingerprint                                                                  #
# --------------------------------------------------------------------------- #

def fingerprint(plan: dict) -> str:
    """A digest of everything the plan would CHANGE.

    Only destructive items feed it: an object that flips from ``keep`` to
    ``delete`` between preview and apply must invalidate the confirmation, and
    an object that stays kept for a differently-worded reason must not. Reasons
    and labels are deliberately excluded — they are prose, and re-wording a
    refusal would otherwise invalidate every confirmation in flight.
    """
    parts = []
    for it in plan.get("items", []):
        if it.get("action") in (DELETE, UNBIND):
            parts.append("|".join([
                str(it.get("stage") or ""), str(it.get("kind") or ""),
                str(it.get("action") or ""), str(it.get("mkey") or ""),
                str(it.get("sub_mkey") or ""), str(it.get("endpoint") or ""),
                str(it.get("backend_id") or ""),
            ]))
    parts.sort()
    blob = json.dumps({"target": plan.get("target", {}), "parts": parts},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
#  DNS stage                                                                    #
# --------------------------------------------------------------------------- #

def _dns_items(hostname: str, aliases: set, backends) -> tuple[list, list]:
    """Records to remove, plus warnings.

    A record is deleted when its name is the hostname itself or one of the
    aliases this service owns (SNI domains, certificate CN/SANs) AND, if it is
    a CNAME, it lands back inside that same set. A CNAME pointing SOMEWHERE
    ELSE is another service borrowing the name: it is kept, and it raises
    :data:`W_ALIAS_FOREIGN`, because deleting it would take out a service this
    plan never looked at.
    """
    items: list = []
    warnings: list = []
    host = _norm(hostname)
    targets = {a for a in ({host} | {_norm(x) for x in aliases}) if a}
    if not targets:
        return items, warnings
    if not backends:
        warnings.append(_warn(
            W_NO_DNS_BACKEND,
            "No DNS backend carries the DNS role, so no record can be removed "
            "here — the name will keep resolving after the service is gone."))
        return items, warnings

    for row in backends:
        try:
            prov = row.instance()
        except Exception as exc:  # noqa: BLE001 — one dead backend is not fatal
            warnings.append(_warn(
                W_READ_FAILED,
                "DNS backend %s could not be opened (%s); its records were NOT "
                "inspected." % (row.name, exc)))
            continue
        for alias in sorted(targets):
            try:
                records = prov.list_records(name=alias)
            except Exception as exc:  # noqa: BLE001 — ProviderError included
                warnings.append(_warn(
                    W_READ_FAILED,
                    "%s could not be read on backend %s (%s); its records were "
                    "left alone." % (alias, row.name, exc)))
                continue
            for rec in records or []:
                rname = _norm(getattr(rec, "name", ""))
                rtype = str(getattr(rec, "type", "") or "").upper()
                rvalue = _norm(getattr(rec, "value", ""))
                if rname not in targets:
                    # A provider that answers a prefix search with the whole
                    # zone must not turn into a zone wipe.
                    continue
                label = "%s %s → %s (%s)" % (rtype, getattr(rec, "name", ""),
                                             getattr(rec, "value", ""), row.name)
                if rtype == "CNAME" and rvalue and rvalue not in targets:
                    warnings.append(_warn(
                        W_ALIAS_FOREIGN,
                        "%s is a CNAME to %s, which is not part of this service "
                        "— kept." % (getattr(rec, "name", ""),
                                     getattr(rec, "value", ""))))
                    items.append(_item("dns", "record", label, KEEP,
                                       "points outside this service",
                                       mkey=str(getattr(rec, "id", "")),
                                       backend_id=row.id,
                                       record=rec.as_dict()))
                    continue
                items.append(_item("dns", "record", label, DELETE, "",
                                   mkey=str(getattr(rec, "id", "")),
                                   backend_id=row.id,
                                   record=rec.as_dict()))
    return items, warnings


# --------------------------------------------------------------------------- #
#  Shared helpers                                                               #
# --------------------------------------------------------------------------- #

def _cert_row(appliance_id: int, cert_name: str):
    from ..models import DeviceCertificate
    if not cert_name:
        return None
    return (DeviceCertificate.query
            .filter_by(appliance_id=appliance_id, name=cert_name).first())


def _cert_names(row) -> list[str]:
    """CN + SANs of a cached certificate row (``[]`` when it was never scanned)."""
    if row is None:
        return []
    out = [getattr(row, "cn", "") or ""]
    out += [s for s in (getattr(row, "sans", []) or [])]
    return [s for s in out if s]


def _uncovered(names, hostname: str) -> list[str]:
    """The certificate names this decommission does NOT account for."""
    return sorted({n for n in names
                   if not _covers(n, hostname) and _norm(n) != _norm(hostname)})


# --------------------------------------------------------------------------- #
#  FortiWeb planning                                                            #
# --------------------------------------------------------------------------- #

def _sni_members(client, sni_name: str) -> list[dict]:
    rows, _err = client.list_with_error(SNI_EP)
    for s in rows or []:
        if isinstance(s, dict) and str(s.get("name", "")) == sni_name:
            return [m for m in (s.get("members") or []) if isinstance(m, dict)]
    return []


def _is_self_binding(usage: dict, policy: str, sni_name: str,
                     removed_member_ids: set) -> bool:
    """Is this certificate binding one THIS plan removes?

    Only two shapes qualify: the policy being deleted, and an SNI member this
    plan already lists for removal. Everything else — another policy, the admin
    GUI, a member left in place — keeps the certificate.
    """
    kind = usage.get("kind")
    if kind == "server-policy":
        return str(usage.get("target") or "") == policy
    if kind == "sni":
        return (str(usage.get("target") or "") == sni_name
                and str(usage.get("sub_mkey") or "") in removed_member_ids)
    return False


def _holder_is(holder: str, policy: str) -> bool:
    """Does this ``q_ref_string`` line name *policy*?

    The lines look like ``inline-protection(wpp-full-lab)`` or
    ``url-rewrite-policy(urw-full) --> rule(1)``: the object's key is what sits
    inside the parentheses. A substring test against the whole line is WRONG
    and not subtly so — ``"pol" in "server-policy(other)"`` is True because the
    COLLECTION name contains it, so a WAF profile shared with an unrelated
    policy would read as "referenced only by this policy" and be deleted. Any
    policy whose name is a fragment of a FortiWeb collection name (``policy``,
    ``server``, ``rule``, ``pol``…) hits it. Caught by
    ``test_wpp_ignores_a_holder_that_merely_contains_the_name``.
    """
    inner = re.findall(r"\(([^()]*)\)", holder or "")
    return any(part.strip() == policy for part in inner)


def _wpp_item(client, wpp_name: str, policy: str) -> dict:
    """The WAF profile, decided by FortiWeb's own ``q_ref``.

    ``q_ref`` counts holders and sometimes names them. Both answers are usable
    and they are not the same answer: named holders are discounted against the
    policy we delete; an unnamed count is compared to 1, because we KNOW this
    policy is one of them. A firmware that reports no refcount at all, or a
    read that failed, keeps the profile — an unverified WAF profile deleted out
    from under a second policy is a silent hole in production traffic.
    """
    try:
        count, holders, status, err = client.cmdb_refcount(WPP_COLL, wpp_name)
    except Exception as exc:  # noqa: BLE001
        count, holders, status, err = 0, [], "error", str(exc)
    label = "WAF profile %s" % wpp_name
    if status == "unsupported":
        return _item("wpp", "wpp", label, KEEP,
                     "this firmware does not report who references it",
                     mkey=wpp_name, endpoint=WPP_EP)
    if status != "ok":
        return _item("wpp", "wpp", label, KEEP,
                     "the device did not answer who references it (%s)"
                     % (err or "no answer"), mkey=wpp_name, endpoint=WPP_EP)
    if holders:
        rest = [h for h in holders if not _holder_is(h, policy)]
        if rest:
            return _item("wpp", "wpp", label, KEEP, "still referenced",
                         mkey=wpp_name, endpoint=WPP_EP, holders=rest)
        return _item("wpp", "wpp", label, DELETE,
                     "referenced only by this policy", mkey=wpp_name,
                     endpoint=WPP_EP)
    if int(count or 0) > 1:
        return _item("wpp", "wpp", label, KEEP,
                     "referenced by %d objects, which the device does not name"
                     % count, mkey=wpp_name, endpoint=WPP_EP)
    return _item("wpp", "wpp", label, DELETE,
                 "referenced only by this policy", mkey=wpp_name, endpoint=WPP_EP)


def _plan_fortiweb(appliance, policy: str, hostname: str) -> dict:
    from . import clone as _clone
    from . import policy_graph as _pg
    from . import cert_manager as _cm
    from . import exception_lifecycle as _exc
    from ..clients.fortiweb import FortiWebClient

    items: list = []
    warnings: list = []
    aliases: set = set()

    client = FortiWebClient(appliance)
    reader = _clone.ClientReader(client)

    rows, err = client.list_with_error(SERVER_POLICY_EP)
    pol = next((r for r in (rows or []) if isinstance(r, dict)
                and str(r.get("name", "")) == policy), None)
    if pol is None:
        return {"error": "server policy %r was not readable on %s (%s)"
                         % (policy, getattr(appliance, "name", "device"),
                            err or "not found")}

    cert_name = str(pol.get("certificate") or "").strip()
    sni_name = str(pol.get("sni-certificate") or "").strip()
    wpp_name = str(pol.get("web-protection-profile") or "").strip()

    # -- 1. the cascade the clone/delete path already owns --------------------
    cascade = _pg.plan_cascade_delete(reader, policy)
    items.append(_item("policy", "server-policy", "Server policy %s" % policy,
                       DELETE, "", mkey=policy, endpoint=SERVER_POLICY_EP))
    for urn, mkey, label in cascade["to_delete"]:
        items.append(_item("policy", "dependency", "%s %s" % (label, mkey),
                           DELETE, "exclusively owned by this policy",
                           mkey=mkey, urn=urn))
    for urn, mkey, label, reason, shared in cascade["to_keep"]:
        # Certificates and the WPP subtree are always-skip for the cascade —
        # THIS module decides them, one stage further down. Listing them here
        # too would show the operator the same object twice with two verdicts.
        if urn.startswith("cmdb/system/certificate") or urn.startswith("cmdb/waf/"):
            continue
        items.append(_item("policy", "dependency", "%s %s" % (label, mkey),
                           KEEP, reason, mkey=mkey, urn=urn,
                           holders=list(shared or [])))

    # -- 2. SNI: member surgery; the container dies only when it empties -------
    removed_member_ids: set = set()
    if sni_name:
        members = _sni_members(client, sni_name)
        mine, others = [], []
        for m in members:
            dom = str(m.get("domain") or "")
            if dom:
                aliases.add(dom)
            (mine if _covers(dom, hostname) else others).append(m)
        for m in mine:
            removed_member_ids.add(str(m.get("id", "")))
            items.append(_item(
                "sni", "sni-member",
                "SNI %s — %s (%s)" % (sni_name, m.get("domain", ""),
                                      m.get("local-cert", "")),
                UNBIND, "the member that serves this hostname",
                mkey=sni_name, sub_mkey=str(m.get("id", "")),
                endpoint=SNI_MEMBERS_EP))
        if others:
            other_certs = sorted({str(m.get("local-cert") or "") for m in others
                                  if m.get("local-cert")})
            warnings.append(_warn(
                W_SNI_SHARED,
                "SNI policy %s still serves %d other domain(s) through %d "
                "certificate(s) (%s). The policy is KEPT; only the member for "
                "this hostname is removed."
                % (sni_name, len(others), len(other_certs),
                   ", ".join(other_certs) or "no local-cert")))
            items.append(_item(
                "sni", "sni-policy", "SNI policy %s" % sni_name, KEEP,
                "still holds %d other member(s)" % len(others), mkey=sni_name,
                endpoint=SNI_EP,
                holders=[str(m.get("domain") or "") for m in others]))
        elif members:
            items.append(_item("sni", "sni-policy", "SNI policy %s" % sni_name,
                               DELETE, "left with no members", mkey=sni_name,
                               endpoint=SNI_EP))

    # -- 3. certificate: fail closed, discount only what WE remove ------------
    if cert_name:
        row = _cert_row(getattr(appliance, "id", None), cert_name)
        store = getattr(row, "store", "") or "Local"
        names = _cert_names(row)
        aliases.update(names)
        complete, usage = _cm._enumerate_usage(client, appliance, cert_name)
        if not complete:
            items.append(_item(
                "certificate", "certificate", "Certificate %s" % cert_name, KEEP,
                "a binder read failed, so SATOM could not confirm nothing else "
                "uses it", mkey=cert_name, store=store))
            warnings.append(_warn(
                W_READ_FAILED,
                "Certificate %s was kept: a binding read on %s failed, so its "
                "other users could not be listed."
                % (cert_name, getattr(appliance, "name", "the device"))))
        else:
            remaining = [u for u in usage if not _is_self_binding(
                u, policy, sni_name, removed_member_ids)]
            if remaining:
                items.append(_item(
                    "certificate", "certificate", "Certificate %s" % cert_name,
                    KEEP, "still bound elsewhere", mkey=cert_name, store=store,
                    holders=[u.get("label", "") for u in remaining]))
            else:
                extra = _uncovered(names, hostname)
                if extra:
                    warnings.append(_warn(
                        W_CERT_MULTI_NAME,
                        "Certificate %s also covers %s. Nothing on this "
                        "appliance binds it any more, but any service that "
                        "expects to reuse it will lose it."
                        % (cert_name, ", ".join(extra))))
                items.append(_item(
                    "certificate", "certificate", "Certificate %s" % cert_name,
                    DELETE, "bound to nothing once this service is gone",
                    mkey=cert_name, store=store))

    # -- 4. WAF profile -------------------------------------------------------
    if wpp_name:
        items.append(_wpp_item(client, wpp_name, policy))

    # -- 5. carve-outs --------------------------------------------------------
    try:
        rep = _exc.on_server_policy_deleted(appliance.id, policy, apply=False)
    except Exception as exc:  # noqa: BLE001 — a DB preview never sinks the plan
        rep = None
        warnings.append(_warn(W_READ_FAILED,
                              "carve-out preview failed (%s)" % exc))
    for r in (rep or {}).get("to_delete", []):
        items.append(_item("exceptions", "carve-out",
                           "Carve-out #%s %s" % (r.get("id"), r.get("name") or ""),
                           DELETE, "bound to no other policy",
                           mkey=str(r.get("id") or "")))
    for r in (rep or {}).get("to_unbind", []):
        items.append(_item("exceptions", "carve-out",
                           "Carve-out #%s %s" % (r.get("id"), r.get("name") or ""),
                           UNBIND,
                           "still bound to %s" % ", ".join(r.get("remaining") or []),
                           mkey=str(r.get("id") or ""),
                           holders=list(r.get("remaining") or [])))

    return {"items": items, "warnings": warnings, "aliases": aliases}


# --------------------------------------------------------------------------- #
#  FortiADC planning                                                            #
# --------------------------------------------------------------------------- #

def _adc_rows(client, logical: str, **params) -> tuple[list, bool]:
    try:
        rows, err = client.list_with_error(logical, **params)
    except Exception:  # noqa: BLE001 — an unreadable table is an unknown holder
        return [], False
    if err:
        return [], False
    return [r for r in (rows or []) if isinstance(r, dict)], True


def _adc_key(row: dict) -> str:
    return str(row.get("mkey") or row.get("name") or "").strip()


def _adc_field(row: dict, *names) -> str:
    """First non-empty of several spellings — ADC payloads mix ``-`` and ``_``."""
    for n in names:
        v = str(row.get(n) or "").strip()
        if v:
            return v
    return ""


def _adc_ssl_chain(client, vs: dict, others: list, hostname: str,
                   appliance) -> tuple[list, set, list]:
    """virtual server → client-SSL profile → local-cert group → certificate.

    Each link is deleted only when nothing OUTSIDE this service names it, and
    the whole chain is abandoned (everything kept) the moment a read fails —
    an ADC has no ``q_ref`` to fall back on, so an unread table is an unknown
    holder, not an absent one.
    """
    items: list = []
    aliases: set = set()
    warnings: list = []

    prof_name = _adc_field(vs, "client_ssl_profile", "client-ssl-profile")
    if not prof_name:
        return items, aliases, warnings

    other_vs = [_adc_key(o) for o in others
                if _adc_field(o, "client_ssl_profile", "client-ssl-profile")
                == prof_name]
    profiles, ok_p = _adc_rows(client, ADC_SSL_PROFILE)
    if not ok_p:
        warnings.append(_warn(
            W_READ_FAILED,
            "the client-SSL profiles could not be read, so %s and everything "
            "below it were kept." % prof_name))
        items.append(_item("certificate", "ssl-profile",
                           "Client-SSL profile %s" % prof_name, KEEP,
                           "profile table unreadable", mkey=prof_name,
                           endpoint=ADC_SSL_PROFILE))
        return items, aliases, warnings

    prof = next((p for p in profiles if _adc_key(p) == prof_name), None)
    if other_vs:
        items.append(_item("certificate", "ssl-profile",
                           "Client-SSL profile %s" % prof_name, KEEP,
                           "used by %s" % ", ".join(other_vs), mkey=prof_name,
                           endpoint=ADC_SSL_PROFILE, holders=other_vs))
        return items, aliases, warnings
    items.append(_item("certificate", "ssl-profile",
                       "Client-SSL profile %s" % prof_name, DELETE,
                       "used only by this virtual server", mkey=prof_name,
                       endpoint=ADC_SSL_PROFILE))

    grp_name = _adc_field(prof or {}, "local_certificate_group",
                          "local-certificate-group")
    if not grp_name:
        return items, aliases, warnings

    other_profs = [_adc_key(p) for p in profiles
                   if _adc_key(p) != prof_name
                   and _adc_field(p, "local_certificate_group",
                                  "local-certificate-group") == grp_name]
    if other_profs:
        items.append(_item("certificate", "cert-group",
                           "Local-cert group %s" % grp_name, KEEP,
                           "used by %s" % ", ".join(other_profs), mkey=grp_name,
                           endpoint=ADC_CERT_GROUP, holders=other_profs))
        return items, aliases, warnings

    groups, ok_g = _adc_rows(client, ADC_CERT_GROUP)
    if not ok_g:
        warnings.append(_warn(
            W_READ_FAILED,
            "the local-cert groups could not be read, so %s and its "
            "certificates were kept." % grp_name))
        items.append(_item("certificate", "cert-group",
                           "Local-cert group %s" % grp_name, KEEP,
                           "group table unreadable", mkey=grp_name,
                           endpoint=ADC_CERT_GROUP))
        return items, aliases, warnings

    members, ok_m = _adc_rows(client, ADC_CERT_GROUP_MEMBERS, pkey=grp_name)
    if not ok_m:
        warnings.append(_warn(
            W_READ_FAILED,
            "the members of %s could not be read, so the group and its "
            "certificates were kept." % grp_name))
        items.append(_item("certificate", "cert-group",
                           "Local-cert group %s" % grp_name, KEEP,
                           "member list unreadable", mkey=grp_name,
                           endpoint=ADC_CERT_GROUP))
        return items, aliases, warnings

    items.append(_item("certificate", "cert-group",
                       "Local-cert group %s" % grp_name, DELETE,
                       "used only by this chain", mkey=grp_name,
                       endpoint=ADC_CERT_GROUP))

    # Which certificates does this group hold, and does any OTHER group hold
    # them too? A certificate in two groups is one another chain still serves.
    elsewhere: dict[str, list[str]] = {}
    for g in groups:
        gname = _adc_key(g)
        if not gname or gname == grp_name:
            continue
        gmembers, ok = _adc_rows(client, ADC_CERT_GROUP_MEMBERS, pkey=gname)
        if not ok:
            warnings.append(_warn(
                W_READ_FAILED,
                "group %s could not be read; certificates it may share were "
                "kept." % gname))
            elsewhere.setdefault("*", []).append(gname)
            continue
        for m in gmembers:
            c = _adc_field(m, "local_cert", "local-cert")
            if c:
                elsewhere.setdefault(c, []).append(gname)

    unreadable = elsewhere.pop("*", [])
    for m in members:
        cert = _adc_field(m, "local_cert", "local-cert")
        if not cert:
            continue
        row = _cert_row(getattr(appliance, "id", None), cert)
        store = getattr(row, "store", "") or "Local"
        names = _cert_names(row)
        aliases.update(names)
        holders = elsewhere.get(cert, [])
        if holders or unreadable:
            items.append(_item(
                "certificate", "certificate", "Certificate %s" % cert, KEEP,
                "also in %s" % ", ".join(holders) if holders
                else "a group that could not be read may hold it",
                mkey=cert, store=store, holders=holders or unreadable))
            continue
        extra = _uncovered(names, hostname)
        if extra:
            warnings.append(_warn(
                W_CERT_MULTI_NAME,
                "Certificate %s also covers %s." % (cert, ", ".join(extra))))
        items.append(_item("certificate", "certificate",
                           "Certificate %s" % cert, DELETE,
                           "bound to nothing once this chain is gone",
                           mkey=cert, store=store))
    return items, aliases, warnings


def _plan_fortiadc(appliance, vs_name: str, hostname: str) -> dict:
    """FortiADC has no ``q_ref``: sharing is decided by reading every virtual
    server once and tallying which pool / profile / chain they name."""
    from ..clients import client_for

    items: list = []
    warnings: list = []

    client = client_for(appliance)
    rows, ok = _adc_rows(client, ADC_VS)
    if not ok:
        return {"error": "the virtual servers on %s could not be read"
                         % getattr(appliance, "name", "device")}
    vs = next((r for r in rows if _adc_key(r) == vs_name), None)
    if vs is None:
        return {"error": "virtual server %r was not found on %s"
                         % (vs_name, getattr(appliance, "name", "device"))}
    others = [r for r in rows if _adc_key(r) != vs_name]

    items.append(_item("policy", "virtual-server", "Virtual server %s" % vs_name,
                       DELETE, "", mkey=vs_name, endpoint=ADC_VS))

    pool = _adc_field(vs, "pool")
    if pool:
        holders = [_adc_key(o) for o in others if _adc_field(o, "pool") == pool]
        items.append(_item(
            "policy", "pool", "Pool %s" % pool, KEEP if holders else DELETE,
            "used by %s" % ", ".join(holders) if holders
            else "used only by this virtual server",
            mkey=pool, endpoint=ADC_POOL, holders=holders))

    waf = _adc_field(vs, "waf-profile", "waf_profile")
    if waf:
        holders = [_adc_key(o) for o in others
                   if _adc_field(o, "waf-profile", "waf_profile") == waf]
        items.append(_item(
            "wpp", "wpp", "WAF profile %s" % waf, KEEP if holders else DELETE,
            "used by %s" % ", ".join(holders) if holders
            else "used only by this virtual server",
            mkey=waf, endpoint=ADC_WAF, holders=holders))

    ssl_items, aliases, ssl_warn = _adc_ssl_chain(client, vs, others, hostname,
                                                  appliance)
    items.extend(ssl_items)
    warnings.extend(ssl_warn)
    return {"items": items, "warnings": warnings, "aliases": aliases}


# --------------------------------------------------------------------------- #
#  Public API                                                                   #
# --------------------------------------------------------------------------- #

def plan(appliance, *, policy: str, hostname: str = "",
         include_dns: bool = True) -> dict:
    """The full decommission plan. Reads only — never touches a device."""
    kind = getattr(appliance, "kind", "fortiweb") or "fortiweb"
    policy = (policy or "").strip()
    hostname = _norm(hostname)
    if not policy:
        return {"ok": False, "error": "a policy / virtual server is required"}

    try:
        leg = (_plan_fortiadc(appliance, policy, hostname)
               if kind == "fortiadc" else
               _plan_fortiweb(appliance, policy, hostname))
    except Exception as exc:  # noqa: BLE001 — a failed plan is a refusal, not a 500
        return {"ok": False,
                "error": "could not build the plan on %s: %s"
                         % (getattr(appliance, "name", "device"), exc)}
    if leg.get("error"):
        return {"ok": False, "error": leg["error"]}

    items = list(leg["items"])
    warnings = list(leg["warnings"])

    if include_dns:
        from . import dns_providers
        aliases = set(leg.get("aliases") or set())
        if hostname:
            aliases.add(hostname)
        dns_items, dns_warn = _dns_items(
            hostname, aliases, dns_providers.enabled_backends("dns"))
        # DNS runs FIRST: the name must stop resolving before the VIP it points
        # at is freed. A record outliving its service is not cosmetic — the
        # address gets reused and the old name lands on a stranger.
        items = dns_items + items
        warnings = dns_warn + warnings

    order = {key: i for i, (key, _t) in enumerate(STAGES)}
    items.sort(key=lambda it: order.get(it["stage"], 99))

    out = {
        "ok": True,
        "target": {
            "appliance_id": getattr(appliance, "id", None),
            "appliance": getattr(appliance, "name", ""),
            "product": "FortiADC" if kind == "fortiadc" else "FortiWeb",
            "kind": kind,
            "policy": policy,
            "hostname": hostname,
        },
        "stages": [{"key": k, "title": t} for k, t in STAGES],
        "items": items,
        "warnings": warnings,
        "counts": {
            DELETE: sum(1 for i in items if i["action"] == DELETE),
            UNBIND: sum(1 for i in items if i["action"] == UNBIND),
            KEEP: sum(1 for i in items if i["action"] == KEEP),
        },
    }
    out["needs_acknowledge"] = bool(warnings)
    out["blocked"] = any(w.get("blocking") for w in warnings)
    out["fingerprint"] = fingerprint(out)
    return out


def apply(appliance, *, policy: str, hostname: str = "", include_dns: bool = True,
          confirm: str = "", acknowledge: bool = False, actor: str = "") -> dict:
    """Re-plan, verify the operator confirmed THIS plan, then execute it."""
    fresh = plan(appliance, policy=policy, hostname=hostname,
                 include_dns=include_dns)
    if not fresh.get("ok"):
        return fresh
    if not confirm:
        return {"ok": False, "code": 400, "plan": fresh,
                "error": "a confirmed plan fingerprint is required"}
    if confirm != fresh["fingerprint"]:
        return {"ok": False, "code": 409, "stale": True, "plan": fresh,
                "error": "the plan changed since you saw it — review it again "
                         "before confirming."}
    if fresh["blocked"]:
        return {"ok": False, "code": 409, "plan": fresh,
                "error": "this plan is blocked and cannot be acknowledged away."}
    if fresh["needs_acknowledge"] and not acknowledge:
        return {"ok": False, "code": 409, "plan": fresh, "needs_acknowledge": True,
                "error": "this plan carries warnings that need an explicit "
                         "acknowledgement."}
    return _execute(appliance, fresh, actor=actor)


def _execute(appliance, plan_dict: dict, *, actor: str = "") -> dict:
    from . import cert_manager as _cm
    from . import clone as _clone
    from . import dns_providers
    from . import exception_lifecycle as _exc
    from . import policy_graph as _pg
    from .fortiweb_ops import FortiWebOps

    kind = plan_dict["target"]["kind"]
    policy = plan_dict["target"]["policy"]
    results: list = []

    def _rec(it, ok, error=""):
        results.append({"stage": it["stage"], "kind": it["kind"],
                        "label": it["label"], "action": it["action"],
                        "ok": bool(ok), "error": str(error or "")})

    def _op(res):
        return (bool(getattr(res, "ok", False)),
                res.get("error", "") if hasattr(res, "get") else "")

    doing = [i for i in plan_dict["items"] if i["action"] in (DELETE, UNBIND)]
    stage = lambda key: [i for i in doing if i["stage"] == key]  # noqa: E731

    # ---- DNS --------------------------------------------------------------- #
    backends = {b.id: b for b in dns_providers.enabled_backends("dns")}
    for it in stage("dns"):
        row = backends.get(it.get("backend_id"))
        if row is None:
            _rec(it, False, "backend is gone or no longer carries the DNS role")
            continue
        try:
            rec = dns_providers.DnsRecord.from_form(it.get("record") or {})
            rec.id = str((it.get("record") or {}).get("id") or it.get("mkey") or "")
            row.instance().delete_record(rec)
            _rec(it, True)
        except Exception as exc:  # noqa: BLE001
            _rec(it, False, exc)

    adc_client = None
    if kind == "fortiadc":
        from ..clients import client_for
        adc_client = client_for(appliance)
        for it in stage("policy"):
            try:
                adc_client.delete(it["endpoint"], it["mkey"])
                _rec(it, True)
            except Exception as exc:  # noqa: BLE001
                _rec(it, False, exc)
    else:
        from ..clients.fortiweb import FortiWebClient
        ops = FortiWebOps(appliance)
        reader = _clone.ClientReader(FortiWebClient(appliance))
        cascade = _pg.execute_delete_plan(
            ops, _pg.plan_cascade_delete(reader, policy), dry_run=False)
        for r in cascade:
            results.append({
                "stage": "policy", "kind": "cascade",
                "label": "%s %s" % (r.get("label", ""), r.get("mkey", "")),
                "action": r.get("action", ""),
                "ok": bool(r.get("ok")), "error": r.get("error", "")})
        if not any(r.get("urn") == "cmdb/server-policy/policy" and r.get("ok")
                   for r in cascade):
            # The policy still holds every reference below it. Continuing would
            # ask the box to delete objects it is right to refuse, and would
            # report those refusals as failures of this run.
            return {"ok": False, "results": results, "summary": _summary(results),
                    "error": "the server policy did not delete — the rest of "
                             "the plan was not attempted."}
        for it in stage("sni"):
            res = (ops.delete(SNI_MEMBERS_EP, it["mkey"], sub_mkey=it["sub_mkey"],
                              dry_run=False)
                   if it["action"] == UNBIND
                   else ops.delete(SNI_EP, it["mkey"], dry_run=False))
            _rec(it, *_op(res))

    # ---- certificate chain (ADC: profile → group → cert; FortiWeb: cert) ---- #
    for it in stage("certificate"):
        if it["kind"] == "certificate":
            # remove_device_certificate re-runs its own fail-closed binder check.
            # That is the point: by this line the policy is gone, so the check
            # runs against the state that matters, not the one we previewed.
            res = _cm.remove_device_certificate(
                appliance, it.get("store") or "Local", it["mkey"],
                dry_run=False, actor=actor)
            _rec(it, res.get("ok") and res.get("removed"), res.get("error", ""))
        elif adc_client is not None:
            try:
                adc_client.delete(it["endpoint"], it["mkey"])
                _rec(it, True)
            except Exception as exc:  # noqa: BLE001
                _rec(it, False, exc)

    # ---- WAF profile ------------------------------------------------------- #
    for it in stage("wpp"):
        if adc_client is not None:
            try:
                adc_client.delete(it["endpoint"], it["mkey"])
                _rec(it, True)
            except Exception as exc:  # noqa: BLE001
                _rec(it, False, exc)
        else:
            _rec(it, *_op(FortiWebOps(appliance).delete(WPP_EP, it["mkey"],
                                                        dry_run=False)))

    # ---- carve-outs -------------------------------------------------------- #
    if stage("exceptions"):
        try:
            rep = _exc.on_server_policy_deleted(appliance.id, policy,
                                                author=actor, apply=True)
            results.append({"stage": "exceptions", "kind": "carve-out",
                            "label": rep.get("summary", ""), "action": DELETE,
                            "ok": True, "error": ""})
        except Exception as exc:  # noqa: BLE001
            results.append({"stage": "exceptions", "kind": "carve-out",
                            "label": "carve-out cascade", "action": DELETE,
                            "ok": False, "error": str(exc)})

    summary = _summary(results)
    return {"ok": summary["failed"] == 0, "results": results, "summary": summary,
            "error": "" if summary["failed"] == 0
                     else "%d step(s) failed" % summary["failed"]}


def _summary(results: list) -> dict:
    return {"total": len(results),
            "ok": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"])}


__all__ = ["plan", "apply", "fingerprint", "STAGES", "DELETE", "KEEP", "UNBIND",
           "W_SNI_SHARED", "W_CERT_MULTI_NAME", "W_ALIAS_FOREIGN",
           "W_READ_FAILED", "W_NO_DNS_BACKEND"]
