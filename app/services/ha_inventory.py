"""Device HA posture, derived from the harvest cache — not from hand entry.

Why this module exists
----------------------
``Appliance.ha_mode`` / ``ha_role_hint`` / ``ha_vip`` are written by exactly one
thing: the appliance form in ``views/appliances.py``. Nothing else populates
them. So the Monitoring redundancy panel — which read ``Appliance.members``
alone — printed *"No HA clusters registered"* on a fleet whose hourly harvest
had ``system_ha`` cached for **every** device. The panel was structurally
incapable of reporting HA for any box an operator had not typed in by hand.

Same defect class, same fix as ``interface_inventory`` (2026-07-20): the sweep
already fetched the truth, the view was reading the documentation table.

The evidence rule
-----------------
A device is reported as **clustered** only when there is *peer evidence* — a
heartbeat device, a group name, a peer address, a node list with more than one
entry. It is NOT inferred from the ``mode`` field alone, for a concrete reason:

FortiWeb and FortiADC return ``mode`` as a **string** (``"standalone"``), which
is unambiguous. FortiAnalyzer returns it as an **int** (``mode: 1`` observed on
faz01), and the enum could not be verified against a live device — faz01 has
been unreachable since 2026-07. Guessing that mapping would print "primary" for
a box that is standalone. So for FortiAnalyzer the label is derived from peer
evidence and the raw value is carried through verbatim as ``raw_mode`` for the
operator to see. Absence of a verified enum is reported as such, never as a
confident label.

A device with no cached ``system_ha`` at all is ``unknown`` — never
``standalone``. "We have not measured this" and "this box is standalone" are
different statements and the panel must not merge them (the 2026-07-28 Fleet
health badge lesson).

Read-only and DB-first: a page load never touches an appliance.
"""
from __future__ import annotations

#: Cached config object holding the HA block, per product.
_HA_OBJECT = {
    "fortiweb": "system_ha",
    "fortiadc": "system_ha",
    "fortianalyzer": "system_ha",
}

#: Products whose ``mode`` field is a trustworthy string.
_STRING_MODE = ("fortiweb", "fortiadc")

#: Products that expose NO HA config object at all, and WHY.
#:
#: Without this the page tells the operator "no HA data harvested yet — run a
#: device sync", which for these products is advice that can never work: the
#: sync is already succeeding and there is nothing to harvest. A wrong remedy
#: is worse than a blank, because the operator spends the run finding out.
_NO_HA_OBJECT = {
    "fortiauthenticator": (
        "FortiAuthenticator exposes no HA resource in /api/v1/ (all 58 "
        "resources censused 2026-08-05). Its only HA signal is "
        "systeminfo.ha_sn, and the config harvest excludes systeminfo as "
        "volatile — so HA presence is collected as the metric "
        "satom_fac_ha_peer instead of cached as config. The CLI "
        "`get system status` also carries a full HA block."),
}

STATUS_CLUSTERED = "clustered"
STATUS_STANDALONE = "standalone"
STATUS_UNKNOWN = "unknown"


def _payloads(appliance_id: int, logical: str) -> list[dict]:
    """Every cached payload for one logical object, newest layer first.

    The harvest projects one row per layer (``config`` and ``deep``), so the
    same object can be present more than once — dedup is the caller's problem
    everywhere else in this codebase and it is ours here.
    """
    from ..models_cache import DeviceObject
    rows = (DeviceObject.query
            .filter(DeviceObject.appliance_id == appliance_id,
                    DeviceObject.logical_name == logical)
            .order_by(DeviceObject.depth, DeviceObject.idx)
            .all())
    out = []
    for r in rows:
        p = getattr(r, "payload", None)
        if isinstance(p, dict):
            out.append(p)
    return out


def _s(payload: dict, *keys: str) -> str:
    """First non-empty string among ``keys`` (FortiOS spells things differently
    per product and per firmware; try them all rather than assume one)."""
    for k in keys:
        v = payload.get(k)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            v = " ".join(str(x) for x in v if x not in (None, ""))
        s = str(v).strip()
        if s and s not in ("0.0.0.0", "0.0.0.0/0", "::/0", "0"):
            return s
    return ""


def _peer_evidence(kind: str, p: dict) -> list[str]:
    """Concrete signs that this box is talking to a peer.

    Only these promote a device to ``clustered``. Each entry is a human-readable
    reason so the panel can say *why* — an unexplained status is a status the
    operator learns to ignore.
    """
    ev: list[str] = []
    hb = _s(p, "hbdev", "hb-interface", "hbdev_val", "datadev")
    if hb:
        ev.append("heartbeat on %s" % hb)
    grp = _s(p, "group-name", "group_name")
    if grp:
        ev.append("group %s" % grp)
    peer = _s(p, "peer", "peer-address", "peer_address")
    if peer:
        ev.append("peer %s" % peer)
    if kind == "fortiadc":
        nodes = [n for n in str(p.get("node-list", "") or "").split() if n]
        if len(nodes) > 1:
            ev.append("%d nodes in the HA node list" % len(nodes))
    if kind == "fortiweb":
        # system_ha_node rows are the per-member table; more than one configured
        # member (a member with a name/ip) is direct evidence.
        pass
    return ev


def posture(appliance) -> dict:
    """HA posture for one appliance, straight from the harvest cache.

    Returns a dict that is always safe to render::

        {'status': 'clustered'|'standalone'|'unknown',
         'mode': str,              # label, '' when not derivable
         'raw_mode': str,          # what the device literally returned
         'vip': str, 'group': str, 'priority': str,
         'evidence': [str, ...],   # why we said 'clustered'
         'source': 'cache'|'manual'|'none',
         'members': [{'name','role'}, ...]}
    """
    kind = (getattr(appliance, "kind", "") or "fortiweb").lower()
    out = {"status": STATUS_UNKNOWN, "mode": "", "raw_mode": "", "vip": "",
           "group": "", "priority": "", "evidence": [], "source": "none",
           "members": [], "reason": ""}

    # Manually registered cluster members always count as evidence: an operator
    # typed them, and that is a stronger statement than any harvest.
    try:
        members = list(getattr(appliance, "members", None) or [])
    except Exception:
        members = []
    if members:
        out["members"] = [{"name": m.name, "role": m.ha_role_hint or ""}
                          for m in members]
        out["status"] = STATUS_CLUSTERED
        out["source"] = "manual"
        out["mode"] = (getattr(appliance, "ha_mode", "") or "").strip()
        out["vip"] = (getattr(appliance, "ha_vip", "") or "").strip()
        out["evidence"] = ["%d member(s) registered in SATOM" % len(members)]

    logical = _HA_OBJECT.get(kind)
    if not logical and kind in _NO_HA_OBJECT:
        # Still ``unknown`` — never ``standalone``. We have not measured this
        # box's HA state, we have only established that this product cannot be
        # asked the way the others are.
        out["reason"] = _NO_HA_OBJECT[kind]
        return out
    payloads = _payloads(getattr(appliance, "id", 0) or 0, logical) if logical else []
    if not payloads:
        # No harvest. If the operator registered members we still report
        # clustered from that; otherwise we know nothing and say so.
        return out

    p = payloads[0]
    raw_mode = p.get("mode")
    out["raw_mode"] = "" if raw_mode is None else str(raw_mode)
    out["group"] = _s(p, "group-name", "group_name")
    out["vip"] = out["vip"] or _s(p, "vip", "eip-addr")
    out["priority"] = _s(p, "priority")
    evidence = _peer_evidence(kind, p)

    if kind in _STRING_MODE and isinstance(raw_mode, str):
        mode = raw_mode.strip().lower()
        out["mode"] = mode or out["mode"]
        if mode and mode != "standalone":
            evidence.insert(0, "device reports HA mode %s" % mode)
            out["status"] = STATUS_CLUSTERED
        elif not members:
            out["status"] = STATUS_STANDALONE
    else:
        # FortiAnalyzer (int enum, unverified) — evidence decides, and the raw
        # value is shown rather than translated into a label we cannot back up.
        if evidence:
            out["status"] = STATUS_CLUSTERED
            out["mode"] = "clustered"
        elif not members:
            out["status"] = STATUS_STANDALONE
            out["mode"] = "standalone (no peer configured)"

    if evidence:
        out["status"] = STATUS_CLUSTERED
        out["evidence"] = (out["evidence"] + evidence) if members else evidence
    out["source"] = "manual+cache" if members else "cache"
    return out


def manager_posture(summary: dict) -> dict:
    """SATOM's OWN HA posture, in the SAME vocabulary as the devices.

    Why this exists
    ---------------
    The v1.4.0 page split put a *device* HA counter on the SATOM health page —
    the page whose header promises "this installation". A reader who takes the
    page at its word sees ``0 clustered · 1 standalone`` and concludes SATOM is
    a single node, which on a two-node streaming pair is exactly backwards. The
    counter was right about the appliances and on the wrong page.

    So the device rows moved to Device health, and the manager states its own
    posture here with the same three statuses and the same evidence rule. A page
    about the installation must answer *"is this installation clustered?"* more
    loudly than it answers anything about the appliances.

    Evidence, not the mode string: ``mode`` is an admin-set switch, so a node
    left on ``standalone`` while a replica streams would otherwise be reported
    as single. A peer that is actually there outranks the switch that says it
    should not be.
    """
    out = {"status": STATUS_UNKNOWN, "mode": "", "role": "", "evidence": [],
           "note": (summary or {}).get("note", ""), "split_brain": False}
    if not isinstance(summary, dict) or not summary:
        return out

    try:
        instances = int(summary.get("instances") or 0)
    except (TypeError, ValueError):
        instances = 0
    admin_mode = str(summary.get("mode") or "").strip().lower()
    standby = bool(summary.get("standby"))
    streaming = bool(summary.get("streaming"))
    split = bool(summary.get("split_brain"))
    out["role"] = str(summary.get("this_role") or "").strip()
    out["split_brain"] = split

    evidence: list[str] = []
    if instances > 1:
        evidence.append("%d nodes registered" % instances)
    if standby:
        evidence.append("hot standby present")
    if streaming:
        evidence.append("streaming replication live")
    if split:
        evidence.append("SPLIT-BRAIN: more than one node reports primary")

    if evidence and not (instances <= 1 and not standby):
        out["status"] = STATUS_CLUSTERED
        out["mode"] = "clustered"
    elif instances >= 1:
        out["status"] = STATUS_STANDALONE
        out["mode"] = "standalone"
        if admin_mode == "standalone":
            evidence.append("standalone mode set by an administrator")
        else:
            evidence.append("no peer node registered")
    # instances == 0 and no evidence -> the probe itself failed: stay unknown
    # rather than claim a single node we never managed to count.
    out["evidence"] = evidence
    return out


def fleet(appliances) -> dict:
    """Roll the per-device posture up for the Monitoring redundancy panel.

    Retired placeholders (``host`` parked on the reserved ``.invalid`` TLD) are
    excluded outright — they name no real box, and counting them as "unknown"
    would keep the panel permanently amber for rows kept only for their history.
    Devices in maintenance ARE listed: parked is not gone.
    """
    devices, clusters = [], []
    counts = {STATUS_CLUSTERED: 0, STATUS_STANDALONE: 0, STATUS_UNKNOWN: 0}
    for a in appliances:
        host = (getattr(a, "host", "") or "")
        if host.endswith(".invalid"):
            continue
        st = posture(a)
        row = {
            "id": getattr(a, "id", None),
            "name": getattr(a, "name", ""),
            "kind": (getattr(a, "kind", "") or "fortiweb"),
            "maintenance": bool(getattr(a, "maintenance", False)),
            **st,
        }
        devices.append(row)
        counts[st["status"]] = counts.get(st["status"], 0) + 1
        if st["status"] == STATUS_CLUSTERED:
            clusters.append({"name": row["name"], "mode": st["mode"],
                             "vip": st["vip"], "members": st["members"],
                             "evidence": st["evidence"]})
    devices.sort(key=lambda r: (r["status"] != STATUS_CLUSTERED, r["name"]))
    return {"devices": devices, "clusters": clusters, "counts": counts}
