"""Registry reconciliation — close the loop between the sweep and the catalog.

The rediscovery sweep already GETs **every** enabled endpoint of a product
against a live appliance. Until now it threw that knowledge away: the snapshot
recorded the rows it got and an ``errors[]`` list that — because
``FortiWebClient._results_list`` flattens a device error envelope to ``[]`` —
was **empty on every snapshot ever written**, including the one taken from an
appliance that was answering ``errcode -20001`` for one of its endpoints. The
sweep was measuring the catalog and reporting nothing.

This module reads the per-endpoint ledger the sweep now writes
(``_config.json → endpoint_status``) across every live appliance of a product
and turns it into a **proposal**, never an action:

* ``proposals``  — the device says the path does not exist, on EVERY live
  appliance of the product. Candidate for the soft-delete the operator already
  has (``registry.toggle``) — **but read the firmware caveat below first.**
* ``divergent``  — absent on one appliance, served by another. That is a
  firmware/feature split, NOT a dead endpoint; proposing a disable here would
  break the catalog for the appliance that still serves it.
* ``partial``    — absent everywhere it was measured, but not measured
  everywhere. Reported with the names of the appliances that must be swept.
* ``unproven``   — in the sweep plan, enabled, and never measured anywhere.
* ``unsweepable``— enabled but NOT in the sweep plan at all, so no amount of
  sweeping will ever give it a verdict. Filing these under "never measured"
  would tell the operator to run a sweep that structurally cannot answer.
* ``verified``   — at least one appliance served it. Nothing to do.

Three rules hold the whole thing up:

1. **``absent`` and ``error`` are never collapsed.** ``absent`` (FortiWeb
   ``errcode -20001``/``-3``; FortiADC HTTP 404) is evidence about the CATALOG.
   ``error`` (transport, auth, licence, a lock) is evidence about the DEVICE.
   Verified live 2026-08-13: fortiweb08 answered ``-20010 "The license of peer
   VM FortiWeb is not valid."`` to *every* CMDB read while SATOM's inventory
   still called it ``online``. A reconciler that read non-200 as "gone" would
   have proposed deleting the entire 321-endpoint catalog from that one sick
   appliance.
2. **A ledger that is mostly errors is not evidence at all** (``MAX_ERROR_RATIO``)
   — same incident, one rule up: the individual verdicts are right and the
   device is still untrustworthy as a witness.
3. **Nothing is ever applied automatically, and ``apply_disable`` re-derives
   the proposal set server-side.** The POSTed names are a filter over what the
   evidence already justifies, never the authority for it — otherwise the
   reconcile form would be a way to disable any endpoint in the catalog.

**The firmware caveat, and it is the most important line in this file.**
Absence is a claim about a FIRMWARE, not about an endpoint. The catalog is a
deliberate cross-firmware superset — ``FortiWebClient._BENIGN_ERRCODES`` says so
outright — so on a fleet where every witness runs the same line, "absent
everywhere" means *"not in that line"*, not *"dead"*. The first real run proved
it: of the 38 endpoints both healthy 7.6.8 appliances rejected, several
(``waf/mcp-security.*``, ``ml-based-anomaly-detection``,
``system/captcha-puzzle``, ``certificate.eab-credentials``) are **8.0**
features. Disabling those would strip the catalog of exactly what the next
upgrade needs. Every proposal therefore carries the firmware lines that produced
it, and ``fleet_spans_one_firmware`` is set when the whole quorum runs a single
line — the page leads with that warning instead of with a delete button.

A disabled row is never swept (the plan is built from ENABLED endpoints), so
SATOM structurally cannot hold evidence for the reverse move. Re-enabling stays
the operator's manual toggle on the Explorer, and this page does not pretend
otherwise.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..extensions import db
from ..models import Appliance, RegistryEndpoint
from ..registry import loader
from .audit import log_action
from . import rediscovery

# Evidence older than this stops counting. A catalog verdict is a claim about a
# firmware that the appliance may since have been upgraded away from; without an
# expiry the page would keep proposing deletions from a measurement nobody
# remembers taking.
STALE_DAYS = 45

# Above this share of ``error`` verdicts the whole ledger is discarded (rule 2).
MAX_ERROR_RATIO = 0.25

VERDICT_OK = "ok"
VERDICT_ABSENT = "absent"
VERDICT_ERROR = "error"

# product -> Appliance.kind. Only these two have a sweep plan; FortiAnalyzer and
# FortiAuthenticator have a catalog but no sweep, so they have no evidence and
# are refused explicitly rather than silently reported as "nothing to do".
PRODUCT_KINDS = {"fortiweb": "fortiweb", "fortiadc": "fortiadc"}

SUPPORTED_PRODUCTS = tuple(PRODUCT_KINDS)


class UnsupportedProduct(ValueError):
    """Raised for a product the rediscovery sweep cannot measure."""


def _parse_ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except Exception:  # noqa: BLE001 — a malformed stamp is "unknown", not fatal
        return None


def _read_snapshot(appliance_id: int) -> dict | None:
    path = rediscovery._dev_dir(appliance_id) / "_config.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def witnesses(product: str):
    """The appliances whose sweep may be used as evidence for ``product``.

    Deliberately NOT "every directory under ``data/rediscovery/``": six of the
    twelve on the primary belong to appliances that were deleted from the
    inventory, and four more are the retired ``*.invalid`` hosts. Ghost
    snapshots forming a quorum is exactly how a reconciler talks itself into a
    deletion nobody can reproduce.
    """
    kind = PRODUCT_KINDS.get(product)
    if kind is None:
        raise UnsupportedProduct(product)
    return (Appliance.query
            .filter(Appliance.kind == kind, Appliance.maintenance.is_(False))
            .order_by(Appliance.name).all())


def device_ledger(appliance) -> dict[str, Any]:
    """One appliance's per-endpoint verdicts, plus whether they may be trusted."""
    out: dict[str, Any] = {
        "appliance_id": appliance.id,
        "device": appliance.name,
        "host": appliance.host,
        "firmware": "",
        "swept_at": None,
        "age_days": None,
        "counts": {VERDICT_OK: 0, VERDICT_ABSENT: 0, VERDICT_ERROR: 0},
        "endpoints": {},
        "trusted": False,
        "reason": "",
    }
    snap = _read_snapshot(appliance.id)
    if snap is None:
        out["reason"] = "never swept"
        return out

    swept = _parse_ts(snap.get("generated_at"))
    out["swept_at"] = snap.get("generated_at")
    # Recorded BY THE SWEEP, not by Appliance.firmware — the column was empty
    # for two of the three live FortiWebs, and an absence attributed to the
    # wrong line is worse than one attributed to none.
    out["firmware"] = str(snap.get("firmware") or "")
    if swept is not None:
        out["age_days"] = max(0, (datetime.utcnow() - swept).days)

    ledger = snap.get("endpoint_status")
    if not isinstance(ledger, dict) or not ledger:
        # Pre-ledger snapshot: it recorded rows, not verdicts, so "no rows" and
        # "the device refused the path" are indistinguishable in it. Refusing it
        # is the point — reading it optimistically is the original defect.
        out["reason"] = "legacy snapshot (no per-endpoint verdicts) — re-run the sweep"
        return out

    counts = {VERDICT_OK: 0, VERDICT_ABSENT: 0, VERDICT_ERROR: 0}
    clean: dict[str, dict] = {}
    for name, entry in ledger.items():
        if not isinstance(entry, dict):
            continue
        verdict = entry.get("verdict")
        if verdict not in counts:
            continue
        counts[verdict] += 1
        clean[name] = entry
    out["counts"] = counts
    out["endpoints"] = clean

    total = sum(counts.values())
    if total == 0:
        out["reason"] = "sweep measured no endpoints"
        return out
    if out["age_days"] is not None and out["age_days"] > STALE_DAYS:
        out["reason"] = f"sweep is {out['age_days']} days old (limit {STALE_DAYS})"
        return out
    ratio = counts[VERDICT_ERROR] / total
    if ratio > MAX_ERROR_RATIO:
        out["reason"] = (f"{counts[VERDICT_ERROR]}/{total} endpoints failed — "
                         f"device-wide failure, not evidence about the catalog")
        return out

    out["trusted"] = True
    return out


def _catalog(product: str) -> list[RegistryEndpoint]:
    return (RegistryEndpoint.query
            .filter_by(product=product, enabled=True)
            .order_by(RegistryEndpoint.name).all())


def plan_names(product: str) -> set[str]:
    """The endpoint names the sweep can actually measure for this product.

    The sweep is the object-LIST layer: a child table whose parent URN is itself
    an endpoint needs an ``mkey`` and is dropped from the plan (321 of 506
    enabled FortiWeb rows; 217 of 244 on FortiADC). Those 185/27 can never earn
    a verdict here, so they are reported as ``unsweepable`` rather than as
    "never measured" — the second wording tells the operator to run a sweep that
    structurally cannot answer, which is worse than saying nothing.
    """
    try:
        plan = (rediscovery.sweep_plan_adc() if product == "fortiadc"
                else rediscovery.sweep_plan())
    except Exception:  # noqa: BLE001 — a plan we cannot build measures nothing
        return set()
    return {e["name"] for e in plan}


def reconcile(product: str = "fortiweb") -> dict[str, Any]:
    """Group every enabled endpoint of ``product`` by what the fleet says of it."""
    if product not in PRODUCT_KINDS:
        raise UnsupportedProduct(product)

    devices = [device_ledger(a) for a in witnesses(product)]
    trusted = [d for d in devices if d["trusted"]]
    trusted_names = [d["device"] for d in trusted]

    buckets: dict[str, list] = {"proposals": [], "divergent": [], "partial": [],
                                "unproven": [], "unsweepable": [], "verified": []}
    sweepable = plan_names(product)

    for row in _catalog(product):
        evidence = []
        for d in trusted:
            entry = d["endpoints"].get(row.name)
            if entry is None:
                continue
            evidence.append({"device": d["device"], "verdict": entry.get("verdict"),
                             "rows": entry.get("rows"), "detail": entry.get("detail") or "",
                             "firmware": d["firmware"], "swept_at": d["swept_at"]})

        item = {"id": row.id, "name": row.name, "urn": row.urn,
                "evidence": evidence,
                "measured_by": [e["device"] for e in evidence],
                "missing_from": [n for n in trusted_names
                                 if n not in {e["device"] for e in evidence}]}

        if not evidence:
            if row.name not in sweepable:
                item["why"] = ("outside the sweep plan (sub-table needing an mkey) — "
                               "no sweep can give this a verdict")
                buckets["unsweepable"].append(item)
            else:
                item["why"] = ("no live appliance has measured this endpoint"
                               if trusted else "no appliance has a usable sweep")
                buckets["unproven"].append(item)
            continue

        verdicts = {e["verdict"] for e in evidence}
        if VERDICT_OK in verdicts and VERDICT_ABSENT in verdicts:
            item["why"] = "served by some appliances, absent on others — firmware split"
            buckets["divergent"].append(item)
        elif verdicts == {VERDICT_ABSENT}:
            if item["missing_from"]:
                item["why"] = ("absent everywhere it was measured, but not measured on "
                               + ", ".join(item["missing_from"]))
                buckets["partial"].append(item)
            else:
                lines = sorted({e["firmware"] for e in evidence if e["firmware"]})
                item["firmware_lines"] = lines
                item["why"] = ("every live appliance reports the path does not exist "
                               f"({len(evidence)}/{len(trusted)}"
                               + (f", firmware {', '.join(lines)}" if lines else "")
                               + ")")
                buckets["proposals"].append(item)
        elif VERDICT_OK in verdicts:
            buckets["verified"].append(item)
        else:
            # error-only evidence from a ledger that passed the ratio gate: the
            # endpoint failed while its neighbours answered. That is a real
            # signal, but it is not the signal "the catalog is wrong".
            item["why"] = "failed to answer where it was measured — not proof of absence"
            buckets["partial"].append(item)

    fleet_lines = sorted({d["firmware"] for d in trusted if d["firmware"]})
    return {
        "product": product,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
        "devices": devices,
        "trusted_devices": trusted_names,
        "fleet_firmware_lines": fleet_lines,
        # One line (or none) across the whole quorum means an "absent
        # everywhere" verdict cannot distinguish a dead endpoint from one that
        # simply belongs to another release. The page leads with this.
        "fleet_spans_one_firmware": len(fleet_lines) <= 1,
        "catalog_size": sum(len(v) for v in buckets.values()),
        "plan_size": len(sweepable),
        "stale_days": STALE_DAYS,
        "max_error_ratio": MAX_ERROR_RATIO,
        **buckets,
        "counts": {k: len(v) for k, v in buckets.items()},
    }


def proposal_names(product: str) -> set[str]:
    """The endpoint names the evidence currently justifies disabling."""
    return {p["name"] for p in reconcile(product)["proposals"]}


def apply_disable(product: str, names, actor: str = "") -> dict[str, Any]:
    """Soft-delete the approved endpoints — and ONLY those the evidence backs.

    ``names`` filters the server-derived proposal set; it never extends it. A
    name that is not currently proposed comes back in ``rejected`` with the
    reason, so an operator acting on a stale page sees why nothing happened
    instead of a silent success.
    """
    if product not in PRODUCT_KINDS:
        raise UnsupportedProduct(product)

    report = reconcile(product)
    by_name = {p["name"]: p for p in report["proposals"]}
    wanted = [n for n in dict.fromkeys(names or []) if n]

    applied, rejected = [], []
    for name in wanted:
        proposal = by_name.get(name)
        if proposal is None:
            rejected.append({"name": name,
                             "reason": "not in the current evidence-backed proposal set"})
            continue
        row = RegistryEndpoint.query.filter_by(
            product=product, name=name, enabled=True).first()
        if row is None:
            rejected.append({"name": name, "reason": "no enabled catalog row"})
            continue
        row.enabled = False
        if actor:
            row.updated_by = actor
        applied.append({"name": name, "urn": row.urn, "id": row.id,
                        "evidence": proposal["evidence"]})

    if applied:
        db.session.commit()
        loader.invalidate_cache()
        for item in applied:
            log_action("registry.reconcile_disable", target=item["name"],
                       extra={"product": product, "urn": item["urn"],
                              "witnesses": [e["device"] for e in item["evidence"]],
                              "verdict": VERDICT_ABSENT})
    if rejected:
        # A refusal is as auditable as a change: it is the trace of someone
        # trying to disable an endpoint the evidence did not justify.
        log_action("registry.reconcile_rejected", target=product,
                   extra={"rejected": rejected})

    return {"applied": applied, "rejected": rejected,
            "product": product, "proposals_left": len(by_name) - len(applied)}


__all__ = ["reconcile", "device_ledger", "witnesses", "apply_disable",
           "proposal_names", "plan_names", "UnsupportedProduct", "STALE_DAYS",
           "MAX_ERROR_RATIO", "SUPPORTED_PRODUCTS",
           "VERDICT_OK", "VERDICT_ABSENT", "VERDICT_ERROR"]
