"""Server-Policy action engine — enable/disable, delete, clone (same box),
clone-to-another and migrate-to-another FortiWeb, for the Workspace row + bulk
actions.

Every REAL action is auditable and reversible-aware:

  * per-object write goes through :class:`FortiWebOps` (before/after snapshot +
    ``ChangeHistory`` + audit, dry-run-capable, never raises on a dead device);
  * a whole-policy tree copy reuses the validated :mod:`services.clone` engine
    (deepest-first, skip-if-exists at the destination), so a clone/migrate never
    blindly overwrites an object that already lives on the target;
  * the caller (the route) wraps a real run in a background **job**
    (:mod:`services.jobs`) so the user gets live progress, a history entry and a
    bell notification — a fleet/policy write is never a silent fire-and-forget.

The per-policy functions take *duck-typed* ops/planner objects, so
``tests/test_policy_ops.py`` drives them with in-memory fakes (no Flask, no
device). ``start_policy_job`` is the only Flask/DB-aware entry point.

Design decisions (see PLAN):
  * **Migrate ≠ delete-source.** A migrate clones the policy tree onto the
    destination and, ONLY when that landed cleanly, disables the SOURCE policy
    (a built-in rollback — the source is kept, never deleted). A failed clone
    leaves the source untouched and live. Deleting a policy is a separate,
    explicit action.
  * **Clone/migrate leave the new root DISABLED** (``clone.disable_root``) so a
    freshly-copied policy can't take real traffic before a human cutover.
"""
from __future__ import annotations

from typing import Any, Callable

from . import clone

EP_POLICY = "/api/v2.0/cmdb/server-policy/policy"

# The 5 workspace actions (single + bulk share these keys).
ACTIONS = ("enable", "disable", "delete", "clone_here", "clone_to", "migrate_to")
_NEEDS_TARGET = ("clone_to", "migrate_to")   # a destination appliance
_NEEDS_NAME = ("clone_here",)                # a distinct name on the same box
_CLONE_ACTIONS = ("clone_here", "clone_to", "migrate_to")


# --------------------------------------------------------------------------- #
#  Per-policy primitives (duck-typed ops/planner — unit-tested with fakes)      #
# --------------------------------------------------------------------------- #
def set_status(ops, policy: str, *, enable: bool, dry_run: bool):
    """Enable/disable one Server Policy (a single ``status`` field write)."""
    status = "enable" if enable else "disable"
    return ops.update(EP_POLICY, policy, {"data": {"status": status}}, dry_run=dry_run)


def delete_policy(ops, policy: str, *, dry_run: bool):
    """Delete the Server Policy object itself. Shared building blocks it
    referenced (WPP, pool, cert, service…) are left in place — a policy delete
    is not a cascade (that is a separate, deliberate operation)."""
    return ops.delete(EP_POLICY, policy, dry_run=dry_run)


def _artifact_kind(item, artifacts: dict | None) -> str:
    """The artifact kind this plan item is, or ``""``.

    Sub-rows are excluded on purpose: a DTD's ``file-list`` child is ordinary
    configuration and must keep going through the normal cmdb write. Only the
    NAMED parent object is the one whose bytes live outside the config."""
    if not (artifacts or {}).get("enabled"):
        return ""
    if getattr(item, "kind", "") != "object":
        return ""
    from . import waf_artifacts as wa
    return wa.kind_for_urn(getattr(item, "urn", ""))


def _resolve_certificates(items, certs: dict | None, *, dry_run: bool):
    """Carry the certificate MATERIAL of every ``cert`` item over the CLI.

    Returns ``(rows, blocking)``. ``rows`` is one record per certificate the
    plan names; ``blocking`` is the subset the operator asked for and this could
    not deliver.

    WHY THIS RUNS BEFORE THE FIRST WRITE, like the artifact resolver above it:
    a certificate is a DEPENDENCY. An object that names one the destination
    lacks is refused with ``-651``, so discovering the failure through the write
    loop means the operator has already been committed to a partial apply — and
    on a MIGRATE it would mean discovering it after the source was disabled.

    WHY AN ALREADY-PRESENT NAME IS LEFT ALONE: overwriting a certificate the
    destination is already serving with is a change to live traffic that nobody
    asked for, and the two may legitimately differ (a per-site certificate
    issued locally). The copy names it and the destination has it; that is the
    whole requirement.

    A private key read here lives in :mod:`cert_carry` for the length of one
    transfer. Nothing about it reaches ``rows`` except whether it was found.
    """
    from . import clone as _clone
    rows: list[dict] = []
    if not certs or not certs.get("enabled"):
        return rows, []
    from . import cert_carry
    src_appl, dst_appl = certs.get("src_appliance"), certs.get("dst_appliance")
    wanted = [it for it in items
              if it.urn in _clone._CERT_URNS and it.kind == "object" and it.mkey]
    seen: set = set()
    present: dict = {}
    for it in wanted:
        key = (it.urn, it.mkey)
        if key in seen:
            continue
        seen.add(key)
        row = {"collection": it.urn, "name": it.mkey, "label": it.label,
               "action": "", "ok": False, "reason": ""}
        if src_appl is None or dst_appl is None:
            row.update(action="not carried",
                       reason="no source/destination appliance for a CLI transfer")
            rows.append(row)
            continue
        if src_appl.id == dst_appl.id:
            row.update(action="same device", ok=True,
                       reason="source and destination are the same appliance")
            rows.append(row)
            continue
        # Ask the destination ONCE per collection, not once per certificate.
        if it.urn not in present:
            try:
                present[it.urn] = set(cert_carry.names_at(dst_appl, it.urn))
            except Exception as exc:  # noqa: BLE001
                present[it.urn] = None
                row["reason"] = "could not list the destination's %s: %s" % (
                    it.urn.rsplit(".", 1)[-1], exc)
        have = present.get(it.urn)
        if have is not None and it.mkey in have:
            row.update(action="already at the destination", ok=True)
            rows.append(row)
            continue
        if dry_run:
            row.update(action="would carry", ok=True,
                       reason="dry run — nothing was read or written")
            rows.append(row)
            continue
        res = cert_carry.carry(src_appl, dst_appl, it.urn, it.mkey)
        row.update(action="carried" if res["carried"] else "not carried",
                   ok=bool(res["carried"]), reason=res["reason"])
        it.note = ("material carried over SSH" if res["carried"]
                   else "material NOT carried: %s" % (res["reason"] or "unknown"))
        it.result = row["action"]
        rows.append(row)
    return rows, [r for r in rows if not r["ok"]]


def _resolve_artifacts(items, artifacts: dict | None, *, dry_run: bool):
    """Fetch the bytes for every file-backed object the plan will create.

    Returns ``({(kind, mkey): blob}, [missing…])`` and REWRITES the status of
    every unresolvable item to ``no-content`` so ``apply_clone`` skips it.

    Skipping is the deliberate choice over creating the object anyway. The
    empty shell is not a smaller version of the artifact — it is an object that
    makes the destination LOOK configured while the validation it names is off,
    and the firmware only complains (``-7694``) if a rule is bound to it in the
    same apply. A skip instead fails the referencing rule with ``-651``, which
    is loud, and leaves a ``~`` in the plan text naming exactly what is absent.

    On a REAL apply this refuses outright unless the operator accepted the
    consequence; on a dry run it never refuses, because a preview that cannot
    be produced is a preview that cannot warn."""
    ctx = artifacts or {}
    blobs: dict[tuple[str, str], bytes] = {}
    missing: list[dict] = []
    if not ctx.get("enabled"):
        return blobs, missing
    from . import waf_artifacts as wa
    for it in items:
        kind = _artifact_kind(it, ctx)
        if not kind or it.status != "create":
            continue
        blob, origin, reason = wa.content_for(
            kind, it.mkey, src_client=ctx.get("src_client"),
            src_vdom=ctx.get("src_vdom", ""),
            source_appliance_id=ctx.get("source_appliance_id"),
            # Capture only on a real apply: a dry run must not mutate SATOM's
            # own state either.
            capture=(not dry_run), by=ctx.get("by", ""))
        empty = wa.is_empty(blob)
        if blob is None or empty:
            # An EMPTY stored copy takes the same exit as an absent one. It
            # used to take the other: `blob is None` was the whole test, so a
            # zero-byte (or whitespace-only) version resolved, was reported as
            # "will be copied WITH content", and was uploaded — producing at
            # the destination the exact empty object this branch exists to
            # refuse to create. The REASON stays distinct because the remedy
            # is: an absence is captured or uploaded, an emptiness is
            # re-authored.
            why = ("the copy SATOM holds is EMPTY (%d bytes)" % len(blob)
                   if empty else (reason or "SATOM holds no copy"))
            missing.append({"kind": kind, "label": wa.label(kind),
                            "name": it.mkey, "reason": why, "empty": empty})
            it.status = "no-content"
            it.note = ("content unavailable — %s. Skipped: creating the object "
                       "would leave an EMPTY %s at the destination."
                       % (why, wa.label(kind)))
        else:
            blobs[(kind, it.mkey)] = blob
            it.note = "content from %s (%d bytes)" % (origin, len(blob))
    if missing and not dry_run and not ctx.get("accept_missing"):
        names = ", ".join('%s "%s"' % (m["label"], m["name"]) for m in missing[:6])
        raise RuntimeError(
            "no content available for %d file-backed object(s): %s%s — either "
            "SATOM holds no copy (FortiWeb stores only their NAME) or the copy "
            "it holds is EMPTY, so the object would be created with nothing in "
            "it and the protection it enforces would be OFF at the destination. "
            "Upload them to the SATOM artifact library, or accept the alert to "
            "clone with those objects SKIPPED."
            % (len(missing), names, "…" if len(missing) > 6 else ""))
    return blobs, missing


def _push_artifact(ops, item, kind: str, blob: bytes, ctx: dict) -> None:
    """Create one file-backed object WITH its content, and audit it.

    The upload endpoint is not under ``/cmdb/`` and takes multipart, so it
    cannot go through ``FortiWebOps.create``; the audit row is written by hand
    rather than skipped, because "an object appeared on the device and nothing
    recorded it" is exactly the hole every other write path was built to close.
    """
    from . import waf_artifacts as wa
    from .audit import log_action
    ok, err = wa.push(ops.client, kind, item.mkey, blob,
                      vdom=str(ctx.get("dst_vdom") or ""))
    if not ok:
        raise RuntimeError("upload failed: %s" % err)
    try:
        log_action("artifact.push", "%s %s -> %s (%d bytes)"
                   % (wa.label(kind), item.mkey,
                      getattr(ops.appliance, "name", "?"), len(blob)))
    except Exception:  # noqa: BLE001 — the write landed; auditing must not undo it
        pass


def clone_policy(planner, ops, policy: str, *, new_name: str, dry_run: bool,
                 disable: bool = True, vip_ip: str = "", copy_wpp: bool = True,
                 wpp_new_name: str = "", wpp_suffix: str = "",
                 iface_map: dict[str, str] | None = None,
                 artifacts: dict | None = None,
                 reconcile_rows: bool = True,
                 dst_wpp: str = "",
                 wpp_only_if_missing: bool = False,
                 certs: dict | None = None,
                 wpp_decisions: dict | None = None) -> list[clone.CloneItem]:
    """Plan the full policy tree on the source and create the missing objects on
    the ``ops`` device (same box or another). The new root is left DISABLED.

    ``ops`` is where writes land: for a same-box clone it wraps the source
    device; for a cross-box clone/migrate it wraps the DESTINATION.

    * ``vip_ip`` — the address the copy's VIP comes up on: an explicit IPv4 (the
      single-policy dialog asked the operator) or ``"auto"`` (every bulk run —
      apply the admin dummy-IP rules to each VIP's own address). Empty keeps the
      source address (legacy behaviour).
    * ``copy_wpp=False`` prunes the Web Protection Profile subtree; the copy
      still names the profile, so the destination must already have it (the
      pre-flight checklist enforces that).
    * ``wpp_new_name`` copies the WPP under a NEW name and re-points the policy
      at it — the escape when the destination has a same-name profile whose
      values differ from the source.
    * ``iface_map`` — ``{source port: destination port}`` re-binding for the
      copy. A port NAME is not portable between chassis: ``port3`` exists on
      both boxes far more often than it means the same network on both, and
      the REST create SUCCEEDS either way. Without a map the source names are
      carried over verbatim (the pre-flight gate is what refuses that when the
      name is absent at the destination).
    * ``artifacts`` — context for the FILE-BACKED objects (XML Schema, DTD,
      WSDL, OpenAPI, gRPC IDL, JSON Schema, Lua scripting). Their content is
      not part of the configuration, so the generic ``create`` produces an
      object that exists and is EMPTY, and the rule bound to it answers
      ``-7694``. Keys: ``enabled``, ``src_client``, ``src_vdom``,
      ``source_appliance_id``, ``accept_missing``, ``by``. Absent/disabled
      keeps the legacy behaviour.
    * ``reconcile_rows`` — update, in place, the destination rows that already
      own a unique key this clone carries while serving different content.
      Turning it OFF does NOT skip those rows: it REFUSES the apply. A skipped
      row would leave the destination serving the old value under a green run,
      which is the failure the reconcile exists to end.
    * ``dst_wpp`` — the copy is pointed at a profile the DESTINATION already
      owns, under ITS name. For the case the destination has an equivalent
      profile under a DIFFERENT name; nothing of the source's profile is copied.
    * ``wpp_only_if_missing`` — create the profile when the destination lacks it
      and PRUNE the whole subtree when it already has one. Not the same as
      leaving the subtree on: an existing profile's object is already left
      alone, but its ~40 sub-tables are not, so today a clone can add a
      signature list to a live profile that other policies share.

    The three profile behaviours are mutually exclusive by construction and the
    refusals live in this function, not only in the caller: a second caller
    cannot forget what it never had to remember."""
    # Contradictory arguments are a fact about the CALL, so they are answered
    # FIRST — before any device read. Reaching a knowable refusal by way of a
    # round trip to an appliance is a round trip spent to learn nothing, and on
    # the bulk path it is one per policy.
    dst_wpp = (dst_wpp or "").strip()
    if dst_wpp and wpp_only_if_missing:
        raise RuntimeError(
            'cannot both reuse the destination profile "%s" and "create the '
            'profile only if it is missing" — the first copies no profile at '
            "all, so there is nothing for the second to decide about." % dst_wpp)
    if dst_wpp and (wpp_new_name or "").strip():
        raise RuntimeError(
            'cannot both reuse the destination profile "%s" and rename a copied '
            'one to "%s" — nothing would be copied for the rename to apply.'
            % (dst_wpp, wpp_new_name.strip()))
    wpp_reused = ""
    if dst_wpp:
        # The name must exist AT THE DESTINATION before anything is planned
        # around it. Left unchecked, the policy create answers -651 halfway
        # through a run that has already written pools, servers and certificates.
        try:
            have = clone.dst_wpp_names(planner.dst)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "could not read the destination's web protection profiles to "
                "confirm %r: %s" % (dst_wpp, exc)) from exc
        if dst_wpp not in have:
            raise RuntimeError(
                'the destination has no web protection profile named "%s" '
                "(it has: %s)" % (dst_wpp, ", ".join(sorted(have)[:8]) or "none"))
        copy_wpp = False        # nothing to follow — that IS the choice
    elif copy_wpp and wpp_only_if_missing:
        # Decided BEFORE the walk, not after: the ~40 sub-tables of a profile
        # are the slow half of a plan, and a decision taken afterwards would
        # have paid for every read it then throws away. It costs one extra GET
        # of the source policy (~13 ms measured on 7.6.8) plus one collection
        # read of the destination's profiles — against a walk that costs seconds.
        src_rows = planner.src.get_raw(clone.ROOT_SERVER_POLICY.urn, policy)
        landing = clone.wpp_landing_name(
            src_rows[0] if src_rows else {}, wpp_new_name)
        try:
            have = clone.dst_wpp_names(planner.dst)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "could not read the destination's web protection profiles, so "
                '"create the profile only if it is missing" cannot be honoured '
                "for %r: %s" % (policy, exc)) from exc
        wpp_reused = clone.wpp_reuse_name(landing, have, True)
        if wpp_reused:
            copy_wpp = False
    items = planner.plan(clone.ROOT_SERVER_POLICY, policy, new_name=new_name,
                         follow_wpp=copy_wpp, wpp_new_name=wpp_new_name,
                         wpp_suffix=wpp_suffix)
    if dst_wpp:
        clone.repoint_wpp(items, dst_wpp)
    # NEW, COMPARE AND DECIDE. Applied to the PLAN, before completeness, the VIP
    # rewrite and every gate below — an item the operator declined must not
    # exist by the time anything counts, renders or verifies it.
    if wpp_decisions:
        from . import wpp_decide
        # ``planner.dst`` goes IN, and the destination row is fetched inside —
        # by the same call that decides. Fetching it out here afterwards (as
        # this did until 1.12.0) is too late for the other thing that needs it:
        # a declined section has to be put back to the destination's own value
        # in every field that named it, and a revert with no destination
        # snapshot has nothing to revert TO.
        clone_decisions = wpp_decide.apply_decisions(
            items, wpp_decisions.get("accepted") or (),
            wpp_decisions.get("shown") or (), dst_reader=planner.dst)
        wpp_decisions["applied"] = clone_decisions
    if not dry_run:
        # HARD BLOCK: never write a partial tree. A referenced object that came
        # back empty from the source (renamed/deleted/unreadable) would leave the
        # copy dangling (-651 / empty pool). Refuse the real apply and name it.
        gaps = clone.validate_completeness(items)
        if gaps:
            names = ", ".join('%s "%s"' % (g["object"], g["mkey"]) for g in gaps[:6])
            raise RuntimeError(
                "source tree incomplete — refusing to clone with missing object(s): "
                + names + ("…" if len(gaps) > 6 else "")
                + ". Re-sync the source device and retry.")
    if disable:
        clone.disable_root(items)
    if vip_ip == "auto":
        from . import clone_rules
        cfg = clone_rules.config()
        clone.set_vip_ip(items, transform=lambda ip: clone_rules.dummy_ip(ip, cfg))
    elif vip_ip:
        clone.set_vip_ip(items, ip=vip_ip)
    # BEFORE the write, after the VIP rewrite. Both rewrites MERGE into the
    # payload ({**payload, field: value}) rather than replacing it, so the
    # order is not load-bearing TODAY — it becomes load-bearing the moment
    # either one is rewritten to build a fresh dict, which is why the
    # invariant is pinned by a test and not left to this comment.
    if iface_map:
        clone.set_interface(items, {str(k): str(v) for k, v in iface_map.items()
                                    if k and v and k != v})
    # File-backed objects. Resolved BEFORE the first write, not lazily inside
    # ``_write``: whether the copy can be complete is a property of the whole
    # plan, and discovering it halfway through means the operator has already
    # been committed to a partial apply by the time anyone can tell them.
    art_blobs, art_missing = _resolve_artifacts(items, artifacts, dry_run=dry_run)

    # Certificate MATERIAL, over the CLI, before the first write — see
    # :func:`_resolve_certificates` for why the order is the whole point.
    cert_rows, cert_blocking = _resolve_certificates(items, certs, dry_run=dry_run)
    if cert_blocking and not dry_run:
        raise RuntimeError(
            "certificate material could not be carried for %s. Every object "
            "that names one of these would be refused by the destination "
            "(-651), so nothing was written: %s"
            % (", ".join('"%s"' % r["name"] for r in cert_blocking[:6])
               + ("…" if len(cert_blocking) > 6 else ""),
               "; ".join(r["reason"] or "no reason given"
                         for r in cert_blocking[:3])))
    # Reported back through the caller's OWN context dict rather than a module
    # global. A global would be shared by every concurrent clone in the process,
    # so the moment anything runs two of these at once each would read the
    # other's certificates — and the report would be wrong in a way that looks
    # exactly like a correct one.
    if isinstance(certs, dict):
        certs["rows"] = cert_rows

    # Keyed collisions. The plan has ALREADY enumerated them (each one carries
    # the destination row and the field-by-field diff in its note), so this
    # block is only the operator's own choice coming back — and refusing is the
    # honest end: creating them is refused by the appliance, so the clone cannot
    # deliver them either way, and only the refusal says so.
    conflicts = [it for it in items if it.status == "update"]
    if conflicts and not reconcile_rows:
        names = "; ".join(
            "%s under %s" % (it.label, it.parent_mkey or "?") for it in conflicts[:6])
        if dry_run:
            for it in conflicts:
                it.status, it.note = "empty", (
                    "row reconciliation is OFF — the destination owns this key "
                    "and a real apply would be REFUSED (%s)" % it.note)
        else:
            raise RuntimeError(
                "%d destination row(s) already hold a unique key this clone "
                "carries, with different content, and row reconciliation is "
                "OFF: %s%s. Creating them is refused by the appliance (a "
                "duplicate error), so the clone cannot deliver them. Turn row "
                "reconciliation on, or fix those rows by hand."
                % (len(conflicts), names, "…" if len(conflicts) > 6 else ""))

    def _write(item: clone.CloneItem) -> None:
        from . import objform
        kind = _artifact_kind(item, artifacts)
        if kind:
            _push_artifact(ops, item, kind, art_blobs[(kind, item.mkey)],
                           artifacts or {})
            return
        ep = objform.rest_path(item.urn)
        mkey = item.parent_mkey if item.kind == "subrow" else None
        if item.status == "obj-update":
            # An OBJECT, so it is addressed by ``?mkey=`` and nothing else. Sent
            # through the sub-row branch below it would carry an empty
            # ``sub_mkey`` and address no row at all — a write that answers
            # cleanly and changes nothing.
            from . import wpp_decide
            body = wpp_decide.object_update_payload(item.payload, item.dst_row)
            res = ops.update(ep, item.mkey, {"data": body}, dry_run=False)
        elif item.status == "update":
            # PUT addressed by the DESTINATION row's id, carrying the source
            # fields MERGED onto the destination row. A bare source payload
            # would blank every destination field the source never named.
            if item.kind != "subrow" or not item.dst_row_key:
                # Not an internal slip: a destination row that carries no
                # addressable id cannot be reconciled AND cannot be created
                # (the appliance refuses the duplicate), so the clone cannot
                # deliver it either way. Naming the row is the only useful
                # thing left — a generic failure would send the operator
                # looking for a device fault that is not there.
                raise RuntimeError(
                    'the destination row that owns this key under "%s" has no '
                    "addressable row id, so it can be neither updated nor "
                    "created — fix it on the destination by hand"
                    % (item.parent_mkey or item.label))
            body = clone.subrow_update_payload(item.payload, item.dst_row, item.urn)
            # The id in the URL is the id IN THE BODY, read from the same place:
            # addressing one row and describing another is a silent cross-write,
            # and it would look like a successful reconcile.
            res = ops.update(ep, mkey, {"data": body}, dry_run=False,
                             sub_mkey=str(body.get("id") or item.dst_row_key))
        else:
            res = ops.create(ep, {"data": item.payload}, mkey=mkey, dry_run=False)
        if not res.ok:
            raise RuntimeError(res.get("error") or "write failed")

    clone.apply_clone(items, _write, dry_run=dry_run)
    if not dry_run:
        # Confirm against the destination what actually landed (read-only).
        try:
            clone.verify_created(items, planner.dst)
        except Exception:  # noqa: BLE001 — verification is advisory
            pass
    return items


def clone_summary(items: list[clone.CloneItem]) -> dict[str, int]:
    """Roll a planned/applied clone up to ``{created, exists, failed, skipped,
    total}`` for the job result + audit line."""
    updated = sum(1 for it in items if it.applied
                  and it.status in ("update", "obj-update"))
    # ``obj-update`` counts as a planned update. Measured on a real dry run
    # before this line existed: accepting a profile retune moved one item out of
    # ``exists`` and into NO counter at all — a plan that describes a write and
    # a summary that mentions it nowhere.
    created = sum(1 for it in items if it.applied) - updated
    failed = sum(1 for it in items if (it.result or "").startswith("error"))
    counts = clone.summarize(items)
    return {
        "created": created,
        # Its own number, never folded into ``created``: a reconciled row is an
        # EDIT of a row the destination already served, and an operator reading
        # only ``created`` would be told a row was made that was not.
        "updated": updated,
        "to_update": counts.get("update", 0) + counts.get("obj-update", 0),
        "failed": failed,
        "exists": counts.get("exists", 0),
        "skipped": counts.get("exists", 0) + counts.get("cert", 0)
        + counts.get("no-endpoint", 0) + counts.get("empty", 0)
        + counts.get("no-content", 0),
        # Broken out of ``skipped`` as its own number because every other thing
        # in that bucket is inert — an object already there, a cert that never
        # travels — while this one means the destination is missing protection
        # the source had. A caller that only reads ``skipped`` cannot tell.
        "no_content": counts.get("no-content", 0),
        # Same reasoning as ``no_content``, one class further out: this object
        # is not inert either. It EXISTS on the source and the API cannot carry
        # it, so the destination is left naming something it may not have. Left
        # inside ``skipped`` it would read as a thing the clone chose not to do.
        "no_rest": counts.get("no-rest", 0),
        "to_create": counts.get("create", 0),
        "total": len(items),
    }


def _failed_msg(report: dict) -> str:
    """A human error naming the objects that failed (not just a count) — the
    operator asked WHICH object broke, so the job error says so."""
    fails = report.get("failed") or []
    names = []
    for f in fails:
        lbl = f.get("label") or f.get("urn") or "?"
        mk = f.get("mkey")
        names.append("%s (%s)" % (lbl, mk) if mk else lbl)
    head = "%d object(s) failed" % len(fails)
    if names:
        head += ": " + ", ".join(names[:5])
        if len(names) > 5:
            head += " …(+%d)" % (len(names) - 5)
    return head


def migrate_policy(dst_planner, dst_ops, src_ops, policy: str, *,
                   new_name: str, dry_run: bool, vip_ip: str = "",
                   copy_wpp: bool = True, wpp_new_name: str = "",
                   wpp_suffix: str = "",
                   iface_map: dict[str, str] | None = None,
                   artifacts: dict | None = None,
                   reconcile_rows: bool = True, dst_wpp: str = "",
                   wpp_only_if_missing: bool = False,
                   certs: dict | None = None,
                   wpp_decisions: dict | None = None) -> dict:
    """Clone the policy tree onto the destination, then — ONLY on a clean clone
    and a real apply — disable the SOURCE policy (rollback-friendly; the source
    is kept). A failed clone leaves the source LIVE and untouched."""
    items = clone_policy(dst_planner, dst_ops, policy, new_name=new_name,
                         dry_run=dry_run, disable=True, vip_ip=vip_ip,
                         copy_wpp=copy_wpp, wpp_new_name=wpp_new_name,
                         wpp_suffix=wpp_suffix, iface_map=iface_map,
                         artifacts=artifacts, reconcile_rows=reconcile_rows,
                         dst_wpp=dst_wpp,
                         wpp_only_if_missing=wpp_only_if_missing, certs=certs,
                         wpp_decisions=wpp_decisions)
    summary = clone_summary(items)
    clone_ok = summary["failed"] == 0 and (dry_run or summary["created"] > 0
                                           or summary["updated"] > 0
                                           or summary["exists"] > 0)
    source_disabled = False
    # ACCEPTING a missing artifact authorises an incomplete COPY. It does not
    # authorise taking the original out of service: the destination now lacks a
    # schema/DTD/IDL the source enforces, so the two are not equivalent and
    # "migrate" would be claiming a swap that did not happen. The clone is kept
    # (nothing is rolled back) and the cutover becomes a deliberate manual step.
    # Note this is NOT covered by the failed==0 test above: the referencing rule
    # only fails when it is itself in the plan, and it is not when the
    # destination already has it.
    if summary.get("no_content") and clone_ok and not dry_run:
        return {
            "ok": True,
            "summary": summary,
            "items": items,
            "source_disabled": False,
            "source_kept_reason":
                "%d file-backed object(s) had no content and were skipped — the "
                "copy does not enforce what the source does, so the source was "
                "left ENABLED. Disable it by hand once the files are in place."
                % summary["no_content"],
        }
    if clone_ok and not dry_run:
        res = set_status(src_ops, policy, enable=False, dry_run=False)
        source_disabled = bool(getattr(res, "ok", False))
    return {
        "ok": bool(clone_ok),
        "summary": summary,
        "items": items,
        "source_disabled": source_disabled,
    }


# --------------------------------------------------------------------------- #
#  Flask/DB-aware orchestration (real objects; wrapped in a background job)      #
# --------------------------------------------------------------------------- #
def _ops(appliance):
    from .fortiweb_ops import FortiWebOps
    return FortiWebOps(appliance)


def _planner(src_appl, dst_appl):
    """A :class:`clone.ClonePlanner` reading the source device and validating
    against the destination (same object when it is the same box)."""
    from ..clients.fortiweb import FortiWebClient
    src_reader = clone.ClientReader(FortiWebClient(src_appl))
    dst_reader = (src_reader if dst_appl.id == src_appl.id
                  else clone.ClientReader(FortiWebClient(dst_appl)))
    return clone.ClonePlanner(src_reader, dst_reader)


def _artifact_ctx(source_appl, dest_appl, opts: dict) -> dict:
    """Everything :func:`clone_policy` needs to make a file-backed object real.

    The SOURCE client is built here (not reused from the planner) because it is
    used for a read the planner never makes: the private, non-``/cmdb/`` file
    endpoints. ``accept_missing`` comes from the operator's acknowledgement of
    the pre-flight alert and is re-read from ``opts`` on every apply — the
    checklist they saw could be minutes old, so the decision has to travel with
    the request rather than be remembered server-side."""
    from ..clients.fortiweb import FortiWebClient
    try:
        src_client = FortiWebClient(source_appl)
    except Exception:  # noqa: BLE001 — an unbuildable client is "cannot read"
        src_client = None
    return {
        "enabled": True,
        "src_client": src_client,
        "src_vdom": str(getattr(source_appl, "vdom", "") or ""),
        "dst_vdom": str(getattr(dest_appl or source_appl, "vdom", "") or ""),
        "source_appliance_id": getattr(source_appl, "id", None),
        "accept_missing": bool(opts.get("accept_missing_artifacts")),
        "by": str(opts.get("by") or ""),
    }


def probe_backends_after(dest_appl, policies, *, use_ssh: bool = False,
                         tcp_timeout: float = 3.0) -> dict:
    """Reachability of the policies' real servers, read back from ``dest_appl``.

    A clone can be perfect and still serve nothing, because the real servers sit
    on a network the NEW appliance cannot reach. That is a different question
    from "did the configuration arrive?", and it is answered from two vantages
    that are never merged: the destination appliance over ``execute ping`` (SSH,
    opt-in) and THIS node over TCP to the member's real port.

    NEVER raises and never contributes to the clone's own verdict. A backend
    that does not answer is a finding about the network, not a failed write, and
    letting it flip ``ok`` would make an operator roll back a copy that landed
    perfectly. On any failure the whole section reports ``not probed``, which is
    a third answer on purpose — folding "we could not tell" into either
    "reachable" or "down" is the exact mistake this module exists to avoid.
    """
    from . import backend_probe as _bp
    out = {"ran": False, "reason": "", "rows": [], "summary": {},
           "vantages": {"appliance": bool(use_ssh), "local": True}}
    if dest_appl is None:
        out["reason"] = "no destination appliance"
        return out
    try:
        from ..clients.fortiweb import FortiWebClient
        targets = _bp.dst_pool_targets(FortiWebClient(dest_appl), policies)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = "could not read the destination's pools: %s" % exc
        return out
    sess = None
    if use_ssh:
        try:
            from . import ssh_ops
            sess = ssh_ops.FortiWebReadonlySSH(dest_appl, timeout=20.0).connect()
        except Exception as exc:  # noqa: BLE001
            # The appliance vantage is lost, not the whole section: the local
            # TCP probe still distinguishes "port shut" from "host gone".
            sess = None
            out["vantages"]["appliance"] = False
            out["reason"] = "no SSH vantage: %s" % exc
    try:
        rows = _bp.probe_targets(targets, ssh_session=sess,
                                 tcp_timeout=tcp_timeout)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = "the probe failed: %s" % exc
        return out
    finally:
        if sess is not None:
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
    out["ran"] = True
    out["rows"] = rows
    out["summary"] = _bp.summarise(rows)
    return out


def _cert_ctx(source_appl, dest_appl, opts: dict) -> dict:
    """Context for carrying certificate MATERIAL over the CLI.

    OFF unless the operator asked. This is the one option in the dialog that
    moves a PRIVATE KEY: the clone's default posture is that key material is
    reported and never carried, and reversing that silently would be a change to
    what a run does that nobody chose.
    """
    return {"enabled": bool(opts.get("copy_cert_material")),
            "src_appliance": source_appl,
            "dst_appliance": dest_appl or source_appl,
            "rows": []}


def perform_one(action: str, *, source_appl, dest_appl=None, policy: str,
                new_name: str = "", dry_run: bool,
                opts: dict | None = None) -> dict:
    """Execute (or preview) ONE action against ONE policy with real appliances.

    ``opts`` carries the clone/migrate knobs from the dialog: ``vip_ip``
    (explicit IPv4 | ``"auto"`` | '' = keep), ``copy_wpp`` (bool),
    ``wpp_new_name`` (copy the WPP under a new name) and ``reconcile_rows``
    (update destination rows that collide on their unique key; ON by default —
    OFF makes a colliding run REFUSE rather than silently leave the destination
    serving the old value).

    Read ONCE here on purpose: the bulk job calls this same function per policy,
    so a knob threaded here is true of a 60-policy run and of a single-policy
    dialog at the same time. Two separate reads would be two defaults.

    Returns a normalised ``{policy, action, ok, error, detail}`` record; never
    raises (a device/logic failure is captured in ``ok``/``error``)."""
    opts = opts or {}
    vip_ip = str(opts.get("vip_ip") or "")
    copy_wpp = bool(opts.get("copy_wpp", True))
    wpp_new_name = str(opts.get("wpp_new_name") or "")
    wpp_suffix = str(opts.get("wpp_suffix") or "")
    reconcile_rows = bool(opts.get("reconcile_rows", True))
    # The two non-interactive profile policies. Read HERE, once, for the same
    # reason `reconcile_rows` is: the bulk job calls this function per policy.
    dst_wpp = str(opts.get("dst_wpp") or "")
    wpp_only_if_missing = bool(opts.get("wpp_only_if_missing", False))
    # Backend reachability. OFF by default, and not out of timidity: a bulk run
    # is N policies times their members times a connect timeout, all of it wall
    # clock the operator did not ask for, and the probe sends live traffic to
    # third-party hosts. ``probe_ssh`` is a second, narrower opt-in because only
    # it needs credentials on the destination.
    probe_backends = bool(opts.get("probe_backends", False))
    probe_ssh = bool(opts.get("probe_ssh", False))
    cert_ctx = _cert_ctx(source_appl, dest_appl, opts)
    # "New, compare and decide": the operator's answer to the comparison the
    # checklist showed. ``{"accepted": [key…], "shown": [key…]}``. Read HERE,
    # once, like every other knob — the bulk job calls this same function per
    # policy, so one read is true of a 60-policy run and of the dialog alike.
    wpp_decisions = opts.get("wpp_decisions") or None
    if wpp_decisions is not None and not isinstance(wpp_decisions, dict):
        wpp_decisions = None
    if wpp_decisions and (dst_wpp or wpp_only_if_missing):
        # Refused BEFORE any device is read: three profile policies that
        # contradict each other are a fact about the call, and resolving it by
        # talking to a box is a round trip per policy in a bulk run.
        rec = {"policy": policy, "action": action, "ok": False, "detail": {},
               "error": ("cannot compare-and-decide a profile while also "
                         "reusing the destination's or skipping an existing "
                         "one — the three are alternatives, not layers")}
        return rec
    # {source port: destination port}. Only cross-box actions can carry one —
    # a same-box clone shares the chassis, so a rewrite there would move the
    # copy to a different network than the original for no stated reason.
    iface_map = opts.get("iface_map") or {}
    if not isinstance(iface_map, dict):
        iface_map = {}
    art_ctx = _artifact_ctx(source_appl, dest_appl, opts)
    rec = {"policy": policy, "action": action, "ok": False, "error": "",
           "detail": {}}
    try:
        if action in ("enable", "disable"):
            res = set_status(_ops(source_appl), policy,
                             enable=(action == "enable"), dry_run=dry_run)
            rec["ok"] = bool(getattr(res, "ok", False))
            rec["error"] = res.get("error", "") if hasattr(res, "get") else ""
            rec["detail"] = {"request": res.get("request") if hasattr(res, "get") else None}
        elif action == "delete":
            from . import policy_graph as _pg
            from . import clone as _clone
            from ..clients.fortiweb import FortiWebClient
            reader = _clone.ClientReader(FortiWebClient(source_appl))
            plan = _pg.plan_cascade_delete(reader, policy)
            if dry_run:
                rec["ok"] = True
                rec["detail"] = {
                    "cascade_plan": {
                        "root": plan["root"],
                        "to_delete": [
                            {"urn": u, "mkey": m, "label": l}
                            for u, m, l in plan["to_delete"]
                        ],
                        "to_keep": [
                            {"urn": u, "mkey": m, "label": l, "reason": r,
                             "shared_with": sw}
                            for u, m, l, r, sw in plan["to_keep"]
                        ],
                        "by_parent_count": len(plan["by_parent"]),
                    },
                    "to_delete_count": len(plan["to_delete"]) + 1,
                    "to_keep_count": len(plan["to_keep"]),
                }
            else:
                cascade = _pg.execute_delete_plan(_ops(source_appl), plan, dry_run=False)
                root_r = next(
                    (r for r in cascade if r["urn"] == "cmdb/server-policy/policy"),
                    {}
                )
                rec["ok"] = bool(root_r.get("ok", False))
                rec["error"] = root_r.get("error", "") or ""
                deleted = [r for r in cascade if r.get("action") == "deleted"]
                kept = [r for r in cascade
                        if r.get("action") in ("kept", "kept_shared")]
                failed_items = [r for r in cascade if r.get("action") == "failed"]
                rec["detail"] = {
                    "cascade": cascade,
                    "deleted_count": len(deleted),
                    "kept_count": len(kept),
                    "failed_count": len(failed_items),
                }
                # Lifecycle hook: purge WPP carve-outs for this policy.
                if rec["ok"]:
                    try:
                        from . import wpp_exceptions as exc_store
                        purged = exc_store.delete_for_policy(source_appl.id, policy)
                        rec["detail"]["carveouts_purged"] = purged
                    except Exception:  # noqa: BLE001
                        rec["detail"]["carveouts_purged"] = None
        elif action == "clone_here":
            planner = _planner(source_appl, source_appl)
            items = clone_policy(planner, _ops(source_appl), policy,
                                 new_name=new_name, dry_run=dry_run,
                                 vip_ip=vip_ip, copy_wpp=copy_wpp,
                                 wpp_new_name=wpp_new_name, wpp_suffix=wpp_suffix,
                                 artifacts=art_ctx, reconcile_rows=reconcile_rows,
                                 dst_wpp=dst_wpp,
                                 wpp_only_if_missing=wpp_only_if_missing,
                                 certs=cert_ctx, wpp_decisions=wpp_decisions)
            summary = clone_summary(items)
            rec["ok"] = summary["failed"] == 0 and (
                dry_run or summary["created"] > 0 or summary["updated"] > 0)
            report = clone.outcome(items)
            rec["detail"] = {"summary": summary, "plan": clone.render_plan(items),
                             "new_name": new_name, "vip_ip": vip_ip,
                             "copy_wpp": copy_wpp, "wpp_new_name": wpp_new_name,
                             "clone": report,
                             "no_content": report["skipped_no_content"]}
            if summary["failed"]:
                rec["error"] = _failed_msg(report)
            elif not dry_run and summary["created"] == 0:
                rec["ok"], rec["error"] = False, 'nothing to create — "%s" exists' % new_name
            rec["detail"]["certificates"] = cert_ctx.get("rows") or []
            if probe_backends and not dry_run:
                rec["detail"]["backends"] = probe_backends_after(
                    source_appl, [new_name or policy], use_ssh=probe_ssh)
        elif action == "clone_to":
            planner = _planner(source_appl, dest_appl)
            items = clone_policy(planner, _ops(dest_appl), policy,
                                 new_name=new_name or policy, dry_run=dry_run,
                                 vip_ip=vip_ip, copy_wpp=copy_wpp,
                                 wpp_new_name=wpp_new_name, wpp_suffix=wpp_suffix,
                                 iface_map=iface_map, artifacts=art_ctx,
                                 reconcile_rows=reconcile_rows,
                                 dst_wpp=dst_wpp,
                                 wpp_only_if_missing=wpp_only_if_missing,
                                 certs=cert_ctx, wpp_decisions=wpp_decisions)
            summary = clone_summary(items)
            rec["ok"] = summary["failed"] == 0 and (dry_run or summary["created"] > 0
                                                    or summary["updated"] > 0
                                                    or summary["exists"] > 0)
            report = clone.outcome(items)
            rec["detail"] = {"summary": summary, "plan": clone.render_plan(items),
                             "dest": dest_appl.name, "new_name": new_name or policy,
                             "vip_ip": vip_ip, "copy_wpp": copy_wpp,
                             "wpp_new_name": wpp_new_name, "clone": report,
                             "iface_map": dict(iface_map),
                             "no_content": report["skipped_no_content"]}
            if summary["failed"]:
                rec["error"] = "%s on %s" % (_failed_msg(report), dest_appl.name)
            rec["detail"]["certificates"] = cert_ctx.get("rows") or []
            if probe_backends and not dry_run:
                rec["detail"]["backends"] = probe_backends_after(
                    dest_appl, [new_name or policy], use_ssh=probe_ssh)
        elif action == "migrate_to":
            planner = _planner(source_appl, dest_appl)
            out = migrate_policy(planner, _ops(dest_appl), _ops(source_appl),
                                 policy, new_name=new_name or policy, dry_run=dry_run,
                                 vip_ip=vip_ip, copy_wpp=copy_wpp,
                                 wpp_new_name=wpp_new_name, wpp_suffix=wpp_suffix,
                                 iface_map=iface_map, artifacts=art_ctx,
                                 reconcile_rows=reconcile_rows,
                                 dst_wpp=dst_wpp,
                                 wpp_only_if_missing=wpp_only_if_missing,
                                 certs=cert_ctx, wpp_decisions=wpp_decisions)
            rec["ok"] = out["ok"]
            report = clone.outcome(out["items"])
            rec["detail"] = {"summary": out["summary"],
                             "plan": clone.render_plan(out["items"]),
                             "dest": dest_appl.name, "new_name": new_name or policy,
                             "vip_ip": vip_ip, "copy_wpp": copy_wpp,
                             "wpp_new_name": wpp_new_name,
                             "source_disabled": out["source_disabled"],
                             "source_kept_reason": out.get("source_kept_reason", ""),
                             "clone": report,
                             "iface_map": dict(iface_map),
                             "no_content": report["skipped_no_content"]}
            if not out["ok"]:
                rec["error"] = ("%s — source left live" % _failed_msg(report)
                                if report["failed"] else "clone failed — source left live")
            rec["detail"]["certificates"] = cert_ctx.get("rows") or []
            if probe_backends and not dry_run:
                rec["detail"]["backends"] = probe_backends_after(
                    dest_appl, [new_name or policy], use_ssh=probe_ssh)
        else:
            rec["error"] = "unknown action %r" % action
    except Exception as exc:  # noqa: BLE001 — one policy's failure never sinks the run
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
    return rec


# --------------------------------------------------------------------------- #
#  Pre-flight checklist (clone/migrate dialog)                                   #
# --------------------------------------------------------------------------- #
def _live_lookup(reader, logical: str, mkey: str) -> dict:
    """One object off a live box via the reliable ``?mkey=`` read ({} on any
    failure — the caller decides the cache fallback)."""
    try:
        rows = reader.get_object(logical, mkey)
        return rows[0] if rows else {}
    except Exception:  # noqa: BLE001
        return {}


def _wpp_diff(src: dict, dst: dict) -> list[str]:
    """Field names whose values differ between two WPP payloads (both run
    through the same write-sanitizer, so volatile/read-only keys are gone)."""
    from .fortiweb_ops import sanitize_payload
    a, b = sanitize_payload(dict(src or {})), sanitize_payload(dict(dst or {}))
    keys = sorted(set(a) | set(b))
    return [k for k in keys if a.get(k) != b.get(k) and k != "name"]


def _same_chassis(a, b) -> bool:
    """Are two appliance ROWS the same physical device?

    Degrades to False on anything unresolvable: a false "same chassis" would
    put a warning on an ordinary cross-device migrate, and a warning that
    fires on the normal case is one operators learn to ignore."""
    try:
        from ..models import chassis_key
    except Exception:  # noqa: BLE001 — unit tests drive this with fakes
        return False
    ka, kb = chassis_key(a), chassis_key(b)
    return bool(ka) and ka == kb


def _live_interfaces(reader) -> list[dict] | None:
    """The destination's ``system/interface`` rows, or ``None`` when the device
    could not be read.

    ``None`` and ``[]`` mean opposite things and the caller branches on that:
    ``[]`` is a device that answered and has no ports (every binding is
    missing → block), ``None`` is a device that did not answer (nothing is
    known → warn). Returning ``[]`` for both is how an unreachable destination
    would masquerade as a definitively broken one."""
    try:
        rows, err = reader.client.list_with_error("/api/v2.0/cmdb/system/interface")
    except Exception:  # noqa: BLE001
        return None
    if err:
        return None
    return [r for r in (rows or []) if isinstance(r, dict)]


def _iface_name(row: dict) -> str:
    return str(row.get("name") or row.get("mkey") or "").strip()


def _documented_roles(appl) -> dict[str, dict]:
    """``{port name: {role, role_label, segment, ip}}`` from the OPERATOR's
    documentation (``ApplianceInterface``), not from the device.

    Resolved across the whole CHASSIS, not just this row. Ports are physical:
    verified live on fortiweb09, ``system/interface`` returns the identical
    four ports from all four of its ADOMs. Documentation is stored per ROW, so
    reading only ``appl.id`` reports every ADOM sibling as undeclared while the
    operator had already declared those exact ports on the chassis' first row
    — a warning produced by the data model, not by the network.

    The row's OWN entries win a name collision: a per-ADOM override is a
    deliberate statement and a sibling's value must not silently replace it.

    Empty dict when nothing was documented anywhere — an absent declaration is
    reported as such and never inferred from the live row, because the live row
    carries no purpose to infer from."""
    try:
        from ..models import (ApplianceInterface, interface_role_label,
                              chassis_siblings)
    except Exception:  # noqa: BLE001 — unit tests drive this with fakes
        return {}
    try:
        ids = [s.id for s in chassis_siblings(appl)] or [appl.id]
        # Own row LAST so its entries overwrite a sibling's on the same name.
        ids = [i for i in ids if i != appl.id] + [appl.id]
        order = {i: n for n, i in enumerate(ids)}
        rows = (ApplianceInterface.query
                .filter(ApplianceInterface.appliance_id.in_(ids)).all())
        rows.sort(key=lambda r: order.get(r.appliance_id, 0))
    except Exception:  # noqa: BLE001 — no app context / no table yet
        return {}
    out: dict[str, dict] = {}
    for r in rows:
        nm = (r.name or "").strip()
        if not nm:
            continue
        out[nm] = {"role": r.role or "unspecified",
                   "role_label": interface_role_label(r.role),
                   "segment": (r.segment or ""),
                   "ip": (r.ip_address or "")}
    return out


def _iface_gate(refs, *, cross_box, dest_name, dest_ifaces, src_roles, dst_roles,
                chosen: dict[str, str] | None = None):
    """Interface decision for the clone/migrate pre-flight.

    ``refs`` are the ``system/interface`` bindings the planned tree carries
    (``clone.interface_refs``). Returns ``(check, suggest)``.

    The rule this encodes: **a port name is not portable.** The REST create
    happily accepts ``interface: port3`` on the destination as long as a
    ``port3`` exists there, and it does on almost every FortiWeb — so the
    dangerous outcome is not the failed clone, it is the SUCCESSFUL one that
    lands the copy on the wrong network. Hence three distinct levels:

      * name absent at the destination      → **block**  (loud, recoverable)
      * name present, roles disagree        → **warn**   (silent risk, named)
      * name present, roles agree & declared→ **ok**

    A same-box clone shares the chassis, so the port means what it meant."""
    suggest: dict[str, Any] = {"interfaces": [], "dest_interfaces": []}
    wanted = sorted({str(r["interface"]) for r in refs})
    if dest_ifaces is not None:
        suggest["dest_interfaces"] = [
            {"name": _iface_name(row),
             "ip": str(row.get("ip") or "").split(" ")[0],
             "status": str(row.get("status") or ""),
             "role": (dst_roles.get(_iface_name(row)) or {}).get("role", "unspecified"),
             "role_label": (dst_roles.get(_iface_name(row)) or {}).get(
                 "role_label", "Not declared"),
             "segment": (dst_roles.get(_iface_name(row)) or {}).get("segment", "")}
            for row in dest_ifaces if _iface_name(row)
        ]
    # "nothing to check" is reported as such, never folded into the success
    # wording below. Both are level ok; only one of them is a measurement, and
    # a checklist that says "Interfaces resolve on fwb2" when it looked at zero
    # bindings is asserting something it never verified.
    if not wanted:
        return ({"key": "iface", "level": "ok",
                 "label": "No interface binding in the tree",
                 "detail": "nothing names a system/interface — the copy inherits "
                           "whatever the destination's VIP defaults to"}, suggest)

    chosen = chosen or {}
    # What each source port maps to at the destination (operator override, or
    # the same name carried over — which is what happens with no override).
    for name in wanted:
        target = (chosen.get(name) or "").strip() or name
        src_doc = src_roles.get(name) or {}
        dst_doc = dst_roles.get(target) or {}
        fields = sorted({r["field"] for r in refs if r["interface"] == name})
        suggest["interfaces"].append({
            "source": name, "target": target, "fields": fields,
            "source_role": src_doc.get("role", "unspecified"),
            "source_role_label": src_doc.get("role_label", "Not declared"),
            "source_segment": src_doc.get("segment", ""),
            "target_role": dst_doc.get("role", "unspecified"),
            "target_role_label": dst_doc.get("role_label", "Not declared"),
            "target_segment": dst_doc.get("segment", ""),
        })

    if not cross_box:
        return ({"key": "iface", "level": "ok",
                 "label": "Interfaces: same chassis",
                 "detail": "the copy keeps %s — a same-box clone cannot land on a "
                           "different network" % ", ".join(wanted)}, suggest)

    if dest_ifaces is None:
        return ({"key": "iface", "level": "warn",
                 "label": "Interfaces on %s could NOT be verified" % dest_name,
                 "detail": "the tree binds %s and the destination did not answer "
                           "system/interface — this is 'not measured', not 'fine'"
                           % ", ".join(wanted)}, suggest)

    present = {_iface_name(r) for r in dest_ifaces if _iface_name(r)}
    missing = [m["target"] for m in suggest["interfaces"] if m["target"] not in present]
    if missing:
        return ({"key": "iface", "level": "block",
                 "label": "Interface %s does not exist on %s"
                          % (", ".join(sorted(set(missing))), dest_name),
                 "detail": "the VIP/policy would be created bound to a port the "
                           "destination does not have. Pick an existing port below, "
                           "or create it on %s first. Present: %s"
                           % (dest_name, ", ".join(sorted(present)) or "(none)")},
                suggest)

    # Every name resolves. Now the part a name can never prove.
    undeclared, mismatched = [], []
    for m in suggest["interfaces"]:
        s_role, t_role = m["source_role"], m["target_role"]
        if s_role == "unspecified" or t_role == "unspecified":
            undeclared.append(m)
        elif s_role != t_role:
            mismatched.append(m)
    if mismatched:
        bits = ["%s (%s) → %s (%s)" % (m["source"], m["source_role_label"],
                                       m["target"], m["target_role_label"])
                for m in mismatched]
        return ({"key": "iface", "level": "warn",
                 "label": "Interface ROLE differs at %s" % dest_name,
                 "detail": "; ".join(bits) + " — the port exists and the clone will "
                           "succeed, but it is documented as carrying different "
                           "traffic. Verify before cutover."}, suggest)
    if undeclared:
        bits = ["%s → %s" % (m["source"], m["target"]) for m in undeclared]
        return ({"key": "iface", "level": "warn",
                 "label": "Interface exists on %s — purpose NOT declared" % dest_name,
                 "detail": "; ".join(bits) + " — a matching port NAME proves the "
                           "create will succeed, not that it is the same network. "
                           "Set the role on both devices (Appliances → Edit → "
                           "Interfaces) to turn this into a real check."}, suggest)
    same_seg = all((m["source_segment"] or "") == (m["target_segment"] or "")
                   or not (m["source_segment"] and m["target_segment"])
                   for m in suggest["interfaces"])
    bits = ["%s → %s (%s)" % (m["source"], m["target"], m["target_role_label"])
            for m in suggest["interfaces"]]
    if not same_seg:
        return ({"key": "iface", "level": "warn",
                 "label": "Interface roles match, SEGMENT differs",
                 "detail": "; ".join(
                     "%s on %s → %s on %s" % (m["source"], m["source_segment"],
                                              m["target"], m["target_segment"])
                     for m in suggest["interfaces"]
                     if (m["source_segment"] or "") != (m["target_segment"] or ""))},
                suggest)
    return ({"key": "iface", "level": "ok",
             "label": "Interfaces resolve on %s" % dest_name,
             "detail": "; ".join(bits)}, suggest)


def _artifact_gate(rows, *, dest_name, accepted: bool):
    """FILE-BACKED objects decision for the clone/migrate pre-flight.

    ``rows`` is :func:`waf_artifacts.resolve_for_plan` output. Returns
    ``(check, suggest)``.

    Never blocks — by explicit product decision, the operator is shown the
    consequence and chooses. What it must not do is understate it. The missing
    piece is not "a file": it is the schema/DTD/IDL a validation rule enforces,
    so a copy without it is a copy running with that protection OFF. The wording
    below says that, and the level stays ``warn`` after acceptance rather than
    flipping to ``ok`` — an accepted risk is still a risk, and a checklist that
    turns green when someone ticks a box has stopped describing the device."""
    suggest = {"artifacts": rows, "artifacts_need_ack": False}
    if not rows:
        return ({"key": "artifacts", "level": "ok",
                 "label": "No file-backed objects in the tree",
                 "detail": "nothing in this policy carries an uploaded schema, "
                           "DTD, WSDL, OpenAPI, gRPC IDL or Lua script"}, suggest)
    todo = [r for r in rows if r["status"] == "create"]
    if not todo:
        return ({"key": "artifacts", "level": "ok",
                 "label": "%d file-backed object(s) already on %s"
                          % (len(rows), dest_name),
                 "detail": "%s — not copied, and their content is whatever the "
                           "destination already holds (SATOM cannot read those "
                           "bytes back to compare)"
                           % ", ".join('%s "%s"' % (r["label"], r["name"]) for r in rows)},
                suggest)
    missing = [r for r in todo if not r["resolved"]]
    warned = [r for r in todo if r.get("name_warning")]
    if not missing:
        bits = ["%s \"%s\" (%s)" % (r["label"], r["name"], r["origin"]) for r in todo]
        chk = {"key": "artifacts", "level": "ok",
               "label": "%d file-backed object(s) will be copied WITH content"
                        % len(todo),
               "detail": "; ".join(bits)}
        if warned:
            chk = {"key": "artifacts", "level": "warn",
                   "label": "File content available — but a name looks wrong",
                   "detail": "; ".join(r["name_warning"] for r in warned)}
        return (chk, suggest)

    suggest["artifacts_need_ack"] = True
    suggest["artifacts_missing"] = missing
    bits = []
    for r in missing:
        # An empty copy is not "unreadable type" and not "no copy": saying
        # either sends the operator to capture a file they already have.
        why = ((r.get("reason") or "the copy SATOM holds is EMPTY")
               if r.get("empty") else
               ("FortiWeb has no read endpoint for this type — only a copy "
                "SATOM already holds can be supplied" if not r["readable"]
                else (r.get("reason") or "no content available")))
        bits.append('%s "%s": %s' % (r["label"], r["name"], why))
    head = ("ACCEPTED — %d file-backed object(s) will be SKIPPED"
            if accepted else
            "%d file-backed object(s) have NO CONTENT available")
    return ({"key": "artifacts", "level": "warn", "label": head % len(missing),
             "detail": "; ".join(bits)
                       + " — these cannot be cloned as configuration: either the "
                         "device stores only the NAME, or the copy SATOM holds "
                         "is empty. They will be SKIPPED (not "
                         "created empty: an empty object makes %s look configured "
                         "while the validation it names is off). The rule that "
                         "references one will fail with -651, and a migrate will "
                         "NOT disable the source. Fix it by uploading the file "
                         "under Artifacts, or accept and clone without it."
                         % dest_name},
            suggest)


def _source_gate(pol, src_name, *, live_ok, src_err, root_present, issues):
    """SOURCE decision for the clone/migrate pre-flight. HARD BLOCK, no soft
    warn, no cache fallback: a clone may only proceed when the source device
    answered LIVE and its whole dependency tree resolved. Returns one check dict
    whose level is exactly ``block`` or ``ok``."""
    if not live_ok:
        return {"key": "source", "level": "block",
                "label": "Source %s is not reachable" % src_name,
                "detail": "live sync required before cloning \u2014 %s. Nothing is "
                          "cloned from stale cache." % (src_err or "device did not answer")}
    if not root_present:
        return {"key": "source", "level": "block",
                "label": 'Source policy "%s" not found on %s' % (pol, src_name),
                "detail": "the device answered but returned no such policy"}
    if issues:
        names = ", ".join('%s "%s"' % (i["object"], i["mkey"]) for i in issues[:6])
        more = "\u2026" if len(issues) > 6 else ""
        return {"key": "source", "level": "block",
                "label": "Source tree is INCOMPLETE \u2014 %d missing object(s)" % len(issues),
                "detail": "%s%s \u2014 sync/repair the source before cloning "
                          "(these are referenced but did not resolve live)" % (names, more)}
    return {"key": "source", "level": "ok",
            "label": "Source tree synced live & complete",
            "detail": "validated on %s" % src_name}


def preflight(action: str, *, source_appl, dest_appl=None, policies: list[str],
              new_name: str = "", opts: dict | None = None) -> dict:
    """The clone/migrate PRE-FLIGHT CHECKLIST the dialog shows before anything
    is written. Read-only; every check degrades to a WARN (never a crash) when
    a device can't be read (the lab fleet's license flaps).

    Per policy: source present · destination reachable · target-name collision ·
    WPP present/identical/different at the destination (with the operator's
    choice when it differs) · VIP dummy-IP suggestion + address conflict ·
    certificate carry-over · INTERFACE bindings (present at the destination, and
    whether the documented role agrees) · capacity headroom."""
    from ..clients.fortiweb import FortiWebClient
    from . import clone_rules, read_layer
    opts = opts or {}
    cfg = clone_rules.config()
    cross_box = dest_appl is not None and dest_appl.id != source_appl.id
    dest = dest_appl if cross_box else source_appl
    copy_wpp = bool(opts.get("copy_wpp", cfg["copy_wpp_default"]))
    explicit_ip = str(opts.get("vip_ip") or "").strip()
    bulk = len(policies) > 1

    src_reader = clone.ClientReader(FortiWebClient(source_appl))
    dst_reader = (src_reader if not cross_box
                  else clone.ClientReader(FortiWebClient(dest)))
    planner = clone.ClonePlanner(src_reader, dst_reader)

    # Destination reachability + its VIP address inventory (one read, reused).
    dest_vips: list[dict] = []
    dest_live = True
    try:
        client = dst_reader.client
        rows, dev_err = client.list_with_error("/api/v2.0/cmdb/system/vip")
        if dev_err:
            dest_live = False
            dest_err = dev_err
        else:
            dest_vips = rows or []
            dest_err = ""
    except Exception as exc:  # noqa: BLE001
        dest_live, dest_err = False, str(exc)
    dest_vip_ips = {str(v.get("vip") or "").split("/")[0] for v in dest_vips}

    # Destination INTERFACE inventory — one read, reused by every policy.
    # ``dest_ifaces is None`` means "could not be read", which is NOT the same
    # as "the destination has no ports": the first must degrade to a warn, the
    # second is a hard block. Collapsing them into an empty list would turn an
    # unreadable device into a wall of false blocks.
    dest_ifaces = _live_interfaces(dst_reader)
    src_roles = _documented_roles(source_appl)
    dst_roles = _documented_roles(dest)

    def _dest_has(logical: str, mkey: str) -> dict | None:
        """Object at the destination — live first, cache fallback when the
        destination can't be read (None = 'could not verify')."""
        if not mkey:
            return {}
        if dest_live:
            return _live_lookup(dst_reader, logical, mkey)
        row = read_layer.object_by_mkey(dest.id, logical, mkey)
        if row is not None:
            return dict(row.payload or {})
        return None  # unverifiable: no live read, no cache row

    out_policies = []
    for pol in policies:
        checks: list[dict] = []
        suggest: dict[str, Any] = {}

        def add(key, level, label, detail=""):
            checks.append({"key": key, "level": level, "label": label,
                           "detail": detail})

        # 1) source tree — SYNCED LIVE + VALIDATED COMPLETE. Hard block: a
        #    clone off stale or partial data is forbidden (no cache fallback).
        try:
            _srows, src_err = src_reader.client.list_with_error(
                "/api/v2.0/cmdb/server-policy/policy")
        except Exception as exc:  # noqa: BLE001
            src_err = str(exc)
        live_ok = not src_err
        items: list = []
        root_item = None
        if live_ok:
            try:
                items = planner.collect(clone.ROOT_SERVER_POLICY, pol)
            except Exception as exc:  # noqa: BLE001
                live_ok, src_err = False, str(exc)
            else:
                root_item = next((it for it in items
                                  if it.depth == 0 and it.kind == "object"), None)
                # The pre-flight has just walked the SOURCE tree. That is
                # exactly the walk services.artifact_refs would run on a timer,
                # so donating it here is free freshness for the migration
                # coverage report — and it can never sink the checklist
                # (record_from_plan swallows and rolls back its own failures).
                from . import artifact_refs as _ar
                _ar.record_from_plan(source_appl.id, pol, items,
                                     refs=getattr(planner, "_refs", None))
        issues = clone.validate_completeness(items) if (live_ok and root_item) else []
        checks.append(_source_gate(
            pol, source_appl.name, live_ok=live_ok, src_err=src_err,
            root_present=bool(root_item and root_item.payload), issues=issues))
        policy_obj = dict(root_item.payload) if (root_item and root_item.payload) else {}
        # cached composite is used ONLY for the (non-blocking) VIP/WPP hints below.
        data, _cr, _meta = read_layer.policy_full_cached(source_appl.id, pol)
        # 1b) SAME CHASSIS, different ADOM. ``cross_box`` only means "a
        #     different appliance ROW", and on a multi-ADOM device that is not
        #     a different box. The distinction matters most for MIGRATE, whose
        #     whole promise is "the traffic now lands somewhere else": between
        #     two ADOMs of one chassis it lands on the same CPU, the same
        #     ports and the same failure domain, and the source is disabled
        #     anyway. Warn, never block — moving a policy between ADOMs of one
        #     box is a legitimate operation, just not the one the button's
        #     name implies.
        if cross_box and _same_chassis(source_appl, dest):
            add("chassis", "warn",
                "%s and %s are the SAME physical device (%s)"
                % (source_appl.name, dest.name, source_appl.host),
                "different ADOMs on one chassis — this %s does not move the "
                "policy off the hardware, and the capacity, ports and outage "
                "domain are shared. Verified live: interfaces and VIPs are "
                "identical across ADOMs; only policies are partitioned."
                % ("migration" if action == "migrate_to" else "clone"))
        # 2) destination reachability
        if cross_box:
            add("dest", "ok" if dest_live else "warn",
                "Destination %s" % dest.name,
                "reachable" if dest_live else
                "unreachable or license-locked (%s) — existence checks fall back to the local cache" % dest_err)
        # 3) target name collision
        target_name = _name_for(action, pol, new_name, policies)
        existing = _dest_has("server_policy", target_name)
        if existing:
            add("name", "block", 'Name "%s" already exists on %s' % (target_name, dest.name),
                "the clone would create nothing — pick a different name")
        elif existing is None:
            add("name", "warn", 'Name "%s" could not be verified' % target_name,
                "destination unreadable and no cached copy")
        else:
            add("name", "ok", 'Name "%s" is free on %s' % (target_name, dest.name))
        suggest["new_name"] = target_name
        # 4) WPP
        wpp_name = str(policy_obj.get("web-protection-profile") or "")
        suggest["wpp_name"] = wpp_name
        if not wpp_name:
            add("wpp", "ok", "No Web Protection Profile bound", "nothing to copy")
            suggest["wpp_status"] = "none"
        elif not cross_box:
            add("wpp", "ok", 'WPP "%s" — same box' % wpp_name,
                "the copy shares the existing profile" if not copy_wpp
                else "already present here; the planner will reuse it")
            suggest["wpp_status"] = "same"
        else:
            src_wpp = (data or {}).get("wpp") or _live_lookup(
                src_reader, "webprotection_profile_inline", wpp_name)
            dst_wpp = _dest_has("webprotection_profile_inline", wpp_name)
            if dst_wpp is None:
                add("wpp", "warn", 'WPP "%s" could not be verified on %s' % (wpp_name, dest.name),
                    "destination unreadable and no cached copy — the plan preview will tell")
                suggest["wpp_status"] = "unknown"
            elif not dst_wpp:
                if copy_wpp:
                    add("wpp", "ok", 'WPP "%s" missing on %s — will be created' % (wpp_name, dest.name))
                else:
                    add("wpp", "block", 'WPP "%s" is NOT on %s' % (wpp_name, dest.name),
                        "and 'Copy Web Protection Profile' is off — the copied policy would "
                        "reference a profile that does not exist. Enable the copy or create it first.")
                suggest["wpp_status"] = "missing"
            else:
                diff = _wpp_diff(src_wpp, dst_wpp) if src_wpp else []
                if not src_wpp:
                    add("wpp", "warn", 'WPP "%s" exists on %s — source values unknown' % (wpp_name, dest.name),
                        "no cached/live source profile to compare against")
                    suggest["wpp_status"] = "unknown"
                elif not diff:
                    add("wpp", "ok", 'WPP "%s" exists on %s and is IDENTICAL' % (wpp_name, dest.name),
                        "the destination profile will be reused as-is")
                    suggest["wpp_status"] = "same"
                else:
                    add("wpp", "choice", 'WPP "%s" exists on %s but DIFFERS' % (wpp_name, dest.name),
                        "differing fields: %s%s — choose below: keep the destination's profile "
                        "(values differ from the source) or copy the source profile under a new name."
                        % (", ".join(diff[:8]), "…" if len(diff) > 8 else ""))
                    suggest["wpp_status"] = "different"
                    suggest["wpp_diff_fields"] = diff[:20]
                    suggest["wpp_new_name"] = "%s-%s" % (wpp_name, source_appl.name)
        # 5) VIP / dummy IP
        vips = (data or {}).get("vips") or []
        src_ip = ""
        for v in vips:
            src_ip = str(v.get("effective_ip") or v.get("vip") or "").split("/")[0]
            if src_ip:
                break
        suggest["source_vip_ip"] = src_ip
        suggest["vip_ip"] = clone_rules.dummy_ip(src_ip, cfg) if (bulk or not explicit_ip) \
            else explicit_ip
        chosen_ip = explicit_ip if (explicit_ip and not bulk) else suggest["vip_ip"]
        if not src_ip and not vips:
            add("vip", "ok", "No VIP address in the cached tree",
                "policy may use the interface IP — no dummy rewrite will apply")
        elif chosen_ip in dest_vip_ips:
            add("vip", "warn", "IP %s is already used by a VIP on %s" % (chosen_ip, dest.name),
                "pick a different address or expect the existing VIP object to be reused")
        else:
            add("vip", "ok", "Copy comes up on %s" % chosen_ip,
                ("admin rule: %s" % clone_rules.rules_summary(cfg)) if (bulk or not explicit_ip)
                else "operator-provided address")
        # 6) certificates
        if cross_box and (policy_obj.get("certificate") or policy_obj.get("sni-certificate")
                          or policy_obj.get("ssl") == "enable"):
            add("certs", "warn", "Policy uses TLS certificates",
                "certificate key material can NOT move over REST — upload it on %s "
                "via SSH/Certificates before cutover" % dest.name)
        # 7) INTERFACE bindings — read off the PLANNED tree, not the cached
        #    composite: the cache describes the policy as it stands on the
        #    source, while the plan is what is about to be written (already
        #    renamed, already WPP-pruned). Checking the cache would validate a
        #    payload nobody is going to send.
        iface_chk, iface_suggest = _iface_gate(
            clone.interface_refs(items) if (live_ok and items) else [],
            cross_box=cross_box, dest_name=dest.name, dest_ifaces=dest_ifaces,
            src_roles=src_roles, dst_roles=dst_roles,
            chosen=(opts.get("iface_map") if isinstance(opts.get("iface_map"), dict)
                    else None))
        checks.append(iface_chk)
        suggest.update(iface_suggest)
        # 7b) FILE-BACKED objects — read off the PLANNED tree for the same
        #     reason as the interfaces above. This one costs a device read per
        #     artifact (the private file endpoints), which is why it runs on the
        #     plan's handful of objects and not on the whole cached composite.
        try:
            from . import waf_artifacts as _wa
            art_rows = _wa.resolve_for_plan(
                items if (live_ok and items) else [],
                src_client=src_reader.client,
                src_vdom=str(getattr(source_appl, "vdom", "") or ""),
                source_appliance_id=source_appl.id)
        except Exception as exc:  # noqa: BLE001 — a checklist never crashes
            art_rows = []
            add("artifacts", "warn", "File-backed objects could NOT be checked",
                "%s: %s — this is 'not measured', not 'fine'" % (type(exc).__name__, exc))
        else:
            art_chk, art_suggest = _artifact_gate(
                art_rows, dest_name=dest.name,
                accepted=bool(opts.get("accept_missing_artifacts")))
            checks.append(art_chk)
            suggest.update(art_suggest)
        # 8) capacity at the destination
        try:
            from . import capacity
            allowed, msg = capacity.check_headroom(dest, "server_policy", want=1)
            add("capacity", "ok" if allowed else "block", "Capacity on %s" % dest.name, msg)
        except Exception:  # noqa: BLE001 — capacity data is optional
            pass

        worst = "ok"
        for c in checks:
            if c["level"] == "block":
                worst = "block"
                break
            if c["level"] in ("warn", "choice") and worst == "ok":
                worst = "warn"
        out_policies.append({"policy": pol, "level": worst, "checks": checks,
                             "suggest": suggest})

    return {
        "policies": out_policies,
        "defaults": {"copy_wpp": cfg["copy_wpp_default"],
                     "rules_summary": clone_rules.rules_summary(cfg),
                     "fallback_ip": cfg["fallback_ip"]},
        "bulk": bulk,
    }


def wpp_compare(action: str, *, source_appl, dest_appl=None,
                policies: list[str], new_name: str = "",
                opts: dict | None = None) -> dict:
    """PHASE ONE of "new, compare and decide": what would change inside the
    destination's existing profile, per policy. Read-only.

    Runs synchronously inside the request, which is what makes the whole feature
    possible without a persisted plan: the operator answers, and the answer
    travels back in ``opts["wpp_decisions"]`` like every other knob. The apply
    RE-PLANS and matches the answer by stable KEYS, so nothing depends on the
    two plans being the same list.

    Returns ``{policy: {offers: [...], profile: name, error: str}}``.
    """
    from . import wpp_decide

    opts = dict(opts or {})
    opts.pop("wpp_decisions", None)   # phase one never applies a decision
    out: dict = {}
    for pol in policies:
        entry = {"offers": [], "profile": "", "error": ""}
        try:
            planner = _planner(source_appl, dest_appl or source_appl)
            items = planner.plan(clone.ROOT_SERVER_POLICY, pol,
                                 new_name=_name_for(action, pol, new_name,
                                                    policies),
                                 follow_wpp=True,
                                 wpp_new_name=str(opts.get("wpp_new_name") or ""),
                                 wpp_suffix=str(opts.get("wpp_suffix") or ""))
            wpp = next((it for it in items if it.urn in clone._WPP_URNS
                        and it.kind == "object"), None)
            entry["profile"] = wpp.mkey if wpp else ""
            entry["offers"] = wpp_decide.offers(items, planner.dst)
        except Exception as exc:  # noqa: BLE001 — one policy never sinks the set
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
        out[pol] = entry
    return out


def action_label(action: str) -> str:
    return {
        "enable": "Enable", "disable": "Disable", "delete": "Delete",
        "clone_here": "Clone (same box)", "clone_to": "Clone to another FortiWeb",
        "migrate_to": "Migrate to another FortiWeb",
    }.get(action, action)


#: The most concurrent readers a preview will open against one appliance.
#: The operator picks the number; this is the ceiling.
MAX_ANALYSE_WORKERS = 10

#: Where the appliance actually saturates. MEASURED on fortiweb12 (7.6.8) with
#: 40 identical GETs, not estimated:
#:
#:     workers   1      2      4      8     10     16
#:     seconds   3.85   1.90   1.61   1.61  1.56   1.54
#:
#: Two workers halve the time; beyond four there is nothing left to win. The
#: number is published so a UI can say so next to the box — offering "10"
#: without it reads as "ten times faster", which is the one thing it is not.
ANALYSE_SATURATION = 4


def analyse_workers(opts: dict | None) -> int:
    """How many readers a preview may run, clamped to [1, MAX].

    Defaults to 1, and 1 is not "a pool of one": the sequential path below
    returns before any pool is built. A pool of one is a different execution
    model wearing the old default's name.
    """
    try:
        want = int((opts or {}).get("analyse_workers") or 1)
    except (TypeError, ValueError):
        return 1
    return max(1, min(MAX_ANALYSE_WORKERS, want))


def preview(action: str, *, source_appl, dest_appl=None, policies: list[str],
            new_name: str = "", opts: dict | None = None) -> list[dict]:
    """Synchronous dry-run across the selected policies (read-only). For
    clone/migrate this reads the source device (and validates the destination)
    but writes nothing.

    ``opts["analyse_workers"]`` runs the policies concurrently. It is safe HERE
    and nowhere else in this module, because a preview is READS ONLY:

      * The apply path stays strictly sequential and MUST. Policies share
        objects — a profile, a certificate, a service — so two applies creating
        the same object at the same instant hand the loser a duplicate error
        that depends on the clock. A correct plan would report a failure that
        cannot be reproduced. :func:`start_policy_job` therefore never reads
        this option, and a test holds that.
      * Each :func:`perform_one` builds its OWN clients, so nothing is shared
        across threads except the appliance rows, which are re-read inside each
        worker's own application context.

    Results come back in the order the policies were GIVEN, never the order
    they finished. A list in completion order would silently re-label every row
    against the selection the operator is looking at.
    """
    workers = analyse_workers(opts)
    if workers <= 1 or len(policies) < 2:
        return [
            perform_one(action, source_appl=source_appl, dest_appl=dest_appl,
                        policy=p, new_name=_name_for(action, p, new_name, policies),
                        dry_run=True, opts=opts)
            for p in policies
        ]

    from concurrent.futures import ThreadPoolExecutor
    from flask import current_app

    app = current_app._get_current_object()
    src_id = source_appl.id
    dst_id = dest_appl.id if dest_appl is not None else None

    def _one(pol: str) -> dict:
        # A fresh app context and a fresh row per thread. Handing the caller's
        # ORM instances to another thread is how a lazy attribute read turns
        # into a session error halfway down a preview.
        with app.app_context():
            from ..models import Appliance
            from ..models import db as _db
            src = _db.session.get(Appliance, src_id)
            dst = _db.session.get(Appliance, dst_id) if dst_id else None
            try:
                return perform_one(
                    action, source_appl=src, dest_appl=dst, policy=pol,
                    new_name=_name_for(action, pol, new_name, policies),
                    dry_run=True, opts=opts)
            except Exception as exc:  # noqa: BLE001 — one policy never sinks the run
                return {"policy": pol, "action": action, "ok": False,
                        "error": "%s: %s" % (type(exc).__name__, exc),
                        "detail": {}}

    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="analyse") as pool:
        return list(pool.map(_one, policies))


def _name_for(action: str, policy: str, new_name: str, policies: list[str]) -> str:
    """The destination name for one policy. A same-box clone of ONE policy uses
    the given name; a bulk same-box clone suffixes each ('-copy') so names stay
    unique. Cross-box keeps the original name unless one was given."""
    if action == "clone_here":
        if len(policies) == 1 and new_name:
            return new_name
        return "%s-copy" % policy
    return new_name or policy


def wpp_dedup_key(planner_src, policy: str, wpp_new_name: str = "") -> tuple:
    """``(source profile, landing profile)`` for one policy, or ``()``.

    The pair — not the landing name alone. Two policies that land on the same
    destination NAME from DIFFERENT source profiles are not a repeat: the second
    walk would carry rows the first never had, and skipping it would silently
    drop them. That case is reachable today through ``wpp_new_name``.

    Costs ONE GET of the source policy (~13 ms measured on 7.6.8) against a
    profile walk that costs seconds.
    """
    try:
        rows = planner_src.get_raw(clone.ROOT_SERVER_POLICY.urn, policy)
    except Exception:  # noqa: BLE001 — an unreadable source is "cannot dedup"
        # Returning () here and falling through to an empty ``rows`` reach the
        # SAME verdict (no row -> no profile name -> no key), so a mutation that
        # swaps one for the other is inert rather than a gap. The early return
        # stays because it states the intent at the point where it is decided.
        return ()
    row = rows[0] if rows else {}
    src_wpp = str(row.get("web-protection-profile") or "").strip()
    if not src_wpp:
        return ()
    landing = clone.wpp_landing_name(row, wpp_new_name)
    return (src_wpp, str(landing or "").strip())


def dedup_opts(opts: dict, key: tuple, carried: set) -> dict:
    """The options for ONE policy of a bulk run, given what the run already did.

    A repeat of a profile already carried by THIS run gets
    ``wpp_only_if_missing`` — it REUSES that path rather than adding a second
    way to prune, so there is one tested implementation of "leave an existing
    profile alone" and not two that can disagree.

    Everything else is passed through UNCHANGED, and the caller's dict is never
    mutated: a job's options belong to the job, and editing them in place would
    make policy N's answer depend on policy N-1 for every knob, not just this
    one.
    """
    if not key or key not in (carried or ()):
        return opts
    return dict(opts, wpp_only_if_missing=True)


def start_policy_job(flask_app, *, action: str, source_appl, dest_appl=None,
                     policies: list[str], new_name: str = "", by: str,
                     user_id: int | None = None, opts: dict | None = None) -> dict:
    """Run a REAL policy action across ``policies`` as a background job.

    The job iterates policies, checks the Stop flag between each (never
    mid-write), calls :func:`perform_one` for real, and finishes with a summary
    the Job Manager shows. It writes ONE audit summary row and pushes a bell
    notification. Returns the created job dict (poll ``/jobs/<id>``)."""
    from . import jobs

    dest_id = dest_appl.id if dest_appl else None
    dest_name = dest_appl.name if dest_appl else ""
    src_id, src_name = source_appl.id, source_appl.name
    title = "%s — %d server polic%s on %s" % (
        action_label(action), len(policies),
        "y" if len(policies) == 1 else "ies", src_name)

    opts = dict(opts or {})
    job = jobs.create_job(
        "policy_action", title, by=by,
        meta={"action": action, "source_id": src_id, "source": src_name,
              "dest_id": dest_id, "dest": dest_name,
              "policies": list(policies), "new_name": new_name, "opts": opts},
        cancelable=True)

    def _worker(app, job_id):
        with app.app_context():
            from ..models import Appliance
            from .audit import log_action
            from . import notifications as notify
            src = Appliance.query.get(src_id)
            dst = Appliance.query.get(dest_id) if dest_id else None
            results = []
            total = len(policies)
            # PROFILES ONCE PER RUN. Several policies routinely share one Web
            # Protection Profile, and walking its ~40 sub-tables again for the
            # second policy is the slow half of a plan spent to reach the same
            # verdict — measured last round at 123 planned objects against 12.
            #
            # This lives in the BULK loop and nowhere else: it is the only thing
            # in the clone that is inherently CROSS-policy. Everything else the
            # dialog and the job share rides in ``opts``, read once by
            # ``perform_one``, so a knob threaded there is true of both.
            #
            # It REUSES ``wpp_only_if_missing`` rather than adding a second way
            # to prune. That path is already tested, already refuses its own
            # contradictions, and creates the profile when it is genuinely
            # absent — so a first policy that failed to carry it does not leave
            # the rest of the run quietly skipping it.
            carried_wpp: set = set()
            dedup_ok = bool(opts.get("copy_wpp", True)) and not opts.get("dst_wpp")
            for i, pol in enumerate(policies):
                jobs.checkpoint(job_id)   # cooperative Stop, between policies
                jobs.set_progress(job_id, int(i * 100 / max(1, total)),
                                  "%s — %s (%d/%d)" % (action_label(action), pol, i + 1, total))
                key = (wpp_dedup_key(_planner(src, dst or src).src, pol,
                                     str(opts.get("wpp_new_name") or ""))
                       if dedup_ok and action in _CLONE_ACTIONS else ())
                pol_opts = dedup_opts(opts, key, carried_wpp)
                rec = perform_one(
                    action, source_appl=src, dest_appl=dst, policy=pol,
                    new_name=_name_for(action, pol, new_name, policies),
                    dry_run=False, opts=pol_opts)
                if key and rec.get("ok"):
                    carried_wpp.add(key)
                results.append(rec)
                # Clear, per-object audit line for THIS policy.
                log_action(
                    "policy.%s" % action, target="%s/%s" % (src_name, pol),
                    detail="%s policy=%s dest=%s ok=%s %s" % (
                        action_label(action), pol, dest_name or "-", rec["ok"],
                        rec.get("error") or ""))
            ok = sum(1 for r in results if r["ok"])
            failed = total - ok
            summary = {"action": action, "label": action_label(action),
                       "source": src_name, "dest": dest_name,
                       "ok": ok, "failed": failed, "total": total,
                       "results": results}
            if action in _CLONE_ACTIONS:
                # Plain path (no url_for — this runs in a worker thread with no
                # request context); the app is mounted under /web. The toast +
                # Job Manager link straight to the reconciliation report.
                summary["report_url"] = "/web/workspace/clone-report/%s" % job_id
            log_action(
                "policy.%s.summary" % action, target=src_name,
                detail="by=%s %s policies=%s dest=%s ok=%d/%d" % (
                    by, action_label(action), policies, dest_name or "-", ok, total))
            if user_id:
                kind = notify.Notification.KIND_SUCCESS if failed == 0 else notify.Notification.KIND_ERROR
                notify.push(
                    user_id,
                    "%s: %d/%d server polic%s ok" % (
                        action_label(action), ok, total, "y" if total == 1 else "ies"),
                    kind=kind,
                    body=("on %s%s" % (src_name, (" → " + dest_name) if dest_name else ""))
                    + ("" if failed == 0 else " — %d failed" % failed))
            if failed:
                jobs.update_job(job_id, result=summary)
                jobs.finish_error(job_id, "%s completed with %d/%d failure(s)"
                                  % (action_label(action), failed, total))
            else:
                jobs.finish_success(job_id, result=summary,
                                    message="%s applied to %d/%d server polic%s"
                                    % (action_label(action), ok, total,
                                       "y" if total == 1 else "ies"))

    jobs.run_async(flask_app, job["id"], _worker)
    return job
