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


def clone_policy(planner, ops, policy: str, *, new_name: str, dry_run: bool,
                 disable: bool = True, vip_ip: str = "", copy_wpp: bool = True,
                 wpp_new_name: str = "", wpp_suffix: str = "") -> list[clone.CloneItem]:
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
      values differ from the source."""
    items = planner.plan(clone.ROOT_SERVER_POLICY, policy, new_name=new_name,
                         follow_wpp=copy_wpp, wpp_new_name=wpp_new_name,
                         wpp_suffix=wpp_suffix)
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

    def _write(item: clone.CloneItem) -> None:
        from . import objform
        ep = objform.rest_path(item.urn)
        mkey = item.parent_mkey if item.kind == "subrow" else None
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
    created = sum(1 for it in items if it.applied)
    failed = sum(1 for it in items if (it.result or "").startswith("error"))
    counts = clone.summarize(items)
    return {
        "created": created,
        "failed": failed,
        "exists": counts.get("exists", 0),
        "skipped": counts.get("exists", 0) + counts.get("cert", 0)
        + counts.get("no-endpoint", 0) + counts.get("empty", 0),
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
                   wpp_suffix: str = "") -> dict:
    """Clone the policy tree onto the destination, then — ONLY on a clean clone
    and a real apply — disable the SOURCE policy (rollback-friendly; the source
    is kept). A failed clone leaves the source LIVE and untouched."""
    items = clone_policy(dst_planner, dst_ops, policy, new_name=new_name,
                         dry_run=dry_run, disable=True, vip_ip=vip_ip,
                         copy_wpp=copy_wpp, wpp_new_name=wpp_new_name,
                         wpp_suffix=wpp_suffix)
    summary = clone_summary(items)
    clone_ok = summary["failed"] == 0 and (dry_run or summary["created"] > 0
                                           or summary["exists"] > 0)
    source_disabled = False
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


def perform_one(action: str, *, source_appl, dest_appl=None, policy: str,
                new_name: str = "", dry_run: bool,
                opts: dict | None = None) -> dict:
    """Execute (or preview) ONE action against ONE policy with real appliances.

    ``opts`` carries the clone/migrate knobs from the dialog: ``vip_ip``
    (explicit IPv4 | ``"auto"`` | '' = keep), ``copy_wpp`` (bool) and
    ``wpp_new_name`` (copy the WPP under a new name).

    Returns a normalised ``{policy, action, ok, error, detail}`` record; never
    raises (a device/logic failure is captured in ``ok``/``error``)."""
    opts = opts or {}
    vip_ip = str(opts.get("vip_ip") or "")
    copy_wpp = bool(opts.get("copy_wpp", True))
    wpp_new_name = str(opts.get("wpp_new_name") or "")
    wpp_suffix = str(opts.get("wpp_suffix") or "")
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
                                 wpp_new_name=wpp_new_name, wpp_suffix=wpp_suffix)
            summary = clone_summary(items)
            rec["ok"] = summary["failed"] == 0 and (dry_run or summary["created"] > 0)
            report = clone.outcome(items)
            rec["detail"] = {"summary": summary, "plan": clone.render_plan(items),
                             "new_name": new_name, "vip_ip": vip_ip,
                             "copy_wpp": copy_wpp, "wpp_new_name": wpp_new_name,
                             "clone": report}
            if summary["failed"]:
                rec["error"] = _failed_msg(report)
            elif not dry_run and summary["created"] == 0:
                rec["ok"], rec["error"] = False, 'nothing to create — "%s" exists' % new_name
        elif action == "clone_to":
            planner = _planner(source_appl, dest_appl)
            items = clone_policy(planner, _ops(dest_appl), policy,
                                 new_name=new_name or policy, dry_run=dry_run,
                                 vip_ip=vip_ip, copy_wpp=copy_wpp,
                                 wpp_new_name=wpp_new_name, wpp_suffix=wpp_suffix)
            summary = clone_summary(items)
            rec["ok"] = summary["failed"] == 0 and (dry_run or summary["created"] > 0
                                                    or summary["exists"] > 0)
            report = clone.outcome(items)
            rec["detail"] = {"summary": summary, "plan": clone.render_plan(items),
                             "dest": dest_appl.name, "new_name": new_name or policy,
                             "vip_ip": vip_ip, "copy_wpp": copy_wpp,
                             "wpp_new_name": wpp_new_name, "clone": report}
            if summary["failed"]:
                rec["error"] = "%s on %s" % (_failed_msg(report), dest_appl.name)
        elif action == "migrate_to":
            planner = _planner(source_appl, dest_appl)
            out = migrate_policy(planner, _ops(dest_appl), _ops(source_appl),
                                 policy, new_name=new_name or policy, dry_run=dry_run,
                                 vip_ip=vip_ip, copy_wpp=copy_wpp,
                                 wpp_new_name=wpp_new_name, wpp_suffix=wpp_suffix)
            rec["ok"] = out["ok"]
            report = clone.outcome(out["items"])
            rec["detail"] = {"summary": out["summary"],
                             "plan": clone.render_plan(out["items"]),
                             "dest": dest_appl.name, "new_name": new_name or policy,
                             "vip_ip": vip_ip, "copy_wpp": copy_wpp,
                             "wpp_new_name": wpp_new_name,
                             "source_disabled": out["source_disabled"],
                             "clone": report}
            if not out["ok"]:
                rec["error"] = ("%s — source left live" % _failed_msg(report)
                                if report["failed"] else "clone failed — source left live")
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
    certificate carry-over · capacity headroom."""
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
        issues = clone.validate_completeness(items) if (live_ok and root_item) else []
        checks.append(_source_gate(
            pol, source_appl.name, live_ok=live_ok, src_err=src_err,
            root_present=bool(root_item and root_item.payload), issues=issues))
        policy_obj = dict(root_item.payload) if (root_item and root_item.payload) else {}
        # cached composite is used ONLY for the (non-blocking) VIP/WPP hints below.
        data, _cr, _meta = read_layer.policy_full_cached(source_appl.id, pol)
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
        # 7) capacity at the destination
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


def action_label(action: str) -> str:
    return {
        "enable": "Enable", "disable": "Disable", "delete": "Delete",
        "clone_here": "Clone (same box)", "clone_to": "Clone to another FortiWeb",
        "migrate_to": "Migrate to another FortiWeb",
    }.get(action, action)


def preview(action: str, *, source_appl, dest_appl=None, policies: list[str],
            new_name: str = "", opts: dict | None = None) -> list[dict]:
    """Synchronous dry-run across the selected policies (read-only). For
    clone/migrate this reads the source device (and validates the destination)
    but writes nothing."""
    return [
        perform_one(action, source_appl=source_appl, dest_appl=dest_appl,
                    policy=p, new_name=_name_for(action, p, new_name, policies),
                    dry_run=True, opts=opts)
        for p in policies
    ]


def _name_for(action: str, policy: str, new_name: str, policies: list[str]) -> str:
    """The destination name for one policy. A same-box clone of ONE policy uses
    the given name; a bulk same-box clone suffixes each ('-copy') so names stay
    unique. Cross-box keeps the original name unless one was given."""
    if action == "clone_here":
        if len(policies) == 1 and new_name:
            return new_name
        return "%s-copy" % policy
    return new_name or policy


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
            for i, pol in enumerate(policies):
                jobs.checkpoint(job_id)   # cooperative Stop, between policies
                jobs.set_progress(job_id, int(i * 100 / max(1, total)),
                                  "%s — %s (%d/%d)" % (action_label(action), pol, i + 1, total))
                rec = perform_one(
                    action, source_appl=src, dest_appl=dst, policy=pol,
                    new_name=_name_for(action, pol, new_name, policies),
                    dry_run=False, opts=opts)
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
