"""Self-update admin page — update the manager's own code + Python deps,
staged across the HA nodes (standby first, primary after validation).

Admin-only (``user_manage``). The write path is an ENQUEUE only: the actual
privileged update runs in ``satom-updater.service`` (root), so the
web worker is never the thing restarting itself.
"""
from __future__ import annotations

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, jsonify, current_app)
from flask_login import login_required, current_user

from .. import runtime
from ..auth.decorators import require_permission
from ..services import self_update as su
from ..services import cluster
from ..services import reconciler
from ..services import update_package_service as upkg
from ..services.audit import log_action

bp = Blueprint("self_update", __name__, url_prefix="/self-update")


def _active_update(history, max_age_s=7200):
    """The update still in flight, if any, so the page resumes watching it.

    The live panel used to appear only behind ``?watch=<uid>``: reloading the
    page, or coming back to it from another one, dropped the operator into the
    history table with no sign that an update was still running. Requests
    older than ``max_age_s`` are left out so an orphaned "queued" file cannot
    pin the panel open for ever (it still shows in the history).
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for h in history or []:
        if h.get("state") not in ("queued", "running"):
            continue
        try:
            at = datetime.fromisoformat(
                str(h.get("updated_at") or "").replace("Z", "+00:00"))
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (now - at).total_seconds() <= max_age_s:
            return h.get("id") or ""
    return ""


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    su.self_report()  # refresh this node's entry in the shared (replicated) state
    check = su.check_remote(fetch=False)  # cheap: no network on page load
    history = su.recent_updates()
    return render_template(
        "self_update/index.html",
        current=check["current"],
        nodes=su.node_reports(),
        this_node=su.this_node_name(),
        this_role=su.node_role(),
        validated=su.validated_state(),
        history=history,
        branch=su.BRANCH,
        ha=cluster.full_state(),
        deploy_mode=reconciler.deploy_mode_orm(),
        reconcile=reconciler.last_status_orm(),
        watch_promote=request.args.get("watch_promote", ""),
        watch=request.args.get("watch", "") or _active_update(history),
        uploads=upkg.list_uploads(),
        trust=upkg.trust_state(),
        api_packs=_api_pack_state(),
    )


def _api_pack_state() -> dict:
    """What the API library packs section needs. Never raises: a broken pack
    directory must not take the whole update page down with it."""
    from ..services import api_pack
    try:
        packs = api_pack.list_packs()
        return {"packs": packs, "history": api_pack.import_history(),
                "pending": api_pack.pending_shipped(packs),
                "role": su.node_role(), "error": ""}
    except Exception as exc:  # noqa: BLE001 — shown in the card, not a 500
        return {"packs": [], "history": [], "pending": [], "role": su.node_role(),
                "error": "%s: %s" % (type(exc).__name__, exc)}


@bp.route("/check", methods=["POST"])
@login_required
@require_permission("user_manage")
def check():
    return jsonify(su.check_remote(fetch=True))


@bp.route("/apply", methods=["POST"])
@login_required
@require_permission("user_manage")
def apply():
    info = su.check_remote(fetch=True)
    target = request.form.get("target") or info["target_sha"]
    role = su.node_role()

    # ---- the staged-rollout SEGURO ------------------------------------
    others = [n for n in su.load_nodes() if n.get("name") != su.this_node_name()]
    if role == "primary" and others and not su.can_apply_to_primary(target):
        flash("Blocked by the staged-rollout safeguard: update the STANDBY to "
              "this revision and let it pass its health check first, then the "
              "PRIMARY unlocks.", "warning")
        return redirect(url_for("self_update.index"))

    if info["behind"] == 0 and target == info["current"]["sha"]:
        flash("Already up to date — nothing to apply.", "info")
        return redirect(url_for("self_update.index"))

    try:
        uid = su.request_update(
            target,
            by=getattr(current_user, "username", "?"),
            do_pip="do_pip" in request.form,
            do_migrate="do_migrate" in request.form,
        )
    except runtime.CapabilityUnavailable as exc:
        flash(exc.reason, "warning")
        return redirect(url_for("self_update.index"))
    log_action("self_update.apply", target=target,
               extra={"request": uid, "role": role,
                      "from": (info.get("current") or {}).get("sha", "")[:12],
                      "pip": "do_pip" in request.form,
                      "migrate": "do_migrate" in request.form})
    flash("Update queued (%s). The privileged runner is applying it — watch the "
          "live status below. The service will restart mid-update." % uid,
          "success")
    return redirect(url_for("self_update.index", watch=uid))


@bp.route("/status/<uid>")
@login_required
@require_permission("user_manage")
def status(uid):
    st = su.update_status(uid)
    if st:
        su.reconcile_interlock(st)  # unlock the primary once the standby validated
    return jsonify(st or {"state": "unknown"})


@bp.route("/ha-mode", methods=["POST"])
@login_required
@require_permission("user_manage")
def set_mode():
    """Switch the deployment mode standalone <-> ha. The setting lives in
    the replicated app_settings table, so it can only be WRITTEN where
    Postgres is read-write: the primary."""
    mode = (request.form.get("mode") or "").strip().lower()
    if mode not in ("ha", "standalone"):
        flash("Invalid deployment mode.", "danger")
        return redirect(url_for("ha.index"))
    if su.node_role() != "primary":
        flash("The deployment mode is stored in the replicated settings — "
              "change it on the PRIMARY node (this node's database is "
              "read-only).", "warning")
        return redirect(url_for("ha.index"))
    su.set_ha_mode(mode)
    log_action("ha.mode", target=mode)
    flash("Deployment mode set to %s." % mode.upper(), "success")
    return redirect(url_for("ha.index"))


@bp.route("/deploy-mode", methods=["POST"])
@login_required
@require_permission("user_manage")
def set_deploy_mode():
    """Toggle deploy AUTOMATION: 'auto' (reconciler drives the staged rollout)
    or 'manual' (reconciler only observes; operator applies). Replicated
    setting -> writable on the PRIMARY only."""
    mode = (request.form.get("mode") or "").strip().lower()
    if mode not in ("auto", "manual"):
        flash("Invalid deploy mode.", "danger")
        return redirect(url_for("self_update.index"))
    if su.node_role() != "primary":
        flash("Deploy automation is a replicated setting \u2014 change it on the "
              "PRIMARY node (this node's database is read-only).", "warning")
        return redirect(url_for("self_update.index"))
    reconciler.set_deploy_mode(mode)
    log_action("self_update.deploy_mode", target=mode)
    flash("Deploy automation set to %s. In AUTO the reconciler drives the staged "
          "rollout (standby first, health-gated, then primary); in MANUAL it "
          "only observes and you apply by hand." % mode.upper(), "success")
    return redirect(url_for("self_update.index"))


@bp.route("/promote", methods=["POST"])
@login_required
@require_permission("user_manage")
def promote():
    """Guarded MANUAL failover: promote THIS node's Postgres to primary. Enqueue
    only — the privileged runner runs satom-promote.sh. Requires typing the node's
    hostname to confirm; only valid on a standby."""
    confirm = (request.form.get("confirm_host") or "").strip()
    this_node = su.this_node_name()
    if not cluster.promote_eligible():
        flash("This node is not a standby — promotion is only valid on the node "
              "currently in recovery.", "warning")
        return redirect(url_for("ha.index"))
    if confirm != this_node:
        flash("Confirmation failed: type this node's hostname (%s) exactly to "
              "promote it." % this_node, "danger")
        return redirect(url_for("ha.index"))
    try:
        uid = cluster.request_promote(by=getattr(current_user, "username", "?"))
    except runtime.CapabilityUnavailable as exc:
        flash(exc.reason, "warning")
        return redirect(url_for("ha.index"))
    log_action("ha.promote", target=this_node, extra={"request": uid})
    flash("Failover queued (%s). The privileged runner is promoting this node to "
          "PRIMARY and starting the app — watch the status below. Only promote "
          "when the old primary is confirmed DOWN." % uid, "success")
    return redirect(url_for("ha.index", watch_promote=uid))


@bp.route("/promote-status/<uid>")
@login_required
@require_permission("user_manage")
def promote_status(uid):
    return jsonify(cluster.promote_status(uid) or {"state": "unknown"})


@bp.route("/nodes", methods=["POST"])
@login_required
@require_permission("user_manage")
def save_node():
    """Register / update the secondary HA node from the admin console (writes
    data/ha_nodes.json; rsync carries it to the peer on the next data sync)."""
    name = (request.form.get("name") or "").strip()
    host = (request.form.get("host") or "").strip()
    desc = (request.form.get("desc") or "").strip()
    if not name or not host:
        flash("Both a node name (hostname) and a host/IP are required.", "danger")
    else:
        su.upsert_node(name, host, desc)
        log_action("ha.node.save", target=name, extra={"host": host})
        flash("HA node '%s' (%s) saved. It propagates to the peer on the next "
              "data sync; its live state is probed on this page." % (name, host),
              "success")
    return redirect(url_for("ha.index"))


@bp.route("/nodes/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def delete_node():
    name = (request.form.get("name") or "").strip()
    if name == su.this_node_name():
        flash("Cannot remove this node (self) from the HA registry.", "warning")
    else:
        su.remove_node(name)
        log_action("ha.node.delete", target=name)
        flash("HA node '%s' removed from the registry." % name, "info")
    return redirect(url_for("ha.index"))

# ---------------------------------------------------------------------------
# offline update packages
# ---------------------------------------------------------------------------
@bp.route("/package/upload", methods=["POST"])
@login_required
@require_permission("user_manage")
def package_upload():
    """Stage a signed update package. Staging is NOT applying: nothing is
    trusted until the operator has read the preflight and pressed Apply, and
    even then the privileged runner re-verifies everything from scratch."""
    f = request.files.get("package")
    if not f or not f.filename:
        flash("Choose a package file to upload.", "danger")
        return redirect(url_for("self_update.index"))
    try:
        info = upkg.save_upload(f.stream, f.filename)
    except upkg.PackageError as exc:
        flash("Upload rejected: %s" % exc, "danger")
        return redirect(url_for("self_update.index"))
    except OSError as exc:
        flash("Upload failed: %s" % exc, "danger")
        return redirect(url_for("self_update.index"))
    log_action("update_package.upload", target=info["name"],
               extra={"size": info["size"]})
    flash("Staged %s. Review the preflight below before applying."
          % info["name"], "success")
    return redirect(url_for("self_update.index", pkg=info["name"]))


@bp.route("/package/preflight/<name>")
@login_required
@require_permission("user_manage")
def package_preflight(name):
    try:
        return jsonify(upkg.preflight(name))
    except upkg.PackageError as exc:
        return jsonify({"name": name, "checks": [
            {"id": "package", "label": "Package", "status": "fail",
             "detail": str(exc)}], "can_apply": False,
            "blocking": ["package"]}), 400


@bp.route("/package/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def package_delete():
    name = request.form.get("name") or ""
    try:
        upkg.delete_upload(name)
        log_action("update_package.delete", target=name)
        flash("Removed %s from the staging area." % name, "info")
    except upkg.PackageError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("self_update.index"))


@bp.route("/package/apply", methods=["POST"])
@login_required
@require_permission("user_manage")
def package_apply():
    """Queue an offline package apply.

    Re-runs preflight server-side. The page the operator saw could be minutes
    old, and 'the button was enabled' is not a safety property — the decision
    has to be made against the state that exists now.
    """
    name = request.form.get("name") or ""
    allow_downgrade = "allow_downgrade" in request.form
    try:
        pre = upkg.preflight(name)
    except upkg.PackageError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("self_update.index"))

    if not pre.get("can_apply"):
        flash("Refused: this package still fails preflight (%s). Nothing was "
              "applied." % ", ".join(pre.get("blocking") or ["unknown"]),
              "danger")
        return redirect(url_for("self_update.index", pkg=name))
    if pre.get("is_downgrade") and not allow_downgrade:
        flash("This package is OLDER than the running version. Tick the "
              "downgrade confirmation to proceed — migrations are not "
              "reversed, so keep the database backup.", "warning")
        return redirect(url_for("self_update.index", pkg=name))

    try:
        uid = upkg.request_package_apply(
            name, by=getattr(current_user, "username", "?"),
            allow_downgrade=allow_downgrade,
            do_backup="skip_backup" not in request.form)
    except upkg.PackageError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("self_update.index"))
    except runtime.CapabilityUnavailable as exc:
        flash(exc.reason, "warning")
        return redirect(url_for("self_update.index"))

    log_action("update_package.apply", target=name,
               extra={"from": pre.get("current_version"),
                      "to": (pre.get("manifest") or {}).get("version"),
                      "downgrade": bool(pre.get("is_downgrade")),
                      "queued": uid})
    flash("Package apply queued (%s). The privileged runner is verifying the "
          "signature again and applying it — watch the live status below. The "
          "service restarts mid-update." % uid, "success")
    return redirect(url_for("self_update.index", watch=uid))


@bp.route("/package/feed")
@login_required
@require_permission("user_manage")
def package_feed():
    """What satom-system-upgrades/latest.json offers. Asked by the page AFTER
    it renders, so a node with no internet never waits on it to load."""
    return jsonify(upkg.check_feed())


def _feed_worker():
    def work(app, jid):
        from ..services import jobs as jobsvc

        def progress(done, total):
            jobsvc.set_progress(jid, int(done * 100 / total) if total else 100,
                                "Downloaded %d of %d MB" % (done >> 20, total >> 20))

        with app.app_context():
            res = upkg.download_from_feed(progress=progress)
        jobsvc.finish_success(jid, result=res, message="Downloaded and staged %s"
                              % res["name"])
        return res
    return work


@bp.route("/package/fetch", methods=["POST"])
@login_required
@require_permission("user_manage")
def package_fetch():
    """Download the feed's package into staging as a background job. It is
    staged, not applied: the operator still reads the preflight first."""
    from ..services import jobs as jobsvc
    actor = getattr(current_user, "username", "") or ""
    job = jobsvc.create_job("update_package_download", "Downloading the update package",
                            by=actor, cancelable=False, meta={})
    jobsvc.run_async(current_app._get_current_object(), job["id"], _feed_worker())
    log_action("update_package.download", target="feed",
               extra={"feed": upkg.feed.feed_url(), "job": job["id"]})
    return jsonify({"job_id": job["id"]}), 202


# ---------------------------------------------------------------------------
# API library packs (docs/api-library.md §11)
# ---------------------------------------------------------------------------
def _standby_refusal():
    """A standby's Postgres is read-only: an import there could only fail half
    way. Its library arrives by replication and its files by the data sync."""
    if su.node_role() == "standby":
        return ("This node is the STANDBY — its database is read-only. Import the "
                "pack on the PRIMARY: the library replicates here, and the data "
                "sync copies the release notes and field schemas.")
    return ""


@bp.route("/apipack/inspect")
@login_required
@require_permission("user_manage")
def apipack_inspect():
    from ..services import api_pack
    source = request.args.get("source") or ""
    name = request.args.get("name") or ""
    try:
        res = api_pack.inspect_pack(api_pack.resolve_pack(source, name))
    except api_pack.PackError as exc:
        return jsonify({"source": source, "name": name, "error": str(exc)}), 400
    res.update(source=source, name=name, refusal=_standby_refusal())
    return jsonify(res)


@bp.route("/apipack/upload", methods=["POST"])
@login_required
@require_permission("user_manage")
def apipack_upload():
    from ..services import api_pack
    f = request.files.get("apipack")
    if not f or not f.filename:
        flash("Choose an API pack file to upload.", "danger")
        return redirect(url_for("self_update.index", _anchor="api-packs"))
    try:
        info = api_pack.save_upload(f.stream, f.filename)
    except (api_pack.PackError, OSError) as exc:
        flash("API pack upload rejected: %s" % exc, "danger")
        return redirect(url_for("self_update.index", _anchor="api-packs"))
    log_action("apipack.upload", target=info["name"], extra={"size": info["size"]})
    flash("Staged %s. Pick the items to import below." % info["name"], "success")
    return redirect(url_for("self_update.index", apipack="uploaded:" + info["name"],
                            _anchor="api-packs"))


@bp.route("/apipack/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def apipack_delete():
    from ..services import api_pack
    name = request.form.get("name") or ""
    try:
        api_pack.delete_upload(name)
        log_action("apipack.delete", target=name)
        flash("Removed %s." % name, "info")
    except (api_pack.PackError, OSError) as exc:
        flash(str(exc), "danger")
    return redirect(url_for("self_update.index", _anchor="api-packs"))


def _apipack_worker(path: str, ids: list, actor: str):
    def work(app, jid):
        from ..services import api_pack
        from ..services import jobs as jobsvc

        def progress(done, total, item_id):
            pct = int(done * 100 / total) if total else 100
            jobsvc.set_progress(jid, pct, ("Importing %s (%d of %d)" % (item_id, done + 1, total))
                                if item_id else "Imported %d item(s)" % total)

        with app.app_context():
            res = api_pack.import_pack(path, ids=ids, actor=actor, progress=progress)
        # Recorded before the verdict, so a red job still shows item by item
        # what went in and what did not.
        jobsvc.update_job(jid, result=res)
        if res["errors"]:
            # Partial imports are kept (each item is independent); the job
            # still ends red so nobody reads "some failed" as "done".
            failed = [r["id"] for r in res["items"] if r.get("error")]
            raise RuntimeError("%d of %d item(s) failed: %s — the other %d were imported"
                               % (res["errors"], len(res["items"]), ", ".join(failed[:5]),
                                  res["imported"]))
        jobsvc.finish_success(jid, result=res, message="Imported %d item(s) from pack %s"
                              % (res["imported"], res["version"]))
        return res
    return work


@bp.route("/apipack/import", methods=["POST"])
@login_required
@require_permission("user_manage")
def apipack_import():
    """Import the ticked items as a background job; the page follows it."""
    from ..services import api_pack
    from ..services import jobs as jobsvc
    refusal = _standby_refusal()
    if refusal:
        return jsonify({"error": refusal}), 409
    source = request.form.get("source") or ""
    name = request.form.get("name") or ""
    ids = [i for i in request.form.getlist("ids") if i]
    if not ids:
        return jsonify({"error": "Tick at least one item to import."}), 400
    try:
        path = api_pack.resolve_pack(source, name)
    except api_pack.PackError as exc:
        return jsonify({"error": str(exc)}), 400
    actor = getattr(current_user, "username", "") or ""
    job = jobsvc.create_job("apipack_import", "Importing API pack %s" % name,
                            by=actor, cancelable=False,
                            meta={"pack": name, "source": source, "items": len(ids)})
    jobsvc.run_async(current_app._get_current_object(), job["id"],
                     _apipack_worker(str(path), ids, actor))
    log_action("apipack.import", target=name, extra={"source": source, "items": len(ids),
                                                     "job": job["id"]})
    return jsonify({"job_id": job["id"]}), 202
