"""Settings → Integrations — the one page where SATOM is wired to systems it
does not own: NetBox (maintenance windows) and the operator's own Python hooks
(their CRM, their ticketing, whatever they run).

Everything on this page is OUTBOUND and optional. The product must install and
run in a management network with no internet and no NetBox, so every control
here degrades to "disabled" rather than to an error, and a disabled integration
never silently reports success.

Rendering this page performs NO network I/O. The NetBox reachability check is a
button (``/netbox/test``) fetched after the page, the same contract the
infra-health card and ``/stores`` keep - a settings page that hangs because
somebody's CRM is down is a settings page nobody can use to turn that CRM off.
"""
from __future__ import annotations

import re

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission, visible_appliances
from ..services import hook_starters

bp = Blueprint("integrations", __name__, url_prefix="/settings/integrations")


def _who() -> str:
    return getattr(current_user, "username", "") or "system"


#: The editor default now lives with the other starters. Kept as an alias
#: rather than a second copy: two authors of one string is how the
#: published site lost its Docs link.
SAMPLE_HOOK = hook_starters.STARTERS["change-ticket"]["source"]

#: The catalog key and default name of the reconciliation task this page
#: writes. ONE row per install, looked up by KEY and not by name, so renaming
#: the task on the Scheduled Actions page does not make this card create a
#: second one that fights the first over the same map.
NB_TASK_ACTION = "netbox_reconcile"
NB_TASK_NAME = "NetBox inventory reconcile"
NB_DEFAULT_TIME = "03:00"
_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _netbox_task():
    """The reconciliation ScheduledAction, or None. Never creates."""
    from ..models import ScheduledAction
    return (ScheduledAction.query
            .filter_by(action=NB_TASK_ACTION)
            .order_by(ScheduledAction.id.asc())
            .first())


# --------------------------------------------------------------------------- #
#  Page                                                                         #
# --------------------------------------------------------------------------- #
@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    from ..services import netbox_client as netbox
    from ..services import tracker_client as tracker
    hooks_mod, hooks_error = _hooks()
    return render_template(
        "integrations/index.html",
        # The Admin Console submenu travels with the page. It is the SAME
        # settings/_nav.html the console renders, in `links` mode because this
        # page has no panes to switch; is_admin is what decides which groups
        # the menu offers at all -- without it the menu would silently shrink
        # to My Account on a page only USER_MANAGE ever reaches.
        is_admin=True,          # gated by @require_permission(USER_MANAGE)
        nav_mode="links",
        nav_active="integrations.index",
        netbox=netbox.config(),                    # never reveals the token
        mw_backends=netbox.MW_BACKENDS,
        appliances=visible_appliances().all(),
        device_map=netbox.device_map(),
        hooks=(hooks_mod.list_hooks() if hooks_mod else []),
        events=(hooks_mod.EVENTS if hooks_mod else {}),
        recent=(hooks_mod.recent(20) if hooks_mod else []),  # newest first, all hooks
        hooks_error=hooks_error,
        tracker=tracker.config(),            # never reveals the token
        tracker_backends=tracker.BACKENDS,
        # The reconciliation card. `nb_task` is the row itself (or None) so the
        # card can show what is ACTUALLY scheduled rather than re-describing
        # the form the operator last posted.
        nb_task=_netbox_task(),
        nb_default_per_round=netbox.DEFAULT_PER_ROUND,
        nb_max_per_round=netbox.MAX_PER_ROUND,
        nb_default_time=NB_DEFAULT_TIME,
        nb_task_name=NB_TASK_NAME,
    )


# --------------------------------------------------------------------------- #
#  NetBox                                                                       #
# --------------------------------------------------------------------------- #
@bp.route("/netbox", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_netbox():
    from ..services import audit
    from ..services import netbox_client as netbox
    try:
        netbox.save_config(request.form)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("integrations.index"))
    # The token is never logged - not its value, not its length. An audit row
    # that records how long a secret is has still narrowed it.
    audit.log_action("integrations.netbox.save", target="netbox",
                     detail=f"url={request.form.get('url', '')!r} "
                            f"backend={request.form.get('mw_backend', '')!r} "
                            f"enabled={'1' if request.form.get('enabled') else '0'}")
    flash("NetBox settings saved.", "success")
    return redirect(url_for("integrations.index"))


@bp.route("/netbox/test", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def test_netbox():
    """Reachability probe. Returns the measured elapsed time and the reported
    version - a green tick with no numbers behind it is not evidence."""
    from ..services import netbox_client as netbox
    return jsonify(netbox.test_connection())


@bp.route("/netbox/map", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_map():
    """Bind SATOM appliances to NetBox objects.

    A value is a DEVICE id on its own (``7``) or a virtual machine with its
    prefix (``vm:95``) -- the same number names different objects in the two
    types, so the id alone is only half an address.

    An UNMAPPED appliance is not an error here: :func:`netbox_client.resolve_plan`
    falls back to an exact name match, devices first and then virtual machines.
    It is recorded as unmapped in the UI so the operator can see which
    appliances depend on that fallback, because a rename on either side breaks
    it silently."""
    from ..services import netbox_client as netbox
    pairs = {}
    for key, value in request.form.items():
        if not key.startswith("map_"):
            continue
        value = (value or "").strip()
        if not value:
            continue
        pairs[key[4:]] = value
    try:
        netbox.save_device_map(pairs)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("integrations.index"))
    flash(f"Saved {len(pairs)} device mapping(s).", "success")
    return redirect(url_for("integrations.index"))


@bp.route("/netbox/schedule", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_netbox_schedule():
    """Save the reconciliation cadence AS A SCHEDULED ACTION.

    Deliberately not a private setting: the row this writes is the same
    :class:`ScheduledAction` the Automation page edits and the calendar draws,
    so the task is visible, runnable-now, auditable and deletable from the
    surfaces that already own scheduled work. A second, page-local scheduler
    would be a job nobody could see from the page that lists the jobs.

    The flash NAMES the outcome it actually produced. A disabled row is saved
    but is neither run nor drawn, so it must not be reported as "on the
    calendar" -- the same rule the rest of this page keeps for a disabled
    integration.
    """
    import json

    from flask_babel import gettext

    from ..models import ScheduledAction, db
    from ..services import audit, settings_store
    from ..services import netbox_client as netbox
    from ..services.product_scope import stamp
    from ..services.scheduler import compute_next_run

    form = request.form
    per_round = netbox.clamp_per_round(form.get("per_round"))

    kind = (form.get("schedule_kind") or "daily").strip()
    if kind not in ("interval", "daily"):
        kind = "daily"
    if kind == "interval":
        try:
            every = int(form.get("interval_every") or 6)
        except (TypeError, ValueError):
            every = 6
        unit = (form.get("interval_unit") or "hours").strip()
        if unit not in ("minutes", "hours", "days"):
            unit = "hours"
        schedule = {"every": max(1, every), "unit": unit}
    else:
        at = (form.get("daily_time") or "").strip()
        # A malformed time is CORRECTED to the default and said out loud: a
        # silently dropped schedule is a task that never fires.
        if not _HHMM_RE.match(at):
            if at:
                flash(gettext("“%(value)s” is not a HH:MM time; using %(fallback)s.",
                              value=at[:16], fallback=NB_DEFAULT_TIME), "warning")
            at = NB_DEFAULT_TIME
        schedule = {"time": at}

    row = _netbox_task()
    created = row is None
    if created:
        row = ScheduledAction(created_by=_who(), product=stamp() or "fortiweb")
        db.session.add(row)
    name = (form.get("name") or "").strip()[:128] or NB_TASK_NAME
    row.name = name
    row.action = NB_TASK_ACTION
    row.scope = "admin"
    row.targets = json.dumps([])
    row.params = json.dumps({"per_round": per_round})
    row.schedule_kind = kind
    row.schedule = json.dumps(schedule)
    row.enabled = bool(form.get("enabled"))
    # No catch-up: a missed reconciliation is not worth replaying. The next
    # round reads the map as it is and takes whatever is still unmapped.
    row.catch_up = False
    row.next_run = compute_next_run(kind, schedule, tz=settings_store.tz_name())
    db.session.commit()

    audit.log_action("integrations.netbox.schedule", target=row.name,
                     detail=f"{'created' if created else 'updated'} id={row.id} "
                            f"per_round={per_round} {kind}={schedule} "
                            f"enabled={'1' if row.enabled else '0'}")

    if not row.enabled:
        flash(gettext("The task “%(name)s” was saved, but it is DISABLED: it "
                      "will not run and it is not drawn on the calendar.",
                      name=name), "warning")
    elif created:
        flash(gettext("The task “%(name)s” has been added to Scheduled Actions "
                      "and is on the calendar.", name=name), "success")
    else:
        flash(gettext("The task “%(name)s” was updated in Scheduled Actions and "
                      "is on the calendar.", name=name), "success")
    return redirect(url_for("integrations.index"))


# --------------------------------------------------------------------------- #
#  Issue tracker (Jira / OpenProject / Vikunja)                                 #
# --------------------------------------------------------------------------- #
@bp.route("/tracker", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_tracker():
    from ..services import audit
    from ..services import tracker_client as tracker
    try:
        tracker.save_config(request.form)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("integrations.index"))
    # The token is never logged - not its value, not its length. An audit row
    # that records how long a secret is has still narrowed it. The PROJECT is
    # logged on purpose: "who pointed our changes at a different project" is
    # the question this row exists to answer.
    audit.log_action("integrations.tracker.save", target="tracker",
                     detail=f"backend={request.form.get('backend', '')!r} "
                            f"url={request.form.get('url', '')!r} "
                            f"project={request.form.get('project', '')!r} "
                            f"enabled={'1' if request.form.get('enabled') else '0'}")
    flash("Issue tracker settings saved.", "success")
    return redirect(url_for("integrations.index"))


@bp.route("/tracker/test", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def test_tracker():
    """Probe identity AND the configured project. Returns the measured elapsed
    time - a green tick with no numbers behind it is not evidence."""
    from ..services import tracker_client as tracker
    return jsonify(tracker.test_connection())


# --------------------------------------------------------------------------- #
#  Hooks (the operator's own Python)                                            #
# --------------------------------------------------------------------------- #
def _hooks():
    """``(module, error)``. The hooks subsystem is optional; a deployment
    without it must still render the NetBox half of this page."""
    try:
        from ..services import integration_hooks as mod
        return mod, ""
    except ImportError as exc:  # pragma: no cover - only when not installed
        return None, str(exc)


@bp.route("/hooks/<slug>")
@login_required
@require_permission(Permission.USER_MANAGE)
def hook_detail(slug):
    mod, error = _hooks()
    if mod is None:
        flash(error or "integrations unavailable", "danger")
        return redirect(url_for("integrations.index"))
    if slug == "new":
        # A named starter, defaulting to the working CRM example. A blank
        # editor is a worse starting point than a real one: what the author
        # most needs to see is that the credential comes from ctx.secret()
        # and the HTTP call is already time-boxed. An unknown slug falls
        # back rather than 404s -- a typo in a query string must not look
        # like "this product ships no examples".
        want = (request.args.get("starter") or "").strip()
        starter = hook_starters.get(want)
        chosen = want if want in hook_starters.STARTERS \
            else hook_starters.DEFAULT_STARTER
        # A blank editor is a worse starting point than a working example: the
        # thing an operator most needs to see is that the secret comes from
        # ctx.secret() and the HTTP call is already time-boxed.
        return render_template("integrations/hook.html",
                               hook={"slug": "new", "enabled": True,
                                     "timeout": 30,
                                     "secrets": starter["secrets"],
                                     "event": starter["event"]},
                               events=mod.EVENTS, recent=[],
                               starters=hook_starters.catalog(),
                               starter_slug=chosen,
                               default_source=starter["source"])
    raw = mod.get_hook(slug)
    if raw is None:
        flash("Hook not found.", "warning")
        return redirect(url_for("integrations.index"))
    # get_hook returns {slug, meta, source, versions}; the template reads a flat
    # record. Flattened HERE rather than in the template so a meta key that
    # shadows 'source' or 'versions' cannot quietly win.
    hook = dict(raw.get("meta") or {})
    hook.update(slug=raw.get("slug", slug), source=raw.get("source", ""),
                versions=raw.get("versions", []))
    # recent() is global and newest-first; this page wants only this hook's runs.
    runs = [r for r in mod.recent(200) if r.get("slug") == slug][:20]
    return render_template("integrations/hook.html", hook=hook,
                           events=mod.EVENTS, recent=runs)


@bp.route("/hooks/save", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def hook_save():
    from ..services import audit
    mod, error = _hooks()
    if mod is None:
        flash(error or "integrations unavailable", "danger")
        return redirect(url_for("integrations.index"))
    slug = (request.form.get("slug") or "").strip()
    meta = {
        "name": (request.form.get("name") or slug).strip(),
        "event": (request.form.get("event") or "").strip(),
        "enabled": bool(request.form.get("enabled")),
        "timeout": request.form.get("timeout") or "",
        "secrets": [s.strip() for s in (request.form.get("secrets") or "").split(",")
                    if s.strip()],
    }
    try:
        mod.save_hook(slug, request.form.get("source") or "", meta, by=_who())
    except ValueError as exc:
        # A syntax error is reported HERE, at save time, with the message. The
        # alternative - accepting it and failing at 03:00 inside a maintenance
        # window - is the failure this validation exists to prevent.
        flash(f"Hook not saved: {exc}", "danger")
        return redirect(url_for("integrations.hook_detail", slug=slug)
                        if slug else url_for("integrations.index"))
    audit.log_action("integrations.hook.save", target=slug,
                     detail=f"event={meta['event']!r} enabled={meta['enabled']}")
    flash("Hook saved.", "success")
    return redirect(url_for("integrations.hook_detail", slug=slug))


@bp.route("/hooks/<slug>/dry-run", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def hook_dry_run(slug):
    """Queue this hook once against the event's sample payload.

    Still goes through the runner, never through this worker - a dry run that
    took a different execution path would be testing something other than what
    production does."""
    from ..services import audit
    mod, error = _hooks()
    if mod is None:
        return jsonify({"ok": False, "detail": error or "integrations unavailable"}), 503
    try:
        result = mod.dispatch_one(slug, sample=True, by=_who())
    except ValueError as exc:
        return jsonify({"ok": False, "detail": str(exc)}), 400
    audit.log_action("integrations.hook.dry_run", target=slug)
    return jsonify({"ok": True, **result})


@bp.route("/hooks/<slug>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def hook_delete(slug):
    from ..services import audit
    mod, error = _hooks()
    if mod is None:
        flash(error or "integrations unavailable", "danger")
        return redirect(url_for("integrations.index"))
    mod.delete_hook(slug, by=_who())
    audit.log_action("integrations.hook.delete", target=slug)
    flash("Hook deleted. Its version history is kept.", "success")
    return redirect(url_for("integrations.index"))


@bp.route("/status/<request_id>")
@login_required
@require_permission(Permission.USER_MANAGE)
def hook_status(request_id):
    mod, error = _hooks()
    if mod is None:
        return jsonify({"ok": False, "detail": error}), 503
    res = mod.result(request_id)
    if res is None:
        return jsonify({"ok": False, "detail": "unknown request"}), 404
    return jsonify({"ok": True, **res})
