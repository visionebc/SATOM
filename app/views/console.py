"""Device Console — Administrator → Device Console, in EVERY ADOM.

Three things an operator needs when a box is misbehaving and the REST API is
not enough, on one page:

1. **Run CLI commands** against a registered appliance and read every answer.
   This is the only write path SSH has in SATOM; the gate lives in
   :mod:`app.services.ssh_console`, never here.
2. **Test a username and password** directly against a FortiOS device —
   including one SATOM does not manage — to tell "wrong credential" apart from
   "unreachable" apart from "logs in but can read nothing".
3. **Package the transcript for Fortinet TAC**, with the read-only diagnostic
   battery attached and every secret redacted.

NO SECOND OPINION LIVES IN THIS MODULE. It reads the form, resolves the
permission and the typed confirmation, calls the service, and renders. Whether
a command may be sent, whether an answer means failure, and what gets redacted
are all decided in ``services.ssh_console`` — the page and the future Process
engine must agree about those, and two authors is how they would stop agreeing.

WHY THE APPLIANCE LIST IS NOT FILTERED TO FORTIWEB
--------------------------------------------------
``logs.py`` restricts itself to FortiWeb because its battery is FortiWeb
syntax. A console has no battery: the operator types what the box in front of
them speaks. ``visible_appliances()`` already scopes the list to the active
ADOM, so the FortiADC ADOM offers FortiADC boxes and nothing else.
"""
from __future__ import annotations

from datetime import datetime

from flask import (Blueprint, abort, flash, render_template, request,
                   send_file)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, Permission, visible_appliance_or_404,
                      visible_appliances)
from ..services import ssh_console as sc
from ..services.audit import log_action

bp = Blueprint("console", __name__, url_prefix="/console")

#: A pasted script larger than this is not a console session.
MAX_SCRIPT = 64 * 1024


def _appliances():
    return visible_appliances().order_by(Appliance.name).all()


def _stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def _render(**kw):
    ctx = dict(
        appliances=_appliances(),
        presets=sc_presets(),
        max_commands=sc.MAX_COMMANDS,
        cred_max=sc.CRED_MAX,
        cred_window=int(sc.CRED_WINDOW),
        script="", result=None, cred=None, bundle=None,
        selected_id=None, ack=False, stop_on_error=True,
    )
    ctx.update(kw)
    return render_template("console/index.html", **ctx)


def sc_presets() -> dict[str, str]:
    """Read-only starting points, reused from the troubleshooting battery.

    Deliberately all reads. A preset that writes is a button that changes an
    appliance with one click, and the whole design of the disruptive tier is
    that a write is something somebody typed on purpose.
    """
    from ..services.ssh_ops import TROUBLESHOOT
    return dict(TROUBLESHOOT)


@bp.route("/")
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    return _render()


@bp.route("/run", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def run():
    raw = (request.form.get("script") or "")[:MAX_SCRIPT]
    ack = request.form.get("ack_disruptive") == "1"
    confirm = (request.form.get("confirm_name") or "").strip()
    stop_on_error = request.form.get("stop_on_error", "1") == "1"
    try:
        app_id = int(request.form.get("appliance_id") or 0)
    except (TypeError, ValueError):
        app_id = 0
    if not app_id:
        flash("Pick an appliance first.", "warning")
        return _render(script=raw, ack=ack, stop_on_error=stop_on_error)

    appliance = visible_appliance_or_404(app_id)
    commands = sc.parse_script(raw)
    if not commands:
        flash("No commands were entered.", "warning")
        return _render(script=raw, selected_id=app_id, ack=ack,
                       stop_on_error=stop_on_error)

    plan = sc.classify_script(commands)
    wants_disruptive = any(p["tier"] == sc.TIER_DISRUPTIVE for p in plan)

    # THE TYPED NAME IS CHECKED HERE, NOT IN THE SERVICE. The service's
    # ``allow_disruptive`` is a statement that a human was warned and agreed;
    # WHICH human and HOW they agreed is a web concern, and putting the form
    # field inside the service would make the future Process engine have to
    # fake a form to run the same command.
    allow = False
    if wants_disruptive:
        if not ack or confirm != appliance.name:
            flash(
                "This script contains a disruptive command. Tick the "
                "acknowledgement and type the appliance name exactly "
                f"({appliance.name}) to send it.", "danger")
            return _render(script=raw, selected_id=app_id, ack=ack,
                           stop_on_error=stop_on_error,
                           result=sc.ScriptResult(
                               appliance=appliance.name,
                               rows=[sc.CommandRow(
                                   command=p["command"], tier=p["tier"],
                                   status="not_run",
                                   detail=p["reason"] or "not sent")
                                   for p in plan],
                               error="the script was not sent — disruptive "
                                     "commands need an explicit confirmation"))
        allow = True

    # A retired placeholder host is rejected by NAME, before a client is built.
    # Otherwise every line of the script waits out a connection timeout to
    # learn what the register already says. The reason text lives in the
    # service so this page and the Process step say the same thing.
    retired = sc.retired_placeholder(appliance)
    if retired:
        result = sc.ScriptResult(
            appliance=appliance.name,
            rows=[sc.CommandRow(command=p["command"], tier=p["tier"],
                                status="not_run", detail=retired) for p in plan],
            error=f"{appliance.name} — {retired}")
    else:
        result = sc.run_script(appliance, commands, allow_disruptive=allow,
                               stop_on_error=stop_on_error)

    log_action(
        "console.run",
        target=appliance.name,
        extra={
            "appliance_id": appliance.id,
            "host": appliance.host,
            "commands": [sc.redact(c) for c in commands],
            "tiers": sorted({p["tier"] for p in plan}),
            "disruptive_ack": allow,
            "stop_on_error": stop_on_error,
            "failed": result.failed,
            "session_error": result.error,
        },
    )
    return _render(script=raw, selected_id=app_id, ack=ack, result=result,
                   stop_on_error=stop_on_error)


@bp.route("/verify", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def verify():
    """Test one credential against one device.

    USER_MANAGE rather than CONFIG_WRITE: this accepts an arbitrary host, so it
    is the one control on the page that can be aimed at something SATOM does
    not manage. Every attempt is audited with the host and username and WITHOUT
    the password, and ``ssh_console`` throttles per operator.
    """
    host = (request.form.get("cred_host") or "").strip()
    username = (request.form.get("cred_username") or "").strip()
    password = request.form.get("cred_password") or ""
    try:
        port = int(request.form.get("cred_port") or 22)
    except (TypeError, ValueError):
        port = 22

    try:
        cred = sc.verify_credentials(
            host, username, password, ssh_port=port,
            actor=getattr(current_user, "username", "anonymous") or "anonymous")
    except sc.ConsoleViolation as exc:
        cred = sc.CredCheck(host=host, username=username, error=str(exc))

    log_action(
        "console.verify_credentials",
        target=f"{username}@{host}:{port}",
        extra={
            "host": host, "username": username, "ssh_port": port,
            "reachable": cred.reachable, "authenticated": cred.authenticated,
            "read_ok": cred.read_ok, "firmware": cred.firmware,
            "error": cred.error,
        },
    )
    return _render(cred=cred)


@bp.route("/bundle", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def bundle():
    """Package a transcript (plus the read-only battery) for a TAC ticket."""
    try:
        app_id = int(request.form.get("appliance_id") or 0)
    except (TypeError, ValueError):
        app_id = 0
    if not app_id:
        abort(400)
    appliance = visible_appliance_or_404(app_id)
    transcript = (request.form.get("transcript") or "")[:2 * 1024 * 1024]
    include = request.form.get("include_diagnostics") == "1"
    ticket = (request.form.get("ticket") or "").strip()[:64]
    note = (request.form.get("note") or "").strip()[:2000]

    meta = sc.build_tac_bundle(
        appliance, transcript, stamp=_stamp(),
        include_diagnostics=include, ticket=ticket, note=note)
    log_action("console.tac_bundle", target=appliance.name,
               extra={"appliance_id": appliance.id, "bundle": meta["name"],
                      "size": meta["size"], "ticket": ticket,
                      "diagnostics": meta["diagnostics_included"],
                      "diagnostics_note": meta["diagnostics_note"]})
    return send_file(meta["path"], as_attachment=True,
                     download_name=meta["name"],
                     mimetype="application/gzip")
