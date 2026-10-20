"""Python Studio -- Administrator > Studio (2026-10-20).

One page for the two Python tools, which used to be separate menu entries:

* **Scripts** -- the Script Library list (scripts with a form that operators
  run). The editor stays in ``views.script_library`` under ``/studio/scripts``.
* **Console** -- the scratch Python console over the curated datasets
  (``services.py_console``), formerly ``/database/py-console``.

Each pane keeps its own key and its own sandbox: the console runs in a
bubblewrap jail with no network that only receives the masked, SELECT-only
data bundle; scripts run in ``satom-scripts.service`` with the network their
author declared. Uniting the pages unites neither the keys nor the jails.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_any_permission, require_permission
from ..services import plugin_sandbox
from ..services import py_console as pyc
from ..services import py_examples
from ..services.audit import log_action

bp = Blueprint("studio", __name__, url_prefix="/studio")
CONSOLE = "studio.python_console"
LIBRARY = "studio.script_library"
PANES = ("scripts", "console")


@bp.route("/")
@login_required
@require_any_permission(LIBRARY, CONSOLE)
def index():
    from ..services import sandbox
    from ..services import script_library as SL
    can_console = current_user.can(CONSOLE)
    can_library = current_user.can(LIBRARY)
    pane = request.args.get("pane")
    if pane not in PANES or (pane == "scripts" and not can_library) \
            or (pane == "console" and not can_console):
        pane = "scripts" if can_library else "console"
    return render_template(
        "studio/index.html", pane=pane,
        can_console=can_console, can_library=can_library,
        scripts=SL.list_scripts() if can_library else [],
        runs=SL.recent_runs(limit=15) if can_library else [],
        datasets=plugin_sandbox.dataset_catalog() if can_console else [],
        examples=py_examples.all_examples() if can_console else [],
        sandbox_ok=sandbox.available())


# A locked-down bwrap sandbox (services.py_console) runs ADMIN-authored
# arbitrary Python over the SAME curated, masked, SELECT-only datasets the
# plugins use (services.plugin_sandbox.load_datasets). The sandbox has NO
# secrets, NO network and NO app filesystem -- the security contract is pinned
# by tests/test_py_console.py. Every run is audited.
@bp.route("/console/run", methods=["POST"])
@login_required
@require_permission(CONSOLE)
def console_run():
    body = request.get_json(silent=True) or {}
    source = (body.get("source") or "")[:100_000]
    req_keys = body.get("datasets") or []
    known = {d["key"] for d in plugin_sandbox.dataset_catalog()}
    # dedupe + keep only entitled dataset keys -- a client can never widen access
    keys = [k for k in dict.fromkeys(req_keys) if k in known]
    bundle = plugin_sandbox.load_datasets(keys)
    result = pyc.run_python(source, bundle)
    log_action("py_console.run", target="python-console", extra={
        "datasets": keys,
        "ok": result["ok"],
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "duration_ms": result["duration_ms"],
        "source": source[:1000],
    })
    return jsonify({**result, "datasets": keys})
