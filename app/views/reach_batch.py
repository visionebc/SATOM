"""Backend Reachability (batch) — Fleet → Backend Reachability.

GET  /reachability/   the form
POST /reachability/   parse the textarea (or the uploaded file) and run

READ-ONLY, and deliberately not attached to an appliance. Every other backend
check in SATOM hangs off a device page or the clone dialog, which means the
operator must first pick a source and a destination in the workspace. The whole
point of this page is that the file names them, one pair per line, and no tab
has to be open anywhere.

All judgement lives in ``services.reach_batch``. This module reads the form,
clamps the two numbers an operator can set, and renders. It does NOT decide
what a verdict means and it does NOT probe anything itself — a second opinion
here could only disagree with the service.

THE UPLOAD REPLACES THE TEXTAREA, AND THE TEXTAREA IS REFILLED WITH IT.
Merging the two was the other option and it is worse: the operator would be
looking at one list and running another. Refilling means the page always shows
exactly the lines that ran, and they stay editable for the next attempt.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import reach_batch as rb
from ..services.audit import log_action

bp = Blueprint("reach_batch", __name__, url_prefix="/reachability")

#: A reachability list is a few kilobytes. Anything past this is a file someone
#: picked by mistake, and reading it into memory to find that out is the bug.
MAX_UPLOAD = 256 * 1024


def _decode(data: bytes) -> tuple:
    """``(text, notice)`` — a file that is not UTF-8 is still readable.

    Operators export these lists from Excel on Windows. Refusing a cp1252 file
    with a stack trace would send them to reformat a file whose CONTENT is
    fine, so the fallback is taken and SAID OUT LOUD rather than hidden.
    """
    try:
        return data.decode("utf-8-sig"), ""
    except UnicodeDecodeError:
        return (data.decode("latin-1", "replace"),
                "the file is not UTF-8 — it was read as latin-1, so check any "
                "line with accented characters")


def _num(name: str, default: float, lo: float, hi: float) -> float:
    try:
        return max(lo, min(float(request.form.get(name) or default), hi))
    except (TypeError, ValueError):
        return default


@bp.route("/", methods=["GET", "POST"])
@login_required
@require_permission(Permission.VIEW)
def index():
    ctx = {
        "entries_raw": "",
        "report": None,
        "tsv": "",
        "notice": "",
        "error": "",
        "max_lines": rb.MAX_LINES,
        "opts": {"ssh": False,
                 "timeout": rb.DEFAULT_TCP_TIMEOUT,
                 "budget": int(rb.DEFAULT_BUDGET_S)},
    }
    if request.method != "POST":
        return render_template("reachability/index.html", **ctx)

    raw = request.form.get("entries", "")
    upload = request.files.get("file")
    if upload is not None and upload.filename:
        data = upload.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            ctx["error"] = ("%s is larger than %d KB — this page takes a list "
                            "of lines, not a config dump"
                            % (upload.filename, MAX_UPLOAD // 1024))
            return render_template("reachability/index.html", **ctx)
        raw, ctx["notice"] = _decode(data)

    ctx["entries_raw"] = raw
    ctx["opts"] = {
        "ssh": bool(request.form.get("ssh")),
        "timeout": _num("timeout", rb.DEFAULT_TCP_TIMEOUT, 0.5, 10.0),
        "budget": int(_num("budget", rb.DEFAULT_BUDGET_S, 10.0,
                           rb.MAX_BUDGET_S)),
    }

    rows, dropped = rb.parse_batch(raw)
    if not rows and not dropped:
        ctx["error"] = ("nothing to check — one line per service, "
                        "'source;policy;destination'")
        return render_template("reachability/index.html", **ctx)

    report = rb.run_batch(rows, use_ssh=ctx["opts"]["ssh"],
                          tcp_timeout=ctx["opts"]["timeout"],
                          budget_s=float(ctx["opts"]["budget"]),
                          user=current_user)
    report["dropped"] = dropped
    ctx["report"] = report
    ctx["tsv"] = rb.to_tsv(report)

    # Audited because it sends real traffic to third-party hosts, even though
    # it changes nothing. "Who made these boxes ping our customer's servers?"
    # is a question that gets asked, and it deserves an answer.
    log_action("reachability.batch",
               target="%d line(s)" % len(rows),
               extra={"totals": report["totals"], "ssh": ctx["opts"]["ssh"],
                      "elapsed_s": report["elapsed_s"],
                      "budget_hit": report["budget_hit"]})
    return render_template("reachability/index.html", **ctx)
