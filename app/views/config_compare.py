"""Config Compare (batch) — Fleet → Compare Source ↔ Destination.

GET  /compare/   the form
POST /compare/   parse the textarea (or the uploaded file) and compare

READ-ONLY, and deliberately not attached to an appliance — same reason the
Backend Reachability page is not: the file names both boxes, one pair per line,
so no workspace tab has to be open anywhere. It takes the SAME
``source;policy;destination`` file, because an operator who has already built
that list for a reachability run should not have to build a second one to ask
the next question about the same services.

All judgement lives in ``services.config_compare``. This module reads the form,
clamps the one number an operator can set, and renders. It does NOT decide what
"different" means and it does NOT read an appliance itself.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import config_compare as cc
from ..services.audit import log_action

bp = Blueprint("config_compare", __name__, url_prefix="/compare")

#: A service list is a few kilobytes. Anything past this is a config dump
#: someone picked by mistake, and reading it into memory to find that out is
#: the bug.
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
        "max_lines": cc.MAX_LINES,
        "opts": {"budget": int(cc.DEFAULT_BUDGET_S)},
    }
    if request.method != "POST":
        return render_template("config_compare/index.html", **ctx)

    raw = request.form.get("entries", "")
    upload = request.files.get("file")
    if upload is not None and upload.filename:
        data = upload.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            ctx["error"] = ("%s is larger than %d KB — this page takes a list "
                            "of services, not a config dump"
                            % (upload.filename, MAX_UPLOAD // 1024))
            return render_template("config_compare/index.html", **ctx)
        raw, ctx["notice"] = _decode(data)

    ctx["entries_raw"] = raw
    try:
        budget = float(request.form.get("budget") or cc.DEFAULT_BUDGET_S)
    except (TypeError, ValueError):
        budget = cc.DEFAULT_BUDGET_S
    budget = max(10.0, min(budget, cc.MAX_BUDGET_S))
    ctx["opts"] = {"budget": int(budget)}

    rows, dropped = cc.parse_batch(raw, max_lines=cc.MAX_LINES)
    if not rows and not dropped:
        ctx["error"] = ("nothing to compare — one line per service, "
                        "'source;policy;destination'")
        return render_template("config_compare/index.html", **ctx)

    report = cc.run_batch(rows, budget_s=budget, user=current_user)
    report["dropped"] = dropped
    ctx["report"] = report
    ctx["tsv"] = cc.to_tsv(report)

    # Audited even though it writes nothing: it reads every object behind a
    # service on two appliances, and "who pulled our customer's full policy
    # tree?" is a question that gets asked.
    log_action("config.compare",
               target="%d line(s)" % len(rows),
               extra={"totals": report["totals"],
                      "elapsed_s": report["elapsed_s"],
                      "budget_hit": report["budget_hit"]})
    return render_template("config_compare/index.html", **ctx)
