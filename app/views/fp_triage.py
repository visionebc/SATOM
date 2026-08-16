# app/views/fp_triage.py
"""Standalone false-positive triage — header Tools menu.

Pure helper endpoints: no device call, no DB write, no save. See
:mod:`app.services.fp_triage` for why the save action deliberately lives
elsewhere.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from ..services import fp_triage

bp = Blueprint("fp_triage", __name__, url_prefix="/fp-triage")

MAX_INPUT = 64 * 1024


@bp.route("/parse", methods=["POST"])
@login_required
def parse():
    """Parse pasted text into an attack-log row, and say what could not be used."""
    body = request.get_json(silent=True) or {}
    res = fp_triage.parse(str(body.get("text") or "")[:MAX_INPUT])
    if res.get("error") and not res["row"]:
        return jsonify(ok=False, error=res["error"], fmt=res["fmt"],
                       unmapped=res["unmapped"]), 400
    return jsonify(ok=True, **res)


@bp.route("/triage", methods=["POST"])
@login_required
def triage():
    """Parse *and* recommend, in one call.

    One endpoint rather than two because the panel has no use for a parse the
    operator cannot act on, and two round-trips would let the row the browser
    holds drift from the row the recommendation was computed against — which is
    how a preview ends up describing a payload nobody will ever build.
    """
    body = request.get_json(silent=True) or {}
    text = str(body.get("text") or "")[:MAX_INPUT]
    parsed = fp_triage.parse(text)
    if not parsed["row"]:
        return jsonify(ok=False, error=parsed["error"] or "nothing recognisable",
                       fmt=parsed["fmt"], unmapped=parsed["unmapped"]), 400
    out = fp_triage.triage(parsed["row"], wpp=str(body.get("wpp") or ""))
    payload_field = str(body.get("decode") or parsed["row"].get("http_url") or "")
    return jsonify(ok=True, **parsed, **out,
                   decoded=fp_triage.decode_layers(payload_field))


@bp.route("/decode", methods=["POST"])
@login_required
def decode():
    """Peel encodings off a payload. Separate endpoint because an operator
    pastes a payload on its own far more often than a whole log entry."""
    body = request.get_json(silent=True) or {}
    value = str(body.get("value") or "")[:MAX_INPUT]
    return jsonify(ok=True, layers=fp_triage.decode_layers(value))
