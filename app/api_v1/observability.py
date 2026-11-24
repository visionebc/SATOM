"""/api/v1 observability — what SATOM has recorded about the estate, for machines.

In the NAF Framework's vocabulary this is the **Observability** block: the
configuration history (SATOM's *Source of Truth*: every captured configuration
of every device, content-addressed), the findings of the alert engine, and the
metrics store. Each of them had a page; none had an API. Everything here is
read-only and needs the ``read`` scope.

* ``GET /appliances/<id>/config-history`` — the recorded versions of one
  device's configuration, newest first.
* ``GET /appliances/<id>/config-diff?from=&to=`` — what changed between two
  of them (object paths added / removed / changed, field detail capped).
* ``GET /findings`` — what the alert engine finds right now, evaluated on the
  call, scoped to the token's ADOM.
* ``GET /metrics/query?expr=`` — a read-only MetricsQL query against the
  metrics store, which stays on loopback with no account of its own: this
  route is the only way in from outside, so it accepts only SATOM's own
  series (``satom_*``), answers within 10 s or not at all, and hands a
  product-bound token only the series of its own devices.

Snapshots are recorded with device secrets and runtime noise already stripped
(``services.sot_store``); the diff shows what the page shows, nothing more.
"""
from __future__ import annotations

import math
import re
import time

from flask import g, jsonify, request

from ..extensions import limiter
from ..models import Appliance, visible_appliance_or_404, visible_appliances
from ..models_sot import SotVersion
from . import bp
from .auth import _err, declares_capability, read_gate, token_required

#: Only SATOM's own series. A metric name is anything the query reads that is
#: not a function, a keyword or a label; the store would answer for any
#: series it holds, and it holds nothing that is not ours today -- the
#: allow-list is what keeps that true the day something else writes to it.
METRIC_PREFIX = "satom_"
QUERY_TIMEOUT_S = 10.0
MAX_EXPR_LEN = 2000
MAX_RANGE_S = 90 * 86400

#: An identifier never starts right after a digit: ``[5m]`` is a duration,
#: not the series ``m``.
_IDENT = re.compile(r"(?<![A-Za-z0-9_:.])[A-Za-z_:][A-Za-z0-9_:.]*")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`[^`]*`')
_SELECTOR = re.compile(r"\{[^{}]*\}")
_MODIFIER_GROUP = re.compile(
    r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^()]*\)", re.I)
_STEP = re.compile(r"^\d+(?:ms|s|m|h|d|w)$")

#: MetricsQL / PromQL words that are not series names.
_KEYWORDS = frozenset({
    "by", "without", "on", "ignoring", "group_left", "group_right", "bool",
    "and", "or", "unless", "offset", "limit", "with", "keep_metric_names",
    "interval", "step", "at", "if", "default", "ifnot", "nan", "inf",
})


def _owner():
    return getattr(g, "api_token_owner", None)


# --------------------------------------------------------------------------- #
#  Configuration history                                                       #
# --------------------------------------------------------------------------- #
def _device_slug(appliance: Appliance) -> str:
    from ..services.device_sync import slugify
    return slugify(appliance.name or "")


def _version_for(device: str, ref: str) -> SotVersion | None:
    """A version by id or by content hash, belonging to *device* only."""
    ref = (ref or "").strip()
    if not ref:
        return None
    q = SotVersion.query.filter_by(device=device)
    if ref.isdigit():
        return q.filter(SotVersion.id == int(ref)).first()
    if re.fullmatch(r"[0-9a-f]{64}", ref.lower()):
        return q.filter(SotVersion.sha256 == ref.lower()).first()
    return None


@bp.route("/appliances/<int:id>/config-history", methods=["GET"])
@limiter.limit("60 per minute")
@token_required("read")
@declares_capability("config_history")
def config_history(id):
    """The recorded configuration versions of one device, newest first.

    ``?limit=`` (default 30, at most 200). Each row: ``id``, ``sha256`` (the
    content identity: an unchanged configuration records no new version),
    ``taken_at``, ``last_seen_at``, ``size_raw``, ``size_gz``,
    ``total_objects``, ``section_count``, ``source`` and whether the payload
    was evacuated to the backup server.

    A token restricted to named capabilities must hold ``config_history``.

    Responses:
        200: ``{"appliance": {...}, "device": "<slug>", "versions": [...]}``.
        403: ``capability_denied``.
        404: No such appliance in the token's ADOM.
    """
    denied = read_gate("config_history")
    if denied is not None:
        return denied
    from ..services import sot_store
    a = visible_appliance_or_404(id, user=_owner())
    try:
        limit = max(1, min(int(request.args.get("limit", 30)), 200))
    except (TypeError, ValueError):
        return _err(400, "bad_request", "'limit' must be a number.")
    device = _device_slug(a)
    return jsonify({
        "appliance": {"id": a.id, "name": a.name, "kind": a.kind},
        "device": device,
        "versions": sot_store.history(device, limit=limit),
    })


@bp.route("/appliances/<int:id>/config-diff", methods=["GET"])
@limiter.limit("30 per minute")
@token_required("read")
@declares_capability("config_history")
def config_diff(id):
    """What changed between two recorded versions of one device's configuration.

    ``?from=`` and ``?to=`` are version ids or content hashes from
    ``config-history``; both must belong to this device. The answer lists the
    object paths added, removed and changed (``section/endpoint/key``), with
    per-field detail for the first changed objects, and ``identical`` when
    nothing differs. Secrets were stripped when the versions were recorded.
    A token restricted to named capabilities must hold ``config_history``.

    Responses:
        200: The diff.
        400: ``from`` or ``to`` missing or malformed.
        403: ``capability_denied``.
        404: No such appliance in the token's ADOM, or a version that is not this device's.
        410: A version whose payload is no longer available (``blob_missing``).
    """
    denied = read_gate("config_history")
    if denied is not None:
        return denied
    from ..services import sot_store
    a = visible_appliance_or_404(id, user=_owner())
    device = _device_slug(a)
    ref_a, ref_b = request.args.get("from", ""), request.args.get("to", "")
    if not ref_a.strip() or not ref_b.strip():
        return _err(400, "bad_request", "'from' and 'to' (version id or sha256) are required.")
    va, vb = _version_for(device, ref_a), _version_for(device, ref_b)
    if va is None or vb is None:
        return _err(404, "not_found", "No such version for this appliance.")
    out = sot_store.diff(va.id, vb.id)
    if not out.get("ok"):
        return _err(410, "blob_missing",
                    "The payload of one of these versions is no longer available: "
                    + str(out.get("error") or ""))
    out["appliance"] = {"id": a.id, "name": a.name, "kind": a.kind}
    out["device"] = device
    return jsonify(out)


# --------------------------------------------------------------------------- #
#  Findings                                                                    #
# --------------------------------------------------------------------------- #
def _finding_visible(f: dict, product: str) -> bool:
    """A product-bound token sees its own product's findings only; the
    installation's own (no product) are Global."""
    if product == "global":
        return True
    return (f.get("product") or "") == product


@bp.route("/findings", methods=["GET"])
@limiter.limit("6 per minute")
@token_required("read")
@declares_capability("findings")
def findings():
    """What the alert engine finds right now, scoped to the token's ADOM.

    Evaluates every enabled check on the call (the same evaluation as
    Settings → Alerts → Preview), so it costs what a check cycle costs and is
    rate-limited to 6/min. Each finding: ``key``, ``severity``
    (``critical``/``warning``/``info``), ``title``, ``detail`` and, for a
    device finding, ``product``. A token bound to a product receives that
    product's findings only; the installation's own (certificate, host,
    backup, code) need a ``global`` token. A token restricted to named
    capabilities must hold ``findings`` (or ``monitoring``).

    Responses:
        200: ``{"evaluated_at": ..., "node": ..., "findings": [...]}``.
        403: ``capability_denied``.
    """
    denied = read_gate("findings")
    if denied is not None:
        return denied
    from ..services import alerts
    product = (g.api_token.product or "global")
    rows = [f for f in alerts.evaluate() if _finding_visible(f, product)]
    from ..services import alert_routing
    out = []
    for f in rows:
        out.append({
            "key": f.get("key", ""),
            "family": alert_routing.family_of(f.get("key", "")),
            "severity": f.get("severity", ""),
            "title": f.get("title", ""),
            "detail": f.get("detail", ""),
            "product": f.get("product", ""),
        })
    return jsonify({"evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "node": alerts._node(), "product": product,
                    "count": len(out), "findings": out})


# --------------------------------------------------------------------------- #
#  Metrics query proxy                                                         #
# --------------------------------------------------------------------------- #
def metric_names(expr: str) -> list[str]:
    """Every series name an expression reads.

    Strings, label selectors and modifier groups (``by (...)``, ``on (...)``)
    are blanked first: what is left and is not followed by ``(`` nor a
    keyword is a metric name. Deliberately conservative: an identifier the
    parser cannot classify counts as a metric, so it has to carry the prefix.
    """
    text = _STRING.sub('""', expr)
    text = _SELECTOR.sub("{}", text)
    text = _MODIFIER_GROUP.sub(" ", text)
    names: list[str] = []
    for m in _IDENT.finditer(text):
        word = m.group(0)
        rest = text[m.end():].lstrip()
        if rest.startswith("("):
            continue                      # a function
        if word.lower() in _KEYWORDS:
            continue
        if re.fullmatch(r"\d+(?:ms|s|m|h|d|w|y)", word):
            continue
        if word not in names:
            names.append(word)
    return names


def allowed_expression(expr: str) -> tuple[bool, str]:
    """``(ok, reason)``: non-empty, bounded, and every series name is ours."""
    if not expr or not expr.strip():
        return False, "'expr' is required."
    if len(expr) > MAX_EXPR_LEN:
        return False, "'expr' is longer than %d characters." % MAX_EXPR_LEN
    names = metric_names(expr)
    if not names:
        return False, "'expr' names no series; it must read at least one satom_* metric."
    bad = [n for n in names if not n.startswith(METRIC_PREFIX)]
    if bad:
        return False, ("only SATOM's own series (%s*) can be queried; refused: %s"
                       % (METRIC_PREFIX, ", ".join(bad[:5])))
    return True, ""


def _series_visible(metric: dict, product: str, devices: set[str]) -> bool:
    """A global token reads every series. A product-bound token reads only
    series labelled with one of its devices (``device`` / ``kind``): the
    nodes' own readings and other products' devices stay out."""
    if product == "global":
        return True
    kind = metric.get("kind") or ""
    device = metric.get("device") or metric.get("appliance") or ""
    if kind and kind != product:
        return False
    return bool(device) and device in devices


def _filter_result(data: dict, product: str, devices: set[str]) -> dict:
    result = (data.get("data") or {}).get("result")
    if not isinstance(result, list):
        return data
    kept = [r for r in result
            if _series_visible((r or {}).get("metric") or {}, product, devices)]
    data = dict(data)
    data["data"] = dict(data.get("data") or {}, result=kept)
    return data


@bp.route("/metrics/query", methods=["GET"])
@limiter.limit("60 per minute")
@token_required("read")
@declares_capability("metrics")
def metrics_query():
    """A read-only MetricsQL query against SATOM's metrics store.

    ``?expr=`` is evaluated as an instant query, or as a range query when
    ``start`` and ``end`` (unix seconds) are given, with ``step`` (``60s``,
    ``5m``, ...; default ``60s``; a range of at most 90 days). Only SATOM's
    own series (``satom_*``) may be read: an expression naming any other
    series is refused before it reaches the store. The store answers within
    10 s or the call is a 504. A token bound to a product receives only the
    series of that product's devices; a ``global`` token receives everything,
    the SATOM nodes' own readings included. The store itself stays on
    loopback; this route is the only way in from outside. A token restricted
    to named capabilities must hold ``metrics`` (or ``monitoring``).

    Responses:
        200: The store's answer (``status``, ``data.resultType``, ``data.result``).
        400: Missing or refused expression, bad ``start``/``end``/``step``.
        403: ``capability_denied``.
        502: The store answered an error (``store_unavailable``).
        504: The store did not answer within 10 s (``store_timeout``).
    """
    denied = read_gate("metrics")
    if denied is not None:
        return denied
    from ..services import vm_store
    expr = request.args.get("expr", "")
    ok, reason = allowed_expression(expr)
    if not ok:
        return _err(400, "bad_request", reason)
    start, end = request.args.get("start"), request.args.get("end")
    step = (request.args.get("step") or "60s").strip()
    if (start is None) != (end is None):
        return _err(400, "bad_request", "'start' and 'end' go together.")
    product = g.api_token.product or "global"
    devices: set[str] = set()
    if product != "global":
        devices = {a.name for a in visible_appliances(user=_owner())
                   .with_entities(Appliance.name).all()}
    t0 = time.monotonic()
    if start is None:
        data = vm_store.query(expr, timeout=QUERY_TIMEOUT_S)
    else:
        try:
            s, e = float(start), float(end)
        except (TypeError, ValueError):
            return _err(400, "bad_request", "'start' and 'end' must be unix seconds.")
        # float() also parses "nan" and "inf": NaN fails every comparison
        # below, so it would slip past the range check into the store.
        if not (math.isfinite(s) and math.isfinite(e)):
            return _err(400, "bad_request", "'start' and 'end' must be unix seconds.")
        if e <= s or (e - s) > MAX_RANGE_S:
            return _err(400, "bad_request",
                        "'end' must be after 'start' and the range at most 90 days.")
        if not _STEP.match(step):
            return _err(400, "bad_request", "'step' must look like 60s, 5m or 1h.")
        data = vm_store.query_range(expr, s, e, step=step, timeout=QUERY_TIMEOUT_S)
    elapsed = time.monotonic() - t0
    if data.get("status") != "success":
        detail = str(data.get("error") or "")[:300]
        if "timed out" in detail or elapsed >= QUERY_TIMEOUT_S:
            return _err(504, "store_timeout",
                        "The metrics store did not answer within %d s." % QUERY_TIMEOUT_S)
        return _err(502, "store_unavailable",
                    "The metrics store did not answer the query: " + detail)
    return jsonify(_filter_result(data, product, devices))
