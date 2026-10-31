"""Plugin Studio > Apps -- the Troubleshooting steps.

The six pages that were Fleet > Troubleshooting (Backend Reachability, Config
Compare, HTTP Observatory, Path Diagnostics, Transaction Tracer, Diagnose Log
Collection) as diagram steps, so each one also runs as a Plugin Studio app.
The apps are PLUGINS, delivered like every other one: the packages
``backend-reachability``, ``config-compare``, ``http-observatory``,
``path-diagnostics``, ``transaction-tracer`` and ``diagnose-log-collection``
of the internal generator (``satom-dev/satom-plugins``), imported in Plugin
Studio > Apps and filed under the menu group *Troubleshooting* of Plugins.
The pages stay and keep answering by URL; both call the same code.

Each step is an ADAPTER over what the page already runs -- nothing is
decided here a second time:

* ``reach_check``      -- ``reach_batch.parse_batch`` + ``run_batch``;
* ``config_compare``   -- ``config_compare.parse_batch`` + ``run_batch``;
* ``observatory_scan`` -- ``observatory_scan.targets_for`` (no site named:
  the list) or ``find_target`` + ``observatory.run`` (the grade, stored like
  a page scan) and the page's own answer, ``views.observatory._view``;
* ``path_walk``        -- ``scout_ladder.run`` with the site's walk defaults,
  then the page's metrics panel and saved report (``views.scout._save``);
* ``txn_trace``        -- ``views.txn_trace.trace``, the page's ``/run``;
* ``log_collect``      -- ``views.logs.start_collection``, the page's
  ``/collect``, then waits for that collection to end.

THE PAGE'S PERMISSIONS, NOT THE APP'S ACCESS LIST
-------------------------------------------------
An app is visible to the people its author ticked. Each step asks the user
who RUNS it for what the page route asks (:data:`PERMISSION`; Path
Diagnostics also its site switch; the tracer its free-target, reveal and
mutating-method gates, which ``trace`` applies as that user), so an app never
widens who probes, compares or collects.

THE RUN'S ADOM AND USER
-----------------------
Every step runs inside ``studio_dns.as_operator``: a request context carrying
the run's ADOM and its user, so ``visible_appliances()``, the ADOM's
diagnostic battery and ``current_user`` are the page's. A run without a user
(a schedule, an event) is refused.

NOTHING HERE WRITES TO A DEVICE
-------------------------------
Every step reads (REST reads, TCP / HTTP probes, read-only SSH guarded by
``assert_readonly``). The one exception is the tracer with a mutating method
(POST, PUT, PATCH, DELETE), which writes to the TARGET APPLICATION: a
rehearsal describes it instead of sending it. Each run is audited with the
page's action and ``via: plugin studio``.
"""
from __future__ import annotations

import json
import time

from . import studio_flow as F

GROUP = "satom"
KIND_KEYS = ("reach_check", "config_compare", "observatory_scan", "path_walk",
             "txn_trace", "log_collect")
#: Read-only steps: a rehearsal runs them (like dns_lookup). The tracer's
#: mutating methods are rehearsed inside :func:`run` instead.
WRITE_KINDS: tuple = ()
DEVICE_KINDS: tuple = ()
DEFAULT_SAVE_AS = {"reach_check": "reach", "config_compare": "compare",
                   "observatory_scan": "scan", "path_walk": "walk",
                   "txn_trace": "trace", "log_collect": "collection"}
#: The permission of the page route each step stands for.
PERMISSION = {"reach_check": "view", "config_compare": "view", "observatory_scan": "view",
              "path_walk": "view", "txn_trace": "view", "log_collect": "config_write"}
PAGE = {"reach_check": "Backend Reachability", "config_compare": "Config Compare",
        "observatory_scan": "HTTP Observatory", "path_walk": "Path Diagnostics",
        "txn_trace": "Transaction Tracer", "log_collect": "Diagnose Log Collection"}
VIA = "plugin studio"
#: How often log_collect looks at the collection it started.
POLL_S = 2.0
#: A saved value stays under the run's limit (studio_flow.MAX_VALUE_BYTES).
_FIT = int(F.MAX_VALUE_BYTES * 0.9)


# --------------------------------------------------------------------------- #
#  the step kinds                                                              #
# --------------------------------------------------------------------------- #
def kinds() -> list:
    P, K = F.Param, F.Kind

    def flag(name, label, help_, default="no"):
        return P(name, label, default=default, help=help_ + " yes / no, or {{ form.%s }}." % name)

    def lines(what):
        return P("entries", "Services", "textarea", True,
                 help="One per line, 'source;policy;destination' -- appliance names or hosts "
                      "(%s), e.g. {{ form.entries }}." % what)

    def appliance(help_):
        return P("appliance", "Appliance (id)", required=True, help=help_)
    return [
        K("reach_check", "Backend Reachability", GROUP,
          "For each 'source;policy;destination' line: does the FortiWeb server policy exist "
          "and can its backends be reached (TCP from SATOM, ping from the appliance with SSH). "
          "The Backend Reachability page's check. Saves the report with rows (one per line), "
          "findings and tsv. Reads only. Needs the view permission.",
          [lines("the destination is optional"),
           flag("ssh", "Ping from the appliance (SSH)", "Add the appliance vantage point."),
           P("timeout", "TCP timeout (s)", default="2", help="0.5 to 10."),
           P("budget", "Time budget (s)", default="120", help="10 to 300."),
           F._save_as("reach")]),
        K("config_compare", "Config Compare", GROUP,
          "For each 'source;policy;destination' line: the server policy and every object "
          "behind it on the source FortiWeb, compared with the same on the destination. The "
          "Config Compare page's check. Saves the report with rows (one per line), differences "
          "and tsv. Reads only. Needs the view permission.",
          [lines("the destination is required"),
           P("budget", "Time budget (s)", default="180", help="10 to 600."),
           F._save_as("compare")]),
        K("observatory_scan", "HTTP Observatory", GROUP,
          "Grade a site a FortiWeb server policy or a FortiADC virtual server publishes "
          "(headers, TLS, cookies, redirects), stored like a page scan, with the findings and "
          "who produces each. With no policy, the appliance's published sites and their last "
          "grade. Reads only. Needs the view permission.",
          [appliance("A FortiWeb or FortiADC of this ADOM, e.g. {{ form.appliance }}."),
           P("policy", "Server policy / virtual server",
             help="Empty: list the published sites instead of grading one."),
           P("host", "Site name (Host / SNI)",
             help="A bare host name; empty = the policy's first protected hostname."),
           F._save_as("scan")]),
        K("path_walk", "Path Diagnostics", GROUP,
          "Walk the path to a published site rung by rung (DNS, VIP, policy, backends, "
          "certificates, logs) and say where it breaks. The Path Diagnostics page's walk, with "
          "the site's walk defaults; the report is saved like a page walk. Reads only. Needs "
          "the view permission and Path Diagnostics switched on.",
          [appliance("A FortiWeb or FortiADC of this ADOM, e.g. {{ form.appliance }}."),
           P("policy", "Server policy / virtual server", required=True),
           P("hostname", "Hostname"), P("port", "Port", default="0", help="0 = auto."),
           P("scheme", "Scheme", default="https", help="https or http."),
           P("path", "Path", default="/"),
           flag("use_ssh", "Probe from the appliance (SSH)", "Use the appliance vantage point."),
           P("window_minutes", "Log window (minutes)",
             help="Empty: the site default (Settings > Path Diagnostics)."),
           P("analyzer", "FortiAnalyzer (id)", help="Optional: read its logs too."),
           P("faz_adom", "FortiAnalyzer ADOM"), P("faz_devid", "FortiAnalyzer device id"),
           P("faz_vdom", "FortiAnalyzer VDOM"),
           F._save_as("walk")]),
        K("txn_trace", "Transaction Tracer", GROUP,
          "Send one request through the appliance (the VIP, leg A) and straight to the "
          "backend (leg C) and compare them: status, headers, cookies, body, timing. The "
          "Transaction Tracer page's trace, with its gates: a free target needs "
          "monitoring.probe_free, revealing values monitoring.reveal_secrets, and a POST / "
          "PUT / PATCH / DELETE both the permission and the confirmation (a rehearsal never "
          "sends it). Needs the view permission.",
          [P("vip", "VIP / site", help="host[:port] or a URL, e.g. {{ form.vip }}."),
           P("backend", "Backend", help="host[:port] or a URL."),
           P("mode_a", "VIP target", default="inventory",
             help="inventory (an appliance SATOM manages) or free."),
           P("mode_c", "Backend target", default="free", help="inventory or free."),
           P("method", "Method", default="GET"), P("path", "Path", default="/"),
           P("headers", "Headers", "textarea", help="'Name: value', one per line (no Host)."),
           P("body", "Body", "textarea"),
           flag("reveal", "Reveal credential values", "Show cookie / token values."),
           flag("confirm_mutating", "Confirm a writing method",
                "Required to send POST, PUT, PATCH or DELETE."),
           F._save_as("trace")]),
        K("log_collect", "Diagnose Log Collection", GROUP,
          "Run this ADOM's diagnostic battery (Administrator > Diagnostic Battery), or the "
          "commands given, over read-only SSH on the devices picked, and wait for the "
          "collection to end. The Diagnose Log Collection page's run: one collection at a "
          "time on the node. Needs the config_write permission.",
          [P("appliances", "Devices (ids)", required=True,
             help="One id, several separated by commas or new lines, or 'all' for every "
                  "device of this ADOM, e.g. {{ form.appliance }}."),
           P("label", "Label", default="plugin"),
           P("commands", "Commands", "textarea",
             help="Empty: the ADOM's battery. Otherwise get / show / diagnose commands, one "
                  "per line, held to the battery's rule."),
           F._save_as("collection")]),
    ]


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #
def _s(node, ctx, name, default="") -> str:
    v = F.render(F._p(node, name, default), ctx.scope())
    return "" if v is None else str(v).strip()


def _truthy(v) -> bool:
    return v is True or str(v or "").strip().lower() in ("yes", "true", "1", "on")


def _num(raw, default: float, lo: float, hi: float) -> float:
    """The page's clamp: an unreadable value is the default."""
    try:
        return max(lo, min(float(str(raw).strip() or default), hi))
    except (TypeError, ValueError):
        return default


def _int(raw, default: int = 0) -> int:
    try:
        return int(str(raw).strip() or default)
    except (TypeError, ValueError):
        return default


def need(ctx, kind: str) -> None:
    perm = PERMISSION[kind]
    u = ctx.user_obj
    if not (u is not None and getattr(u, "can", None) and u.can(perm)):
        raise F.FlowError("this step needs the %s permission (the %s page asks the same); the "
                          "user running the app does not hold it" % (perm, PAGE[kind]))


def _appliance(raw, kinds: tuple, what: str):
    """A visible appliance of one of *kinds*, by id -- the page's lookup."""
    from ..models import Appliance, visible_appliances
    try:
        aid = int(str(raw).strip())
    except (TypeError, ValueError):
        raise F.FlowError("%r is not an appliance id" % raw) from None
    a = visible_appliances().filter(Appliance.id == aid).first()
    if a is None:
        raise F.FlowError("no appliance %s in this ADOM" % aid)
    if (a.kind or "fortiweb") not in kinds:
        raise F.FlowError("%s is a %s; %s takes %s" % (a.name, a.kind, what, " or ".join(kinds)))
    return a


def _size(value) -> int:
    return len(json.dumps(value, default=str))


def fit(res: dict, heavy: tuple) -> dict:
    """Keep *res* under the run's value limit: drop the *heavy* keys (paths
    into the dict, ``("lines", "*", "rows")``) one after the other, marking
    what went in ``trimmed``. The rows, totals and tsv stay."""
    for path in heavy:
        if _size(res) <= _FIT:
            break
        _drop(res, list(path))
        res.setdefault("trimmed", []).append(".".join(path))
    if _size(res) > _FIT:
        raise F.FlowError("the result is larger than a run can keep (%d KB); give fewer lines"
                          % (_size(res) // 1024))
    return res


def _drop(obj, path):
    if not path:
        return
    head, rest = path[0], path[1:]
    if head == "*" and isinstance(obj, list):
        for item in obj:
            _drop(item, rest)
    elif isinstance(obj, dict) and head in obj:
        if rest:
            _drop(obj[head], rest)
        else:
            obj.pop(head, None)


def _audit(action: str, target: str, extra: dict) -> None:
    from .audit import log_action
    log_action(action, target=target, extra=dict(extra, via=VIA))


# --------------------------------------------------------------------------- #
#  rows the Output step shows                                                  #
# --------------------------------------------------------------------------- #
def reach_rows(report: dict) -> list[dict]:
    return [{"Line": ln.get("lineno"), "Source": ln.get("source") or "",
             "Policy": ln.get("policy") or "", "Destination": ln.get("destination") or "",
             "Verdict": ln.get("verdict") or "",
             "Findings": ln.get("error") or "; ".join(
                 "%s: %s" % (f.get("verdict"), f.get("text")) for f in ln.get("findings") or [])}
            for ln in report.get("lines") or []]


def compare_rows(report: dict) -> list[dict]:
    out = []
    for ln in report.get("lines") or []:
        c = ln.get("counts") or {}
        out.append({"Line": ln.get("lineno"), "Source": ln.get("source") or "",
                    "Policy": ln.get("policy") or "",
                    "Destination": ln.get("destination") or "",
                    "Verdict": ln.get("verdict") or "", "Same": c.get("same", 0),
                    "Changed": c.get("changed", 0), "Renamed": c.get("renamed", 0),
                    "Only source": c.get("only_source", 0),
                    "Only destination": c.get("only_destination", 0),
                    "Error": ln.get("error") or ""})
    return out


def compare_differences(report: dict) -> list[dict]:
    out = []
    for ln in report.get("lines") or []:
        for r in ln.get("rows") or []:
            if r.get("state") == "same":
                continue
            flds = r.get("fields_all") or r.get("fields") or []
            out.append({"Line": ln.get("lineno"), "Object": r.get("label") or r.get("kind"),
                        "Kind": r.get("kind") or "", "State": r.get("state") or "",
                        "Source name": r.get("src_name") or "",
                        "Destination name": r.get("dst_name") or "",
                        "Fields": "; ".join("%s: %s -> %s" % (f.get("field"), f.get("src"),
                                                               f.get("dst"))
                                            for f in flds[:20])
                        + (" (+%d)" % (len(flds) - 20) if len(flds) > 20 else "")})
    return out


def finding_rows(findings: list) -> list[dict]:
    return [{"Test": f.get("title") or f.get("test"), "Result": f.get("result") or "",
             "Pass": "yes" if f.get("pass") else "no", "Modifier": f.get("modifier"),
             "Produced by": f.get("who") or "", "Why": f.get("explain") or "",
             "Fixes": ", ".join(x.get("label") or x.get("id") or ""
                                for x in f.get("fixes") or [] if x.get("available"))}
            for f in findings or []]


def layer_rows(report: dict) -> list[dict]:
    return [{"Layer": ly.get("title") or ly.get("key"), "Verdict": ly.get("verdict") or "",
             "Vantage": ly.get("vantage_label") or ly.get("vantage") or "",
             "Headline": ly.get("headline") or "",
             "Evidence": "; ".join("%s: %s" % tuple((list(e) + ["", ""])[:2])
                                   for e in ly.get("evidence") or [])}
            for ly in report.get("layers") or []]


def leg_rows(payload: dict) -> list[dict]:
    rows = []
    for leg in payload.get("legs") or []:
        t = leg.get("timing") or {}
        req = leg.get("request") or {}
        rows.append({"Leg": leg.get("leg"), "Label": leg.get("label") or "",
                     "Request": "%s %s://%s:%s%s" % (req.get("method", ""), req.get("scheme", ""),
                                                     req.get("host", ""), req.get("port", ""),
                                                     req.get("path", "")),
                     "Status": leg.get("status"), "Reason": leg.get("reason") or "",
                     "Error": leg.get("error") or "", "TTFB ms": t.get("ttfb_ms"),
                     "Total ms": t.get("total_ms"), "Body bytes": leg.get("body_bytes")})
    return rows


def collection_rows(progress: dict) -> list[dict]:
    return [{"Device": r.get("device"), "OK": "yes" if r.get("ok") else "no",
             "File": r.get("file") or "", "Ran": r.get("ran"), "Skipped": r.get("skipped"),
             "Error": r.get("error") or r.get("unavailable") or ""}
            for r in (progress or {}).get("results") or []]


# --------------------------------------------------------------------------- #
#  the steps                                                                   #
# --------------------------------------------------------------------------- #
def _reach(node, ctx):
    from . import reach_batch as rb
    text = _s(node, ctx, "entries")
    rows, dropped = rb.parse_batch(text)
    if not rows and not dropped:
        raise F.FlowError("nothing to check -- one line per service, 'source;policy;destination'")
    report = rb.run_batch(rows, use_ssh=_truthy(_s(node, ctx, "ssh", "no")),
                          tcp_timeout=_num(_s(node, ctx, "timeout"), rb.DEFAULT_TCP_TIMEOUT,
                                           0.5, 10.0),
                          budget_s=_num(_s(node, ctx, "budget"), rb.DEFAULT_BUDGET_S, 10.0,
                                        rb.MAX_BUDGET_S),
                          user=ctx.user_obj)
    report["dropped"] = dropped
    report["tsv"] = rb.to_tsv(report)
    report["rows"] = reach_rows(report)
    _audit("reachability.batch", "%d line(s)" % len(rows),
           {"totals": report["totals"], "elapsed_s": report["elapsed_s"],
            "budget_hit": report["budget_hit"]})
    return fit(report, (("lines", "*", "src"), ("lines", "*", "dst"), ("vantages",)))


def _compare(node, ctx):
    from . import config_compare as cc
    rows, dropped = cc.parse_batch(_s(node, ctx, "entries"), max_lines=cc.MAX_LINES)
    if not rows and not dropped:
        raise F.FlowError("nothing to compare -- one line per service, "
                          "'source;policy;destination'")
    budget = _num(_s(node, ctx, "budget"), cc.DEFAULT_BUDGET_S, 10.0, cc.MAX_BUDGET_S)
    report = cc.run_batch(rows, budget_s=budget, user=ctx.user_obj)
    report["dropped"] = dropped
    report["tsv"] = cc.to_tsv(report)
    report["rows"] = compare_rows(report)
    report["differences"] = compare_differences(report)
    _audit("config.compare", "%d line(s)" % len(rows),
           {"totals": report.get("totals"), "elapsed_s": report.get("elapsed_s"),
            "budget_hit": report.get("budget_hit")})
    return fit(report, (("lines", "*", "rows", "*", "fields_all"), ("lines", "*", "rows"),
                        ("tsv",)))


def _observatory(node, ctx):
    from . import observatory, observatory_scan as osc
    from ..views import observatory as ov
    a = _appliance(_s(node, ctx, "appliance"), osc.PRODUCTS, "the HTTP Observatory")
    policy = _s(node, ctx, "policy")
    if not policy:
        try:
            targets = osc.targets_for(a)
        except Exception as exc:  # noqa: BLE001 -- unreadable box: say so, never "no sites"
            raise F.FlowError("could not list the published sites of %s: %s" % (a.name, exc)) \
                from None
        latest = observatory.latest_by_policy(a.id)
        rows = []
        for t in targets:
            d = t.as_dict()
            last = latest.get(t.policy)
            rows.append({"Policy": d.get("policy"), "VIP": d.get("vip") or "",
                         "Host": d.get("default_host") or "",
                         "Scannable": "yes" if d.get("scannable") else "no",
                         "Last grade": (last.grade if last else "") or "",
                         "Last score": last.score if last else None,
                         "_aid": a.id, "_policy": d.get("policy")})
        return {"mode": "targets", "appliance": {"id": a.id, "name": a.name, "kind": a.kind},
                "targets": rows}
    try:
        host = ov._host_arg(_s(node, ctx, "host"))
    except ValueError as exc:
        raise F.FlowError(str(exc)) from None
    try:
        target = osc.find_target(a, policy)
    except Exception as exc:  # noqa: BLE001
        raise F.FlowError("could not read %s: %s" % (a.name, exc)) from None
    if target is None:
        raise F.FlowError("%s has no published site named %s" % (a.name, policy))
    row = observatory.run(a, target, host or None, trigger="manual",
                          username=getattr(ctx.user_obj, "username", "") or ctx.user)
    _audit("observatory.scan", "%s:%s" % (a.name, policy),
           {"appliance_id": a.id, "host": row.host, "grade": row.grade, "score": row.score,
            "error": (row.error or "")[:200]})
    res = ov._view(row, a)
    res["mode"] = "scan"
    res["finding_rows"] = finding_rows(res.get("findings"))
    res["summary"] = {k: res["scan"].get(k) for k in ("policy", "host", "grade", "score",
                                                      "tests_passed", "tests_failed", "error")}
    return fit(res, (("retrieval",), ("analysis",), ("context",)))


def _walk(node, ctx):
    from . import scout_config, scout_ladder as sl, scout_metrics
    from ..models import Appliance, visible_appliances
    from ..views.cert_inspect import _may_free
    from ..views.scout import _save
    if not scout_config.enabled():
        raise F.FlowError("Path Diagnostics is switched off for this site (Settings > Path "
                          "Diagnostics > Availability)")
    a = _appliance(_s(node, ctx, "appliance"), sl.SUPPORTED_KINDS, "Path Diagnostics")
    dflt = scout_config.walk_defaults()
    analyzer = None
    zid = _int(_s(node, ctx, "analyzer"))
    if zid:
        analyzer = (visible_appliances().filter(Appliance.id == zid,
                                                Appliance.kind == "fortianalyzer").first())
        if analyzer is None:
            raise F.FlowError("no FortiAnalyzer %s in this ADOM" % zid)
    target = sl.Target(appliance=a, policy=_s(node, ctx, "policy"),
                       hostname=_s(node, ctx, "hostname"), port=_int(_s(node, ctx, "port")),
                       scheme="http" if _s(node, ctx, "scheme").lower() == "http" else "https",
                       path=_s(node, ctx, "path") or "/", method="GET")
    opts = sl.Options(use_ssh=_truthy(_s(node, ctx, "use_ssh", "no")),
                      timeout=float(dflt["probe_timeout"]),
                      window_minutes=_int(_s(node, ctx, "window_minutes"),
                                          int(dflt["window_minutes"])),
                      analyzer=analyzer,
                      faz_adom=_s(node, ctx, "faz_adom") or dflt["faz_adom"] or "root",
                      faz_devid=_s(node, ctx, "faz_devid") or dflt["faz_devid"] or "",
                      faz_vdom=_s(node, ctx, "faz_vdom") or dflt["faz_vdom"] or "")
    try:
        report = sl.run(target, opts, sl.default_ports(
            analyzer=analyzer, faz_adom=opts.faz_adom, faz_devid=opts.faz_devid,
            faz_vdom=opts.faz_vdom, faz_limit=int(dflt["faz_limit"]),
            faz_timeout=float(dflt["faz_timeout"]), may_free=_may_free()))
    except sl.ScoutRefused as exc:
        raise F.FlowError(str(exc)) from None
    metrics = scout_metrics.context(a.name, target.policy, report["options"]["window_minutes"])
    saved = _save(a, target, opts, report, metrics)
    _audit("scout.walk", "appliance=%s object=%r verdict=%s" % (
        a.name, target.policy, report["verdict"].get("layer") or "no fault localised"),
        {"report_id": saved.id, "metrics": metrics.get("status")})
    res = {"report_id": saved.id, "report_url": "/scout/reports/%d" % saved.id,
           "verdict": {"headline": "", "text": "", "layer": "", **(report.get("verdict") or {})},
           "target": report.get("target"),
           "endpoint": report.get("endpoint"), "endpoint_error": report.get("endpoint_error"),
           "timing": report.get("timing"), "layers": report.get("layers") or [],
           "rows": layer_rows(report), "metrics": metrics}
    return fit(res, (("metrics",), ("layers",)))


def _trace(node, ctx):
    from . import txn_trace as tt
    from ..views.txn_trace import trace
    method = (_s(node, ctx, "method") or "GET").upper()
    body = {"vip": _s(node, ctx, "vip"), "backend": _s(node, ctx, "backend"),
            "mode_a": _s(node, ctx, "mode_a") or "inventory",
            "mode_c": _s(node, ctx, "mode_c") or "free", "method": method,
            "path": _s(node, ctx, "path") or "/", "headers": _s(node, ctx, "headers"),
            "body": _s(node, ctx, "body"), "reveal": _truthy(_s(node, ctx, "reveal", "no")),
            "confirm_mutating": _truthy(_s(node, ctx, "confirm_mutating", "no"))}
    if not ctx.armed and method in tt.MUTATING_METHODS:
        return {"rehearsal": True, "would": {k: v for k, v in body.items() if k != "body"}}, \
            "rehearsal: %s not sent" % method
    payload, status = trace(body)
    if not payload.get("ok"):
        raise F.FlowError("%s (HTTP %d)" % (payload.get("error") or "the trace failed", status))
    payload["rows"] = leg_rows(payload)
    diff = payload.get("diff") or {}
    v = diff.get("verdict") or {}
    # always both keys: a template reading {{ trace.verdict.text }} must not
    # fail when only one leg was traced (no comparison, no verdict)
    payload["verdict"] = {"key": v.get("key") or "", "text": v.get("text") or diff.get("why") or ""}
    return fit(payload, (("legs", "*", "body_preview"), ("legs", "*", "headers"))), None


def parse_ids(raw: str) -> list[int] | None:
    """``None`` = every device of the ADOM ('all'); else the ids given."""
    text = str(raw or "").strip()
    if text.lower() in ("all", "*"):
        return None
    out = []
    for part in text.replace(",", "\n").split():
        try:
            out.append(int(part))
        except ValueError:
            raise F.FlowError("%r is not a device id (ids, or 'all')" % part) from None
    return out


def _collect(node, ctx):
    from . import logcollect
    from ..views import logs as lv
    ids = parse_ids(_s(node, ctx, "appliances"))
    if ids is None:
        ids = [a.id for a in lv._adom_appliances(lv._adom_key())]
    if not ids:
        raise F.FlowError("select at least one device")
    payload, status = lv.start_collection(ids, label=_s(node, ctx, "label") or "plugin",
                                          custom_text=_s(node, ctx, "commands"), via=VIA)
    if not payload.get("ok"):
        raise F.FlowError("%s (HTTP %d)" % (payload.get("error") or "could not start", status))
    started = (payload.get("progress") or {}).get("started")
    deadline = ctx.deadline or (time.time() + F.RUN_TIMEOUT)
    cur = payload.get("progress") or {}
    while True:
        cur = logcollect.status() or {}
        if cur.get("started") != started:
            raise F.FlowError("another collection replaced this one before it ended")
        if cur.get("state") != "running":
            break
        if time.time() > deadline - 5:
            raise F.FlowError("the collection is still running (%s%%); it carries on -- see "
                              "Diagnose Log Collection" % cur.get("percent", 0))
        time.sleep(POLL_S)
    res = {k: cur.get(k) for k in ("state", "label", "by", "total", "done", "percent",
                                   "command_count", "started", "finished", "summary",
                                   "errors", "results")}
    res["errors"] = res.get("errors") or []
    res["results"] = res.get("results") or []
    res["rows"] = collection_rows(cur)
    res["log"] = (cur.get("log") or [])[-200:]
    return fit(res, (("log",),))


_STEPS = {"reach_check": _reach, "config_compare": _compare, "observatory_scan": _observatory,
          "path_walk": _walk, "log_collect": _collect}


def _detail(kind: str, res: dict) -> str:
    if kind == "reach_check":
        t = res.get("totals") or {}
        return "%d line(s): %s%s" % (len(res.get("lines") or []),
                                     ", ".join("%s %s" % (v, k) for k, v in t.items() if v),
                                     ", time budget hit" if res.get("budget_hit") else "")
    if kind == "config_compare":
        t = res.get("totals") or {}
        return "%d line(s): %s, %d difference(s)%s" % (
            len(res.get("lines") or []),
            ", ".join("%s %s" % (v, k) for k, v in t.items() if v),
            len(res.get("differences") or []),
            ", time budget hit" if res.get("budget_hit") else "")
    if kind == "observatory_scan":
        if res.get("mode") == "targets":
            return "%d published site(s) on %s" % (len(res["targets"]), res["appliance"]["name"])
        s = res.get("summary") or {}
        return "%s: grade %s (%s)%s" % (s.get("policy"), s.get("grade") or "-",
                                        s.get("score"),
                                        ", " + s["error"] if s.get("error") else "")
    if kind == "path_walk":
        v = res.get("verdict") or {}
        return "report %s: %s" % (res.get("report_id"),
                                  v.get("headline") or v.get("text") or "no fault localised")
    if kind == "log_collect":
        return "%s of %s device(s) collected, %d error(s)" % (
            sum(1 for r in res.get("results") or [] if r.get("ok")), res.get("total"),
            len(res.get("errors") or []))
    return ""


# --------------------------------------------------------------------------- #
#  the runner (no rehearse: nothing here is in WRITE_KINDS)                    #
# --------------------------------------------------------------------------- #
def run(node: dict, ctx) -> tuple:
    from .studio_dns import as_operator
    kind = node.get("kind")
    if kind not in KIND_KEYS:
        raise F.FlowError("unknown step kind %r" % kind)
    need(ctx, kind)
    with as_operator(ctx):
        if kind == "txn_trace":
            res, why = _trace(node, ctx)
            if why:
                return "ok", res, why
            key = (res.get("verdict") or {}).get("key")
            return "ok", res, "%d leg(s)%s" % (len(res["legs"]), ": " + key if key else "")
        res = _STEPS[kind](node, ctx)
    return "ok", res, _detail(kind, res)
