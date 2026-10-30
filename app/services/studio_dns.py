"""Plugin Studio > Apps -- the DNS & LB Lookup steps.

The DNS & LB Lookup page (``views.dns_tool``, Global > Fleet > DNS Lookup and
its copy in every ADOM) as diagram steps, so the lookup, the DNS Records
editor and the hostname decommission also run as Plugin Studio apps. The
apps are PLUGINS, delivered like every other one: the packages
``dns-lb-lookup``, ``dns-records`` and ``dns-decommission`` of the internal
generator (``satom-dev/satom-plugins``), imported in Plugin Studio > Apps.
The page stays; both call the same modules.

Each step is an ADAPTER over the module the page already uses -- nothing is
decided here a second time:

* ``dns_lookup``             -- ``dns_tool.lookup_many`` over the enabled
  resolvers (Administrator > Objects > DNS Resolvers);
* ``lb_lookup``              -- ``dns_tool.fleet_lb_rows`` + ``match_rows``:
  the device CACHE, never the device (Presentation reads what the Collector
  left);
* ``dns_records``            -- one DNS backend's records (reads);
* ``dns_record_change``      -- create, update or delete one record (writes);
* ``dns_decommission_plan``  -- ``dns_decommission.plan`` (reads only);
* ``dns_decommission_apply`` -- ``dns_decommission.apply``: it plans again and
  refuses a plan whose fingerprint moved, a blocked plan, and warnings nobody
  acknowledged.

THE PAGE'S PERMISSIONS, NOT THE APP'S ACCESS LIST
-------------------------------------------------
An app is visible to the people its author ticked. Each step asks the user
who RUNS it for the permission the page's route asks (``network.view``,
``user_manage``, ``config_write``, :data:`PERMISSION`), so an app never
widens who looks names up, edits a record or retires a service.

THE RUN'S ADOM AND USER
-----------------------
A run walks in a thread with no request, and there ``visible_appliances()``
answers "the whole fleet" (a worker's scope). The steps that read the fleet
therefore run inside :func:`as_operator`: a request context carrying the
run's ADOM (``StudioAppRun.product``) and its user, so the page's scoping
applies -- the ADOM's product, the user's ADOM confinement, maintenance
visibility. A run without a user (a schedule, an event) is refused: these
steps answer for a person.
"""
from __future__ import annotations

import contextlib

from . import studio_flow as F

GROUP = "satom"
KIND_KEYS = ("dns_lookup", "lb_lookup", "dns_records", "dns_record_change",
             "dns_decommission_plan", "dns_decommission_apply")
WRITE_KINDS = ("dns_record_change", "dns_decommission_apply")
DEVICE_KINDS = ("dns_decommission_apply",)
DEFAULT_SAVE_AS = {"dns_lookup": "dns", "lb_lookup": "lb", "dns_records": "records",
                   "dns_record_change": "record", "dns_decommission_plan": "plan",
                   "dns_decommission_apply": "decommission"}
#: The permission of the page route each step stands for (views.dns_tool).
PERMISSION = {"dns_lookup": "network.view", "lb_lookup": "network.view",
              "dns_records": "user_manage", "dns_record_change": "user_manage",
              "dns_decommission_plan": "config_write",
              "dns_decommission_apply": "config_write"}
RECORD_OPS = ("create", "update", "delete")
#: What dig_lookup answers when a resolver gave nothing.
NO_ANSWER = ("No result", "timeout", "error")
#: ``g`` keys :func:`as_operator` sets; saved and put back, because ``g``
#: belongs to the APP context, which an inline run shares with its caller.
_G_KEYS = ("product", "_login_user", "_satom_allowed_adoms")
_MISSING = object()


# --------------------------------------------------------------------------- #
#  the step kinds                                                              #
# --------------------------------------------------------------------------- #
def kinds() -> list:
    P, K = F.Param, F.Kind
    from .dns_tool import MAX_ENTRIES

    def entries():
        return P("entries", "Hostnames / IPs", "textarea", True,
                 help="One per line, optionally 'name TYPE' (app.example.com CNAME), e.g. "
                      "{{ form.entries }}. At most %d; a duplicate is looked up once."
                      % MAX_ENTRIES)

    def flag(name, label, help_):
        return P(name, label, default="no", help=help_ + " yes / no, or {{ form.%s }}." % name)

    def appliance():
        return P("appliance", "Appliance (id)", required=True,
                 help="A FortiWeb or FortiADC of this ADOM, e.g. {{ form.appliance }}.")

    def backend():
        return P("backend", "DNS backend",
                 help="Id or name of a backend with the DNS role (Settings > DNS Records), "
                      "e.g. {{ form.backend }}. Empty: the only one there is; with two or "
                      "more the step refuses to guess.")
    return [
        K("dns_lookup", "DNS: look names up", GROUP,
          "Ask every enabled resolver (Administrator > Objects > DNS Resolvers) for each "
          "name, as the DNS & LB Lookup page does. Saves rows (one per name, a column per "
          "resolver), answers, unresolved and tsv (the page's Copy DNS text). Reads only.",
          [entries(), flag("ttl", "Show TTL", "Add the TTL to every answer."),
           F._save_as("dns")]),
        K("lb_lookup", "LB: match names to the fleet", GROUP,
          "Match each name (and a wildcard's resolved form) to the FortiWeb server "
          "policies and FortiADC virtual servers of this ADOM, from the device cache. "
          "Saves rows (one per match, with Path, _aid, _policy, _url), gateways, "
          "not_found and tsv (Copy LB). Reads only; ends in error when the cache cannot "
          "be read.",
          [entries(), flag("exact", "Exact match", "Whole values only, not substrings."),
           P("dns", "DNS result", help="{{ dns }} -- a dns_lookup result: names with no "
                                       "answer and no match go to not_found."),
           F._save_as("lb")]),
        K("dns_records", "DNS records: list", GROUP,
          "The records one DNS backend holds for a name (or a zone), with the backend's "
          "capabilities. Needs the user_manage permission, like the page's DNS Records.",
          [backend(), P("name", "Name", help="e.g. {{ form.name }}"),
           P("zone", "Zone"), F._save_as("records")]),
        K("dns_record_change", "DNS records: create, change or delete", GROUP,
          "Write one record in a DNS backend. create needs a name and a value; update and "
          "delete need the record's id (from DNS records: list). Audited like the page. "
          "Needs user_manage.",
          [P("operation", "Operation", required=True,
             help="create, update or delete -- or {{ form.operation }}"),
           backend(),
           P("record", "Record (JSON)", "json", True,
             help='{"id": "{{ form.id }}", "name": "{{ form.name }}", "type": '
                  '"{{ form.type }}", "value": "{{ form.value }}", "ttl": "{{ form.ttl }}", '
                  '"zone": "{{ form.zone }}"}'),
           F._save_as("record")], writes=True),
        K("dns_decommission_plan", "Decommission: plan", GROUP,
          "What retiring a service would remove: the server policy or virtual server, "
          "its exclusive dependencies, SNI member, certificate, WAF profile, carve-outs "
          "and DNS records -- with the warnings and blockers, and the fingerprint the "
          "apply step must be given. Reads only. Needs config_write.",
          [appliance(), P("policy", "Server policy / virtual server", required=True),
           P("hostname", "Hostname", help="The name being retired, e.g. {{ form.hostname }}"),
           F._save_as("plan")]),
        K("dns_decommission_apply", "Decommission: apply the plan", GROUP,
          "Plan again and execute it only when the fingerprint is the one shown, the plan "
          "is not blocked and its warnings were acknowledged (an Ask step with "
          "'Must be acknowledged'). Writes to the appliance and the DNS backend; audited "
          "like the page. Needs config_write.",
          [appliance(), P("policy", "Server policy / virtual server", required=True),
           P("hostname", "Hostname"),
           P("confirm", "Confirmed fingerprint", required=True,
             help="{{ plan.fingerprint }} -- of the plan the person saw."),
           P("acknowledge", "Warnings acknowledged",
             help="{{ last_answer.all_acknowledged }} -- true only when the Ask step's "
                  "warnings were all ticked."),
           F._save_as("decommission")], writes=True),
    ]


def _truthy(v) -> bool:
    return v is True or str(v or "").strip().lower() in ("yes", "true", "1", "on")


# --------------------------------------------------------------------------- #
#  who runs it                                                                 #
# --------------------------------------------------------------------------- #
def need(ctx, kind: str) -> None:
    perm = PERMISSION[kind]
    u = ctx.user_obj
    if not (u is not None and getattr(u, "can", None) and u.can(perm)):
        raise F.FlowError("this step needs the %s permission (the DNS & LB Lookup page asks "
                          "the same); the user running the app does not hold it" % perm)


def run_product(ctx) -> str:
    if not ctx.run_id:
        return ""
    from ..extensions import db
    from ..models_studio import StudioAppRun
    run = db.session.get(StudioAppRun, ctx.run_id)
    return (run.product if run is not None else "") or ""


@contextlib.contextmanager
def as_operator(ctx):
    """Run the body as the run's user, in the run's ADOM (module docstring)."""
    if ctx.user_obj is None:
        raise F.FlowError("this step answers for the person who runs the app; a run "
                          "without a user (a schedule or an event) cannot use it")
    from flask import current_app, g
    product = run_product(ctx)
    with current_app.test_request_context("/"):
        saved = {k: g.pop(k, _MISSING) for k in _G_KEYS}
        g.product = product
        g._login_user = ctx.user_obj
        try:
            yield
        finally:
            for k in _G_KEYS:
                g.pop(k, None)
            for k, v in saved.items():
                if v is not _MISSING:
                    setattr(g, k, v)


# --------------------------------------------------------------------------- #
#  DNS                                                                         #
# --------------------------------------------------------------------------- #
def clean_entries(raw) -> tuple[list[str], int]:
    """``(entries, dropped)``: cleaned, unique, at most MAX_ENTRIES (the page's
    rule); *dropped* is how many valid ones were cut."""
    from . import dns_tool
    lines = [str(x) for x in raw] if isinstance(raw, (list, tuple)) else str(raw or "").splitlines()
    out = []
    for line in lines:
        e = dns_tool.clean_entry(line)
        if e and e not in out:
            out.append(e)
    return out[:dns_tool.MAX_ENTRIES], max(0, len(out) - dns_tool.MAX_ENTRIES)


def dns_lookup(entries: list[str], *, ttl: bool = False) -> dict:
    from . import dns_tool
    servers = [s for s in dns_tool.dns_servers() if s.get("enabled", True)]
    if not servers:
        raise F.FlowError("no DNS resolver is configured: Administrator > Objects > "
                          "DNS Resolvers")
    found = dns_tool.lookup_many(entries, servers, show_ttl=ttl)
    names = [s["name"] for s in servers]
    rows, answers, resolved_of, unresolved = [], {}, {}, []
    tsv = ["\t".join(["Entry"] + names)]
    for e in entries:
        query, _rtype = dns_tool.parse_entry(e)
        resolved = dns_tool.resolve_wildcard(query)
        per = {n: found.get((e, n), ["No result"]) for n in names}
        answers[e], resolved_of[e] = per, resolved
        if all(all(v in NO_ANSWER for v in vals) for vals in per.values()):
            unresolved.append(e)
        row = {"Entry": e if resolved == query else "%s (as %s)" % (e, resolved)}
        row.update({n: "; ".join(per[n]) for n in names})
        row.update({"_entry": e, "_resolved": resolved})
        rows.append(row)
        tsv.append("\t".join([e] + ["; ".join(per[n]) for n in names]))
    return {"entries": entries, "servers": names, "rows": rows, "answers": answers,
            "resolved": resolved_of, "unresolved": unresolved, "tsv": "\n".join(tsv)}


# --------------------------------------------------------------------------- #
#  LB                                                                          #
# --------------------------------------------------------------------------- #
def policy_url(m: dict) -> str:
    """The page's "Open policy" link (dns_lookup/index.html)."""
    from flask import url_for
    if not m.get("policy") or not m.get("_aid"):
        return ""
    try:
        if m.get("_kind") == "fortiadc":
            return url_for("adc.use_device", id=m["_aid"], next=url_for(
                "adc.object_detail", logical="load_balance_virtual_server", mkey=m["policy"]))
        return url_for("workspace.policy_detail", appliance_id=m["_aid"], name=m["policy"])
    except Exception:  # noqa: BLE001 -- a link is a convenience, never the answer
        return ""


def path_of(m: dict) -> str:
    """The page's mini topology as text: policy (status) > pool > members."""
    def st(x):
        return " (%s)" % x if x else ""
    parts = ["%s%s" % (m.get("policy") or "?", st(m.get("status")))]
    if m.get("pool"):
        parts.append(str(m["pool"]))
    back = ["%s%s%s" % (b.get("ip") or "?", ":%s" % b["port"] if b.get("port") else "",
                        st(b.get("status"))) for b in (m.get("_backends") or [])
            if isinstance(b, dict)]
    parts.append(", ".join(back) or "no backends in cache")
    return " > ".join(parts)


def lb_lookup(entries: list[str], lb_rows: list[dict], *, exact: bool = False,
              dns: dict | None = None) -> dict:
    from . import dns_tool
    rows, gateways, unmatched = [], [], []
    tsv = ["\t".join(label for _k, label in dns_tool.COLUMNS)]
    for e in entries:
        query, _rtype = dns_tool.parse_entry(e)
        resolved = dns_tool.resolve_wildcard(query)
        matches = dns_tool.match_rows(lb_rows, query, resolved, exact=exact)
        if not matches:
            unmatched.append(e)
        gateways.append({"Entry": e, "Gateways": ", ".join(
            sorted({str(m.get("gateway") or "") for m in matches} - {""})) or "-",
            "_entry": e})
        for m in matches:
            row = {"Entry": e}
            row.update({label: m.get(k, "") for k, label in dns_tool.COLUMNS})
            row["Path"] = path_of(m)
            row.update({"_entry": e, "_hostname": resolved, "_aid": m.get("_aid"),
                        "_kind": m.get("_kind") or "", "_policy": m.get("policy") or "",
                        "_url": policy_url(m)})
            rows.append(row)
            tsv.append("\t".join(str(m.get(k, "")) for k, _l in dns_tool.COLUMNS))
    not_found = []
    if isinstance(dns, dict) and isinstance(dns.get("unresolved"), list):
        nores = set(dns["unresolved"])
        not_found = [e for e in unmatched if e in nores]
    return {"rows": rows, "gateways": gateways, "unmatched": unmatched,
            "not_found": not_found, "tsv": "\n".join(tsv)}


# --------------------------------------------------------------------------- #
#  DNS records                                                                 #
# --------------------------------------------------------------------------- #
def backend_row(raw):
    """The backend a step acts on -- ``views.dns_tool._records_backend``'s
    rule: a named one (id, or a name no other backend has), else the only
    one; with two or more and none named, refuse rather than write into
    whichever sorts first."""
    from . import dns_providers
    rows = dns_providers.enabled_backends("dns")
    if not rows:
        raise F.FlowError("no backend carries the DNS role: configure one in "
                          "Settings > DNS Records")
    raw = str(raw or "").strip()
    if raw:
        hit = [r for r in rows if str(r.id) == raw] or [r for r in rows if r.name == raw]
        if len(hit) == 1:
            return hit[0]
        if hit:
            raise F.FlowError("%d DNS backends are called %r: name it by id" % (len(hit), raw))
        raise F.FlowError("DNS backend %r is gone, disabled, or no longer carries the DNS "
                          "role" % raw)
    if len(rows) == 1:
        return rows[0]
    raise F.FlowError("%d DNS backends are configured (%s): say which one this record "
                      "belongs to" % (len(rows), ", ".join("%s=%s" % (r.id, r.name) for r in rows)))


def _backend_dict(row) -> dict:
    try:
        zones = row.zone_list()
    except Exception:  # noqa: BLE001
        zones = []
    return {"id": row.id, "name": row.name, "zones": zones}


def list_records(row, *, name: str = "", zone: str = "") -> dict:
    from .dns_providers import ProviderError
    prov = row.instance()
    try:
        caps = prov.capabilities().as_dict()
        recs = prov.list_records(name=name, zone=zone)
    except ProviderError as exc:
        raise F.FlowError("%s: %s" % (row.name, exc)) from None
    return {"backend": _backend_dict(row), "capabilities": caps, "name": name, "zone": zone,
            "records": [r.as_dict() for r in recs]}


def record_of(raw) -> object:
    from .dns_providers import DnsRecord
    if not isinstance(raw, dict):
        raise F.FlowError("the record is an object of id, name, type, value, ttl, zone")
    return DnsRecord.from_form({k: ("" if v is None else v) for k, v in raw.items()})


def check_record(op: str, rec) -> None:
    if op not in RECORD_OPS:
        raise F.FlowError("operation %r: %s" % (op, ", ".join(RECORD_OPS)))
    if op == "create" and (not rec.name or not rec.value):
        raise F.FlowError("a new record needs a name and a value")
    if op in ("update", "delete") and not rec.id:
        raise F.FlowError("%s needs the record's id (from DNS records: list)" % op)


def change_record(row, op: str, rec) -> dict:
    from .audit import log_action
    from .dns_providers import ProviderError
    check_record(op, rec)
    prov = row.instance()
    try:
        if op == "create":
            saved = prov.create_record(rec)
        elif op == "update":
            saved = prov.update_record(rec)
        else:
            prov.delete_record(rec)
            saved = rec
    except ProviderError as exc:
        raise F.FlowError("%s: %s" % (row.name, exc)) from None
    log_action("dns_records." + op, target="%s:%s %s" % (row.name, rec.type, rec.name),
               extra={"via": "plugin studio"})
    return {"operation": op, "backend": _backend_dict(row), "record": saved.as_dict()}


# --------------------------------------------------------------------------- #
#  decommission                                                                #
# --------------------------------------------------------------------------- #
def visible_appliance(raw):
    """``visible_appliance_or_404`` without the abort: inside as_operator, so
    another ADOM's device and a hidden maintenance row are "not here"."""
    from werkzeug.exceptions import NotFound
    from ..models import visible_appliance_or_404
    s = str(raw or "").strip()
    if not s.isdigit():
        raise F.FlowError("appliance %r: an appliance id is expected" % s)
    try:
        a = visible_appliance_or_404(int(s))
    except NotFound:
        raise F.FlowError("no appliance %s in this ADOM" % s) from None
    if (getattr(a, "kind", "") or "fortiweb") not in ("fortiweb", "fortiadc"):
        raise F.FlowError("%s is a %s: only a FortiWeb server policy or a FortiADC virtual "
                          "server can be decommissioned" % (a.name, a.kind))
    return a


def plan_rows(plan: dict) -> list[dict]:
    titles = {s["key"]: s["title"] for s in plan.get("stages") or []}
    return [{"Stage": titles.get(i.get("stage"), i.get("stage")), "Object": i.get("label"),
             "Kind": i.get("kind"), "Action": i.get("action"), "Why": i.get("reason") or "",
             "Still used by": ", ".join(str(h) for h in i.get("holders") or [])}
            for i in plan.get("items") or []]


# --------------------------------------------------------------------------- #
#  rehearsal and the runner                                                    #
# --------------------------------------------------------------------------- #
def _s(node, ctx, name, default="") -> str:
    v = F.render(F._p(node, name, default), ctx.scope())
    return "" if v is None else str(v).strip()


def rehearse(node: dict, ctx) -> tuple:
    kind = node.get("kind")
    if kind == "dns_record_change":
        op = _s(node, ctx, "operation").lower()
        rec = record_of(F._json(node, ctx, "record", "Record"))
        check_record(op, rec)
        return "ok", {"operation": op, "backend": {"id": None, "name": _s(node, ctx, "backend")},
                      "record": rec.as_dict(), "rehearsal": True}, \
            "rehearsal: would %s %s %s %s in %s" % (op, rec.type, rec.name, rec.value or rec.id,
                                                   _s(node, ctx, "backend") or "the DNS backend")
    return "ok", {"ok": True, "results": [], "summary": {"total": 0, "ok": 0, "failed": 0},
                  "rehearsal": True}, \
        "rehearsal: would decommission %s on appliance %s (plan %s)" % (
            _s(node, ctx, "policy"), _s(node, ctx, "appliance"), _s(node, ctx, "confirm")[:12])


def run(node: dict, ctx) -> tuple:
    kind = node.get("kind")
    need(ctx, kind)
    if kind in ("dns_lookup", "lb_lookup"):
        entries, dropped = clean_entries(F.render(F._p(node, "entries"), ctx.scope()))
        if not entries:
            raise F.FlowError("no valid name or address to look up")
        cut = " (the first %d; %d more left out)" % (len(entries), dropped) if dropped else ""
        if kind == "dns_lookup":
            res = dns_lookup(entries, ttl=_truthy(F.render(F._p(node, "ttl", "no"), ctx.scope())))
            return "ok", res, "%d name(s) x %d resolver(s), %d without an answer%s" % (
                len(entries), len(res["servers"]), len(res["unresolved"]), cut)
        from . import dns_tool
        dns = F.render(F._p(node, "dns", ""), ctx.scope())
        with as_operator(ctx):
            try:
                lb_rows = dns_tool.fleet_lb_rows()
            except Exception as exc:  # noqa: BLE001 -- the page shows it; so does the run
                raise F.FlowError("LB matching failed: %s" % exc) from None
            res = lb_lookup(entries, lb_rows, dns=dns if isinstance(dns, dict) else None,
                            exact=_truthy(F.render(F._p(node, "exact", "no"), ctx.scope())))
        return "ok", res, "%d match(es) for %d name(s) in %d cached LB row(s)%s" % (
            len(res["rows"]), len(entries), len(lb_rows), cut)
    if kind == "dns_records":
        with as_operator(ctx):
            res = list_records(backend_row(_s(node, ctx, "backend")), name=_s(node, ctx, "name"),
                               zone=_s(node, ctx, "zone"))
        return "ok", res, "%d record(s) in %s" % (len(res["records"]), res["backend"]["name"])
    if kind == "dns_record_change":
        op = _s(node, ctx, "operation").lower()
        rec = record_of(F._json(node, ctx, "record", "Record"))
        check_record(op, rec)
        with as_operator(ctx):
            res = change_record(backend_row(_s(node, ctx, "backend")), op, rec)
        r = res["record"]
        return "ok", res, "%sd %s %s %s in %s" % (op.rstrip("e"), r.get("type"), r.get("name"),
                                                 r.get("value") or "", res["backend"]["name"])
    if kind == "dns_decommission_plan":
        from . import dns_decommission
        with as_operator(ctx):
            a = visible_appliance(_s(node, ctx, "appliance"))
            res = dns_decommission.plan(a, policy=_s(node, ctx, "policy"),
                                        hostname=_s(node, ctx, "hostname"))
        if not res.get("ok"):
            raise F.FlowError(res.get("error") or "the plan could not be built")
        res["rows"] = plan_rows(res)
        c = res.get("counts") or {}
        return "ok", res, "%s on %s: %s delete, %s unbind, %s keep; %d warning(s)%s" % (
            res["target"]["policy"], res["target"]["appliance"], c.get("delete", 0),
            c.get("unbind", 0), c.get("keep", 0), len(res.get("warnings") or []),
            ", BLOCKED" if res.get("blocked") else "")
    if kind == "dns_decommission_apply":
        from . import dns_decommission
        from .audit import log_action
        with as_operator(ctx):
            a = visible_appliance(_s(node, ctx, "appliance"))
            policy = _s(node, ctx, "policy")
            res = dns_decommission.apply(
                a, policy=policy, hostname=_s(node, ctx, "hostname"),
                confirm=_s(node, ctx, "confirm"),
                acknowledge=_truthy(F.render(F._p(node, "acknowledge", ""), ctx.scope())),
                actor=ctx.user or "")
            log_action("dns_decommission.apply", target="%s:%s" % (a.name, policy),
                       appliance_id=a.id, via="plugin studio",
                       detail=("ok=%s %s" % (res.get("ok"), res.get("error")
                                             or (res.get("summary") or {})))[:400])
        if not res.get("ok"):
            # what was done stays readable on the error arrow: {{ decommission.results }}
            ctx.vars[str(F._p(node, "save_as", "") or "decommission")] = res
            raise F.FlowError(res.get("error") or "the decommission failed")
        s = res.get("summary") or {}
        return "ok", res, "%s on %s: %s of %s step(s) done" % (policy, a.name, s.get("ok", 0),
                                                              s.get("total", 0))
    raise F.FlowError("unknown step kind %r" % kind)
