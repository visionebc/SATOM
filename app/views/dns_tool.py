"""DNS & LB Lookup page (Global → Fleet → DNS Lookup, mirrored per ADOM).

The Global ADOM sees the whole fleet; a concrete ADOM (fortiweb / fortiadc)
gets the SAME tool with the LB output cut to its own product — that scoping
is inherited from ``visible_appliances()`` inside ``dns_tool.fleet_lb_rows``.
DNS servers are variable, managed in Settings → admin console.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from ..services import dns_tool
from ..services import dns_providers
from ..services import dns_decommission
from ..services.dns_providers import DnsRecord, ProviderError
from ..services.product_scope import session_product
from ..services.audit import log_action
from ..auth.decorators import require_permission
from ..models import Permission, visible_appliance_or_404

bp = Blueprint("dns_tool", __name__, url_prefix="/dns-lookup")


def _clipboards(results, servers, columns):
    """TSV exports mirroring the PHP tool's Copy DNS / Copy LB buttons."""
    dns_lines = ["\t".join(["Entry"] + [s["name"] for s in servers])]
    for r in results:
        dns_lines.append("\t".join(
            [r["entry"]] + ["; ".join(r["dns"].get(s["name"], [])) for s in servers]))
    lb_lines = ["\t".join(label for _k, label in columns)]
    for r in results:
        for m in r["matches"]:
            lb_lines.append("\t".join(str(m.get(k, "")) for k, _l in columns))
    return "\n".join(dns_lines), "\n".join(lb_lines)


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    servers = [s for s in dns_tool.dns_servers() if s.get("enabled", True)]
    opts = {"lb": True, "quick": False, "exact": False, "ttl": False}
    entries_raw = ""
    results = []
    not_found = []
    clip_dns = clip_lb = ""
    searched = False
    lb_error = None

    if request.method == "POST":
        searched = True
        opts = {k: bool(request.form.get(k)) for k in opts}
        entries_raw = request.form.get("entries", "")
        entries = []
        for line in entries_raw.splitlines():
            e = dns_tool.clean_entry(line)
            if e and e not in entries:
                entries.append(e)
        entries = entries[:dns_tool.MAX_ENTRIES]

        lb_rows = []
        if entries and (opts["lb"] or opts["quick"]):
            try:
                lb_rows = dns_tool.fleet_lb_rows()
            except Exception as exc:  # noqa: BLE001 — DNS half still renders
                lb_error = str(exc)

        dns_map = dns_tool.lookup_many(entries, servers, show_ttl=opts["ttl"])
        for e in entries:
            query, _rtype = dns_tool.parse_entry(e)
            resolved = dns_tool.resolve_wildcard(query)
            per_server = {s["name"]: dns_map.get((e, s["name"]), ["No result"])
                          for s in servers}
            matches = dns_tool.match_rows(lb_rows, query, resolved,
                                          exact=opts["exact"]) if lb_rows else []
            gateways = sorted({m["gateway"] for m in matches})
            no_dns = all(v in (["No result"], ["timeout"], ["error"])
                         for v in per_server.values()) if per_server else True
            if no_dns and not matches:
                not_found.append(e)
            results.append({
                "entry": e,
                "resolved": resolved,
                "is_wildcard": query.startswith("*."),
                "dns": per_server,
                "matches": matches,
                "gateways": gateways,
            })
        clip_dns, clip_lb = _clipboards(results, servers, dns_tool.COLUMNS)

    return render_template(
        "dns_lookup/index.html",
        servers=servers,
        columns=dns_tool.COLUMNS,
        results=results,
        not_found=not_found,
        opts=opts,
        entries_raw=entries_raw,
        searched=searched,
        clip_dns=clip_dns,
        clip_lb=clip_lb,
        lb_error=lb_error,
        adom=session_product() or "global",
        dns_backends=[r.public()
                      for r in dns_providers.enabled_backends("dns")],
        can_manage_records=current_user.can("user_manage"),
        can_decommission=current_user.can("config_write"),
    )


# ---------------------------------------------------------- Decommission
# Retire a whole service from the row the operator is looking at: the LB
# object and its exclusively-owned dependencies, the SNI member, the
# certificate, the WAF profile, the carve-outs and the DNS records.
#
# Two endpoints, never one. ``/plan`` reads and returns what WOULD go;
# ``/apply`` re-plans, checks the operator confirmed THAT plan by
# fingerprint, and only then executes. A single endpoint with a `confirm`
# flag would let a caller skip the preview entirely, and the preview is the
# feature.


def _decommission_args():
    body = request.get_json(silent=True) or request.form or {}
    try:
        aid = int(body.get("appliance_id") or 0)
    except (TypeError, ValueError):
        aid = 0
    return (aid, str(body.get("policy") or "").strip(),
            str(body.get("hostname") or "").strip(), body)


@bp.route("/decommission/plan", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def decommission_plan():
    aid, policy, hostname, _body = _decommission_args()
    if not aid or not policy:
        return jsonify(ok=False,
                       error="appliance_id and policy are required"), 400
    appliance = visible_appliance_or_404(aid)
    res = dns_decommission.plan(appliance, policy=policy, hostname=hostname)
    return jsonify(**res), (200 if res.get("ok") else 400)


@bp.route("/decommission/apply", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def decommission_apply():
    aid, policy, hostname, body = _decommission_args()
    if not aid or not policy:
        return jsonify(ok=False,
                       error="appliance_id and policy are required"), 400
    appliance = visible_appliance_or_404(aid)
    res = dns_decommission.apply(
        appliance, policy=policy, hostname=hostname,
        confirm=str(body.get("confirm") or ""),
        acknowledge=bool(body.get("acknowledge")),
        actor=getattr(current_user, "username", "") or "")
    # Audited whichever way it went: a refused decommission is exactly the
    # event an operator will look for afterwards.
    log_action("dns_decommission.apply",
               target="%s:%s" % (appliance.name, policy),
               appliance_id=appliance.id,
               detail=("ok=%s %s" % (res.get("ok"),
                                     res.get("error") or
                                     (res.get("summary") or {})))[:400])
    return jsonify(**res), (200 if res.get("ok") else res.get("code", 400))


# ------------------------------------------------------------- DNS Records
# CRUD against a CHOSEN DNS backend (EfficientIP / phpIPAM / NetBox), driven
# by the +DNS Records modal. Admin-only (USER_MANAGE); every write is audited.
# Backends are configured in Settings → DNS Records, and the modal adapts to
# whichever one is selected (capabilities from schema()).
#
# The backend is part of every request rather than a server-side "current"
# one. A selection remembered in the session would be a second author of the
# same decision, and the record the operator was looking at could be written
# to a different system from the one whose records they had just listed.


def _records_backend():
    """The backend this request acts on, or a 400 explaining why there isn't one.

    An explicit ``backend_id`` always wins. With exactly ONE DNS backend
    configured the choice is made without asking — that is not a guess, it is
    the only answer. With two or more and nothing named, the request is
    REFUSED: picking the first row would write into whichever zone happened to
    sort first, which is the failure this whole module was restructured to
    make impossible.
    """
    rows = dns_providers.enabled_backends("dns")
    if not rows:
        return None, (jsonify(
            error="No backend carries the DNS role. Configure one in "
                  "Settings -> DNS Records."), 400)
    body = request.get_json(silent=True) or {}
    raw = (request.args.get("backend_id")
           or body.get("backend_id")
           or request.form.get("backend_id") or "")
    raw = str(raw).strip()
    if raw:
        for row in rows:
            if str(row.id) == raw:
                return row, None
        return None, (jsonify(
            error="That DNS backend is gone, disabled, or no longer carries "
                  "the DNS role."), 400)
    if len(rows) == 1:
        return rows[0], None
    return None, (jsonify(
        error="%d DNS backends are configured — say which one this record "
              "belongs to." % len(rows),
        backends=[{"id": r.id, "name": r.name} for r in rows]), 400)


def _provider_or_400():
    """Kept as the single call shape the five handlers below use."""
    row, err = _records_backend()
    if err:
        return None, None, err
    return row, row.instance(), None


@bp.route("/records/schema", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_schema():
    """The chosen backend's capabilities — the modal renders itself from this."""
    row, prov, err = _provider_or_400()
    if err:
        return err
    try:
        caps = prov.capabilities().as_dict()
    except ProviderError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify(capabilities=caps, backend={"id": row.id, "name": row.name,
                                               "zones": row.zone_list()})


@bp.route("/records/list", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_list():
    _row, prov, err = _provider_or_400()
    if err:
        return err
    name = (request.args.get("name") or "").strip()
    zone = (request.args.get("zone") or "").strip()
    try:
        records = prov.list_records(name=name, zone=zone)
    except ProviderError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify(records=[r.as_dict() for r in records])


@bp.route("/records", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_create():
    row, prov, err = _provider_or_400()
    if err:
        return err
    rec = DnsRecord.from_form(request.get_json(silent=True) or request.form)
    if not rec.name or not rec.value:
        return jsonify(error="Name and value are required."), 400
    try:
        saved = prov.create_record(rec)
    except ProviderError as exc:
        return jsonify(error=str(exc)), 502
    log_action("dns_records.create",
               target=f"{row.name}:{rec.type} {rec.name}")
    return jsonify(record=saved.as_dict()), 201


@bp.route("/records", methods=["PUT"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_update():
    row, prov, err = _provider_or_400()
    if err:
        return err
    rec = DnsRecord.from_form(request.get_json(silent=True) or request.form)
    if not rec.id:
        return jsonify(error="Record id is required."), 400
    try:
        saved = prov.update_record(rec)
    except ProviderError as exc:
        return jsonify(error=str(exc)), 502
    log_action("dns_records.update",
               target=f"{row.name}:{rec.type} {rec.name}")
    return jsonify(record=saved.as_dict())


@bp.route("/records", methods=["DELETE"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_delete():
    row, prov, err = _provider_or_400()
    if err:
        return err
    rec = DnsRecord.from_form(request.get_json(silent=True) or request.form)
    if not rec.id:
        return jsonify(error="Record id is required."), 400
    try:
        prov.delete_record(rec)
    except ProviderError as exc:
        return jsonify(error=str(exc)), 502
    log_action("dns_records.delete",
               target=f"{row.name}:{rec.type} {rec.name}")
    return jsonify(ok=True)
