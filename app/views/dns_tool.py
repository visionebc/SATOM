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
from ..services.dns_providers import DnsRecord, ProviderError
from ..services.product_scope import session_product
from ..services.audit import log_action
from ..auth.decorators import require_permission
from ..models import Permission

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
        dns_provider=dns_providers.provider_key(),
        can_manage_records=current_user.can("user_manage"),
    )


# ------------------------------------------------------------- DNS Records
# CRUD against the configured IPAM/DDI provider (EfficientIP / phpIPAM /
# NetBox), driven by the +DNS Records modal. Admin-only (USER_MANAGE); every
# write is audited. The active provider is chosen in Settings → DNS Records,
# so the same modal adapts per install (capabilities from schema()).

def _provider_or_400():
    prov = dns_providers.active_provider()
    if prov is None:
        return None, (jsonify(error="No DNS/IPAM provider is configured."), 400)
    return prov, None


@bp.route("/records/schema", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_schema():
    """Active provider's capabilities — the modal renders itself from this."""
    prov, err = _provider_or_400()
    if err:
        return err
    try:
        caps = prov.capabilities().as_dict()
    except ProviderError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify(capabilities=caps)


@bp.route("/records/list", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_list():
    prov, err = _provider_or_400()
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
    prov, err = _provider_or_400()
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
               target=f"{dns_providers.provider_key()}:{rec.type} {rec.name}")
    return jsonify(record=saved.as_dict()), 201


@bp.route("/records", methods=["PUT"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_update():
    prov, err = _provider_or_400()
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
               target=f"{dns_providers.provider_key()}:{rec.type} {rec.name}")
    return jsonify(record=saved.as_dict())


@bp.route("/records", methods=["DELETE"])
@login_required
@require_permission(Permission.USER_MANAGE)
def records_delete():
    prov, err = _provider_or_400()
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
               target=f"{dns_providers.provider_key()}:{rec.type} {rec.name}")
    return jsonify(ok=True)
