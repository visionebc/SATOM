"""**Naming** scheme — standalone admin page.

The name-pattern editor (ported ``services.naming``) with a live preview from one
sample web address. Split by **product** (FortiWeb / FortiADC) via a selector —
each product has its own object catalog and its own stored overrides.

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import naming as naming_svc
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('naming', __name__, url_prefix='/naming')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    raw = request.args.get('product')
    if raw and not _has_scheme(raw) and raw in dict(_device_products()):
        # no naming catalog for this product: its Naming entry IS Discovery
        return redirect(url_for('naming.discovery', product=raw))
    product = naming_svc.valid_product(raw)
    scheme = naming_svc.effective_scheme(store.naming_overrides(product), product)
    return render_template(
        'naming/index.html',
        naming_sections=naming_svc.elements_by_section(product),
        naming_scheme=scheme,
        naming_products=naming_svc.PRODUCTS,  # not `products`: base.html reads that global (the ADOM registry)
        current_product=product,
        product_label=dict(naming_svc.PRODUCTS)[product],
    )


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    product = naming_svc.valid_product(request.form.get('product'))
    label = dict(naming_svc.PRODUCTS)[product]
    if request.form.get('action') == 'reset':
        store.reset_naming(product)
        log_action('naming.save', detail=f'Reset {label} naming to defaults')
        flash(f'{label} naming patterns restored to defaults.', 'success')
        return redirect(url_for('naming.index', product=product))
    scheme = {
        e.key: request.form.get('nm_' + e.key, '')
        for e in naming_svc.elements_for_product(product)
    }
    store.save_naming(scheme, product)
    log_action('naming.save',
               detail=f'{label}: {len([v for v in scheme.values() if v.strip()])} patterns')
    flash(f'{label} naming patterns saved.', 'success')
    return redirect(url_for('naming.index', product=product))


# ── Discovery: the convention the devices already follow ─────────────────────
#
# The scheme editor above says how NEW objects are named; Discovery reads the
# configuration tree SATOM already holds for each device (no device call) and
# shows the convention behind the names that are there (services.
# naming_discovery). It lives under Naming in EVERY device ADOM — the scheme
# editor only where the product has a naming catalog.

#: Discovered table -> Naming scheme element, where the scheme has one. Drives
#: the "Scheme" column and "Apply to scheme". ``tests/test_naming_discovery.py``
#: pins every target to an element of the right product.
SCHEME_ELEMENT_OF = {
    "fortiweb": {
        "server_policy": "server_policy", "vserver": "virtual_server", "vip": "vip",
        "server_pool": "server_pool", "server_pool_health_check": "health_check",
        "server_pool_persistence": "persistence",
        "http_content_routing_policy": "content_routing",
        "certificate": "certificate",
        "webprotection_profile_inline": "web_protection_profile",
        "http_protocol": "http_constraint", "x_forwarded_for": "x_forward",
        "allow_method_policy": "allow_method", "ip_list": "ip_list", "geo_block": "geo",
        "cookie_security": "cookie_security", "csrf_protection": "csrf",
        "padding_oracle": "padding_oracle", "http_header_security": "http_header_security",
        "parameter_validation_policy": "parameter_validation",
        "hidden_field_protection_policy": "hidden_fields",
        "file_security_policy": "file_upload", "url_access_policy": "url_access",
        "bot_mitigation_policy_2": "bot_mitigation",
    },
    "fortiadc": {
        "load_balance_virtual_server": "adc_virtual_server",
        "load_balance_real_server": "adc_real_server",
        "load_balance_pool": "adc_real_server_pool",
        "system_health_check": "adc_health_check",
        "load_balance_persistence": "adc_persistence",
        "load_balance_method": "adc_lb_method",
        "load_balance_content_routing": "adc_content_routing",
        "load_balance_content_rewriting": "adc_content_rewriting",
        "load_balance_schedule_pool": "adc_schedule_pool",
        "load_balance_error_page": "adc_error_page",
        "load_balance_client_ssl_profile": "adc_client_ssl_profile",
        "load_balance_real_server_ssl_profile": "adc_server_ssl_profile",
        "system_certificate_local": "adc_certificate",
    },
}


def _device_products() -> list[tuple[str, str]]:
    """(key, name) of every active device ADOM — Discovery covers them all."""
    from ..branding import PRODUCTS
    return [(k, PRODUCTS[k].get("name", k)) for k in PRODUCTS if k != "global"]


def _discovery_product(raw: str | None) -> str:
    keys = [k for k, _ in _device_products()]
    if raw in keys:
        return raw
    from ..services.product_scope import session_product
    cur = session_product()
    if cur in keys:
        return cur
    return keys[0] if keys else naming_svc.DEFAULT_PRODUCT


def _has_scheme(product: str) -> bool:
    """True when the scheme editor has a tab for *product* (a naming catalog
    AND the ADOM flag) — naming.PRODUCTS already requires both."""
    return product in {k for k, _ in naming_svc.PRODUCTS}


def _tree_path(appliance):
    from ..services import device_sync
    return device_sync._reports_dir() / device_sync.slugify(appliance.name) / "_config.json"


def _table_labels(product: str) -> dict[str, str]:
    """Registry name -> the tab label the ADOM's own menu uses."""
    out: dict[str, str] = {}
    try:
        if product == "fortigate":
            from ..registry import loader
            from ..services import fgt_menu
            for g in fgt_menu.menu():
                for it in g.items:
                    for path, label in it.tabs:
                        out.setdefault(loader.fgt_logical(path), label)
        elif product in ("fortianalyzer", "fortiauthenticator"):
            from ..services import faz_menu, fac_menu
            groups = faz_menu.menu() if product == "fortianalyzer" else fac_menu.visible_menu()
            for g in groups:
                for it in g.items:
                    for logical, label in it.logicals:
                        out.setdefault(logical, label)
    except Exception:  # noqa: BLE001 — labels are cosmetic; the key still shows
        pass
    return out


def _adopted(product: str) -> dict:
    return store.get_json(f"naming.discovered.{product}", {}) or {}


def _annotate(analysis: dict, product: str) -> None:
    """Add the scheme / adopted-pattern checks to each table of an analysis."""
    from ..services import naming_discovery as nd
    adopted = _adopted(product)
    scheme = (naming_svc.effective_scheme(store.naming_overrides(product), product)
              if _has_scheme(product) else {})
    elements = SCHEME_ELEMENT_OF.get(product, {})
    for t in analysis["tables"]:
        names = t.get("names") or []
        key = elements.get(t["table"])
        t["scheme_key"] = key
        t["scheme"] = nd.conformance(scheme[key], names) if key and key in scheme else None
        ad = adopted.get(t["table"])
        t["adopted"] = nd.conformance(ad["pattern"], names) if ad else None
        if ad:
            t["adopted"]["by"] = ad.get("by", "")
            t["adopted"]["at"] = ad.get("at", "")
        ok, why = nd.scheme_compatible(t.get("main") or "")
        t["can_apply"] = bool(key and ok)
        t["apply_why"] = "" if t["can_apply"] else (
            why if key else "the naming scheme has no element for this object type")


def _analyse(appliance, product: str, labels: dict) -> dict:
    from ..services import naming_discovery as nd
    tree = nd.load_tree(_tree_path(appliance))
    if tree is None:
        return {"device": appliance.name, "appliance_id": appliance.id, "missing": True,
                "tables": [], "user_objects": 0, "factory_objects": 0}
    a = nd.analyse_device(product, appliance.name, tree, labels)
    a["appliance_id"] = appliance.id
    _annotate(a, product)
    return a


def _discovery_context():
    from ..models import Appliance, visible_appliances
    product = _discovery_product(request.args.get("product") or request.form.get("product"))
    fleet = (visible_appliances().filter_by(kind=product)
             .order_by(Appliance.name).all())
    raw = request.args.get("appliance") or request.form.get("appliance") or ""
    selected = None
    if raw != "all":
        selected = next((a for a in fleet if str(a.id) == raw), None)
        if selected is None and fleet:
            from ..services import device_context
            cur = device_context.current_appliance()
            selected = cur if cur is not None and cur in fleet else fleet[0]
    return product, fleet, selected


@bp.route('/discovery')
@login_required
@require_permission(Permission.USER_MANAGE)
def discovery():
    from ..services import naming_discovery as nd
    product, fleet, selected = _discovery_context()
    labels = _table_labels(product)
    analysis, fleet_rows, missing = None, None, []
    show_factory = request.args.get("factory") == "1"
    if selected is not None:
        analysis = _analyse(selected, product, labels)
    elif fleet:
        analyses = [_analyse(a, product, labels) for a in fleet]
        missing = [a["device"] for a in analyses if a.get("missing")]
        fleet_rows = nd.fleet_view([a for a in analyses if not a.get("missing")])
        adopted = _adopted(product)
        for r in fleet_rows:
            r["adopted"] = (adopted.get(r["table"]) or {}).get("pattern")
    plabel = dict(_device_products()).get(product, product)
    return render_template(
        'naming/discovery.html',
        current_product=product, product_label=plabel,
        has_scheme=_has_scheme(product), fleet=fleet, selected=selected,
        analysis=analysis, fleet_rows=fleet_rows, missing=missing,
        show_factory=show_factory,
        factory_source=(nd.factory_catalog().get(product) or {}).get("measured_on", ""),
    )


@bp.route('/discovery.csv')
@login_required
@require_permission(Permission.USER_MANAGE)
def discovery_csv():
    import csv
    import io
    from flask import Response
    from ..services import naming_discovery as nd
    from ..services.csv_safe import spreadsheet_safe
    product, fleet, selected = _discovery_context()
    labels = _table_labels(product)
    targets = [selected] if selected is not None else fleet
    buf = io.StringIO()
    w = csv.writer(buf)
    header_done = False
    for appl in targets:
        a = _analyse(appl, product, labels)
        if a.get("missing"):
            continue
        rows = nd.to_csv_rows(a)
        for row in (rows if not header_done else rows[1:]):
            w.writerow([spreadsheet_safe(c) for c in row])
        header_done = True
    name = f"naming-{product}-{selected.name if selected else 'fleet'}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@bp.route('/discovery/adopt', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def discovery_adopt():
    """Keep a discovered pattern as THE convention for one object type.

    Stored per product (``naming.discovered.<product>``); every device of the
    product is then checked against it. With ``apply=1`` it is also written
    into the Naming scheme — only when the scheme can carry it (``{name}``
    and literals) and the object type has a scheme element."""
    from datetime import datetime
    from flask_login import current_user
    from ..services import naming_discovery as nd
    product = _discovery_product(request.form.get("product"))
    table = (request.form.get("table") or "").strip()
    pattern = (request.form.get("pattern") or "").strip()
    back = url_for('naming.discovery', product=product,
                   appliance=request.form.get("appliance") or None)
    if request.form.get("action") == "forget":
        adopted = _adopted(product)
        if adopted.pop(table, None) is not None:
            store.set_json(f"naming.discovered.{product}", adopted)
            log_action('naming.discovery', detail=f'{product}: forgot the convention of {table}')
            flash(f'Convention for {table} removed.', 'success')
        return redirect(back)
    if not table or not pattern or nd.pattern_regex(pattern) is None:
        flash('Nothing to adopt: the object type has no discovered pattern.', 'warning')
        return redirect(back)
    adopted = _adopted(product)
    adopted[table] = {"pattern": pattern[:200],
                      "by": getattr(current_user, "username", "") or "",
                      "at": datetime.utcnow().strftime("%Y-%m-%d %H:%M")}
    store.set_json(f"naming.discovered.{product}", adopted)
    msg = f'{table}: {pattern} adopted as the convention.'
    if request.form.get("apply") == "1":
        key = SCHEME_ELEMENT_OF.get(product, {}).get(table)
        ok, why = nd.scheme_compatible(pattern)
        if key and ok and _has_scheme(product):
            overrides = dict(store.naming_overrides(product))
            overrides[key] = pattern
            store.save_naming(overrides, product)
            msg += f' Naming scheme "{key}" set to {pattern}.'
        else:
            flash(f'Not written to the naming scheme: '
                  f'{why or "the naming scheme has no element for this object type"}.', 'warning')
    log_action('naming.discovery', detail=f'{product}: {msg}')
    flash(msg, 'success')
    return redirect(back)


@bp.route('/discovery/sync', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def discovery_sync():
    """Refresh one device's configuration tree (the read-only sweep every
    other page uses) so Discovery reads today's names."""
    from flask_login import current_user
    from ..errors import ServiceError, service_call
    from ..services import device_sync
    product, fleet, selected = _discovery_context()
    if selected is None:
        flash('Pick one device to sync.', 'warning')
        return redirect(url_for('naming.discovery', product=product))
    try:
        run = service_call(device_sync.sync_device, selected,
                           user_label=getattr(current_user, "username", None),
                           trigger="manual", context="naming.discovery.sync",
                           user_message="Sync failed")
    except ServiceError as exc:
        flash(f'{exc.user_message} (error {exc.error_id}).', 'danger')
    else:
        level = 'success' if getattr(run, 'status', '') == 'ok' else 'danger'
        flash(f'{selected.name}: {getattr(run, "detail", "")}', level)
    return redirect(url_for('naming.discovery', product=product, appliance=selected.id))
