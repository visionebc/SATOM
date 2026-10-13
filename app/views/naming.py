"""**Naming** — standalone admin page, one per device ADOM.

Two tabs over ONE list of object types:

* **Scheme** — the pattern each object type is named by. The catalog of
  ``services.naming`` (what SATOM builds new names from, FortiWeb's creation
  flows) plus every other object type the product's configuration sweep reads
  (``device_sync.sweep_tables``), stored per product. Each entry shows what
  Discovery found on the devices next to the input.
* **Discovery** — the convention the devices already follow
  (``services.naming_discovery``). **Adopt** writes the discovered pattern into
  the scheme entry of that object type; **Adopt & adapt** opens it for a small
  edit first, with a live check against the existing names.

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

import logging

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import naming as naming_svc
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('naming', __name__, url_prefix='/naming')
log = logging.getLogger(__name__)

#: Discovered table -> catalog element of ``services.naming``, where the
#: catalog has one: that element IS the table's scheme entry. Any other table
#: is stored as ``naming.table_key(table)``. ``tests/test_naming_discovery.py``
#: pins every target to an element of the right product.
SCHEME_ELEMENT_OF = {
    "fortiweb": {
        "server_policy": "server_policy", "vserver": "virtual_server", "vip": "vip",
        "server_pool": "server_pool", "server_pool_health_check": "health_check",
        "server_pool_persistence": "persistence",
        "http_content_routing": "content_routing",
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

#: Names sent to the page per object type for the live check (a type with
#: thousands of objects still checks against a representative sample).
NAMES_FOR_LIVE_CHECK = 400


# ── product / devices ────────────────────────────────────────────────────────

def _device_products() -> list[tuple[str, str]]:
    """(key, name) of every active device ADOM — each has a Naming page."""
    from ..branding import PRODUCTS
    return [(k, PRODUCTS[k].get("name", k)) for k in PRODUCTS if k != "global"]


def _naming_product(raw: str | None) -> str:
    keys = [k for k, _ in _device_products()]
    if raw in keys:
        return raw
    from ..services.product_scope import session_product
    cur = session_product()
    if cur in keys:
        return cur
    return keys[0] if keys else naming_svc.DEFAULT_PRODUCT


def _catalog(product: str) -> list:
    """The ``services.naming`` elements of *product* (none for most products;
    never the FortiWeb fallback ``naming.valid_product`` applies)."""
    return [e for e in naming_svc.NAMING_ELEMENTS if e.product == product]


def _fleet(product: str) -> list:
    from ..models import Appliance, visible_appliances
    return visible_appliances().filter_by(kind=product).order_by(Appliance.name).all()


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


# Analyses keyed by (tree file, mtime): the Scheme tab reads every device of
# the product on each render and a tree only changes when a sync rewrites it.
_ANALYSIS_CACHE: dict[tuple, tuple] = {}


def _load(appliance, product: str, labels: dict):
    """(tree, analysis) of one device, or (None, None) when SATOM holds no
    tree for it. The analysis is a copy the caller may annotate."""
    from ..services import naming_discovery as nd
    path = _tree_path(appliance)
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return None, None
    ck = (str(path), mtime, product, appliance.name)
    hit = _ANALYSIS_CACHE.get(ck)
    if hit is None:
        tree = nd.load_tree(path)
        if tree is None:
            return None, None
        if len(_ANALYSIS_CACHE) > 256:
            _ANALYSIS_CACHE.clear()
        hit = _ANALYSIS_CACHE[ck] = (tree, nd.analyse_device(product, appliance.name, tree, labels))
    tree, a = hit
    a = dict(a, tables=[dict(t) for t in a["tables"]], appliance_id=appliance.id)
    return tree, a


# ── the scheme: one entry per object type ───────────────────────────────────

def _scheme_key(product: str, table: str) -> str:
    return SCHEME_ELEMENT_OF.get(product, {}).get(table) or naming_svc.table_key(table)


def _migrate_adopted(product: str) -> None:
    """Fold the retired per-product "adopted convention" store into the scheme.

    Discovery's first version kept adopted patterns apart from the scheme
    (``naming.discovered.<product>``) — two lists of conventions that could
    disagree. Each entry moves to its scheme entry unless that entry already
    has a pattern of its own or cannot carry it; the old key is then emptied."""
    legacy_key = f"naming.discovered.{product}"
    legacy = store.get_json(legacy_key, {}) or {}
    if not legacy:
        return
    overrides = dict(store.naming_overrides(product))
    moved, dropped = [], []
    for table, entry in legacy.items():
        pattern = ((entry or {}).get("pattern") or "").strip()
        key = _scheme_key(product, table)
        if not pattern or overrides.get(key):
            continue
        if naming_svc.pattern_problem(key, pattern):
            dropped.append(f"{table}={pattern}")
            continue
        overrides[key] = pattern
        moved.append(f"{table}={pattern}")
    store.save_naming(overrides, product)
    store.set_json(legacy_key, {})
    log_action('naming.save', detail=f'{product}: adopted conventions moved into the scheme '
               f'({", ".join(moved) or "none"}; not movable: {", ".join(dropped) or "none"})')


def _scheme_model(product: str) -> dict:
    """Everything both tabs draw from: the entries (catalog + every object
    type of the sweep), what each device holds, and the per-table fleet view."""
    from ..services import device_sync
    from ..services import naming_discovery as nd
    _migrate_adopted(product)
    fleet = _fleet(product)
    labels = _table_labels(product)
    trees, analyses = [], []
    for a in fleet:
        tree, an = _load(a, product, labels)
        if tree is not None:
            trees.append(tree)
            analyses.append(an)
    try:
        sweep = device_sync.sweep_tables(product, fleet)
    except Exception:  # noqa: BLE001 — the trees still list what devices hold
        sweep = {}
    try:
        kinds = device_sync.table_kinds(product, fleet, sweep)
    except Exception:  # noqa: BLE001 — unmeasured shapes stay listed
        log.exception("naming: table_kinds(%s) failed", product)
        kinds = {}
    types = nd.object_types(sweep, trees, kinds)
    by_table: dict[str, dict] = {}
    for an in analyses:
        for t in an["tables"]:
            b = by_table.setdefault(t["table"], {"names": [], "factory": 0})
            b["names"].extend(t.get("names") or ())
            b["factory"] += t.get("factory") or 0
    found = {r["table"]: r for r in nd.fleet_view(analyses)}
    overrides = store.naming_overrides(product)
    mapping = SCHEME_ELEMENT_OF.get(product, {})
    table_of = {v: k for k, v in mapping.items()}

    def entry(key, label, section, table, default="", derives=False, note="", curated=False):
        info = by_table.get(table or "", {})
        names = sorted(set(info.get("names") or ()))
        value = (overrides.get(key) or "").strip()
        pattern = value or default
        return {
            "key": key, "label": label, "section": section, "table": table,
            "default": default, "value": value, "pattern": pattern,
            "derives": derives, "note": note, "curated": curated,
            "seen": bool(table and (types.get(table) or {}).get("seen")),
            "numeric": bool(table and (types.get(table) or {}).get("numeric")),
            "shape": (types.get(table or "") or {}).get("shape") or "",
            "found": found.get(table or ""), "names": names[:NAMES_FOR_LIVE_CHECK],
            "user": len(names), "factory": info.get("factory", 0),
            "check": nd.conformance(pattern, names) if pattern and names else None,
        }

    entries = []
    for e in _catalog(product):
        entries.append(entry(e.key, e.label, e.section, table_of.get(e.key), e.default,
                             e.derives, e.note, curated=True))
    curated_tables = set(mapping)        # the TABLE names (table_of is keyed by element)
    rest = []
    for table, meta in types.items():
        if table in curated_tables:
            continue
        rest.append(entry(naming_svc.table_key(table),
                          labels.get(table) or nd.humanize(table), meta["section"], table))
    rest.sort(key=lambda x: (x["section"].lower(), x["label"].lower()))
    entries += rest
    sections: dict[str, list] = {}
    for x in entries:
        sections.setdefault(x["section"], []).append(x)
    return {"entries": entries, "sections": sections, "fleet": fleet,
            "analyses": analyses, "overrides": overrides,
            "by_key": {x["key"]: x for x in entries}, "by_table":
            {x["table"]: x for x in entries if x["table"]}}


def _proto_words() -> list[str]:
    from ..services import naming_discovery as nd
    return sorted(nd.PROTO_WORDS, key=len, reverse=True)


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    product = _naming_product(request.args.get('product'))
    model = _scheme_model(product)
    entries = model["entries"]
    return render_template(
        'naming/index.html',
        naming_sections=model["sections"],
        naming_products=_device_products(),  # not `products`: base.html reads that global (the ADOM registry)
        current_product=product,
        product_label=dict(_device_products()).get(product, product),
        catalog_sections={e.section for e in _catalog(product)},
        n_entries=len(entries),
        n_seen=sum(1 for x in entries if x["seen"]),
        n_set=sum(1 for x in entries if x["value"]),
        has_devices=bool(model["fleet"]),
        proto_words=_proto_words(),
    )


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    product = _naming_product(request.form.get('product'))
    label = dict(_device_products()).get(product, product)
    if request.form.get('action') == 'reset':
        store.reset_naming(product)
        log_action('naming.save', detail=f'Reset {label} naming to defaults')
        flash(f'{label} naming patterns restored to defaults.', 'success')
        return redirect(url_for('naming.index', product=product))
    model = _scheme_model(product)
    # Start from what is stored: an entry whose object type left the sweep
    # (another build, a device removed) keeps its pattern.
    scheme = dict(model["overrides"])
    refused = []
    for key in model["by_key"]:
        if ('nm_' + key) not in request.form:
            continue
        value = (request.form.get('nm_' + key) or '').strip()
        problem = naming_svc.pattern_problem(key, value)
        if problem:
            refused.append(f'{model["by_key"][key]["label"]}: {problem}')
            continue
        if value:
            scheme[key] = value
        else:
            scheme.pop(key, None)
    store.save_naming(scheme, product)
    log_action('naming.save',
               detail=f'{label}: {len([v for v in scheme.values() if v.strip()])} patterns'
               + (f'; refused {len(refused)}' if refused else ''))
    if refused:
        flash('Not saved (kept the previous pattern): ' + ' · '.join(refused), 'warning')
    flash(f'{label} naming patterns saved.', 'success')
    return redirect(url_for('naming.index', product=product))


# ── Discovery: the convention the devices already follow ─────────────────────

def _annotate(analysis: dict, product: str, model: dict) -> None:
    """Add each table's scheme entry and the Adopt checks."""
    from ..services import naming_discovery as nd
    for t in analysis["tables"]:
        names = t.get("names") or []
        key = _scheme_key(product, t["table"])
        e = model["by_key"].get(key)
        pattern = e["pattern"] if e else (model["overrides"].get(key) or "")
        t["scheme_key"] = key
        t["scheme_set"] = bool(model["overrides"].get(key))
        t["scheme"] = nd.conformance(pattern, names) if pattern else None
        t["derives"] = bool(e and e["derives"])
        problem = naming_svc.pattern_problem(key, t["main"]) if t.get("main") else ""
        t["can_adopt"] = bool(t.get("main")) and not problem and t["main"] != pattern
        t["adopt_why"] = problem
        t["adapt_seed"] = t.get("main") or pattern or ""


def _discovery_context(model: dict):
    fleet = model["fleet"]
    raw = request.args.get("appliance") or request.form.get("appliance") or ""
    selected = None
    if raw != "all":
        selected = next((a for a in fleet if str(a.id) == raw), None)
        if selected is None and fleet:
            from ..services import device_context
            cur = device_context.current_appliance()
            selected = cur if cur is not None and cur in fleet else fleet[0]
    return fleet, selected


def _analysis_of(model: dict, appliance) -> dict:
    a = next((x for x in model["analyses"] if x["appliance_id"] == appliance.id), None)
    if a is None:
        return {"device": appliance.name, "appliance_id": appliance.id, "missing": True,
                "tables": [], "user_objects": 0, "factory_objects": 0}
    return a


@bp.route('/discovery')
@login_required
@require_permission(Permission.USER_MANAGE)
def discovery():
    from ..services import naming_discovery as nd
    product = _naming_product(request.args.get("product"))
    model = _scheme_model(product)
    fleet, selected = _discovery_context(model)
    analysis, fleet_rows, missing = None, None, []
    show_factory = request.args.get("factory") == "1"
    if selected is not None:
        analysis = _analysis_of(model, selected)
        _annotate(analysis, product, model)
    elif fleet:
        have = {a["appliance_id"] for a in model["analyses"]}
        missing = [a.name for a in fleet if a.id not in have]
        fleet_rows = nd.fleet_view(model["analyses"])
        for r in fleet_rows:
            e = model["by_table"].get(r["table"])
            r["scheme"] = e["pattern"] if e else ""
    return render_template(
        'naming/discovery.html',
        current_product=product,
        product_label=dict(_device_products()).get(product, product),
        fleet=fleet, selected=selected,
        analysis=analysis, fleet_rows=fleet_rows, missing=missing,
        show_factory=show_factory, proto_words=_proto_words(),
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
    product = _naming_product(request.args.get("product"))
    model = _scheme_model(product)
    fleet, selected = _discovery_context(model)
    targets = [selected] if selected is not None else fleet
    buf = io.StringIO()
    w = csv.writer(buf)
    header_done = False
    for appl in targets:
        a = _analysis_of(model, appl)
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
    """Write a pattern into the scheme entry of one object type.

    **Adopt** posts the discovered pattern as it is; **Adopt & adapt** posts
    the operator's edit of it. ``action=forget`` clears the entry (a catalog
    element falls back to its default). Refused when the entry is one SATOM
    builds names from and the pattern carries a token it cannot fill in."""
    from ..services import naming_discovery as nd
    product = _naming_product(request.form.get("product"))
    table = (request.form.get("table") or "").strip()
    pattern = (request.form.get("pattern") or "").strip()[:200]
    back = url_for('naming.discovery', product=product,
                   appliance=request.form.get("appliance") or None)
    if not table:
        flash('No object type given.', 'warning')
        return redirect(back)
    key = _scheme_key(product, table)
    overrides = dict(store.naming_overrides(product))
    if request.form.get("action") == "forget":
        if overrides.pop(key, None) is not None:
            store.save_naming(overrides, product)
            log_action('naming.save', detail=f'{product}: cleared the scheme pattern of {table}')
            flash(f'{table}: scheme pattern cleared.', 'success')
        return redirect(back)
    if not pattern or nd.pattern_regex(pattern) is None:
        flash('Nothing to adopt: the pattern is empty.', 'warning')
        return redirect(back)
    problem = naming_svc.pattern_problem(key, pattern)
    if problem:
        flash(f'{table}: {pattern} not adopted — {problem}. Use “Adopt & adapt” to change it.',
              'warning')
        return redirect(back)
    adapted = request.form.get("adapted") == "1"
    overrides[key] = pattern
    store.save_naming(overrides, product)
    msg = f'{table}: {pattern} is now the naming scheme’s pattern'
    if key != naming_svc.table_key(table):
        msg += f' (element “{key}”)'
    log_action('naming.save', detail=f'{product}: {msg}' + (' (adapted)' if adapted else ''))
    flash(msg + '.', 'success')
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
    product = _naming_product(request.form.get("product"))
    fleet = _fleet(product)
    selected = next((a for a in fleet if str(a.id) == (request.form.get("appliance") or "")), None)
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
