"""Fleet objects — fleet-wide FortiWeb object browser (read-only).

Web port of the desktop ``settings_page._fleet_objects_page``. Unlike the
desktop (which reads a local object cache), this view aggregates the objects
**live** across every FortiWeb appliance on each request — see
``app/services/fleet_objects.py`` for the aggregation + short-TTL caching.

Routes
  GET /fleet-objects?type=server_policy|wpp|server_pool|search&q=...
      → the 4-mode browser. Typed modes show an aggregated table with a Device
        column + filter dropdowns; ``search`` is a generic any-field search.
  GET /fleet-objects?...&format=csv
      → the current view as a CSV download.

Read-only: ``@login_required`` only, no special permission.
"""
from flask import Blueprint, Response, render_template, request
from flask_login import login_required

from ..services import fleet_objects as svc

bp = Blueprint('fleet_objects', __name__, url_prefix='/fleet-objects')


@bp.route('/')
@login_required
def index():
    # --- mode + query params --------------------------------------------
    type_key = request.args.get('type') or svc.DEFAULT_TYPE
    if type_key not in svc.TYPES:
        type_key = svc.DEFAULT_TYPE
    spec = svc.TYPES[type_key]
    is_search = bool(spec.get('search'))
    q = (request.args.get('q') or '').strip()
    fmt = (request.args.get('format') or '').strip().lower()

    columns = svc.columns_for(type_key)
    filters = spec.get('filters', [])
    selected: dict[str, str] = {}
    filter_options: dict[str, list[str]] = {}

    # --- live aggregation ------------------------------------------------
    if is_search:
        rows, errors = svc.collect_search(q)
        total = len(rows)
    else:
        all_rows, errors = svc.collect_objects(type_key)
        total = len(all_rows)
        filter_options = svc.distinct_values(all_rows, [k for k, _ in filters])
        for fkey, _label in filters:
            val = (request.args.get('f_' + fkey) or '').strip()
            if val:
                selected[fkey] = val
        rows = svc.apply_filters(all_rows, selected, q, columns)

    shown = len(rows)

    # --- CSV export of the current view ---------------------------------
    if fmt == 'csv':
        csv_text = svc.to_csv(columns, rows)
        filename = 'fleet_objects_%s.csv' % type_key
        return Response(
            csv_text,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=%s' % filename},
        )

    # Args that reproduce the current view (used by the CSV link + GET form).
    query_args: dict[str, str] = {'type': type_key}
    if q:
        query_args['q'] = q
    for fkey, val in selected.items():
        query_args['f_' + fkey] = val

    return render_template(
        'fleet_objects/index.html',
        type_key=type_key,
        spec=spec,
        is_search=is_search,
        type_choices=svc.type_choices(),
        columns=columns,
        rows=rows,
        errors=errors,
        q=q,
        filters=filters,
        selected=selected,
        filter_options=filter_options,
        shown=shown,
        total=total,
        query_args=query_args,
    )
