"""Shared implementation behind the two probe pages.

**Deep monitors** and **Service Monitor** are two *views* of one subsystem, not
two subsystems. They share the ``monitor_probe`` / ``monitor_sample`` tables, the
runner in ``services.deep_monitor`` and the single ``deep_monitor`` scheduled
action. Splitting the storage or the runner would double-schedule every device:
two sweeps, two SSH sessions, two sets of samples for the same box.

What the split *is*: a partition of ``deep_monitor.KINDS``.

* Deep monitors  — ``https``, ``interface``, ``cpu``, ``memory``, ``proxyd``:
  the checks that reach into the appliance (SSH / synthetic request / harvest
  cache).
* Service Monitor — ``sessions``, ``policy_sessions``, ``throughput``,
  ``transactions``: the REST telemetry kinds, which never open an SSH session
  and keep answering on a licence-locked appliance.

The partition is enforced **server-side on every route**, not by hiding rows in
a template: each blueprint filters its listing, refuses to create or edit a kind
outside its set, and 404s a probe id belonging to the other page. A page that
merely hides what it does not own is hidden, not scoped — the same rule §9c
applies to ADOM scoping.

ADOM scoping is unchanged and stacks on top: every query still runs through
``visible_appliances()``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from flask import (current_app, jsonify, render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, MonitorProbe, MonitorSample, Permission, db,
                      visible_appliances)
from ..services import deep_monitor as dm
from ..services import jobs as jobsvc
from ..services import notifications as notify
from ..services.audit import log_action

# How many samples the sparkline / history strip carries per probe.
SERIES_POINTS = 60

# Fixed windows the chart offers. `custom` takes explicit from/to.
SERIES_RANGES = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

_INT_FIELDS = ("expect_status", "warn_ms", "tls_warn_days", "stale_after_h",
               "warn_cpu", "warn_mem", "warn_pct", "crit_pct",
               "timeout_s", "interval_min", "retention")

# Absolute thresholds for the REST-monitor kinds. Float, not int: a throughput
# ceiling is naturally fractional ("warn at 0.5 Mbps") and rounding it to an
# integer would silently disable the level on a slow link.
_FLOAT_FIELDS = ("warn_num", "crit_num")


def _visible_ids() -> set[int]:
    return {a.id for a in visible_appliances().all()}


def _global_adom() -> bool:
    """True in the Global ADOM (or outside a request context)."""
    from ..services.product_scope import session_product, GLOBAL
    return (session_product() or GLOBAL) == GLOBAL


def _parse_dt(raw: str | None):
    """Accept an ISO instant (what the picker sends) or a bare ``YYYY-MM-DD``."""
    raw = (raw or "").strip()
    if not raw:
        return None
    txt = raw.replace("Z", "").replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(txt, fmt)
        except ValueError:
            continue
    return None


def _thresholds(probe) -> dict:
    """Threshold lines to draw, per kind — empty when the kind has none."""
    if probe.kind in ("cpu", "memory"):
        return {"warn": probe.warn_pct or 0, "crit": probe.crit_pct or 0}
    if probe.kind == "https":
        return {"warn": probe.warn_ms or 0, "crit": 0}
    if probe.kind in dm.API_KINDS:
        return {"warn": probe.warn_num or 0, "crit": probe.crit_num or 0}
    return {}


def _interface_target(form) -> str:
    """Join the ticked ports into ``target`` without ever slicing a name in half.

    ``target`` is 120 chars. Truncating mid-name would produce a port that
    matches nothing and a probe that silently watches less than it claims, so a
    list that does not fit drops whole names at the end instead.
    """
    joined = ""
    for raw in form.getlist('target'):
        name = (raw or '').strip()
        if not name:
            continue
        cand = (joined + "," + name) if joined else name
        if len(cand) > 120:
            break
        joined = cand
    return joined


class PageSpec:
    """Everything that differs between the two probe pages."""

    def __init__(self, *, key: str, title: str, icon: str, kinds: tuple,
                 template: str, discover: tuple, blurb: str, footnote: str,
                 job_label: str):
        self.key = key
        self.title = title
        self.icon = icon
        self.kinds = tuple(kinds)
        self.template = template
        self.discover = tuple(discover)
        self.blurb = blurb
        self.footnote = footnote
        self.job_label = job_label

    # Which form field GROUP each kind uses. cpu/memory share one ('box'):
    # identical thresholds, and a single element cannot carry two kind classes
    # without the show/hide loop fighting itself. The four REST kinds share one
    # ('api') because they take the same shape of input — a policy name plus two
    # absolute thresholds. Only the UNIT differs, and that is a label, not a form.
    _GROUP = {"https": "https", "interface": "interface", "proxyd": "proxyd",
              "cpu": "box", "memory": "box",
              "sessions": "api", "policy_sessions": "api",
              "throughput": "api", "transactions": "api"}

    def groups(self) -> list[str]:
        """Field groups this page has to render, in a stable order."""
        want = {self._GROUP[k] for k in self.kinds if k in self._GROUP}
        return [g for g in ("https", "interface", "proxyd", "box", "api")
                if g in want]

    def as_dict(self, base: str) -> dict:
        return {
            "key": self.key, "title": self.title, "icon": self.icon,
            "kinds": list(self.kinds), "discover": list(self.discover),
            "blurb": self.blurb, "footnote": self.footnote, "base": base,
            "labels": {k: dm.KIND_LABEL[k] for k in self.kinds},
            "groups": self.groups(),
            "group_of": {k: self._GROUP[k] for k in self.kinds
                         if k in self._GROUP},
            "units": {k: dm.NUM_UNIT[k] for k in self.kinds if k in dm.NUM_UNIT},
        }


def attach(bp, spec: PageSpec) -> None:  # noqa: C901 - one route per view
    """Register the full probe-page route set on ``bp``.

    Endpoint names are identical on both blueprints (``index``, ``data``,
    ``create``…), so ``url_for('deep_monitor.index')`` and
    ``url_for('service_monitor.index')`` both resolve and neither page has to
    know the other exists.
    """
    kinds = set(spec.kinds)

    # -- queries ------------------------------------------------------------

    def probes_query():
        """This page's kinds, for devices this session can see.

        Device-less URL probes (``appliance_id`` NULL) belong to whichever page
        owns their kind.
        """
        ids = _visible_ids()
        return (MonitorProbe.query
                .filter(MonitorProbe.kind.in_(spec.kinds))
                .filter(db.or_(MonitorProbe.appliance_id.is_(None),
                               MonitorProbe.appliance_id.in_(ids or [-1])))
                .order_by(MonitorProbe.kind, MonitorProbe.name))

    def get_probe(pid: int):
        """Fetch a probe of THIS page's kinds, or (None, response)."""
        probe = MonitorProbe.query.get(pid)
        if probe is None or probe.kind not in kinds:
            # A probe that exists but belongs to the other page is a 404 here,
            # not a 403: from this page's point of view it does not exist.
            return None, (jsonify({"error": "no such probe on this page"}), 404)
        if probe.appliance_id and probe.appliance_id not in _visible_ids():
            return None, (jsonify({"error": "not visible in this ADOM"}), 403)
        return probe, None

    def series(probe_id: int, limit: int = SERIES_POINTS) -> list[dict]:
        rows = (MonitorSample.query
                .filter(MonitorSample.probe_id == probe_id)
                .order_by(MonitorSample.ts.desc()).limit(limit).all())
        return [r.to_dict() for r in reversed(rows)]

    def payload() -> dict:
        probes = probes_query().all()
        out, by_kind = [], {}
        for p in probes:
            row = p.to_dict()
            row["series"] = series(p.id)
            latest = row["series"][-1] if row["series"] else None
            row["latest"] = latest
            # A probe that has never run is 'unknown', not 'ok' — never imply
            # health we have not measured.
            row["status"] = (latest or {}).get("status") or "unknown"
            out.append(row)
            by_kind.setdefault(p.kind, []).append(row["status"])
        summary = {k: {"count": len(v), "worst": dm.worst(v)}
                   for k, v in by_kind.items()}
        return {
            "page": spec.key,
            "probes": out,
            "summary": summary,
            "worst": dm.worst([r["status"] for r in out]),
            "kinds": [{"key": k, "label": dm.KIND_LABEL[k]} for k in spec.kinds],
            "devices": [{"id": a.id, "name": a.name, "kind": a.kind or "fortiweb",
                         "host": a.host}
                        for a in visible_appliances()
                        .order_by(Appliance.name).all()],
        }

    # -- reads --------------------------------------------------------------

    @bp.route('/')
    @login_required
    def index():
        try:
            can_edit = current_user.can(Permission.CONFIG_WRITE)
        except Exception:  # noqa: BLE001
            can_edit = False
        return render_template(spec.template, can_edit=can_edit,
                               page=spec.as_dict(bp.url_prefix or ''))

    @bp.route('/data')
    @login_required
    def data():
        return jsonify(payload())

    @bp.route('/probe/<int:pid>/history')
    @login_required
    def history(pid: int):
        probe, err = get_probe(pid)
        if err:
            return err
        rows = (MonitorSample.query.filter(MonitorSample.probe_id == pid)
                .order_by(MonitorSample.ts.desc()).limit(200).all())
        out = []
        for r in rows:
            item = r.to_dict()
            try:
                item["payload"] = json.loads(r.payload or "{}")
            except (ValueError, TypeError):
                item["payload"] = {}
            out.append(item)
        return jsonify({"probe": probe.to_dict(), "samples": out})

    @bp.route('/probe/<int:pid>/series')
    @login_required
    def probe_series(pid: int):
        """Chart data: 1 h / 24 h / 7 d / 30 d or explicit dates.

        Resolution is chosen server-side (raw samples, hourly buckets or daily
        buckets) and reported back in ``source`` — the UI states which one it
        drew, because an average over a day and a reading every five minutes are
        not the same claim about the device.
        """
        probe, err = get_probe(pid)
        if err:
            return err

        rng = (request.args.get('range') or '24h').strip()
        now = datetime.utcnow()
        if rng == 'custom':
            start = _parse_dt(request.args.get('from'))
            end = _parse_dt(request.args.get('to'))
            if start is None or end is None:
                return jsonify({"error": "from/to must be ISO timestamps"}), 400
            if end <= start:
                return jsonify({"error": "'to' must be after 'from'"}), 400
            if end - start > timedelta(days=dm.MAX_RANGE_DAYS):
                return jsonify({"error":
                                f"range capped at {dm.MAX_RANGE_DAYS} days"}), 400
        else:
            delta = SERIES_RANGES.get(rng)
            if delta is None:
                return jsonify({"error": f"unknown range {rng!r}"}), 400
            end, start = now, now - delta

        out = dm.series(pid, start, end)
        out["range"] = rng
        out["probe"] = probe.to_dict()
        out["meta"] = dm.METRIC_META.get(probe.kind, {})
        out["thresholds"] = _thresholds(probe)
        out["retention"]["raw_samples"] = int(probe.retention or 0)
        return jsonify(out)

    @bp.route('/device/<int:aid>/ports')
    @login_required
    def ports(aid: int):
        """Interface names for the probe form's port picker.

        Read from the harvest CACHE, never the box: the operator picks from what
        the device actually has instead of typing a name blind, the modal opens
        instantly, and it still works with the appliance powered off.
        """
        from ..services import interface_inventory

        if aid not in _visible_ids():
            return jsonify({"error": "not visible in this ADOM"}), 403
        appliance = Appliance.query.get_or_404(aid)
        try:
            rows = interface_inventory.merged(appliance).get("interfaces") or []
        except Exception as exc:  # noqa: BLE001
            return jsonify({"ports": [], "error": str(exc)})
        out = [{"name": str(r.get("name") or "").strip(),
                "ip": str(r.get("ip_address") or "").strip(),
                "status": str(r.get("status") or "").strip()}
               for r in rows if str(r.get("name") or "").strip()]
        out.sort(key=lambda r: r["name"])
        return jsonify({"ports": out})

    @bp.route('/policies/<int:aid>')
    @login_required
    def policies(aid: int):
        """Server-policy names for the target picker, from the LIVE box.

        Deliberately not the harvest cache: on a licence-locked appliance every
        cmdb read fails while ``policystatus`` still answers, and these probes
        exist precisely for that case. Failure is reported, never swallowed into
        an empty list that reads as "this device has no policies".
        """
        if aid not in _visible_ids():
            return jsonify({"error": "not visible in this ADOM"}), 403
        appliance = Appliance.query.get_or_404(aid)
        if (appliance.kind or "fortiweb") not in dm.API_PRODUCTS:
            return jsonify({"policies": [],
                            "error": "REST telemetry is %s-only"
                                     % "/".join(dm.API_PRODUCTS)})
        from ..clients.fortiweb import FortiWebClient
        try:
            rows, error = FortiWebClient(appliance).policy_status()
        except Exception as exc:  # noqa: BLE001
            return jsonify({"policies": [], "error": str(exc)})
        if error:
            return jsonify({"policies": [], "error": str(error)})
        return jsonify({"policies": [
            {"name": p["name"], "protocol": p["protocol"],
             "status": p["status"], "sessions": p["sessions"]}
            for p in dm.parse_policy_rows(rows)],
            "aggregate": dm.TOTAL_HTTP})

    # -- mutations (CONFIG_WRITE) -------------------------------------------

    def apply_form(probe: MonitorProbe, form) -> str:
        """Copy submitted fields onto ``probe``. Returns an error string or ''."""
        kind = (form.get('kind') or probe.kind or spec.kinds[0]).strip()
        if kind not in kinds:
            # Not "unknown kind": the kind may be perfectly valid — it just
            # belongs to the other page, and silently accepting it would create
            # a probe its owner page cannot see.
            return (f"{kind!r} is not a {spec.title} probe kind"
                    if kind in dm.KINDS else f"unknown probe kind {kind!r}")
        probe.kind = kind
        probe.name = (form.get('name') or '').strip()[:120]
        probe.note = (form.get('note') or '').strip()[:250]
        aid = form.get('appliance_id', type=int)
        probe.appliance_id = aid or None
        if probe.appliance_id and probe.appliance_id not in _visible_ids():
            return "that device is not visible in this ADOM"
        if kind == 'interface':
            # Multi-select: no tick at all means "every port", which is the
            # whole-device watch the discovery job creates.
            probe.target = _interface_target(form)
        elif 'target' in form:
            # Never blank an HTTPS probe's policy name just because the edit
            # form for another kind does not render the field.
            probe.target = (form.get('target') or '').strip()[:120]
        probe.url = (form.get('url') or '').strip()[:500]
        probe.process_name = (form.get('process_name') or 'proxyd').strip()[:48]
        for f in _INT_FIELDS:
            val = form.get(f, type=int)
            if val is not None:
                setattr(probe, f, max(0, val))
        for f in _FLOAT_FIELDS:
            val = form.get(f, type=float)
            if val is not None:
                setattr(probe, f, max(0.0, val))
        probe.interval_min = max(1, int(probe.interval_min or 5))
        probe.timeout_s = max(1, int(probe.timeout_s or 10))
        probe.retention = max(10, int(probe.retention or dm.DEFAULT_RETENTION))

        if kind == 'https' and not probe.url:
            return "an HTTPS probe needs a URL"
        if kind != 'https' and not probe.appliance_id:
            return f"a {kind} probe needs a device"
        if kind in dm.BOX_METRICS and probe.warn_pct and probe.crit_pct \
                and probe.crit_pct < probe.warn_pct:
            return "the critical threshold must be at or above the warning one"
        if kind in dm.API_KINDS:
            if probe.warn_num and probe.crit_num and probe.crit_num < probe.warn_num:
                return "the critical threshold must be at or above the warning one"
            # `sessions` is box-wide and takes no target; the other three address
            # one policy, and without a name they would silently grade nothing.
            if kind in ("policy_sessions", "transactions") \
                    and not (probe.target or "").strip():
                return f"a {dm.KIND_LABEL[kind]} probe needs a server policy name"
        if not probe.name:
            probe.name = (probe.url or probe.kind)[:120]
        return ''

    @bp.route('/probe', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def create():
        probe = MonitorProbe()
        err = apply_form(probe, request.form)
        if err:
            return jsonify({"error": err}), 400
        db.session.add(probe)
        db.session.commit()
        log_action(f"{spec.key}.create", target=probe.name,
                   extra={"kind": probe.kind, "url": probe.url,
                          "appliance_id": probe.appliance_id})
        return jsonify({"ok": True, "probe": probe.to_dict()})

    @bp.route('/probe/<int:pid>', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def update(pid: int):
        probe, err_res = get_probe(pid)
        if err_res:
            return err_res
        err = apply_form(probe, request.form)
        if err:
            db.session.rollback()
            return jsonify({"error": err}), 400
        db.session.commit()
        log_action(f"{spec.key}.update", target=probe.name, extra={"id": pid})
        return jsonify({"ok": True, "probe": probe.to_dict()})

    @bp.route('/probe/<int:pid>/toggle', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def toggle(pid: int):
        probe, err_res = get_probe(pid)
        if err_res:
            return err_res
        probe.enabled = not probe.enabled
        db.session.commit()
        log_action(f"{spec.key}.toggle", target=probe.name,
                   extra={"enabled": probe.enabled})
        return jsonify({"ok": True, "enabled": probe.enabled})

    @bp.route('/probe/<int:pid>/delete', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def delete(pid: int):
        probe, err_res = get_probe(pid)
        if err_res:
            return err_res
        name = probe.name
        db.session.delete(probe)
        db.session.commit()
        log_action(f"{spec.key}.delete", target=name, extra={"id": pid})
        return jsonify({"ok": True})

    # -- background execution ------------------------------------------------

    def _run_sweep(app, job_id, ids, uid, link):
        with app.app_context():
            try:
                jobsvc.update_job(job_id, percent=5, message="Probing…")
                res = dm.sweep(ids=ids, force=True)
                counts = ", ".join(f"{v} {k}"
                                   for k, v in sorted(res["counts"].items()))
                msg = f"{res['ran']} probe(s) run" + (f" — {counts}" if counts else "")
                jobsvc.finish_success(job_id, message=msg,
                                      result={"reload": True,
                                              "reload_path": link, **res})
                kind = (notify.Notification.KIND_SUCCESS if res["worst"] == "ok"
                        else notify.Notification.KIND_WARNING)
            except Exception as exc:  # noqa: BLE001
                db.session.rollback()
                jobsvc.finish_error(job_id, f"{spec.title} sweep failed: {exc}")
                msg, kind = str(exc)[:200], notify.Notification.KIND_ERROR
            if uid:
                try:
                    notify.push(uid, f"{spec.title}: {msg}", kind=kind, link=link)
                except Exception:  # noqa: BLE001
                    pass

    @bp.route('/run', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def run():
        """Probe now — one id, a list, or every enabled probe ON THIS PAGE.

        Always a job: an HTTPS round trip plus an SSH session per device is far
        too slow to block a request, and a dead appliance would hold the worker
        for the full timeout.

        "Probe now" with no selection is pinned to this page's kinds and this
        ADOM's devices. Sweeping globally from here would run the *other* page's
        probes — in a product ADOM, that means SSH into appliances of another
        product — and a button whose scope is wider than the table under it is a
        button that lies.
        """
        ids = request.form.getlist('id', type=int) or None
        mine = {p.id for p in probes_query().all()}
        if ids:
            ids = sorted(set(ids) & mine)
        else:
            ids = sorted(p.id for p in probes_query().filter_by(enabled=True).all())
        if not ids:
            return jsonify({"error": "nothing to run"}), 400
        job = jobsvc.create_job(spec.key, f"{spec.title} — probe",
                                by=getattr(current_user, 'username', '') or '',
                                meta={"ids": ids})
        link = url_for(f'{bp.name}.index')
        jobsvc.run_async(current_app._get_current_object(), job["id"],
                         lambda app, jid: _run_sweep(
                             app, jid, ids,
                             getattr(current_user, 'id', None), link))
        return jsonify({"job_id": job["id"]})

    def _run_discover(app, job_id, aid, what, uid, link):
        with app.app_context():
            try:
                appliance = Appliance.query.get(aid)
                jobsvc.update_job(job_id, percent=10,
                                  message=f"Reading {appliance.name}…")
                parts, total = [], 0
                steps = (
                    ('policies', dm.discover_https_probes, "service probe(s)"),
                    ('interfaces', dm.discover_interface_probes, "per-port probe(s)"),
                    ('api', dm.discover_api_probes, "REST telemetry probe(s)"),
                )
                for key, fn, label in steps:
                    if key not in what:
                        continue
                    res = fn(appliance)
                    if res.get("error"):
                        # FortiADC / FortiAnalyzer have no server policies. That
                        # is not a failure of the whole run — say so, keep going.
                        parts.append(res["error"])
                        continue
                    total += res["created"]
                    parts.append(f"{res['created']} {label} "
                                 f"({res['skipped']} already present)")
                if 'baseline' in what:
                    base = dm.ensure_baseline(appliance)
                    total += len(base["created"])
                    parts.append("baseline: "
                                 + (", ".join(base["created"]) or "nothing missing"))
                msg = "; ".join(parts) or "nothing selected"
                jobsvc.finish_success(job_id, message=msg,
                                      result={"reload": True,
                                              "reload_path": link,
                                              "created": total})
                if uid:
                    notify.push(uid, f"{spec.title}: {msg}",
                                kind=notify.Notification.KIND_SUCCESS, link=link)
            except Exception as exc:  # noqa: BLE001
                db.session.rollback()
                jobsvc.finish_error(job_id, f"discovery failed: {exc}")

    @bp.route('/discover', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def discover():
        """Auto-create probes for a device — only the steps this page owns.

        ``policies``    one HTTPS probe per server policy front-end (FortiWeb)
        ``baseline``    interfaces (all ports), CPU, memory, proxyd on FortiWeb
        ``interfaces``  one probe PER PORT — a separate series per interface
        ``api``         REST telemetry: box sessions + per-policy sessions and
                        throughput (FortiWeb; works even when the cmdb is
                        licence-locked)
        """
        aid = request.form.get('appliance_id', type=int)
        if not aid or aid not in _visible_ids():
            return jsonify({"error": "pick a visible device"}), 400
        what = [w for w in request.form.getlist('what') if w in spec.discover]
        if not what:
            what = list(spec.discover)
        job = jobsvc.create_job(f"{spec.key}_discover",
                                f"{spec.title} — discover",
                                by=getattr(current_user, 'username', '') or '',
                                meta={"appliance_id": aid, "what": what})
        link = url_for(f'{bp.name}.index')
        jobsvc.run_async(current_app._get_current_object(), job["id"],
                         lambda app, jid: _run_discover(
                             app, jid, aid, what,
                             getattr(current_user, 'id', None), link))
        return jsonify({"job_id": job["id"]})
