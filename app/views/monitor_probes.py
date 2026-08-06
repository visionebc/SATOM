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

#: Columns that understand NULL as "inherit from this product's scope"
#: (``services.thresholds``). Everything else in ``_INT_FIELDS`` is plumbing —
#: an interval or a timeout — that has no scope to fall back to.
_INHERITABLE = ("warn_ms", "tls_warn_days", "stale_after_h",
                "warn_pct", "crit_pct", "warn_num", "crit_num")

#: Longest mute this page will write. There is deliberately no "forever": a
#: silence that never expires becomes permanent by inattention, and the reason
#: it was granted stops being true long before anybody re-reads it.
MAX_SUPPRESS_HOURS = 720.0


def _apply_suppression(probe, form) -> None:
    """Mute or unmute a probe from the edit form.

    A suppressed probe still runs, still stores samples and still shows its own
    real status; what it stops doing is raising the DEVICE roll-up — which is
    the one thing both the badge and the alert mail read, so the page and the
    mailbox stay in agreement. The reason and the expiry are mandatory
    together: a silence nobody can explain is indistinguishable from a bug.
    """
    if "suppress_hours" not in form:
        return
    raw = (form.get("suppress_hours") or "").strip()
    try:
        hours = float(raw) if raw else 0.0
    except ValueError:
        hours = 0.0
    reason = (form.get("suppress_reason") or "").strip()[:200]
    if hours <= 0:
        probe.suppress_until = None
        probe.suppress_reason = ""
        return
    from datetime import timedelta
    probe.suppress_until = (datetime.utcnow()
                            + timedelta(hours=min(hours, MAX_SUPPRESS_HOURS)))
    probe.suppress_reason = reason or "no reason recorded"


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
    """Threshold lines to draw, per kind — empty when the kind has none.

    Resolved, never read off the column: a probe that inherits its levels holds
    NULL there, and a chart drawn from the raw column would show no threshold
    line at all on the majority of probes while still grading against one."""
    from ..services import thresholds as th
    if probe.kind in ("cpu", "memory"):
        return {"warn": th.num(probe, "warn_pct"), "crit": th.num(probe, "crit_pct")}
    if probe.kind == "https":
        return {"warn": th.num(probe, "warn_ms"), "crit": 0}
    if probe.kind in dm.API_KINDS:
        return {"warn": th.num(probe, "warn_num"), "crit": th.num(probe, "crit_num")}
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
                 job_label: str, rollup: bool = False):
        self.key = key
        self.title = title
        self.icon = icon
        self.kinds = tuple(kinds)
        self.template = template
        self.discover = tuple(discover)
        self.blurb = blurb
        self.footnote = footnote
        self.job_label = job_label
        # Per-device traffic cards + the per-policy drill-down. Off by default:
        # they consolidate the REST-telemetry payloads, and a page whose kinds
        # never produce a ``policy``/``stats`` payload would render a strip of
        # empty cards that reads as "no traffic" rather than "not applicable".
        self.rollup = bool(rollup)

    # Which form field GROUP each kind uses. cpu/memory share one ('box'):
    # identical thresholds, and a single element cannot carry two kind classes
    # without the show/hide loop fighting itself. The four REST kinds share one
    # ('api') because they take the same shape of input — a policy name plus two
    # absolute thresholds. Only the UNIT differs, and that is a label, not a form.
    _GROUP = {"https": "https", "interface": "interface", "proxyd": "proxyd",
              "cpu": "box", "memory": "box",
              "sessions": "api", "policy_sessions": "api",
              "throughput": "api", "transactions": "api",
              # The two FortiAuthenticator kinds take the SAME shape of input as
              # the FortiWeb ones — a target name plus two absolute thresholds —
              # so they reuse the group rather than growing a sixth. What
              # differs (which names are valid, what the number means) is a
              # label and a datalist, not a form.
              "licence": "api", "tokens": "api"}

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
            # Kinds whose target is a CLOSED set of names, shipped to the form so
            # the picker offers exactly what the validator accepts. A free-text
            # box next to a server-side allowlist is a typo that becomes an
            # error sample instead of a form message.
            "targets": {k: v for k, v in (
                ("licence", [{"value": key, "label": lbl}
                             for key, (_f, lbl) in sorted(dm.FAC_CAPACITY.items())]),
                ("tokens", [{"value": key, "label": lbl}
                            for key, (_f, lbl) in sorted(dm.FAC_TOKENS.items())]),
            ) if k in self.kinds},
            # Which products each of this page's kinds can measure — the form
            # uses it to explain a greyed-out choice instead of letting the
            # operator submit and read a rejection.
            "kind_products": {k: list(dm.products_for(k)) for k in self.kinds},
            "rollup": self.rollup,
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
            # Where each number came from. Without this the page shows a grade
            # produced by a value the operator never typed and cannot locate.
            from ..services import thresholds as th
            row["resolved"] = {o["key"]: o for o in th.probe_origins(p)}
            row["suppressed"] = bool(getattr(p, "suppressed", False))
            row["suppress_note"] = getattr(p, "suppress_note", "") or ""
            row["suppress_reason"] = p.suppress_reason or ""
            out.append(row)
            by_kind.setdefault(p.kind, []).append(row["status"])
        summary = {k: {"count": len(v), "worst": dm.worst(v)}
                   for k, v in by_kind.items()}
        # The rollup is OMITTED, not emptied, on a page that does not own it —
        # the collection never runs, so a page without the flag cannot leak a
        # half-built card set through a template that forgot to check.
        rollup = []
        if spec.rollup:
            from ..services import service_rollup
            rollup = service_rollup.device_rollup(
                visible_appliances().order_by(Appliance.name).all())
        out_payload = {
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
        if spec.rollup:
            out_payload["device_rollup"] = rollup
        return out_payload

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

    if spec.rollup:
        @bp.route('/policy/<int:aid>')
        @login_required
        def policy_detail(aid: int):
            """Everything stored about ONE server policy, in one object.

            Reads only saved samples — no call to the appliance, so it opens
            instantly and still answers with the box powered off or its cmdb
            licence-locked. The policy name arrives as a query parameter rather
            than a path segment: FortiWeb allows characters that would need
            escaping in a URL path, and a name that fails to round-trip would
            look like "policy not monitored".
            """
            from ..services import service_rollup

            if aid not in _visible_ids():
                return jsonify({"error": "not visible in this ADOM"}), 403
            appliance = Appliance.query.get_or_404(aid)
            name = (request.args.get('name') or '').strip()
            if not name:
                return jsonify({"error": "name is required"}), 400
            out = service_rollup.policy_detail(appliance, name)
            if out is None:
                # No probe targets this policy. A 404 rather than an empty
                # skeleton: "not monitored" and "idle" must not render alike.
                return jsonify({"error": "no probe on this page targets %r"
                                         % name}), 404
            return jsonify(out)

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
        # Gate on the products that have POLICY-addressed kinds, not on every
        # product with any REST telemetry. Since FortiAuthenticator gained
        # licence/tokens it is in API_PRODUCTS — and the old gate would have let
        # it through to a FortiWeb client asking for server policies it does not
        # have. Derived, so a second product with policies needs no edit here.
        picker_products = dm.products_for("policy_sessions")
        if (appliance.kind or "fortiweb") not in picker_products:
            return jsonify({"policies": [],
                            "error": "the server-policy picker is %s-only"
                                     % "/".join(picker_products)})
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
        # Refuse an inapplicable kind HERE, at creation, from the same map the
        # runner and discovery consult. Accepting it would produce a row that
        # renders fine and then reports a transport error forever — which reads
        # as a broken appliance, not as a check that does not apply to it.
        if probe.appliance_id:
            dev = db.session.get(Appliance, probe.appliance_id)
            prod = (getattr(dev, 'kind', '') or '') if dev else ''
            if not dm.supports(kind, prod):
                return ("%s cannot be measured on %s — supported: %s"
                        % (dm.KIND_LABEL.get(kind, kind),
                           prod or 'that device',
                           "/".join(dm.products_for(kind) or ("any product",))))
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
        # Three inputs, three different answers, and conflating any two of
        # them loses information the operator supplied:
        #   field ABSENT from the form -> leave the column alone (the edit form
        #     for another kind simply does not render it),
        #   field PRESENT and EMPTY   -> clear the override, inherit the scope,
        #   field PRESENT with a value -> override (0 switches that level off).
        for f in _INT_FIELDS:
            if f in _INHERITABLE and f in form and not (form.get(f) or "").strip():
                setattr(probe, f, None)
                continue
            val = form.get(f, type=int)
            if val is not None:
                setattr(probe, f, max(0, val))
        for f in _FLOAT_FIELDS:
            if f in _INHERITABLE and f in form and not (form.get(f) or "").strip():
                setattr(probe, f, None)
                continue
            val = form.get(f, type=float)
            if val is not None:
                setattr(probe, f, max(0.0, val))
        _apply_suppression(probe, form)
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
            # The FortiAuthenticator kinds address a NAMED counter, not a free
            # string. An unrecognised name is rejected instead of silently
            # falling back to the default, because a probe labelled "FSSO" that
            # is actually grading licensed users is worse than no probe.
            for k, choices in (("licence", dm.FAC_CAPACITY),
                               ("tokens", dm.FAC_TOKENS)):
                if kind != k:
                    continue
                want = (probe.target or "").strip().lower()
                if not want:
                    probe.target = (dm.DEFAULT_FAC_RESOURCE if k == "licence"
                                    else dm.DEFAULT_FAC_TOKEN)
                elif want not in choices:
                    return ("%r is not a %s target — pick one of: %s"
                            % (probe.target, dm.KIND_LABEL[k],
                               ", ".join(sorted(choices))))
                else:
                    probe.target = want
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

    @bp.route('/probe/<int:pid>/unmute', methods=['POST'])
    @login_required
    @require_permission(Permission.CONFIG_WRITE)
    def unmute(pid: int):
        """Lift a suppression now. Muting needs a reason and an expiry and so
        lives in the edit form; lifting one never needs justifying."""
        probe, err_res = get_probe(pid)
        if err_res:
            return err_res
        probe.suppress_until = None
        probe.suppress_reason = ""
        db.session.commit()
        log_action(f"{spec.key}.unmute", target=probe.name, extra={"id": pid})
        return jsonify({"ok": True})

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

    def _run_sweep(app, job_id, ids, uid, link, product=""):
        """Run the sweep as a BACKGROUND job — silent unless it breaks.

        A sweep that ran is not news: the table under the button reloads itself,
        and a probe that turned crit is already carried by the device badge and
        by the alert engine (which owns escalation and cooldown). Announcing
        every successful run in the bell is how a notification area stops being
        read. A sweep that FAILED is the one outcome the page cannot show — the
        numbers just stay stale — so that, and only that, is pushed.

        ``product`` is the ADOM stamped on the job at creation: this worker runs
        in a thread with no request context, so an unstamped notification would
        fall into the unscoped bucket and surface under FortiWeb.
        """
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
                return                       # ran fine → say nothing
            except Exception as exc:  # noqa: BLE001
                db.session.rollback()
                jobsvc.finish_error(job_id, f"{spec.title} sweep failed: {exc}")
                msg = str(exc)[:200]
            if uid:
                try:
                    notify.push(uid, f"{spec.title} sweep failed: {msg}",
                                kind=notify.Notification.KIND_ERROR,
                                link=link, product=product)
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
                                meta={"ids": ids}, background=True)
        link = url_for(f'{bp.name}.index')
        product = (job.get("meta") or {}).get("product") or ""
        jobsvc.run_async(current_app._get_current_object(), job["id"],
                         lambda app, jid: _run_sweep(
                             app, jid, ids,
                             getattr(current_user, 'id', None), link, product))
        return jsonify({"job_id": job["id"]})

    def _run_discover(app, job_id, aid, what, uid, link, product=""):
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
                                kind=notify.Notification.KIND_SUCCESS, link=link,
                                product=product)
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
        product = (job.get("meta") or {}).get("product") or ""
        jobsvc.run_async(current_app._get_current_object(), job["id"],
                         lambda app, jid: _run_discover(
                             app, jid, aid, what,
                             getattr(current_user, 'id', None), link, product))
        return jsonify({"job_id": job["id"]})
