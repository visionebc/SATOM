import threading

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from .. import collect, crypto, overlay
from ..connectors import PLANNED, get as connector_class, kinds
from ..extensions import db
from ..models import EndpointStatus, Job, Source, audit
from . import admin_required

bp = Blueprint("sources", __name__, url_prefix="/sources")


def _get(sid) -> Source:
    s = db.session.get(Source, sid)
    if s is None:
        abort(404)
    return s


@bp.route("/")
@login_required
def index():
    from .. import satom_bridge
    if not satom_bridge.read_only():
        satom_bridge.sync_sources()
    reads = {}
    for st in EndpointStatus.query.all():
        ok, total = reads.get(st.source_id, (0, 0))
        reads[st.source_id] = (ok + (1 if st.ok else 0), total + 1)
    return render_template("sources/index.html", sources=Source.query.order_by(Source.name).all(),
                           kinds=kinds(), planned=PLANNED, reads=reads,
                           satom_planned=satom_bridge.planned_devices())


def _apply_form(s: Source, form) -> list[str]:
    errors = []
    s.name = (form.get("name") or "").strip()[:80]
    s.host = (form.get("host") or "").strip()[:255]
    try:
        s.port = int(form.get("port") or 443)
        s.interval_s = max(60, int(form.get("interval_s") or 300))
        cap = int(form.get("max_policy_detail") or 60)
    except ValueError:
        errors.append("port, interval and cap must be numbers")
        cap = 60
    s.username = (form.get("username") or "").strip()[:128]
    s.tls_verify = form.get("tls_verify") == "on"
    s.ca_pem = (form.get("ca_pem") or "").strip()
    s.enabled = form.get("enabled") == "on"
    cfg = dict(s.config or {})
    cfg["max_policy_detail"] = max(0, min(500, cap))
    if form.get("vdom") is not None:
        cfg["vdom"] = (form.get("vdom") or "").strip()[:64]
    s.config = cfg
    if form.get("secret"):
        s.secret_enc = crypto.encrypt(form.get("secret"))
    if not s.name or not s.host:
        errors.append("name and host are required")
    if s.ca_pem and "BEGIN CERTIFICATE" not in s.ca_pem:
        errors.append("the CA must be a PEM certificate")
    return errors


@bp.route("/new", methods=["GET", "POST"])
@login_required
@admin_required
def new():
    flash("Sources are SATOM's devices: add, edit or remove them in SATOM › Devices.", "info")
    return redirect(url_for("sources.index"))
    kind = request.values.get("kind", "fortiweb")
    if kind not in kinds():
        flash("%s is planned, not available yet." % PLANNED.get(kind, kind), "warning")
        return redirect(url_for("sources.index"))
    s = Source(kind=kind, tls_verify=True, enabled=True, config={})
    if request.method == "POST":
        errors = _apply_form(s, request.form)
        if Source.query.filter_by(name=s.name).first():
            errors.append("a source with that name exists")
        if not request.form.get("secret"):
            errors.append("the %s is required" % connector_class(kind).secret_label.lower())
        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            db.session.add(s)
            db.session.flush()
            audit(current_user.username, "source.create", s.name,
                  "%s %s:%s tls_verify=%s" % (s.kind, s.host, s.port, s.tls_verify))
            db.session.commit()
            flash("Source added. Test it, then collect.", "success")
            return redirect(url_for("sources.detail", sid=s.id))
    return render_template("sources/form.html", s=s, kind_label=kinds()[kind], conn=connector_class(kind))


@bp.route("/<int:sid>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit(sid):
    flash("Sources are SATOM's devices: add, edit or remove them in SATOM › Devices.", "info")
    return redirect(url_for("sources.index"))
    s = _get(sid)
    if request.method == "POST":
        errors = _apply_form(s, request.form)
        if errors:
            db.session.rollback()
            for e in errors:
                flash(e, "danger")
        else:
            audit(current_user.username, "source.update", s.name,
                  "%s:%s tls_verify=%s secret_changed=%s" % (s.host, s.port, s.tls_verify,
                                                             bool(request.form.get("secret"))))
            db.session.commit()
            flash("Saved.", "success")
            return redirect(url_for("sources.detail", sid=s.id))
    return render_template("sources/form.html", s=s, kind_label=kinds().get(s.kind, s.kind), conn=connector_class(s.kind))


@bp.route("/<int:sid>")
@login_required
def detail(sid):
    s = _get(sid)
    statuses = EndpointStatus.query.filter_by(source_id=s.id).order_by(EndpointStatus.endpoint).all()
    reads = {"failed": [r for r in statuses if not r.ok],
             "health": [r for r in statuses if r.ok and r.endpoint.startswith("backend health")],
             "other": [r for r in statuses if r.ok and not r.endpoint.startswith("backend health")]}
    return render_template("sources/detail.html", s=s, ov=overlay.for_source(s),
                           statuses=statuses, reads=reads,
                           jobs=Job.query.filter_by(source_id=s.id).order_by(Job.id.desc()).limit(10).all())


@bp.route("/<int:sid>/test", methods=["POST"])
@login_required
@admin_required  # in SATOM: reaching the device needs config_write
def test(sid):
    s = _get(sid)
    out = collect.test_source(s, current_user.username)
    flash(("Connection OK — " if out["ok"] else "Connection FAILED — ") + out["detail"],
          "success" if out["ok"] else "danger")
    return redirect(url_for("sources.detail", sid=sid))


@bp.route("/<int:sid>/collect", methods=["POST"])
@login_required
@admin_required  # in SATOM: reaching the device needs config_write
def collect_now(sid):
    s = _get(sid)
    app = current_app._get_current_object()
    user = current_user.username
    audit(user, "source.collect", s.name)
    db.session.commit()

    def run():
        with app.app_context():
            collect.run_source(db.session.get(Source, sid), user)

    threading.Thread(target=run, daemon=True, name="collect-%d" % sid).start()
    flash("Collection started — it shows under Jobs; this page refreshes the facts.", "info")
    return redirect(url_for("sources.detail", sid=sid))


@bp.route("/<int:sid>/delete", methods=["POST"])
@login_required
@admin_required
def delete(sid):
    flash("Sources are SATOM's devices: add, edit or remove them in SATOM › Devices.", "info")
    return redirect(url_for("sources.index"))
    s = _get(sid)
    audit(current_user.username, "source.delete", s.name)
    db.session.delete(s)
    db.session.commit()
    flash("Source deleted with its facts.", "success")
    return redirect(url_for("sources.index"))
