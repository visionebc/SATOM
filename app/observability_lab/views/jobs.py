from flask import Blueprint, abort, render_template, request
from flask_login import login_required

from ..extensions import db
from ..models import Job, Source

bp = Blueprint("jobs", __name__, url_prefix="/jobs")

KINDS = ("collect", "test")
STATUSES = ("done", "failed", "running")


@bp.route("/")
@login_required
def index():
    kind = request.args.get("kind") if request.args.get("kind") in KINDS else ""
    status = request.args.get("status") if request.args.get("status") in STATUSES else ""
    q = Job.query
    if kind:
        q = q.filter_by(kind=kind)
    if status:
        q = q.filter_by(status=status)
    return render_template("jobs/index.html", jobs=q.order_by(Job.id.desc()).limit(200).all(),
                           kind=kind, status=status, kinds=KINDS, statuses=STATUSES,
                           source_names={s.id: s.name for s in Source.query.all()})


@bp.route("/<int:jid>")
@login_required
def detail(jid):
    j = db.session.get(Job, jid)
    if j is None:
        abort(404)
    src = db.session.get(Source, j.source_id) if j.source_id else None
    return render_template("jobs/detail.html", j=j, src=src,
                           failed=[s for s in j.steps if not s.ok])
