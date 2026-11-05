from flask import Blueprint, render_template
from flask_login import login_required

from ..connectors import PLANNED, kinds
from ..models import Audit, Diagram, EndpointStatus, Fact, Job, Source

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def index():
    from .. import satom_bridge
    if not satom_bridge.read_only():
        satom_bridge.sync_sources()
    sources = Source.query.order_by(Source.name).all()
    failing = EndpointStatus.query.filter_by(ok=False).count()
    last = max((s.last_run_at for s in sources if s.last_run_at), default=None)
    return render_template(
        "index.html",
        diagrams=Diagram.query.order_by(Diagram.updated_at.desc()).limit(8).all(),
        sources=sources, failing_reads=failing, last_run=last,
        sources_ok=sum(1 for s in sources if s.last_status == "ok"),
        jobs=Job.query.order_by(Job.id.desc()).limit(10).all(),
        fact_count=Fact.query.count(), diagram_count=Diagram.query.count(),
        source_names={s.id: s.name for s in sources},
        kinds=kinds(), planned=PLANNED)


@bp.route("/audit")
@login_required
def audit_log():
    return render_template("audit.html", rows=Audit.query.order_by(Audit.id.desc()).limit(300).all())
