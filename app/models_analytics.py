"""Storage for the analytics boards and the persisted period reports.

Kept OUT of ``models.py`` for the same reason ``models_theme`` and
``models_adom`` are: that module is already past two thousand lines and every
table added to it makes the next one harder to find. The monitoring *data*
tables (``monitor_probe`` / ``monitor_sample`` / ``monitor_rollup``) stay where
they are — this module holds only what is layered on top of them.

Three tables, and one deliberate absence:

* :class:`MonitorDashboard` — a named board.
* :class:`MonitorPanel` — one chart on a board.
* :class:`MonitorReport` — one generated summary of one period.

The absence is a report *schedule* table. Recurring reports run through the
existing ``ScheduledAction`` catalog (action key ``monitor_report``) rather than
a parallel scheduler: one place fires automation, one history to read, one set
of overdue/failure alerts. A second scheduler would need its own guard rail for
every property the first one already has.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .models import db

# Panel visualisations. Data, not a class hierarchy: the renderer is a switch in
# JavaScript and every one of these draws from the same series payload.
VIZ_KINDS = (
    "line",       # multi-series time chart, optional min/max band
    "area",       # same, filled — for things that stack meaningfully
    "bar",        # bucketed columns; good for counts per period
    "stat",       # one big number + sparkline + delta vs previous period
    "gauge",      # latest value against the probe's own thresholds
    "heatmap",    # series x bucket, coloured by status
    "table",      # min/avg/max/last/healthy% per series
    "status",     # availability strip: one band per bucket
)

# How a panel picks the probes it draws.
SELECT_MODES = ("probes", "rule", "metricsql")
# "metricsql" resolves at render time against the node's metrics store: one
# expression can draw a hundred devices (`satom_box_cpu_pct` or
# `topk(10, satom_policy_conn_per_sec)`), which is the only selection mode
# that survives a fleet where enumerating series is not an option.

# Which number a single-value panel (stat/gauge) reports.
STAT_FUNCS = ("last", "avg", "min", "max", "sum", "healthy_pct")

REPORT_PERIODS = ("daily", "weekly", "monthly")


class MonitorDashboard(db.Model):
    """A named board of panels.

    ``product`` scopes the board to an ADOM (empty string = Global, matching the
    convention every other product-scoped table in this schema uses, where ''
    means "predates scoping / belongs to everyone").

    ``builtin`` boards are reconciled from code on every boot and cannot be
    edited or deleted from the UI. That is the same contract the shipped themes
    use, and it exists for the same reason: a board that ships with the product
    is code, so there is no operator intent to preserve, and an installation
    whose only board was deleted would open on an empty page with no way back.
    """

    __tablename__ = "monitor_dashboard"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), nullable=False, unique=True, index=True)
    title = db.Column(db.String(120), nullable=False, default="")
    description = db.Column(db.String(400), nullable=True, default="")
    product = db.Column(db.String(16), nullable=False, default="", index=True)
    builtin = db.Column(db.Boolean, nullable=False, default=False)
    position = db.Column(db.Integer, nullable=False, default=100)

    # Board-level defaults a panel may override.
    default_range = db.Column(db.String(16), nullable=False, default="24h")
    refresh_s = db.Column(db.Integer, nullable=False, default=0)   # 0 = manual

    created_by = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # NOT passive_deletes, for the reason documented on MonitorProbe.samples:
    # SQLite ships with foreign keys DISABLED, so leaning on ON DELETE CASCADE
    # would leak orphan panels on any non-Postgres deployment and in the test
    # suite. A board holds a handful of panels; the extra SELECT is free.
    panels = db.relationship(
        "MonitorPanel", backref="dashboard", lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="MonitorPanel.position, MonitorPanel.id")

    def to_dict(self, *, with_panels: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id, "slug": self.slug, "title": self.title,
            "description": self.description or "",
            "product": self.product or "", "builtin": bool(self.builtin),
            "position": self.position,
            "default_range": self.default_range or "24h",
            "refresh_s": self.refresh_s or 0,
            "created_by": self.created_by or "",
            "updated_at": self.updated_at.isoformat(timespec="seconds")
                          if self.updated_at else "",
        }
        if with_panels:
            out["panels"] = [p.to_dict() for p in self.panels]
        return out

    def __repr__(self) -> str:
        return f"<MonitorDashboard {self.slug!r}>"


class MonitorPanel(db.Model):
    """One chart on a board.

    The important field is ``select_mode``.

    ``probes`` pins an explicit id list. ``rule`` stores a *kind* plus an
    optional device filter and resolves at render time, so a probe recreated by
    Discover — or a newly registered appliance — joins the panel with no edit.
    A frozen id list is how a board silently narrows while still looking
    complete: the chart keeps drawing, just with fewer lines than the operator
    believes they are watching.
    """

    __tablename__ = "monitor_panel"

    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(
        db.Integer, db.ForeignKey("monitor_dashboard.id", ondelete="CASCADE"),
        nullable=False, index=True)

    title = db.Column(db.String(120), nullable=False, default="")
    subtitle = db.Column(db.String(200), nullable=True, default="")
    viz = db.Column(db.String(16), nullable=False, default="line")

    select_mode = db.Column(db.String(16), nullable=False, default="rule")
    probe_ids = db.Column(db.String(500), nullable=True, default="")  # csv
    rule_kind = db.Column(db.String(24), nullable=True, default="")
    rule_devices = db.Column(db.String(500), nullable=True, default="")  # csv ids
    rule_match = db.Column(db.String(120), nullable=True, default="")  # name substring
    # MetricsQL selector for select_mode="metricsql". Stored verbatim and
    # evaluated by the store, never interpolated into SQL or a shell.
    vm_expr = db.Column(db.String(500), nullable=True, default="")
    vm_legend = db.Column(db.String(120), nullable=True, default="")   # label key
    vm_unit = db.Column(db.String(24), nullable=True, default="")

    # Presentation
    range_key = db.Column(db.String(16), nullable=False, default="")   # '' = board
    stat_func = db.Column(db.String(16), nullable=False, default="last")
    show_band = db.Column(db.Boolean, nullable=False, default=True)
    show_v2 = db.Column(db.Boolean, nullable=False, default=False)
    show_thresholds = db.Column(db.Boolean, nullable=False, default=True)
    compare_prev = db.Column(db.Boolean, nullable=False, default=False)

    # Layout: a 12-column grid, so 3/4/6/12 all tile cleanly.
    width = db.Column(db.Integer, nullable=False, default=6)
    height = db.Column(db.Integer, nullable=False, default=260)
    position = db.Column(db.Integer, nullable=False, default=100)

    options = db.Column(db.Text, nullable=True, default="")   # JSON escape hatch

    def id_list(self) -> list[int]:
        return _csv_ints(self.probe_ids)

    def device_list(self) -> list[int]:
        return _csv_ints(self.rule_devices)

    def opts(self) -> dict:
        try:
            val = json.loads(self.options or "{}")
            return val if isinstance(val, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "dashboard_id": self.dashboard_id,
            "title": self.title, "subtitle": self.subtitle or "",
            "viz": self.viz, "select_mode": self.select_mode,
            "probe_ids": self.id_list(),
            "rule_kind": self.rule_kind or "",
            "rule_devices": self.device_list(),
            "rule_match": self.rule_match or "",
            "vm_expr": self.vm_expr or "",
            "vm_legend": self.vm_legend or "",
            "vm_unit": self.vm_unit or "",
            "range_key": self.range_key or "",
            "stat_func": self.stat_func or "last",
            "show_band": bool(self.show_band), "show_v2": bool(self.show_v2),
            "show_thresholds": bool(self.show_thresholds),
            "compare_prev": bool(self.compare_prev),
            "width": self.width, "height": self.height,
            "position": self.position, "options": self.opts(),
        }

    def __repr__(self) -> str:
        return f"<MonitorPanel {self.viz} {self.title!r}>"


class MonitorReport(db.Model):
    """A generated summary of one period, stored so it stays comparable.

    The report is persisted rather than recomputed on view for two reasons.
    Raw samples age out at ``probe.retention`` (~2 days at the default), so a
    report rebuilt six months later would silently answer from coarser data than
    the one the operator read at the time. And a stored report is a record: it
    still describes what the fleet looked like after the probe that produced it
    has been deleted.

    ``period_start`` is inclusive and ``period_end`` EXCLUSIVE. Two adjacent
    reports must not both claim the instant on their shared boundary.
    """

    __tablename__ = "monitor_report"
    __table_args__ = (
        db.UniqueConstraint("period", "period_start", "product",
                            name="uq_report_period"),
    )

    id = db.Column(db.Integer, primary_key=True)
    period = db.Column(db.String(16), nullable=False, default="daily", index=True)
    period_start = db.Column(db.DateTime, nullable=False, index=True)
    period_end = db.Column(db.DateTime, nullable=False)
    product = db.Column(db.String(16), nullable=False, default="", index=True)

    title = db.Column(db.String(200), nullable=False, default="")
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    generated_by = db.Column(db.String(64), nullable=True, default="")

    # Roll-up headline figures, denormalised so the LIST view never has to parse
    # every payload just to render a row.
    probes_n = db.Column(db.Integer, nullable=False, default=0)
    devices_n = db.Column(db.Integer, nullable=False, default=0)
    samples_n = db.Column(db.Integer, nullable=False, default=0)
    healthy_pct = db.Column(db.Float, nullable=True)     # None = nothing measured
    worst_status = db.Column(db.String(16), nullable=False, default="unknown")
    incidents_n = db.Column(db.Integer, nullable=False, default=0)

    emailed_at = db.Column(db.DateTime, nullable=True)
    payload = db.Column(db.Text, nullable=True, default="")   # full JSON body

    def body(self) -> dict:
        try:
            val = json.loads(self.payload or "{}")
            return val if isinstance(val, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self, *, with_body: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id, "period": self.period,
            "period_start": self.period_start.isoformat(timespec="seconds"),
            "period_end": self.period_end.isoformat(timespec="seconds"),
            "product": self.product or "", "title": self.title,
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "generated_by": self.generated_by or "",
            "probes_n": self.probes_n, "devices_n": self.devices_n,
            "samples_n": self.samples_n,
            # None, not 0. "Nothing was measured" and "everything measured was
            # unhealthy" are different findings and must not share a rendering.
            "healthy_pct": self.healthy_pct,
            "worst_status": self.worst_status or "unknown",
            "incidents_n": self.incidents_n,
            "emailed_at": self.emailed_at.isoformat(timespec="seconds")
                          if self.emailed_at else "",
        }
        if with_body:
            out["body"] = self.body()
        return out

    def __repr__(self) -> str:
        return f"<MonitorReport {self.period} {self.period_start:%Y-%m-%d}>"


def _csv_ints(raw: str | None) -> list[int]:
    out: list[int] = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            out.append(int(chunk))
        except ValueError:
            continue
    return out
