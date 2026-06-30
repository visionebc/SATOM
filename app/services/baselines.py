"""Baselines — named, scoped assemblies of APPROVED templates (the "armado").

A baseline binds a name + zone/line/department to a set of approved templates.
Provisioning resolves a baseline's scope to the matching appliances and pushes
its templates through the shared dry-run -> canary machinery. Templates stay
scope-free; the scope lives here.
"""
from __future__ import annotations

from ..models import Appliance, Baseline, BaselineTemplate, Template, db
from . import section_taxonomy as tax


def list_baselines() -> list[Baseline]:
    return Baseline.query.order_by(Baseline.name).all()


def get_baseline(baseline_id: int) -> Baseline | None:
    return Baseline.query.get(baseline_id)


def approved_templates() -> list[Template]:
    """Every APPROVED template, newest version first within a name."""
    return (Template.query
            .filter_by(status=Template.STATUS_APPROVED)
            .order_by(Template.kind, Template.name, Template.version.desc())
            .all())


def _link_rows(template_ids: list[int]) -> list[BaselineTemplate]:
    """Build junction rows for the given approved template ids, in order.

    Raises ``ValueError`` if any id is missing or not approved."""
    rows: list[BaselineTemplate] = []
    for pos, tid in enumerate(template_ids):
        t = Template.query.get(tid)
        if t is None:
            raise ValueError(f"Template {tid} not found")
        if t.status != Template.STATUS_APPROVED:
            raise ValueError(f'Template "{t.name}" is not approved')
        rows.append(BaselineTemplate(template_id=t.id,
                                     section=tax.section_for_kind(t.kind),
                                     position=pos))
    return rows


def create_baseline(name: str, *, zone: str = "", line: str = "",
                    department: str = "", template_ids: list[int] | None = None,
                    note: str = "", author: str = "") -> Baseline:
    name = (name or "").strip()
    if not name:
        raise ValueError("Baseline name is required")
    if Baseline.query.filter_by(name=name).first() is not None:
        raise ValueError(f'A baseline named "{name}" already exists')
    b = Baseline(name=name, zone=(zone or "").strip(), line=(line or "").strip(),
                 department=(department or "").strip(),
                 note=(note or "").strip(), author=(author or "").strip())
    b.items = _link_rows(list(template_ids or []))
    db.session.add(b)
    db.session.commit()
    return b


def update_baseline(baseline_id: int, *, name: str | None = None,
                    zone: str | None = None, line: str | None = None,
                    department: str | None = None,
                    template_ids: list[int] | None = None,
                    note: str | None = None) -> Baseline:
    b = Baseline.query.get(baseline_id)
    if b is None:
        raise ValueError(f"Baseline {baseline_id} not found")
    if name is not None:
        new_name = name.strip()
        if not new_name:
            raise ValueError("Baseline name is required")
        clash = Baseline.query.filter(Baseline.name == new_name,
                                      Baseline.id != b.id).first()
        if clash is not None:
            raise ValueError(f'A baseline named "{new_name}" already exists')
        b.name = new_name
    if zone is not None:
        b.zone = zone.strip()
    if line is not None:
        b.line = line.strip()
    if department is not None:
        b.department = department.strip()
    if note is not None:
        b.note = note.strip()
    if template_ids is not None:
        b.items = _link_rows(list(template_ids))
    db.session.commit()
    return b


def delete_baseline(baseline_id: int) -> bool:
    b = Baseline.query.get(baseline_id)
    if b is None:
        return False
    db.session.delete(b)
    db.session.commit()
    return True


def matching_devices(baseline: Baseline) -> list[Appliance]:
    """Appliances whose classification matches the baseline scope. An empty
    facet on the baseline means "any" for that facet."""
    q = Appliance.query
    if (baseline.zone or "").strip():
        q = q.filter(Appliance.zone == baseline.zone)
    if (baseline.line or "").strip():
        q = q.filter(Appliance.line == baseline.line)
    if (baseline.department or "").strip():
        q = q.filter(Appliance.department == baseline.department)
    return q.order_by(Appliance.name).all()


def baseline_push_items(baseline: Baseline) -> list:
    """Flatten every composing template's body into ``iter_push_items`` rows,
    in baseline order (section by section). Reused by the apply path."""
    from .bulk import iter_push_items
    items: list = []
    for link in baseline.items:
        t = Template.query.get(link.template_id)
        if t is not None:
            items.extend(iter_push_items(t.body_dict))
    return items
