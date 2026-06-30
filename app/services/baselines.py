"""Baselines / Combos — scoped containers binding APPROVED templates to a
zone/line/department permutation (the "armado").

A *combo* is one Baseline row per zone x line x department permutation,
auto-generated from the classification catalogs. Operators open a combo and
assign approved templates (the "things") to it; a template may be assigned to
several combos. Provisioning resolves a combo's scope to the matching
appliances and pushes its templates through the shared dry-run -> canary
machinery. Templates stay scope-free; the scope lives on the combo.
"""
from __future__ import annotations

from ..models import Appliance, Baseline, BaselineTemplate, Template, db
from . import section_taxonomy as tax
from . import settings_store


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


def approved_templates_for_scope(zone: str = "", line: str = "",
                                  department: str = "") -> list[Template]:
    """APPROVED system-profile templates whose _scope matches the given facets.

    An empty facet on the *template* means it applies to any value for that
    facet. An empty facet on the *query* means "any" — so all templates match.
    Returns newest-version-first within each name.
    """
    candidates = (Template.query
                  .filter_by(status=Template.STATUS_APPROVED,
                             kind="system-profile")
                  .order_by(Template.name, Template.version.desc())
                  .all())
    out = []
    for t in candidates:
        body = t.body_dict or {}
        scope = body.get("_scope") or {}
        tz = (scope.get("zone") or "").strip()
        tl = (scope.get("line") or "").strip()
        td = (scope.get("department") or "").strip()
        # A template facet == "" means "any"; a query facet == "" means "any".
        if zone and tz and tz != zone:
            continue
        if line and tl and tl != line:
            continue
        if department and td and td != department:
            continue
        out.append(t)
    return out


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


# --------------------------------------------------------------------------- #
#  Combo grid — auto-generated zone x line x department permutations            #
# --------------------------------------------------------------------------- #
def combo_name(zone: str, line: str, department: str) -> str:
    """Stable display/identity name for a combo permutation."""
    return " / ".join((p or "Any") for p in (zone, line, department))


def _catalog_axes() -> tuple[list[str], list[str], list[str]]:
    """The three classification axes, each falling back to a single '' ("any")
    slot when its catalog is empty so combos still generate across the others."""
    cls = settings_store.all_classification()
    zones = list(cls.get("zones") or []) or [""]
    lines = list(cls.get("lines") or []) or [""]
    departments = list(cls.get("departments") or []) or [""]
    return zones, lines, departments


def _all_permutations() -> list[tuple[str, str, str]]:
    """Every (zone, line, department) permutation worth a combo. The all-"any"
    triple is skipped (nothing to scope)."""
    zones, lines, departments = _catalog_axes()
    perms = []
    for z in zones:
        for l in lines:
            for d in departments:
                if not (z or l or d):
                    continue
                perms.append((z, l, d))
    return perms


def _existing_triples() -> set[tuple[str, str, str]]:
    return {((b.zone or ""), (b.line or ""), (b.department or ""))
            for b in Baseline.query.all()}


def missing_combos() -> list[tuple[str, str, str]]:
    """Permutations from the current catalogs that have no Baseline yet."""
    existing = _existing_triples()
    return [p for p in _all_permutations() if p not in existing]


def missing_combo_count() -> int:
    return len(missing_combos())


def generate_missing_combos(author: str = "") -> int:
    """Create a Baseline (combo) for every zone x line x department permutation
    that does not yet have one. Idempotent. Returns the number created."""
    existing = _existing_triples()
    created = 0
    for z, l, d in _all_permutations():
        if (z, l, d) in existing:
            continue
        name = combo_name(z, l, d)
        # Guard the name unique-constraint even if a manual baseline took it.
        if Baseline.query.filter_by(name=name).first() is not None:
            continue
        db.session.add(Baseline(name=name, zone=z, line=l, department=d,
                                author=(author or "").strip()))
        existing.add((z, l, d))
        created += 1
    if created:
        db.session.commit()
    return created


def combos_for_template(template_id: int) -> list[Baseline]:
    """The combos a template is currently assigned to (for the catalog chips)."""
    return (Baseline.query
            .join(BaselineTemplate, BaselineTemplate.baseline_id == Baseline.id)
            .filter(BaselineTemplate.template_id == template_id)
            .order_by(Baseline.name)
            .all())


def assigned_templates(baseline: Baseline) -> list[Template]:
    """Resolve a combo's links to Template rows, in assignment order."""
    out = []
    for link in baseline.items:
        t = Template.query.get(link.template_id)
        if t is not None:
            out.append(t)
    return out


def available_templates_for_combo(baseline: Baseline) -> list[Template]:
    """Approved, scope-compatible templates NOT yet assigned to this combo.

    Only the NEWEST version of each template is offered (the scope query already
    returns newest-first within a name), so the picker never lists stale revisions.
    """
    assigned_ids = {link.template_id for link in baseline.items}
    # Keep only the newest version of each template FIRST, then drop the ones
    # already assigned to this combo. Doing it the other way round would let an
    # OLD version survive as a candidate when its newest version is assigned.
    latest = _latest_version_only(approved_templates_for_scope(
        baseline.zone or "", baseline.line or "", baseline.department or ""))
    return [t for t in latest if t.id not in assigned_ids]


def _latest_version_only(templates: list[Template]) -> list[Template]:
    """Keep only the newest version of each (kind, name). Assumes the input is
    already ordered newest-version-first within a name."""
    seen: set[tuple[str, str]] = set()
    out: list[Template] = []
    for t in templates:
        key = (t.kind or "", t.name or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def group_by_section(templates: list[Template]) -> list[tuple[str, str, list[Template]]]:
    """Group an arbitrary list of templates by their logical SECTION (System /
    Server Objects / Web Protection / Server Policy / config sections...), in the
    same taxonomy order used everywhere else. Empty groups are omitted; input
    order is preserved within each group."""
    from collections import OrderedDict
    groups = OrderedDict()
    for sec in tax.known_sections():
        groups.setdefault(sec["key"], [])
    for t in templates:
        groups.setdefault(tax.section_for_kind(t.kind), []).append(t)
    return [(key, tax.section_label(key), items)
            for key, items in groups.items() if items]


def combo_assign(baseline_id: int, template_id: int) -> Baseline:
    """Assign one approved template to a combo (idempotent)."""
    b = Baseline.query.get(baseline_id)
    if b is None:
        raise ValueError(f"Combo {baseline_id} not found")
    t = Template.query.get(template_id)
    if t is None:
        raise ValueError(f"Template {template_id} not found")
    if t.status != Template.STATUS_APPROVED:
        raise ValueError(f'Template "{t.name}" is not approved')
    if any(link.template_id == template_id for link in b.items):
        return b  # already assigned
    b.items.append(BaselineTemplate(template_id=t.id,
                                    section=tax.section_for_kind(t.kind),
                                    position=len(b.items)))
    db.session.commit()
    return b


def combo_unassign(baseline_id: int, template_id: int) -> Baseline:
    """Remove a template from a combo (the junction row is deleted)."""
    b = Baseline.query.get(baseline_id)
    if b is None:
        raise ValueError(f"Combo {baseline_id} not found")
    link = next((l for l in b.items if l.template_id == template_id), None)
    if link is not None:
        b.items.remove(link)
        db.session.commit()
    return b


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


# --------------------------------------------------------------------------- #
#  Template -> combos (assign one template to many combos at once)              #
# --------------------------------------------------------------------------- #
def template_combo_id_map() -> dict[int, list[int]]:
    """For every template, the ids of the combos it is currently assigned to."""
    out: dict[int, list[int]] = {}
    for link in BaselineTemplate.query.all():
        out.setdefault(link.template_id, []).append(link.baseline_id)
    return out


def set_template_combos(template_id: int, combo_ids) -> dict:
    """Sync a template's combo memberships to EXACTLY ``combo_ids`` (add the
    missing links, drop the deselected ones). Idempotent. The template must be
    approved. Returns {'added', 'removed', 'total'}."""
    t = Template.query.get(template_id)
    if t is None:
        raise ValueError(f"Template {template_id} not found")
    if t.status != Template.STATUS_APPROVED:
        raise ValueError(f'Template "{t.name}" is not approved')
    want = {int(c) for c in combo_ids}
    if want:
        valid = {b.id for b in Baseline.query.filter(Baseline.id.in_(want)).all()}
        want &= valid
    links = BaselineTemplate.query.filter_by(template_id=template_id).all()
    have = {l.baseline_id for l in links}
    added = removed = 0
    for cid in want - have:
        b = Baseline.query.get(cid)
        if b is None:
            continue
        b.items.append(BaselineTemplate(template_id=template_id,
                                        section=tax.section_for_kind(t.kind),
                                        position=len(b.items)))
        added += 1
    for l in links:
        if l.baseline_id not in want:
            db.session.delete(l)
            removed += 1
    if added or removed:
        db.session.commit()
    return {"added": added, "removed": removed, "total": len(want)}


def grouped_approved_templates() -> list[tuple[str, str, list[Template]]]:
    """Approved templates grouped by their logical SECTION (System / Web
    Protection / Server Policy / config sections), in taxonomy order. Each group
    keeps the approved_templates() ordering (newest version first within a name).
    Empty groups are omitted."""
    from collections import OrderedDict
    groups: "OrderedDict[str, list[Template]]" = OrderedDict()
    for sec in tax.known_sections():
        groups.setdefault(sec["key"], [])
    for t in _latest_version_only(approved_templates()):
        groups.setdefault(tax.section_for_kind(t.kind), []).append(t)
    return [(key, tax.section_label(key), items)
            for key, items in groups.items() if items]
