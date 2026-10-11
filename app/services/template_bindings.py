"""Template ↔ device bindings (:mod:`app.models_tpl_binding`).

The template stays the shared intent of its ADOM; a binding says which devices
it governs, which version they follow (pinned, or the newest approved) and the
per-device values its ``{{ variable }}`` placeholders take. Three readers:

* the apply renders the body per device (:func:`render`) and refuses a device
  whose binding leaves a placeholder unresolved;
* the template lock (:func:`locked_families`) — an approved Web Protection
  Profile template with bindings is read-only on its bound devices only;
* the upgrade pre-flight and the comparison matrix (:func:`for_appliance`) —
  every template a device is bound to is checked against the build it is
  going to run.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Iterable

from ..extensions import db
from ..models import Appliance, Template
from ..models_tpl_binding import TemplateBinding

#: ``{{ name }}`` inside a string value of a template body.
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}")
_VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


# ---------------------------------------------------------------------------
# placeholders
# ---------------------------------------------------------------------------

def _walk_strings(node, fn):
    """Apply ``fn`` to every string in ``node`` (keys untouched); returns the copy."""
    if isinstance(node, dict):
        return {k: _walk_strings(v, fn) for k, v in node.items()}
    if isinstance(node, list):
        return [_walk_strings(v, fn) for v in node]
    if isinstance(node, str):
        return fn(node)
    return node


def placeholders(body) -> list[str]:
    """The variable names a body asks for, sorted."""
    found: set[str] = set()

    def _grab(s):
        found.update(PLACEHOLDER.findall(s))
        return s

    _walk_strings(body, _grab)
    return sorted(found)


def render(body, variables: dict | None) -> tuple[Any, list[str]]:
    """``(rendered body, missing variable names)``. Never mutates ``body``.

    A value that is exactly one placeholder takes the variable's value as is;
    a placeholder inside a longer string is replaced by its text.
    """
    variables = variables or {}
    missing: set[str] = set()

    def _sub(s):
        whole = PLACEHOLDER.fullmatch(s.strip())
        if whole:
            name = whole.group(1)
            if name in variables:
                return variables[name]
            missing.add(name)
            return s

        def _one(m):
            name = m.group(1)
            if name in variables:
                return str(variables[name])
            missing.add(name)
            return m.group(0)
        return PLACEHOLDER.sub(_one, s)

    return _walk_strings(copy.deepcopy(body), _sub), sorted(missing)


def missing_text(missing: dict, names: dict | None = None) -> str:
    """``fwb-a: no value for vip, port; fwb-b: …`` for a ``{appliance_id:
    [missing]}`` map (``names``: ``{appliance_id: name}``)."""
    names = names or {}
    return "; ".join("%s: no value for %s" % (names.get(aid, aid), ", ".join(m))
                     for aid, m in sorted(missing.items()))


def clean_variables(raw) -> dict[str, str]:
    """Validate a ``{name: value}`` map from a form/JSON. Raises ``ValueError``."""
    if raw in (None, "", {}):
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise ValueError("variables must be a JSON object: %s" % exc) from exc
    if not isinstance(raw, dict):
        raise ValueError("variables must be a JSON object {name: value}")
    out = {}
    for k, v in raw.items():
        k = str(k).strip()
        if not _VAR_NAME.match(k):
            raise ValueError("invalid variable name %r (letters, digits, _ . -)" % k)
        if isinstance(v, (dict, list)):
            raise ValueError("variable %r must be a single value" % k)
        out[k] = "" if v is None else str(v)
    return out


# ---------------------------------------------------------------------------
# bindings
# ---------------------------------------------------------------------------

def family(kind: str, name: str) -> list[Template]:
    return (Template.query.filter_by(kind=kind, name=name)
            .order_by(Template.version.desc()).all())


def resolve(binding: TemplateBinding, *, approved_only: bool = True) -> Template | None:
    """The template version a binding follows."""
    q = Template.query.filter_by(kind=binding.kind, name=binding.name)
    if binding.pinned_version:
        return q.filter_by(version=binding.pinned_version).first()
    if approved_only:
        q = q.filter_by(status=Template.STATUS_APPROVED)
    return q.order_by(Template.version.desc()).first()


def for_template(template: Template) -> list[TemplateBinding]:
    return (TemplateBinding.query
            .filter_by(kind=template.kind, name=template.name)
            .order_by(TemplateBinding.appliance_id).all())


def for_appliance(appliance_id: int) -> list[TemplateBinding]:
    return (TemplateBinding.query.filter_by(appliance_id=appliance_id)
            .order_by(TemplateBinding.kind, TemplateBinding.name).all())


def bind(appliance: Appliance, template: Template, *, pinned_version=None,
         variables=None, note: str = "", by: str = "") -> TemplateBinding:
    """Create or update the binding of ``appliance`` to ``template``'s family.

    The device must belong to the template's ADOM: a FortiWeb template cannot
    govern a FortiADC.
    """
    product = template.product or "fortiweb"
    if (appliance.kind or "") != product:
        raise ValueError("%s is a %s; template %r belongs to the %s ADOM"
                         % (appliance.name, appliance.kind, template.name, product))
    if pinned_version not in (None, ""):
        try:
            pinned_version = int(pinned_version)
        except (TypeError, ValueError) as exc:
            raise ValueError("pinned version must be a number") from exc
        if not Template.query.filter_by(kind=template.kind, name=template.name,
                                        version=pinned_version).first():
            raise ValueError("template %r has no version %s"
                             % (template.name, pinned_version))
    else:
        pinned_version = None
    vars_ = clean_variables(variables)
    row = TemplateBinding.query.filter_by(appliance_id=appliance.id,
                                          kind=template.kind,
                                          name=template.name).first()
    if row is None:
        row = TemplateBinding(appliance_id=appliance.id, kind=template.kind,
                              name=template.name, product=product,
                              created_by=by or "")
        db.session.add(row)
    row.pinned_version = pinned_version
    row.variables = json.dumps(vars_, sort_keys=True)
    row.note = note or ""
    db.session.flush()
    return row


def unbind(binding_id: int) -> TemplateBinding | None:
    row = TemplateBinding.query.get(binding_id)
    if row is not None:
        db.session.delete(row)
        db.session.flush()
    return row


def variables_for(template: Template, appliance_ids: Iterable[int]) -> dict[int, dict]:
    """``{appliance_id: variables}`` of the devices bound to ``template``'s family."""
    ids = [int(i) for i in appliance_ids or []]
    if not ids:
        return {}
    rows = (TemplateBinding.query
            .filter(TemplateBinding.kind == template.kind,
                    TemplateBinding.name == template.name,
                    TemplateBinding.appliance_id.in_(ids)).all())
    return {r.appliance_id: r.variables_dict for r in rows}


def render_for_devices(template: Template, appliance_ids) -> tuple[dict, dict]:
    """``({appliance_id: rendered body}, {appliance_id: [missing]})``.

    Only devices that NEED rendering appear: a body without placeholders is
    the same for every device and is pushed as is.
    """
    body = template.body_dict
    if not placeholders(body):
        return {}, {}
    vars_by = variables_for(template, appliance_ids)
    bodies, missing = {}, {}
    for aid in appliance_ids or []:
        rendered, miss = render(body, vars_by.get(int(aid)) or {})
        bodies[int(aid)] = rendered
        if miss:
            missing[int(aid)] = miss
    return bodies, missing


def render_parts_for_devices(parts, appliance_ids) -> tuple[dict, dict]:
    """The push items of one or more templates, rendered per device.

    ``parts`` = ``[(template, push items)]`` in push order: a System
    Provisioning profile is one part, a baseline one per composing template.
    Each part takes the variables of ITS template's binding on that device.
    ``({appliance_id: items}, {appliance_id: [missing]})``; both empty when no
    part has a placeholder (every device then gets the same items).
    """
    parts = [(t, list(items or [])) for t, items in parts]
    if not any(placeholders(items) for _t, items in parts):
        return {}, {}
    ids = [int(i) for i in appliance_ids or []]
    vars_by = [variables_for(t, ids) for t, _items in parts]
    out, missing = {}, {}
    for aid in ids:
        rendered, miss = [], set()
        for (_t, items), by in zip(parts, vars_by):
            got, m = render(items, by.get(aid) or {})
            rendered.extend(got)
            miss.update(m)
        out[aid] = rendered
        if miss:
            missing[aid] = sorted(miss)
    return out, missing


# ---------------------------------------------------------------------------
# lock scope
# ---------------------------------------------------------------------------

def locked_families(kind: str) -> dict[str, set[int] | None]:
    """``{template name: bound appliance ids, or None = every device of the ADOM}``
    for the APPROVED templates of ``kind``."""
    names = {t.name for t in Template.query.filter_by(
        kind=kind, status=Template.STATUS_APPROVED).all() if t.name}
    if not names:
        return {}
    out: dict[str, set[int] | None] = {n: None for n in names}
    for b in (TemplateBinding.query.filter(TemplateBinding.kind == kind,
                                           TemplateBinding.name.in_(sorted(names)))
              .all()):
        cur = out.get(b.name)
        out[b.name] = (cur or set()) | {b.appliance_id}
    return out


def governs(scope: set[int] | None, appliance_id) -> bool:
    """Does a family whose lock scope is ``scope`` govern ``appliance_id``?

    ``appliance_id=None`` asks about ANY device (the conservative union)."""
    if scope is None or appliance_id is None:
        return True
    try:
        return int(appliance_id) in scope
    except (TypeError, ValueError):
        return True


def governing(appliance) -> list[tuple[Template, TemplateBinding | None]]:
    """The template versions that govern ``appliance``: every binding it has,
    plus each APPROVED family of its ADOM that has no binding at all (the
    global rule). ``[(template, binding or None)]``."""
    product = getattr(appliance, "kind", "") or "fortiweb"
    out: list = []
    seen: set = set()
    for b in for_appliance(appliance.id):
        t = resolve(b)
        seen.add((b.kind, b.name))
        if t is not None:
            out.append((t, b))
    bound_families = {(k, n) for k, n in db.session.query(
        TemplateBinding.kind, TemplateBinding.name).distinct()}
    latest: dict = {}
    for t in Template.query.filter_by(status=Template.STATUS_APPROVED).all():
        if (t.product or "fortiweb") != product:
            continue
        fam = (t.kind, t.name)
        if fam in seen or fam in bound_families:
            continue
        if fam not in latest or t.version > latest[fam].version:
            latest[fam] = t
    out.extend((t, None) for _, t in sorted(latest.items()))
    return out


def upgrade_report(appliance, target_version: str) -> dict:
    """Every template governing ``appliance`` against the build it is about to
    run. ``ok`` False when a template does not fit: after the upgrade its next
    apply would be refused, so it must be adapted (or the binding moved to an
    adapted version) before the window."""
    from . import template_compat as tc
    rows = []
    for t, b in governing(appliance):
        rep = tc.check(t, target_version)
        s = tc.summarize(rep)
        undecided = tc.undecided_new_fields(t, rep)
        rows.append({"template_id": t.id, "kind": t.kind, "name": t.name,
                     "version": t.version, "source_firmware": t.source_firmware or "",
                     "bound": b is not None, "cell": tc.cell_of(s, t),
                     "blocking": bool(s.get("blocking")),
                     "undecided": undecided, "text": tc.verdict_text(s)})
    bad = [r for r in rows if r["blocking"]]
    return {"ok": not bad, "target_version": target_version, "templates": rows,
            "not_fitting": len(bad),
            "undecided": sum(1 for r in rows if r["undecided"])}


# ---------------------------------------------------------------------------
# per-device status
# ---------------------------------------------------------------------------

def status(binding: TemplateBinding, appliance=None, *, build: str = "") -> dict:
    """The bound version, the build it is checked against and the verdict."""
    from . import template_compat as tc
    from . import version_compat as vc
    tpl = resolve(binding)
    appliance = appliance or Appliance.query.get(binding.appliance_id)
    build = build or (vc._resolved(appliance).get("version") if appliance else "") or ""
    out = {"binding_id": binding.id, "appliance_id": binding.appliance_id,
           "appliance": getattr(appliance, "name", "") or "",
           "kind": binding.kind, "name": binding.name,
           "pinned_version": binding.pinned_version,
           "variables": binding.variables_dict, "build": build,
           "template_id": getattr(tpl, "id", None),
           "version": getattr(tpl, "version", None),
           "source_firmware": getattr(tpl, "source_firmware", "") or ""}
    if tpl is None:
        out.update(state="no-version", blocking=True,
                   reason=("no approved version of %r" % binding.name)
                   if not binding.pinned_version else
                   "version %s no longer exists" % binding.pinned_version)
        return out
    missing = render(tpl.body_dict, binding.variables_dict)[1]
    if not build:
        out.update(state="unmeasured", blocking=True,
                   reason="%s reports no firmware" % out["appliance"])
        return out
    rep = tc.summarize(tc.check(tpl, build))
    out.update(state=rep["state"], level=rep["level"], blocking=rep["blocking"],
               dropped=rep["dropped"], renamed=rep["renamed"],
               absent_keys=rep["absent_keys"], missing_variables=missing,
               reason=tc.verdict_text(rep))
    if missing:
        out["blocking"] = True
        out["reason"] = ("unset variable(s): %s; " % ", ".join(missing)) + out["reason"]
    return out
