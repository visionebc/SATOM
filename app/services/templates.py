"""Desired-state template library — web port of the desktop ``TemplateLibrary``.

Stores reusable Web Protection Profile / system / Server Policy / structure
templates as versioned JSON in the ``templates`` table. This is desired-state
only: applying a template to a live device is a separate, audited action — the
library itself never touches an appliance.
"""
from __future__ import annotations

import json
from typing import Any

from ..models import Template, db

# Friendly labels for the template kinds, for the UI.
KIND_LABELS = {
    Template.KIND_WEB_PROTECTION: "Web Protection Profile",
    Template.KIND_SERVER_POLICY: "Server Policy",
    Template.KIND_SYSTEM: "System Profile",
    Template.KIND_STRUCTURE: "Structure",
}


def list_templates(kind: str | None = None) -> list[Template]:
    """All templates, optionally filtered by kind, newest first."""
    query = Template.query
    if kind:
        query = query.filter_by(kind=kind)
    return query.order_by(Template.kind, Template.name, Template.version.desc()).all()


def get_template(template_id: int) -> Template | None:
    return Template.query.get(template_id)


def _next_version(kind: str, name: str) -> int:
    latest = (Template.query.filter_by(kind=kind, name=name)
              .order_by(Template.version.desc()).first())
    return (latest.version + 1) if latest else 1


def _normalize_exceptions(exceptions: Any) -> str:
    """Validate/canonicalise an optional exceptions blob to a JSON string.

    Accepts ``None``/empty (stored as ``""``), a dict/list, or a JSON string.
    Raises ``ValueError`` if a provided string is not valid JSON.
    """
    if exceptions is None:
        return ""
    if isinstance(exceptions, str):
        text = exceptions.strip()
        if not text:
            return ""
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"Exceptions is not valid JSON: {exc}") from exc
    else:
        parsed = exceptions
    if not isinstance(parsed, (dict, list)):
        raise ValueError("Template exceptions must be a JSON object or array")
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)


def save_template(kind: str, name: str, body: Any, *, note: str = "",
                  author: str = "", exceptions: Any = None,
                  new_version: bool = True) -> Template:
    """Create a template (or a new version of an existing name).

    ``body`` may be a dict or a JSON string; it is validated and stored as
    canonical JSON. ``exceptions`` is an optional JSON blob (dict/list or JSON
    string) persisted alongside the body. Raises ``ValueError`` on an invalid
    kind or malformed body/exceptions. Accepts the built-in kinds as well as the
    per-section ``config:<section>`` kinds (validated via ``is_valid_kind``).
    """
    if not Template.is_valid_kind(kind):
        raise ValueError(f"Unknown template kind: {kind}")
    name = (name or "").strip()
    if not name:
        raise ValueError("Template name is required")

    if isinstance(body, str):
        try:
            parsed = json.loads(body or "{}")
        except ValueError as exc:
            raise ValueError(f"Body is not valid JSON: {exc}") from exc
    else:
        parsed = body
    if not isinstance(parsed, dict):
        raise ValueError("Template body must be a JSON object")

    exc_json = _normalize_exceptions(exceptions)

    version = _next_version(kind, name) if new_version else 1
    row = Template(
        kind=kind, name=name, version=version,
        body=json.dumps(parsed, separators=(",", ":"), sort_keys=True),
        exceptions=exc_json,
        note=(note or "").strip(), author=(author or "").strip(),
    )
    db.session.add(row)
    db.session.commit()
    return row


def clone_template(template_id: int, new_name: str | None = None) -> Template:
    """Clone a template (body + exceptions) under a new name.

    The copy is always unlocked. ``version`` is 1 for a brand-new name, or the
    next version if the chosen name already exists for that kind. Raises
    ``ValueError`` if the source template does not exist.
    """
    src = Template.query.get(template_id)
    if src is None:
        raise ValueError(f"Template {template_id} not found")
    name = (new_name or "").strip() or f"{src.name} (copy)"
    version = _next_version(src.kind, name)
    row = Template(
        kind=src.kind, name=name, version=version,
        body=src.body, exceptions=src.exceptions or "",
        note=src.note or "", author=src.author or "", locked=False,
    )
    db.session.add(row)
    db.session.commit()
    return row


def delete_template(template_id: int) -> bool:
    """Delete a template by id. Locked templates are refused. Returns True if
    a row was removed."""
    row = Template.query.get(template_id)
    if row is None or row.locked:
        return False
    db.session.delete(row)
    db.session.commit()
    return True
