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


def save_template(kind: str, name: str, body: Any, *, note: str = "",
                  author: str = "", new_version: bool = True) -> Template:
    """Create a template (or a new version of an existing name).

    ``body`` may be a dict or a JSON string; it is validated and stored as
    canonical JSON. Raises ``ValueError`` on an invalid kind or malformed body.
    """
    if kind not in Template.KINDS:
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

    version = _next_version(kind, name) if new_version else 1
    row = Template(
        kind=kind, name=name, version=version,
        body=json.dumps(parsed, separators=(",", ":"), sort_keys=True),
        note=(note or "").strip(), author=(author or "").strip(),
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
