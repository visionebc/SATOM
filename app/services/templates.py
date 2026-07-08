"""Desired-state template library — web port of the desktop ``TemplateLibrary``.

Stores reusable Web Protection Profile / system / Server Policy / structure
templates as versioned JSON in the ``templates`` table. This is desired-state
only: applying a template to a live device is a separate, audited action — the
library itself never touches an appliance.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..models import Template, TemplateReviewEvent, db

# Friendly labels for the template kinds, for the UI.
KIND_LABELS = {
    Template.KIND_WEB_PROTECTION: "Web Protection Profile",
    Template.KIND_SERVER_POLICY: "Server Policy",
    Template.KIND_SYSTEM: "System Profile",
    Template.KIND_STRUCTURE: "Structure",
}


def list_templates(kind: str | None = None) -> list[Template]:
    """All templates VISIBLE TO THE ACTIVE ADOM (product-scoped), optionally
    filtered by kind, newest first. FortiADC sessions see only 'fortiadc'
    templates, FortiWeb everything else, Global all."""
    from .product_scope import scope_query
    query = scope_query(Template.query, Template.product)
    if kind:
        query = query.filter_by(kind=kind)
    return query.order_by(Template.kind, Template.name, Template.version.desc()).all()


def config_template_collection(template: Template) -> str | None:
    """The bare cmdb collection a ``config:<section>`` template captures.

    Config templates authored by "Save as template" carry the source object's
    REST endpoint on their first sub-object node; ``None`` means the body
    declares no endpoint (a freeform "New template" body we cannot attribute to a
    single object type). Used to scope a section's library to the object type
    currently being viewed.
    """
    from .objform import collection_of

    body = template.body_dict
    endpoint = None
    subs = body.get("subobjects")
    if isinstance(subs, list):
        for node in subs:
            if isinstance(node, dict) and node.get("endpoint"):
                endpoint = node["endpoint"]
                break
    endpoint = endpoint or body.get("endpoint")   # single-object body shape
    return collection_of(endpoint) if endpoint else None


def list_config_templates(kind: str, collection: str | None = None) -> list[Template]:
    """Config-section templates, scoped to the object type being viewed.

    Every ``config:<section>`` template shares a section-level kind, so a section
    with several object types (System -> Global, NTP, DNS...) would otherwise
    show EVERY type's templates on EVERY type's page. When ``collection`` is the
    object type currently selected, keep only templates captured from THAT type
    -- plus freeform templates that declare no endpoint (so an authored template
    we cannot attribute is never hidden). No ``collection`` -> the whole section
    (unchanged behaviour).
    """
    rows = list_templates(kind)
    if not collection:
        return rows
    from .objform import collection_of

    target = collection_of(collection)
    return [t for t in rows
            if (tc := config_template_collection(t)) is None or tc == target]


def get_template(template_id: int) -> Template | None:
    return Template.query.get(template_id)


def managed_wpp_names() -> set[str]:
    """Names of Web Protection Profiles governed by an APPROVED template.

    A profile whose name matches an approved ``web-protection-profile`` template
    is TEMPLATE-MANAGED: it is read-only everywhere except Administrator →
    WPP Templates, and editing it there deploys to the whole fleet. This is the
    team rule that keeps per-device drift out of templated profiles.
    """
    rows = (Template.query
            .filter_by(kind=Template.KIND_WEB_PROTECTION,
                       status=Template.STATUS_APPROVED)
            .all())
    names: set[str] = set()
    for t in rows:
        if t.name:
            names.add(t.name)
        # Also honour a body whose root object carries a different name than the
        # library entry (a template captured under an alias).
        try:
            body = t.body_dict or {}
            root = body.get("data") or {}
            inner = root.get("data") if isinstance(root.get("data"), dict) else root
            n = (inner or {}).get("name")
            if n:
                names.add(str(n))
        except Exception:  # noqa: BLE001 — a malformed body never breaks the lock
            continue
    return names


def latest_approved_wpp_template(name: str) -> Template | None:
    """The newest APPROVED web-protection-profile template for ``name``."""
    return (Template.query
            .filter_by(kind=Template.KIND_WEB_PROTECTION, name=name,
                       status=Template.STATUS_APPROVED)
            .order_by(Template.version.desc())
            .first())


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

    from .product_scope import stamp
    version = _next_version(kind, name) if new_version else 1
    row = Template(
        kind=kind, name=name, version=version,
        body=json.dumps(parsed, separators=(",", ":"), sort_keys=True),
        exceptions=exc_json,
        note=(note or "").strip(), author=(author or "").strip(),
        product=stamp() or "fortiweb",
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
        product=src.product or "fortiweb",
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


def approve_template(template_id: int, reviewer: str) -> Template:
    """Mark a template APPROVED (fleet-deployable). Clears any prior rejection
    reason. Raises ``ValueError`` if the template does not exist."""
    row = Template.query.get(template_id)
    if row is None:
        raise ValueError(f"Template {template_id} not found")
    row.status = Template.STATUS_APPROVED
    row.reject_reason = ""
    row.reviewed_by = (reviewer or "").strip()
    row.reviewed_at = datetime.utcnow()
    _record_review_event(row.id, TemplateReviewEvent.ACTION_APPROVE, reviewer)
    db.session.commit()
    return row


def reject_template(template_id: int, reviewer: str, reason: str = "") -> Template:
    """Mark a template REJECTED with an author-visible reason. Raises
    ``ValueError`` if the template does not exist."""
    row = Template.query.get(template_id)
    if row is None:
        raise ValueError(f"Template {template_id} not found")
    row.status = Template.STATUS_REJECTED
    row.reject_reason = (reason or "").strip()
    row.reviewed_by = (reviewer or "").strip()
    row.reviewed_at = datetime.utcnow()
    _record_review_event(row.id, TemplateReviewEvent.ACTION_REJECT, reviewer, reason)
    db.session.commit()
    return row


def unapprove_template(template_id: int, reviewer: str) -> Template:
    """Revoke approval — returns the template to PENDING so it can be
    re-reviewed. Raises ``ValueError`` if the template does not exist."""
    row = Template.query.get(template_id)
    if row is None:
        raise ValueError(f"Template {template_id} not found")
    row.status = Template.STATUS_PENDING
    row.reject_reason = ""
    row.reviewed_by = (reviewer or "").strip()
    row.reviewed_at = datetime.utcnow()
    _record_review_event(row.id, TemplateReviewEvent.ACTION_REVOKE, reviewer)
    db.session.commit()
    return row


def _record_review_event(template_id: int, action: str, reviewer: str,
                         reason: str = "") -> None:
    """Queue an approval-history row (committed by the caller's commit)."""
    db.session.add(TemplateReviewEvent(
        template_id=template_id, action=action,
        reviewer=(reviewer or "").strip(), reason=(reason or "").strip()))


def review_history(template_id: int) -> list[TemplateReviewEvent]:
    """Full approval timeline for a template, newest first."""
    return (TemplateReviewEvent.query.filter_by(template_id=template_id)
            .order_by(TemplateReviewEvent.created_at.desc(),
                      TemplateReviewEvent.id.desc()).all())
