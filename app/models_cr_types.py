"""Administrator-defined change types for the Change Request form.

Until now the "type of change" picker and every sentence it proposes were
compiled into the product: :data:`app.services.scheduled_actions.ALL_ACTIONS`
for the options and :data:`app.services.cr_document.ACTION_PROFILES` for the
prose.  Adding a category, or fixing a paragraph an auditor objected to, meant
a release.  This table is the editable layer over both.

Two rules this table exists to keep, neither of which fails loudly if broken:

**Executability is NOT stored here.**  Whether a change type can be *run* by
the scheduler is decided solely by whether its key names a real
:class:`~app.services.scheduled_actions.ActionSpec`.  A boolean column an
administrator could tick would let somebody create a category that looks
runnable, bind it to a one-shot ``ScheduledAction``, and have the executor
resolve it to nothing at fire time -- the change would close as failed hours
after anybody could act on it.  :func:`is_builtin` derives the answer from the
registry every time it is asked.

**``products`` never widens a built-in.**  For a key that names a real action,
the action's own ``spec.products`` is the authority on which appliance kinds it
runs against; the column is read only for administrator-defined (documentary)
types, which have no executor and therefore no other source of truth.

The TEXT of a change type is not stored here either -- it lives in
:class:`app.models_i18n.TranslationUnit` under the ``cr_type`` namespace, so it
gets staleness tracking, machine-translation provenance and the token ledger
for free.  See :mod:`app.services.cr_types`.
"""
from __future__ import annotations

import json
from datetime import datetime

from .models import db


class CrChangeType(db.Model):
    """One row per change type an administrator has touched.

    A row exists for two different reasons and the difference is derived, not
    stored: either the key names a built-in action (the row is an OVERRIDE of
    its wording and its position in the picker) or it does not (the row IS the
    change type, and it is documentary -- there is nothing to execute).
    """

    __tablename__ = "cr_change_type"

    id = db.Column(db.Integer, primary_key=True)
    #: The value the ``<select>`` submits and ``ChangeRequest.action`` stores.
    #: Slug-shaped so it can never collide with a future action key by accident
    #: of casing or spacing.
    key = db.Column(db.String(64), nullable=False, unique=True, index=True)

    #: The language the administrator authored this type's text in.  Every
    #: translation derives from it, never from another translation.
    source_lang = db.Column(db.String(8), nullable=False, default="en")

    #: Appliance kinds a documentary type may name.  Ignored for a key that is
    #: a built-in action -- see the module docstring.  ``[]`` means "any kind
    #: this console can see", which is the honest default for a category like
    #: "cabling" that is not about a product at all.
    products = db.Column(db.Text, nullable=False, default="[]")

    #: Off = not offered on the form.  Change requests already raised with it
    #: keep rendering: hiding a category must not retro-edit history.
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    sort_order = db.Column(db.Integer, nullable=False, default=100)

    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.String(64), nullable=False, default="")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # -- derived ---------------------------------------------------------- #
    @property
    def products_list(self) -> list:
        try:
            value = json.loads(self.products or "[]")
        except (ValueError, TypeError):
            return []
        return [str(v) for v in value] if isinstance(value, list) else []

    @property
    def builtin(self) -> bool:
        """True when this key names a real automation action.

        Asked of the registry every time, never cached on the row: an action
        removed from the product must stop looking runnable the moment it is
        removed, not the next time somebody re-saves this row.
        """
        return is_builtin(self.key)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "source_lang": self.source_lang,
            "products": self.products_list,
            "enabled": bool(self.enabled),
            "sort_order": self.sort_order,
            "builtin": self.builtin,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else "",
        }


def is_builtin(key) -> bool:
    """Does ``key`` name a registered automation action?

    The ONE authority on "can this be executed".  Imported lazily so this
    module stays importable without the service layer.
    """
    from .services import scheduled_actions as sa
    try:
        return sa.get_spec(str(key or "").strip()) is not None
    except Exception:  # noqa: BLE001 — a registry hiccup must not read as True
        return False
