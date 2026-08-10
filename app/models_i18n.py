"""Translated strings and the ledger of what producing them cost.

Two tables, deliberately separate:

``TranslationUnit`` is the CONTENT -- one row per (namespace, key, language).
It carries ``source_hash`` because a translation is only true of the source it
was made from.  Without that hash, editing the English leaves four other
languages rendering confidently stale text: nothing fails, nothing logs, and
the operator reading Spanish is told something the author retracted.  The hash
turns that silent divergence into a visible ``stale`` flag.

``TranslationRun`` is the LEDGER -- one row per provider call, success or
failure, with wall time and token counts.  It mirrors
:class:`app.models_advisor.AdvisorRequestLog` on purpose: the advisor already
proved that per-call duration/tokens is the shape you need to answer "what is
this costing us", and a second, differently-shaped ledger for the same
question would have to be reconciled by hand forever.

A failed call still writes a run.  A ledger that only records successes cannot
answer why a language is missing.
"""
from __future__ import annotations

import hashlib
from datetime import datetime

from .models import db

#: ``origin`` values.  A machine translation is never silently promoted: only
#: an operator edit writes ``HUMAN``.
ORIGIN_HUMAN = "human"
ORIGIN_MACHINE = "machine"


def source_digest(text: str) -> str:
    """The identity of a source string: sha256 of its exact bytes.

    Not normalised, not stripped -- whitespace changes the rendered document,
    so a whitespace-only edit genuinely does invalidate the translations.
    """
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


class TranslationUnit(db.Model):
    __tablename__ = "translation_unit"
    __table_args__ = (
        db.UniqueConstraint("namespace", "key", "lang",
                            name="uq_translation_unit_scope"),
    )

    id = db.Column(db.Integer, primary_key=True)
    #: Which catalogue this string belongs to (``cr_field``, ``cr_option``,
    #: ``ui``...).  Namespaced so one feature's keys can never collide with
    #: another's, and so a catalogue can be re-translated on its own.
    namespace = db.Column(db.String(64), nullable=False, default="", index=True)
    key = db.Column(db.String(200), nullable=False, default="", index=True)
    lang = db.Column(db.String(8), nullable=False, default="en", index=True)

    text = db.Column(db.Text, nullable=False, default="")

    #: The language this row was produced FROM, and the digest of that exact
    #: source text.  Both are empty on a source row (it is its own origin).
    source_lang = db.Column(db.String(8), nullable=False, default="")
    source_hash = db.Column(db.String(64), nullable=False, default="")

    origin = db.Column(db.String(16), nullable=False, default=ORIGIN_HUMAN)
    #: The model that produced a machine row -- so a bad translation can be
    #: traced to the model that made it, not just to "the AI".
    model = db.Column(db.String(120), nullable=False, default="")
    provider_key = db.Column(db.String(64), nullable=False, default="")

    #: An operator has read this machine translation and accepted it.  Kept
    #: distinct from ``origin``: reviewed machine text is still machine text,
    #: and a reviewer's name is the only thing that makes it citable.
    reviewed = db.Column(db.Boolean, nullable=False, default=False)
    reviewed_by = db.Column(db.String(64), nullable=False, default="")

    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.String(64), nullable=False, default="")

    def is_stale(self, source_text: str) -> bool:
        """True when this row was made from a different source than the one
        passed in.  A source row (no recorded origin) is never stale."""
        if not self.source_hash:
            return False
        return self.source_hash != source_digest(source_text)

    def to_dict(self, source_text: str | None = None) -> dict:
        d = {
            "id": self.id,
            "namespace": self.namespace,
            "key": self.key,
            "lang": self.lang,
            "text": self.text,
            "origin": self.origin,
            "model": self.model,
            "provider_key": self.provider_key,
            "reviewed": bool(self.reviewed),
            "reviewed_by": self.reviewed_by,
            "source_lang": self.source_lang,
            "updated_at": self.updated_at.isoformat() if self.updated_at else "",
            "updated_by": self.updated_by,
        }
        if source_text is not None:
            d["stale"] = self.is_stale(source_text)
        return d


class TranslationRun(db.Model):
    """One provider call.  ``prompt_tokens``/``completion_tokens`` are NULL
    when the provider reported nothing -- distinct from zero, which would be a
    claim we did not measure."""

    __tablename__ = "translation_run"

    id = db.Column(db.Integer, primary_key=True)
    namespace = db.Column(db.String(64), nullable=False, default="", index=True)
    key = db.Column(db.String(200), nullable=False, default="")
    source_lang = db.Column(db.String(8), nullable=False, default="")
    target_lang = db.Column(db.String(8), nullable=False, default="", index=True)

    provider_key = db.Column(db.String(64), nullable=False, default="")
    provider_kind = db.Column(db.String(32), nullable=False, default="")
    model = db.Column(db.String(120), nullable=False, default="")
    destination_host = db.Column(db.String(200), nullable=False, default="")
    external = db.Column(db.Boolean, nullable=False, default=False, index=True)

    duration_ms = db.Column(db.Integer, nullable=False, default=0)
    prompt_tokens = db.Column(db.Integer, nullable=True)
    completion_tokens = db.Column(db.Integer, nullable=True)
    chars_in = db.Column(db.Integer, nullable=False, default=0)
    chars_out = db.Column(db.Integer, nullable=False, default=0)

    ok = db.Column(db.Boolean, nullable=False, default=True, index=True)
    error = db.Column(db.String(400), nullable=False, default="")

    username = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow,
                           nullable=False, index=True)

    @property
    def total_tokens(self):
        """Sum, or ``None`` when NEITHER side was reported.  A half-reported
        call still yields a number: losing the half we do have would make the
        cost look smaller than it was."""
        if self.prompt_tokens is None and self.completion_tokens is None:
            return None
        return (self.prompt_tokens or 0) + (self.completion_tokens or 0)
