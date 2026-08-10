"""Resolution layer over administrator-defined change types and their text.

Everything the Change Request form and the change document say about a *type
of change* used to have exactly one author: Python source.  This module puts a
database layer in front of it without giving the sentences a second author --
the rule is strict precedence, never a merge of two half-sentences:

    administrator text (requested language)
      -> administrator text (the language they authored it in)
        -> the compiled profile in :mod:`app.services.cr_document`

An empty administrator field is NOT an override.  It means "keep whatever the
product says", which is what lets somebody correct one paragraph of a built-in
action without transcribing the other eleven.

The text itself is stored as :class:`app.models_i18n.TranslationUnit` rows in
the ``cr_type`` namespace, so an administrator's paragraph gets exactly what
the i18n foundation already guarantees: the digest of the source it was
translated from (so editing the English marks the other four languages stale
instead of leaving them confidently wrong), a permanent ``machine`` label on
anything a model wrote, and a row in the token/duration ledger per call.

This module imports the ORM; :mod:`app.services.cr_document` deliberately does
not, and must not start.  The document renderer stays pure and is *handed* the
resolved profile by its caller.
"""
from __future__ import annotations

import json
import re
import string

from ..models import db
from ..models_cr_types import CrChangeType, is_builtin
from ..models_i18n import ORIGIN_MACHINE, TranslationUnit
from . import cr_document, langs, translator

#: The catalogue every change-type string lives under.
NAMESPACE = "cr_type"

#: The editable fields, in form order.  ``kind`` drives BOTH the widget and how
#: the stored string is turned back into what the renderer expects:
#:
#:   ``line``  one line of text
#:   ``para``  one paragraph
#:   ``list``  one item per line -> the tuple sections 7/9/10 iterate over
#:
#: The last nine names are exactly :data:`cr_document.REQUIRED_PROFILE_KEYS`;
#: the check that they still are is a test, because a field renamed on one side
#: would silently stop overriding anything.
FIELDS: tuple[tuple[str, str, str], ...] = (
    ("label", "line",
     "Name in the picker, and the change type printed on the document"),
    ("draft_title", "line", "Proposed title for a new change request"),
    ("draft_reason", "para", "Proposed reason"),
    ("draft_rollback", "para", "Proposed rollback statement"),
    ("purpose", "para", "Document §2 — purpose of the change"),
    ("justification", "para", "Document §4 — why it needs a window"),
    ("impact", "para", "Document §5 — impact while it runs"),
    ("downtime", "line", "Document §5 — expected downtime"),
    ("risk", "para", "Document §6 — risk analysis"),
    ("rollback", "list", "Document §7 — rollback steps (one per line)"),
    ("work", "list", "Document §9 — work to perform (one per line)"),
    ("validation", "list", "Document §10 — validation (one per line)"),
)

FIELD_NAMES: tuple[str, ...] = tuple(name for name, _kind, _help in FIELDS)
FIELD_KINDS: dict = {name: kind for name, kind, _help in FIELDS}

#: The three fields the NEW-change form proposes, mapped onto the keys
#: :func:`cr_document.draft_fields` returns.
_DRAFT_MAP = {"draft_title": "title", "draft_reason": "reason",
              "draft_rollback": "rollback"}

_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


# --------------------------------------------------------------------------- #
#  Keys                                                                         #
# --------------------------------------------------------------------------- #
def slugify_key(value) -> str:
    """A free-typed name reduced to a stable key, or ``""`` if nothing is left.

    Keys end up in ``ChangeRequest.action``, in audit lines and in the printed
    document, so they are ASCII, lowercase and punctuation-free.  Returning
    empty rather than a fallback is deliberate: a change type whose key the
    product invented is a change type nobody can find again.
    """
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text[:64]


def key_error(key: str) -> str:
    """Why ``key`` may not be used, or ``""`` when it may."""
    if not _KEY_RE.match(key or ""):
        return ("A key must be 2–64 characters, start with a letter and use "
                "only lowercase letters, digits and underscores.")
    if is_builtin(key):
        return ""          # editing a built-in is allowed; creating one is not
    return ""


def text_key(key: str, field: str) -> str:
    return f"{key}.{field}"


# --------------------------------------------------------------------------- #
#  Rows                                                                         #
# --------------------------------------------------------------------------- #
def get(key) -> CrChangeType | None:
    key = str(key or "").strip()
    return CrChangeType.query.filter_by(key=key).first() if key else None


def all_types() -> list:
    return (CrChangeType.query
            .order_by(CrChangeType.sort_order, CrChangeType.key).all())


def custom_types(*, enabled_only: bool = False) -> list:
    """Administrator-defined types, i.e. the ones with NO executor.

    These are the rows that add options to the picker.  A row whose key names a
    built-in action is an override of wording, not a new option, and is
    excluded here so it cannot be offered twice.
    """
    rows = [r for r in all_types() if not r.builtin]
    return [r for r in rows if r.enabled] if enabled_only else rows


def options_for(kinds) -> list:
    """Enabled documentary types offerable to a console that can see ``kinds``.

    A type with no products declared is offered everywhere: a category like
    "cabling" is a property of the work, not of a product, and hiding it from
    four consoles out of five would be an invented restriction.
    """
    seen = {str(k) for k in (kinds or [])}
    out = []
    for row in custom_types(enabled_only=True):
        want = row.products_list
        if not want or (seen & set(want)):
            out.append(row)
    return out


def upsert(key: str, *, source_lang: str = "", products=None,
           enabled: bool | None = None, sort_order: int | None = None,
           username: str = "") -> CrChangeType:
    """Create or update the row for ``key``.  Does not touch its text."""
    row = get(key)
    if row is None:
        row = CrChangeType(key=key, created_by=username or "")
        db.session.add(row)
    if source_lang:
        row.source_lang = langs.normalize(source_lang)
    if products is not None:
        row.products = json.dumps([str(p) for p in products])
    if enabled is not None:
        row.enabled = bool(enabled)
    if sort_order is not None:
        row.sort_order = int(sort_order)
    row.updated_by = username or ""
    db.session.commit()
    return row


def delete(row) -> None:
    """Drop a change type and its whole text catalogue.

    Change requests already raised with this key keep their stored ``action``
    and keep rendering from the compiled fallback -- deleting a category must
    not blank a document somebody signed.
    """
    key = row.key
    (TranslationUnit.query
     .filter(TranslationUnit.namespace == NAMESPACE,
             TranslationUnit.key.like(f"{key}.%")).delete(synchronize_session=False))
    db.session.delete(row)
    db.session.commit()


# --------------------------------------------------------------------------- #
#  Text                                                                         #
# --------------------------------------------------------------------------- #
def stored_text(key: str, field: str, lang: str) -> str:
    """The administrator's text for one field in one language, or ``""``.

    Falls back to the language it was AUTHORED in before giving up.  A German
    console that has no German translation yet is better served the English the
    administrator actually wrote than the compiled paragraph they replaced --
    the two would otherwise contradict each other on the same page.
    """
    lang = langs.normalize(lang)
    unit = translator.get_unit(NAMESPACE, text_key(key, field), lang)
    if unit is not None and (unit.text or "").strip():
        return unit.text
    row = get(key)
    src = langs.normalize(row.source_lang if row is not None else langs.DEFAULT)
    if src != lang:
        unit = translator.get_unit(NAMESPACE, text_key(key, field), src)
        if unit is not None and (unit.text or "").strip():
            return unit.text
    return ""


def source_texts(key: str) -> dict:
    """Every authored field for ``key``, in its source language."""
    row = get(key)
    src = langs.normalize(row.source_lang if row is not None else langs.DEFAULT)
    out = {}
    for field in FIELD_NAMES:
        unit = translator.get_unit(NAMESPACE, text_key(key, field), src)
        out[field] = (unit.text if unit is not None else "")
    return out


def save_texts(key: str, texts: dict, *, source_lang: str = "",
               username: str = "") -> list:
    """Write the authored fields.  Returns the field names that CHANGED.

    Only changed fields are returned so the caller can fan out translations for
    those alone: re-translating twelve paragraphs because one comma moved is
    how a token ledger stops being worth reading.
    """
    lang = langs.normalize(source_lang or langs.DEFAULT)
    changed = []
    for field in FIELD_NAMES:
        new = (texts.get(field) or "").strip()
        unit = translator.get_unit(NAMESPACE, text_key(key, field), lang)
        old = (unit.text if unit is not None else "")
        if new == (old or "").strip():
            continue
        translator.set_source(NAMESPACE, text_key(key, field), new,
                              lang=lang, username=username)
        changed.append(field)
    return changed


def translate_type(key: str, *, fields=None, username: str = "",
                   provider_key: str = "", force: bool = False) -> dict:
    """Fan one change type's authored text out to the other languages.

    One report per field.  A field whose source is empty is NOT translated:
    an empty override means "use the product's text", and translating it would
    write four rows that override the compiled paragraph with nothing.
    """
    row = get(key)
    src = langs.normalize(row.source_lang if row is not None else langs.DEFAULT)
    names = tuple(fields) if fields else FIELD_NAMES
    report = {"key": key, "source_lang": src, "fields": {}, "ok": 0,
              "failed": 0, "skipped": 0, "duration_ms": 0,
              "prompt_tokens": None, "completion_tokens": None}
    for field in names:
        unit = translator.get_unit(NAMESPACE, text_key(key, field), src)
        text = (unit.text if unit is not None else "").strip()
        if not text:
            report["fields"][field] = {"status": "empty"}
            continue
        sub = translator.fan_out(NAMESPACE, text_key(key, field), text,
                                 source_lang=src, username=username,
                                 provider_key=provider_key, force=force)
        report["fields"][field] = sub
        report["ok"] += sub["ok"]
        report["failed"] += sub["failed"]
        report["skipped"] += sub["skipped"]
        report["duration_ms"] += sub["duration_ms"]
        for tok in ("prompt_tokens", "completion_tokens"):
            if sub[tok] is not None:
                report[tok] = (report[tok] or 0) + sub[tok]
    return report


def catalogue(key: str) -> dict:
    """Per-field, per-language state for the editor: text, origin, staleness."""
    src_texts = source_texts(key)
    out = {}
    for field in FIELD_NAMES:
        out[field] = translator.catalogue(NAMESPACE, text_key(key, field),
                                          src_texts.get(field) or "")
    return out


def machine_pending(key: str) -> int:
    """Machine translations for this type that nobody has reviewed yet."""
    return (TranslationUnit.query
            .filter(TranslationUnit.namespace == NAMESPACE,
                    TranslationUnit.key.like(f"{key}.%"),
                    TranslationUnit.origin == ORIGIN_MACHINE,
                    TranslationUnit.reviewed.is_(False)).count())


# --------------------------------------------------------------------------- #
#  Resolution — what the form and the document actually read                     #
# --------------------------------------------------------------------------- #
class _Keep(dict):
    """A format mapping that leaves unknown placeholders untouched.

    An administrator writing ``{devices}`` means the device list; an
    administrator writing ``{foo}`` made a typo, and a typo must print as the
    typo rather than raise ``KeyError`` in front of an approver -- or, worse,
    swallow the rest of the sentence.
    """

    def __missing__(self, key):  # noqa: D105
        return "{" + key + "}"


def _fmt(text: str, **ctx) -> str:
    try:
        return string.Formatter().vformat(text, (), _Keep(**ctx))
    except Exception:  # noqa: BLE001 — a bad brace must not break a render
        return text


def _as_lines(text: str) -> tuple:
    return tuple(line.strip() for line in (text or "").splitlines()
                 if line.strip())


def overrides(key: str, lang: str) -> dict:
    """The administrator's text for ``key`` in ``lang``, empties dropped.

    Empties are dropped rather than returned blank BECAUSE an empty field means
    "keep the product's wording".  Returning it would blank a paragraph of the
    signed document and nothing would fail.
    """
    out = {}
    for field in FIELD_NAMES:
        value = stored_text(key, field, lang)
        if not (value or "").strip():
            continue
        out[field] = (_as_lines(value) if FIELD_KINDS[field] == "list"
                      else value.strip())
    return out


def profile_text(action, lang: str) -> dict:
    """The document profile for ``action``: compiled text, overridden per field.

    This is what :func:`cr_document.render` must be handed.  Never returns a
    partial dict: an override replaces one field, it does not replace the
    profile, so a document can never lose a section because somebody filled in
    one box.
    """
    lang = cr_document.normalize_lang(lang)
    base = dict(cr_document._profile_text(action, lang))
    over = overrides(str(action or "").strip(), lang)
    for field in cr_document.REQUIRED_PROFILE_KEYS:
        if field in over:
            base[field] = over[field]
    return base


def label(action, lang: str) -> str:
    """The change type's name, administrator text winning."""
    key = str(action or "").strip()
    text = stored_text(key, "label", cr_document.normalize_lang(lang))
    if (text or "").strip():
        return text.strip()
    return cr_document.action_label(key, lang)


def draft_fields(action, lang, *, prep=None) -> dict:
    """Proposed title/reason/rollback, administrator text winning per field.

    Overridden text may use ``{action}`` (the type's name) and ``{devices}``
    (:data:`cr_document.DEVICES_TOKEN`, which the page substitutes with the
    live selection).  It is NOT given the pre-flight variables: the compiled
    sentences have a separate, evidence-citing variant for that, and a
    hand-written template that silently dropped the citation would produce a
    document claiming less evidence than the change actually rests on.
    """
    code = cr_document.normalize_lang(lang)
    key = str(action or "").strip()
    out = dict(cr_document.draft_fields(key, code, prep=prep))
    over = overrides(key, code)
    name = label(key, code)
    for field, target in _DRAFT_MAP.items():
        if field in over:
            out[target] = _fmt(over[field], action=name,
                               devices=cr_document.DEVICES_TOKEN)
    return out


def snapshot(action) -> dict:
    """The resolved profile in every language the document can be produced in.

    Stored on the change request when it is approved.  Without it, editing a
    paragraph here would retroactively rewrite documents that were already
    signed -- the reprint would differ from the paper in the file, and nothing
    would say so.
    """
    return {code: profile_text(action, code) for code, _label in cr_document.LANGS}
