"""Administration -> Change Types: the Change Request form, made editable.

What this page owns: the options in the form's "type of change" picker, and
every sentence a chosen option contributes -- the proposed title/reason/
rollback, and the eight profile paragraphs the printed document quotes.  Both
used to be compiled into the product.

What it deliberately does NOT own:

* **Which fields the form has.**  Adding a field would mean versioning its
  definition, because a change request signed three months ago must keep
  printing the fields that existed then, not today's.  That is a different
  feature and pretending otherwise here would produce documents whose shape
  changes under the signature.
* **Whether a change type can be executed.**  A type an administrator invents
  has no executor; the picker says so, and
  :func:`app.services.change_requests.schedule_change_request` refuses to bind
  one to a scheduled action.  A checkbox here would only move the failure to
  fire time, hours after anybody could act on it.
"""
from __future__ import annotations

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..models_i18n import ORIGIN_MACHINE
from ..services import cr_document, cr_types, langs, translator
from ..services.audit import log_action

bp = Blueprint('cr_types', __name__, url_prefix='/administration/change-types')


def _username() -> str:
    return getattr(current_user, 'username', '') or ''


def _builtin_rows() -> list:
    """The compiled change types, each with its override state.

    Read through the SAME eligibility rule the form uses
    (``views.change_requests._cr_specs``) so this page can never offer to edit
    a type the form does not offer, nor miss one it does.
    """
    from .change_requests import _cr_specs
    rows = []
    for spec in _cr_specs():
        row = cr_types.get(spec.key)
        rows.append({
            'key': spec.key,
            'label': cr_types.label(spec.key, langs.DEFAULT),
            'stock_label': cr_document.action_label(spec.key, langs.DEFAULT),
            'products': list(spec.products),
            'builtin': True,
            'row': row,
            'overridden': len(cr_types.overrides(spec.key, langs.DEFAULT)),
            'enabled': (row.enabled if row is not None else True),
            'pending': cr_types.machine_pending(spec.key),
        })
    return rows


def _custom_rows() -> list:
    out = []
    for row in cr_types.custom_types():
        out.append({
            'key': row.key,
            'label': cr_types.label(row.key, row.source_lang),
            'stock_label': '',
            'products': row.products_list,
            'builtin': False,
            'row': row,
            'overridden': len(cr_types.overrides(row.key, row.source_lang)),
            'enabled': bool(row.enabled),
            'pending': cr_types.machine_pending(row.key),
        })
    return out


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    from .change_requests import cr_kinds
    return render_template('cr_types/index.html',
                           builtin=_builtin_rows(),
                           custom=_custom_rows(),
                           kinds=cr_kinds(),
                           langs=langs.SUPPORTED,
                           usage=translator.usage_summary(30))


@bp.route('/new', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    raw = (request.form.get('key') or '').strip()
    key = cr_types.slugify_key(raw)
    err = cr_types.key_error(key)
    if err:
        flash(err, 'danger')
        return redirect(url_for('cr_types.index'))
    # A new type may NOT take the name of a compiled action. Not because the
    # name is reserved, but because the two rows would then disagree about
    # whether the type is executable, and the picker would have to pick one.
    if cr_types.get(key) is not None:
        flash(f'A change type "{key}" already exists.', 'danger')
        return redirect(url_for('cr_types.index'))
    from ..models_cr_types import is_builtin
    if is_builtin(key):
        flash(f'"{key}" is a built-in action. Edit its wording instead of '
              f'creating a second type with the same key.', 'danger')
        return redirect(url_for('cr_types.edit', key=key))

    lang = langs.normalize(request.form.get('source_lang'))
    products = [p for p in request.form.getlist('products') if p]
    row = cr_types.upsert(key, source_lang=lang, products=products,
                          enabled=True, sort_order=100, username=_username())
    label = (request.form.get('label') or '').strip()
    if label:
        cr_types.save_texts(key, {'label': label}, source_lang=lang,
                            username=_username())
    log_action('cr_type.create', target=key,
               detail=f'lang={lang} products={",".join(products) or "any"}')
    flash(f'Change type "{key}" created. Fill in its text below.', 'success')
    return redirect(url_for('cr_types.edit', key=row.key))


def _load_or_404(key: str):
    from flask import abort
    from ..models_cr_types import is_builtin
    key = (key or '').strip()
    if not is_builtin(key) and cr_types.get(key) is None:
        abort(404)
    return key


@bp.route('/<key>')
@login_required
@require_permission(Permission.USER_MANAGE)
def edit(key):
    from .change_requests import cr_kinds
    key = _load_or_404(key)
    from ..models_cr_types import is_builtin
    row = cr_types.get(key)
    builtin = is_builtin(key)
    src = langs.normalize(row.source_lang if row is not None else langs.DEFAULT)
    # The compiled text is shown NEXT TO the box, not inside it: prefilling the
    # box would turn "leave empty to keep the product's wording" into "the
    # administrator has transcribed and now owns this paragraph", and the next
    # release's correction would silently stop reaching this install.
    stock = cr_document._profile_text(key, src) if builtin else {}
    stock_draft = cr_document.draft_fields(key, src) if builtin else {}
    return render_template('cr_types/edit.html',
                           key=key,
                           row=row,
                           builtin=builtin,
                           source_lang=src,
                           fields=cr_types.FIELDS,
                           texts=cr_types.source_texts(key),
                           stock=stock,
                           stock_draft=stock_draft,
                           draft_map=cr_types._DRAFT_MAP,
                           catalogue=cr_types.catalogue(key),
                           langs=langs.SUPPORTED,
                           default_lang=langs.DEFAULT,
                           kinds=cr_kinds(),
                           machine=ORIGIN_MACHINE,
                           devices_token=cr_document.DEVICES_TOKEN)


@bp.route('/<key>/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save(key):
    key = _load_or_404(key)
    from ..models_cr_types import is_builtin
    builtin = is_builtin(key)
    lang = langs.normalize(request.form.get('source_lang'))
    products = ([p for p in request.form.getlist('products') if p]
                if not builtin else None)
    order = request.form.get('sort_order')
    cr_types.upsert(key, source_lang=lang, products=products,
                    enabled=bool(request.form.get('enabled')),
                    sort_order=(int(order) if (order or '').strip().isdigit()
                                else None),
                    username=_username())

    texts = {name: (request.form.get(f'f_{name}') or '')
             for name in cr_types.FIELD_NAMES}
    # A documentary type with no name is an unreadable entry in the picker.
    # Refuse before writing, not after: a half-saved type is worse than none.
    if not builtin and not (texts.get('label') or '').strip():
        flash('A change type needs a name — the picker has nothing to show '
              'otherwise.', 'danger')
        return redirect(url_for('cr_types.edit', key=key))

    changed = cr_types.save_texts(key, texts, source_lang=lang,
                                  username=_username())
    msg = (f'Saved. {len(changed)} field(s) changed.' if changed
           else 'Saved — no text changed.')
    log_action('cr_type.save', target=key,
               detail=f'lang={lang} changed={",".join(changed) or "none"}')

    if request.form.get('translate') and changed:
        report = cr_types.translate_type(key, fields=changed,
                                         username=_username())
        msg += (f' Translated into {report["ok"]} language slot(s)'
                f' in {report["duration_ms"]} ms')
        tok = report.get('prompt_tokens')
        ctok = report.get('completion_tokens')
        if tok is not None or ctok is not None:
            msg += f' ({(tok or 0) + (ctok or 0)} tokens)'
        msg += '.'
        if report['failed']:
            # Named, not swallowed: a language that failed to translate is a
            # language the console will keep rendering in English, and the
            # only way to notice is to be told now.
            msg += f' {report["failed"]} failed — see the table below.'
            flash(msg, 'warning')
            return redirect(url_for('cr_types.edit', key=key))
    flash(msg, 'success')
    return redirect(url_for('cr_types.edit', key=key))


@bp.route('/<key>/translate', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def translate(key):
    key = _load_or_404(key)
    force = bool(request.form.get('force'))
    report = cr_types.translate_type(key, username=_username(), force=force)
    log_action('cr_type.translate', target=key,
               detail=(f'ok={report["ok"]} failed={report["failed"]} '
                       f'skipped={report["skipped"]} '
                       f'ms={report["duration_ms"]}'))
    tok = (report.get('prompt_tokens') or 0) + (report.get('completion_tokens') or 0)
    flash(f'{report["ok"]} translated, {report["skipped"]} kept, '
          f'{report["failed"]} failed — {report["duration_ms"]} ms, '
          f'{tok or "no"} tokens reported.',
          'warning' if report['failed'] else 'success')
    return redirect(url_for('cr_types.edit', key=key))


@bp.route('/<key>/review', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def review(key):
    """Mark one machine translation as read and accepted by a named person.

    Reviewing does NOT make it human-written — ``origin`` stays ``machine``.
    The reviewer's name is what makes the sentence citable; rewriting the
    provenance would erase the fact that a model drafted it.
    """
    key = _load_or_404(key)
    field = (request.form.get('field') or '').strip()
    lang = langs.normalize(request.form.get('lang'))
    if field not in cr_types.FIELD_NAMES:
        flash('Unknown field.', 'danger')
        return redirect(url_for('cr_types.edit', key=key))
    unit = translator.get_unit(cr_types.NAMESPACE,
                               cr_types.text_key(key, field), lang)
    if unit is None:
        flash('There is no translation to review there.', 'danger')
        return redirect(url_for('cr_types.edit', key=key))
    from ..models import db
    unit.reviewed = True
    unit.reviewed_by = _username()
    db.session.commit()
    log_action('cr_type.review', target=key, detail=f'{field}/{lang}')
    flash(f'{field} ({lang}) marked as reviewed by {_username()}.', 'success')
    return redirect(url_for('cr_types.edit', key=key))


@bp.route('/<key>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(key):
    key = _load_or_404(key)
    row = cr_types.get(key)
    if row is None:
        flash('Nothing to delete.', 'danger')
        return redirect(url_for('cr_types.index'))
    if row.builtin:
        # Deleting the OVERRIDE of a built-in is a reset, and that is what it
        # says it is. Deleting the built-in itself is not on offer: the action
        # is in the product, and a picker that hid it would not stop it
        # running.
        cr_types.delete(row)
        log_action('cr_type.reset', target=key)
        flash(f'"{key}" reset to the wording shipped with the product.',
              'success')
        return redirect(url_for('cr_types.edit', key=key))
    cr_types.delete(row)
    log_action('cr_type.delete', target=key)
    flash(f'Change type "{key}" deleted. Change requests already raised with '
          f'it keep their document.', 'success')
    return redirect(url_for('cr_types.index'))
