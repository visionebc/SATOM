"""**Bookmarks panel** — the right-hand rail and everything that mutates it.

Two rules decide every route in this module, and both exist because the
alternative is a permission leak rather than an untidy screen.

1. **A by-id route NEVER touches ``Bookmark.query.get``.** Every id the browser
   sends is resolved against :func:`services.bookmarks.visible_bookmarks` for
   the person asking, so an id belonging to somebody else's personal bookmark,
   or to a row stamped for another ADOM, is indistinguishable from an id that
   does not exist. This product already shipped the other shape once: until
   2026-08-06 every by-id appliance route served another ADOM's device to
   anyone who guessed the number.

2. **A refusal names the rule that refused it.** ``BookmarkDenied`` carries a
   reason and it reaches the operator. A bare "not allowed" at 03:00 is what
   sends people looking for a way around the rule instead of a way to satisfy
   it.

The panel is a TREE, the shape a browser sidebar has: folders with a folder
icon and their name beside it, nested groups that collapse, and one search box
instead of a grouping dropdown. Three consequences worth stating, because each
replaced something that looked simpler:

*   **There is ONE inventory lens, and its heading is its order.** The
    reader picks the nesting — ``Department › Product › Line`` — on their own
    profile page, and the root is named after it. A ``<select>`` could only
    answer "how is this grouped right now" once you opened it; four fixed
    roots answered a question nobody asked ("how *could* it be grouped").
*   **The classification roots list the LIVE INVENTORY, not the bookmarks.**
    Every device the reader may see is in the tree from the first render, so
    the panel is useful before anybody has bookmarked anything, and a device
    added to the fleet appears without a bookmark migration. Starring or
    filing one *adopts* it — that, and only that, creates a row.
*   **Search filters on the SERVER.** The tree the browser holds is already
    the filtered one; a client-side ``display:none`` overlay would leave rows
    in the DOM that the reader's permissions had removed from the answer.
"""
from __future__ import annotations

import json

from flask import (
    Blueprint, render_template, request, abort, jsonify, url_for, g, session,
)
from flask_login import login_required, current_user

from ..branding import get_product

from ..extensions import db
from ..models import Appliance, UserSetting, visible_appliances
from ..models_bookmarks import (
    Bookmark, KIND_APPLIANCE, KIND_FOLDER, KIND_LINK, SCOPE_TEAM,
)
from ..services import bookmarks as svc
from ..services import settings_store
from ..services.audit import log_action

bp = Blueprint('bookmarks', __name__, url_prefix='/bookmarks')

#: Per-user preference keys. ``open`` stores the set of EXPANDED nodes, never
#: the collapsed one: the panel defaults to fully collapsed, and an empty set
#: gives exactly that with no first-run flag. Storing the collapsed set would
#: make "no preference yet" mean "expand everything", which on a hundred-device
#: fleet is the one state nobody wants.
K_OPEN = 'bookmarks.open'
K_SHOWHIDDEN = 'bookmarks.showhidden'
K_COLLAPSED = 'bookmarks.railclosed'

#: Root keys. Stable strings, because they are what the stored open-set holds:
#: deriving them from a translated label would collapse every operator's tree
#: the day somebody switches language.
ROOT_FAV = 'r:fav'
ROOT_FOLDERS = 'r:folders'
ROOT_SHARED = 'r:shared'
#: Deliberately NOT derived from the chosen order. The stored open-set is
#: keyed by node key, and a root whose key changed with the order would
#: slam itself shut every time somebody re-ordered their own tree.
ROOT_LENS = 'r:lens'

MAX_OPEN_KEYS = 400


# ---------------------------------------------------------------------------
# Preference helpers
# ---------------------------------------------------------------------------

def _open_nodes() -> set[str]:
    raw = UserSetting.get(current_user.id, K_OPEN, '[]')
    try:
        data = json.loads(raw or '[]')
    except (TypeError, ValueError):
        return set()
    return {str(x) for x in data} if isinstance(data, list) else set()


def _show_hidden() -> bool:
    return UserSetting.get(current_user.id, K_SHOWHIDDEN, '0') == '1'


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def _visible_or_404(bid: int) -> Bookmark:
    """The only way this module turns an id into a row."""
    for bm in svc.visible_bookmarks(current_user):
        if bm.id == bid:
            return bm
    abort(404)


def _denied(exc: svc.BookmarkDenied):
    return jsonify({'ok': False, 'reason': exc.reason, 'error': str(exc)}), 400


# ---------------------------------------------------------------------------
# Tree construction
# ---------------------------------------------------------------------------

def _label(bm: Bookmark) -> str:
    """The name shown. For a device this is the LIVE appliance name unless the
    author typed one — a stored copy of the name is the first field to go stale
    after a rename."""
    if bm.label:
        return bm.label
    if bm.kind == KIND_APPLIANCE and bm.appliance is not None:
        return bm.appliance.name
    return bm.url or '(untitled)'


def _node(key, name, *, icon='', kind='group', item=None,
          folder_id=None, droppable=False, sub='', note='', chip=False):
    return {
        'key': key, 'name': name, 'icon': icon, 'kind': kind, 'item': item,
        'children': [], 'folder_id': folder_id, 'droppable': droppable,
        'sub': sub, 'note': note, 'count': 0, 'chip': chip,
    }


def _prune(node: dict, q: str) -> bool:
    """Keep *node* if it, or anything under it, matches *q*.

    A group whose own name matches keeps its WHOLE subtree: searching for a
    zone and being shown the zone with none of its devices would be a worse
    answer than no answer. Matching is over the visible name plus the
    subtitle — for a device that is its management address, which is what an
    operator actually remembers at 03:00.
    """
    if not q:
        return True
    if node['kind'] == 'item':
        return q in (node['name'] + ' ' + (node['sub'] or '')).lower()
    if q in node['name'].lower():
        return True
    node['children'] = [c for c in node['children'] if _prune(c, q)]
    return bool(node['children'])


def _count(node: dict) -> int:
    if node['kind'] == 'item':
        node['count'] = 1
    else:
        node['count'] = sum(_count(c) for c in node['children'])
    return node['count']


def _sorted_children(node: dict) -> None:
    """Groups before devices, each alphabetically. ``(unclassified)`` and the
    other synthetic buckets sort LAST so they never push the real tree below
    the fold — they are shown, never hidden, but they are not the headline."""
    def rank(c):
        synthetic = c['name'] in (svc.UNCLASSIFIED, svc.NO_SEGMENT, svc.NON_DEVICE)
        return (0 if c['kind'] == 'group' else 1, 1 if synthetic else 0,
                c['name'].lower())
    node['children'].sort(key=rank)
    for c in node['children']:
        _sorted_children(c)


def _device_node(prefix: str, appl, item: dict | None) -> dict:
    # A device nobody has bookmarked yet still gets its direct link: the link
    # describes the DEVICE, and making it appear only after somebody stars the
    # row would hide it on exactly the devices nobody is watching.
    _dev = svc.device_link(appl)
    return _node(
        f'{prefix}|a{appl.id}', appl.name, icon='bi-hdd-network', kind='item',
        item=item or {'bm': None, 'appliance_id': appl.id, 'label': appl.name,
                      'fav': False, 'hidden': False, 'shared': False,
                      'mine': False, 'may_edit': False, 'parent_id': None,
                      'dev_url': _dev[0], 'dev_note': _dev[1]},
        sub=appl.host or '',
    )


def build_panel(q: str = '') -> dict:
    """Everything the template needs, in one pass over the visible rows."""
    q = (q or '').strip().lower()
    rows = svc.visible_bookmarks(current_user)
    placed = svc.placements(current_user)
    favs = svc.favorites(current_user)
    show_hidden = _show_hidden()
    segments = settings_store.segments()

    items: list[dict] = []
    by_appliance: dict[int, dict] = {}
    hidden_shown = 0

    for bm in rows:
        row = placed.get(bm.id)
        is_hidden = bool(row is not None and row.hidden)
        if is_hidden:
            hidden_shown += 1
            if not show_hidden:
                continue
        # Computed HERE, not in the template: the panel renders items
        # through four roots, and a per-root expression is four authors of
        # one truth. An item that is not a device carries (None, '').
        dev_url, dev_note = (
            svc.device_link(bm.appliance)
            if bm.kind == KIND_APPLIANCE else (None, ''))
        # A stored URL is re-checked on the way OUT as well as on the way
        # in. `svc.create` is not the only writer that can reach this
        # table, and a `javascript:` href in a TEAM bookmark is stored XSS
        # in every colleague's sidebar -- including the read-only ones, who
        # cannot delete it. Checking only at write time trusts every row
        # this process did not write.
        link_url, link_note = (
            svc.safe_link_url(bm.url) if bm.kind == KIND_LINK
            else (None, ''))
        item = {
            'bm': bm,
            'dev_url': dev_url,
            'dev_note': dev_note,
            'link_url': link_url,
            'link_note': link_note,
            'appliance_id': bm.appliance_id,
            'label': _label(bm),
            'fav': bm.id in favs,
            'hidden': is_hidden,
            'shared': bm.scope == SCOPE_TEAM,
            'mine': bm.owner_user_id == current_user.id,
            'may_edit': svc.may_edit(bm, current_user),
            'parent_id': row.parent_id if row is not None else None,
            'filed': row is not None,
        }
        items.append(item)
        if bm.kind == KIND_APPLIANCE and bm.appliance_id is not None:
            # A personal row wins over a team row for the star/eye controls
            # shown next to a device in the inventory lenses: the acting user's
            # own bookmark is the one their actions write to.
            prev = by_appliance.get(bm.appliance_id)
            if prev is None or (not prev['mine'] and item['mine']):
                by_appliance[bm.appliance_id] = item

    # ---- root: favourites -------------------------------------------------
    fav_root = _node(ROOT_FAV, 'Favourites', icon='bi-star-fill')
    for it in items:
        if it['fav'] and it['bm'].kind != KIND_FOLDER:
            fav_root['children'].append(
                _node(f'{ROOT_FAV}|b{it["bm"].id}', it['label'],
                      icon=_icon_for(it), kind='item', item=it,
                      sub=_sub_for(it)))

    # ---- root: personal folders ------------------------------------------
    folders_root = _node(ROOT_FOLDERS, 'Folders', icon='bi-folder2',
                         droppable=True, folder_id=0)
    by_parent: dict[int | None, list[dict]] = {}
    for it in items:
        by_parent.setdefault(it['parent_id'], []).append(it)

    def _folder_children(parent_id, prefix, seen):
        out = []
        for it in by_parent.get(parent_id, []):
            bm = it['bm']
            if bm.kind == KIND_FOLDER:
                if bm.id in seen:
                    continue
                n = _node(f'{prefix}|f{bm.id}', it['label'], icon='bi-folder2',
                          folder_id=bm.id, droppable=it['may_edit'])
                n['children'] = _folder_children(bm.id, n['key'], seen | {bm.id})
                n['item'] = it
                out.append(n)
            elif parent_id is not None or not it['shared'] or it['filed']:
                # An unfiled TEAM bookmark belongs in the Shared tray, which is
                # the default destination of a row nobody has placed yet — not
                # a folder anybody can delete.
                out.append(_node(f'{prefix}|b{bm.id}', it['label'],
                                 icon=_icon_for(it), kind='item', item=it,
                                 sub=_sub_for(it)))
        return out

    folders_root['children'] = _folder_children(None, ROOT_FOLDERS, set())

    # ---- root: shared tray ------------------------------------------------
    shared_root = _node(ROOT_SHARED, 'Shared', icon='bi-inbox')
    for it in items:
        if it['shared'] and not it['filed']:
            shared_root['children'].append(
                _node(f'{ROOT_SHARED}|b{it["bm"].id}', it['label'],
                      icon=_icon_for(it), kind='item', item=it,
                      sub=_sub_for(it)))

    # ---- root: THE inventory lens ----------------------------------------
    # One root, nested in the order this reader chose, and named after it.
    # Four fixed roots answered "how COULD this be grouped"; an operator wants
    # one answer and wants to see which one without opening anything, so the
    # order is the heading. Changing it is a per-user act on the profile page:
    # nobody re-shapes anybody else's panel.
    stack = svc.lens_for(current_user)
    appliances = visible_appliances(
        db.session.query(Appliance), user=current_user).all()
    lens_root = _node(ROOT_LENS, svc.lens_title(stack), icon='bi-diagram-3')
    for appl in appliances:
        cursor = lens_root
        path = ROOT_LENS
        values = [svc.dimension_value(appl, d, segments) for d in stack]
        # A device classified nowhere would otherwise sink three levels of
        # "(unclassified) → (unclassified) → (unclassified)": depth with no
        # information in it, on the half of the fleet that most needs to be
        # noticed. The chain is truncated at the first empty level ONLY when
        # every level below it is empty too — a device with no line but a
        # real zone still gets "(unclassified) → internal", because that
        # zone is a fact and the tree should not swallow it.
        for i, value in enumerate(values):
            if all(v == svc.UNCLASSIFIED for v in values[i:]):
                values = values[:i + 1]
                break
        # The KEY is the raw stored value; only the NAME is the displayed one.
        # Keying on the label would move every node the day a product is
        # renamed in the ADOM registry, and the open/closed set is keyed on
        # exactly that string -- a rename would silently collapse the tree of
        # every user who had it open.
        for dim, value in zip(stack, values):
            path = f'{path}|{value}'
            nxt = next((c for c in cursor['children']
                        if c['kind'] == 'group' and c['key'] == path), None)
            if nxt is None:
                # The chip claims "this is a product". `(unclassified)` is a
                # sentence about the record, not a product, so it is left as
                # plain text -- a tinted pill reading "(unclassified)" would
                # look like a device kind somebody had declared.
                nxt = _node(path, svc.dimension_label(dim, value),
                            icon='bi-folder2',
                            chip=(dim == 'kind' and value != svc.UNCLASSIFIED))
                cursor['children'].append(nxt)
            cursor = nxt
        cursor['children'].append(
            _device_node(cursor['key'], appl, by_appliance.get(appl.id)))

    roots = [fav_root, folders_root, shared_root, lens_root]
    roots = [r for r in roots if _prune(r, q)]
    for r in roots:
        _count(r)
        _sorted_children(r)

    counts = svc.tray_counts(current_user)
    # The chip wash follows the reader's own banner, resolved through the same
    # store the top bar uses. Emitted as two custom properties on ONE element
    # rather than a style= on every chip: the stylesheet keeps the rule, the
    # server only supplies the colour.
    _prod = get_product(getattr(g, 'product', None) or session.get('product'))
    _tint = svc.reader_tint(current_user.id, _prod['key'])
    return {
        'roots': roots,
        'type_fill': _tint['fill'],
        'type_line': _tint['line'],
        'row_hover': _tint['hover'],
        'q': q,
        # Searching expands what it found. Returning matches inside collapsed
        # nodes would render as "no results" while holding them.
        'force_open': bool(q),
        'open_nodes': _open_nodes(),
        'show_hidden': show_hidden,
        'hidden_shown': hidden_shown,
        'unplaced': counts['unplaced'],
        'hidden_count': counts['hidden'],
        'can_share': current_user.can(svc.SHARE_PERMISSION),
        'root_shared': ROOT_SHARED,
        'root_folders': ROOT_FOLDERS,
        'root_lens': ROOT_LENS,
        'lens': stack,
        'lens_url': url_for('auth.profile') + '#bookmark-view',
        'device_count': len(appliances),
    }


def _icon_for(it: dict) -> str:
    bm = it['bm']
    if bm is None or bm.kind == KIND_APPLIANCE:
        return 'bi-hdd-network'
    if bm.kind == 'link':
        return 'bi-link-45deg'
    if bm.kind == KIND_FOLDER:
        return 'bi-folder2'
    return 'bi-funnel'


def _sub_for(it: dict) -> str:
    bm = it['bm']
    if bm is None:
        return ''
    if bm.kind == KIND_APPLIANCE and bm.appliance is not None:
        return bm.appliance.host or ''
    return bm.url or ''


def _render(q: str = ''):
    return render_template('partials/bookmarks_panel.html', **build_panel(q))


@bp.route('/panel')
@login_required
def panel():
    return _render(request.args.get('q', ''))


@bp.route('/devices')
@login_required
def devices():
    """The device picker for "add bookmark". Scoped through the SAME gate the
    rest of the console uses, so the picker cannot enumerate devices the user
    may not open."""
    q = (request.args.get('q') or '').strip().lower()
    rows = visible_appliances(db.session.query(Appliance), user=current_user).all()
    out = [
        {'id': a.id, 'name': a.name, 'host': a.host, 'kind': a.kind}
        for a in rows if not q or q in a.name.lower() or q in (a.host or '').lower()
    ]
    return jsonify({'devices': sorted(out, key=lambda d: d['name'].lower())[:200]})


# ---------------------------------------------------------------------------
# Mutations — each answers with the re-rendered panel
# ---------------------------------------------------------------------------

def _q() -> str:
    """The search term in force while a mutation happens. Answering a starred
    device with the UNFILTERED tree would silently drop the operator out of
    their search."""
    return request.form.get('q', '')


@bp.route('/create', methods=['POST'])
@login_required
def create():
    f = request.form
    parent = f.get('parent_id', type=int)
    try:
        svc.create(
            current_user, (f.get('kind') or KIND_APPLIANCE).strip(),
            appliance_id=f.get('appliance_id', type=int),
            url=f.get('url', ''), label=f.get('label', ''),
            view_query=f.get('view_query', ''), parent_id=parent,
        )
    except svc.BookmarkDenied as exc:
        return _denied(exc)
    return _render(_q())


@bp.route('/adopt', methods=['POST'])
@login_required
def adopt():
    """Turn a device shown in an inventory lens into a bookmark this user owns.

    Idempotent on purpose: starring a device that already has a bookmark must
    not mint a second one. Two rows for one device is how a panel starts
    showing the same appliance twice with different stars.
    """
    try:
        bm = svc.adopt(current_user, request.form.get('appliance_id', type=int),
                       parent_id=request.form.get('parent_id', type=int))
    except svc.BookmarkDenied as exc:
        return _denied(exc)
    if request.form.get('favorite') == '1':
        svc.set_favorite(current_user, bm, True)
    return _render(_q())


@bp.route('/<int:bid>/place', methods=['POST'])
@login_required
def place(bid):
    bm = _visible_or_404(bid)
    parent = request.form.get('parent_id', type=int)
    try:
        svc.place(current_user, bm, parent_id=parent,
                  position=request.form.get('position', 0, type=int))
    except svc.BookmarkDenied as exc:
        return _denied(exc)
    return _render(_q())


@bp.route('/<int:bid>/favorite', methods=['POST'])
@login_required
def favorite(bid):
    bm = _visible_or_404(bid)
    svc.set_favorite(current_user, bm, request.form.get('favorite') == '1')
    return _render(_q())


@bp.route('/<int:bid>/hidden', methods=['POST'])
@login_required
def hidden(bid):
    bm = _visible_or_404(bid)
    try:
        svc.set_hidden(current_user, bm, request.form.get('hidden') == '1')
    except svc.BookmarkDenied as exc:
        return _denied(exc)
    return _render(_q())


@bp.route('/<int:bid>/share', methods=['POST'])
@login_required
def share(bid):
    bm = _visible_or_404(bid)
    try:
        svc.share(bm, current_user)
    except svc.BookmarkDenied as exc:
        return _denied(exc)
    # Publishing changes what every operator sees. An unaudited change of
    # visibility is a change nobody can attribute afterwards.
    log_action('bookmark.share', target=f'bookmark:{bm.id}',
               detail=f'{bm.kind} "{_label(bm)}" shared with the team')
    return _render(_q())


@bp.route('/<int:bid>/delete', methods=['POST'])
@login_required
def delete(bid):
    bm = _visible_or_404(bid)
    shared, label, kind = bm.scope == SCOPE_TEAM, _label(bm), bm.kind
    try:
        svc.delete(bm, current_user)
    except svc.BookmarkDenied as exc:
        return _denied(exc)
    if shared:
        log_action('bookmark.delete', target=f'bookmark:{bid}',
                   detail=f'shared {kind} "{label}" removed')
    return _render(_q())


@bp.route('/prefs', methods=['POST'])
@login_required
def prefs():
    f = request.form
    if 'open' in f:
        try:
            nodes = json.loads(f.get('open') or '[]')
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'reason': 'bad_open'}), 400
        if not isinstance(nodes, list):
            return jsonify({'ok': False, 'reason': 'bad_open'}), 400
        UserSetting.set(current_user.id, K_OPEN,
                        json.dumps([str(n) for n in nodes][:MAX_OPEN_KEYS]))
    if 'showhidden' in f:
        UserSetting.set(current_user.id, K_SHOWHIDDEN,
                        '1' if f.get('showhidden') == '1' else '0')
    if 'railclosed' in f:
        UserSetting.set(current_user.id, K_COLLAPSED,
                        '1' if f.get('railclosed') == '1' else '0')
    db.session.commit()
    return _render(_q())
