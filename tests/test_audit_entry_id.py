"""The audit entry ID: rendered, copyable, and findable.

Every row in ``audit_logs`` has always had a primary key — what it did not have
was a way for an operator to name one. A compliance question ("which entry are
you referring to?") could only be answered by quoting a timestamp, which is not
unique: one apply writes several rows inside the same second.

The guards below hold the three halves that make an ID useful together, because
any one of them alone is dead weight:

  1. it is RENDERED (a label nobody can see is not an identifier),
  2. it is FINDABLE (an ID you can copy and then not look up is a decoration),
  3. the listing is TOTALLY ORDERED (without a tiebreak the same ID can appear
     on two pages, which is exactly the confusion the ID exists to end).
"""
from __future__ import annotations

import re

from conftest import admin_user_id, login


# --------------------------------------------------------------------------
# §1 parse_entry_id — the three shapes an ID reaches the server in
# --------------------------------------------------------------------------

def test_parse_entry_id_accepts_the_shapes_the_ui_produces():
    from app.views.audit import parse_entry_id

    assert parse_entry_id('4821') == 4821        # clipboard copies the bare id
    assert parse_entry_id('#4821') == 4821       # the table renders it with '#'
    assert parse_entry_id('AUD-004821') == 4821  # zero-padded, as tickets quote it
    assert parse_entry_id('aud-4821') == 4821    # case must not matter
    assert parse_entry_id('  #4821  ') == 4821   # pasted text carries whitespace


def test_parse_entry_id_rejects_anything_that_is_not_an_id():
    """The ``None`` branch is the load-bearing one: it keeps an ordinary text
    search from being reinterpreted as a primary-key lookup."""
    from app.views.audit import parse_entry_id

    for junk in ('', '   ', 'admin', 'config.delete', '4821a', 'a4821',
                 '-4821', '48.21', '48 21', '#', 'AUD-', '#abc'):
        assert parse_entry_id(junk) is None, junk


def test_parse_entry_id_does_not_overflow_on_a_pasted_essay():
    """A long digit run is a search term, not an id — an unbounded int() here
    is a cheap way to make a query planner cry."""
    from app.views.audit import parse_entry_id

    assert parse_entry_id('9' * 40) is None


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _seed(app, rows):
    """rows: list of (action, target, extra, product). Returns the ids, in order."""
    from datetime import datetime
    from app.extensions import db
    from app.models import AuditLog

    ids = []
    with app.app_context():
        for action, target, extra, product in rows:
            e = AuditLog(username='admin', action=action, target=target,
                         extra=extra, product=product, ip_address='192.0.2.1',
                         timestamp=datetime(2026, 8, 9, 12, 0, 0))
            db.session.add(e)
            db.session.commit()
            ids.append(e.id)
    return ids


def _page(client, **params):
    from urllib.parse import urlencode
    r = client.get('/audit/?' + urlencode(params))
    assert r.status_code == 200
    return r.get_data(as_text=True)


# --------------------------------------------------------------------------
# §2 the ID is rendered
# --------------------------------------------------------------------------

def test_table_has_an_id_column_and_renders_every_row_id(app, client):
    ids = _seed(app, [
        ('config.create', 'waf/a', '{}', 'fortiweb'),
        ('config.delete', 'waf/b', '{}', 'fortiweb'),
    ])
    login(client, admin_user_id(app))
    html = _page(client)

    assert '<th style="width:92px;">ID</th>' in html
    for i in ids:
        assert f'>#{i}</span>' in html, f'entry {i} rendered without its ID'


def test_id_cell_carries_the_copy_hook_and_the_row_carries_the_id(app, client):
    """The drawer reads the ID off the row dataset; the cell is what you click
    to copy. Losing either one silently removes half the feature."""
    ids = _seed(app, [('config.create', 'waf/a', '{}', 'fortiweb')])
    login(client, admin_user_id(app))
    html = _page(client)

    assert f'data-js="copy-id" data-id="{ids[0]}"' in html
    assert f'data-id="{ids[0]}"' in html
    assert 'openAuditDetail' in html


def test_header_and_body_column_counts_agree(app, client):
    """Adding a column without widening the empty-state colspan leaves a table
    that renders correctly with data and skewed without it."""
    login(client, admin_user_id(app))
    html = _page(client)          # no rows seeded -> empty state renders

    head = html.split('<thead>')[1].split('</thead>')[0]
    n_th = len(re.findall(r'<th[ >]', head))
    colspan = int(re.search(r'<td colspan="(\d+)">', html).group(1))
    assert n_th == colspan, f'{n_th} headers vs colspan {colspan}'


def test_template_binds_handlers_and_never_uses_inline_on_attributes(app, client):
    """CSP sets ``script-src-attr 'none'`` — an ``onclick=`` would be silently
    refused by the browser, so the copy control would look wired and do nothing."""
    ids = _seed(app, [('config.create', 'waf/a', '{}', 'fortiweb')])
    login(client, admin_user_id(app))
    html = _page(client)

    assert 'onclick=' not in html
    assert 'copyEntryId' in html
    assert 'stopPropagation' in html   # copying must not also open the drawer


# --------------------------------------------------------------------------
# §3 the ID is findable
# --------------------------------------------------------------------------

def test_search_by_bare_id_finds_that_entry(app, client):
    ids = _seed(app, [
        ('config.create', 'waf/alpha', '{}', 'fortiweb'),
        ('config.delete', 'waf/beta', '{}', 'fortiweb'),
    ])
    login(client, admin_user_id(app))
    html = _page(client, q=str(ids[1]))

    assert 'waf/beta' in html
    assert 'waf/alpha' not in html


def test_search_accepts_the_id_exactly_as_the_table_prints_it(app, client):
    ids = _seed(app, [
        ('config.create', 'waf/alpha', '{}', 'fortiweb'),
        ('config.delete', 'waf/beta', '{}', 'fortiweb'),
    ])
    login(client, admin_user_id(app))

    for q in (f'#{ids[1]}', f'AUD-{ids[1]:06d}'):
        html = _page(client, q=q)
        assert 'waf/beta' in html, q
        assert 'waf/alpha' not in html, q


def test_id_search_is_additive_and_never_hides_a_text_match(app, client):
    """A numeric query is ALSO an ordinary search. If the id term replaced the
    LIKE terms instead of joining them, searching a port or an appliance number
    would start returning one unrelated row and nothing else."""
    ids = _seed(app, [
        ('config.create', 'waf/port-8443', '{}', 'fortiweb'),
        ('config.delete', 'waf/other', '{}', 'fortiweb'),
    ])
    login(client, admin_user_id(app))
    html = _page(client, q='8443')

    assert 'waf/port-8443' in html
    # ...and the row whose id happens to be that number would come too — the
    # point is only that the text match is not lost.
    assert 'waf/other' not in html
    assert ids                                    # ids exist; nothing to assert on them


def test_a_text_query_is_not_turned_into_an_id_lookup(app, client):
    _seed(app, [
        ('config.create', 'waf/alpha', '{}', 'fortiweb'),
        ('config.delete', 'waf/beta', '{}', 'fortiweb'),
    ])
    login(client, admin_user_id(app))
    html = _page(client, q='alpha')

    assert 'waf/alpha' in html
    assert 'waf/beta' not in html


def test_id_search_still_obeys_product_scoping(app, client):
    """The ID is a handle, not a bypass: a fortiweb session must not be able to
    pull a fortiadc row up by guessing its number."""
    ids = _seed(app, [('config.delete', 'adc/secret', '{}', 'fortiadc')])
    login(client, admin_user_id(app), product='fortiweb')
    html = _page(client, q=f'#{ids[0]}')

    assert 'adc/secret' not in html


# --------------------------------------------------------------------------
# §4 the listing is totally ordered
# --------------------------------------------------------------------------

def test_rows_sharing_a_timestamp_come_back_newest_id_first(app, client):
    """Same-second rows are the normal case (one apply writes several). Without
    the id tiebreak their order is whatever the database feels like, so a row
    can appear on two pages — or on none."""
    ids = _seed(app, [
        ('config.create', 'waf/first', '{}', 'fortiweb'),
        ('config.create', 'waf/second', '{}', 'fortiweb'),
        ('config.create', 'waf/third', '{}', 'fortiweb'),
    ])
    login(client, admin_user_id(app))
    html = _page(client)

    order = [int(m) for m in re.findall(r'data-js="copy-id" data-id="(\d+)"', html)]
    assert order == sorted(ids, reverse=True), order


def test_listing_orders_by_timestamp_then_id_in_the_emitted_sql(app, client):
    """SQLite happens to hand back same-timestamp rows newest-first on its own,
    so a behavioural assertion cannot tell "ordered" from "lucky" — deleting the
    tiebreak leaves every row-order test green. The tiebreak is a property of
    the QUERY, so that is what gets asserted: the real statement the page ran."""
    from sqlalchemy import event
    from app.extensions import db

    _seed(app, [('config.create', 'waf/a', '{}', 'fortiweb')])
    login(client, admin_user_id(app))

    seen = []

    def _rec(conn, cursor, statement, params, context, executemany):
        seen.append(' '.join(statement.split()))

    with app.app_context():
        event.listen(db.engine, 'before_cursor_execute', _rec)
    try:
        _page(client)
    finally:
        with app.app_context():
            event.remove(db.engine, 'before_cursor_execute', _rec)

    listing = [s for s in seen if 'audit_logs' in s and 'ORDER BY' in s]
    assert listing, 'the audit listing issued no ordered query at all'
    assert any('ORDER BY audit_logs.timestamp DESC, audit_logs.id DESC' in s
               for s in listing), listing


def test_paging_over_same_timestamp_rows_neither_repeats_nor_drops(app, client):
    ids = _seed(app, [(f'config.create', f'waf/n{i}', '{}', 'fortiweb')
                      for i in range(6)])
    login(client, admin_user_id(app))

    seen = []
    for page in (1, 2, 3):
        html = _page(client, page=page, per_page=10)   # per_page is clamped to >=10
        seen += [int(m) for m in re.findall(r'data-js="copy-id" data-id="(\d+)"', html)]
    # page 1 holds all six; pages 2-3 are empty. What must NOT happen is a row
    # showing up twice or vanishing.
    assert sorted(set(seen)) == sorted(ids)
    assert len(seen) == len(ids)


# --------------------------------------------------------------------------
# §5 the drawer
# --------------------------------------------------------------------------

def test_detail_drawer_shows_the_entry_id_with_its_own_copy_control(app, client):
    _seed(app, [('config.create', 'waf/a', '{}', 'fortiweb')])
    login(client, admin_user_id(app))
    html = _page(client)

    # Match the rendered LABEL, not the bare phrase: the code above it opens
    # with the comment ``// Entry ID first: ...``, so ``'Entry ID' in html``
    # passes against a panel that no longer draws the block at all.
    assert '>Entry ID</div>' in html
    assert 'copy-entryid' in html
    # The error-reference copy button predates this and must keep working: both
    # are bound by the same selector now, and dropping either silently kills a
    # button that still looks clickable.
    assert 'copy-errid' in html
    assert "'[data-js=\"copy-errid\"],[data-js=\"copy-entryid\"]'" in html
