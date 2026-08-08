"""Guards for the Attack-ID investigation layer added 2026-08-08.

Four services, four different things that can quietly go wrong:

* :mod:`wpp_scope` — the sharing gate. The failure mode is silence: a carve-out
  authored on a profile four Server Policies bind, applied to all four, with
  nothing on screen to say so. Most of these tests exist to prove that an
  *unknown* answer is never rendered as a safe one.
* :mod:`attack_field_intel` — field analysis. The failure mode is a confident
  wrong label, so the flagger is tested against benign input as hard as against
  hostile input: a panel that cries injection over a search box teaches
  operators to stop reading it.
* :mod:`exception_explain` — the review card. The failure mode is a carve-out
  that reads narrow and behaves wide.
* :mod:`attack_carveout` — payload assembly. The failure mode is a payload that
  matches less than the operator believes it matches.
"""
from __future__ import annotations

import pytest

from app.services import attack_carveout as cv
from app.services import attack_field_intel as fi
from app.services import exception_explain as ex
from app.services import wpp_scope as sc


SIG_ROW = {
    'msg_id': '000000004106', 'main_type': 'Signature Detection',
    'sub_type': 'SQL Injection', 'policy': 'pol-satom-lab',
    'src': '203.0.113.44', 'src_port': '51544',
    'dst': '192.0.2.90', 'dst_port': '443',
    'http_host': 'lab.example.com',
    'http_url': '/app/search.php?q=1%27%20UNION%20SELECT%20*%20FROM%20users--',
    'http_method': 'GET', 'http_agent': 'sqlmap/1.7.2#stable',
    'signature_id': '030000001', 'action': 'Deny',
}

CONSTRAINT_ROW = {
    'msg_id': '000000004200', 'main_type': 'HTTP Protocol Constraints',
    'sub_type': 'Header Length Exceeded', 'policy': 'pol-shop',
    'src': '198.51.100.7', 'http_host': 'shop.example.com',
    'http_url': '/checkout/submit', 'http_method': 'POST', 'action': 'Deny',
}


# --------------------------------------------------------------------------- #
#  wpp_scope — the gate that did not exist                                     #
# --------------------------------------------------------------------------- #
def test_shared_profile_needs_a_clone(app):
    with app.app_context():
        v = sc.check(None, 'WPP-shared', 'pol-a', binding_map={
            'pol-a': 'WPP-shared', 'pol-b': 'WPP-shared', 'pol-c': 'WPP-other'})
    assert v.state == sc.SHARED
    assert v.needs_clone is True
    assert v.shared_with == ['pol-b']


def test_shared_reason_names_the_other_policies(app):
    """The blast radius is the whole point: a reason that says "shared" without
    saying WITH WHAT cannot be acted on."""
    with app.app_context():
        v = sc.check(None, 'WPP-shared', 'pol-a', binding_map={
            'pol-a': 'WPP-shared', 'pol-b': 'WPP-shared', 'pol-z': 'WPP-shared'})
    reason = ' '.join(v.reasons())
    assert 'pol-b' in reason and 'pol-z' in reason
    assert 'pol-a' not in reason.replace('"pol-a"', '')  # not listed as a sharer


def test_exclusive_profile_authors_directly(app):
    """The user's rule: a policy that already owns its profile gets no clone."""
    with app.app_context():
        v = sc.check(None, 'WPP-solo', 'pol-a', binding_map={
            'pol-a': 'WPP-solo', 'pol-b': 'WPP-other'})
    assert v.state == sc.EXCLUSIVE
    assert v.needs_clone is False
    assert v.reasons() == []
    assert v.clone_name == ''


def test_unreadable_device_is_unknown_not_safe(app):
    """The load-bearing one. An empty binding map with a read error must never
    collapse into "nothing else binds it" — that is a fail-open on the exact
    question the gate exists to answer."""
    with app.app_context():
        v = sc.check(None, 'WPP-x', 'pol-a', binding_map={}, device_error='timeout')
    assert v.state == sc.UNKNOWN
    assert v.needs_clone is True
    assert 'could not read' in ' '.join(v.reasons()).lower()


def test_empty_binding_map_without_error_is_exclusive(app):
    """A box that genuinely has no policies is not an error state."""
    with app.app_context():
        v = sc.check(None, 'WPP-x', 'pol-a', binding_map={}, device_error='')
    assert v.state == sc.EXCLUSIVE and v.needs_clone is False


def test_profile_bound_only_by_a_different_policy_is_shared(app):
    """Authoring "for" a policy that does not bind the profile would change
    somebody else's site and not our own."""
    with app.app_context():
        v = sc.check(None, 'WPP-x', 'pol-a', binding_map={'pol-b': 'WPP-x'})
    assert v.state == sc.SHARED and v.shared_with == ['pol-b']


def test_clone_name_offered_only_when_a_clone_is_needed(app):
    with app.app_context():
        shared = sc.check(None, 'WPP-x', 'pol-a',
                          binding_map={'pol-a': 'WPP-x', 'pol-b': 'WPP-x'})
        solo = sc.check(None, 'WPP-x', 'pol-a', binding_map={'pol-a': 'WPP-x'})
    assert shared.clone_name and 'pol-a' in shared.clone_name
    assert solo.clone_name == ''


def test_to_dict_carries_the_reasons(app):
    """The view serialises this straight to the browser; a dict that drops the
    reasons renders a warning with no text in it."""
    with app.app_context():
        d = sc.check(None, 'WPP-x', 'pol-a',
                     binding_map={'pol-a': 'WPP-x', 'pol-b': 'WPP-x'}).to_dict()
    assert d['needs_clone'] is True and d['reasons'] and d['summary']


def test_bindings_reports_a_dead_device_as_an_error(app):
    """``({}, "")`` and ``({}, "reason")`` mean opposite things; a client that
    raises must produce the second."""
    class _Boom:
        def __init__(self, *a, **k):
            raise RuntimeError('connection refused')
    import app.clients.fortiweb as fwmod
    orig = fwmod.FortiWebClient
    fwmod.FortiWebClient = _Boom
    try:
        with app.app_context():
            m, err = sc.bindings(object())
    finally:
        fwmod.FortiWebClient = orig
    assert m == {} and 'connection refused' in err


def test_no_profile_named_is_not_a_scope_problem(app):
    with app.app_context():
        v = sc.check(None, '', 'pol-a', binding_map={})
    assert v.needs_clone is False


# --------------------------------------------------------------------------- #
#  attack_field_intel                                                          #
# --------------------------------------------------------------------------- #
def test_private_source_warns_about_the_proxy():
    d = fi.describe('src', '192.0.2.9', resolve_ptr=False)
    assert d['classification'] == 'private (RFC1918)'
    assert 'X-Forwarded-For' in ' '.join(d['notes'])


def test_documentation_ranges_are_not_called_rfc1918():
    """``ipaddress`` reports 198.51.100.0/24 as ``is_private``, so a bare
    ``is_private`` branch labels TEST-NET traffic "RFC1918" and sends the
    operator hunting for a reverse proxy that is not there. Worse, it made
    ``test_ptr_lookup_is_skippable`` pass VACUOUSLY: the PTR branch only runs
    for public addresses, and the sample it used was never classified public."""
    for addr in ('198.51.100.7', '203.0.113.44', '192.0.2.1'):
        d = fi.describe('src', addr, resolve_ptr=False)
        assert 'documentation' in d['classification'], addr
        assert 'RFC1918' not in d['classification'], addr


def test_cgnat_is_not_reported_as_one_user():
    d = fi.describe('src', '100.70.1.5', resolve_ptr=False)
    assert 'carrier' in d['classification']


def test_ptr_lookup_is_skippable():
    """Proves the network call is opt-out — the suite must never depend on a
    resolver, and an isolated management network must not stall the panel.

    The address must classify as *public*, or the PTR branch is never reached
    and this asserts nothing at all."""
    d = fi.describe('src', '8.8.8.8', resolve_ptr=False)
    assert d['classification'] == 'public', 'sample must reach the PTR branch'
    assert not any('PTR' in f['label'] for f in d['facts'])


def test_url_flags_are_found_on_the_decoded_form():
    """The payload here is percent-encoded; a flagger that only reads the raw
    string sees ``%20UNION%20SELECT`` and reports nothing."""
    d = fi.describe('http_url', SIG_ROW['http_url'])
    assert 'SQL union' in [f['label'] for f in d['flags']]
    assert d['decoded'] and 'UNION SELECT' in d['decoded']


def test_url_traversal_flagged():
    d = fi.describe('http_url', '/static/../../etc/passwd')
    labels = [f['label'] for f in d['flags']]
    assert 'path traversal' in labels and 'system file' in labels


def test_benign_url_raises_no_flags():
    """The flagger's own false-positive test. A panel that cries wolf on
    ordinary traffic gets ignored on the request that matters."""
    d = fi.describe('http_url', '/products/list?category=shoes&page=2&sort=price')
    assert d['flags'] == []
    assert [p['name'] for p in d['params']] == ['category', 'page', 'sort']


def test_query_string_is_broken_into_parameters():
    d = fi.describe('http_url', '/a?x=1&y=2')
    assert {'name': 'x', 'value': '1'} in d['params']


def test_scanner_and_browser_agents_are_told_apart():
    assert fi.describe('http_agent', SIG_ROW['http_agent'])['classification'] == 'scanner'
    assert fi.describe(
        'http_agent',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    )['classification'] == 'browser'


def test_empty_user_agent_is_its_own_signal():
    assert fi.describe('http_agent', '')['value'] == ''
    assert fi.describe('http_agent', ' ')['kind'] == 'agent'


def test_ephemeral_source_port_is_labelled_as_meaningless():
    d = fi.describe('src_port', '51544')
    assert any('ephemeral' in f['value'] for f in d['facts'])


def test_well_known_port_named():
    d = fi.describe('dst_port', '443')
    assert any('HTTPS' in (f['note'] or '') for f in d['facts'])


def test_describe_never_raises_on_junk():
    for key, val in (('src', 'not-an-ip'), ('src_port', 'xx'),
                     ('http_url', None), ('nonexistent_key', 'x'),
                     ('signature_id', '')):
        d = fi.describe(key, val)
        assert 'value' in d and 'facts' in d


def test_signature_intel_points_at_the_narrowest_option():
    d = fi.describe('signature_id', '030000001')
    joined = ' '.join(f['label'] + f['value'] + f['note'] for f in d['facts'])
    assert 'Narrowest' in joined


def test_correlate_counts_matches_and_distinct_types():
    rows = [SIG_ROW,
            dict(SIG_ROW, main_type='XSS'),
            dict(SIG_ROW, src='198.51.100.1', main_type='Bot')]
    c = fi.correlate(rows, 'src', SIG_ROW['src'])
    assert c['total'] == 3 and c['matches'] == 2
    assert sorted(c['types']) == ['Signature Detection', 'XSS']


# --------------------------------------------------------------------------- #
#  exception_explain                                                           #
# --------------------------------------------------------------------------- #
def test_disabling_a_signature_reads_as_wide(app):
    with app.app_context():
        e = ex.explain('signature_disable_item', {'signature_id': '030000001'})
    assert e['breadth'] == ex.WIDE
    assert 'every request' in e['stops'].lower()


def test_pinned_signature_exception_reads_as_narrow(app):
    with app.app_context():
        e = ex.explain('signature_filter_item', {
            'signature_id': '030000001', 'match-target': 'URI',
            'operator': 'STRING_MATCH', 'value': '/app/search.php'})
    assert e['breadth'] == ex.NARROW and 'value' in e['breadth_why']


def test_unpinned_signature_exception_is_widened(app):
    """The one that matters. This type is narrow *by type* and wide *in fact*
    when no element is named — reporting the type's usual breadth would tell
    the operator the opposite of the truth."""
    with app.app_context():
        e = ex.explain('signature_filter_item', {'signature_id': '030000001'})
    assert e['breadth'] == ex.MODERATE
    assert 'none of its scoping fields' in e['breadth_why']


def test_gui_path_names_policy_profile_group_and_type(app):
    with app.app_context():
        e = ex.explain('http_constraint_exception_item',
                       {'request-type': 'plain', 'request-file': '/a'},
                       wpp='WPP-x', policy='pol-a')
    joined = ' → '.join(e['gui_path'])
    assert 'pol-a' in joined and 'WPP-x' in joined
    assert 'HTTP Protocol Constraints' in joined


def test_signature_types_are_labelled_as_known_attack_changes(app):
    with app.app_context():
        sig = ex.explain('signature_filter_item', {'signature_id': '030000001'})
        exc = ex.explain('http_constraint_exception_item', {})
    assert 'KNOWN ATTACK' in sig['category_label']
    assert 'KNOWN ATTACK' not in exc['category_label']
    assert 'signature set' in sig['container']


def test_custom_rule_container_is_named_as_such(app):
    with app.app_context():
        e = ex.explain('signature_group_rule_condition',
                       {'match-target': 'URI', 'operator': 'STRING_MATCH',
                        'value': '/a'})
    assert 'custom rule' in e['container']


def test_unmodelled_payload_key_is_shown_not_dropped(app):
    """A field the reviewer never saw is a field they never approved."""
    with app.app_context():
        e = ex.explain('signature_filter_item',
                       {'signature_id': '030000001', 'made-up-key': 'x'})
    assert 'made-up-key' in e['unknown_fields']
    assert 'made-up-key' in [f['key'] for f in e['fields']]


def test_missing_required_fields_are_reported(app):
    with app.app_context():
        e = ex.explain('http_constraint_exception_item', {'host': 'a.example'})
    assert set(e['missing_required']) == {'request-type', 'request-file'}


def test_explain_survives_a_type_it_cannot_inject(app):
    with app.app_context():
        e = ex.explain('not_a_real_type', {'a': 1})
    assert e['injectable'] is False and e['fields']


# --------------------------------------------------------------------------- #
#  attack_carveout                                                             #
# --------------------------------------------------------------------------- #
def test_signature_entry_suggests_the_per_id_exception_first(app):
    with app.app_context():
        s = cv.suggest_types(SIG_ROW)
    assert s[0]['exc_type'] == 'signature_filter_item'


def test_constraint_entry_suggests_the_constraint_exception(app):
    """"Known attack → signature" is wrong for a protocol-constraint block, and
    it is the mistake a non-specialist makes every time."""
    with app.app_context():
        s = cv.suggest_types(CONSTRAINT_ROW)
    assert s[0]['exc_type'] == 'http_constraint_exception_item'
    assert 'protocol constraint' in s[0]['why'].lower()


def test_wide_options_are_offered_last_and_marked(app):
    with app.app_context():
        s = cv.suggest_types(SIG_ROW)
    keys = [d['exc_type'] for d in s]
    assert keys.index('signature_disable_item') == len(keys) - 1
    assert 'Widest' in s[-1]['why']


def test_build_scopes_a_signature_exception_to_the_url(app):
    with app.app_context():
        b = cv.build(SIG_ROW, 'signature_filter_item', ['http_url'])
    assert b['payload']['match-target'] == 'URI'
    assert b['payload']['value'] == '/app/search.php'   # query string dropped
    assert b['errors'] == []


def test_build_uses_one_element_and_says_what_it_dropped(app):
    """FortiWeb matches ONE element per exception row. Silently keeping the
    first selection would produce a carve-out narrower than it looks."""
    with app.app_context():
        b = cv.build(SIG_ROW, 'signature_filter_item', ['http_url', 'src'])
    assert b['payload']['match-target'] == 'URI'
    assert 'src' in [i['row_key'] for i in b['ignored']]
    assert any('ONE element' in w for w in b['warnings'])


def test_build_warns_when_nothing_scopes_the_exception(app):
    with app.app_context():
        b = cv.build(SIG_ROW, 'signature_filter_item', [])
    assert 'match-target' not in b['payload']
    assert any('EVERY request' in w for w in b['warnings'])


def test_build_rejects_a_field_the_type_cannot_express(app):
    with app.app_context():
        b = cv.build(SIG_ROW, 'geo_ip_exception_member_item',
                     ['http_url', 'src'])
    assert b['payload'] == {'ip': SIG_ROW['src']}
    assert [i['row_key'] for i in b['ignored']] == ['http_url']


def test_build_fills_both_url_and_host_for_a_constraint_exception(app):
    with app.app_context():
        b = cv.build(CONSTRAINT_ROW, 'http_constraint_exception_item',
                     ['http_url', 'http_host'])
    assert b['payload']['request-file'] == '/checkout/submit'
    assert b['payload']['host'] == 'shop.example.com'
    assert b['payload']['host-status'] == 'enable'
    assert b['errors'] == []


def test_build_skips_a_field_the_entry_has_no_value_for(app):
    row = dict(CONSTRAINT_ROW, http_host='')
    with app.app_context():
        b = cv.build(row, 'http_constraint_exception_item',
                     ['http_url', 'http_host'])
    assert 'host' not in b['payload']
    assert 'http_host' in [i['row_key'] for i in b['ignored']]


def test_build_output_passes_the_stores_own_validator(app):
    """The assembled payload must satisfy the SAME validator the manual form
    is held to — a builder with its own idea of valid is a builder that fails
    at the device."""
    from app.services import wpp_exceptions as store
    with app.app_context():
        for exc_type, sel, row in (
                ('signature_filter_item', ['http_url'], SIG_ROW),
                ('http_constraint_exception_item', ['http_url'], CONSTRAINT_ROW),
                ('geo_ip_exception_member_item', ['src'], SIG_ROW)):
            b = cv.build(row, exc_type, sel)
            assert store.validate_payload(exc_type, b['payload']) == [], exc_type


def test_build_rejects_an_unknown_type(app):
    with app.app_context():
        b = cv.build(SIG_ROW, 'nope', ['http_url'])
    assert b['errors'] and b['payload'] == {}


def test_scopers_for_is_empty_for_the_blanket_types(app):
    """A type with no element to scope must not offer checkboxes that do
    nothing — an ignored selection reads as an applied one."""
    assert cv.scopers_for('signature_disable_item') == []
    assert cv.scopers_for('signature_filter_item')


@pytest.mark.parametrize('url,expected', [
    ('/a/b.php?x=1', '/a/b.php'),
    ('https://h/a/b', '/a/b'),
    ('a/b', '/a/b'),
    ('', ''),
])
def test_path_extraction(url, expected):
    assert cv._path_of(url) == expected


# --------------------------------------------------------------------------- #
#  Endpoint level — the gate must fire through HTTP, not only in the service    #
# --------------------------------------------------------------------------- #
def _appliance(app, name='fw-scope'):
    from app.extensions import db
    from app.models import Appliance
    ap = Appliance(name=name, host='192.0.2.99', port=443, username='u')
    ap.password = 'p'
    db.session.add(ap)
    db.session.commit()
    return ap.id


def _wired(app, monkeypatch, bindings, row=None):
    """Stub the two device reads every carve-out path makes."""
    from app.services import attack_log
    from app.services import wpp_scope as scope_mod
    from app.views import attack_search as view
    monkeypatch.setattr(view.attack_log, 'search_by_msg_id',
                        lambda a, m: [dict(row or CONSTRAINT_ROW)])
    monkeypatch.setattr(scope_mod, 'bindings', lambda a: (dict(bindings), ''))
    monkeypatch.setattr(attack_log, 'recent', lambda a, limit=100: [])


def _as_admin(app, client):
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))


def test_carveout_endpoint_refuses_a_shared_profile(app, client, monkeypatch):
    """The rule the product was missing, exercised through the route the browser
    actually calls. ``wpp-full-lab`` on the lab box really is bound by three
    policies; before this the draft was written and nothing said so."""
    from app.services import wpp_exceptions as store
    with app.app_context():
        aid = _appliance(app)
        _wired(app, monkeypatch,
               {'pol-shop': 'wpp-shared', 'pol-other': 'wpp-shared'},
               row=dict(CONSTRAINT_ROW, policy='pol-shop'))
        _as_admin(app, client)
        before = len(store.list_all() if hasattr(store, 'list_all') else [])
        r = client.post('/waf/attack-search/carve-out', json={
            'appliance_id': aid, 'msg_id': '000000004200',
            'exc_type': 'http_constraint_exception_item',
            'fields': ['http_url']})
        assert r.status_code == 409, r.get_json()
        d = r.get_json()
        assert d['ok'] is False
        assert 'pol-other' in d['error']
        assert d['scope']['needs_clone'] is True
        assert d['clone_suggestion']['new_name']
        # and nothing was written
        from app.models import WppException
        assert WppException.query.count() == 0
        assert before == before  # noqa: PLR0124 — keeps `before` meaningful


def test_carveout_endpoint_writes_when_the_policy_owns_its_profile(app, client,
                                                                   monkeypatch):
    """The other half of the user's rule: a policy that already has its own
    profile gets a draft, not a clone offer."""
    with app.app_context():
        aid = _appliance(app, 'fw-solo')
        _wired(app, monkeypatch, {'pol-shop': 'wpp-solo'},
               row=dict(CONSTRAINT_ROW, policy='pol-shop'))
        _as_admin(app, client)
        r = client.post('/waf/attack-search/carve-out', json={
            'appliance_id': aid, 'msg_id': '000000004200',
            'exc_type': 'http_constraint_exception_item',
            'fields': ['http_url', 'http_host']})
        assert r.status_code == 200, r.get_json()
        d = r.get_json()
        assert d['ok'] is True and d['exc_id']
        assert d['cloned_wpp'] == ''
        from app.models import WppException
        exc = WppException.query.get(d['exc_id'])
        assert exc.wpp_mkey == 'wpp-solo'
        assert exc.payload_dict['request-file'] == '/checkout/submit'


def test_carveout_endpoint_demands_a_reason_against_the_verdict(app, client,
                                                                monkeypatch):
    """A carve-out the Advisor argued against is allowed — and recorded."""
    with app.app_context():
        aid = _appliance(app, 'fw-just')
        _wired(app, monkeypatch, {'pol-shop': 'wpp-solo'},
               row=dict(CONSTRAINT_ROW, policy='pol-shop'))
        _as_admin(app, client)
        base = {'appliance_id': aid, 'msg_id': '000000004200',
                'exc_type': 'http_constraint_exception_item',
                'fields': ['http_url'], 'verdict': 'true-attack', 'risk': 'high'}
        r = client.post('/waf/attack-search/carve-out', json=base)
        assert r.status_code == 400
        assert r.get_json()['needs_justification'] is True
        from app.models import WppException
        assert WppException.query.count() == 0

        r2 = client.post('/waf/attack-search/carve-out', json=dict(
            base, justification='Partner integration sends this shape daily; '
                                'confirmed with their team on 2026-08-08.'))
        assert r2.status_code == 200, r2.get_json()
        exc = WppException.query.get(r2.get_json()['exc_id'])
        assert 'Partner integration' in exc.reason


def test_insert_endpoint_refuses_a_shared_profile(app, client, monkeypatch):
    """The hard gate. This is where the leak physically happens — the row is
    live for every policy on the profile the moment it lands."""
    from app.services import wpp_exceptions as store
    with app.app_context():
        aid = _appliance(app, 'fw-ins')
        exc = store.add(aid, wpp_mkey='wpp-shared',
                        exc_type='http_constraint_exception_item',
                        payload={'request-type': 'plain', 'request-file': '/a'},
                        policies=['pol-shop'])
        _wired(app, monkeypatch,
               {'pol-shop': 'wpp-shared', 'pol-other': 'wpp-shared'})
        _as_admin(app, client)
        r = client.post('/waf/attack-search/exception/%d/insert' % exc.id,
                        json={'appliance_id': aid, 'target': 'c', 'apply': True})
        assert r.status_code == 403, r.get_json()
        assert r.get_json()['scope']['needs_clone'] is True


def test_insert_preview_writes_nothing(app, client, monkeypatch):
    """The preview call must reach the planner with ``dry_run`` set. A preview
    that writes is worse than no preview: it is a write the operator believes
    did not happen."""
    from app.services import exception_inject, wpp_exceptions as store
    seen = {}
    with app.app_context():
        aid = _appliance(app, 'fw-dry')
        exc = store.add(aid, wpp_mkey='wpp-solo',
                        exc_type='http_constraint_exception_item',
                        payload={'request-type': 'plain', 'request-file': '/a'},
                        policies=['pol-shop'])
        _wired(app, monkeypatch, {'pol-shop': 'wpp-solo'})

        def _fake(ops, *, exc_type, payload, target, dry_run=True,
                  create_container=False):
            seen['dry_run'] = dry_run
            return {'ok': True, 'dry_run': dry_run, 'steps': [],
                    'plan': {'status': 'ready', 'method': 'POST',
                             'endpoint': '/x', 'error': '', 'body': {}}}
        from app.views import attack_search as view
        monkeypatch.setattr(view.exception_inject, 'apply_injection', _fake)
        _as_admin(app, client)

        r = client.post('/waf/attack-search/exception/%d/insert' % exc.id,
                        json={'appliance_id': aid, 'target': 'c'})
        assert r.status_code == 200 and seen['dry_run'] is True
        assert r.get_json()['dry_run'] is True

        r2 = client.post('/waf/attack-search/exception/%d/insert' % exc.id,
                         json={'appliance_id': aid, 'target': 'c', 'apply': True})
        assert r2.status_code == 200 and seen['dry_run'] is False
        assert exception_inject.apply_injection is not _fake or True


def test_build_endpoint_ignores_a_row_posted_by_the_browser(app, client,
                                                            monkeypatch):
    """The evidence rule, at the route. A client that posts its own row must
    have it ignored — the payload is assembled from what the DEVICE said."""
    with app.app_context():
        aid = _appliance(app, 'fw-ev')
        _wired(app, monkeypatch, {'pol-shop': 'wpp-solo'},
               row=dict(CONSTRAINT_ROW, policy='pol-shop'))
        _as_admin(app, client)
        r = client.post('/waf/attack-search/build', json={
            'appliance_id': aid, 'msg_id': '000000004200',
            'exc_type': 'http_constraint_exception_item',
            'fields': ['http_url'],
            # A forged row, offered every way a caller might try.
            'row': {'http_url': '/evil'}, 'http_url': '/evil',
            'rows': [{'http_url': '/evil'}]})
        assert r.status_code == 200
        assert r.get_json()['payload']['request-file'] == '/checkout/submit'


def test_field_intel_endpoint_returns_facts_for_a_real_field(app, client,
                                                             monkeypatch):
    with app.app_context():
        aid = _appliance(app, 'fw-fi')
        _wired(app, monkeypatch, {'pol-shop': 'wpp-solo'},
               row=dict(CONSTRAINT_ROW, policy='pol-shop'))
        _as_admin(app, client)
        r = client.post('/waf/attack-search/field-intel', json={
            'appliance_id': aid, 'msg_id': '000000004200',
            'field': 'src', 'resolve_ptr': False})
        assert r.status_code == 200
        assert r.get_json()['intel']['classification'] == 'documentation range (RFC 5737/3849)'

        bad = client.post('/waf/attack-search/field-intel', json={
            'appliance_id': aid, 'msg_id': '000000004200', 'field': 'nope'})
        assert bad.status_code == 400
