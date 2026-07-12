"""FortiAnalyzer ADOM — promotion + scope guards (regression lock).

FortiAnalyzer was promoted from a placeholder ADOM to a real one (its own
faz blueprint, static Configuration/Operation/Automation menu, and the shared
Fleet/Administration pages). These tests lock the contract so a future edit to
the branding fallback or the product gate can't silently revert it.
"""
from __future__ import annotations

from tests.conftest import admin_user_id, login


def test_branding_fortianalyzer_is_a_real_adom(app):
    from app.branding import get_product, products_with
    with app.app_context():
        p = get_product('fortianalyzer')
        assert p and not p.get('placeholder'), 'fortianalyzer must not be a placeholder'
        # caps that back Firmware / API tokens / banner picker
        assert 'fortianalyzer' in products_with('banner')
        assert 'fortianalyzer' in products_with('firmware')
        assert 'fortianalyzer' in products_with('tokens')
        # FortiAuthenticator keeps its banner (user profile requirement)
        assert 'fortiauthenticator' in products_with('banner')


def test_faz_dashboard_and_scaffolds_render(app, client):
    uid = admin_user_id(app)
    login(client, uid, product='fortianalyzer')
    r = client.get('/faz/')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    for label in ('Device Manager', 'Log View', 'Fabric View',
                  'System Settings', 'Architecture', 'Analysis', 'Metrics'):
        assert label in body, f'dashboard missing {label}'
    # a menu leaf renders; with no FAZ selected it asks for a device instead
    # of exploding (sections are LIVE, registry-bound — 2026-07-12)
    r = client.get('/faz/m/misc')
    assert r.status_code == 200
    assert 'No FortiAnalyzer selected' in r.get_data(as_text=True)


def test_faz_registry_seeded_and_api_explorer_renders(app, client):
    """The FortiAnalyzer endpoint registry seeds from
    endpoints_fortianalyzer.yaml (DB-first, product='fortianalyzer') and the
    JSON-RPC API explorer page renders with the catalog."""
    from app.registry import loader
    with app.app_context():
        reg = loader.load_faz_registry()
        assert reg.get('dvmdb_device') == '/dvmdb/device'
        assert reg.get('sys_status') == '/sys/status'
        # v3-family url present so the client's apiver-3 envelope is exercised
        assert (reg.get('report_layouts') or '').startswith('/report/')
    login(client, admin_user_id(app), product='fortianalyzer')
    r = client.get('/faz/api/')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'FortiAnalyzer API-Registry Explorer' in body
    assert '/dvmdb/device' in body


def test_faz_menu_unknown_item_404(app, client):
    login(client, admin_user_id(app), product='fortianalyzer')
    assert client.get('/faz/m/does-not-exist').status_code == 404


def test_faz_gate_allows_shared_admin_pages(app, client):
    """Fleet + Administration reuse shared blueprints; a FAZ session reaches
    them (200), it is not bounced to the dashboard."""
    login(client, admin_user_id(app), product='fortianalyzer')
    for url in ('/appliances/', '/audit/', '/architecture/', '/metrics/',
                '/web/firmware/', '/web/segments/', '/settings/', '/docs/'):
        assert client.get(url).status_code == 200, f'{url} should be reachable'


def test_faz_gate_blocks_fortiweb_only_pages(app, client):
    """A FortiWeb-only page is an ADOM mismatch in a FAZ session -> /faz/."""
    login(client, admin_user_id(app), product='fortianalyzer')
    r = client.get('/web/workspace/')
    assert r.status_code == 302 and r.headers['Location'].endswith('/faz/')


def test_profile_banner_picker_lists_faz_and_fauth(app, client):
    """The per-user top-bar banner picker (auth/profile) offers a banner for
    both FortiAnalyzer and FortiAuthenticator."""
    login(client, admin_user_id(app), product='global')
    r = client.get('/auth/profile')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'name="banner_fortianalyzer"' in body
    assert 'name="banner_fortiauthenticator"' in body


def test_enter_fortianalyzer_lands_on_faz(app, client):
    login(client, admin_user_id(app), product='global')
    r = client.get('/product/enter/fortianalyzer')
    assert r.status_code == 302 and r.headers['Location'].endswith('/faz/')


def _mk(app, name, kind):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind=kind, host=f'{name}.local',
                      port=443, username='admin', verify_ssl=False)
        a.password = 'secret'
        db.session.add(a); db.session.commit()
        return a.id


def test_appliance_kind_isolation_across_adoms(app):
    """A fortianalyzer box is visible ONLY in the FAZ ADOM — it must never
    leak into the FortiWeb or FortiADC appliance lists (regression for the
    'Kind' dropdown gaining FortiAnalyzer, 2026-07-12)."""
    from app.models import visible_appliances
    _mk(app, 'web-box', 'fortiweb')
    _mk(app, 'adc-box', 'fortiadc')
    _mk(app, 'faz-box', 'fortianalyzer')

    def kinds(product):
        with app.test_request_context(headers={'X-ADOM': product}):
            return {a.kind for a in visible_appliances().all()}

    assert kinds('fortianalyzer') == {'fortianalyzer'}
    assert 'fortianalyzer' not in kinds('fortiweb')
    assert 'fortianalyzer' not in kinds('fortiadc')
    assert kinds('fortiweb') == {'fortiweb'}          # FAZ+ADC excluded
    assert kinds('fortiadc') == {'fortiadc'}


def test_faz_write_endpoint_dry_run_and_guards(app, client):
    """The section-page write endpoint (/faz/write) builds the correct
    JSON-RPC request on a dry run, refuses operational/read-only panes, and
    enforces its mkey guards. Locks the CRUD contract added 2026-07-12 so the
    FAZ ADOM stays as create/edit-capable as the real 7.6.7 GUI."""
    faz_id = _mk(app, 'faz-write', 'fortianalyzer')
    login(client, admin_user_id(app), product='fortianalyzer')
    # select the FAZ as the session's active device (write context)
    assert client.get(f'/faz/use/{faz_id}').status_code == 302

    # create on a legacy /cli config table -> JSON-RPC 'add', mkey in body
    r = client.post('/faz/write/admin_user',
                    json={'op': 'create', 'mkey': 'qa-admin',
                          'fields': {'description': 'x'}})
    assert r.status_code == 200, r.get_data(as_text=True)
    j = r.get_json()
    assert j['ok'] and j['dry_run'] is True
    assert j['request']['method'] == 'add'
    assert j['request']['path'] == '/cli/global/system/admin/user'
    assert j['request']['body']['userid'] == 'qa-admin'

    # update addresses a legacy row path-style (.../<mkey>)
    r = client.post('/faz/write/admin_user',
                    json={'op': 'update', 'mkey': 'qa-admin',
                          'fields': {'description': 'y'}})
    assert r.get_json()['request']['path'] ==         '/cli/global/system/admin/user/qa-admin'

    # delete on a legacy row -> path-style, no body
    r = client.post('/faz/write/admin_user',
                    json={'op': 'delete', 'mkey': 'qa-admin'})
    jd = r.get_json()['request']
    assert jd['method'] == 'delete' and jd['path'].endswith('/qa-admin')

    # an operational / read-only pane is never writable
    r = client.post('/faz/write/dvmdb_device',
                    json={'op': 'create', 'mkey': 'x'})
    assert r.status_code == 400 and 'not writable' in r.get_json()['error']

    # guard: create without a name (mkey) is rejected
    assert client.post('/faz/write/admin_user',
                       json={'op': 'create'}).status_code == 400
