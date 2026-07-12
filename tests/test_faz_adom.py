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
    for label in ('Configuration', 'Operation', 'Automation',
                  'Architecture', 'Analysis', 'Metrics'):
        assert label in body, f'dashboard missing {label}'
    # a scaffold leaf renders and is honest about the missing backend
    r = client.get('/faz/m/system-global')
    assert r.status_code == 200
    assert 'Not wired to a FortiAnalyzer backend yet' in r.get_data(as_text=True)


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
