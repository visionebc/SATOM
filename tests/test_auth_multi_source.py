"""Multi-source sign-in + the removal of the per-username allowlist.

Two changes are guarded here, and each one has a failure mode that is SILENT:

1. **Several authentication sources at once.** The old model stored one string.
   Every widening of that shape can go wrong quietly — a chain that loses its
   order, a source that never gets tried, a corrupt row that reads as "local
   only" without saying so, a group list wiped by a form that never mentioned
   groups. None of those raise; they just authenticate the wrong set of people.

2. **The per-username allowlist is gone.** Removing a gate is exactly the class
   of change nothing fails on: the code path simply stops running. The guards
   below assert the gate is really gone AND that the leftover row is reported
   rather than obeyed — an install that relied on it just got wider.

Every assertion is behavioural. Nothing here matches on source text, so no
comment can satisfy it.
"""
from __future__ import annotations

import json

import pytest
from werkzeug.datastructures import MultiDict

from app.models import AppSetting
from app.services import auth_store
from app.services import settings_store as store

from tests.conftest import admin_user_id, login, make_user
from tests.test_directory_import import FakeFacClient, _fac_fixture, _register_fac


# ═══════════════════════════════════════════════════════════════════════════
# 1 — reading the enabled sources
# ═══════════════════════════════════════════════════════════════════════════
def test_a_legacy_single_backend_row_still_configures_a_source(app):
    """Upgrades must not silently lose the directory they were using."""
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        assert auth_store.backends() == ['radius']
        assert auth_store.backend() == 'radius'
        assert auth_store.is_enabled() is True


def test_the_new_list_wins_over_the_legacy_row_and_keeps_its_order(app):
    with app.app_context():
        AppSetting.set('auth.backend', 'ldap')          # stale mirror
        AppSetting.set('auth.backends', json.dumps(['radius', 'ad']))
        assert auth_store.backends() == ['radius', 'ad']
        assert auth_store.backend() == 'radius'


def test_unknown_and_duplicate_sources_are_dropped_not_tried(app):
    with app.app_context():
        AppSetting.set('auth.backends',
                       json.dumps(['radius', 'radius', 'local', 'kerberos', 'ad']))
        assert auth_store.backends() == ['radius', 'ad'], (
            "'local' is the always-on floor, not a source; an unknown name must "
            "never reach the dispatcher")


def test_a_corrupt_source_list_falls_closed_to_local_only(app):
    """A row nobody can parse must not authenticate anyone externally, and must
    not silently revive the legacy single value it replaced."""
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        AppSetting.set('auth.backends', '{"broken')
        assert auth_store.backends() == []
        assert auth_store.is_enabled() is False


def test_no_source_configured_reports_local(app):
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps([]))
        assert auth_store.backend() == 'local'
        assert auth_store.is_enabled() is False


# ═══════════════════════════════════════════════════════════════════════════
# 2 — saving the enabled sources
# ═══════════════════════════════════════════════════════════════════════════
def test_saving_several_sources_honours_the_submitted_order(app):
    form = MultiDict([('backends[]', 'ad'), ('backends[]', 'radius'),
                      ('backend_order_ad', '2'), ('backend_order_radius', '1'),
                      ('ldap_host', 'dc.example.com'), ('radius_host', '192.0.2.19')])
    with app.app_context():
        auth_store.save_config(form)
        assert auth_store.backends() == ['radius', 'ad']


def test_the_legacy_mirror_row_is_kept_in_sync_on_every_save(app):
    """A dump that shows two disagreeing rows is worse than one stale row."""
    with app.app_context():
        auth_store.save_config(MultiDict([('backends[]', 'radius')]))
        assert AppSetting.get('auth.backend') == 'radius'
        auth_store.save_config(MultiDict([]))
        assert AppSetting.get('auth.backend') == 'local'
        assert auth_store.backends() == []


def test_the_old_single_field_form_still_saves(app):
    """The previous form (and every caller written against it) keeps working."""
    with app.app_context():
        auth_store.save_config({'backend': 'ldap', 'ldap_host': 'dc.example.com'})
        assert auth_store.backends() == ['ldap']


# ═══════════════════════════════════════════════════════════════════════════
# 3 — sign-in walks the chain in order
# ═══════════════════════════════════════════════════════════════════════════
def test_sign_in_tries_sources_in_order_and_the_first_acceptance_wins(app, monkeypatch):
    tried = []

    def fake_bind(source, username, password):
        tried.append(source)
        return (source == 'radius'), f'{source} says so'

    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['ad', 'radius']))
        monkeypatch.setattr(auth_store, '_bind_one', fake_bind)
        res = auth_store.authenticate_external('someone', 'pw')
        assert res['ok'] is True
        assert res['source'] == 'radius', "the stamped source must be the one that accepted"
        assert tried == ['ad', 'radius'], "order is the configured order"


def test_a_source_after_the_winner_is_never_asked(app, monkeypatch):
    """Every extra bind is a wrong-password event on a directory that did not
    need to see it."""
    tried = []

    def fake_bind(source, username, password):
        tried.append(source)
        return True, 'ok'

    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['ad', 'ldap', 'radius']))
        monkeypatch.setattr(auth_store, '_bind_one', fake_bind)
        auth_store.authenticate_external('someone', 'pw')
        assert tried == ['ad']


def test_a_failed_chain_reports_every_reason(app, monkeypatch):
    """Three sources failing for three reasons is not one reason."""
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['ad', 'radius']))
        monkeypatch.setattr(auth_store, '_bind_one',
                            lambda s, u, p: (False, f'{s} was unreachable'))
        res = auth_store.authenticate_external('someone', 'pw')
        assert res['ok'] is False
        assert 'ad was unreachable' in res['detail']
        assert 'radius was unreachable' in res['detail']


def test_with_no_source_configured_the_dispatcher_says_so(app):
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps([]))
        res = auth_store.authenticate_external('someone', 'pw')
        assert res['ok'] is False and res['tried'] == []


# ═══════════════════════════════════════════════════════════════════════════
# 4 — group lists and per-group profiles
# ═══════════════════════════════════════════════════════════════════════════
def test_a_legacy_single_group_is_read_as_a_one_row_list(app):
    with app.app_context():
        AppSetting.set('auth.radius.sync_group', 'fweb_users')
        assert auth_store.sync_groups('radius') == [
            {'group': 'fweb_users', 'profile': ''}]
        assert auth_store.fac_sync_group() == 'fweb_users'


def test_group_rows_keep_order_and_drop_duplicates(app):
    with app.app_context():
        AppSetting.set('auth.radius.sync_groups', json.dumps([
            {'group': 'admins', 'profile': 'operator'},
            {'group': 'ADMINS', 'profile': 'readonly'},
            {'group': 'support', 'profile': ''}]))
        rows = auth_store.sync_groups('radius')
        assert [r['group'] for r in rows] == ['admins', 'support']
        assert rows[0]['profile'] == 'operator'


def test_saving_groups_needs_the_explicit_marker(app):
    """A form that never mentioned groups must LEAVE THEM ALONE. Treating "no
    rows posted" as "delete every row" would wipe the scope from any other form
    that posts the auth section."""
    with app.app_context():
        AppSetting.set('auth.radius.sync_groups',
                       json.dumps([{'group': 'fweb_users', 'profile': 'readonly'}]))
        auth_store.save_config(MultiDict([('backends[]', 'radius'),
                                          ('radius_host', '192.0.2.19')]))
        assert [r['group'] for r in auth_store.sync_groups('radius')] == ['fweb_users']


def test_clearing_every_row_is_a_real_instruction(app):
    with app.app_context():
        AppSetting.set('auth.radius.sync_groups',
                       json.dumps([{'group': 'fweb_users', 'profile': ''}]))
        auth_store.save_config(MultiDict([('backends[]', 'radius'),
                                          ('groups_submitted', '1')]))
        assert auth_store.sync_groups('radius') == []


def test_saving_group_rows_pairs_each_group_with_its_profile(app):
    form = MultiDict([('backends[]', 'radius'), ('groups_submitted', '1'),
                      ('radius_group[]', 'admins'), ('radius_group_profile[]', 'operator'),
                      ('radius_group[]', 'support'), ('radius_group_profile[]', '')])
    with app.app_context():
        auth_store.save_config(form)
        assert auth_store.sync_groups('radius') == [
            {'group': 'admins', 'profile': 'operator'},
            {'group': 'support', 'profile': ''}]


# ═══════════════════════════════════════════════════════════════════════════
# 5 — the importer applies the per-group profile
# ═══════════════════════════════════════════════════════════════════════════
def _two_group_fac():
    return FakeFacClient(
        memberships=[
            {'group_name': 'grp_ops', 'username': 'opsuser'},
            {'group_name': 'grp_ro', 'username': 'rouser'},
        ],
        localusers=[],
        groups=[{'name': 'grp_ops'}, {'name': 'grp_ro'}])


def test_each_group_imports_with_its_own_profile(app, monkeypatch):
    from app.models import User
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['radius']))
        AppSetting.set('auth.radius.sync_groups', json.dumps([
            {'group': 'grp_ops', 'profile': 'operator'},
            {'group': 'grp_ro', 'profile': ''}]))
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_two_group_fac(), ''))
        res = auth_store.sync_directory_users(default_active=False)
        assert res['ok'] is True and res['created'] == 2, res['detail']
        assert User.query.filter_by(username='opsuser').first().profile.name == 'operator'
        assert User.query.filter_by(username='rouser').first().profile.name == 'readonly', (
            "a blank per-group profile must inherit the GLOBAL default")


def test_an_unknown_group_profile_falls_back_down_never_up(app, monkeypatch):
    from app.models import User
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['radius']))
        AppSetting.set('auth.radius.sync_groups', json.dumps([
            {'group': 'grp_ops', 'profile': 'no-such-profile'}]))
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_two_group_fac(), ''))
        auth_store.sync_directory_users(default_active=False)
        assert User.query.filter_by(username='opsuser').first().profile.name == 'readonly'


def test_one_bad_group_name_fails_the_whole_import(app, monkeypatch):
    """A partial roster reported as success is how a typo becomes permanent."""
    from app.models import User
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['radius']))
        AppSetting.set('auth.radius.sync_groups', json.dumps([
            {'group': 'grp_ops', 'profile': 'operator'},
            {'group': 'typo_grp', 'profile': ''}]))
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_two_group_fac(), ''))
        res = auth_store.sync_directory_users(default_active=False)
        assert res['ok'] is False
        assert 'typo_grp' in res['detail']
        assert User.query.filter_by(username='opsuser').first() is None, (
            "nothing may be created when part of the scope could not be read")


def test_the_import_detail_still_names_the_groups_it_read(app, monkeypatch):
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['radius']))
        AppSetting.set('auth.radius.sync_group', 'fweb_users')
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_fac_fixture(), ''))
        res = auth_store.list_directory_users()
        assert res['ok'] is True
        assert 'fweb_users' in res['detail']


# ═══════════════════════════════════════════════════════════════════════════
# 6 — least privilege by default
# ═══════════════════════════════════════════════════════════════════════════
def test_the_shipped_default_profile_is_readonly(app):
    with app.app_context():
        assert auth_store.default_profile_name() == 'readonly'


def test_a_broken_global_default_profile_still_lands_on_readonly(app):
    """The LAST resort in the fallback chain, and the only case that reaches it.

    If the global default names a profile that does not exist — one typo in a
    text field — the floor has to be the profile that can change nothing.
    Reaching for a privileged one here would hand out admin on a spelling
    mistake, and nothing would report it.
    """
    with app.app_context():
        AppSetting.set('auth.default_profile', 'no-such-profile')
        user = auth_store.provision_external_user('typocase', 'radius')
        assert user.profile.name == 'readonly'


def test_a_just_in_time_user_gets_the_global_default(app):
    with app.app_context():
        AppSetting.set('auth.backends', json.dumps(['radius']))
        user = auth_store.provision_external_user('newcomer', 'radius')
        assert user.profile.name == 'readonly'


# ═══════════════════════════════════════════════════════════════════════════
# 7 — the removed allowlist
# ═══════════════════════════════════════════════════════════════════════════
def test_settings_store_no_longer_exposes_an_allowlist_reader(app):
    """If a reader comes back, so does the gate — by accident."""
    assert not hasattr(store, 'allowed_users')
    assert not hasattr(store, 'save_allowed_users')


def test_a_leftover_allowlist_row_no_longer_denies_anyone(app):
    uid = make_user(app, username='ro-user', role='readonly')
    c = app.test_client()
    login(c, uid)
    with app.app_context():
        store.set_json(store.K_ALLOWED_USERS_LEGACY, ['somebody-else'])
    assert c.get('/', follow_redirects=False).status_code != 403


def test_a_corrupt_leftover_allowlist_row_no_longer_stops_the_service(app):
    """It was policy input once; it is inert data now, and inert data must not
    be able to 503 the application."""
    uid = make_user(app, username='ro-user2', role='readonly')
    c = app.test_client()
    login(c, uid)
    with app.app_context():
        store.set_str(store.K_ALLOWED_USERS_LEGACY, '{"broken')
        assert store.access_config_error() == ''
    assert c.get('/', follow_redirects=False).status_code != 503


def test_the_leftover_row_is_still_visible_to_an_admin(app):
    with app.app_context():
        store.set_json(store.K_ALLOWED_USERS_LEGACY, ['alice', 'bob'])
        assert store.stale_allowed_users() == ['alice', 'bob']
        store.clear_stale_allowed_users()
        assert store.stale_allowed_users() == []


def test_the_ip_whitelist_survived_the_removal(app):
    """The other half of the same card must keep gating."""
    uid = make_user(app, username='ro-user3', role='readonly')
    c = app.test_client()
    login(c, uid)
    with app.app_context():
        store.save_ip_whitelist([{'ip': '203.0.113.0/24', 'note': 'elsewhere'}])
    # Loopback is exempt by design, so the request has to come from somewhere
    # else or this passes without the gate ever running.
    r = c.get('/', follow_redirects=False,
              environ_base={'REMOTE_ADDR': '198.51.100.7'})
    assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# 8 — the page an operator actually looks at
# ═══════════════════════════════════════════════════════════════════════════
@pytest.fixture()
def _admin_client(app):
    c = app.test_client()
    login(c, admin_user_id(app))
    return c


def test_the_settings_page_offers_every_source_and_group_rows(app, _admin_client):
    body = _admin_client.get('/settings/', follow_redirects=True).get_data(as_text=True)
    for token in ('backends[]', 'auth-src-ad', 'auth-src-ldap', 'auth-src-radius',
                  'backend_order_radius', 'radius_group[]', 'radius_group_profile[]',
                  'ldap_group[]', 'groups_submitted'):
        assert token in body, f'{token} missing from the settings page'


def test_the_settings_page_no_longer_renders_the_allowlist(app, _admin_client):
    body = _admin_client.get('/settings/', follow_redirects=True).get_data(as_text=True)
    assert 'allowed_users[]' not in body


def test_the_settings_page_warns_about_a_leftover_allowlist(app, _admin_client):
    with app.app_context():
        store.set_json(store.K_ALLOWED_USERS_LEGACY, ['alice'])
    body = _admin_client.get('/settings/', follow_redirects=True).get_data(as_text=True)
    assert 'no longer' in body.lower() and 'alice' in body


def test_an_admin_can_clear_the_leftover_allowlist(app, _admin_client):
    with app.app_context():
        store.set_json(store.K_ALLOWED_USERS_LEGACY, ['alice'])
    r = _admin_client.post('/settings/access/clear-legacy-allowlist',
                           follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert store.stale_allowed_users() == []
