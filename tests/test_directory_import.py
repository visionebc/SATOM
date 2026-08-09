"""Directory import (FortiAuthenticator roster) + approval gate + login-page limiter.

Three things are guarded here, and each one failed in the field before it was
guarded:

1. **The login page was rate-limited as if it were a login attempt.** Five GETs
   a minute — a logout redirect plus a couple of reloads — and the operator got
   ``429 Too Many Requests`` on the *form*, having submitted no credential.
2. **``next=/auth/logout``.** Hitting logout with a dead session redirects to
   ``/auth/login?next=/auth/logout``; honouring that ``next`` signs you out the
   instant you sign in.
3. **You cannot enumerate RADIUS.** The roster has to come from the FAC's REST
   API, and on that firmware ``/localusers/`` under-reports — the memberships
   resource is the authoritative one.
"""
from __future__ import annotations

import pytest

from tests.conftest import _TestConfig, admin_user_id, login, make_user


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class FakeFacClient:
    """Mimics FortiAuthenticatorClient.list_path_with_error → (rows, error).

    Modelled on the REAL shapes measured against fac01 v8.0.3: the memberships
    resource carries ``username`` for members that ``/localusers/`` omits.
    """

    def __init__(self, memberships=None, localusers=None, groups=None,
                 error_for=None):
        self.memberships = memberships if memberships is not None else []
        self.localusers = localusers if localusers is not None else []
        self.groups = groups if groups is not None else []
        self.error_for = error_for or {}
        self.calls = []

    def list_path_with_error(self, path, **params):
        self.calls.append(path)
        if path in self.error_for:
            return [], self.error_for[path]
        if 'memberships' in path:
            return list(self.memberships), None
        if 'localusers' in path:
            return list(self.localusers), None
        if 'usergroups' in path:
            return list(self.groups), None
        return [], f'unexpected path {path}'


def _fac_fixture():
    """fweb_users has TWO members; /localusers/ only admits to one of them."""
    return FakeFacClient(
        memberships=[
            {'group_name': 'fweb_users', 'username': 'wafuser1'},
            {'group_name': 'fweb_users', 'username': 'ebc'},
            {'group_name': 'other_grp', 'username': 'someoneelse'},
        ],
        localusers=[{'username': 'wafuser1', 'display_name': 'WAF Test'}],
        groups=[{'name': 'fweb_users'}, {'name': 'other_grp'}],
    )


def _rl_app(tmp_path):
    """A real app with the limiter ENABLED (the shared fixture disables it)."""
    import os
    uri = f"sqlite:///{tmp_path}/rl.db"
    os.environ["SQLALCHEMY_DATABASE_URI"] = uri

    class _Cfg(_TestConfig):
        SQLALCHEMY_DATABASE_URI = uri
        RATELIMIT_ENABLED = True
        RATELIMIT_STORAGE_URI = "memory://"

    from app import create_app
    from app.extensions import db, limiter

    application = create_app(_Cfg)
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    limiter.enabled = True
    with application.app_context():
        try:
            limiter.reset()
        except Exception:  # noqa: BLE001 — storage without reset()
            pass
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()
    limiter.enabled = False


@pytest.fixture()
def rl_app(tmp_path):
    yield from _rl_app(tmp_path)


# ---------------------------------------------------------------------------
# 1. the login PAGE is not a login ATTEMPT
# ---------------------------------------------------------------------------
def test_login_page_survives_many_views(rl_app):
    """Ten renders of the form must not lock the operator out of the form."""
    c = rl_app.test_client()
    codes = [c.get('/auth/login').status_code for _ in range(10)]
    assert codes == [200] * 10, codes


def test_login_post_is_still_rate_limited(rl_app):
    """The credential-carrying verb keeps its 5/minute guard."""
    c = rl_app.test_client()
    codes = [c.post('/auth/login', data={'username': 'nobody', 'password': 'x'},
                    follow_redirects=False).status_code for _ in range(8)]
    assert 429 in codes, codes
    assert codes.count(429) >= 2, codes
    # ...and a page view is still served while POSTs are being refused: the
    # user must be able to SEE the form that is telling them to slow down.
    assert c.get('/auth/login').status_code == 200


def test_get_flood_does_not_consume_the_post_budget(rl_app):
    """The regression proper: browsing the page must leave the POST budget whole."""
    c = rl_app.test_client()
    for _ in range(10):
        c.get('/auth/login')
    first = c.post('/auth/login', data={'username': 'nobody', 'password': 'x'})
    assert first.status_code != 429


# ---------------------------------------------------------------------------
# 2. next= must never point back at logout
# ---------------------------------------------------------------------------
def test_next_logout_is_refused(app, client):
    uid = make_user(app, 'nextvictim', role='admin')
    with app.app_context():
        from app.extensions import db
        from app.models import User
        User.query.get(uid).set_password('pw123456')
        db.session.commit()
    resp = client.post('/auth/login',
                       data={'username': 'nextvictim', 'password': 'pw123456',
                             'next': '/auth/logout'})
    assert resp.status_code == 302
    assert '/auth/logout' not in resp.headers['Location']


def test_ordinary_next_still_honoured(app, client):
    uid = make_user(app, 'nextok', role='admin')
    with app.app_context():
        from app.extensions import db
        from app.models import User
        User.query.get(uid).set_password('pw123456')
        db.session.commit()
    resp = client.post('/auth/login',
                       data={'username': 'nextok', 'password': 'pw123456',
                             'next': '/appliances'})
    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/appliances')


# ---------------------------------------------------------------------------
# 3. pending != disabled
# ---------------------------------------------------------------------------
def test_is_pending_approval_distinguishes_states(app):
    from datetime import datetime
    from app.extensions import db
    from app.models import User
    with app.app_context():
        imported = User(username='imported', auth_source='radius', is_active=False)
        imported.set_password('x')
        revoked = User(username='revoked', auth_source='radius', is_active=False,
                       last_login=datetime.utcnow())
        revoked.set_password('x')
        local_off = User(username='localoff', auth_source='local', is_active=False)
        local_off.set_password('x')
        db.session.add_all([imported, revoked, local_off])
        db.session.commit()
        assert imported.is_pending_approval is True
        assert revoked.is_pending_approval is False      # was used, then revoked
        assert local_off.is_pending_approval is False    # local accounts aren't imported


def test_gate_creates_disabled_users(app):
    from app.models import AppSetting
    from app.services import auth_store
    with app.app_context():
        AppSetting.set('auth.require_approval', '1')
        u = auth_store.provision_external_user('gated', 'radius')
        assert u.is_active is False
        assert u.is_pending_approval is True


def test_gate_off_creates_active_users(app):
    from app.models import AppSetting
    from app.services import auth_store
    with app.app_context():
        AppSetting.set('auth.require_approval', '0')
        u = auth_store.provision_external_user('ungated', 'radius')
        assert u.is_active is True


def test_gate_never_touches_an_existing_account(app):
    """An admin-approved user must not be re-gated on their next sign-in."""
    from app.extensions import db
    from app.models import AppSetting, User
    from app.services import auth_store
    with app.app_context():
        existing = User(username='approved', auth_source='radius', is_active=True)
        existing.set_password('x')
        db.session.add(existing)
        db.session.commit()
        AppSetting.set('auth.require_approval', '1')
        u = auth_store.provision_external_user('approved', 'radius')
        assert u.is_active is True


def test_login_reports_pending_not_bad_password(app, client, monkeypatch):
    """The bind SUCCEEDED — blaming the password would send the user to reset
    a credential that was correct."""
    from app.models import AppSetting
    from app.services import auth_store
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        AppSetting.set('auth.radius.host', '192.0.2.19')
        AppSetting.set('auth.require_approval', '1')
    monkeypatch.setattr(auth_store, 'authenticate_external',
                        lambda u, p: {'ok': True, 'source': 'radius', 'detail': ''})
    resp = client.post('/auth/login', data={'username': 'freshguy', 'password': 'right'},
                       follow_redirects=True)
    body = resp.get_data(as_text=True)
    assert 'awaiting administrator approval' in body
    assert 'Invalid username or password' not in body
    with app.app_context():
        from app.models import User
        assert User.query.filter_by(username='freshguy').first().is_active is False


# ---------------------------------------------------------------------------
# 4. the FAC roster
# ---------------------------------------------------------------------------
def test_roster_includes_members_localusers_hides():
    from app.services import fac_directory
    ok, users = fac_directory.list_group_members(_fac_fixture(), 'fweb_users')
    assert ok is True
    names = [u['username'] for u in users]
    assert names == ['ebc', 'wafuser1']          # sorted, and 'ebc' is present
    assert 'someoneelse' not in names            # other group excluded


def test_roster_blank_group_unions_both_resources():
    from app.services import fac_directory
    ok, users = fac_directory.list_group_members(_fac_fixture(), '')
    assert ok is True
    assert {u['username'] for u in users} == {'ebc', 'wafuser1', 'someoneelse'}


def test_roster_unknown_group_is_an_error_not_an_empty_list():
    """Importing zero users and calling it success hides a typo forever."""
    from app.services import fac_directory
    ok, detail = fac_directory.list_group_members(_fac_fixture(), 'typo_grp')
    assert ok is False
    assert 'typo_grp' in detail and 'fweb_users' in detail


def test_roster_device_refusal_is_not_an_empty_group():
    from app.services import fac_directory
    client = FakeFacClient(error_for={'/api/v1/localgroup-memberships/': '403 forbidden'})
    ok, detail = fac_directory.list_group_members(client, 'fweb_users')
    assert ok is False
    assert '403' in detail


def test_roster_survives_a_localusers_refusal():
    """The enrichment call is allowed to fail; the roster stands on memberships."""
    from app.services import fac_directory
    client = _fac_fixture()
    client.error_for = {'/api/v1/localusers/': 'HTTP 500'}
    ok, users = fac_directory.list_group_members(client, 'fweb_users')
    assert ok is True
    assert {u['username'] for u in users} == {'ebc', 'wafuser1'}


# ---------------------------------------------------------------------------
# 5. wiring: radius backend + import
# ---------------------------------------------------------------------------
def _register_fac(app, name='fac01', kind='fortiauthenticator'):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name=name, host='192.0.2.19', kind=kind, username='admin',
                      port=443, verify_ssl=False)
        a.password = 'apikey'
        db.session.add(a)
        db.session.commit()
        return a.id


def test_radius_backend_no_longer_refuses_to_list(app, monkeypatch):
    from app.models import AppSetting
    from app.services import auth_store, fac_directory
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        AppSetting.set('auth.radius.sync_group', 'fweb_users')
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_fac_fixture(), ''))
        res = auth_store.list_directory_users()
        assert res['ok'] is True, res['detail']
        assert {u['username'] for u in res['users']} == {'ebc', 'wafuser1'}
        assert 'fweb_users' in res['detail']


def test_import_creates_pending_rows(app, monkeypatch):
    from app.models import AppSetting, User
    from app.services import auth_store
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        AppSetting.set('auth.radius.sync_group', 'fweb_users')
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_fac_fixture(), ''))
        res = auth_store.sync_directory_users(default_active=False)
        assert res['ok'] is True and res['created'] == 2
        for name in ('ebc', 'wafuser1'):
            u = User.query.filter_by(username=name).first()
            assert u is not None and u.is_active is False
            assert u.auth_source == 'radius'
            assert u.is_pending_approval is True
            # An imported row must not be usable as a LOCAL login.
            assert u.check_password('') is False


def test_import_is_idempotent_and_never_downgrades(app, monkeypatch):
    from app.extensions import db
    from app.models import AppSetting, User
    from app.services import auth_store
    _register_fac(app)
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        AppSetting.set('auth.radius.sync_group', 'fweb_users')
        monkeypatch.setattr(auth_store, 'fac_client', lambda: (_fac_fixture(), ''))
        auth_store.sync_directory_users(default_active=False)
        approved = User.query.filter_by(username='ebc').first()
        approved.is_active = True
        db.session.commit()
        res = auth_store.sync_directory_users(default_active=False)
        assert res['created'] == 0 and res['existing'] == 2
        assert User.query.filter_by(username='ebc').first().is_active is True


def test_no_fortiauthenticator_registered_says_so(app):
    from app.models import AppSetting
    from app.services import auth_store
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        res = auth_store.list_directory_users()
        assert res['ok'] is False
        assert 'FortiAuthenticator' in res['detail']


def test_two_facs_without_a_choice_refuse_rather_than_guess(app):
    from app.models import AppSetting
    from app.services import auth_store
    _register_fac(app, 'fac01')
    _register_fac(app, 'fac02')
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        client, detail = auth_store.fac_client()
        assert client is None
        assert 'fac01' in detail and 'fac02' in detail


def test_configured_appliance_must_be_a_fac(app):
    from app.models import AppSetting
    from app.services import auth_store
    wrong = _register_fac(app, 'fweb01', kind='fortiweb')
    with app.app_context():
        AppSetting.set('auth.backend', 'radius')
        AppSetting.set('auth.radius.sync_appliance_id', str(wrong))
        client, detail = auth_store.fac_client()
        assert client is None
        assert 'fortiweb' in detail


def test_settings_roundtrip_persists_the_new_fields(app):
    from app.services import auth_store
    with app.app_context():
        auth_store.save_config({
            'backend': 'radius', 'radius_host': '192.0.2.19',
            'radius_sync_group': 'fweb_users', 'radius_sync_appliance_id': '12',
            'require_approval': 'on',
        })
        cfg = auth_store.config()
        assert cfg['require_approval'] is True
        assert cfg['radius']['sync_group'] == 'fweb_users'
        assert cfg['radius']['sync_appliance_id'] == 12


def test_approval_gate_is_saved_from_the_ldap_half_too(app):
    """The gate is global; editing the LDAP form must not silently clear it."""
    from app.services import auth_store
    with app.app_context():
        auth_store.save_config({'backend': 'ldap', 'ldap_host': 'dc.example.com',
                                'require_approval': 'on'})
        assert auth_store.require_approval() is True
        auth_store.save_config({'backend': 'ldap', 'ldap_host': 'dc.example.com'})
        assert auth_store.require_approval() is False


def test_settings_page_renders_the_import_controls(app, client):
    login(client, admin_user_id(app))
    body = client.get('/settings/', follow_redirects=True).get_data(as_text=True)
    assert 'radius_group[]' in body
    assert 'radius_sync_appliance_id' in body
    assert 'require_approval' in body
