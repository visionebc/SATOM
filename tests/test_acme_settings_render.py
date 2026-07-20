"""The ACME / Let's Encrypt Settings UI renders and is driven by the catalog."""
from app.services import acme_providers, settings_store as store

from conftest import admin_user_id, login


def test_acme_cards_render_from_catalog(app, client):
    login(client, admin_user_id(app))
    r = client.get('/settings/')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'ACME / Let' in body                      # account card
    assert 'DNS provider credentials' in body        # per-provider creds card
    assert 'Add or edit a DNS provider' in body      # catalog editor
    assert 'acme-dns-provider' in body               # provider selector
    assert 'Cloudflare' in body                      # a seeded catalog row


def test_provider_secrets_never_reach_the_page(app, client):
    login(client, admin_user_id(app))
    with app.app_context():
        acme_providers.upsert('t-secret', {
            'label': 'T', 'flag': 'exec',
            'fields': '[{"env": "T_TOKEN", "secret": true, "required": true}]'})
        store.save_acme_provider_creds(
            't-secret', acme_providers.get('t-secret').field_list,
            {'T_TOKEN': 'NEVER-RENDER-ME'})
    body = client.get('/settings/').get_data(as_text=True)
    assert 'NEVER-RENDER-ME' not in body
    assert 'T_TOKEN' in body           # the field IS rendered, the value is not
