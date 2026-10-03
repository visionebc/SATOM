"""The Naming page renders inside every chrome.

It passed its product list to the template as ``products`` -- the same name
base.html reads for the ADOM registry (a mapping). In the Global ADOM the
sidebar iterates ``products.items()``, so the page answered 500 there.
"""
from tests.conftest import admin_user_id, login


def test_the_naming_page_renders_in_the_global_adom(app, client):
    login(client, admin_user_id(app), product="global")
    r = client.get("/naming/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'data-nav-group="ADOMs"' in html      # the sidebar that broke
    assert "FortiWeb" in html                     # the page's own product list


def test_the_naming_page_renders_in_the_fortiweb_adom(app, client):
    login(client, admin_user_id(app), product="fortiweb")
    assert client.get("/web/naming/").status_code == 200
