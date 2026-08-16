"""The Classification page: the form contract, and the guarantee that it is
the ONLY way these catalogs get written.

The reference bookkeeping is guarded in ``test_classification_ops.py``. What
matters here is that the page actually reaches it: a row that loses its hidden
original turns every rename back into the orphaning delete the textarea did,
and it does so without a single test in that other file going red.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from app.extensions import db
from app.models import Appliance
from app.services import settings_store as store
from tests.conftest import admin_user_id, login, make_user, profile_id

REPO = Path(__file__).resolve().parents[1]


def _seed(app):
    with app.app_context():
        store.save_classification("zones", ["internal", "external"])
        store.save_classification("lines", ["A"])
        store.save_classification("departments", ["WAF/LB"])


def _appl(app, name, **kw):
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host="192.0.2.13", port=443,
                      username="admin", password_enc="x", verify_ssl=False, **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _admin(app, client):
    login(client, admin_user_id(app))


def _form(zones=(), lines=(("A", "A"),), departments=(("WAF/LB", "WAF/LB"),)):
    """Build the flat multi-value payload the page posts."""
    out = {}
    for kind, rows in (("zones", zones), ("lines", lines), ("departments", departments)):
        out[f"{kind}_orig[]"] = [r[0] for r in rows]
        out[f"{kind}_value[]"] = [r[1] for r in rows]
        out[f"{kind}_action[]"] = [r[2] if len(r) > 2 else "keep" for r in rows]
        out[f"{kind}_reassign[]"] = [r[3] if len(r) > 3 else "?" for r in rows]
    return out


# --------------------------------------------------------------------------- #
#  the form carries what the server needs to tell rename from delete           #
# --------------------------------------------------------------------------- #
def test_every_row_ships_its_original_value(app, client):
    """Without the hidden original the server sees a brand-new list and every
    rename degrades into delete-plus-add — silently, in the one code path this
    whole page exists to avoid."""
    _seed(app)
    _admin(app, client)
    html = client.get("/classification/").get_data(as_text=True)
    for kind in ("zones", "lines", "departments"):
        assert f'name="{kind}_orig[]"' in html
        assert f'name="{kind}_value[]"' in html
        assert f'name="{kind}_action[]"' in html
    assert 'value="internal"' in html


def test_the_page_shows_how_many_rows_reference_each_value(app, client):
    """A Remove button that cannot say '6 appliances' is a Remove button people
    press."""
    _seed(app)
    _appl(app, "a1", zone="internal")
    _admin(app, client)
    html = client.get("/classification/").get_data(as_text=True)
    row = html.split('value="internal"', 1)[1].split("</tr>", 1)[0]
    assert "1 appl" in row


def test_values_in_use_but_absent_from_the_catalog_are_surfaced(app, client):
    _seed(app)
    _appl(app, "a1", zone="dmz")
    _admin(app, client)
    html = client.get("/classification/").get_data(as_text=True)
    assert 'data-cls-adopt="dmz"' in html


def test_a_rename_posted_through_the_page_cascades(app, client):
    _seed(app)
    aid = _appl(app, "a1", zone="internal")
    _admin(app, client)
    res = client.post("/classification/save",
                      data=_form(zones=[("internal", "Internal"), ("external", "external")]),
                      follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        assert db.session.get(Appliance, aid).zone == "Internal"
        assert store.classification("zones") == ["Internal", "external"]


def test_a_refused_save_answers_400_and_changes_nothing(app, client):
    _seed(app)
    aid = _appl(app, "a1", zone="internal")
    _admin(app, client)
    res = client.post("/classification/save",
                      data=_form(zones=[("internal", "", "delete", "?"),
                                        ("external", "external")]))
    assert res.status_code == 400
    with app.app_context():
        assert db.session.get(Appliance, aid).zone == "internal"
        assert store.classification("zones") == ["internal", "external"]


def test_a_refused_save_hands_back_the_operator_s_own_rows(app, client):
    """Re-rendering the stored catalog would discard the very edits the
    operator was just told to correct."""
    _seed(app)
    _appl(app, "a1", zone="internal")
    _admin(app, client)
    html = client.post("/classification/save",
                       data=_form(zones=[("internal", "", "delete", "?"),
                                         ("external", "Perimeter")])
                       ).get_data(as_text=True)
    assert 'value="Perimeter"' in html, "the untouched-by-the-error edit was thrown away"
    assert 'data-deleted="1"' in html, "the row marked for removal came back alive"


def test_the_refusal_names_the_value_and_the_counts(app, client):
    _seed(app)
    _appl(app, "a1", zone="internal")
    _admin(app, client)
    html = client.post("/classification/save",
                       data=_form(zones=[("internal", "", "delete", "?"),
                                         ("external", "external")])
                       ).get_data(as_text=True)
    assert "internal" in html and "1 appliance" in html


def test_clear_and_undecided_are_different_tokens_in_the_form(app, client):
    """They both mean an empty target. If the page submits the same string for
    both, an untouched dropdown wipes references nobody agreed to wipe."""
    _seed(app)
    _admin(app, client)
    html = client.get("/classification/").get_data(as_text=True)
    assert 'value="?"' in html and 'value="__clear__"' in html


def test_a_clear_posted_through_the_page_unsets_the_references(app, client):
    _seed(app)
    aid = _appl(app, "a1", zone="internal")
    _admin(app, client)
    client.post("/classification/save",
                data=_form(zones=[("internal", "", "delete", "__clear__"),
                                  ("external", "external")]))
    with app.app_context():
        assert db.session.get(Appliance, aid).zone is None


# --------------------------------------------------------------------------- #
#  one writer                                                                  #
# --------------------------------------------------------------------------- #
def test_the_settings_console_no_longer_posts_catalogs(app, client):
    """It kept a live USER_MANAGE endpoint that wrote the catalogs with no
    reference handling at all — every guard above bypassed by one URL."""
    _seed(app)
    _admin(app, client)
    res = client.post("/settings/classification",
                      data={"zones": "only-this", "lines": "", "departments": ""})
    assert res.status_code in (404, 405)
    with app.app_context():
        assert store.classification("zones") == ["internal", "external"]


def test_classification_ops_is_the_only_caller_of_save_classification():
    """An AST walk, not a grep: a fifth view could reach the store through an
    alias or a different import spelling and a text search would miss it."""
    callers = set()
    for path in (REPO / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if name == "save_classification":
                    callers.add(str(path.relative_to(REPO)))
    assert callers == {"app/services/classification_ops.py"}, callers


def test_the_page_stays_admin_only(app, client):
    _seed(app)
    login(client, make_user(app, "bob", role="readonly",
                            profile_id=profile_id(app, "readonly")))
    assert client.get("/classification/").status_code in (302, 403)
    assert client.post("/classification/save", data=_form()).status_code in (302, 403)


# --------------------------------------------------------------------------- #
#  chrome                                                                      #
# --------------------------------------------------------------------------- #
def test_the_page_carries_no_dark_theme_leftovers(app, client):
    """SATOM is a light product: fw-card on #F4F5F7 with an orange accent. A
    slab of rgba(30,41,59,.8) here renders as an opaque grey card (safeguards
    §9m)."""
    _seed(app)
    _admin(app, client)
    html = client.get("/classification/").get_data(as_text=True)
    body = html.split("fw-page-header", 1)[1]
    for banned in ("#3b82f6", "#8b5cf6", "#080d1a", "backdrop-filter",
                   "rgba(30,41,59"):
        assert banned not in body, banned
