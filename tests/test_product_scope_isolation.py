"""An ADOM sees its OWN product and nothing else — for EVERY registered ADOM.

Adding FortiAuthenticator (2026-08-05) fired two latent bugs at once, neither
of which raised anything:

1. ``product_scope`` recognised a HARDCODED tuple of keys. ``fortiauthenticator``
   was not in it, so :func:`session_product` returned '' inside that ADOM and
   every filter became a no-op — the FAC ADOM listed all six appliances and all
   322 notifications.
2. the FortiWeb branch was an EXCLUSION (``kind NOT IN (fortiadc,
   fortianalyzer)``), so the new product's device showed up in the FortiWeb
   ADOM.

Both are structural: they recur for the NEXT product unless the key set is
derived from the ADOM registry and every filter names what it keeps. So these
tests parametrise over :func:`product_scope.product_keys` rather than over a
list written here — a product declared in the registry tomorrow is covered by
this file the same day, with no edit.
"""
from __future__ import annotations

import ast
import pathlib

import pytest
from flask import g

from app.models import Appliance, db
from app.services import product_scope as ps

REPO = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# the parametrisation itself must not silently become empty
# --------------------------------------------------------------------------

def test_the_registry_actually_yields_products(app):
    """Anti-vacuity. Every parametrised test below iterates concrete_products();
    if that ever returned an empty set they would all pass without asserting
    anything about anything."""
    with app.app_context():
        concrete = ps.concrete_products()
    assert len(concrete) >= 4, concrete
    assert "fortiweb" in concrete
    assert "fortiauthenticator" in concrete, (
        "the product whose absence caused the bug must be recognised")
    assert ps.GLOBAL not in concrete


def _concrete(app) -> list[str]:
    with app.app_context():
        return sorted(ps.concrete_products())


@pytest.fixture()
def fleet(app):
    """One appliance per registered product, plus one unscoped row.

    ``Appliance.kind`` is NOT NULL with a ``'fortiweb'`` default, so the row
    that predates product stamping is the EMPTY STRING, not NULL — the NULL
    branch in the filters is defence only."""
    ids = {}
    with app.app_context():
        for kind in sorted(ps.concrete_products()):
            a = Appliance(name=f"{kind}-box", host=f"{kind}.example.invalid",
                          kind=kind, username="admin")
            a.password = "pw"          # setter — password_enc is NOT NULL
            db.session.add(a)
            db.session.flush()
            ids[kind] = a.id
        legacy = Appliance(name="legacy-box", host="legacy.example.invalid",
                           kind="", username="admin")
        legacy.password = "pw"
        db.session.add(legacy)
        db.session.flush()
        ids["__legacy__"] = legacy.id
        db.session.commit()
    return ids


# --------------------------------------------------------------------------
# 1. appliances — inclusion, for every product
# --------------------------------------------------------------------------

def test_every_adom_sees_only_its_own_appliances(app, fleet):
    for product in _concrete(app):
        with app.test_request_context("/"):
            g.product = product
            q = ps.scope_appliance_query(Appliance.query, Appliance.kind)
            kinds = {a.kind for a in q.all()}
        expected = {product, ""} if product == ps.LEGACY_PRODUCT else {product}
        assert kinds == expected, (
            f"the {product} ADOM sees {sorted(k or '<unscoped>' for k in kinds)}; "
            f"an ADOM must never list another product's devices")


def test_global_sees_every_product(app, fleet):
    with app.test_request_context("/"):
        g.product = ps.GLOBAL
        n = ps.scope_appliance_query(Appliance.query, Appliance.kind).count()
    assert n == len(fleet), "the Global ADOM is the one place that sees all"


def test_only_fortiweb_owns_the_unscoped_rows(app, fleet):
    """NULL/'' predates stamping and is FortiWeb-era by construction. If any
    OTHER product inherited it, two ADOMs would claim the same rows."""
    owners = []
    for product in _concrete(app):
        with app.test_request_context("/"):
            g.product = product
            got = ps.scope_appliance_query(
                Appliance.query, Appliance.kind).filter(
                    Appliance.name == "legacy-box").count()
        if got:
            owners.append(product)
    assert owners == [ps.LEGACY_PRODUCT], owners


# --------------------------------------------------------------------------
# 2. product-stamped rows (scope_query) and the job store (visible_product)
# --------------------------------------------------------------------------

def test_scope_query_and_visible_product_agree_for_every_pair(app):
    """The SQL filter and the pure Python check are two implementations of one
    rule. They drifting apart is how a row hidden from a page stays visible in
    the job dock."""
    from app.models import User
    from app.models_notifications import Notification
    with app.app_context():
        u = User.query.first()
        if u is None:
            u = User(username="scopeuser", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        uid = u.id
        products = sorted(ps.concrete_products())
        for stamped in products + [""]:
            db.session.add(Notification(user_id=uid, kind="info", title="t",
                                        body="b", product=stamped))
        db.session.commit()

    for viewer in products:
        with app.test_request_context("/"):
            g.product = viewer
            rows = ps.scope_query(Notification.query,
                                  Notification.product).all()
            sql_visible = sorted({(r.product or "") for r in rows})
            pure_visible = sorted(
                {s for s in products + [""] if ps.visible_product(s)})
        assert sql_visible == pure_visible, (
            f"{viewer}: scope_query sees {sql_visible} but visible_product "
            f"says {pure_visible}")
        expected = ([viewer, ""] if viewer == ps.LEGACY_PRODUCT else [viewer])
        assert sql_visible == sorted(expected), (
            f"the {viewer} ADOM sees stamps {sql_visible}")


# --------------------------------------------------------------------------
# 3. the key set is DERIVED, and unknown keys never reach a filter
# --------------------------------------------------------------------------

def test_an_unregistered_session_key_is_not_honoured(app):
    """The session cookie used to be returned unvalidated. That is the exact
    path by which a key the filters did not understand reached them."""
    with app.test_request_context("/"):
        from flask import session
        session["product"] = "fortimadeup"
        g.product = None
        assert ps.session_product() == ""


def test_product_keys_include_inactive_adoms(app):
    """Deactivating an ADOM must not make its key unrecognised: an unrecognised
    key does not fail closed, it disables every filter for that session — the
    deactivated product's rows would become visible to everyone.

    Every shipped ADOM is active, so asserting over the registry as-found
    proves nothing. This test DEACTIVATES one and checks the key survives."""
    import app.branding as branding
    from app.models_adom import Adom

    with app.app_context():
        row = Adom.query.filter_by(key="fortiauthenticator").first()
        assert row is not None, "fixture ADOM missing"
        assert row.active, "precondition: it starts active"
        row.active = False
        db.session.commit()
        branding.invalidate()
        try:
            assert "fortiauthenticator" not in branding.PRODUCTS, (
                "precondition: PRODUCTS is active-only, so it is the WRONG "
                "source for the scoping key set")
            assert "fortiauthenticator" in ps.product_keys(), (
                "a deactivated ADOM lost its key — every filter now no-ops "
                "for a session still holding it")
        finally:
            row.active = True
            db.session.commit()
            branding.invalidate()


def test_registry_read_failure_falls_back_to_the_shipped_keys(app, monkeypatch):
    monkeypatch.setattr("app.branding.all_adoms",
                        lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    with app.app_context():
        keys = ps.product_keys()
    assert "fortiauthenticator" in keys and "fortiweb" in keys


# --------------------------------------------------------------------------
# 4. the callers must not re-declare the product list
# --------------------------------------------------------------------------

# Each of these had its OWN hardcoded product list and each one leaked when a
# product was added. Structural, not textual: a comment that mentions the old
# tuple must not satisfy the guard.
_MUST_DERIVE = [
    ("app/services/alerts.py", "_product_of"),
    ("app/views/cert_manager.py", "_product_kind"),
    ("app/services/plugin_sandbox.py", "_appliance_options"),
]


@pytest.mark.parametrize("relpath,func", _MUST_DERIVE)
def test_caller_derives_its_product_list(relpath, func):
    src = (REPO / relpath).read_text(encoding="utf-8")
    tree = ast.parse(src)
    node = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == func), None)
    assert node is not None, f"{func} not found in {relpath}"
    body = [n for n in node.body
            if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
    calls = {n.func.id for n in ast.walk(ast.Module(body=body, type_ignores=[]))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    names = {n.id for n in ast.walk(ast.Module(body=body, type_ignores=[]))
             if isinstance(n, ast.Name)}
    assert "concrete_products" in (calls | names), (
        f"{relpath}::{func} does not consult product_scope.concrete_products() "
        f"— a hardcoded product list there leaks the next ADOM")


def test_no_scoping_module_hardcodes_a_product_pair():
    """The literal pair ('fortiweb', 'fortiadc') as a MEMBERSHIP test is the
    shape that leaked three times. Comments are stripped by ast.parse, so this
    cannot be satisfied by prose."""
    offenders = []
    for rel in ("app/services/product_scope.py", "app/services/plugin_sandbox.py",
                "app/views/cert_manager.py", "app/services/alerts.py"):
        tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if not isinstance(n, ast.Compare):
                continue
            if not any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops):
                continue
            for cmp_ in n.comparators:
                if not isinstance(cmp_, (ast.Tuple, ast.List, ast.Set)):
                    continue
                vals = {e.value for e in cmp_.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if {"fortiweb", "fortiadc"} <= vals:
                    offenders.append(f"{rel}:{n.lineno}")
    assert not offenders, (
        "hardcoded product membership test(s): " + ", ".join(offenders))


# --------------------------------------------------------------------------
# 5. a device finding is stamped with the DEVICE's product, for every product
# --------------------------------------------------------------------------

def test_alerts_stamp_every_registered_kind(app):
    """An unrecognised kind stamps '' and an unscoped notification lands in the
    FortiWeb bell — that is how fadc and faz01 alerts became FortiWeb's, and it
    is what fortiauthenticator inherited."""
    from app.services.alerts import _product_of

    class _A:
        def __init__(self, kind):
            self.kind = kind

    with app.app_context():
        for kind in sorted(ps.concrete_products()):
            assert _product_of(_A(kind)) == kind, kind
        assert _product_of(_A("fortimadeup")) == ""
        assert _product_of(_A(None)) == ""


# --------------------------------------------------------------------------
# 6. Metrics must not print another product's inventory under its own labels
# --------------------------------------------------------------------------

def test_products_without_an_inventory_pipeline_report_none(app):
    """FortiAnalyzer and FortiAuthenticator have no config-object projection.
    The old ``else`` served FORTIWEB's totals beneath their labels — numbers
    that read as the ADOM's own."""
    from app.views.metrics import _INVENTORY_SNAPSHOT_PRODUCTS, INV_LABELS
    assert "fortiweb" in _INVENTORY_SNAPSHOT_PRODUCTS
    for p in ("fortianalyzer", "fortiauthenticator"):
        assert p not in _INVENTORY_SNAPSHOT_PRODUCTS, p
        assert p in INV_LABELS, f"{p} has no inventory labels of its own"
