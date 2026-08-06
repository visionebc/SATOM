"""Product (ADOM) separation guards.

Two contracts, locked so they can't drift:

1. IMPORT DIRECTION — the ADC side is a self-contained module: ADC code
   imports only the platform layer (auth, extensions, models, registry,
   device_context, audit), NEVER FortiWeb business modules — and no FortiWeb
   business module imports ADC code. The only legitimate meeting points are
   the whitelisted platform dispatchers (app factory, registry loader,
   cert-manager dispatch, the product switcher).

2. PRODUCT SCOPING — jobs / audit rows / notifications carry the product of
   the ADOM that created them; a fortiadc session never sees FortiWeb
   records and vice versa; the global ADOM sees everything.
"""
from __future__ import annotations

import ast
import pathlib

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app"

ADC_MODULES = [
    "views/adc.py",
    "views/adc_api.py",
    "services/adc_menu.py",
    "services/adc_ops.py",
    "services/adc_objform.py",
    "services/cert_adc.py",
    "clients/fortiadc.py",
]

# FortiWeb business modules the ADC side must never import.
FORTIWEB_ONLY_TOKENS = (
    "clients.fortiweb", "fortiweb_ops", "wp_menu", "waf_specs", "wpp_",
    "workspace", "objedit", "signature_catalog", "policy_ops", "read_layer",
)

# ADC module names no FortiWeb/business module may import.
ADC_TOKENS = ("fortiadc", "adc_menu", "adc_objform", "cert_adc")

# Platform layer — the ONLY files allowed to import both sides.
PLATFORM_WHITELIST = {
    "app/__init__.py",
    "app/models.py",
    "app/registry/loader.py",
    "app/services/cert_manager.py",
    "app/views/cert_manager.py",
    "app/views/product.py",
    "app/services/product_scope.py",
    "app/clients/__init__.py",
    # The collector engine is fleet-wide by construction: COLLECTORS declares
    # which products each collector serves and _RUNNERS dispatches by
    # appliance.kind. It already imports the FortiWeb and FortiAuthenticator
    # clients for the same reason. Keeping it out of the whitelist would force
    # a per-product copy of the sweep, which is the shape this file exists to
    # prevent in the other direction.
    "app/services/metrics_collect.py",
}


def _imported(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            mods.append(base)
            mods.extend(f"{base}.{a.name}" for a in node.names)
    return mods


def test_adc_imports_only_platform():
    offending = []
    for rel in ADC_MODULES:
        for mod in _imported(APP / rel):
            if any(tok in mod for tok in FORTIWEB_ONLY_TOKENS):
                offending.append(f"{rel} imports {mod}")
    assert not offending, (
        "ADC modules must not import FortiWeb business code:\n"
        + "\n".join(offending))


def test_fortiweb_never_imports_adc():
    adc_paths = {str(APP / rel) for rel in ADC_MODULES}
    offending = []
    for path in APP.rglob("*.py"):
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        if str(path) in adc_paths or rel in PLATFORM_WHITELIST:
            continue
        for mod in _imported(path):
            if any(tok in mod for tok in ADC_TOKENS):
                offending.append(f"{rel} imports {mod}")
    assert not offending, (
        "Only the platform whitelist may import ADC modules:\n"
        + "\n".join(offending))


# --------------------------------------------------------------------------
# 2. Product scoping
# --------------------------------------------------------------------------

def test_visible_product_unscoped_context():
    # No request context (a worker thread) -> everything is visible.
    from app.services.product_scope import visible_product
    assert visible_product("fortiweb")
    assert visible_product("fortiadc")
    assert visible_product("")
    assert visible_product(None)


def test_create_job_stamps_session_product(app, monkeypatch, tmp_path):
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "_state_dir", lambda: tmp_path)
    with app.test_request_context():
        from flask import session
        session["product"] = "fortiadc"
        j = jobsvc.create_job("demo", "adc job")
    assert j["meta"]["product"] == "fortiadc"
    # Worker thread (no request context) -> unscoped.
    j2 = jobsvc.create_job("demo", "worker job")
    assert j2["meta"]["product"] == ""
    # An explicit product in meta is never overwritten.
    j3 = jobsvc.create_job("demo", "explicit", meta={"product": "fortiweb"})
    assert j3["meta"]["product"] == "fortiweb"


def test_jobs_feed_scoped_by_adom(app, client, monkeypatch, tmp_path):
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "_state_dir", lambda: tmp_path)
    jobsvc.create_job("demo", "web job", by="x", meta={"product": "fortiweb"})
    jobsvc.create_job("demo", "adc job", by="x", meta={"product": "fortiadc"})
    jobsvc.create_job("demo", "legacy job", by="x")  # unscoped
    uid = admin_user_id(app)

    def titles(product):
        login(client, uid, product=product)
        r = client.get("/jobs/all")
        assert r.status_code == 200
        return {j["title"] for j in r.get_json()["jobs"]}

    assert titles("fortiadc") == {"adc job"}
    assert titles("fortiweb") == {"web job", "legacy job"}
    assert titles("global") == {"web job", "adc job", "legacy job"}


def test_audit_rows_scoped_by_adom(app):
    from flask import session

    from app.models import AuditLog
    from app.services.audit import log_action
    from app.services.product_scope import scope_query

    with app.test_request_context():
        session["product"] = "fortiadc"
        log_action("adc.action")
        session["product"] = "fortiweb"
        log_action("web.action")

        def acts():
            return {r.action for r in
                    scope_query(AuditLog.query, AuditLog.product).all()}

        session["product"] = "fortiadc"
        assert acts() == {"adc.action"}
        session["product"] = "fortiweb"
        assert "web.action" in acts() and "adc.action" not in acts()
        session["product"] = "global"
        assert {"adc.action", "web.action"} <= acts()


def test_notifications_scoped_by_adom(app):
    from flask import session

    from app.services import notifications as notify

    uid = admin_user_id(app)
    with app.test_request_context():
        session["product"] = "fortiadc"
        assert notify.push(uid, "adc note") is not None
        session["product"] = "fortiweb"
        assert notify.push(uid, "web note") is not None

        session["product"] = "fortiadc"
        assert notify.unread_count(uid) == 1
        assert {n.title for n in notify.recent(uid)} == {"adc note"}
        session["product"] = "fortiweb"
        assert notify.unread_count(uid) == 1
        assert {n.title for n in notify.recent(uid)} == {"web note"}
        session["product"] = "global"
        assert notify.unread_count(uid) == 2

        # mark_all_read in one ADOM must not touch the other's rows.
        session["product"] = "fortiadc"
        assert notify.mark_all_read(uid) == 1
        session["product"] = "global"
        assert notify.unread_count(uid) == 1  # the web note survives


def test_new_records_default_to_fortiweb_product(app):
    from app.models import Baseline, ScheduledAction, Template
    from app.extensions import db

    with app.app_context():
        t = Template(kind="server-policy", name="psep-t", version=1, body="{}")
        b = Baseline(name="psep-b")
        a = ScheduledAction(name="psep-a", action="backup")
        db.session.add_all([t, b, a])
        db.session.commit()
        assert t.product == "fortiweb"
        assert b.product == "fortiweb"
        assert a.product == "fortiweb"
