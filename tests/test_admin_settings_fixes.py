"""Administration fixes from the Documentation Center audit, 2026-10-03
(AD-21, AD-22, AD-23, AD-27, AD-52, AD-54, AD-55, AD-59)."""
from __future__ import annotations

import io
import json

import pytest

from conftest import admin_user_id, login


# AD-21 ---------------------------------------------------------------------
def test_hour_thresholds_saved_as_floats_are_honoured(app):
    from app.models import AppSetting
    from app.services import alerts
    with app.app_context():
        AppSetting.set(alerts.K_BACKUP_MAX_H, "12.0")
        AppSetting.set(alerts.K_COOLDOWN_H, "3.0")
        cfg = alerts.config()
        assert cfg["backup_max_hours"] == 12
        assert cfg["cooldown_hours"] == 3
        AppSetting.set(alerts.K_BACKUP_MAX_H, "junk")
        assert alerts.config()["backup_max_hours"] == 48     # fallback still works


# AD-22 ---------------------------------------------------------------------
class _SMTP:
    sent = []

    def __init__(self, *a, **k):
        pass

    def ehlo(self): pass
    def starttls(self, *a, **k): pass
    def login(self, *a, **k): pass

    def send_message(self, msg, *a, **k):
        _SMTP.sent.append(msg["To"])

    def quit(self): pass
    def close(self): pass


def _email(app, enabled):
    from app.services import email_service as es
    with app.app_context():
        es.save_config({"enabled": "on" if enabled else "", "mode": "smtp",
                        "host": "smtp.example.com", "security": "none",
                        "from_addr": "ops@example.com"})


def test_disabled_email_sends_nothing_but_the_test_button_still_works(app, monkeypatch):
    from app.services import email_service as es
    monkeypatch.setattr(es.smtplib, "SMTP", _SMTP)
    _SMTP.sent = []
    _email(app, enabled=False)
    with app.app_context():
        r = es.send_email("a@example.com", "s", "b")
        assert r["ok"] is False and "disabled" in r["detail"]
        assert _SMTP.sent == []
        assert es.send_test("t@example.com")["ok"] is True      # explicit test
        assert _SMTP.sent == ["t@example.com"]
    _email(app, enabled=True)
    with app.app_context():
        assert es.send_email("a@example.com", "s", "b")["ok"] is True
    assert _SMTP.sent[-1] == "a@example.com"


# AD-23 ---------------------------------------------------------------------
def test_adom_delete_confirm_is_not_an_inline_handler(app, client):
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert "onsubmit=\"return confirm('Delete ADOM" not in html
    tpl = open("app/templates/settings/index.html", encoding="utf-8").read()
    assert 'data-fw-confirm-form="Delete ADOM {{ a.key }}?' in tpl


# AD-27 ---------------------------------------------------------------------
def test_acme_issuance_does_not_require_an_adcs_template(app, monkeypatch):
    from app.services import cert_manager as cm, settings_store as store

    def _boom(*a, **k):
        raise RuntimeError("reached CSR generation")
    monkeypatch.setattr(cm, "generate_csr", _boom)
    monkeypatch.setattr(store, "cert_class_config", lambda c: {"template": ""})
    with app.app_context():
        monkeypatch.setattr(store, "cert_manager_protocol", lambda: "adcs")
        r = cm.create_certificate(None, "www.example.com", "server")
        assert "ADCS template" in r["error"]
        monkeypatch.setattr(store, "cert_manager_protocol", lambda: "acme")
        r = cm.create_certificate(None, "www.example.com", "server")
        assert "reached CSR generation" in r["error"], r


# AD-52 ---------------------------------------------------------------------
def test_importing_the_same_theme_three_times_never_500s(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    payload = json.dumps({"schema": "satom.ui-theme/1", "name": "Ocean", "tokens": {}})
    for _ in range(3):
        r = client.post("/settings/appearance/import",
                        data={"themefile": (io.BytesIO(payload.encode()), "ocean.json")},
                        content_type="multipart/form-data")
        assert r.status_code == 302
    with app.app_context():
        names = sorted(t.name for t in UiTheme.query.filter(UiTheme.name.like("Ocean%")).all())
    assert names == ["Ocean", "Ocean (imported 2)", "Ocean (imported)"], names


# AD-54 ---------------------------------------------------------------------
def test_builtin_report_offers_clone_not_edit(app, client):
    from app.extensions import db
    from app.models import DbReport
    with app.app_context():
        b = DbReport(name="Builtin X", builtin=True, created_by="seed",
                     definition='{"widgets": []}')
        db.session.add(b)
        db.session.commit()
        bid = b.id
        u = DbReport(name="Mine", builtin=False, created_by="admin",
                     definition='{"widgets": []}')
        db.session.add(u)
        db.session.commit()
        uid = u.id
    login(client, admin_user_id(app))
    html = client.get(f"/database/reports/{bid}").get_data(as_text=True)
    assert f"/database/reports/{bid}/edit" not in html
    assert f"/database/reports/{bid}/clone" in html
    html = client.get(f"/database/reports/{uid}").get_data(as_text=True)
    assert f"/database/reports/{uid}/edit" in html


# AD-55 / AD-59 (front-end only: asserted on the shipped script) ------------
def test_sql_csv_export_fills_the_query_on_submit():
    tpl = open("app/templates/database/index.html", encoding="utf-8").read()
    i = tpl.index("getElementById('sql-csv-form').addEventListener('submit'")
    assert "sql-csv-field').value=input.value" in tpl[i:i + 300]


def test_faz_menu_group_reenable_rechecks_its_items():
    tpl = open("app/templates/settings/index.html", encoding="utf-8").read()
    i = tpl.index("function recheck(g)")
    assert "kids[i].checked = true" in tpl[i:i + 400]
    assert "recheck(g); sync(g);" in tpl
