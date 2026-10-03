"""Sentinel and Scout settings saves are admin-only, like their panes.

Documentation Center audit, 2026-10-03 (AD-19, MO-09, AD-46): the saves
accepted config_write (operator) while the panes are only shown to admins;
the Sentinel model endpoint and the seeded backup schedule name pointed at
internal hosts.
"""
from __future__ import annotations

from conftest import admin_user_id, login, make_user, profile_id


def _operator(app):
    return make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))


def test_operator_cannot_save_sentinel_settings(app, client):
    from app.services.sentinel import config as sn
    login(client, _operator(app))
    r = client.post("/settings/sentinel", data={"ai_model": "evil:1b"})
    assert r.status_code == 403
    with app.app_context():
        assert sn.get("ai_model") != "evil:1b"
    # positive control: an admin's save goes through
    login(client, admin_user_id(app))
    r = client.post("/settings/sentinel", data={"ai_model": "llama3:8b"})
    assert r.status_code == 302
    with app.app_context():
        assert sn.get("ai_model") == "llama3:8b"


def test_operator_cannot_switch_scout(app, client):
    from app.services import scout_config as sc
    login(client, _operator(app))
    r = client.post("/settings/scout", data={"faz_adom": "evil"})
    assert r.status_code == 403
    with app.app_context():
        assert sc.get("faz_adom") != "evil"
    login(client, admin_user_id(app))
    assert client.post("/settings/scout", data={"faz_adom": "border"}).status_code == 302
    with app.app_context():
        assert sc.get("faz_adom") == "border"


def test_sentinel_ai_endpoint_ships_empty_and_keeps_ai_off(app):
    from app.services.sentinel import ai, config as sn
    with app.app_context():
        assert sn.get("ai_url") == ""
        sn.set_value("ai_enabled", True)
        assert ai.enabled() is False, "switched on with no endpoint must stay off"
        sn.set_value("ai_url", "http://localhost:11434")
        assert ai.enabled() is True


def test_seeded_system_backup_schedule_has_a_neutral_name(app):
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        for row in ScheduledAction.query.all():
            if "system backup" in (row.name or "").lower():
                from app.extensions import db
                db.session.delete(row)
        from app.extensions import db
        db.session.commit()
        store.save_system_backup_schedule("01:30")
        names = [r.name for r in ScheduledAction.query.all()
                 if "system backup" in (r.name or "").lower()]
    assert names and all("backup-server" not in n for n in names), names
