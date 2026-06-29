"""Phase 6 — device_sync / device_inspect catalog actions."""
from app.services import scheduled_actions as SA


def test_catalog_has_device_sync():
    assert SA.get_spec("device_sync") is not None
    assert SA.get_spec("device_inspect") is not None
    assert SA.get_spec("device_sync").scope == "admin"


def test_device_sync_dry_run_no_device():
    spec = SA.get_spec("device_sync")
    r = SA.run_action(spec, None, {}, dry_run=True)
    assert r["ok"] is False        # needs a target


def test_device_sync_dry_run_with_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        r = SA.run_action(SA.get_spec("device_sync"), a, {}, dry_run=True)
        assert r["ok"] is True and "dry-run" in r["summary"]
        r2 = SA.run_action(SA.get_spec("device_inspect"), a, {}, dry_run=True)
        assert "git publish" in r2["summary"]
