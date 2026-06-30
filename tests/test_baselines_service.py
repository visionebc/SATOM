def _mk_template(app, name, kind=None):
    from app.models import db, Template
    kind = kind or Template.KIND_WEB_PROTECTION
    with app.app_context():
        t = Template(kind=kind, name=name, version=1, body="{}",
                     status=Template.STATUS_APPROVED)
        db.session.add(t); db.session.commit()
        return t.id


def _mk_appliance(app, name, zone="", line="", dept=""):
    from app.models import db, Appliance
    with app.app_context():
        a = Appliance(name=name, host="1.1.1.1", username="x",
                      zone=zone, line=line, department=dept)
        a.password = "pw"
        db.session.add(a); db.session.commit()
        return a.id


def test_create_and_get(app):
    from app.services import baselines as B
    with app.app_context():
        t1 = _mk_template(app, "wpp-a")
        b = B.create_baseline("Edge", zone="DMZ", line="8.0", department="",
                              template_ids=[t1], author="admin")
        got = B.get_baseline(b.id)
        assert got.name == "Edge"
        assert [i.template_id for i in got.items] == [t1]
        assert got.items[0].section == "web_protection"


def test_create_rejects_unapproved(app):
    from app.models import db, Template
    from app.services import baselines as B
    import pytest
    with app.app_context():
        t = Template(kind=Template.KIND_WEB_PROTECTION, name="pend", version=1,
                     body="{}", status=Template.STATUS_PENDING)
        db.session.add(t); db.session.commit()
        with pytest.raises(ValueError):
            B.create_baseline("X", template_ids=[t.id])


def test_matching_devices_by_scope(app):
    from app.services import baselines as B
    with app.app_context():
        t1 = _mk_template(app, "wpp-a")
        _mk_appliance(app, "fw1", zone="DMZ", line="8.0", dept="Ops")
        _mk_appliance(app, "fw2", zone="LAN", line="8.0", dept="Ops")
        b = B.create_baseline("Edge", zone="DMZ", line="", department="",
                              template_ids=[t1])
        names = {a.name for a in B.matching_devices(b)}
        assert names == {"fw1"}                # zone filter excludes fw2


def test_matching_devices_any_scope_matches_all(app):
    from app.services import baselines as B
    with app.app_context():
        t1 = _mk_template(app, "wpp-a")
        _mk_appliance(app, "fw1", zone="DMZ")
        _mk_appliance(app, "fw2", zone="LAN")
        b = B.create_baseline("All", zone="", line="", department="",
                              template_ids=[t1])
        assert len(B.matching_devices(b)) == 2


def test_delete_baseline(app):
    from app.services import baselines as B
    with app.app_context():
        t1 = _mk_template(app, "wpp-a")
        b = B.create_baseline("Tmp", template_ids=[t1])
        assert B.delete_baseline(b.id) is True
        assert B.get_baseline(b.id) is None
