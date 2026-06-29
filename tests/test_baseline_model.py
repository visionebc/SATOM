def test_baseline_crud_and_cascade(app):
    from app.models import db, Baseline, BaselineTemplate, Template
    with app.app_context():
        t = Template(kind=Template.KIND_WEB_PROTECTION, name="wpp-a", version=1,
                     body="{}", status=Template.STATUS_APPROVED)
        db.session.add(t); db.session.commit()
        b = Baseline(name="Edge-North", zone="DMZ", line="8.0", department="Ops",
                     author="admin")
        db.session.add(b); db.session.commit()
        link = BaselineTemplate(baseline_id=b.id, template_id=t.id,
                                section="web_protection", position=0)
        db.session.add(link); db.session.commit()

        got = Baseline.query.filter_by(name="Edge-North").first()
        assert got.zone == "DMZ" and got.line == "8.0" and got.department == "Ops"
        assert len(got.items) == 1
        assert got.items[0].template_id == t.id
        assert got.items[0].section == "web_protection"

        # deleting the baseline cascades the junction rows, not the templates
        db.session.delete(got); db.session.commit()
        assert BaselineTemplate.query.count() == 0
        assert Template.query.count() == 1


def test_baseline_scope_dict(app):
    from app.models import db, Baseline
    with app.app_context():
        b = Baseline(name="b", zone="", line="8.0", department="")
        db.session.add(b); db.session.commit()
        assert b.scope_dict() == {"zone": "", "line": "8.0", "department": ""}
