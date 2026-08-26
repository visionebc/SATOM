"""Guards: /artifacts/* takes its (device, ADOM) from the SESSION, like every
other per-device page in this product — and its pickers offer that pair only.

Reported three times in three days, escalating to "sigue exactamente igual".
It was, and the first two fixes could not have helped: they narrowed by
``?appl=``, a query argument the operator's navigation never produces. The
operator picks a device on the Architecture map; that lands in
``session['appliance_id']`` and ``device_context.current_appliance()`` is how
Backups, Server Objects, Web Protection, Exceptions, Section Config, Analysis
and FortiAnalyzer all know where they are. ``/artifacts/*`` was the ONLY
per-device area that never called it, so with a device selected it rendered the
whole fleet: measured on the live node, 163 mentions of other pairs on one page.

The second half is the half the earlier rounds could not see. Every guard I
wrote stripped ``<select>`` before asserting, on the reasoning that a picker
lists the fleet by design — so the fleet lived on in the controls, which is
literally what the operator said he was still seeing ("en los filtros").
A picker narrowed in the template is decoration, not a scope, so each guard on
a control has a matching guard on the POST that control drives.
"""
from __future__ import annotations

import re
from datetime import datetime

import pytest

from tests.conftest import admin_user_id, login

CHASSIS = "192.0.2.1"
OTHER = "192.0.2.2"


@pytest.fixture()
def ctx(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        from app import db
        yield db


def _appl(name, host, vdom, maintenance=False):
    from app import db
    from app.models import Appliance

    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="u", password_enc="x", vdom=vdom,
                    maintenance=maintenance)
    db.session.add(row)
    db.session.commit()
    return row


def _ref(aid, policy, kind, name, wpp="wpp-x"):
    from app import db
    from app.models_artifact_refs import WafArtifactRef

    now = datetime.utcnow()
    db.session.add(WafArtifactRef(appliance_id=aid, policy_mkey=policy,
                                  kind=kind, name=name, wpp_mkey=wpp, urn="",
                                  derived_from="test", first_seen_at=now,
                                  seen_at=now))
    db.session.commit()


def _put(kind, name, body, appliance_id=None):
    from app.services import waf_artifacts as wa
    wa.put(kind, name, body.encode("utf-8"), appliance_id=appliance_id,
           source="uploaded")


def _fleet():
    """Two ADOMs of one chassis, a second chassis, and a retired row.

    prod and dev are mirror images on purpose — same counts, disjoint names —
    so no guard here can pass merely because a number changed. ``retired`` is
    in maintenance: it must never reach a picker either.
    """
    prod = _appl("fw@prod", CHASSIS, "adom_prod")
    dev = _appl("fw@dev", CHASSIS, "adom_dev")
    other = _appl("fw2@root", OTHER, "adom_root")
    retired = _appl("fw-retired", "retired-x.invalid", "root", maintenance=True)

    for appl, tag in ((prod, "prod"), (dev, "dev"), (other, "other")):
        _put("wsdl", "sch-%s-1" % tag, "<x/>", appliance_id=appl.id)
        _put("wsdl", "sch-%s-2" % tag, "<x/>", appliance_id=appl.id)
        _ref(appl.id, "pol-%s" % tag, "wsdl", "sch-%s-1" % tag)
        _ref(appl.id, "pol-%s" % tag, "wsdl", "sch-%s-2" % tag)
    return prod, dev, other, retired


def _stand_on(client, app, appliance_id):
    """Exactly what picking a device on the Architecture map leaves behind."""
    login(client, admin_user_id(app))
    with client.session_transaction() as sess:
        sess["appliance_id"] = appliance_id


def _selects(html, name="appliance_id"):
    """Every <select name=...> on the page, as lists of option LABELS."""
    out = []
    for m in re.finditer(r'<select[^>]*name="%s"[^>]*>(.*?)</select>' % name,
                         html, re.S):
        out.append([re.sub(r"\s+", " ", o).strip()
                    for o in re.findall(r"<option[^>]*>(.*?)</option>",
                                        m.group(1), re.S)])
    return out


# ------------------------------------------------------------------ page body

def test_the_session_device_alone_scopes_the_inventory_with_no_query_args(
        ctx, app, client):
    prod, dev, other, _r = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert "sch-prod-1" in html
    # No query argument was passed: this is the operator's actual navigation.
    for stranger in ("sch-dev-1", "sch-other-1", "fw@dev", "fw2@root"):
        assert stranger not in html, (
            "%r is on a page scoped to %s — the session device was ignored"
            % (stranger, prod.name))


def test_the_statistics_page_is_scoped_by_the_session_device_too(
        ctx, app, client):
    prod, dev, other, _r = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/").get_data(as_text=True)

    assert "fw@dev" not in html and "fw2@root" not in html


def test_the_retired_manage_page_is_gone_not_merely_unlinked(ctx, app, client):
    """It carried upload, capture, push, edit and DELETE over a list of rows.

    An unlinked page keeps answering to anyone who bookmarked it, and this one
    was a duplicate of the inventory — so a scope or validation fix applied to
    one of the two would leave the other serving the old behaviour."""
    prod, dev, other, _r = _fleet()
    _stand_on(client, app, prod.id)

    assert client.get("/artifacts/manage").status_code == 404


# ---------------------------------------------------------------- the pickers

@pytest.mark.parametrize("path", ["/artifacts/inventory"])
def test_no_appliance_picker_offers_another_device(ctx, app, client, path):
    """The half three rounds of guards could not see, because they stripped
    <select> before asserting."""
    prod, dev, other, retired = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get(path).get_data(as_text=True)

    picks = _selects(html)
    assert picks, "no appliance picker on %s — guard would pass vacuously" % path
    for options in picks:
        joined = " | ".join(options)
        for stranger in ("fw@dev", "fw2@root", "adom_dev", OTHER):
            assert stranger not in joined, (
                "%s picker offers %r while standing on %s: %s"
                % (path, stranger, prod.name, options))


def test_no_picker_offers_a_maintenance_device(ctx, app, client):
    prod, _d, _o, retired = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert "retired-x.invalid" not in html and "fw-retired" not in html


def test_the_row_filter_cannot_widen_the_page_back_to_the_fleet(ctx, app, client):
    """The ``appl`` filter's default was 'Any' — the page's own escape hatch
    back to the defect. A control whose neutral value is 'the whole fleet' is
    not a filter on a scoped page."""
    prod, dev, other, _r = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert not _selects(html, "appl"), "the fleet-wide appliance filter is back"
    assert not _selects(html, "scope"), "the fleet-wide scope picker is back"


def test_the_statistics_counter_counts_this_pair_not_the_whole_store(
        ctx, app, client):
    """``wa.stats()`` sums every row in the store. Printed on a page cut to one
    pair it states the fleet's total as this pair's — and the bigger number is
    the one that reads as authoritative."""
    prod, dev, other, _r = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/").get_data(as_text=True)

    m = re.search(r"data-store-objects[^>]*>([^<]*)<", html)
    assert m, "no store-objects counter on the page"
    assert m.group(1).strip() == "2", (
        "%s objects printed on a page holding 2 — the store total leaked"
        % m.group(1).strip())


def test_the_object_page_lists_no_other_scopes_versions(ctx, app, client):
    """One name can be held by several pairs with DIFFERENT bytes. A version
    list that mixes them lets the operator open, edit and save another
    device's file from a page that names theirs."""
    prod, dev, _o, _r = _fleet()
    from app.services import waf_artifacts as wa
    wa.put("wsdl", "shared-name", b"<prod/>", appliance_id=prod.id,
           source="uploaded")
    wa.put("wsdl", "shared-name", b"<dev/>", appliance_id=dev.id,
           source="uploaded")
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/object/wsdl/shared-name").get_data(as_text=True)

    assert "fw@dev" not in html and "adom_dev" not in html


# ------------------------------------------------------- navigation semantics

def test_with_no_device_chosen_the_page_sends_the_operator_to_the_map(
        ctx, app, client):
    """What Backups and Server Objects do. Rendering the fleet instead is the
    behaviour that was reported."""
    _fleet()
    login(client, admin_user_id(app))

    r = client.get("/artifacts/inventory")

    assert r.status_code == 302
    assert "/architecture" in r.headers["Location"]


def test_a_legacy_appl_link_switches_the_device_instead_of_forking_the_scope(
        ctx, app, client):
    """Old links carry ``?appl=``. Honouring it as a SECOND scope is what let
    the URL bar and the nav badge disagree; it moves the session instead."""
    prod, dev, _o, _r = _fleet()
    _stand_on(client, app, prod.id)

    r = client.get("/artifacts/inventory?appl=%d" % dev.id)

    assert r.status_code == 302
    assert "appl=" not in r.headers["Location"]
    with client.session_transaction() as sess:
        assert sess["appliance_id"] == dev.id


# --------------------------------------------------------- the gate, not the UI

def test_a_write_aimed_outside_the_scope_is_refused_not_merely_unlisted(
        ctx, app, client):
    """``require_device_scope`` states the rule this product already learned:
    a page that only hides a control is decorated, not scoped."""
    prod, dev, _o, _r = _fleet()
    _stand_on(client, app, prod.id)

    r = client.post("/artifacts/upload",
                    data={"kind": "wsdl", "name": "smuggled",
                          "appliance_id": str(dev.id), "back": "inventory",
                          "file": (__import__("io").BytesIO(b"<x/>"), "s.wsdl")},
                    content_type="multipart/form-data")

    assert r.status_code in (302, 400)
    from app.services import waf_artifacts as wa
    assert wa.resolve("wsdl", "smuggled", dev.id)[0] is None, (
        "content was written to a device the page is not standing on")


# ------------------------------------------------------------------- control

def test_control_the_two_adoms_are_indistinguishable_by_their_numbers(
        ctx, app, client):
    """If prod and dev ever stop being mirror images, every guard above can go
    green for the wrong reason: an unscoped page would print a different
    number and the NAME assertions would still be the only real check."""
    prod, dev, _o, _r = _fleet()
    from app.services import artifact_refs as ar, artifact_files as af

    held = {}
    for appl in (prod, dev):
        held[appl.id] = len([o for o in af.object_index()
                             if o["appliance_id"] == appl.id])
    assert held[prod.id] == held[dev.id] == 2
    edges = ar.usage_index()
    assert len([r for k, v in edges.items() for r in v
                if r["appliance_id"] == prod.id]) == \
           len([r for k, v in edges.items() for r in v
                if r["appliance_id"] == dev.id])
