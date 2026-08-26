"""Guards: EMPTY stored content is a warned state, and ``push`` is gone.

Two reported items, and they are the same defect seen from two ends.

**The push button.** Content reaches an appliance at CREATE time — the
clone/migrate engine uploads the bytes for every file-backed object that run
creates. A standalone "Push this version to an appliance" wrote to a device
with nothing bound to the write: no plan, no policy, no reconciliation report,
and the object page was the only place that said it had happened. It was
removed rather than gated, and the guards below assert the endpoint stays
unrouted — a scope test on a dead route keeps passing after somebody re-adds an
unscoped one under a different name.

**The empty copy.** ``blob is None`` was the whole test for "can this object
travel", so a zero-byte (or whitespace-only) version RESOLVED: the pre-flight
counted it under "will be copied WITH content", the coverage verdict said
``ready``, and the apply uploaded it. What lands is an object the destination
shows as configured while the rule bound to it enforces nothing. An emptiness
is worse than an absence precisely because every "is it held?" check answers
yes, so nothing anywhere reports it.

The two are one story: the push button was the only way to repair such an
object, and repairing it that way left bytes on a box SATOM could not tie to
anything.

The fixture stores EMPTY versions directly through ``wa.put``, which has no
guard of its own — deliberately, because the store already contains whatever
the three doors let through before they were closed. A door test alone would
assert the house is clean because the lock is new.
"""
from __future__ import annotations

import re
from datetime import datetime

import pytest

from tests.conftest import admin_user_id, login

CHASSIS = "192.0.2.1"


@pytest.fixture()
def ctx(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        from app import db
        yield db


def _appl(name, host, vdom):
    from app import db
    from app.models import Appliance

    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="u", password_enc="x", vdom=vdom)
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


def _scan(aid, policy, refs=1, ok=True):
    from app import db
    from app.models_artifact_refs import WafArtifactScan

    db.session.add(WafArtifactScan(appliance_id=aid, policy_mkey=policy, ok=ok,
                                   error="", refs=refs,
                                   scanned_at=datetime.utcnow()))
    db.session.commit()


def _put(kind, name, body: bytes, appliance_id=None):
    from app.services import waf_artifacts as wa
    return wa.put(kind, name, body, appliance_id=appliance_id,
                  source="uploaded")


def _stand_on(client, app, appliance_id):
    from flask import g

    login(client, admin_user_id(app))
    with client.session_transaction() as sess:
        sess["appliance_id"] = appliance_id
    g.__dict__.pop("_current_appliance", None)


def _one_device():
    """One device with a real copy and an EMPTY one, both read by its policy."""
    appl = _appl("fw@prod", CHASSIS, "adom_prod")
    _put("wsdl", "sch-real", b"<real/>", appliance_id=appl.id)
    _put("wsdl", "sch-hollow", b"", appliance_id=appl.id)
    _ref(appl.id, "pol-a", "wsdl", "sch-real")
    _ref(appl.id, "pol-a", "wsdl", "sch-hollow")
    _scan(appl.id, "pol-a", refs=2)
    return appl


def _table(html: str, anchor: str) -> str:
    """Only the table carrying ``anchor``.

    The page has several, and the "needed and NOT held" one legitimately prints
    names this pair does not hold — a grep over the whole document would match
    it and report the opposite of what it measured."""
    i = html.index(anchor)
    return html[i:html.index("</table>", i)]


# ═══════════════════════════════════════════════════ the verb that was removed


def test_the_push_endpoint_is_unrouted(app):
    rules = {r.endpoint for r in app.url_map.iter_rules()}
    assert "artifacts.push" not in rules
    paths = {str(r) for r in app.url_map.iter_rules()}
    assert "/artifacts/push" not in paths

    from app.views import artifacts as v
    assert not hasattr(v, "push")


def test_the_object_page_offers_no_control_that_writes_to_a_device(ctx, app,
                                                                   client):
    """The route can be gone and the page still offer the button — a template
    posting to a dead URL is a 404 the operator reads as a broken product, not
    as a removed feature."""
    appl = _one_device()
    _stand_on(client, app, appl.id)

    html = client.get("/artifacts/object/wsdl/sch-real").get_data(as_text=True)

    assert "Push this version" not in html
    actions = re.findall(r'<form[^>]*action="([^"]*)"', html)
    assert actions, "no form at all — the fixture stopped exercising the page"
    assert not [a for a in actions if "push" in a.lower()], actions


def test_the_route_reason_map_does_not_still_explain_push(app):
    """``concept_map`` explains WHY each endpoint is reachable. An entry for a
    route that no longer exists is a reason for nothing, and route_audit reads
    this map to decide which endpoints are legitimately unlinked."""
    from app.services import concept_map as cm

    src = __import__("inspect").getsource(cm)
    assert '"artifacts.push"' not in src


# ═══════════════════════════════════════════════════════ the doors to the store


def test_a_whitespace_only_upload_is_refused(ctx, app, client):
    """``if not blob`` passed a file holding one newline: stored, resolvable,
    with a size — the empty object wearing a byte count."""
    import io

    from app.services import waf_artifacts as wa
    appl = _one_device()
    _stand_on(client, app, appl.id)

    client.post("/artifacts/upload", data={
        "kind": "wsdl", "name": "sch-blank", "appliance_id": str(appl.id),
        "file": (io.BytesIO(b"  \n\t \n"), "sch-blank.wsdl")},
        content_type="multipart/form-data", follow_redirects=True)

    assert wa.latest("wsdl", "sch-blank", appl.id) is None


def test_control_a_real_upload_is_still_stored(ctx, app, client):
    import io

    from app.services import waf_artifacts as wa
    appl = _one_device()
    _stand_on(client, app, appl.id)

    client.post("/artifacts/upload", data={
        "kind": "wsdl", "name": "sch-good", "appliance_id": str(appl.id),
        "file": (io.BytesIO(b"<x/>"), "sch-good.wsdl")},
        content_type="multipart/form-data", follow_redirects=True)

    assert wa.latest("wsdl", "sch-good", appl.id) is not None


def test_a_capture_that_comes_back_empty_stores_nothing(ctx, app, client,
                                                        monkeypatch):
    """The device answered, and answered with nothing. Storing that turns a
    device-side hole into a SATOM-side false positive."""
    from app.clients import fortiweb
    from app.services import waf_artifacts as wa
    appl = _one_device()
    _stand_on(client, app, appl.id)
    monkeypatch.setattr(fortiweb, "FortiWebClient", lambda a: object())
    monkeypatch.setattr(wa, "fetch", lambda *a, **k: (b"\n", ""))

    # ``openapi``, not ``wsdl``: WSDL is one of the three kinds no FortiWeb
    # hands back, so a capture of one is refused BEFORE the fetch — this guard
    # would have gone green without ever reaching the emptiness check.
    client.post("/artifacts/capture",
                data={"kind": "openapi", "name": "sch-cap",
                      "appliance_id": str(appl.id)},
                follow_redirects=True)

    assert wa.latest("openapi", "sch-cap", appl.id) is None


def test_control_a_capture_with_content_is_stored(ctx, app, client,
                                                  monkeypatch):
    from app.clients import fortiweb
    from app.services import waf_artifacts as wa
    appl = _one_device()
    _stand_on(client, app, appl.id)
    monkeypatch.setattr(fortiweb, "FortiWebClient", lambda a: object())
    monkeypatch.setattr(wa, "fetch", lambda *a, **k: (b"{}", ""))

    client.post("/artifacts/capture",
                data={"kind": "openapi", "name": "sch-cap",
                      "appliance_id": str(appl.id)},
                follow_redirects=True)

    assert wa.latest("openapi", "sch-cap", appl.id) is not None


# ══════════════════════════════════════════════════════ the migration verdicts


def test_an_empty_copy_is_not_content_for_a_plan(ctx, app):
    from app.services import waf_artifacts as wa
    appl = _one_device()

    class _It:
        kind = "object"
        urn = wa.KINDS["wsdl"]["urn"]
        status = "create"

    hollow, real = _It(), _It()
    hollow.mkey, real.mkey = "sch-hollow", "sch-real"

    rows = {r["name"]: r for r in
            wa.resolve_for_plan([hollow, real], source_appliance_id=appl.id)}

    assert rows["sch-hollow"]["resolved"] is False, (
        "an empty copy reported as content available is how the object gets "
        "created, empty, at the destination")
    assert rows["sch-hollow"]["empty"] is True
    assert "EMPTY" in rows["sch-hollow"]["reason"]
    # Control, in the same call: the real one still travels.
    assert rows["sch-real"]["resolved"] is True
    assert rows["sch-real"]["empty"] is False


def test_the_preflight_gate_asks_for_an_acknowledgement_and_says_why(app):
    """An empty copy must not be explained as "FortiWeb has no read endpoint
    for this type": the operator HAS a copy — it is the copy that is empty —
    and that message sends them to capture a file the device will never return.

    The row is deliberately an UNREADABLE kind (WSDL), and that is the whole
    point of the guard. For a readable kind the reason falls through unchanged
    whether or not the empty branch exists, so a row built with
    ``readable=True`` asserts nothing: my first version of this test used one
    and the mutation that deletes the branch SURVIVED it."""
    from app.services import policy_ops

    rows = [{"kind": "wsdl", "label": "WSDL", "name": "sch-hollow",
             "status": "create", "resolved": False, "empty": True,
             "readable": False, "origin": "",
             "reason": "the copy SATOM holds is EMPTY (0 bytes)"}]

    chk, suggest = policy_ops._artifact_gate(rows, dest_name="fw2",
                                             accepted=False)

    assert chk["level"] == "warn"
    assert suggest["artifacts_need_ack"] is True
    assert "EMPTY" in chk["detail"]
    assert "no read endpoint" not in chk["detail"]


def test_control_the_preflight_gate_is_green_for_a_resolved_copy(app):
    from app.services import policy_ops

    rows = [{"kind": "wsdl", "label": "WSDL", "name": "sch-real",
             "status": "create", "resolved": True, "empty": False,
             "readable": True, "origin": "SATOM", "reason": "",
             "name_warning": ""}]

    chk, suggest = policy_ops._artifact_gate(rows, dest_name="fw2",
                                             accepted=False)

    assert chk["level"] == "ok"
    assert suggest["artifacts_need_ack"] is False


def test_the_apply_skips_an_empty_copy_instead_of_uploading_it(ctx, app):
    from app.services import policy_ops, waf_artifacts as wa
    appl = _one_device()

    class _It:
        kind = "object"
        urn = wa.KINDS["wsdl"]["urn"]
        status = "create"
        mkey = "sch-hollow"
        note = ""

    it = _It()
    ctx_d = {"enabled": True, "source_appliance_id": appl.id,
             "accept_missing": True}

    blobs, missing = policy_ops._resolve_artifacts([it], ctx_d, dry_run=False)

    assert blobs == {}, "the empty bytes were queued for upload"
    assert [m["name"] for m in missing] == ["sch-hollow"]
    assert missing[0]["empty"] is True
    assert it.status == "no-content"


def test_the_apply_refuses_an_empty_copy_without_an_acknowledgement(ctx, app):
    """Same shape as an absent copy: the run stops rather than deciding for
    the operator that an object enforcing nothing is close enough."""
    from app.services import policy_ops, waf_artifacts as wa
    appl = _one_device()

    class _It:
        kind = "object"
        urn = wa.KINDS["wsdl"]["urn"]
        status = "create"
        mkey = "sch-hollow"
        note = ""

    with pytest.raises(RuntimeError) as exc:
        policy_ops._resolve_artifacts(
            [_It()], {"enabled": True, "source_appliance_id": appl.id},
            dry_run=False)

    assert "EMPTY" in str(exc.value)


def test_policy_coverage_counts_the_empty_copy_and_refuses_ready(ctx, app):
    from app.services import artifact_refs as ar
    appl = _one_device()

    cov = ar.policy_coverage(appl.id, "pol-a")

    assert cov["empty"] == 1
    assert cov["missing"] == 0, (
        "an empty copy is not an absent one — telling the operator to capture "
        "a file they already hold is a different, and useless, instruction")
    assert cov["ready"] is False, (
        "'all content held' over an object with nothing in it is the verdict "
        "that sends someone into a migration unprepared")
    hollow = next(a for a in cov["artifacts"] if a["name"] == "sch-hollow")
    assert hollow["empty"] is True and hollow["held"] is True
    assert "EMPTY" in hollow["reason"]


def test_control_policy_coverage_is_ready_when_every_copy_has_content(ctx, app):
    from app.services import artifact_refs as ar
    appl = _appl("fw@solo", CHASSIS, "adom_solo")
    _put("wsdl", "sch-real", b"<real/>", appliance_id=appl.id)
    _ref(appl.id, "pol-b", "wsdl", "sch-real")
    _scan(appl.id, "pol-b", refs=1)

    cov = ar.policy_coverage(appl.id, "pol-b")

    assert cov["empty"] == 0 and cov["ready"] is True


# ═══════════════════════════════════════════════════════════ the inventory page


def test_the_inventory_warns_about_a_copy_it_holds_and_that_is_empty(
        ctx, app, client):
    appl = _one_device()
    _stand_on(client, app, appl.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert "data-empty-warning" in html, (
        "the row says held, the size says nothing, and no page said so")
    assert "sch-hollow" in _table(html, "data-empty-table")
    assert "sch-real" not in _table(html, "data-empty-table")
    assert re.search(r'data-head="empty"[^>]*>\s*1\s*<', html), html[:0]


def test_control_no_warning_when_every_copy_has_content(ctx, app, client):
    appl = _appl("fw@solo", CHASSIS, "adom_solo")
    _put("wsdl", "sch-real", b"<real/>", appliance_id=appl.id)
    _ref(appl.id, "pol-b", "wsdl", "sch-real")
    _scan(appl.id, "pol-b", refs=1)
    _stand_on(client, app, appl.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert "data-empty-warning" not in html
    assert re.search(r'data-head="empty"[^>]*>\s*0\s*<', html)


def test_a_filter_cannot_hide_the_empty_warning(ctx, app, client):
    """The filters are for finding a row. A warning they can hide is a warning
    that is not there — and "show me only the captured ones" is not a decision
    about which risks this pair carries."""
    appl = _one_device()
    _stand_on(client, app, appl.id)

    html = client.get("/artifacts/inventory?q=sch-real").get_data(as_text=True)

    assert "sch-hollow" not in _table(html, "data-held-table")
    assert "sch-hollow" in _table(html, "data-empty-table")


def test_the_row_of_an_empty_copy_is_badged_in_the_held_table(ctx, app, client):
    """The warning card is above the fold; the row is where an operator who
    scrolled to their object actually is."""
    appl = _one_device()
    _stand_on(client, app, appl.id)

    held = _table(client.get("/artifacts/inventory").get_data(as_text=True),
                  "data-held-table")

    hollow = held[held.index("sch-hollow"):]
    hollow = hollow[:hollow.index("</tr>")]
    assert "data-empty-badge" in hollow


# ══════════════════════════════════════════════ the coverage table that moved


def test_the_migration_coverage_table_is_not_on_the_inventory(ctx, app, client):
    appl = _one_device()
    _stand_on(client, app, appl.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert "Migration coverage" not in html
    assert "walk failed" not in html


def test_the_inventory_does_not_compute_coverage_at_all(ctx, app, client,
                                                        monkeypatch):
    """Not rendering it is half the point; the other half is the cost. The
    report resolves every artifact of every scanned policy — one blob read per
    edge, on every page load — to answer a question asked when MIGRATING."""
    from app.services import artifact_refs as ar
    appl = _one_device()
    _stand_on(client, app, appl.id)

    def _boom(*a, **k):
        raise AssertionError("coverage_fleet was called from the inventory")

    monkeypatch.setattr(ar, "coverage_fleet", _boom)

    assert client.get("/artifacts/inventory").status_code == 200


def test_the_failed_walk_counter_survived_the_removal(ctx, app, client):
    """It was the one figure the coverage report fed. Read from the scan rows,
    which is where it always came from."""
    appl = _one_device()
    _scan(appl.id, "pol-broken", refs=0, ok=False)
    _stand_on(client, app, appl.id)

    html = client.get("/artifacts/inventory").get_data(as_text=True)

    assert re.search(r'data-head="failed_scans"[^>]*>\s*1\s*<', html)


def test_the_per_device_audit_still_answers_which_policies_can_move(
        ctx, app, client):
    """The question did not disappear — it moved to the page whose subject is
    one device's readiness, and to the clone pre-flight. A guard that only
    asserted the removal would pass just as well if the answer were nowhere."""
    appl = _one_device()
    _stand_on(client, app, appl.id)

    r = client.get("/artifacts/audit")

    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "pol-a" in html
