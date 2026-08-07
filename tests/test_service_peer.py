"""Guards for the state-aware button set and the peer service fan-out.

Two properties carry this feature and both are easy to lose in a refactor:

* the button set an operator SEES is derived from live state, but the endpoint
  gate is NOT -- collapsing them would turn a lost poll race into a scary
  "not allowed" for a button that was legitimately on screen;
* a peer is asked, never commanded: the receiving node re-validates against its
  OWN table, so a peer holding a valid identity key still cannot reach a unit
  that node does not permit.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services import service_control as svc  # noqa: E402

TPL = ROOT / "app" / "templates" / "settings" / "index.html"
VIEW = ROOT / "app" / "views" / "settings.py"


# ---------------------------------------------------------------------------
# available_actions -- presentation, derived from live state
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("state", list(svc.RUNNING_STATES))
def test_a_running_unit_is_never_offered_start(state):
    """Start on a running unit is a no-op dressed as an action."""
    for unit in svc.POLICY:
        assert "start" not in svc.available_actions(unit, state)


@pytest.mark.parametrize("state", ["inactive", "failed", "dead", "unknown", ""])
def test_a_stopped_unit_is_never_offered_stop(state):
    for unit in svc.POLICY:
        assert "stop" not in svc.available_actions(unit, state)


@pytest.mark.parametrize("unit", sorted(svc.POLICY))
@pytest.mark.parametrize("state", ["inactive", "failed"])
def test_a_stopped_unit_always_keeps_a_way_back(unit, state):
    """The load-bearing case. Restart-only units (the console, PostgreSQL) must
    still offer Restart when they are DOWN -- systemctl restart starts a stopped
    unit, and withholding it would leave a dead unit with no button at all,
    which is exactly when the operator needs one."""
    assert svc.available_actions(unit, state), \
        "%s in state %s would render with no way to bring it back" % (unit, state)


@pytest.mark.parametrize("unit", sorted(svc.POLICY))
@pytest.mark.parametrize("state", ["active", "inactive", "failed", ""])
def test_offered_actions_are_always_a_subset_of_permitted(unit, state):
    """Presentation may narrow the permitted set; it may never widen it."""
    permitted = set(svc.POLICY[unit]["actions"])
    assert set(svc.available_actions(unit, state)) <= permitted


@pytest.mark.parametrize("state", ["active", "inactive", "failed"])
def test_a_unit_not_installed_here_offers_nothing(state):
    for unit in svc.POLICY:
        assert svc.available_actions(unit, state, installed=False) == []


def test_a_running_unit_that_may_be_stopped_offers_both(a_unit="satom-scheduler.service"):
    assert svc.available_actions(a_unit, "active") == ["restart", "stop"]


def test_states_reports_both_sets_separately(monkeypatch):
    """`actions` (permitted, the gate) and `available` (offered now) must both
    be present and must not be the same key wearing two names."""
    monkeypatch.setattr(svc, "_show", lambda u, p: {
        "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "UnitFileState": "enabled"}.get(p, ""))
    rows = {r["unit"]: r for r in svc.states()}
    sched = rows["satom-scheduler.service"]
    assert sched["actions"] == ["start", "stop", "restart"]   # permitted
    assert sched["available"] == ["start"]                    # offered while down


def test_the_endpoint_gate_ignores_live_state():
    """`allowed()` is the privilege boundary and must NOT consult live state:
    if it did, a button rendered a second before a poll flipped the unit would
    come back refused and the console would look broken. A lost race has to be
    a systemd no-op, not an error."""
    import inspect
    src = inspect.getsource(svc.allowed)
    for forbidden in ("available_actions", "_show(", "ActiveState", "RUNNING_STATES"):
        assert forbidden not in src, \
            "allowed() must not depend on live state (found %r)" % forbidden


# ---------------------------------------------------------------------------
# peer fan-out
# ---------------------------------------------------------------------------
def test_a_peer_host_is_resolved_from_the_registry_not_the_request(monkeypatch):
    """The browser names a NODE; the host comes from ha_nodes.json. Otherwise
    the console could be pointed at an arbitrary address."""
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: None)
    row = svc.request_service_action_on_peer("192.0.2.99", "satom-scheduler.service",
                                             "restart", by="t")
    assert row["state"] == "rejected"
    assert "not a registered peer" in row["error"]


def test_a_peer_request_is_checked_against_the_table_before_the_wire(monkeypatch):
    called = {}

    def boom(*a, **k):  # pragma: no cover - must never run
        called["hit"] = True
        raise AssertionError("a forbidden unit reached the network")

    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    import app.services.node_security as nsec
    monkeypatch.setattr(nsec, "peer_post", boom)
    row = svc.request_service_action_on_peer("peer", "satom-updater.service",
                                             "stop", by="t")
    assert row["state"] == "rejected"
    assert "hit" not in called


@pytest.mark.parametrize("unit", list(svc.FORBIDDEN))
def test_the_updater_is_unreachable_on_a_peer_too(unit, monkeypatch):
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    for action in svc.ACTIONS:
        row = svc.request_service_action_on_peer("peer", unit, action, by="t")
        assert row["state"] == "rejected"


def _post(status, body):
    return lambda host, path, data, timeout=6.0: (status, body, True)


def test_an_unreachable_peer_is_never_reported_as_queued(monkeypatch):
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    import app.services.node_security as nsec
    monkeypatch.setattr(nsec, "peer_post", _post(None, b""))
    row = svc.request_service_action_on_peer("peer", "satom-scheduler.service",
                                             "restart", by="t")
    assert row["state"] == "unreachable"
    assert row["uid"] is None


@pytest.mark.parametrize("body", [b'{"ok": true}', b'{}', b'{"uid": ""}',
                                  b'{"error": "busy"}'])
def test_a_2xx_without_an_id_is_not_success(body, monkeypatch):
    """Only an id means the peer actually queued something. A 200 alone does
    not: a proxy, a login interstitial or a partial handler can all produce
    one.  [M7-REACHABLE-FIXTURE]

    The bodies here are deliberately VALID JSON. An earlier version of this
    test sent HTML, which the unreadable-body branch caught first -- so the
    "no id" check was never reached and a mutation that deleted it survived.
    A guard that cannot reach the line it is about proves nothing."""
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    import app.services.node_security as nsec
    monkeypatch.setattr(nsec, "peer_post", _post(200, body))
    row = svc.request_service_action_on_peer("peer", "satom-scheduler.service",
                                             "restart", by="t")
    assert row["state"] != "queued"
    assert not row["uid"]


def test_a_2xx_with_an_unreadable_body_is_not_success(monkeypatch):
    """The other half: HTML with a 200 is 'I could not read it', never queued."""
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    import app.services.node_security as nsec
    monkeypatch.setattr(nsec, "peer_post", _post(200, b"<html>hello</html>"))
    row = svc.request_service_action_on_peer("peer", "satom-scheduler.service",
                                             "restart", by="t")
    assert row["state"] == "unreachable"


def test_a_queued_peer_action_carries_the_peer_id(monkeypatch):
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    import app.services.node_security as nsec
    monkeypatch.setattr(nsec, "peer_post",
                        _post(200, json.dumps({"uid": "abc-123"}).encode()))
    row = svc.request_service_action_on_peer("peer", "satom-scheduler.service",
                                             "restart", by="t")
    assert row["state"] == "queued" and row["uid"] == "abc-123"


def test_an_unreachable_peer_never_renders_as_an_empty_unit_list(monkeypatch):
    """'I could not read it' and 'it has nothing' are opposite findings."""
    import app.services.node_security as nsec
    import app.services.self_update as su
    monkeypatch.setattr(su, "peer_nodes", lambda: [{"name": "p", "host": "192.0.2.2"}])
    monkeypatch.setattr(nsec, "peer_get",
                        lambda host, path, timeout=6.0: (None, b"", False))
    rows = svc.peer_states()
    assert len(rows) == 1
    assert rows[0]["reachable"] is False and rows[0]["error"]


def test_a_peer_on_an_older_release_says_so(monkeypatch):
    import app.services.node_security as nsec
    import app.services.self_update as su
    monkeypatch.setattr(su, "peer_nodes", lambda: [{"name": "p", "host": "192.0.2.2"}])
    monkeypatch.setattr(nsec, "peer_get",
                        lambda host, path, timeout=6.0: (404, b"<html>404</html>", True))
    row = svc.peer_states()[0]
    assert row["reachable"] is False
    assert "older release" in row["error"]


def test_a_mid_restart_poll_failure_is_polling_not_failed(monkeypatch):
    """A peer that stops answering while restarting its own web is the EXPECTED
    middle of a successful restart. Calling that 'failed' would teach the
    operator that a working button is broken."""
    import app.services.node_security as nsec
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    monkeypatch.setattr(nsec, "peer_get",
                        lambda host, path, timeout=6.0: (None, b"", False))
    st = svc.peer_action_status("p", "20260807-1")
    assert st["state"] == "polling"


def test_a_peer_status_id_cannot_escape_its_path(monkeypatch):
    seen = {}

    def spy(host, path, timeout=6.0):
        seen["path"] = path
        return 200, b"{}", True

    import app.services.node_security as nsec
    monkeypatch.setattr(svc, "_peer_by_name", lambda n: {"name": n, "host": "192.0.2.2"})
    monkeypatch.setattr(nsec, "peer_get", spy)
    svc.peer_action_status("p", "../../etc/passwd")
    assert ".." not in seen["path"] and "/etc/" not in seen["path"]
    assert seen["path"].startswith(svc.PEER_STATUS_PATH)


# ---------------------------------------------------------------------------
# the receiving half, and what the page draws
# ---------------------------------------------------------------------------
def test_the_receiving_endpoints_are_gated_by_the_node_identity_key():
    src = VIEW.read_text()
    for fn in ("def peer_services(", "def peer_service_action(", "def peer_service_status("):
        i = src.index(fn)
        window = src[i:i + 1400]
        assert "_peer_gate()" in window, "%s is not behind the peer gate" % fn


def test_the_receiving_action_endpoint_revalidates_locally():
    """It must go through request_service_action -- the function that applies
    THIS node's own table -- not write a request file of its own."""
    src = VIEW.read_text()
    i = src.index("def peer_service_action(")
    window = src[i:i + 1800]
    assert "svc.request_service_action(" in window


def test_the_card_draws_the_state_aware_set_not_the_permitted_one():
    tpl = TPL.read_text()
    i = tpl.index("[SATOM-SERVICE-PEER-JS]")
    js = tpl[i:]
    assert "u.available || []" in js, "buttons must be drawn from `available`"
    assert "var acts = u.actions" not in js


@pytest.mark.parametrize("action,cls", [("start", "btn-success"),
                                        ("stop", "btn-danger"),
                                        ("restart", "btn-warning")])
def test_each_action_has_its_own_colour(action, cls):
    """Scoped to the services block on purpose. [SATOM-TEST-SCOPED-ANCHOR]
    `var CLS = {` also appears in the unrelated classification widget earlier
    in this template, and anchoring on it made this guard read a block it was
    never about -- the failure mode this repo keeps re-learning."""
    js = _services_js()
    i = js.index("var CLS = {")
    assert "%s: '%s'" % (action, cls) in js[i:i + 200]


def test_every_confirm_names_the_node():
    """Dropping 'this node only' is only safe because the node is unmissable."""
    tpl = TPL.read_text()
    i = tpl.index("function confirmText(")
    window = tpl[i:tpl.index("document.addEventListener('click'", i)]
    assert "the PEER node ' + node" in window
    assert "this node (' + node + ')" in window


def test_peers_load_from_their_own_endpoint():
    """Folding peers into /services would let a dead standby break the local
    table on a healthy primary."""
    tpl = TPL.read_text()
    assert 'url_for("settings.services_peers")' in tpl
    i = tpl.index("function loadPeers(")
    j = tpl.index("function loadAll(")
    assert "catch" in tpl[i:j], "a peer failure must not propagate"


def _services_js() -> str:
    """Only the services card's script. Every guard below must read THIS block:
    settings/index.html is ~4k lines and short anchors match elsewhere."""
    tpl = TPL.read_text()
    return tpl[tpl.index("[SATOM-SERVICE-PEER-JS]"):]


def test_the_status_reader_rejects_a_traversing_id(tmp_path, monkeypatch):
    """update_status() builds a filesystem path out of a URL segment. The check
    lives THERE, not in each caller: the next caller would have to remember."""
    from app.services import self_update as su
    monkeypatch.setattr(su, "STATUS_DIR", tmp_path)
    (tmp_path / "20260101-000000-abcdef.json").write_text('{"state": "done"}')
    outside = tmp_path.parent / "secret.json"
    outside.write_text('{"state": "leaked"}')

    assert su.update_status("20260101-000000-abcdef")["state"] == "done"
    for hostile in ("../secret", "..%2fsecret", "a/../../secret", "..", "."):
        assert su.update_status(hostile) is None, hostile


def test_the_id_pattern_matches_the_ids_we_actually_mint():
    """A narrower class than the minted shape would silently break polling."""
    import re as _re
    from datetime import datetime
    import uuid
    from app.services import self_update as su
    for _ in range(20):
        uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        assert su.UID_RE.match(uid), uid
