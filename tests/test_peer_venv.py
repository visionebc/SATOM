"""Peer venv fan-out: apply a curated pip change to BOTH HA nodes from one node.

The venv is node-local (not in git, not in the HA rsync), so a library upgrade
applied on one node silently drifts the pair. These tests lock the contract of
the opt-in "also apply on peer" path:

* ``node_security.peer_post`` mirrors ``peer_get`` (HTTPS :8443 first, plain
  :8000 fallback, ``X-FM-Node-Key`` identity header, same error semantics).
* the receiving endpoint RE-VALIDATES package/version against its OWN allowlist
  and its OWN regex, and refuses callers that do not carry the identity key.
* the fan-out is OPT-IN; an unreachable peer is reported UNREACHABLE (never
  success, never "already up to date") and never rolls back or blocks the local
  change that already succeeded.
* the card can show per-node version drift.

Everything is behavioural: the functions are called and the TRANSPORT is faked.
No test ever touches the real peer. Structural checks (there is one, for the
opt-in default) go through ``ast`` with docstrings stripped, never substrings.
"""
from __future__ import annotations

import ast
import json
import urllib.error
from pathlib import Path

import pytest

from app.services import node_security as nsec
from app.services import self_update as su
from tests.conftest import admin_user_id, login

APP_SRC = Path(su.__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# fake transport
# ---------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, code: int, body: bytes):
        self._code, self._body = code, body

    def getcode(self):
        return self._code

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _urlopen_recorder(handler, calls):
    """Patch urllib.request.urlopen with ``handler(url) -> _FakeResp|raise``."""
    def _fake(req, **kw):
        calls.append({
            "url": req.full_url,
            "method": req.get_method(),
            "headers": {k.lower(): v for k, v in req.header_items()},
            "body": req.data,
            "timeout": kw.get("timeout"),
            "context": kw.get("context"),
        })
        return handler(req.full_url)
    return _fake


@pytest.fixture()
def keyed(monkeypatch):
    """A configured identity key on this node."""
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    return "IDENTITY-KEY-123"


@pytest.fixture()
def queue(tmp_path, monkeypatch):
    """Redirect the enqueue dirs so nothing is written into the live tree."""
    monkeypatch.setattr(su, "REQ_DIR", tmp_path / "req")
    monkeypatch.setattr(su, "STATUS_DIR", tmp_path / "sta")
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    return tmp_path


def _queued(tmp_path):
    return sorted((tmp_path / "req").glob("*.json"))


# ===========================================================================
# 1. peer_post mirrors peer_get
# ===========================================================================
def test_peer_post_prefers_https_and_carries_identity_header(monkeypatch, keyed):
    calls = []
    monkeypatch.setattr(
        nsec.urllib.request, "urlopen",
        _urlopen_recorder(lambda url: _FakeResp(200, b'{"uid":"x"}'), calls))

    st, body, secure = nsec.peer_post("192.0.2.9", "/settings/peer/library-pip",
                                      b'{"package":"Flask"}', timeout=3.0)

    assert (st, body, secure) == (200, b'{"uid":"x"}', True)
    assert len(calls) == 1
    c = calls[0]
    assert c["url"] == "https://192.0.2.9:8443/settings/peer/library-pip"
    assert c["method"] == "POST"
    assert c["body"] == b'{"package":"Flask"}'
    assert c["headers"][nsec.HEADER.lower()] == keyed
    assert c["timeout"] == 3.0
    assert c["context"] is not None          # TLS context passed on the https leg


def test_peer_post_falls_back_to_plain_http_when_tls_unreachable(monkeypatch, keyed):
    calls = []

    def handler(url):
        if url.startswith("https://"):
            raise urllib.error.URLError("tls down")
        return _FakeResp(201, b"ok")

    monkeypatch.setattr(nsec.urllib.request, "urlopen",
                        _urlopen_recorder(handler, calls))
    st, body, secure = nsec.peer_post("192.0.2.9", "/p", b"{}")

    assert (st, body, secure) == (201, b"ok", False)
    assert [c["url"] for c in calls] == [
        "https://192.0.2.9:8443/p", "http://192.0.2.9:8000/p"]
    assert calls[1]["headers"][nsec.HEADER.lower()] == keyed
    assert calls[1]["context"] is None


def test_peer_post_unreachable_returns_none_status(monkeypatch, keyed):
    calls = []
    monkeypatch.setattr(
        nsec.urllib.request, "urlopen",
        _urlopen_recorder(lambda url: (_ for _ in ()).throw(
            urllib.error.URLError("down")), calls))

    assert nsec.peer_post("192.0.2.9", "/p", b"{}") == (None, b"", False)
    assert len(calls) == 2  # tried both legs


def test_peer_post_http_error_is_a_valid_answer(monkeypatch, keyed):
    calls = []

    def handler(url):
        raise urllib.error.HTTPError(url, 400, "bad", {}, None)

    monkeypatch.setattr(nsec.urllib.request, "urlopen",
                        _urlopen_recorder(handler, calls))
    st, body, secure = nsec.peer_post("192.0.2.9", "/p", b"{}")
    assert st == 400          # answered, not unreachable
    assert secure is True
    assert len(calls) == 1    # a real HTTP answer stops the fallback


def test_peer_post_sends_no_identity_header_when_unconfigured(monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: None)
    calls = []
    monkeypatch.setattr(nsec.urllib.request, "urlopen",
                        _urlopen_recorder(lambda url: _FakeResp(200, b"{}"), calls))
    nsec.peer_post("192.0.2.9", "/p", b"{}")
    assert nsec.HEADER.lower() not in calls[0]["headers"]


# ===========================================================================
# 2. the receiving endpoint: identity-key gated + re-validates locally
# ===========================================================================
def _peer_post_to_app(client, payload, key="IDENTITY-KEY-123"):
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers[nsec.HEADER] = key
    return client.post("/settings/peer/library-pip",
                       data=json.dumps(payload), headers=headers)


def test_peer_endpoint_enqueues_when_key_matches(app, client, queue, monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    r = _peer_post_to_app(client, {"package": "Flask", "version": "3.0.3",
                                   "action": "upgrade", "requested_by": "admin@node-b"})
    assert r.status_code == 200
    uid = r.get_json()["uid"]
    files = _queued(queue)
    assert len(files) == 1
    req = json.loads(files[0].read_text())
    assert req["id"] == uid
    assert req["kind"] == "pip"
    assert req["package"] == "Flask" and req["version"] == "3.0.3"
    assert req["action"] == "upgrade"
    assert req["node"] == "node-a"          # enqueued on the RECEIVING node


def test_peer_endpoint_rejects_missing_identity_key(app, client, queue, monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    r = _peer_post_to_app(client, {"package": "Flask", "version": "3.0.3"}, key=None)
    assert r.status_code == 403
    assert _queued(queue) == []


def test_peer_endpoint_rejects_wrong_identity_key(app, client, queue, monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    r = _peer_post_to_app(client, {"package": "Flask", "version": "3.0.3"},
                          key="not-the-key")
    assert r.status_code == 403
    assert _queued(queue) == []


def test_peer_endpoint_rejects_when_no_identity_key_configured(app, client, queue,
                                                               monkeypatch):
    """verify_request() answers None ("feature off") — that is NOT permission.
    Fails closed with the repo's distinguishable 503, never an enqueue."""
    monkeypatch.setattr(nsec, "get_identity_key", lambda: None)
    r = _peer_post_to_app(client, {"package": "Flask", "version": "3.0.3"}, key="x")
    assert r.status_code == 503
    assert r.status_code != 200
    assert _queued(queue) == []


def test_peer_endpoint_revalidates_the_allowlist(app, client, queue, monkeypatch):
    """A correctly-authenticated peer still may not install arbitrary packages."""
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    r = _peer_post_to_app(client, {"package": "evil-backdoor", "version": "1.0",
                                   "action": "upgrade"})
    assert r.status_code == 400
    assert _queued(queue) == []


def test_peer_endpoint_revalidates_the_version_regex(app, client, queue, monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    for bad in ("1.0; rm -rf /", "$(id)", "../../etc/passwd", "3.0.3 --extra-index-url x"):
        r = _peer_post_to_app(client, {"package": "Flask", "version": bad,
                                       "action": "upgrade"})
        assert r.status_code == 400, bad
    assert _queued(queue) == []


def test_peer_endpoint_rejects_unknown_action(app, client, queue, monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    r = _peer_post_to_app(client, {"package": "Flask", "version": "3.0.3",
                                   "action": "uninstall"})
    assert r.status_code == 400
    assert _queued(queue) == []


def test_local_enqueue_also_rejects_a_bad_version(queue):
    """The same regex guards the local button — not only the peer endpoint."""
    with pytest.raises(ValueError):
        su.request_pip_change("Flask", "1.0; rm -rf /", by="admin")
    assert _queued(queue) == []


def test_peer_libraries_endpoint_is_identity_key_gated(app, client, monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: "IDENTITY-KEY-123")
    assert client.get("/settings/peer/libraries").status_code == 403
    assert client.get("/settings/peer/libraries",
                      headers={nsec.HEADER: "wrong"}).status_code == 403
    r = client.get("/settings/peer/libraries",
                   headers={nsec.HEADER: "IDENTITY-KEY-123"})
    assert r.status_code == 200
    assert isinstance(r.get_json()["libraries"], dict)


def test_peer_libraries_endpoint_fails_closed_without_a_configured_key(app, client,
                                                                      monkeypatch):
    monkeypatch.setattr(nsec, "get_identity_key", lambda: None)
    r = client.get("/settings/peer/libraries", headers={nsec.HEADER: "anything"})
    assert r.status_code == 503


# ===========================================================================
# 3. the sender: per-node status, UNREACHABLE is never success
# ===========================================================================
@pytest.fixture()
def one_peer(monkeypatch):
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "_nodes_raw", lambda: [
        {"name": "node-a", "host": "127.0.0.1"},
        {"name": "node-b", "host": "192.0.2.249"},
    ])


def _fake_peer_post(monkeypatch, answer, calls=None):
    def _pp(host, path, data, timeout=2.0):
        if calls is not None:
            calls.append({"host": host, "path": path, "data": data})
        if callable(answer):
            return answer(host, path, data)
        return answer
    monkeypatch.setattr(nsec, "peer_post", _pp)


def test_peer_fanout_reports_queued(monkeypatch, one_peer):
    calls = []
    _fake_peer_post(monkeypatch, (200, b'{"uid":"U-1","node":"node-b"}', True), calls)
    res = su.request_pip_change_on_peers("Flask", "3.0.3", by="admin",
                                         action="upgrade")
    assert len(res) == 1
    assert res[0]["node"] == "node-b"
    assert res[0]["state"] == "queued"
    assert res[0]["uid"] == "U-1"
    body = json.loads(calls[0]["data"].decode())
    assert body["package"] == "Flask" and body["version"] == "3.0.3"
    assert body["action"] == "upgrade"


def test_peer_fanout_reports_unreachable_not_success(monkeypatch, one_peer):
    """The whole point: a peer we could not reach is UNREACHABLE."""
    _fake_peer_post(monkeypatch, (None, b"", False))
    res = su.request_pip_change_on_peers("Flask", "3.0.3", by="admin")
    assert len(res) == 1
    assert res[0]["state"] == "unreachable"
    assert res[0].get("uid") in (None, "")
    assert res[0]["node"] == "node-b"


def test_peer_fanout_transport_exception_is_unreachable(monkeypatch, one_peer):
    def _boom(host, path, data, timeout=2.0):
        raise OSError("network down")
    monkeypatch.setattr(nsec, "peer_post", _boom)
    res = su.request_pip_change_on_peers("Flask", "3.0.3", by="admin")
    assert res[0]["state"] == "unreachable"


def test_peer_fanout_reports_rejection_distinctly(monkeypatch, one_peer):
    _fake_peer_post(monkeypatch,
                    (400, b'{"error":"package not in the curated allowlist"}', True))
    res = su.request_pip_change_on_peers("evil", "1.0", by="admin")
    assert res[0]["state"] == "rejected"
    assert "allowlist" in (res[0].get("error") or "")


def test_peer_fanout_unparseable_answer_is_not_success(monkeypatch, one_peer):
    _fake_peer_post(monkeypatch, (200, b"<html>gateway</html>", True))
    res = su.request_pip_change_on_peers("Flask", "3.0.3", by="admin")
    assert res[0]["state"] != "queued"


def test_peer_fanout_skips_self(monkeypatch, one_peer):
    calls = []
    _fake_peer_post(monkeypatch, (200, b'{"uid":"U"}', True), calls)
    su.request_pip_change_on_peers("Flask", "3.0.3", by="admin")
    assert [c["host"] for c in calls] == ["192.0.2.249"]


# ===========================================================================
# 4. the route: OPT-IN, and a peer failure never undoes the local change
# ===========================================================================
def _post_local(client, payload):
    return client.post("/settings/library-pip", data=json.dumps(payload),
                       headers={"Content-Type": "application/json"})


def test_counterweight_single_node_upgrade_still_works(app, client, queue, monkeypatch,
                                                       one_peer):
    """No peer option -> unchanged behaviour, and the peer is NEVER contacted."""
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    calls = []
    _fake_peer_post(monkeypatch, (200, b'{"uid":"U"}', True), calls)
    login(client, admin_user_id(app))

    r = _post_local(client, {"package": "Flask", "version": "3.0.3",
                             "action": "upgrade"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["uid"]
    assert data["node"] == "node-a"
    assert calls == []                       # opt-in: nothing pushed
    assert data.get("peers") in (None, [])
    files = _queued(queue)
    assert len(files) == 1
    assert json.loads(files[0].read_text())["package"] == "Flask"


def test_peer_push_happens_only_when_opted_in(app, client, queue, monkeypatch,
                                              one_peer):
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    calls = []
    _fake_peer_post(monkeypatch, (200, b'{"uid":"U-9","node":"node-b"}', True), calls)
    login(client, admin_user_id(app))

    r = _post_local(client, {"package": "Flask", "version": "3.0.3",
                             "action": "upgrade", "also_peer": True})
    assert r.status_code == 200
    data = r.get_json()
    assert data["uid"]
    assert [c["host"] for c in calls] == ["192.0.2.249"]
    assert data["peers"][0]["node"] == "node-b"
    assert data["peers"][0]["state"] == "queued"


def test_unreachable_peer_does_not_block_or_revert_the_local_change(
        app, client, queue, monkeypatch, one_peer):
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    _fake_peer_post(monkeypatch, (None, b"", False))
    login(client, admin_user_id(app))

    r = _post_local(client, {"package": "Flask", "version": "3.0.3",
                             "action": "upgrade", "also_peer": True})
    assert r.status_code == 200                       # local success is reported
    data = r.get_json()
    assert data["uid"]                                # ... and NOT rolled back
    assert len(_queued(queue)) == 1                   # local request still queued
    assert data["peers"][0]["state"] == "unreachable"
    assert data["partial"] is True                    # honest partial state


def test_peer_push_with_no_peer_registered_is_reported(app, client, queue,
                                                       monkeypatch):
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "_nodes_raw", lambda: [{"name": "node-a",
                                                    "host": "127.0.0.1"}])
    login(client, admin_user_id(app))
    r = _post_local(client, {"package": "Flask", "version": "3.0.3",
                             "action": "upgrade", "also_peer": True})
    assert r.status_code == 200
    assert r.get_json()["peers"] == []


def test_bad_local_package_is_rejected_before_any_peer_is_contacted(
        app, client, queue, monkeypatch, one_peer):
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    calls = []
    _fake_peer_post(monkeypatch, (200, b'{"uid":"U"}', True), calls)
    login(client, admin_user_id(app))
    r = _post_local(client, {"package": "evil-backdoor", "version": "1.0",
                             "action": "upgrade", "also_peer": True})
    assert r.status_code == 400
    assert calls == []
    assert _queued(queue) == []


# ===========================================================================
# 5. per-node drift
# ===========================================================================
def _fake_peer_get(monkeypatch, answer):
    def _pg(host, path, timeout=2.0):
        if callable(answer):
            return answer(host, path)
        return answer
    monkeypatch.setattr(nsec, "peer_get", _pg)


def test_drift_shows_both_nodes_and_flags_a_mismatch(monkeypatch, one_peer):
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "local_lib_versions",
                        lambda: {"Flask": "3.0.3", "requests": "2.32.3"})
    _fake_peer_get(monkeypatch, (200, json.dumps({
        "node": "node-b", "role": "standby",
        "libraries": {"Flask": "3.0.2", "requests": "2.32.3"}}).encode(), True))

    d = su.lib_version_drift()
    by_pkg = {p["package"]: p for p in d["packages"]}
    assert by_pkg["Flask"]["versions"] == {"node-a": "3.0.3", "node-b": "3.0.2"}
    assert by_pkg["Flask"]["level"] is False
    assert by_pkg["requests"]["level"] is True
    assert d["level"] is False
    assert [n["name"] for n in d["nodes"]] == ["node-a", "node-b"]


def test_drift_level_when_both_nodes_agree(monkeypatch, one_peer):
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "local_lib_versions", lambda: {"Flask": "3.0.3"})
    _fake_peer_get(monkeypatch, (200, json.dumps({
        "libraries": {"Flask": "3.0.3"}}).encode(), True))
    d = su.lib_version_drift()
    assert d["level"] is True
    assert d["packages"][0]["level"] is True


def test_drift_never_calls_an_unreachable_peer_level(monkeypatch, one_peer):
    """An unreachable peer must not read as 'in sync' — that is the lie."""
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "local_lib_versions", lambda: {"Flask": "3.0.3"})
    _fake_peer_get(monkeypatch, (None, b"", False))

    d = su.lib_version_drift()
    peer = [n for n in d["nodes"] if n["name"] == "node-b"][0]
    assert peer["reachable"] is False
    assert d["level"] is False
    assert d["packages"][0]["level"] is False


def test_drift_peer_http_error_is_unreachable(monkeypatch, one_peer):
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "local_lib_versions", lambda: {"Flask": "3.0.3"})
    _fake_peer_get(monkeypatch, (403, b'{"error":"no"}', True))
    d = su.lib_version_drift()
    peer = [n for n in d["nodes"] if n["name"] == "node-b"][0]
    assert peer["reachable"] is False
    assert d["level"] is False


def test_drift_route_serves_the_service_result(app, client, monkeypatch, one_peer):
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "local_lib_versions", lambda: {"Flask": "3.0.3"})
    _fake_peer_get(monkeypatch, (None, b"", False))
    login(client, admin_user_id(app))
    r = client.get("/settings/library-pip/drift")
    assert r.status_code == 200
    d = r.get_json()
    assert d["level"] is False
    assert any(n["name"] == "node-b" and n["reachable"] is False for n in d["nodes"])


# ===========================================================================
# 6. structural: the opt-in default lives in the code, not in a comment
# ===========================================================================
class _StripDocstrings(ast.NodeTransformer):
    """Remove docstrings so no assertion below can match prose."""

    def _strip(self, node):
        self.generic_visit(node)
        body = node.body
        if body and isinstance(body[0], ast.Expr) and \
                isinstance(body[0].value, ast.Constant) and \
                isinstance(body[0].value.value, str):
            node.body = body[1:] or [ast.Pass()]
        return node

    visit_Module = _strip
    visit_FunctionDef = _strip
    visit_AsyncFunctionDef = _strip
    visit_ClassDef = _strip


def _clean_tree(path: Path) -> ast.AST:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return ast.fix_missing_locations(_StripDocstrings().visit(tree))


def test_route_reads_also_peer_with_a_falsy_default(monkeypatch):
    """`payload.get('also_peer')` must not be given a truthy default anywhere —
    ast over the stripped tree, so a comment or docstring cannot satisfy this."""
    tree = _clean_tree(APP_SRC / "views" / "settings.py")
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "get" and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and a0.value == "also_peer":
                default = node.args[1] if len(node.args) > 1 else ast.Constant(None)
                found.append(default)
    assert found, "the route never reads an 'also_peer' flag"
    for d in found:
        assert isinstance(d, ast.Constant), "also_peer default must be a literal"
        assert not d.value, "also_peer must default to FALSE (opt-in)"
