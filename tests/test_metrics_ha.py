"""Guards for metrics survival across an HA promote — the COLLECTION layer.

The gap this covers: the metrics store is a node-local VictoriaMetrics that is
deliberately outside ``data/`` (the HA datasync rsyncs data/ with --delete and a
TSDB must never be rsynced under a live process) and deliberately outside the
backup bundle (~8 GB per bundle). The consequence was that the standby had no
store and no collection at all, so a promote produced a new primary with zero
history AND zero ability to make new history.

The fix is VictoriaMetrics' own documented HA shape: two independent single-node
stores fed the SAME samples. So the properties under test are the properties of
a dual-write, and each has a matching way to regress silently:

* **the mirror must never cost the original** — a peer write that fails must not
  turn a good local scrape into a failed one;
* **but a failing mirror must be loud** — a peer write that has been failing for
  an hour and reports nothing is the exact bug this product keeps hitting, where
  a probe that cannot answer looks healthy;
* **"no peer configured" and "peer unreachable" are different facts** — collapse
  them and a single-node install looks broken, or a broken pair looks single;
* **off by default** — a node with no peer must behave EXACTLY as it did before.

Nothing here touches the network or the real store: the transport
(``node_security.peer_post`` / ``peer_get``) and the store client
(``vm_store.ingest`` / ``health``) are always faked.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC_COLLECT = REPO / "app" / "services" / "metrics_collect.py"
SRC_ADMIN = REPO / "app" / "views" / "metrics_admin.py"


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_peer_state(tmp_path, monkeypatch):
    """Never let a test write the node's real /opt/satom/state journal — the
    jobs-ledger contamination lesson, applied before it can happen again."""
    from app.services import metrics_collect as mc
    monkeypatch.setattr(mc, "PEER_STATE_FILE", tmp_path / "metrics-peer.json")
    yield


@pytest.fixture(autouse=True)
def _no_real_transport(monkeypatch):
    """A test that reaches the peer for real is a test that passes on the wrong
    machine. Make the raw transport explode; every test that needs a peer
    installs its own fake."""
    from app.services import node_security as nsec

    def _boom(*a, **k):  # pragma: no cover - tripwire
        raise AssertionError("test made a real peer call")

    monkeypatch.setattr(nsec, "peer_get", _boom)
    if hasattr(nsec, "peer_post"):
        monkeypatch.setattr(nsec, "peer_post", _boom)
    yield


def _appliance(name="fwm", kind="fortiweb", host="192.0.2.5"):
    from app.models import Appliance, db
    a = Appliance(name=name, host=host, username="admin", kind=kind)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _target(collector="box"):
    """One provisioned scrape target, ready to run."""
    from app.models_metrics import ScrapeTarget
    from app.services import metrics_collect as mc
    a = _appliance()
    mc.ensure_targets(a)
    return ScrapeTarget.query.filter_by(appliance_id=a.id,
                                        collector=collector).first()


def _enable_dual_write(host="192.0.2.249"):
    from app.services import metrics_collect as mc
    from app.services import settings_store as ss
    ss.set_str(mc.K_DUAL_WRITE, "1")
    ss.set_str(mc.K_PEER_HOST, host)


def _fake_local_store(monkeypatch, ok=True):
    """Capture what would have gone into the LOCAL store."""
    from app.services import vm_store
    seen = []

    def _ingest(lines):
        seen.append(list(lines))
        return {"ok": ok, "count": len(lines),
                "detail": "" if ok else "local store down"}

    monkeypatch.setattr(vm_store, "ingest", _ingest)
    return seen


def _fake_peer(monkeypatch, result=(200, b"", True), exc=None):
    """Install a fake ``node_security.peer_post`` and record every call."""
    from app.services import node_security as nsec
    calls = []

    def _post(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        if exc is not None:
            raise exc
        return result

    monkeypatch.setattr(nsec, "peer_post", _post, raising=False)
    return calls


def _remove_peer_post(monkeypatch):
    """Simulate the node where node_security.peer_post has not landed yet."""
    from app.services import node_security as nsec
    monkeypatch.delattr(nsec, "peer_post", raising=False)


# ── 5. OFF BY DEFAULT — the counterweight ───────────────────────────────────

def test_dual_write_is_off_by_default(app, monkeypatch):
    """A node with no peer configured must behave EXACTLY as it does today: no
    peer call, no state file, no new warning. Anything else makes every
    single-node install pay for a feature it did not ask for."""
    from app.services import metrics_collect as mc
    with app.app_context():
        calls = _fake_peer(monkeypatch)
        local = _fake_local_store(monkeypatch)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()

        res = mc.run_target(t)

        assert res["ok"] is True
        assert t.last_status == "ok"
        assert calls == [], "dual-write must not run unless switched on"
        assert local, "the local scrape must still happen"
        assert mc.peer_health()["enabled"] is False
        assert mc.peer_health()["state"] == mc.PEER_OFF
        # "off" is not a complaint: a single-node node is not degraded.
        assert mc.peer_health()["alarm"] is False
        assert not mc.PEER_STATE_FILE.exists(), \
            "an unconfigured node must not even create peer state"


def test_single_node_scrape_lines_are_unchanged_by_the_feature(app, monkeypatch):
    """The dual-write must add nothing to what the local store receives."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _fake_peer(monkeypatch)
        local = _fake_local_store(monkeypatch)
        monkeypatch.setitem(
            mc._RUNNERS, "box",
            lambda a, p, ts: [mc.vm_store.line("satom_box_cpu_pct",
                                               {"device": a.name}, 5, ts)])
        t = _target()
        mc.run_target(t)
        names = sorted(l.split("{")[0] for l in local[0])
        assert names == ["satom_box_cpu_pct", "satom_scrape_up"]


# ── 3. FAILURE SEMANTICS — the mirror never costs the original ──────────────

@pytest.mark.parametrize("kind,kw", [
    ("transport-exploded", {"exc": OSError("connection refused")}),
    ("peer-rejected", {"result": (500, b"boom", True)}),
    ("peer-unreachable", {"result": (None, b"", False)}),
])
def test_peer_write_failure_never_fails_the_local_scrape(app, monkeypatch,
                                                         kind, kw):
    """Local collection is the primary duty. Degrading it to keep a mirror in
    step trades the thing that works for the thing that is optional."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _enable_dual_write()
        _fake_peer(monkeypatch, **kw)
        _fake_local_store(monkeypatch, ok=True)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()

        res = mc.run_target(t)

        assert res["ok"] is True, "peer failure (%s) failed the local scrape" % kind
        assert t.last_status == "ok"
        assert "peer" not in (res["detail"] or "").lower() or res["ok"] is True


def test_local_ingest_failure_still_fails_the_scrape(app, monkeypatch):
    """Counterweight to the guard above: the LOCAL store failing is still a
    failed scrape. The 'never fail on peer' rule must not have widened into
    'never fail'."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _enable_dual_write()
        _fake_peer(monkeypatch)
        _fake_local_store(monkeypatch, ok=False)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()

        res = mc.run_target(t)

        assert res["ok"] is False
        assert "local store down" in res["detail"]


# ── 3. FAILURE SEMANTICS — but the failure is loud ──────────────────────────

def test_failing_peer_write_is_never_reported_as_healthy(app, monkeypatch):
    """The bug this product keeps hitting: a probe that cannot answer looks
    healthy. An unreachable peer store must read as NOT redundant and must
    raise the alarm, with a failure count and no last-success timestamp."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _enable_dual_write()
        _fake_peer(monkeypatch, result=(None, b"", False))
        _fake_local_store(monkeypatch)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()

        mc.run_target(t)
        mc.run_target(t)

        h = mc.peer_health()
        assert h["state"] == mc.PEER_UNREACHABLE
        assert h["redundant"] is False, "an unreachable peer claimed redundancy"
        assert h["alarm"] is True
        assert h["consecutive_failures"] == 2
        assert h["last_success_at"] is None
        assert h["last_error"]


def test_consecutive_failures_reset_and_last_success_is_stamped(app, monkeypatch):
    """'Time of the last success' is the number that tells an operator how far
    back the mirror actually goes. A counter that never resets, or a success
    that is not stamped, makes the pair unauditable."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _enable_dual_write()
        _fake_local_store(monkeypatch)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()

        _fake_peer(monkeypatch, result=(502, b"", True))
        mc.run_target(t)
        assert mc.peer_health()["consecutive_failures"] == 1
        assert mc.peer_health()["state"] == mc.PEER_REJECTED

        _fake_peer(monkeypatch, result=(204, b"", True))
        mc.run_target(t)

        h = mc.peer_health()
        assert h["state"] == mc.PEER_OK
        assert h["consecutive_failures"] == 0
        assert h["redundant"] is True
        assert h["alarm"] is False
        assert h["last_success_at"]


def test_peer_write_receives_exactly_the_local_lines(app, monkeypatch):
    """Two independent stores are only redundant if they are fed the SAME
    samples. A peer that gets a different set is a second store, not a mirror."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _enable_dual_write()
        calls = _fake_peer(monkeypatch)
        local = _fake_local_store(monkeypatch)
        monkeypatch.setitem(
            mc._RUNNERS, "box",
            lambda a, p, ts: [mc.vm_store.line("satom_box_cpu_pct",
                                               {"device": a.name}, 7, ts)])
        t = _target()
        mc.run_target(t)

        assert len(calls) == 1
        body = [x for x in calls[0]["args"] if isinstance(x, (bytes, str))]
        body = [x.decode() if isinstance(x, bytes) else x for x in body]
        payload = [b for b in body if "satom_box_cpu_pct" in b]
        assert payload, "peer write carried no samples: %r" % (calls[0],)
        sent = set(payload[0].strip().splitlines())
        assert sent == set(local[0])


def test_peer_write_does_not_use_raw_urllib(app, monkeypatch):
    """The peer write must ride the authenticated node channel, never a direct
    connection. Exposing :8428 beyond loopback would publish the whole fleet's
    telemetry to anything on the LAN — the store has no authentication at all."""
    import urllib.request

    from app.services import metrics_collect as mc

    def _boom(*a, **k):  # pragma: no cover - tripwire
        raise AssertionError("peer write opened a raw URL")

    with app.app_context():
        _enable_dual_write()
        _fake_peer(monkeypatch)
        _fake_local_store(monkeypatch)
        monkeypatch.setattr(urllib.request, "urlopen", _boom)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()
        assert mc.run_target(t)["ok"] is True
        assert mc.peer_health()["state"] == mc.PEER_OK


# ── 4. STATES THAT MUST NEVER RENDER THE SAME ───────────────────────────────

def test_off_unconfigured_unreachable_and_unavailable_are_four_facts(app,
                                                                     monkeypatch):
    """Four different operator actions, four different states. Collapsing any
    pair means the page lies about whether the pair is redundant."""
    from app.services import metrics_collect as mc
    from app.services import settings_store as ss
    seen = {}
    with app.app_context():
        _fake_local_store(monkeypatch)

        # (a) switched off
        seen["off"] = mc.peer_write(["x 1 1"])["state"]

        # (b) switched on, but no peer host known
        ss.set_str(mc.K_DUAL_WRITE, "1")
        ss.set_str(mc.K_PEER_HOST, "")
        monkeypatch.setattr(mc, "_derived_peer_host", lambda: None)
        seen["unconfigured"] = mc.peer_write(["x 1 1"])["state"]

        # (c) configured, but the transport is not deployed on this node
        ss.set_str(mc.K_PEER_HOST, "192.0.2.249")
        _remove_peer_post(monkeypatch)
        seen["unavailable"] = mc.peer_write(["x 1 1"])["state"]

        # (d) configured, transport present, peer silent
        _fake_peer(monkeypatch, result=(None, b"", False))
        seen["unreachable"] = mc.peer_write(["x 1 1"])["state"]

    assert len(set(seen.values())) == 4, seen
    assert seen["off"] == mc.PEER_OFF
    assert seen["unconfigured"] == mc.PEER_UNCONFIGURED
    assert seen["unavailable"] == mc.PEER_UNAVAILABLE
    assert seen["unreachable"] == mc.PEER_UNREACHABLE


def test_missing_peer_post_is_not_an_unreachable_peer(app, monkeypatch):
    """A missing dependency on THIS node and a dead peer are fixed by opposite
    actions (deploy code vs. go look at the other box). They must not share a
    state, and the missing dependency must not crash the scrape."""
    from app.services import metrics_collect as mc
    with app.app_context():
        _enable_dual_write()
        _remove_peer_post(monkeypatch)
        _fake_local_store(monkeypatch)
        monkeypatch.setitem(mc._RUNNERS, "box", lambda *a: [])
        t = _target()

        assert mc.run_target(t)["ok"] is True
        h = mc.peer_health()
        assert h["state"] == mc.PEER_UNAVAILABLE
        assert h["state"] != mc.PEER_UNREACHABLE
        assert h["dependency_ready"] is False
        assert h["redundant"] is False


def test_module_still_imports_without_peer_post():
    """The transport lands in node_security separately. This module must load
    and collect locally even on a node where peer_post does not exist yet."""
    import importlib

    from app.services import metrics_collect as mc
    assert importlib.reload(mc)
    assert callable(mc.peer_write)


# ── 4. PER-NODE STORE REPORT ────────────────────────────────────────────────

def test_stores_report_separates_not_configured_from_unreachable(app,
                                                                 monkeypatch):
    """'We have no peer' and 'the peer will not answer' must not both render as
    a blank second column."""
    from app.services import metrics_collect as mc
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health",
                        lambda: {"up": True, "url": "http://127.0.0.1:8428",
                                 "series": 1234, "detail": ""})
    with app.app_context():
        monkeypatch.setattr(mc, "_derived_peer_host", lambda: None)
        rep = mc.stores_report()
        peer = [n for n in rep if not n["is_local"]]
        assert peer and peer[0]["store"]["state"] == mc.STORE_NOT_CONFIGURED

        monkeypatch.setattr(mc, "_derived_peer_host", lambda: "192.0.2.249")
        from app.services import node_security as nsec
        monkeypatch.setattr(nsec, "peer_get", lambda *a, **k: (None, b"", False))
        rep = mc.stores_report()
        peer = [n for n in rep if not n["is_local"]][0]
        assert peer["store"]["state"] == mc.STORE_UNREACHABLE
        assert peer["store"]["series"] is None


def test_stores_report_shows_the_pair_when_the_peer_answers(app, monkeypatch):
    """The whole point of the page: is this pair ACTUALLY redundant, i.e. does
    the other node hold series too, or does it only claim to."""
    import json

    from app.services import metrics_collect as mc
    from app.services import node_security as nsec
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health",
                        lambda: {"up": True, "url": "http://127.0.0.1:8428",
                                 "series": 1000, "detail": ""})
    with app.app_context():
        monkeypatch.setattr(mc, "_derived_peer_host", lambda: "192.0.2.249")
        monkeypatch.setattr(nsec, "peer_get", lambda *a, **k: (
            200, json.dumps({"ok": True, "store": {
                "up": True, "series": 990, "url": "http://127.0.0.1:8428",
                "detail": ""}}).encode(), True))
        rep = mc.stores_report()
        local = [n for n in rep if n["is_local"]][0]
        peer = [n for n in rep if not n["is_local"]][0]
        assert local["store"]["state"] == mc.STORE_REACHABLE
        assert local["store"]["series"] == 1000
        assert peer["store"]["state"] == mc.STORE_REACHABLE
        assert peer["store"]["series"] == 990


def test_stores_report_marks_a_rejected_peer_probe_distinctly(app, monkeypatch):
    """A peer that answers 403 is up but does not trust our identity key —
    a credential problem, not a dead box."""
    from app.services import metrics_collect as mc
    from app.services import node_security as nsec
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health",
                        lambda: {"up": True, "url": "u", "series": 1,
                                 "detail": ""})
    with app.app_context():
        monkeypatch.setattr(mc, "_derived_peer_host", lambda: "192.0.2.249")
        monkeypatch.setattr(nsec, "peer_get", lambda *a, **k: (403, b"no", True))
        peer = [n for n in mc.stores_report() if not n["is_local"]][0]
        assert peer["store"]["state"] == mc.STORE_UNAUTHORIZED


# ── 2. the receiving end is authenticated, never an open port ───────────────

def test_peer_ingest_refuses_without_the_node_key(app, client, monkeypatch):
    from app.services import node_security as nsec
    from app.services import vm_store
    called = []
    monkeypatch.setattr(vm_store, "ingest",
                        lambda lines: called.append(lines) or {"ok": True,
                                                               "count": 0,
                                                               "detail": ""})
    with app.app_context():
        nsec.ensure_identity_key()
    r = client.post("/monitoring/collection/peer/ingest", data="m{a=\"b\"} 1 1")
    assert r.status_code == 403
    assert called == [], "an unauthenticated body reached the store"


def test_peer_ingest_refuses_when_no_identity_key_is_configured(app, client,
                                                                monkeypatch):
    """Fail CLOSED. The store behind this endpoint has no authentication of its
    own; an un-keyed node accepting writes would be a fleet-wide open write
    port, which is exactly what the loopback bind exists to prevent."""
    from app.services import node_security as nsec
    from app.services import vm_store
    called = []
    monkeypatch.setattr(vm_store, "ingest",
                        lambda lines: called.append(lines) or {"ok": True,
                                                               "count": 0,
                                                               "detail": ""})
    monkeypatch.setattr(nsec, "get_identity_key", lambda: None)
    r = client.post("/monitoring/collection/peer/ingest", data="m 1 1")
    assert r.status_code == 503
    assert called == []


def test_peer_ingest_accepts_a_keyed_write(app, client, monkeypatch):
    from app.services import node_security as nsec
    from app.services import vm_store
    got = {}

    def _ingest(lines):
        got["lines"] = list(lines)
        return {"ok": True, "count": len(lines), "detail": ""}

    monkeypatch.setattr(vm_store, "ingest", _ingest)
    with app.app_context():
        key = nsec.ensure_identity_key()
    r = client.post("/monitoring/collection/peer/ingest",
                    data='satom_box_cpu_pct{device="fw1"} 5 1000',
                    headers={nsec.HEADER: key},
                    content_type="text/plain")
    assert r.status_code == 200, r.data
    assert got["lines"] == ['satom_box_cpu_pct{device="fw1"} 5 1000']


def test_peer_store_probe_requires_the_node_key(app, client):
    from app.services import node_security as nsec
    with app.app_context():
        nsec.ensure_identity_key()
    assert client.get("/monitoring/collection/peer/store").status_code == 403


# ── 6. snapshots ────────────────────────────────────────────────────────────

def test_snapshot_create_reports_the_name(app, monkeypatch):
    from app.services import metrics_collect as mc
    monkeypatch.setattr(mc, "_store_api",
                        lambda path, **k: {"status": "ok",
                                           "snapshot": "20260807-AAAA"})
    with app.app_context():
        out = mc.snapshot_create()
    assert out["ok"] is True and out["snapshot"] == "20260807-AAAA"


def test_snapshot_failure_is_reported_not_raised(app, monkeypatch):
    """A snapshot that could not be taken must say so — a silent 'ok' here
    would be a backup that does not exist."""
    from app.services import metrics_collect as mc

    def _boom(path, **k):
        raise OSError("store down")

    monkeypatch.setattr(mc, "_store_api", _boom)
    with app.app_context():
        out = mc.snapshot_create()
    assert out["ok"] is False and "store down" in out["detail"]
    assert out.get("snapshot") in (None, "")


# ── structural: nothing here widens the store's exposure ────────────────────

def _stripped_ast(path: Path):
    """Parse and DROP every docstring. Comments never reach the AST, so this
    tree contains only code — the repo has been bitten 13 times by substring
    assertions that matched a comment."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)) and body:
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                body.pop(0)
    return tree


def _code_strings(path: Path) -> list[str]:
    return [n.value for n in ast.walk(_stripped_ast(path))
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


@pytest.mark.parametrize("src", [SRC_COLLECT, SRC_ADMIN])
def test_no_code_path_rebinds_or_names_the_store_port(src):
    """The store has NO authentication; 127.0.0.1:8428 is the only thing
    protecting the whole fleet's telemetry. Nothing in the collection layer may
    name a wildcard bind or hard-code the store port — cross-node access goes
    through the authenticated node channel or not at all."""
    bad = [s for s in _code_strings(src)
           if "0.0.0.0" in s or "8428" in s or "::" == s.strip()]
    assert bad == [], "%s names a store bind address: %r" % (src.name, bad)


# ---------------------------------------------------------------------------
# the store URL was unconfigurable for months and nothing said so
# ---------------------------------------------------------------------------

def test_the_configured_store_url_is_actually_used(app, monkeypatch):
    """Behavioural, because the bug was invisible to every structural check.

    ``vm_store.base_url()`` called ``settings_store.get`` -- an accessor that
    has never existed -- and a broad ``except`` turned the resulting
    ``AttributeError`` into the default URL. Every test passed, the store
    worked, and ``metrics.vm_url`` did nothing.
    """
    from app.services import vm_store, settings_store
    with app.app_context():
        settings_store.set_str("metrics.vm_url", "http://127.0.0.1:9999/")
        assert vm_store.base_url() == "http://127.0.0.1:9999"


def test_an_unset_store_url_still_falls_back(app):
    """Counterweight: the default must survive. A guard that forces the
    operator to configure something they never had to would break every
    existing install."""
    from app.services import vm_store
    with app.app_context():
        assert vm_store.base_url() == vm_store.DEFAULT_URL.rstrip("/")


def test_a_missing_accessor_is_not_swallowed():
    """A name error is a programming mistake. Folding it in with 'outside an
    app context' is what hid this for months."""
    import ast
    src = (_PATHLIB.Path(vm_store_path())).read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "base_url":
            kinds = set()
            for h in ast.walk(node):
                if isinstance(h, ast.ExceptHandler):
                    kinds.add("bare" if h.type is None else ast.unparse(h.type))
            assert "AttributeError" in kinds, (
                "base_url no longer separates a missing accessor from a "
                "missing app context: %s" % sorted(kinds))
            return
    raise AssertionError("base_url is gone")


def vm_store_path():
    import pathlib as _p
    return _p.Path(__file__).resolve().parents[1] / "app" / "services" / "vm_store.py"


import pathlib as _PATHLIB  # noqa: E402
