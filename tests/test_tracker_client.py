"""Guards for the native issue-tracker integration (services.tracker_client).

The classes of failure these exist to stop — every one of them SILENT, which is
why a test is the only thing that catches them:

* **Vikunja creates with PUT.** ``POST /api/v1/projects/<id>/tasks`` is the
  update verb there. A backend that sends POST looks configured, returns
  something that is not an error, and creates nothing. Nobody finds out until
  an approver asks where the ticket is.
* **Jira v3 will not take a string description.** It takes Atlassian Document
  Format. Posting a string yields a 400 whose message reads like a permissions
  problem, so the operator rotates a perfectly good token.
* **The API token leaking** into a flash message, an audit row or a support
  ticket through a ``detail`` string. OpenProject echoes the request back in
  its error bodies.
* **A 2xx with no id reported as success.** A tracker behind a proxy that
  answers 200 with an HTML login page would otherwise stamp an empty reference
  onto the change and report a ticket that does not exist.
* **A green tick that only proves authentication.** A token that authenticates
  but cannot see the project fails at the one moment anyone cares — while a
  change window is opening.
* **A second ticket for the same window.** A double-click, a browser retry or a
  second operator must not each produce another CRQ; change management then has
  no way to tell which one is real.
* An unbounded call to somebody else's SaaS hanging a gunicorn worker.

Every HTTP call is faked. Nothing here touches a real tracker.
"""
from __future__ import annotations

import importlib
import sys

import httpx
import pytest

from app.services import tracker_client as tc

TOKEN = "abcd1234abcd1234abcd1234abcd1234"
BASE = "https://tracker.test"


# ── fake HTTP layer ─────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else (
            str(payload) if payload is not None else "")

    def json(self):
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


def _install(monkeypatch, handler):
    """Replace httpx.Client. Returns (calls, inits) recording lists."""
    calls: list[dict] = []
    inits: list[dict] = []

    class _Client:
        def __init__(self, **kwargs):
            inits.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def request(self, method, url, json=None, params=None):
            calls.append({"method": method, "url": url, "json": json,
                          "params": params, "headers": inits[-1].get("headers")})
            out = handler(method, url, json, params) if callable(handler) else handler
            if isinstance(out, Exception):
                raise out
            return out

    monkeypatch.setattr(tc.httpx, "Client", _Client)
    return calls, inits


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield


def _setup(backend="jira", **over):
    form = {"backend": backend, "enabled": "1", "url": BASE, "token": TOKEN,
            "verify_tls": "1", "timeout": "8", "user": "ops@example.com",
            "project": "OPS", "issue_type": "Task"}
    form.update(over)
    tc.save_config(form)


PAYLOAD = {
    "cr_id": 412, "cr_ref": "CR-2026-0412", "title": "FortiWeb fleet 7.6.2",
    "action": "upgrade", "risk": "high", "reason": "CVE-2026-1234",
    "device_ids": [3, 7], "device_count": 2,
    "devices": [{"appliance": "fortiweb01"}, {"appliance": "fortiweb02"}],
    "evidence_missing": ["fortiweb02"], "policies": ["pol-shop"],
    "policy_count": 1, "policies_truncated": False,
    "approval_mode": "external", "crq_ref": "",
    "window_start": "2026-08-15T22:00:00Z", "window_end": "2026-08-16T02:00:00Z",
    "requested_by": "alice",
}


# ── import purity ───────────────────────────────────────────────────────────

def test_import_touches_no_db_and_no_network(monkeypatch):
    """No app context is active here: a DB read at import time would raise."""
    original = sys.modules.pop("app.services.tracker_client")

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("tracker_client opened a connection at import")

    monkeypatch.setattr(httpx, "Client", _Boom)
    try:
        fresh = importlib.import_module("app.services.tracker_client")
        assert fresh.BACKEND_SLUGS == ("none", "jira", "openproject", "vikunja")
    finally:
        sys.modules["app.services.tracker_client"] = original


# ── config + secret handling ────────────────────────────────────────────────

def test_blank_token_keeps_the_stored_one(ctx):
    _setup()
    tc.save_config({"backend": "jira", "url": BASE, "token": ""})
    assert tc.config(reveal=True)["token"] == TOKEN


def test_clear_token_wipes_it(ctx):
    _setup()
    tc.save_config({"clear_token": "1"})
    assert tc.config()["has_token"] is False


def test_unknown_backend_raises_rather_than_falling_back(ctx):
    """A silently rewritten backend sends the ticket somewhere the operator did
    not choose. Every other field on that form is fixable in place."""
    _setup()
    with pytest.raises(ValueError) as exc:
        tc.save_config({"backend": "trac"})
    assert "trac" in str(exc.value)
    assert tc.config()["backend"] == "jira"


def test_corrupted_backend_row_reads_back_as_none(ctx):
    _setup()
    tc.store.set_str(tc.K_BACKEND, "wat")
    assert tc.config()["backend"] == "none"


def test_absent_key_leaves_setting_untouched(ctx):
    """HTML omits unchecked checkboxes; an absent verify_tls must not silently
    downgrade TLS on an unrelated save."""
    _setup()
    tc.save_config({"url": "https://other.test"})
    assert tc.config()["verify_tls"] is True


def test_timeout_is_clamped(ctx):
    _setup(timeout="9999")
    assert tc.config()["timeout"] == tc.MAX_TIMEOUT
    _setup(timeout="nonsense")
    assert tc.config()["timeout"] == tc.DEFAULT_TIMEOUT


def test_is_configured_requires_a_project(ctx):
    _setup(project="")
    assert tc.is_configured() is False
    _setup()
    assert tc.is_configured() is True


# ── the gate ────────────────────────────────────────────────────────────────

def test_disabled_is_named_never_silent(ctx):
    _setup(enabled="0")
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is False
    assert tc.DETAIL_DISABLED in out["detail"]


def test_backend_none_refuses_by_name(ctx):
    _setup(backend="none")
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is False and out["backend"] == "none"
    assert tc.K_BACKEND in out["detail"]


def test_missing_jira_email_is_named(ctx):
    _setup(user="")
    assert tc.K_USER in tc.create_ticket(PAYLOAD)["detail"]


def test_missing_project_is_named(ctx):
    _setup(project="")
    assert tc.K_PROJECT in tc.create_ticket(PAYLOAD)["detail"]


def test_openproject_does_not_demand_a_username(ctx):
    """Its username is the constant 'apikey'. Demanding one would block a
    correct configuration."""
    _setup("openproject", user="", project="7", issue_type="1")
    assert tc._gate(tc.config(reveal=True)) == ""


# ── auth schemes ────────────────────────────────────────────────────────────

def test_jira_uses_basic_with_the_account_email(ctx):
    _setup()
    import base64
    hdr = tc._auth_headers(tc.config(reveal=True))["Authorization"]
    assert hdr.startswith("Basic ")
    assert base64.b64decode(hdr[6:]).decode() == f"ops@example.com:{TOKEN}"


def test_openproject_uses_the_literal_username_apikey(ctx):
    """Using the operator's e-mail here 401s in a way that looks exactly like a
    bad token, and they rotate a good one."""
    _setup("openproject", user="ops@example.com", project="7")
    import base64
    hdr = tc._auth_headers(tc.config(reveal=True))["Authorization"]
    assert base64.b64decode(hdr[6:]).decode() == f"apikey:{TOKEN}"


def test_vikunja_uses_bearer(ctx):
    _setup("vikunja", project="3")
    assert tc._auth_headers(tc.config(reveal=True))["Authorization"] \
        == f"Bearer {TOKEN}"


# ── per-backend request shape ───────────────────────────────────────────────

def test_jira_posts_adf_never_a_string(ctx, monkeypatch):
    _setup()
    calls, _ = _install(monkeypatch, _Resp(201, {"id": "1", "key": "OPS-14"}))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is True
    body = calls[0]["json"]["fields"]
    assert isinstance(body["description"], dict)
    assert body["description"]["type"] == "doc"
    assert body["description"]["version"] == 1
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"].endswith("/rest/api/3/issue")


def test_jira_ref_is_the_key_and_url_is_browsable(ctx, monkeypatch):
    """`self` points at the REST resource. Handing an approver a JSON URL is
    the same defect as handing them a list of database ids."""
    _setup()
    _install(monkeypatch, _Resp(
        201, {"id": "1", "key": "OPS-14",
              "self": f"{BASE}/rest/api/3/issue/1"}))
    out = tc.create_ticket(PAYLOAD)
    assert out["ref"] == "OPS-14"
    assert out["url"] == f"{BASE}/browse/OPS-14"
    assert "rest/api" not in out["url"]


def test_adf_emits_no_empty_text_node(ctx):
    """ADF rejects {"type":"text","text":""} with a 400 that names no field."""
    doc = tc._adf("a\n\n\nb\n")
    texts = [n["content"][0]["text"] for n in doc["content"]]
    assert texts == ["a", "b"]
    assert all(t for t in texts)
    assert tc._adf("")["content"] == []


def test_openproject_sends_the_type_link_and_suppresses_notification(ctx, monkeypatch):
    _setup("openproject", project="7", issue_type="1")
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 91}))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is True and out["ref"] == "WP-91"
    assert out["url"] == f"{BASE}/work_packages/91"
    assert calls[0]["json"]["_links"]["type"]["href"] == "/api/v3/types/1"
    assert calls[0]["json"]["description"]["format"] == "markdown"
    assert calls[0]["params"] == {"notify": "false"}
    assert calls[0]["url"].endswith("/api/v3/projects/7/work_packages")


def test_vikunja_creates_with_PUT_not_POST(ctx, monkeypatch):
    """The whole point. POST is Vikunja's UPDATE verb: a POST here creates
    nothing and does not look like a failure."""
    _setup("vikunja", project="3")
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 55, "identifier": "#55"}))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is True
    assert calls[0]["method"] == "PUT"
    assert calls[0]["url"].endswith("/api/v1/projects/3/tasks")
    assert out["url"] == f"{BASE}/tasks/55"


# ── failures that must not look like successes ──────────────────────────────

@pytest.mark.parametrize("backend,project,body", [
    ("jira", "OPS", {"id": "1"}),                 # no key
    ("openproject", "7", {"subject": "x"}),       # no id
    ("vikunja", "3", {"title": "x"}),             # no id
])
def test_2xx_without_an_id_is_not_a_success(ctx, monkeypatch, backend, project, body):
    _setup(backend, project=project)
    _install(monkeypatch, _Resp(200, body))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is False and out["ref"] == ""


def test_auth_failure_is_labelled_and_redacted(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, _Resp(401, None, text=f"bad token {TOKEN} rejected"))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is False
    assert tc.DETAIL_AUTH in out["detail"]
    assert TOKEN not in out["detail"]
    assert tc.REDACTED in out["detail"]


def test_error_body_echoing_the_token_is_redacted(ctx, monkeypatch):
    """OpenProject echoes the request back in error bodies."""
    _setup("openproject", project="7")
    _install(monkeypatch, _Resp(422, None, text=f'{{"auth":"Basic {TOKEN}"}}'))
    assert TOKEN not in tc.create_ticket(PAYLOAD)["detail"]


def test_timeout_is_reported_not_raised(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, httpx.ConnectTimeout("slow"))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is False and tc.DETAIL_TIMEOUT in out["detail"]


def test_a_broken_backend_cannot_raise_out_of_create_ticket(ctx, monkeypatch):
    """A tracker outage must never be able to throw out of a change request."""
    _setup()
    monkeypatch.setitem(tc._CREATORS, "jira",
                        lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    out = tc.create_ticket(PAYLOAD)
    assert out["ok"] is False and "boom" in out["detail"]


# ── transport hardening ─────────────────────────────────────────────────────

def test_both_timeout_legs_are_bounded(ctx, monkeypatch):
    _setup(timeout="30")
    _, inits = _install(monkeypatch, _Resp(201, {"key": "OPS-1", "id": "1"}))
    tc.create_ticket(PAYLOAD)
    timeout = inits[0]["timeout"]
    assert timeout.connect <= tc.MAX_CONNECT_S
    assert timeout.read == 30


def test_redirects_are_not_followed(ctx, monkeypatch):
    """A tracker behind a proxy that 302s to a login page would otherwise turn
    an auth failure into a 200 with an HTML body."""
    _setup()
    _, inits = _install(monkeypatch, _Resp(201, {"key": "OPS-1", "id": "1"}))
    tc.create_ticket(PAYLOAD)
    assert inits[0]["follow_redirects"] is False


def test_verify_tls_reaches_the_client(ctx, monkeypatch):
    _setup(verify_tls="0")
    _, inits = _install(monkeypatch, _Resp(201, {"key": "OPS-1", "id": "1"}))
    tc.create_ticket(PAYLOAD)
    assert inits[0]["verify"] is False


# ── ticket content ──────────────────────────────────────────────────────────

def test_ticket_names_appliances_and_missing_baselines(ctx):
    summary, body = tc.render_ticket(PAYLOAD)
    assert summary == "[CR-2026-0412] FortiWeb fleet 7.6.2"
    assert "fortiweb01" in body and "fortiweb02" in body
    assert "NO stored pre-upgrade run: fortiweb02" in body


def test_no_missing_baseline_says_none_not_an_empty_list(ctx):
    body = tc.render_ticket({**PAYLOAD, "evidence_missing": []})[1]
    assert "NO stored pre-upgrade run: none" in body


def test_external_gate_is_stated_only_when_it_holds(ctx):
    assert "HOLDS THE GATE" in tc.render_ticket(PAYLOAD)[1]
    assert "HOLDS THE GATE" not in tc.render_ticket(
        {**PAYLOAD, "approval_mode": "manual"})[1]


def test_summary_is_capped(ctx):
    summary, _ = tc.render_ticket({**PAYLOAD, "title": "x" * 500})
    assert len(summary) <= tc.MAX_SUMMARY


# ── the test button ─────────────────────────────────────────────────────────

def test_probe_checks_the_project_not_just_the_credential(ctx, monkeypatch):
    """A token that authenticates but cannot see the project must NOT show a
    green tick — it fails while a change window is opening."""
    def handler(method, url, json, params):
        if "myself" in url:
            return _Resp(200, {"displayName": "Ops Bot"})
        return _Resp(404, None, text="No project could be found")

    _setup()
    calls, _ = _install(monkeypatch, handler)
    out = tc.test_connection()
    assert out["ok"] is False
    assert out["who"] == "Ops Bot"          # auth DID succeed, and says so
    assert "OPS" in out["detail"]
    assert len(calls) == 2


def test_probe_reports_who_and_project_on_success(ctx, monkeypatch):
    def handler(method, url, json, params):
        if "myself" in url:
            return _Resp(200, {"displayName": "Ops Bot"})
        return _Resp(200, {"name": "Operations"})

    _setup()
    _install(monkeypatch, handler)
    out = tc.test_connection()
    assert out["ok"] is True
    assert "Ops Bot" in out["detail"] and "Operations" in out["detail"]
    assert out["elapsed_ms"] >= 0


def test_probe_on_a_disabled_integration_is_a_named_refusal(ctx):
    _setup(enabled="0")
    out = tc.test_connection()
    assert out["ok"] is False and tc.DETAIL_DISABLED in out["detail"]


# ── idempotency at the orchestrator ─────────────────────────────────────────

def test_a_change_that_already_has_a_ref_gets_no_second_ticket(ctx, monkeypatch):
    """A double-click, a browser retry or a second operator must not each open
    another CRQ for the same window."""
    from app.services import cr_orchestrator as orch

    _setup()
    created: list = []
    monkeypatch.setattr(tc, "create_ticket",
                        lambda p: created.append(p) or {"ok": True, "ref": "X-1"})
    monkeypatch.setattr(orch, "_policy_names", lambda cr: [])
    monkeypatch.setattr(orch, "_evidence_rows", lambda cr: ([], []))
    monkeypatch.setattr(orch, "_device_rows", lambda cr: [])
    monkeypatch.setattr(orch, "_log", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_event", lambda *a, **k: None)
    monkeypatch.setattr(orch, "record_crq", lambda *a, **k: None)

    import app.services.integration_hooks as hooks
    monkeypatch.setattr(hooks, "dispatch", lambda *a, **k: [])

    class _CR:
        id = 1
        ref = "CR-1"
        title = "t"
        status = "draft"
        action = "upgrade"
        risk = "low"
        reason = ""
        device_ids_list: list = []
        approval_mode = "manual"
        crq_ref = "OPS-9"          # <- already ticketed
        window_start = None
        window_end = None
        requested_by = "alice"

    out = orch.request_crq(_CR(), by="alice")
    assert created == []
    assert out["tracker"]["attempted"] is False
    assert "OPS-9" in out["tracker"]["detail"]
