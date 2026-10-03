"""A FortiWeb that refuses the credentials stops discovery at once.

Reported from the field (SI-0001/SI-0002): a rediscovery answered ``HTTP 401``
on all 295 endpoints, then wrote a snapshot with zero objects as the latest
one — "I ran discovery and there is absolutely nothing, not even NTP". Each of
those 295 GETs was a failed admin login on a device whose
``admin-lockout-threshold`` is 3 by default, so the sweep itself kept the
account locked for SATOM and for the humans on the GUI.

The properties fixed here:

* a 401 on the status read stops the sweep after ONE failed login;
* a 401 mid-sweep is re-checked once against status — still 401 stops it,
  a working status means the 401 was that endpoint's and the sweep goes on;
* a sweep in which no endpoint answered writes NO snapshot;
* the error says what to check, not the first bytes of an HTML page;
* the CLI-coverage discovery run (discovery_run.run) lets the error through
  instead of turning it into one more failed candidate.

No device is contacted: ``FortiWebClient._request`` is a scripted fake.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from app.clients import base as client_base
from app.clients.fortiweb import DeviceAuthError, FortiWebClient
from app.services import discovery_run, rediscovery

STATUS = "/api/v2.0/system/status.systemstatus"
PLAN = [{"name": f"ep{i}", "urn": f"/api/v2.0/cmdb/x/ep{i}", "section": "System"}
        for i in range(6)]
APACHE_401 = ('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
              '"http://www.w3.org/TR/html4/strict.dtd">\n<html><head>\n'
              '<title>401 Unauthorized</title>\n</head><body><h1>Unauthorized</h1>'
              '<p>This server could not verify that you are authorized.</p></body></html>')


@pytest.fixture(autouse=True)
def _private_stores(tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))
    monkeypatch.setattr(rediscovery, "_refresh_api_matrix", lambda *a, **k: None)
    monkeypatch.setattr(rediscovery, "_ingest_library", lambda *a, **k: {})
    monkeypatch.setattr(rediscovery, "_persist_firmware", lambda *a, **k: None)
    from app.registry import loader
    monkeypatch.setattr(loader, "version_of", lambda *_a, **_k: "7.6.8")


def _snap(aid=61):
    return SimpleNamespace(id=aid, name="fw-auth", host="fw-auth.test", port=443,
                           verify_ssl=False, username="admin", password="x",
                           vdom="", kind="fortiweb")


def _ok(body=None):
    return httpx.Response(200, json=body if body is not None else {"results": [{"name": "a"}]})


def _denied():
    return httpx.Response(401, text=APACHE_401, headers={"content-type": "text/html"})


def _device(monkeypatch, answer):
    """Route every client call through ``answer(path, n)``; return the call log."""
    calls = []

    def _request(self, method, path, **kwargs):
        calls.append(path)
        return answer(path, len(calls))
    monkeypatch.setattr(FortiWebClient, "_request", _request)
    return calls


def _previous(aid):
    p = rediscovery._dev_dir(aid) / "_config.json"
    p.write_text(json.dumps({"generated_at": "earlier", "total_objects": 99}))
    return p


# --- the message --------------------------------------------------------------

def test_an_html_error_page_is_reduced_to_its_title():
    s = client_base.response_summary(httpx.Response(401, text=APACHE_401))
    assert s == "401 Unauthorized"


def test_an_empty_401_still_says_why_through_its_challenge_header():
    resp = httpx.Response(401, headers={"www-authenticate": 'error="invalid_token"'})
    assert client_base.response_summary(resp) == 'WWW-Authenticate: error="invalid_token"'


def test_status_check_raises_a_typed_error_that_says_what_to_check(monkeypatch):
    _device(monkeypatch, lambda p, n: _denied())
    with pytest.raises(DeviceAuthError) as ei:
        FortiWebClient(_snap()).status_check()
    msg = str(ei.value)
    assert msg.startswith("HTTP 401: the appliance rejected the credentials (401 Unauthorized)")
    assert "admin-lockout-threshold" in msg and "trusted hosts" in msg
    assert "DOCTYPE" not in msg


def test_status_check_still_returns_the_body_when_authorised(monkeypatch):
    _device(monkeypatch, lambda p, n: _ok({"results": {"firmwareVersion": "v7.6.8"}}))
    assert FortiWebClient(_snap()).status_check()["results"]["firmwareVersion"] == "v7.6.8"


# --- the sweep ----------------------------------------------------------------

def test_bad_credentials_stop_the_sweep_after_one_failed_login(app, monkeypatch):
    aid = 61
    prev = _previous(aid)
    calls = _device(monkeypatch, lambda p, n: _denied())
    rediscovery._run(_snap(aid), by="t", plan=PLAN)

    assert calls == [STATUS], f"{len(calls)} failed logins sent; one is the most allowed"
    st = rediscovery.status(aid)
    assert st["state"] == rediscovery.FAILED
    assert "rejected the credentials" in st["error"]
    assert "stopped at endpoint 0/6" in st["error"]
    assert json.loads(prev.read_text())["generated_at"] == "earlier"


def test_a_lockout_mid_sweep_is_confirmed_once_then_stops(app, monkeypatch):
    aid = 62
    prev = _previous(aid)

    def answer(path, n):
        # status + ep0 + ep1 answer; from the 4th call on, the account is locked.
        return _ok({"results": {"firmwareVersion": "7.6.8"}} if path == STATUS else None) \
            if n <= 3 else _denied()
    calls = _device(monkeypatch, answer)
    rediscovery._run(_snap(aid), by="t", plan=PLAN)

    assert calls[3:] == [PLAN[2]["urn"], STATUS], (
        "after the first 401 exactly one confirmation read may follow: %r" % calls)
    st = rediscovery.status(aid)
    assert st["state"] == rediscovery.FAILED
    assert "stopped at endpoint 2/6" in st["error"]
    assert json.loads(prev.read_text())["generated_at"] == "earlier"


def test_a_401_on_one_endpoint_with_working_credentials_does_not_stop(app, monkeypatch):
    aid = 63

    def answer(path, n):
        if path == PLAN[3]["urn"]:
            return _denied()
        return _ok({"results": {"firmwareVersion": "7.6.8"}} if path == STATUS else None)
    _device(monkeypatch, answer)
    rediscovery._run(_snap(aid), by="t", plan=PLAN)

    st = rediscovery.status(aid)
    assert st["state"] == "done"
    snap = json.loads((rediscovery._dev_dir(aid) / "_config.json").read_text())
    assert snap["verdict_counts"] == {"ok": 5, "absent": 0, "error": 1}
    assert snap["errors"][0]["error"].startswith("HTTP 401: 401 Unauthorized")


def test_a_sweep_where_nothing_answered_writes_no_snapshot(app, monkeypatch):
    aid = 64
    prev = _previous(aid)

    def answer(path, n):
        if path == STATUS:
            return _ok({"results": {"firmwareVersion": "7.6.8"}})
        return httpx.Response(500, json={"errcode": "-20010",
                                         "message": "The license of peer VM FortiWeb is not valid"})
    _device(monkeypatch, answer)
    rediscovery._run(_snap(aid), by="t", plan=PLAN)

    st = rediscovery.status(aid)
    assert st["state"] == rediscovery.FAILED
    assert st["error"].startswith("None of the 6 endpoint(s) answered")
    assert "-20010" in st["error"]
    assert json.loads(prev.read_text())["generated_at"] == "earlier"


def test_absent_only_is_not_a_failure(app, monkeypatch):
    """No endpoint ``ok`` but no error either is a real (if empty) answer."""
    aid = 65

    def answer(path, n):
        if path == STATUS:
            return _ok({"results": {"firmwareVersion": "7.6.8"}})
        return httpx.Response(500, json={"errcode": "-20001"})
    _device(monkeypatch, answer)
    rediscovery._run(_snap(aid), by="t", plan=PLAN)
    assert rediscovery.status(aid)["state"] == "done"
    assert (rediscovery._dev_dir(aid) / "_config.json").exists()


# --- the CLI-coverage discovery run --------------------------------------------

def _finding(urns):
    return discovery_run.Finding(path="config x", name="x",
                                 candidates=[discovery_run.Candidate(urn=u) for u in urns])


def test_discovery_run_lets_an_auth_failure_through(monkeypatch):
    seen = []

    def probe(urn):
        seen.append(urn)
        raise DeviceAuthError("HTTP 401")
    with pytest.raises(DeviceAuthError):
        discovery_run.run([_finding(["a", "b"]), _finding(["c"])], probe, budget=10)
    assert seen == ["a"]


def test_discovery_run_still_absorbs_any_other_error():
    f = _finding(["a", "b"])
    calls = []

    def probe(urn):
        calls.append(urn)
        raise RuntimeError("boom")
    res = discovery_run.run([f], probe, budget=10)
    assert calls == ["a", "b"]
    assert res["errors"] == 1
    assert f.candidates[0].detail == "RuntimeError: boom"


# --- FortiADC -----------------------------------------------------------------

def _adc_snap(aid=71):
    return SimpleNamespace(id=aid, name="adc-auth", host="adc-auth.test", port=443,
                           verify_ssl=False, username="admin", password="x",
                           vdom="", kind="fortiadc")


def _adc_device(monkeypatch, answer):
    from app.clients.fortiadc import FortiADCClient
    calls = []

    def _request(self, method, path, **kwargs):
        calls.append(path)
        resp = answer(path, len(calls))
        resp.request = httpx.Request(method, "https://adc-auth.test" + path)
        return resp
    monkeypatch.setattr(FortiADCClient, "_request", _request)
    return calls


def test_adc_bad_credentials_stop_the_sweep_after_one_failed_login(app, monkeypatch):
    """A FortiADC that refuses the login stops the sweep instead of sending
    one failed admin login per endpoint."""
    aid = 71
    prev = _previous(aid)
    monkeypatch.setattr(rediscovery, "_device_firmware", lambda *a, **k: "")
    calls = _adc_device(monkeypatch, lambda p, n: httpx.Response(401, text="denied"))
    rediscovery._run(_adc_snap(aid), by="t", plan=PLAN)
    assert calls == ["/api/user/login"], calls
    st = rediscovery.status(aid)
    assert st["state"] == rediscovery.FAILED
    assert "rejected the credentials" in st["error"]
    assert json.loads(prev.read_text())["generated_at"] == "earlier"


def test_adc_expired_token_is_renewed_once_and_the_sweep_goes_on(app, monkeypatch):
    aid = 72
    monkeypatch.setattr(rediscovery, "_device_firmware", lambda *a, **k: "8.0.3")
    state = {"expired": True}

    def answer(path, n):
        if path == "/api/user/login":
            return httpx.Response(200, json={"token": "t"})
        if path == PLAN[1]["urn"] and state["expired"]:
            state["expired"] = False
            return httpx.Response(401, text="expired")
        return httpx.Response(200, json={"payload": [{"mkey": "a"}]})
    calls = _adc_device(monkeypatch, answer)
    rediscovery._run(_adc_snap(aid), by="t", plan=PLAN)
    assert calls.count("/api/user/login") == 2, calls
    assert rediscovery.status(aid)["state"] == "done"
