"""The status badge is probed in THREADS, and a thread does not inherit the app context.

What this file pins down, in one line: **"I cannot read the vault
configuration" is not the same as "the vault is off"**, and confusing the two
marks a responsive appliance as offline.

The real defect (measured 2026-09-14 against the live DB of satom-node-1): the
three appliances in the inventory (fac01, fortiweb15, fortiweb16) came out
`offline` in `GET /api/appliances` while the SAME code, on the main thread,
reported them `online` in 0.08 s. The chain:

1. `api/appliances.list_appliances` probes inside a `ThreadPoolExecutor`.
2. A new thread starts with empty ContextVars -> **no app context**.
3. `secret_backend._raw()` called `AppSetting.get(...)` and swallowed the
   failure with `except Exception: return {}`.
4. Empty config -> `active()` becomes False -> `get_appliance_password()`
   returns None, which means "use the local copy".
5. The local copy is the `__stored-in-vault__` sentinel -> the getter RAISES.
6. `probe_status` swallows the exception and returns `"offline"`.

Neither piece introduced the defect on its own: the pool has existed since the
initial commit and was harmless because the credential path was env + column
(zero DB). The COMBINATION introduced it, the day the credential became able to
live in a vault (2026-08-19). It sat in production for ~3.5 weeks without a
single log line, because "offline" is a perfectly believable answer.

That is why the guards here come in TWO kinds and both are needed:
  - behavioural: the badge route has to say `online`;
  - structural: `_raw()`/`active()` have to FAIL in a thread without context
    instead of answering "off", because otherwise the same symptom reappears
    in the next route that uses threads.
"""
import logging
import threading

import pytest
from flask import has_app_context

from app.models import Appliance, AppSetting, db
from app.services import encryption, secret_backend as sb

from conftest import admin_user_id, login
from test_secret_backend import configure, vault  # noqa: F401  (fixture)


VAULT_PW = "the-one-that-only-lives-in-the-vault"


# ---------------------------------------------------------------------------
# client double
# ---------------------------------------------------------------------------
class _RecordingClient:
    """Fake client that INSISTS on reading the credential, like the real one.

    A double that does not touch `appliance.password` would let the guard pass
    without exercising the one line that breaks. It also records WHICH thread
    it ran on: that is what distinguishes "fixed" from "serialised on the
    request thread", which would also go green and turn the page into N x 6 s.
    """

    seen: list = []
    threads: set = set()

    def __init__(self, appliance, timeout=30.0):
        self.appliance = appliance

    def status_check(self):
        pw = self.appliance.password
        _RecordingClient.seen.append((self.appliance.name, pw))
        _RecordingClient.threads.add(threading.current_thread().name)
        return {"hostName": "FortiWeb", "version": "7.6.8"}


@pytest.fixture()
def rec(monkeypatch):
    _RecordingClient.seen = []
    _RecordingClient.threads = set()
    # client_for() and _own_client() both end up here, so a single patch
    # covers the badge route AND the manual test button.
    monkeypatch.setattr("app.clients.fortiweb.FortiWebClient", _RecordingClient)
    return _RecordingClient


def _vaulted_row(name="fortiweb16", host="192.0.2.28"):
    """A row like those created once the vault is already authoritative: no local copy."""
    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="admin",
                    password_enc=encryption.encrypt(sb.VAULT_SENTINEL))
    db.session.add(row)
    db.session.commit()
    return row


def _arm_vault(app, name="fortiweb16"):
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = _vaulted_row(name)
        sb.write(sb.appliance_path(name), {"password": VAULT_PW})
        return row.id


# ---------------------------------------------------------------------------
# behavioural: the defect the user saw
# ---------------------------------------------------------------------------
def test_the_badge_route_says_online_for_a_vault_backed_appliance(app, client, vault, rec):
    """The reported defect, exactly: the appliance responds and the badge lies."""
    _arm_vault(app)
    login(client, admin_user_id(app))
    body = client.get("/api/appliances").get_json()
    assert [(a["name"], a["status"]) for a in body] == [("fortiweb16", "online")]


def test_the_probe_sends_the_vault_password_not_the_sentinel(app, client, vault, rec):
    """Green does not count if it got there with the wrong credential."""
    _arm_vault(app)
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    assert rec.seen == [("fortiweb16", VAULT_PW)]
    assert all(sb.VAULT_SENTINEL not in pw for _, pw in rec.seen)


def test_every_appliance_is_probed_not_just_the_first(app, client, vault, rec):
    """The defect hit all THREE; a single-appliance guard does not see it."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        for n in ("fac01", "fortiweb15", "fortiweb16"):
            _vaulted_row(n, host="192.0.2.1")
            sb.write(sb.appliance_path(n), {"password": VAULT_PW})
    login(client, admin_user_id(app))
    body = client.get("/api/appliances").get_json()
    assert {a["name"]: a["status"] for a in body} == {
        "fac01": "online", "fortiweb15": "online", "fortiweb16": "online"}


def test_the_probe_still_runs_off_the_request_thread(app, client, vault, rec):
    """Serialising on the request thread also goes green, and it is N x 6 s."""
    _arm_vault(app)
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    assert rec.threads, "nothing was probed"
    assert threading.main_thread().name not in rec.threads


def test_the_cached_status_is_persisted(app, client, vault, rec):
    """Every other view reads `last_status`; they do not probe again."""
    rid = _arm_vault(app)
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    with app.app_context():
        row = db.session.get(Appliance, rid)
        assert row.last_status == "online"
        assert row.last_checked_at is not None


# ---------------------------------------------------------------------------
# structural: the silent degradation that caused it
# ---------------------------------------------------------------------------
def test_the_vault_config_refuses_to_guess_without_an_app_context(app):
    """`{}` would mean "not configured", and that is a made-up answer."""
    assert not has_app_context(), "the guard needs to run OUTSIDE a context"
    with pytest.raises(sb.VaultConfigUnavailable):
        sb._raw()


def test_active_does_not_answer_false_in_a_thread_without_context(app, vault):
    """This is step 4 of the chain: the lie that propagates."""
    with app.app_context():
        configure(sb.MODE_VAULT)
    box = {}

    def worker():
        try:
            box["value"] = sb.active()
        except BaseException as exc:  # noqa: BLE001 — inspected below
            box["error"] = exc

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert "value" not in box, (
        "the vault answered %r from a thread without context" % (box.get("value"),))
    assert isinstance(box["error"], sb.VaultConfigUnavailable)


def test_the_failure_is_not_a_kind_of_vault_error(app):
    """If it inherited from VaultError, `get_appliance_password` would swallow
    it again and return None = "use the local copy" — the degradation, again."""
    assert not issubclass(sb.VaultConfigUnavailable, sb.VaultError)


def test_an_unmigrated_settings_table_is_still_tolerated(app, monkeypatch):
    """A fresh install, before Alembic, must NOT break."""
    def boom(*a, **k):
        raise RuntimeError("no such table: app_settings")

    with app.app_context():
        monkeypatch.setattr(AppSetting, "get", staticmethod(boom))
        assert sb._raw() == {}
        assert sb.active() is False


# ---------------------------------------------------------------------------
# the 3.5-week silence
# ---------------------------------------------------------------------------
def test_a_failed_probe_leaves_a_trace(app, caplog):
    """`offline` is believable, and that is why a mute failure survives for weeks."""
    with app.app_context():
        row = _vaulted_row("fortiweb15")  # sentinel, vault out of the path
        with caplog.at_level(logging.WARNING):
            assert row.probe_status(timeout=0.1) == "offline"
    assert "fortiweb15" in caplog.text, "the warning does not say WHICH one failed"


def test_a_probe_of_a_healthy_box_logs_nothing(app, vault, rec, caplog):
    """A log line per successful probe turns the warning into noise nobody reads."""
    with app.app_context():
        configure(sb.MODE_VAULT)
        row = _vaulted_row()
        sb.write(sb.appliance_path("fortiweb16"), {"password": VAULT_PW})
        with caplog.at_level(logging.WARNING):
            assert row.probe_status(timeout=1.0) == "online"
    assert "fortiweb16" not in caplog.text


# ---------------------------------------------------------------------------
# a probe is not a configuration edit
# ---------------------------------------------------------------------------
def test_a_status_poll_does_not_look_like_a_config_edit(app, client, vault, rec):
    """`updated_at` answers "when was this row edited", not "when was it looked at"."""
    rid = _arm_vault(app)
    with app.app_context():
        before = db.session.get(Appliance, rid).updated_at
    login(client, admin_user_id(app))
    client.get("/api/appliances")
    with app.app_context():
        row = db.session.get(Appliance, rid)
        assert row.updated_at == before
        assert row.last_checked_at is not None  # guard-the-guard: it WAS probed


def test_the_manual_test_button_does_not_look_like_a_config_edit(app, client, vault, rec):
    """Same defect, second route: the button in the appliance list."""
    rid = _arm_vault(app)
    with app.app_context():
        before = db.session.get(Appliance, rid).updated_at
    login(client, admin_user_id(app))
    resp = client.post("/api/appliances/%d/test" % rid)
    assert resp.get_json()["status"] == "online"
    with app.app_context():
        row = db.session.get(Appliance, rid)
        assert row.updated_at == before
        assert row.last_status == "online"


class _DeadClient:
    """Fails with an ANONYMOUS exception: it names no host, appliance or credential."""

    def __init__(self, appliance, timeout=30.0):
        pass

    def status_check(self):
        raise TimeoutError("timed out")


def _plain_row(name, host="192.0.2.27"):
    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="admin", password_enc=encryption.encrypt("pw"))
    db.session.add(row)
    db.session.commit()
    return row


def test_the_trace_names_the_appliance_even_when_the_error_does_not(
        app, monkeypatch, caplog):
    """The trap that let a mutation survive on the first pass.

    `test_a_failed_probe_leaves_a_trace` uses the sentinel failure, and that
    RuntimeError ALREADY carries the appliance name inside it. So the assertion
    `"fortiweb15" in caplog.text` held thanks to the EXCEPTION text even though
    the warning named nothing: removing the `%s` from the format broke
    nothing. A network timeout names nobody, and there it DOES show.
    """
    monkeypatch.setattr("app.clients.fortiweb.FortiWebClient", _DeadClient)
    with app.app_context():
        _plain_row("fortiweb15")
        row = Appliance.query.filter_by(name="fortiweb15").one()
        with caplog.at_level(logging.WARNING):
            assert row.probe_status(timeout=0.1) == "offline"
    assert "fortiweb15" in caplog.text, "the warning does not say WHICH one failed"
    assert "timed out" in caplog.text, "the warning does not say WHY it failed"
