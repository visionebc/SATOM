"""Guards for the NetBox integration (services.netbox_client).

The classes of failure these exist to stop, all of them silent:

* a naive timestamp sent to NetBox is read in the NetBox server's local
  timezone, so the recorded window is offset from the real one and the upgrade
  runs OUTSIDE its own change window;
* the API token — the customer's source-of-truth credential — leaking into a
  flash message, an audit row or a support ticket via a ``detail`` string;
* an unbounded call to a management host that is normally unreachable, hanging
  a gunicorn worker instead of erroring in seconds;
* a disabled or unreachable integration that looks like a successful one, so
  nobody notices the change record was never written;
* closing a journal-backed window by EDITING the opening entry, which destroys
  the record of when the window opened — the one thing an auditor asks for.

Every HTTP call is faked. Nothing here touches a real NetBox.
"""
from __future__ import annotations

import importlib
import sys
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.services import netbox_client as nb

TOKEN = "0123456789abcdef0123456789abcdef01234567"
BASE = "http://netbox.test"


# ── fake HTTP layer ─────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else (str(payload) if payload is not None else "")

    def json(self):
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


def _install(monkeypatch, handler):
    """Replace httpx.Client. Returns (calls, inits) recording lists.

    *handler* is a ``_Resp``, an ``Exception`` (raised), or a callable
    ``(method, url, json, params) -> _Resp | Exception``."""
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
            calls.append({"method": method, "url": url, "json": json, "params": params})
            out = handler(method, url, json, params) if callable(handler) else handler
            if isinstance(out, Exception):
                raise out
            return out

    monkeypatch.setattr(nb.httpx, "Client", _Client)
    return calls, inits


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield


def _setup(**over):
    form = {"enabled": "1", "url": BASE, "token": TOKEN, "verify_tls": "1",
            "timeout": "8", "mw_backend": "journal", "device_map": {"1": 7}}
    form.update(over)
    nb.save_config(form)


# ── import purity ───────────────────────────────────────────────────────────

def test_import_touches_no_db_and_no_network(monkeypatch):
    """No app context is active here: a DB read at import time would raise.
    Constructing a client would too."""
    original = sys.modules.pop("app.services.netbox_client")

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("netbox_client opened a connection at import time")

    monkeypatch.setattr(httpx, "Client", _Boom)
    try:
        fresh = importlib.import_module("app.services.netbox_client")
        assert fresh.MW_BACKEND_SLUGS == ("journal", "tag", "custom_field")
    finally:
        sys.modules["app.services.netbox_client"] = original


# ── config + secret handling ────────────────────────────────────────────────

def test_token_is_stored_encrypted_never_plain(ctx):
    from app.models import AppSetting
    _setup()
    raw = AppSetting.get(nb.K_TOKEN)
    assert raw and TOKEN not in raw          # nothing plaintext at rest
    assert nb.config(reveal=True)["token"] == TOKEN


def test_config_hides_token_unless_revealed(ctx):
    _setup()
    cfg = nb.config()
    assert cfg["has_token"] is True
    assert cfg["token"] == ""
    assert TOKEN not in str(cfg)


def test_blank_token_keeps_the_existing_one(ctx):
    _setup()
    nb.save_config({"url": "http://other.test", "token": ""})
    cfg = nb.config(reveal=True)
    assert cfg["token"] == TOKEN             # re-saving the form never wipes it
    assert cfg["url"] == "http://other.test"


def test_clear_token_is_the_only_way_to_wipe(ctx):
    _setup()
    nb.save_config({"clear_token": "1"})
    assert nb.config()["has_token"] is False


def test_absent_key_leaves_verify_tls_untouched(ctx):
    """HTML omits unchecked checkboxes; an absent flag must not silently
    downgrade TLS verification on an unrelated save."""
    _setup(verify_tls="1")
    nb.save_config({"url": BASE})
    assert nb.config()["verify_tls"] is True


def test_timeout_is_hard_capped_floored_and_defaulted(ctx):
    _setup(timeout="900")
    assert nb.config()["timeout"] == nb.MAX_TIMEOUT
    nb.save_config({"timeout": "0"})
    assert nb.config()["timeout"] == nb.MIN_TIMEOUT
    nb.save_config({"timeout": "soon"})
    assert nb.config()["timeout"] == nb.DEFAULT_TIMEOUT


def test_mw_backend_defaults_to_journal_and_rejects_junk(ctx):
    assert nb.config()["mw_backend"] == nb.DEFAULT_MW_BACKEND == "journal"
    nb.save_config({"mw_backend": "plugin"})   # no plugin backend exists
    assert nb.config()["mw_backend"] == "journal"
    assert nb.config()["mw_backend"] in nb.MW_BACKEND_SLUGS


def test_mw_backends_carry_human_labels():
    slugs = [s for s, _ in nb.MW_BACKENDS]
    assert slugs == ["journal", "tag", "custom_field"]
    assert all(label and label != slug for slug, label in nb.MW_BACKENDS)


def test_is_configured_needs_enabled_url_and_token(ctx):
    assert nb.is_configured() is False
    _setup()
    assert nb.is_configured() is True
    nb.save_config({"enabled": "0"})
    assert nb.is_configured() is False


# ── device map ──────────────────────────────────────────────────────────────

def test_device_map_round_trips_and_drops_blanks(ctx):
    nb.save_device_map({"1": "7", "2": "", "3": None})
    assert nb.device_map() == {"1": 7}        # blank = unmapped, never 0


def test_device_map_rejects_non_integer_naming_the_row(ctx):
    with pytest.raises(ValueError) as exc:
        nb.save_device_map({"1": "fortiweb08"})
    assert "fortiweb08" in str(exc.value) and "'1'" in str(exc.value)
    with pytest.raises(ValueError) as exc2:
        nb.save_device_map({"fw08": "7"})
    assert "fw08" in str(exc2.value)


# ── failure taxonomy ────────────────────────────────────────────────────────

def test_disabled_short_circuits_every_call(ctx, monkeypatch):
    _setup(enabled="0")
    calls, _ = _install(monkeypatch, _Resp(200, {"ok": True}))

    ok, _payload, detail = nb.request("GET", "/api/status/")
    assert ok is False and nb.DETAIL_DISABLED in detail

    probe = nb.test_connection()
    assert probe["ok"] is False and nb.DETAIL_DISABLED in probe["detail"]

    opened = nb.open_window(1, cr_id="CR-1", title="t",
                            start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                            reason="r")
    assert opened["ok"] is False and nb.DETAIL_DISABLED in opened["detail"]
    assert opened["ref"] == ""               # disabled is never a closable success

    closed = nb.close_window("journal:12", ok=True, summary="s")
    assert closed["ok"] is False and nb.DETAIL_DISABLED in closed["detail"]

    assert nb.list_devices() == []
    assert calls == []                        # and NOTHING was sent


def test_not_configured_is_distinct_from_disabled(ctx, monkeypatch):
    calls, _ = _install(monkeypatch, _Resp(200, {}))
    nb.save_config({"enabled": "1", "url": "", "token": TOKEN})
    ok, _p, detail = nb.request("GET", "/api/status/")
    assert ok is False
    assert nb.DETAIL_NOT_CONFIGURED in detail and nb.DETAIL_DISABLED not in detail
    assert calls == []


def test_unreachable_and_auth_rejected_are_distinguishable(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, httpx.ConnectError("connection refused"))
    _ok, _p, unreachable = nb.request("GET", "/api/status/")

    _install(monkeypatch, _Resp(403, None, text='{"detail":"Invalid v1 token"}'))
    _ok, _p, rejected = nb.request("GET", "/api/status/")

    assert nb.DETAIL_UNREACHABLE in unreachable
    assert nb.DETAIL_AUTH in rejected
    # "NetBox said no" must never read like "NetBox never answered".
    assert nb.DETAIL_AUTH not in unreachable
    assert nb.DETAIL_UNREACHABLE not in rejected


def test_timeout_is_its_own_reason(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, httpx.ReadTimeout("timed out"))
    ok, _p, detail = nb.request("GET", "/api/status/")
    assert ok is False and nb.DETAIL_TIMEOUT in detail


def test_http_4xx_is_distinct_from_transport_failure(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, _Resp(400, None, text='{"comments":["This field is required."]}'))
    ok, payload, detail = nb.request("POST", "/api/extras/journal-entries/", json={})
    assert ok is False and payload is None
    assert detail.startswith(nb.DETAIL_HTTP) and "400" in detail
    assert nb.DETAIL_UNREACHABLE not in detail


def test_nothing_escapes_the_module(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, RuntimeError("something exotic"))
    ok, _p, detail = nb.request("GET", "/api/status/")   # must not raise
    assert ok is False and detail


# ── token redaction ─────────────────────────────────────────────────────────

def test_token_never_appears_in_an_http_error_detail(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, _Resp(400, None,
                                text=f'{{"detail":"bad header Authorization: Token {TOKEN}"}}'))
    _ok, _p, detail = nb.request("GET", "/api/status/")
    assert TOKEN not in detail and nb.REDACTED in detail


def test_token_never_appears_in_an_exception_detail(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, httpx.ConnectError(f"failed with Token {TOKEN}"))
    _ok, _p, detail = nb.request("GET", "/api/status/")
    assert TOKEN not in detail


def test_token_never_appears_in_a_window_result(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, _Resp(500, None, text=f"upstream said {TOKEN}"))
    res = nb.open_window(1, cr_id="CR-9", title="t",
                         start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                         reason="r")
    assert res["ok"] is False and TOKEN not in str(res)


def test_redact_scrubs_bare_keys_and_token_headers():
    assert TOKEN not in nb._redact(f"leaked {TOKEN} here")
    assert TOKEN not in nb._redact(f"Authorization: Token {TOKEN}")


# ── timeout wiring ──────────────────────────────────────────────────────────

def test_every_call_bounds_both_connect_and_read(ctx, monkeypatch):
    _setup(timeout="6")
    _calls, inits = _install(monkeypatch, _Resp(200, {"netbox-version": "4.6.7"}))
    nb.request("GET", "/api/status/")
    timeout = inits[0]["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.read == 6 and timeout.write == 6 and timeout.pool == 6
    assert timeout.connect is not None and timeout.connect <= min(nb.MAX_CONNECT_S, 6)
    # no leg left unbounded
    assert all(v is not None for v in
               (timeout.connect, timeout.read, timeout.write, timeout.pool))


def test_verify_tls_setting_reaches_the_client(ctx, monkeypatch):
    _setup(verify_tls="0")
    _calls, inits = _install(monkeypatch, _Resp(200, {}))
    nb.request("GET", "/api/status/")
    assert inits[0]["verify"] is False


# ── datetimes (the hour-shift guard) ────────────────────────────────────────

def test_journal_window_sends_offset_aware_utc(ctx, monkeypatch):
    _setup()
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 12}))
    res = nb.open_window(1, cr_id="CR-42", title="7.6.2 upgrade",
                         start=datetime(2026, 8, 10, 2, 0),      # naive = UTC
                         end=datetime(2026, 8, 10, 4, 0),
                         reason="quarterly firmware")
    assert res["ok"] is True
    comments = calls[0]["json"]["comments"]
    assert "Start: 2026-08-10T02:00:00+00:00" in comments
    assert "End: 2026-08-10T04:00:00+00:00" in comments
    # a bare naive stamp anywhere in the payload is the bug this test exists for
    assert "2026-08-10T02:00:00\n" not in comments


def test_aware_non_utc_is_converted_not_relabelled(ctx, monkeypatch):
    _setup()
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 12}))
    zurich = timezone(timedelta(hours=2))
    nb.open_window(1, cr_id="CR-42", title="t",
                   start=datetime(2026, 8, 10, 4, 0, tzinfo=zurich),
                   end=datetime(2026, 8, 10, 6, 0, tzinfo=zurich), reason="r")
    comments = calls[0]["json"]["comments"]
    assert "Start: 2026-08-10T02:00:00+00:00" in comments   # 04:00+02:00 == 02:00Z
    assert "+02:00" not in comments


def test_custom_field_patch_sends_offset_aware_utc(ctx, monkeypatch):
    _setup(mw_backend="custom_field")

    def handler(method, url, json, params):
        if "custom-fields" in url:
            return _Resp(200, {"results": [
                {"name": nb.CF_START, "object_types": ["dcim.device"]},
                {"name": nb.CF_END, "object_types": ["dcim.device"]}]})
        return _Resp(200, {"id": 7})

    calls, _ = _install(monkeypatch, handler)
    res = nb.open_window(1, cr_id="CR-1", title="t",
                         start="2026-08-10T02:00:00", end="2026-08-10T04:00:00",
                         reason="r")
    assert res["ok"] is True
    patch = [c for c in calls if c["method"] == "PATCH"][0]
    fields = patch["json"]["custom_fields"]
    assert fields[nb.CF_START].endswith("+00:00")
    assert fields[nb.CF_END].endswith("+00:00")


def test_unusable_datetime_refuses_rather_than_guessing(ctx, monkeypatch):
    _setup()
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 12}))
    res = nb.open_window(1, cr_id="CR-1", title="t", start="not a date",
                         end=datetime(2026, 8, 10, 4), reason="r")
    assert res["ok"] is False and res["ref"] == ""
    assert "start" in res["detail"]
    assert calls == []


# ── refs ────────────────────────────────────────────────────────────────────

def test_ref_round_trips_for_every_backend():
    for backend, ident in (("journal", 12), ("tag", 7), ("custom_field", 7)):
        ref = nb.make_ref(backend, ident)
        assert nb.parse_ref(ref) == (backend, ident)
    assert nb.parse_ref("garbage") == ("", 0)
    assert nb.parse_ref("journal:abc") == ("", 0)
    assert nb.parse_ref("") == ("", 0)


def test_close_uses_the_backend_from_the_ref_not_the_setting(ctx, monkeypatch):
    """An operator who switches mw_backend mid-flight must still be able to
    close windows opened the old way, or devices stay tagged forever."""
    _setup(mw_backend="tag")

    def handler(method, url, json, params):
        if url.endswith("/api/extras/journal-entries/12/"):
            return _Resp(200, {"id": 12, "assigned_object_id": 7})
        return _Resp(201, {"id": 13})

    calls, _ = _install(monkeypatch, handler)
    res = nb.close_window("journal:12", ok=True, summary="done")
    assert res["ok"] is True
    assert all("dcim/devices" not in c["url"] for c in calls)


# ── journal backend ─────────────────────────────────────────────────────────

def test_journal_close_appends_a_second_entry_and_never_edits_the_first(ctx, monkeypatch):
    _setup()

    def handler(method, url, json, params):
        if url.endswith("/api/extras/journal-entries/12/"):
            return _Resp(200, {"id": 12, "assigned_object_id": 7})
        return _Resp(201, {"id": 13})

    calls, _ = _install(monkeypatch, handler)
    res = nb.close_window("journal:12", ok=True, summary="upgrade verified")
    assert res["ok"] is True

    # the opening entry is READ, never mutated
    assert not [c for c in calls
                if c["method"] in ("PATCH", "PUT", "DELETE")
                and "journal-entries/12" in c["url"]]
    posts = [c for c in calls
             if c["method"] == "POST" and c["url"].endswith("/api/extras/journal-entries/")]
    assert len(posts) == 1
    body = posts[0]["json"]
    assert body["assigned_object_id"] == 7
    assert body["assigned_object_type"] == "dcim.device"
    assert "#12" in body["comments"] and "Result: OK" in body["comments"]
    assert body["kind"] == "success"


def test_journal_close_marks_a_failed_change_danger(ctx, monkeypatch):
    _setup()

    def handler(method, url, json, params):
        if url.endswith("/journal-entries/12/"):
            return _Resp(200, {"id": 12, "assigned_object_id": 7})
        return _Resp(201, {"id": 13})

    calls, _ = _install(monkeypatch, handler)
    nb.close_window("journal:12", ok=False, summary="rolled back")
    body = [c for c in calls if c["method"] == "POST"][0]["json"]
    assert body["kind"] == "danger" and "Result: FAILED" in body["comments"]


# ── tag backend ─────────────────────────────────────────────────────────────

def test_tag_open_preserves_existing_tags(ctx, monkeypatch):
    """NetBox REPLACES the tag list on PATCH — sending only our tag would wipe
    the customer's."""
    _setup(mw_backend="tag")

    def handler(method, url, json, params):
        if "extras/tags" in url:
            return _Resp(200, {"results": [{"id": 1, "name": nb.MAINT_TAG_NAME}]})
        if method == "GET":
            return _Resp(200, {"id": 7, "tags": [{"name": "prod"}]})
        return _Resp(200, {"id": 7})

    calls, _ = _install(monkeypatch, handler)
    res = nb.open_window(1, cr_id="CR-1", title="t",
                         start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                         reason="r")
    assert res["ok"] is True and res["ref"] == "tag:7"
    patch = [c for c in calls if c["method"] == "PATCH"][0]
    names = [t["name"] for t in patch["json"]["tags"]]
    assert names == ["prod", nb.MAINT_TAG_NAME]
    assert "not which one" in res["detail"]     # the lossiness is stated


def test_tag_is_created_with_a_slug_when_missing(ctx, monkeypatch):
    """A name-only POST is rejected by NetBox with
    {"slug": ["This field is required."]}."""
    _setup(mw_backend="tag")
    state = {"exists": False}

    def handler(method, url, json, params):
        if "extras/tags" in url:
            if method == "POST":
                state["exists"] = True
                return _Resp(201, {"id": 1})
            return _Resp(200, {"results": [{"id": 1}] if state["exists"] else []})
        if method == "GET":
            return _Resp(200, {"id": 7, "tags": []})
        return _Resp(200, {"id": 7})

    calls, _ = _install(monkeypatch, handler)
    assert nb.open_window(1, cr_id="CR-1", title="t",
                          start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                          reason="r")["ok"] is True
    created = [c for c in calls if c["method"] == "POST" and "extras/tags" in c["url"]][0]
    assert created["json"]["name"] == nb.MAINT_TAG_NAME
    assert created["json"]["slug"] == nb.MAINT_TAG_NAME


def test_tag_close_removes_only_the_maintenance_tag(ctx, monkeypatch):
    _setup(mw_backend="tag")

    def handler(method, url, json, params):
        if method == "GET":
            return _Resp(200, {"id": 7, "tags": [{"name": "prod"},
                                                 {"name": nb.MAINT_TAG_NAME}]})
        return _Resp(200, {"id": 7})

    calls, _ = _install(monkeypatch, handler)
    res = nb.close_window("tag:7", ok=True, summary="done")
    assert res["ok"] is True
    patch = [c for c in calls if c["method"] == "PATCH"][0]
    assert [t["name"] for t in patch["json"]["tags"]] == ["prod"]


# ── custom_field backend ────────────────────────────────────────────────────

def test_custom_field_missing_names_the_field_and_writes_nothing(ctx, monkeypatch):
    _setup(mw_backend="custom_field")

    def handler(method, url, json, params):
        if "custom-fields" in url:
            return _Resp(200, {"results": [
                {"name": nb.CF_START, "object_types": ["dcim.device"]}]})
        return _Resp(200, {"id": 7})

    calls, _ = _install(monkeypatch, handler)
    res = nb.open_window(1, cr_id="CR-1", title="t",
                         start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                         reason="r")
    assert res["ok"] is False and res["ref"] == ""
    assert nb.CF_END in res["detail"]                 # NAMES the missing field
    assert not [c for c in calls if c["method"] == "PATCH"]   # no silent no-op


def test_custom_field_close_clears_both_fields(ctx, monkeypatch):
    _setup(mw_backend="custom_field")
    calls, _ = _install(monkeypatch, _Resp(200, {"id": 7}))
    res = nb.close_window("cf:7", ok=True, summary="done")
    assert res["ok"] is True
    fields = [c for c in calls if c["method"] == "PATCH"][0]["json"]["custom_fields"]
    assert fields == {nb.CF_START: None, nb.CF_END: None}


# ── device resolution / listing ─────────────────────────────────────────────

def test_resolve_device_prefers_the_explicit_map(ctx, monkeypatch):
    _setup(device_map={"1": 7})
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [{"id": 99, "name": "fw"}]}))
    assert nb.resolve_device({"id": 1, "name": "fw"}) == 7
    assert calls == []            # an operator decision needs no lookup


def test_resolve_device_falls_back_to_an_exact_name(ctx, monkeypatch):
    _setup(device_map={})
    _install(monkeypatch, _Resp(200, {"results": [{"id": 1, "name": "fortiweb08"}]}))
    assert nb.resolve_device({"id": 5, "name": "fortiweb08"}) == 1


def test_resolve_device_refuses_to_guess(ctx, monkeypatch):
    _setup(device_map={})
    _install(monkeypatch, _Resp(200, {"results": []}))
    assert nb.resolve_device({"id": 5, "name": "nope"}) is None
    # two same-named devices is ambiguity, not a match
    _install(monkeypatch, _Resp(200, {"results": [{"id": 1, "name": "dup"},
                                                  {"id": 2, "name": "dup"}]}))
    assert nb.resolve_device({"id": 5, "name": "dup"}) is None


def test_open_window_refuses_an_unmapped_appliance(ctx, monkeypatch):
    _setup(device_map={})
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 12}))
    res = nb.open_window(1, cr_id="CR-1", title="t",
                         start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                         reason="r")
    assert res["ok"] is False and res["ref"] == ""
    assert nb.K_DEVICE_MAP in res["detail"]
    assert calls == []


def test_list_devices_flattens_the_netbox_shape(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, _Resp(200, {"count": 1, "results": [
        {"id": 1, "name": "fortiweb08",
         "site": {"id": 1, "name": "Lab"},
         "status": {"value": "active", "label": "Active"}}]}))
    assert nb.list_devices() == [
        {"id": 1, "name": "fortiweb08", "site": "Lab", "status": "active"}]


def test_test_connection_reports_version_plugins_and_elapsed(ctx, monkeypatch):
    _setup()
    _install(monkeypatch, _Resp(200, {"netbox-version": "4.6.7", "plugins": {}}))
    res = nb.test_connection()
    assert res["ok"] is True
    assert res["version"] == "4.6.7"
    assert res["plugins"] == []                 # the lab NetBox has none
    assert isinstance(res["elapsed_ms"], int) and res["elapsed_ms"] >= 0
    assert set(res) == {"ok", "detail", "version", "plugins", "elapsed_ms"}
