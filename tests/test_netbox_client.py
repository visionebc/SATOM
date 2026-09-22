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
    # TEXT, not an int: a NetBox id is only half an address. "7" is a device
    # (the historical meaning of a bare number); a virtual machine is "vm:95".
    assert nb.device_map() == {"1": "7"}      # blank = unmapped, never 0


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


def test_a_pre_network_refusal_is_flagged_as_not_sent(ctx, monkeypatch):
    """open_window must tell its caller whether anything actually left this
    process. The caller turns that answer into ``mw_state``, and the CR page
    renders ``error`` as "a device may still be shown in maintenance in
    NetBox" - a sentence no refusal that never opened a socket may produce."""
    _setup()
    calls, _ = _install(monkeypatch, _Resp(201, {"id": 12}))

    unmapped = nb.open_window(999, cr_id="CR-1", title="t",
                              start=datetime(2026, 8, 10, 2),
                              end=datetime(2026, 8, 10, 4), reason="r")
    assert unmapped["ok"] is False and unmapped["sent"] is False
    bad_time = nb.open_window(1, cr_id="CR-1", title="t", start="not a date",
                              end=datetime(2026, 8, 10, 4), reason="r")
    assert bad_time["ok"] is False and bad_time["sent"] is False
    assert calls == [], "a pre-network refusal opened a socket"

    # The gate is the third pre-network refusal, and it is REACHABLE with the
    # integration looking healthy: is_configured() only asks whether a token is
    # STORED, while the gate also has to decrypt it. A rotated FERNET_KEY lands
    # here, and reporting that as sent would mark the change as a NetBox error.
    _setup(enabled="0")
    off = nb.open_window(1, cr_id="CR-1", title="t",
                         start=datetime(2026, 8, 10, 2),
                         end=datetime(2026, 8, 10, 4), reason="r")
    assert off["ok"] is False and off["sent"] is False
    assert calls == [], "a gated refusal opened a socket"


def test_a_call_netbox_actually_answered_is_flagged_as_sent(ctx, monkeypatch):
    """The other side of the same contract: a 500 from NetBox IS an attempt,
    and so is a timeout - the window may have been applied server-side. Both
    must keep the cautious state."""
    _setup()
    _install(monkeypatch, _Resp(500, None, text="boom"))
    refused = nb.open_window(1, cr_id="CR-1", title="t",
                             start=datetime(2026, 8, 10, 2),
                             end=datetime(2026, 8, 10, 4), reason="r")
    assert refused["ok"] is False
    assert refused.get("sent", True) is True

    _install(monkeypatch, _Resp(201, {"id": 12}))
    ok = nb.open_window(1, cr_id="CR-1", title="t",
                        start=datetime(2026, 8, 10, 2),
                        end=datetime(2026, 8, 10, 4), reason="r")
    assert ok["ok"] is True and ok.get("sent", True) is True


def test_is_mapped_is_the_one_author_of_the_mapping_question(ctx):
    """The settings page, the CR page and :func:`open_window` must agree on
    whether an appliance is documented in NetBox. Two spellings of that
    question is how a button gets offered for a window that cannot open."""
    _setup(device_map={"1": 7})
    assert nb.is_mapped(1) is True
    assert nb.is_mapped("1") is True
    assert nb.is_mapped(999) is False
    assert nb.is_mapped(None) is False


# ── refs ────────────────────────────────────────────────────────────────────

def test_ref_round_trips_for_every_backend():
    for backend, ident in (("journal", 12), ("tag", 7), ("custom_field", 7)):
        ref = nb.make_ref(backend, ident)
        assert nb.parse_ref(ref) == (backend, "device", ident)
    assert nb.parse_ref("garbage") == ("", "", 0)
    assert nb.parse_ref("journal:abc") == ("", "", 0)
    assert nb.parse_ref("") == ("", "", 0)


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


# ── resolution plan: the ONE author of "which device is this" ───────────────

def test_resolve_plan_asks_netbox_once_for_the_whole_change(ctx, monkeypatch):
    """N appliances, ONE request. A per-appliance lookup makes a page render
    cost grow with the size of the change, against a host that is normally
    slow."""
    _setup(device_map={})
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [
        {"id": 11, "name": "a"}, {"id": 12, "name": "b"}, {"id": 13, "name": "c"}]}))
    plan = nb.resolve_plan([{"id": 1, "name": "a"}, {"id": 2, "name": "b"},
                            {"id": 3, "name": "c"}])
    assert len(calls) == 1, "one lookup per appliance"
    assert calls[0]["params"]["name"] == ["a", "b", "c"]
    assert [plan[k]["device_id"] for k in ("1", "2", "3")] == [11, 12, 13]
    assert {plan[k]["via"] for k in ("1", "2", "3")} == {"name"}


def test_resolve_plan_lets_the_operator_decision_win_without_a_lookup(ctx, monkeypatch):
    _setup(device_map={"1": 7})
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [{"id": 99, "name": "a"}]}))
    plan = nb.resolve_plan([{"id": 1, "name": "a"}])
    assert plan["1"]["device_id"] == 7 and plan["1"]["via"] == "map"
    assert calls == []


def test_an_unreachable_netbox_is_unknown_not_absent(ctx, monkeypatch):
    """``checked`` False is the whole point: a page that renders a timeout as
    "NetBox does not document this appliance" accuses the operator's inventory
    of a fault the integration caused."""
    _setup(device_map={})
    _install(monkeypatch, httpx.ConnectError("no route"))
    plan = nb.resolve_plan([{"id": 1, "name": "a"}])
    assert plan["1"]["device_id"] == 0
    assert plan["1"]["checked"] is False
    assert "does not document" not in plan["1"]["error"]


def test_a_disabled_integration_is_unknown_too(ctx, monkeypatch):
    """Nothing was asked, so nothing may be asserted about the inventory."""
    _setup(device_map={}, enabled="")
    calls, _ = _install(monkeypatch, _Resp(200, {"results": []}))
    plan = nb.resolve_plan([{"id": 1, "name": "a"}])
    assert plan["1"]["checked"] is False and calls == []


def test_resolve_plan_names_a_case_insensitive_near_miss(ctx, monkeypatch):
    """NetBox's ``name`` filter is case-INSENSITIVE (measured against 4.6.7);
    this module's match is not. Without naming the near miss the operator reads
    "no such device" while looking straight at one in the NetBox UI."""
    _setup(device_map={})
    _install(monkeypatch, _Resp(200, {"results": [{"id": 5, "name": "FortiWeb15"}]}))
    plan = nb.resolve_plan([{"id": 1, "name": "fortiweb15"}])
    assert plan["1"]["device_id"] == 0, "a different letter case is a DIFFERENT object"
    assert plan["1"]["near"] == "FortiWeb15"
    assert "FortiWeb15" in plan["1"]["error"] and "fortiweb15" in plan["1"]["error"]


def test_resolve_plan_refuses_to_guess_between_duplicates(ctx, monkeypatch):
    _setup(device_map={})
    _install(monkeypatch, _Resp(200, {"results": [{"id": 1, "name": "dup"},
                                                  {"id": 2, "name": "dup"}]}))
    plan = nb.resolve_plan([{"id": 9, "name": "dup"}])
    assert plan["9"]["device_id"] == 0 and plan["9"]["checked"] is True
    assert "2 objects" in plan["9"]["error"] and "device" in plan["9"]["error"]


def test_the_unresolved_reason_names_BOTH_remedies(ctx, monkeypatch):
    """"not mapped" alone sends the operator to a settings form to type an id
    for an object nobody has created yet."""
    _setup(device_map={})
    _install(monkeypatch, _Resp(200, {"results": []}))
    detail = nb.resolve_plan([{"id": 1, "name": "fortiweb15"}])["1"]["error"]
    assert "fortiweb15" in detail
    assert "Create it in NetBox" in detail
    assert "Settings -> Integrations" in detail
    # BOTH object kinds are named: an operator whose appliance is a VM must
    # not read "create the device" and go build a duplicate.
    assert "virtual machine" in detail and "vm:95" in detail


def test_open_window_resolves_an_unmapped_appliance_by_name(ctx, monkeypatch):
    """The fallback the Integrations page DOCUMENTS, exercised through the real
    entry point. Until 2026-09-21 it was unreachable from the only caller."""
    _setup(device_map={})

    def handler(method, url, json=None, params=None):
        if method == "GET":
            return _Resp(200, {"results": [{"id": 42, "name": "fortiweb15"}]})
        return _Resp(201, {"id": 77})

    calls, _ = _install(monkeypatch, handler)
    res = nb.open_window({"id": 32, "name": "fortiweb15"}, cr_id="CR-1", title="t",
                         start=datetime(2026, 8, 10, 2), end=datetime(2026, 8, 10, 4),
                         reason="r")
    assert res["ok"] is True and res["ref"] == "journal:77"
    posted = [c for c in calls if c["method"] == "POST"]
    assert len(posted) == 1
    assert posted[0]["json"]["assigned_object_id"] == 42


def test_a_caller_budget_may_only_SHORTEN_the_configured_timeout(ctx, monkeypatch):
    """The operator's timeout is a ceiling. A page asking for a fast answer
    must not be able to widen a budget an operator narrowed."""
    _setup(timeout="8")
    _, inits = _install(monkeypatch, _Resp(200, {}))
    nb.request("GET", "/api/status/", timeout=3)
    assert inits[-1]["timeout"].read == 3
    nb.request("GET", "/api/status/", timeout=99)
    assert inits[-1]["timeout"].read == 8
    nb.request("GET", "/api/status/", timeout="nonsense")
    assert inits[-1]["timeout"].read == 8
    nb.request("GET", "/api/status/")
    assert inits[-1]["timeout"].read == 8


# ── virtual machines are window targets too ─────────────────────────────────
# NetBox models a VM as a DIFFERENT object from a device: another API path,
# another content type, and a SEPARATE id space. Measured on the live fleet
# 2026-09-21: 13 devices, 87 virtual machines, and all four FortiWeb/FortiADC
# appliances are virtual machines. A device-only integration calls a fully
# documented appliance undocumented and switches its button off.

def test_an_appliance_netbox_documents_as_a_vm_resolves(ctx, monkeypatch):
    _setup(device_map={})

    def handler(method, url, json=None, params=None):
        if "/virtualization/virtual-machines/" in url:
            return _Resp(200, {"results": [{"id": 95, "name": "fortiweb16"}]})
        return _Resp(200, {"results": []})        # dcim knows nothing

    calls, _ = _install(monkeypatch, handler)
    plan = nb.resolve_plan([{"id": 33, "name": "fortiweb16"}])
    assert plan["33"]["device_id"] == 95
    assert plan["33"]["kind"] == nb.KIND_VM
    assert plan["33"]["via"] == "name"
    assert plan["33"]["error"] == ""
    assert [c["url"] for c in calls] == [
        BASE + "/api/dcim/devices/",
        BASE + "/api/virtualization/virtual-machines/"]


def test_a_device_match_wins_and_costs_no_vm_lookup(ctx, monkeypatch):
    """Precedence is fixed, not a race: a name NetBox documents as a device is
    that device. The VM leg is not even asked, so the page's cost is unchanged
    for every install that has no VMs."""
    _setup(device_map={})
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [{"id": 8, "name": "hypervisor03"}]}))
    plan = nb.resolve_plan([{"id": 1, "name": "hypervisor03"}])
    assert (plan["1"]["kind"], plan["1"]["device_id"]) == (nb.KIND_DEVICE, 8)
    assert len(calls) == 1 and "/dcim/devices/" in calls[0]["url"]


def test_only_the_unanswered_names_are_asked_of_virtualization(ctx, monkeypatch):
    _setup(device_map={})

    def handler(method, url, json=None, params=None):
        if "/virtualization/" in url:
            return _Resp(200, {"results": [{"id": 95, "name": "b"}]})
        return _Resp(200, {"results": [{"id": 8, "name": "a"}]})

    calls, _ = _install(monkeypatch, handler)
    plan = nb.resolve_plan([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}])
    vm_call = [c for c in calls if "/virtualization/" in c["url"]][0]
    assert vm_call["params"]["name"] == ["b"], "a is already answered"
    assert (plan["1"]["kind"], plan["1"]["device_id"]) == (nb.KIND_DEVICE, 8)
    assert (plan["2"]["kind"], plan["2"]["device_id"]) == (nb.KIND_VM, 95)


def test_a_vm_leg_that_never_answers_is_unknown_not_absent(ctx, monkeypatch):
    """Half an answer is still not an answer. The names dcim resolved stand;
    the rest are UNVERIFIED, which leaves the button alive — rendering them as
    "NetBox does not document this" accuses the inventory of the integration's
    own fault."""
    _setup(device_map={})

    def handler(method, url, json=None, params=None):
        if "/virtualization/" in url:
            raise httpx.ConnectError("no route")
        return _Resp(200, {"results": [{"id": 8, "name": "a"}]})

    _install(monkeypatch, handler)
    plan = nb.resolve_plan([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}])
    assert plan["1"]["device_id"] == 8 and plan["1"]["checked"] is True
    assert plan["2"]["device_id"] == 0
    assert plan["2"]["checked"] is False
    assert "does not document" not in plan["2"]["error"]


def test_a_window_on_a_vm_is_written_to_the_vm_not_to_a_device(ctx, monkeypatch):
    """The whole reason the kind is carried: NetBox device 95 and virtual
    machine 95 are unrelated objects, and PATCHing the wrong one tags a
    stranger's hardware."""
    _setup(device_map={}, mw_backend="tag")

    def handler(method, url, json=None, params=None):
        if "/virtualization/virtual-machines/" in url and method == "GET":
            return _Resp(200, {"results": [{"id": 95, "name": "fortiweb16"}],
                               "id": 95, "tags": [{"name": "keep-me"}]})
        if "/dcim/devices/" in url:
            return _Resp(200, {"results": []})
        if "/extras/tags/" in url:
            return _Resp(200, {"results": [{"id": 1, "slug": nb.MAINT_TAG_SLUG}]})
        return _Resp(200, {"id": 95})

    calls, _ = _install(monkeypatch, handler)
    res = nb.open_window({"id": 33, "name": "fortiweb16"}, cr_id="CR-9", title="t",
                         start=datetime(2026, 9, 21, 2), end=datetime(2026, 9, 21, 4),
                         reason="r")
    assert res["ok"] is True
    patches = [c for c in calls if c["method"] == "PATCH"]
    assert len(patches) == 1
    assert patches[0]["url"] == BASE + "/api/virtualization/virtual-machines/95/"
    assert not [c for c in calls
                if c["method"] == "PATCH" and "/dcim/devices/" in c["url"]]
    # the operator's own tags survive: NetBox REPLACES the list on PATCH
    assert {t["name"] for t in patches[0]["json"]["tags"]} == {"keep-me", nb.MAINT_TAG_NAME}
    # and the ref says WHICH object, or the close would go to a device
    assert res["ref"] == "tag:vm:95"


def test_the_vm_ref_closes_against_the_vm_and_a_legacy_ref_against_a_device(ctx, monkeypatch):
    _setup(mw_backend="tag")
    for ref, expected in (("tag:vm:95", "/api/virtualization/virtual-machines/95/"),
                          ("tag:95", "/api/dcim/devices/95/")):
        calls, _ = _install(
            monkeypatch,
            _Resp(200, {"id": 95, "tags": [{"name": nb.MAINT_TAG_NAME}]}))
        res = nb.close_window(ref, ok=True, summary="done")
        assert res["ok"] is True, ref
        urls = {c["url"] for c in calls}
        assert urls == {BASE + expected}, ref


def test_a_journal_close_follows_the_object_the_open_was_filed_against(ctx, monkeypatch):
    """A journal ref carries no kind — the ENTRY does. Reading it back is what
    stops the closing note from being filed against a device that merely
    shares the virtual machine's number."""
    _setup()

    def handler(method, url, json=None, params=None):
        if url.endswith("/api/extras/journal-entries/12/"):
            return _Resp(200, {"id": 12, "assigned_object_id": 95,
                               "assigned_object_type": nb.VM_CT})
        return _Resp(201, {"id": 13})

    calls, _ = _install(monkeypatch, handler)
    res = nb.close_window("journal:12", ok=True, summary="done")
    assert res["ok"] is True
    posted = [c for c in calls if c["method"] == "POST"][0]["json"]
    assert posted["assigned_object_type"] == nb.VM_CT
    assert posted["assigned_object_id"] == 95
    assert "virtual machine" in res["detail"]


def test_a_journal_close_refuses_an_object_type_satom_does_not_maintain(ctx, monkeypatch):
    """Anything else is somebody else's object. Writing to it is worse than
    refusing, and guessing "probably a device" is how the wrong one gets hit."""
    _setup()

    def handler(method, url, json=None, params=None):
        if url.endswith("/api/extras/journal-entries/12/"):
            return _Resp(200, {"id": 12, "assigned_object_id": 3,
                               "assigned_object_type": "circuits.circuit"})
        return _Resp(201, {"id": 13})

    calls, _ = _install(monkeypatch, handler)
    res = nb.close_window("journal:12", ok=True, summary="done")
    assert res["ok"] is False
    assert "circuits.circuit" in res["detail"]
    assert not [c for c in calls if c["method"] == "POST"]


def test_an_open_window_on_a_vm_files_the_journal_against_the_vm(ctx, monkeypatch):
    _setup(device_map={})

    def handler(method, url, json=None, params=None):
        if "/virtualization/" in url:
            return _Resp(200, {"results": [{"id": 95, "name": "fortiweb16"}]})
        if "/dcim/devices/" in url:
            return _Resp(200, {"results": []})
        return _Resp(201, {"id": 77})

    calls, _ = _install(monkeypatch, handler)
    res = nb.open_window({"id": 33, "name": "fortiweb16"}, cr_id="CR-9", title="t",
                         start=datetime(2026, 9, 21, 2), end=datetime(2026, 9, 21, 4),
                         reason="r")
    assert res["ok"] is True
    body = [c for c in calls if c["method"] == "POST"][0]["json"]
    assert body["assigned_object_type"] == nb.VM_CT
    assert body["assigned_object_id"] == 95


def test_custom_fields_are_checked_on_the_TARGETS_object_type(ctx, monkeypatch):
    """A custom field defined for devices does not exist on a virtual machine.
    Sending it anyway earns a 400 the operator cannot read as "wrong object
    type" — so the refusal names the type, before anything is written."""
    _setup(device_map={"33": "vm:95"}, mw_backend="custom_field")
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [
        {"name": nb.CF_START, "object_types": [nb.DEVICE_CT]},
        {"name": nb.CF_END, "object_types": [nb.DEVICE_CT]}]}))
    res = nb.open_window({"id": 33, "name": "fortiweb16"}, cr_id="CR-9", title="t",
                         start=datetime(2026, 9, 21, 2), end=datetime(2026, 9, 21, 4),
                         reason="r")
    assert res["ok"] is False
    assert nb.VM_CT in res["detail"]
    assert not [c for c in calls if c["method"] == "PATCH"]


def test_custom_fields_declared_for_vms_are_written_to_the_vm(ctx, monkeypatch):
    _setup(device_map={"33": "vm:95"}, mw_backend="custom_field")
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [
        {"name": nb.CF_START, "object_types": [nb.VM_CT]},
        {"name": nb.CF_END, "object_types": [nb.VM_CT]}]}))
    res = nb.open_window({"id": 33, "name": "fortiweb16"}, cr_id="CR-9", title="t",
                         start=datetime(2026, 9, 21, 2), end=datetime(2026, 9, 21, 4),
                         reason="r")
    assert res["ok"] is True and res["ref"] == "cf:vm:95"
    patch = [c for c in calls if c["method"] == "PATCH"][0]
    assert patch["url"] == BASE + "/api/virtualization/virtual-machines/95/"


def test_the_map_binds_an_appliance_to_a_vm_and_wins_without_a_lookup(ctx, monkeypatch):
    _setup(device_map={})
    nb.save_device_map({"33": "vm:95", "34": "7"})
    assert nb.device_map() == {"33": "vm:95", "34": "7"}
    calls, _ = _install(monkeypatch, _Resp(200, {"results": [{"id": 1, "name": "fortiweb16"}]}))
    plan = nb.resolve_plan([{"id": 33, "name": "fortiweb16"}])
    assert (plan["33"]["kind"], plan["33"]["device_id"], plan["33"]["via"]) == \
        (nb.KIND_VM, 95, "map")
    assert calls == [], "an operator decision is not re-litigated against NetBox"


def test_a_mapping_that_is_neither_a_device_id_nor_a_vm_names_the_row(ctx):
    for bad in ("fortiweb08", "vm:abc", "cluster:3", "vm:0", "-2"):
        with pytest.raises(ValueError) as exc:
            nb.save_device_map({"1": bad})
        assert bad in str(exc.value) and "'1'" in str(exc.value), bad
        assert "vm:95" in str(exc.value), "the accepted spelling is shown"


def test_one_parser_answers_what_object_a_text_names():
    """The map and the refs read the same spelling through the same function.
    Two parsers is how "vm:95" comes to mean one object in a mapping and
    another in a ref."""
    assert nb.parse_target("7") == (nb.KIND_DEVICE, 7)
    assert nb.parse_target("vm:95") == (nb.KIND_VM, 95)
    assert nb.parse_target(" vm:95 ") == (nb.KIND_VM, 95)
    assert nb.parse_target("device:7") == (nb.KIND_DEVICE, 7)
    for bad in ("", None, "0", "-1", "vm:", "cluster:1", "vm:x", "7.5"):
        assert nb.parse_target(bad) == ("", 0), bad
    assert nb.parse_ref("tag:vm:95") == ("tag", nb.KIND_VM, 95)
    assert nb.parse_ref("cf:vm:95") == ("custom_field", nb.KIND_VM, 95)
    assert nb.parse_ref("tag:cluster:1") == ("", "", 0)
    assert nb.make_ref("tag", 95, "cluster") == ""


def test_no_write_path_addresses_a_device_by_a_hardcoded_url():
    """A source guard, because this is the class of bug the round fixed: every
    write went to an f-string ending in /api/dcim/devices/<id>/, so a virtual
    machine's id was silently sent to whatever device wore that number."""
    import inspect
    src = inspect.getsource(nb)
    body = src[src.index("#  maintenance windows"):]
    assert 'f"/api/dcim/devices/{' not in body
    # Not a count — each helper that addresses one object is named, so
    # deleting the kind from any single one of them is caught.
    for fn in (nb._device_tag_names, nb._patch_device_tags,
               nb._open_custom_field, nb._close_custom_field):
        assert "object_path(kind" in inspect.getsource(fn), fn.__name__


# ── batched reconciliation (services.netbox_client.reconcile) ───────────────
#
# What these exist to stop, all of them silent:
#
#   * an outage writing the operator's inventory — NetBox unreachable must
#     write NOTHING and say "not checked", because "we could not ask" and
#     "NetBox documents none of these" are opposite instructions;
#   * a round quietly rewriting the WHOLE map instead of its batch, which is
#     what makes an unbounded sweep unwatchable on a large fleet;
#   * a virtual machine stored as a bare id — VM 95 and device 95 are two
#     unrelated objects, and that is exactly the bug that switched the
#     maintenance-window button off for every appliance on this fleet;
#   * a mapping an operator typed being dropped by a round they scheduled.

def _appliances(n, start=1):
    from app.extensions import db
    from app.models import Appliance
    out = []
    for i in range(start, start + n):
        a = Appliance(name="fw%d" % i, host="10.0.0.%d" % i, kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        out.append(a)
    db.session.commit()
    return out


def _name_hits(rows_by_path):
    """Handler answering the two name lookups from a {path: [rows]} map."""
    def handler(method, url, json=None, params=None):
        for path, rows in rows_by_path.items():
            if path in url:
                asked = params.get("name") if params else []
                asked = asked if isinstance(asked, (list, tuple)) else [asked]
                return _Resp(200, {"results": [r for r in rows
                                               if r["name"] in asked]})
        return _Resp(200, {"results": []})
    return handler


def test_clamp_per_round_floors_caps_and_defaults():
    assert nb.clamp_per_round(0) == 1
    assert nb.clamp_per_round(-7) == 1
    assert nb.clamp_per_round(10 ** 9) == nb.MAX_PER_ROUND
    assert nb.clamp_per_round("abc") == nb.DEFAULT_PER_ROUND
    assert nb.clamp_per_round(None) == nb.DEFAULT_PER_ROUND
    assert nb.clamp_per_round(" 7 ") == 7


def test_a_round_writes_its_batch_and_names_the_remainder(ctx, monkeypatch):
    _setup(device_map={})
    rows = _appliances(5)
    _install(monkeypatch, _name_hits({
        "/dcim/devices": [],
        "/virtualization/virtual-machines":
            [{"name": a.name, "id": 90 + a.id} for a in rows],
    }))
    res = nb.reconcile(per_round=2)
    assert res["checked"] is True
    assert res["scanned"] == 2                      # the BATCH, not the fleet
    assert res["remaining"] == 3                    # and the rest is reported
    assert len(res["mapped"]) == 2
    assert len(nb.device_map()) == 2                # only two rows written

    res2 = nb.reconcile(per_round=2)                # the next round continues
    assert res2["scanned"] == 2 and res2["remaining"] == 1
    assert len(nb.device_map()) == 4


def test_a_virtual_machine_is_stored_with_its_type_never_a_bare_id(ctx, monkeypatch):
    _setup(device_map={})
    rows = _appliances(1)
    _install(monkeypatch, _name_hits({
        "/dcim/devices": [],
        "/virtualization/virtual-machines": [{"name": rows[0].name, "id": 95}],
    }))
    nb.reconcile(per_round=1)
    stored = nb.device_map()[str(rows[0].id)]
    assert stored == "vm:95"                        # NOT "95"
    kind, ident = nb.parse_target(stored)
    assert (kind, ident) == (nb.KIND_VM, 95)


def test_an_unreachable_netbox_writes_nothing_and_says_not_checked(ctx, monkeypatch):
    _setup(device_map={})
    _appliances(3)
    _install(monkeypatch, httpx.ConnectError("boom"))
    res = nb.reconcile(per_round=3)
    assert res["checked"] is False                  # unknown, never "absent"
    assert res["error"]
    assert res["mapped"] == []
    assert nb.device_map() == {}                    # an outage wrote nothing


def test_a_disabled_integration_is_never_asked_and_never_green(ctx, monkeypatch):
    _setup(enabled="", device_map={})
    _appliances(2)
    calls, _ = _install(monkeypatch, _Resp(200, {"results": []}))
    res = nb.reconcile(per_round=2)
    assert res["checked"] is False
    assert calls == []                              # no call was made at all
    assert nb.device_map() == {}


def test_a_round_never_drops_a_mapping_somebody_typed(ctx, monkeypatch):
    _setup(device_map={})
    rows = _appliances(2)
    nb.save_device_map({str(rows[0].id): "7"})      # an operator's decision
    _install(monkeypatch, _name_hits({
        "/dcim/devices": [],
        "/virtualization/virtual-machines": [{"name": rows[1].name, "id": 95}],
    }))
    res = nb.reconcile(per_round=10)
    assert res["scanned"] == 1                      # the mapped one is not re-asked
    after = nb.device_map()
    assert after[str(rows[0].id)] == "7"            # merged, not replaced
    assert after[str(rows[1].id)] == "vm:95"


def test_what_netbox_does_not_document_is_reported_by_name(ctx, monkeypatch):
    _setup(device_map={})
    rows = _appliances(2)
    _install(monkeypatch, _name_hits({
        "/dcim/devices": [{"name": rows[0].name, "id": 7}],
        "/virtualization/virtual-machines": [],
    }))
    res = nb.reconcile(per_round=2)
    assert res["unresolved"] == [rows[1].name]      # the NAME, never a count
    assert len(res["mapped"]) == 1
    assert str(rows[1].id) not in nb.device_map()


def test_dry_run_reports_what_it_would_do_and_writes_nothing(ctx, monkeypatch):
    _setup(device_map={})
    rows = _appliances(1)
    _install(monkeypatch, _name_hits({
        "/dcim/devices": [{"name": rows[0].name, "id": 7}],
        "/virtualization/virtual-machines": [],
    }))
    res = nb.reconcile(per_round=1, dry_run=True)
    assert res["checked"] is True and len(res["mapped"]) == 1
    assert nb.device_map() == {}                    # preview wrote nothing


def test_nothing_left_to_do_is_not_an_error(ctx, monkeypatch):
    _setup(device_map={})
    rows = _appliances(1)
    nb.save_device_map({str(rows[0].id): "vm:95"})
    calls, _ = _install(monkeypatch, _Resp(200, {"results": []}))
    res = nb.reconcile(per_round=5)
    assert res["checked"] is True and res["scanned"] == 0 and res["remaining"] == 0
    assert calls == []                              # nothing to ask about
