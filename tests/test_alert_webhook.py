"""The webhook sink, the ``alert.fired`` event and the hook starters.

Everything here fails quietly by construction, which is why each guard exists.

* A **signature over the body alone** verifies perfectly forever, so a captured
  POST replays cleanly and the receiver has no way to notice. The only thing
  that catches it is asserting the timestamp is *inside* the signed string.
* **Signing one serialisation and sending another** produces a signature the
  receiver correctly rejects — intermittently, whenever key order or separators
  differ. Nothing on this side ever sees an error.
* **Retrying a 400** neither fixes the request nor tells anyone; **not retrying
  a 502** loses the alert. Both look identical from the settings page.
* A **hooks sink with no hook bound to the event** enqueues nothing. If the
  engine stamps the cooldown anyway, the finding is suppressed for six hours on
  behalf of a subscriber that does not exist — the alert existed, was counted,
  and never arrived.
* A **starter that reads a payload key the event does not emit**, or reads a
  secret it never declared, fails at 03:00 with ``KeyError`` / ``ctx.secret()``
  raising — in a subprocess, in somebody else's install.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

import pytest

from app.models import AppSetting
from app.services import alert_routing as routing
from app.services import alert_webhook as wh
from app.services import alerts
from app.services import hook_starters
from app.services import integration_hooks as ih


def F(key, severity="warning"):
    return {"key": key, "severity": severity, "title": "t " + key,
            "detail": "d " + key}


@pytest.fixture()
def sink_on(app):
    """Webhook sink enabled and pointed somewhere, inside an app context."""
    with app.app_context():
        AppSetting.set("alerts.sink.webhook.enabled", "1")
        AppSetting.set("alerts.webhook.url", "https://hook.example.com/x")
        AppSetting.set("alerts.webhook.retries", "0")
        yield


class _Resp:
    def __init__(self, status, text="ok"):
        self.status_code = status
        self.text = text


def _capture(monkeypatch, responses):
    """Stub ``httpx.post`` and record every call. ``responses`` is a list of
    ``_Resp`` or exceptions, consumed one per attempt."""
    calls = []
    seq = list(responses)

    def fake_post(url, content=None, headers=None, timeout=None, **kw):
        calls.append({"url": url, "content": content, "headers": headers,
                      "timeout": timeout})
        nxt = seq.pop(0) if seq else _Resp(200)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    return calls


# ===================================================== signature / payload ==
def test_the_timestamp_is_inside_the_signed_string_not_merely_beside_it():
    """A signature over the body alone stays valid forever: a captured POST can
    be replayed at any hour and still verify, and the receiver cannot tell."""
    body = b'{"a":1}'
    assert wh.sign(body, 1000, "k") != wh.sign(body, 2000, "k")


def test_the_signature_verifies_against_the_exact_bytes_that_were_sent(
        sink_on, monkeypatch):
    """Serialising twice — once to sign, once to send — yields a signature the
    receiver correctly rejects whenever key order or separators differ. This
    recomputes the HMAC the way a real receiver would: from the captured bytes
    and the captured header, with nothing from this process."""
    wh.set_secret("sh4red")
    calls = _capture(monkeypatch, [_Resp(200)])
    wh.emit([F("cert.expiry")], "node-a")

    sent = calls[0]
    ts = int(sent["headers"][wh.TS_HEADER])
    expect = hmac.new(b"sh4red",
                      b"v1:%d:" % ts + sent["content"], hashlib.sha256).hexdigest()
    assert sent["headers"][wh.SIG_HEADER] == "v1=" + expect


def test_no_secret_means_no_signature_header_never_an_empty_one(
        sink_on, monkeypatch):
    """A receiver whose check is "is a signature present" must not be handed a
    value that passes that check and proves nothing."""
    AppSetting.set("alerts.webhook.secret", "")
    calls = _capture(monkeypatch, [_Resp(200)])
    res = wh.emit([F("cert.expiry")], "node-a")
    assert wh.SIG_HEADER not in calls[0]["headers"]
    assert res["signed"] is False


def test_config_never_carries_the_secret(sink_on):
    """``config()`` is what the settings template renders. A secret that reaches
    a page reaches every screenshot, cache and proxy log of that page."""
    from app.services.encryption import encrypt
    AppSetting.set("alerts.webhook.secret", encrypt("t0p-s3cret"))
    blob = json.dumps(wh.config())
    assert "t0p-s3cret" not in blob
    assert wh.config()["secret_set"] is True
    assert wh.secret() == "t0p-s3cret"


def test_a_retry_repeats_its_delivery_id_and_a_new_batch_does_not(app):
    """The id is what lets a receiver dedupe. A random component would make
    every retry look like a brand-new event — the opposite of the purpose."""
    from datetime import datetime, timezone
    ts = datetime(2026, 8, 13, 21, 40, tzinfo=timezone.utc)
    a = wh.delivery_id("n", [F("cert.expiry")], ts)
    assert a == wh.delivery_id("n", [F("cert.expiry")], ts)
    assert a != wh.delivery_id("n", [F("host.disk")], ts)
    assert a != wh.delivery_id("other", [F("cert.expiry")], ts)


def test_finding_order_does_not_change_the_delivery_id(app):
    from datetime import datetime, timezone
    ts = datetime(2026, 8, 13, 21, 40, tzinfo=timezone.utc)
    one = [F("cert.expiry"), F("host.disk")]
    assert wh.delivery_id("n", one, ts) == wh.delivery_id("n", one[::-1], ts)


def test_the_documented_sample_is_generated_by_the_real_builder(app):
    """A documented shape maintained separately from the emitter drifts, and the
    operator only finds out when their verifier rejects a real delivery."""
    doc = json.loads(wh.sample_payload())
    from datetime import datetime, timezone
    live = wh.envelope([F("cert.expiry")], "n",
                       datetime(2026, 1, 1, tzinfo=timezone.utc), "id")
    assert set(doc) == set(live)
    assert set(doc["findings"][0]) == set(live["findings"][0])
    assert doc["version"] == wh.ENVELOPE_VERSION


def test_the_envelope_resolves_the_family_so_receivers_do_not_have_to(app):
    """``action.*`` findings belong to the ``actions`` family. A receiver
    re-deriving that from the key prefix ticks a rule that matches nothing."""
    from datetime import datetime, timezone
    env = wh.envelope([F("action.error.7")], "n",
                      datetime(2026, 1, 1, tzinfo=timezone.utc), "i")
    assert env["findings"][0]["family"] == "actions"


def test_max_severity_is_the_worst_and_not_the_first(app):
    from datetime import datetime, timezone
    env = wh.envelope([F("cert.expiry", "info"), F("host.disk", "critical")],
                      "n", datetime(2026, 1, 1, tzinfo=timezone.utc), "i")
    assert env["max_severity"] == "critical"


def test_slack_encoding_sends_only_text(sink_on, monkeypatch):
    AppSetting.set("alerts.webhook.format", "slack")
    calls = _capture(monkeypatch, [_Resp(200)])
    wh.emit([F("cert.expiry"), F("host.disk")], "node-a")
    doc = json.loads(calls[0]["content"])
    assert list(doc) == ["text"]
    assert "t host.disk" in doc["text"] and "t cert.expiry" in doc["text"]


# ================================================================= retries ==
@pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 422])
def test_a_permanent_4xx_is_tried_once_and_says_it_is_permanent(
        sink_on, monkeypatch, status):
    """Repeating a rejected request neither fixes it nor tells anyone; the
    operator needs to read "your URL is wrong", not "it retried and gave up"."""
    AppSetting.set("alerts.webhook.retries", "3")
    calls = _capture(monkeypatch, [_Resp(status, "nope")] * 4)
    res = wh.emit([F("cert.expiry")], "n", sleep=lambda s: None)
    assert len(calls) == 1
    assert res["ok"] is False and res["retryable"] is False
    assert str(status) in res["detail"]


@pytest.mark.parametrize("status", sorted(wh.RETRY_STATUSES))
def test_a_transient_status_is_retried_up_to_the_configured_count(
        sink_on, monkeypatch, status):
    AppSetting.set("alerts.webhook.retries", "2")
    calls = _capture(monkeypatch, [_Resp(status)] * 5)
    res = wh.emit([F("cert.expiry")], "n", sleep=lambda s: None)
    assert len(calls) == 3          # first attempt + 2 retries
    assert res["ok"] is False and res["retryable"] is True


def test_a_transport_error_is_retried_and_never_raises(sink_on, monkeypatch):
    AppSetting.set("alerts.webhook.retries", "1")
    calls = _capture(monkeypatch, [OSError("connection refused"),
                                   OSError("connection refused")])
    res = wh.emit([F("cert.expiry")], "n", sleep=lambda s: None)
    assert len(calls) == 2
    assert res["ok"] is False and "connection refused" in res["detail"]


def test_a_late_success_is_a_success(sink_on, monkeypatch):
    AppSetting.set("alerts.webhook.retries", "2")
    _capture(monkeypatch, [_Resp(503), _Resp(200)])
    res = wh.emit([F("cert.expiry")], "n", sleep=lambda s: None)
    assert res["ok"] is True and res["attempts"] == 2 and res["sent"] == 1


def test_retries_and_timeout_are_clamped(app):
    """An unbounded retry can outlive the 15-minute evaluation interval and
    stack runs on top of each other."""
    with app.app_context():
        AppSetting.set("alerts.webhook.retries", "99")
        AppSetting.set("alerts.webhook.timeout", "9999")
        assert wh.config()["retries"] == wh.RETRIES_MAX
        assert wh.config()["timeout"] == wh.TIMEOUT_MAX


def test_the_backoff_table_covers_every_allowed_retry(app):
    """Indexing past the table would raise inside the delivery loop — the one
    place an exception turns a failed alert into no alert at all."""
    assert len(wh._BACKOFF) >= wh.RETRIES_MAX


# ============================================================ sink contract ==
def test_the_webhook_sink_is_off_by_default(app):
    with app.app_context():
        assert routing.is_enabled(routing.SINK_WEBHOOK) is False
        assert wh.emit([F("cert.expiry")], "n") is None


def test_disabled_returns_none_and_matched_nothing_returns_ok(
        sink_on, monkeypatch):
    """A caller must be able to tell "off" from "on and delivered nothing" —
    only the second one is a problem worth a red badge."""
    calls = _capture(monkeypatch, [_Resp(200)])
    AppSetting.set("alerts.sink.webhook.checks", "host")
    res = wh.emit([F("cert.expiry")], "n")
    assert res["ok"] is True and res["sent"] == 0 and res["matched"] == 0
    assert calls == []

    AppSetting.set("alerts.sink.webhook.enabled", "0")
    assert wh.emit([F("cert.expiry")], "n") is None


def test_an_enabled_sink_with_no_url_reports_why_instead_of_going_quiet(app):
    with app.app_context():
        AppSetting.set("alerts.sink.webhook.enabled", "1")
        AppSetting.set("alerts.webhook.url", "")
        res = wh.emit([F("cert.expiry")], "n")
        assert res["ok"] is False and "URL" in res["detail"]


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://x/y",
                                 "gopher://x", "not-a-url"])
def test_a_non_http_url_is_refused_without_ever_reaching_the_client(
        app, bad, monkeypatch):
    """Asserting only "ok is False" passes for the WRONG reason: an unsupported
    scheme also blows up inside httpx, so the test stays green with the check
    deleted. The property that matters is that an arbitrary scheme is never
    handed to the HTTP client at all."""
    with app.app_context():
        AppSetting.set("alerts.sink.webhook.enabled", "1")
        AppSetting.set("alerts.webhook.url", bad)
        calls = _capture(monkeypatch, [_Resp(200)])
        res = wh.emit([F("cert.expiry")], "n")
        assert calls == []
        assert res["ok"] is False and res["detail"]


def test_a_private_network_target_is_allowed_on_purpose(app):
    """An automation host on the management LAN is the normal case in every
    install this ships to; blocking RFC 1918 would break the primary use."""
    assert wh.url_problem("http://192.0.2.41:5678/webhook/satom") == ""


def test_one_post_carries_every_finding_rather_than_one_post_each(
        sink_on, monkeypatch):
    """The router exists so a channel stops being a hose. N POSTs per
    evaluation is the hose with extra steps."""
    calls = _capture(monkeypatch, [_Resp(200)])
    res = wh.emit([F("cert.expiry"), F("host.disk"), F("device.down")], "n")
    assert len(calls) == 1
    assert json.loads(calls[0]["content"])["count"] == 3
    assert res["matched"] == 3


def test_the_webhook_carries_the_cooldown_and_the_feed_does_not(app):
    """A chat channel is a recipient, not a record: without the cooldown it
    receives the same finding every fifteen minutes for six hours."""
    assert routing.SINK_WEBHOOK in routing.NOTIFICATION_SINKS
    assert routing.SINK_SYSLOG not in routing.NOTIFICATION_SINKS


def test_a_blank_secret_field_keeps_the_stored_one(app):
    """The secret is never rendered back, so blank must mean "unchanged".
    Treating it as "delete" silently unsigns every future delivery."""
    class _Form(dict):
        def getlist(self, k):
            v = self.get(k)
            return v if isinstance(v, list) else ([v] if v else [])

    with app.app_context():
        wh.set_secret("keep-me")
        wh.save(_Form({"webhook_url": "https://x/y", "webhook_secret": ""}))
        assert wh.secret() == "keep-me"
        wh.save(_Form({"webhook_url": "https://x/y", "webhook_secret_clear": "on"}))
        assert wh.secret() == ""


# ========================================================= run() integration ==
@pytest.fixture()
def wired(app, monkeypatch):
    seen = {"bell": [], "email": [], "dispatch": []}
    monkeypatch.setattr(alerts.alert_syslog, "emit",
                        lambda f, n, dry_run=False: None)
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [])
    monkeypatch.setattr(alerts, "recipients", lambda: [])
    monkeypatch.setattr(alerts, "_is_read_only_replica", lambda: False)
    return seen


def _only_webhook(app):
    """Every notification sink off except the webhook, so ``dispatched`` and the
    cooldown can only have come from it."""
    AppSetting.set("alerts.enabled", "1")
    AppSetting.set("alerts.sink.in_app.enabled", "0")
    AppSetting.set("alerts.sink.email.enabled", "0")
    AppSetting.set("alerts.sink.webhook.enabled", "1")
    AppSetting.set("alerts.webhook.url", "https://hook.example.com/x")
    AppSetting.set("alerts.webhook.retries", "0")


def test_a_failed_webhook_does_not_stamp_the_cooldown(app, wired, monkeypatch):
    """Stamping an undelivered finding suppresses it for the whole window: the
    alert exists, is counted, and never arrives."""
    with app.app_context():
        _only_webhook(app)
        monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
        _capture(monkeypatch, [_Resp(500)])
        res = alerts.run()
        assert res["dispatched"] == 0
        assert any("webhook" in d for d in res["delivery_failed"])
        assert alerts.run()["fresh"] == 1       # still fresh — not suppressed


def test_a_delivered_webhook_counts_and_stamps(app, wired, monkeypatch):
    with app.app_context():
        _only_webhook(app)
        monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
        _capture(monkeypatch, [_Resp(200)] * 4)
        res = alerts.run()
        assert res["dispatched"] == 1 and "webhook" in res["channels"]
        assert alerts.run()["fresh"] == 0       # suppressed by the cooldown


def test_the_master_switch_gates_the_webhook_like_email(app, wired, monkeypatch):
    """It is an outbound call into somebody else's system. Turning the engine
    off and still POSTing to their SIEM is a surprise nobody asked for."""
    with app.app_context():
        _only_webhook(app)
        AppSetting.set("alerts.enabled", "0")
        monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
        calls = _capture(monkeypatch, [_Resp(200)])
        res = alerts.run()
        assert calls == []
        assert res["routed"][routing.SINK_WEBHOOK] == 0


# ============================================== alert.fired + hooks sink ====
def test_alert_fired_is_in_the_catalogue_with_a_complete_example():
    """A documented field the emitter does not send is a promise the product
    breaks on the integrator's first run."""
    assert "alert.fired" in ih.EVENTS
    spec = ih.EVENTS["alert.fired"]
    assert set(spec["example"]) == set(spec["payload"])


def test_the_documented_payload_matches_what_the_engine_actually_emits(app):
    """Checked against the emitter, never against a second hand-written list —
    a duplicated list is how the first one drifts."""
    with app.app_context():
        live = alerts.alert_event_payload(F("action.error.7"), "node-a")
    assert set(live) == set(ih.EVENTS["alert.fired"]["payload"])
    assert live["family"] == "actions"       # not the raw "action" prefix
    assert live["node"] == "node-a"


def test_the_hooks_sink_is_off_by_default_and_is_a_notification_sink(app):
    with app.app_context():
        assert routing.is_enabled(routing.SINK_HOOKS) is False
    assert routing.SINK_HOOKS in routing.NOTIFICATION_SINKS
    assert routing.SINK_HOOKS in routing.SINKS


def test_an_enabled_hooks_sink_with_no_hook_bound_stamps_nothing(
        app, wired, monkeypatch):
    """THE one that matters. dispatch() returns [] when nothing subscribes.
    Crediting that as handled suppresses the finding for six hours on behalf of
    a subscriber that does not exist."""
    with app.app_context():
        AppSetting.set("alerts.enabled", "1")
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        AppSetting.set("alerts.sink.email.enabled", "0")
        AppSetting.set("alerts.sink.hooks.enabled", "1")
        monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
        monkeypatch.setattr(ih, "dispatch", lambda *a, **k: [])
        res = alerts.run()
        assert res["queued"] == 0 and res["dispatched"] == 0
        assert any("no hook is bound" in d for d in res["delivery_failed"])
        assert alerts.run()["fresh"] == 1        # NOT suppressed


def test_a_bound_hook_fires_once_per_finding_and_stamps_them(
        app, wired, monkeypatch):
    with app.app_context():
        AppSetting.set("alerts.enabled", "1")
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        AppSetting.set("alerts.sink.email.enabled", "0")
        AppSetting.set("alerts.sink.hooks.enabled", "1")
        monkeypatch.setattr(alerts, "evaluate",
                            lambda: [F("cert.expiry"), F("host.disk")])
        sent = []

        def fake_dispatch(event, payload, by="system", dry_run=False):
            sent.append((event, payload["key"]))
            return [{"slug": "tg", "request_id": "r", "status": "queued"}]

        monkeypatch.setattr(ih, "dispatch", fake_dispatch)
        res = alerts.run()
        assert sent == [("alert.fired", "cert.expiry"),
                        ("alert.fired", "host.disk")]
        assert res["queued"] == 2
        assert alerts.run()["fresh"] == 0        # cooldown stamped


def test_queued_hooks_are_not_counted_as_dispatched(app, wired, monkeypatch):
    """An enqueue writes a JSON file. The runner that turns it into a process
    is a separate systemd unit, and it has been found disabled on a live node.
    A counter that says "sent" when nothing ran is the bug ``dispatched`` was
    introduced to fix, wearing a different hat."""
    with app.app_context():
        AppSetting.set("alerts.enabled", "1")
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        AppSetting.set("alerts.sink.email.enabled", "0")
        AppSetting.set("alerts.sink.hooks.enabled", "1")
        monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
        monkeypatch.setattr(ih, "dispatch", lambda *a, **k: [
            {"slug": "tg", "request_id": "r", "status": "queued"}])
        res = alerts.run()
        assert res["queued"] == 1
        assert res["dispatched"] == 0
        assert "hooks" in res["channels"]


def test_a_raising_dispatch_is_reported_and_does_not_sink_the_run(
        app, wired, monkeypatch):
    with app.app_context():
        AppSetting.set("alerts.enabled", "1")
        AppSetting.set("alerts.sink.hooks.enabled", "1")
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        AppSetting.set("alerts.sink.email.enabled", "0")
        monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])

        def boom(*a, **k):
            raise OSError("read-only filesystem")

        monkeypatch.setattr(ih, "dispatch", boom)
        res = alerts.run()
        assert any("hooks" in d and "read-only" in d
                   for d in res["delivery_failed"])
        assert res["queued"] == 0


# ================================================================ starters ==
def test_every_starter_compiles_and_defines_run():
    """Saving compiles too, but a starter that never compiled would ship a
    syntax error to every operator who clicked the button."""
    for slug, st in hook_starters.STARTERS.items():
        ns = {}
        exec(compile(st["source"], "<%s>" % slug, "exec"), ns)  # noqa: S102
        assert callable(ns.get("run")), slug


def test_every_starter_declares_the_secrets_its_source_reads():
    """``ctx.secret("X")`` on a secret the hook did not declare is simply absent
    from the child's environment and raises — in a subprocess, at 03:00."""
    for slug, st in hook_starters.STARTERS.items():
        used = set(re.findall(r'ctx\.secret\(\s*"([A-Z0-9_]+)"', st["source"]))
        assert used <= set(st["secrets"]), (slug, used, st["secrets"])
        assert used, slug          # a starter with no credential is suspicious


def test_every_starter_is_bound_to_an_event_that_exists():
    for slug, st in hook_starters.STARTERS.items():
        assert st["event"] in ih.EVENTS, slug


def test_alert_starters_only_read_keys_the_event_actually_emits(app):
    """A starter reading ``payload["device"]`` raises KeyError on the first real
    alert. The authority is the emitter, not the documentation."""
    with app.app_context():
        emitted = set(alerts.alert_event_payload(F("cert.expiry"), "n"))
    for slug, st in hook_starters.STARTERS.items():
        if st["event"] != "alert.fired":
            continue
        read = set(re.findall(r'a\.get\(\s*"([a-z_]+)"', st["source"]))
        read |= set(re.findall(r'a\[\s*"([a-z_]+)"\s*\]', st["source"]))
        assert read, slug
        assert read <= emitted, (slug, read - emitted)


def test_no_starter_hardcodes_a_credential():
    """A starter is versioned and readable in the editor. A token pasted into
    one is a token in every version snapshot of that hook."""
    for slug, st in hook_starters.STARTERS.items():
        src = st["source"]
        assert "https://hooks.slack.com/services/" not in src, slug
        assert not re.search(r'\bbot\d{6,}:', src), slug
        assert "xoxb-" not in src, slug


def test_the_editor_default_is_an_alias_and_not_a_second_copy():
    """Two authors of one string is how the published site lost its Docs link."""
    from app.views import integrations as view
    assert view.SAMPLE_HOOK is hook_starters.STARTERS["change-ticket"]["source"]


def test_an_unknown_starter_slug_falls_back_instead_of_emptying_the_editor():
    """A query-string typo must not look like "this product ships no
    examples" — a blank editor is exactly that message."""
    assert hook_starters.get("nope")["source"]
    assert hook_starters.get("")["source"]
    assert hook_starters.get("nope") is hook_starters.STARTERS[
        hook_starters.DEFAULT_STARTER]


def test_the_catalog_does_not_ship_four_hook_bodies_to_render_four_labels():
    for row in hook_starters.catalog():
        assert "source" not in row
        assert row["label"] and row["description"] and row["event"]
