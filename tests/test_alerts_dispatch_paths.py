"""``alerts.run`` has two dispatch paths, and conflating them is silent.

The feed (syslog/CEF) and the notifications (bell, email) look like three
entries in one list of destinations. They are not, and a single loop over three
sinks gets one of them wrong by construction:

* the feed must **not** carry the cooldown — a record queried after the fact
  cannot have six-hour holes in it, because a hole reads as "nothing was wrong";
* the feed must run on the **read-only standby**, which is exactly where the
  notification path correctly refuses to run;
* the feed must **not** count towards ``dispatched`` — a healthy record that
  makes a dead mailbox look alive is the same defect the ``dispatched`` counter
  was introduced to fix, wearing a different hat.

And now that a finding can be filtered out of every notification sink, the
cooldown has to stamp what was *delivered*, not what was *evaluated*: stamping
an undelivered finding suppresses it for the whole window, so widening a filter
would appear not to work until the window expired.
"""
from __future__ import annotations

import pytest

from app.models import AppSetting
from app.services import alerts
from app.services import alert_routing as routing


def F(key, severity="warning"):
    return {"key": key, "severity": severity, "title": "t " + key,
            "detail": "d"}


@pytest.fixture()
def wired(app, monkeypatch):
    """Engine with every outbound edge stubbed and recorded."""
    seen = {"syslog": [], "bell": [], "email": []}

    def fake_emit(findings, node, dry_run=False):
        seen["syslog"].append([f["key"] for f in findings])
        return {"ok": True, "sent": len(findings), "matched": len(findings)}

    monkeypatch.setattr(alerts.alert_syslog, "emit", fake_emit)
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [1])
    monkeypatch.setattr(alerts.notify, "push_many",
                        lambda ids, title, **kw: seen["bell"].append(title))
    monkeypatch.setattr(alerts, "recipients", lambda: ["ops@example.com"])
    monkeypatch.setattr(
        alerts.email_service, "send_email",
        lambda to, subj, text, html=None: (seen["email"].append(subj),
                                           {"ok": True})[1])
    monkeypatch.setattr(alerts, "_is_read_only_replica", lambda: False)
    return seen


def test_the_feed_runs_on_a_read_only_standby_where_notification_cannot(
        app, wired, monkeypatch):
    """Without this the standby's own cert, host and reachability findings
    never leave the node at all — the copy meant to survive the primary is the
    one nobody can see."""
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    monkeypatch.setattr(alerts, "_is_read_only_replica", lambda: True)
    with app.app_context():
        res = alerts.run()
    assert wired["syslog"] == [["cert.expiry"]]
    assert res["syslog"]["sent"] == 1
    assert res["dispatched"] == 0 and "replica" in res["skipped"]
    assert wired["bell"] == [] and wired["email"] == []


def test_the_feed_is_not_suppressed_by_the_cooldown(app, wired, monkeypatch):
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    with app.app_context():
        AppSetting.set("alerts.sink.in_app.enabled", "1")
        alerts.run()
        alerts.run()          # second run, same finding, inside the window
    assert wired["syslog"] == [["cert.expiry"], ["cert.expiry"]]
    # ...while the bell, correctly, only rang once.
    assert len(wired["bell"]) == 1


def test_a_healthy_feed_cannot_make_a_silent_notification_path_look_alive(
        app, wired, monkeypatch):
    """``dispatched`` is the number an operator reads to decide the channel is
    healthy. Counting the record in it hides a dead mailbox behind a live
    collector."""
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    with app.app_context():
        AppSetting.set("alerts.enabled", "0")          # email off
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        res = alerts.run()
    assert res["syslog"]["sent"] == 1
    assert res["dispatched"] == 0
    assert "syslog" in res["channels"]


def test_a_feed_only_run_does_not_stamp_the_cooldown(app, wired, monkeypatch):
    """Otherwise repairing the mailbox would appear not to work until the
    suppression window it never earned had expired."""
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    with app.app_context():
        AppSetting.set("alerts.enabled", "0")
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        alerts.run()
        assert alerts._load_state() == {}


def test_a_refused_email_does_not_stamp_the_cooldown(app, wired, monkeypatch):
    """The relay said no. The alert exists, was counted, and arrived nowhere —
    stamping it here is how "454 4.7.1 Relay access denied" stayed invisible
    for weeks: every run suppressed the finding it had just failed to send."""
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    monkeypatch.setattr(alerts.email_service, "send_email",
                        lambda *a, **k: {"ok": False, "detail": "454 refused"})
    with app.app_context():
        AppSetting.set("alerts.enabled", "1")
        AppSetting.set("alerts.sink.in_app.enabled", "0")
        AppSetting.set("alerts.sink.email.enabled", "1")
        res = alerts.run()
        assert alerts._load_state() == {}
    assert res["dispatched"] == 0
    assert any("454" in d for d in res["delivery_failed"])


def test_dispatched_counts_findings_a_sink_actually_accepted(
        app, wired, monkeypatch):
    monkeypatch.setattr(alerts, "evaluate",
                        lambda: [F("cert.expiry"), F("host.disk")])
    with app.app_context():
        AppSetting.set("alerts.enabled", "0")
        AppSetting.set("alerts.sink.in_app.enabled", "1")
        AppSetting.set("alerts.sink.in_app.checks", "cert")
        res = alerts.run()
    assert res["fresh"] == 2
    assert res["routed"][routing.SINK_IN_APP] == 1
    assert res["dispatched"] == 1
    assert len(wired["bell"]) == 1


def test_a_finding_no_sink_accepted_is_not_stamped_into_the_cooldown(
        app, wired, monkeypatch):
    """It reached nobody. If widening the mask tomorrow had to wait out a
    window the finding never earned, the filter would look broken."""
    monkeypatch.setattr(alerts, "evaluate",
                        lambda: [F("cert.expiry"), F("host.disk")])
    with app.app_context():
        AppSetting.set("alerts.enabled", "0")
        AppSetting.set("alerts.sink.in_app.enabled", "1")
        AppSetting.set("alerts.sink.in_app.checks", "cert")
        alerts.run()
        state = alerts._load_state()
    assert set(state) == {"cert.expiry"}


def test_the_email_master_switch_still_gates_the_email_sink(
        app, wired, monkeypatch):
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    with app.app_context():
        AppSetting.set("alerts.enabled", "0")
        AppSetting.set("alerts.sink.email.enabled", "1")
        res = alerts.run()
    assert wired["email"] == [] and res["routed"][routing.SINK_EMAIL] == 0

    with app.app_context():
        AppSetting.set("alerts.enabled", "1")
        AppSetting.set("alerts.state", "{}")
        res = alerts.run()
    assert len(wired["email"]) == 1 and res["routed"][routing.SINK_EMAIL] == 1


def test_a_dry_run_sends_nothing_on_either_path(app, wired, monkeypatch):
    monkeypatch.setattr(alerts, "evaluate", lambda: [F("cert.expiry")])
    with app.app_context():
        res = alerts.run(dry_run=True)
    assert res["dry_run"] is True and res["dispatched"] == 0
    assert wired["bell"] == [] and wired["email"] == []
    # The feed is asked what it WOULD send, never told to send it.
    assert res["syslog"] is not None


def test_engine_failures_reach_the_bell_through_a_narrowed_filter(
        app, wired, monkeypatch):
    """An operator who masks down to ``cert`` at a ``critical`` floor still has
    to hear that a check crashed — otherwise the checks stop and the console
    stays green."""
    monkeypatch.setattr(alerts, "evaluate",
                        lambda: [{"key": "engine.error", "severity": "info",
                                  "title": "check exploded", "detail": "boom"}])
    with app.app_context():
        AppSetting.set("alerts.enabled", "0")
        AppSetting.set("alerts.sink.in_app.enabled", "1")
        AppSetting.set("alerts.sink.in_app.min_severity", "critical")
        AppSetting.set("alerts.sink.in_app.checks", "cert")
        res = alerts.run()
    assert res["dispatched"] == 1 and wired["bell"] == ["check exploded"]
