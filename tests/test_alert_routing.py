"""Alert routing and the syslog feed — what a filter breaks, it breaks quietly.

Nothing fails when a router drops the wrong finding. There is no exception, no
red badge and no log line: the channel just goes quiet, and a quiet channel is
exactly what a healthy one looks like. Every guard here exists because the
failure it describes would otherwise be invisible until somebody asked "why
didn't we get paged for that?" weeks later.

The three that cost the most thought:

* **``action.*`` findings belong to the ``actions`` family.** The engine's key
  prefix and the family name have never matched. A mask built on the prefix
  would tick "Scheduled automation" in the UI and deliver nothing.
* **A stored empty mask is not "everything".** ``None`` (never configured) and
  ``""`` (operator unticked every box) are different intentions, and collapsing
  them is how a filter delivers the exact opposite of what the screen showed.
* **Engine failures and unknown families bypass both filters.** A router that
  can silence the component reporting that a check crashed converts a defect
  into silence.
"""
from __future__ import annotations

import io
import os
import re
import time
from datetime import datetime, timezone

import pytest

from app.models import AppSetting
from app.services import alert_routing as routing
from app.services import alert_syslog as syslog


def F(key, severity="warning", title="t", detail="d"):
    return {"key": key, "severity": severity, "title": title, "detail": detail}


# --------------------------------------------------------------- families --
def test_action_findings_land_in_the_actions_family():
    """The engine emits ``action.*``; every label, toggle and settings key says
    "actions". A mask keyed on the raw prefix ticks a box that matches nothing."""
    assert routing.family_of("action.error.7") == "actions"
    assert routing.family_of("action.overdue") == "actions"
    assert "actions" in routing.FAMILIES
    assert "action" not in routing.FAMILIES


@pytest.mark.parametrize("key,family", [
    ("cert.expiry", "cert"), ("cert.renew_failed", "cert"),
    ("git.behind", "git"), ("git.diverged", "git"),
    ("device.error.fw08", "device"), ("backup.stale", "backup"),
    ("drift.fw08.abc123", "drift"), ("host.disk", "host"),
])
def test_known_prefixes_map_to_their_family(key, family):
    assert routing.family_of(key) == family


def test_every_key_prefix_the_engine_can_emit_is_routable():
    """Derived from the engine source, never from a second hand-written list.

    A new check ships with a new prefix, the router has never heard of it, and
    the mask drops it. This reads the literals out of ``alerts.py`` so the
    guard cannot fall out of date with the thing it guards.
    """
    with io.open("app/services/alerts.py", encoding="utf-8") as fh:
        src = fh.read()
    prefixes = set(re.findall(r'"key":\s*f?"([a-z_]+)[.\"]', src))
    assert len(prefixes) >= 7, "regex stopped matching the engine's key literals"
    unroutable = sorted(p for p in prefixes
                        if routing.family_of(p + ".x") == routing.FAM_UNKNOWN)
    assert not unroutable, (
        "these checks emit keys no sink filter can name: %s" % unroutable)


def test_an_unknown_prefix_is_unfilterable_rather_than_dropped():
    """Fail towards delivery. A prefix nobody taught the router about is noise
    if delivered and a silent loss if dropped; only one of those is visible."""
    assert routing.family_of("brandnew.thing") == routing.FAM_UNKNOWN
    assert routing.FAM_UNKNOWN in routing.UNFILTERABLE


# ------------------------------------------------------------- predicate ---
def test_severity_floor_drops_only_what_is_below_it():
    kw = dict(family="cert", families=None)
    assert not routing.accepts(severity="info", floor="warning", **kw)
    assert routing.accepts(severity="warning", floor="warning", **kw)
    assert routing.accepts(severity="critical", floor="warning", **kw)
    assert not routing.accepts(severity="warning", floor="critical", **kw)


def test_mask_drops_families_it_does_not_name():
    kw = dict(severity="critical", floor="info")
    assert routing.accepts(family="cert", families={"cert", "git"}, **kw)
    assert not routing.accepts(family="host", families={"cert", "git"}, **kw)


def test_no_mask_means_every_family():
    assert routing.accepts(family="host", severity="info", floor="info",
                           families=None)


def test_engine_failures_ignore_the_severity_floor():
    """``engine.error`` is emitted at ``info``. A NOC that raises its floor to
    critical would otherwise stop hearing that its checks are crashing — and a
    channel silenced by a broken check looks exactly like a healthy one."""
    assert routing.accepts(family=routing.FAM_ENGINE, severity="info",
                           floor="critical", families=None)


def test_engine_failures_ignore_the_family_mask():
    assert routing.accepts(family=routing.FAM_ENGINE, severity="info",
                           floor="info", families=set())


def test_unknown_family_ignores_both_filters():
    assert routing.accepts(family=routing.FAM_UNKNOWN, severity="info",
                           floor="critical", families=set())


# ---------------------------------------------------------------- config ---
def test_defaults_reproduce_the_behaviour_that_predates_the_filter(app):
    """Upgrading an install must not quietly narrow a path nobody touched:
    email and the bell delivered everything before sinks existed."""
    with app.app_context():
        for sink in (routing.SINK_IN_APP, routing.SINK_EMAIL):
            assert routing.is_enabled(sink)
            assert routing.min_severity(sink) == routing.SEV_INFO
            assert routing.mask(sink) is None
        assert not routing.is_enabled(routing.SINK_SYSLOG)


def test_an_unset_mask_delivers_everything_and_an_empty_one_delivers_nothing(app):
    """``None`` and ``""`` are different intentions. Collapsing the empty set
    into "all" makes the settings page a liar in the one direction that
    matters: it would show no ticked family and deliver every family."""
    with app.app_context():
        AppSetting.set("alerts.sink.email.checks", "")
        assert routing.mask(routing.SINK_EMAIL) == set()
        assert routing.route([F("cert.expiry")], routing.SINK_EMAIL) == []
        cfg = routing.sink_config(routing.SINK_EMAIL)
        assert cfg["silent"] is True and cfg["masked"] is True

        AppSetting.set("alerts.sink.email.checks", "cert,host")
        assert routing.mask(routing.SINK_EMAIL) == {"cert", "host"}
        assert routing.sink_config(routing.SINK_EMAIL)["silent"] is False


def test_a_disabled_sink_routes_nothing_even_to_unfilterable_findings(app):
    with app.app_context():
        AppSetting.set("alerts.sink.email.enabled", "0")
        assert routing.route([F("engine.error", "info")],
                             routing.SINK_EMAIL) == []


def test_route_applies_floor_and_mask_together(app):
    with app.app_context():
        AppSetting.set("alerts.sink.email.enabled", "1")
        AppSetting.set("alerts.sink.email.min_severity", "warning")
        AppSetting.set("alerts.sink.email.checks", "cert,device")
        findings = [F("cert.expiry", "warning"), F("cert.error", "info"),
                    F("host.disk", "critical"), F("device.down", "critical"),
                    F("engine.error", "info")]
        got = [f["key"] for f in routing.route(findings, routing.SINK_EMAIL)]
        assert got == ["cert.expiry", "device.down", "engine.error"]


# ------------------------------------------------------------------ save ---
class _Form(dict):
    def getlist(self, key):
        v = self.get(key, [])
        return v if isinstance(v, list) else [v]


def test_a_bad_severity_falls_back_to_info_and_never_to_critical(app):
    """A typo in a settings field must not be able to silence an alert path."""
    with app.app_context():
        routing.save(routing.SINK_EMAIL,
                     _Form({"email_enabled": "on", "email_min_severity": "urgent"}))
        assert routing.min_severity(routing.SINK_EMAIL) == routing.SEV_INFO


def test_the_mask_is_only_written_when_the_form_carried_the_checkboxes(app):
    """Without the hidden marker a partial POST reads as "no boxes ticked" and
    silences the sink — the same shape of bug as a checkbox form that forgets
    its ``*_submitted`` field."""
    with app.app_context():
        AppSetting.set("alerts.sink.email.checks", "cert")
        routing.save(routing.SINK_EMAIL, _Form({"email_enabled": "on"}))
        assert routing.mask(routing.SINK_EMAIL) == {"cert"}

        routing.save(routing.SINK_EMAIL,
                     _Form({"email_enabled": "on", "email_checks_submitted": "1",
                            "email_checks": ["git", "host"]}))
        assert routing.mask(routing.SINK_EMAIL) == {"git", "host"}


def test_unticking_every_box_is_stored_literally(app):
    with app.app_context():
        routing.save(routing.SINK_EMAIL,
                     _Form({"email_enabled": "on",
                            "email_checks_submitted": "1"}))
        assert routing.mask(routing.SINK_EMAIL) == set()


def test_save_all_covers_every_sink(app):
    with app.app_context():
        routing.save_all(_Form({"syslog_enabled": "on",
                                "in_app_enabled": "on"}))
        assert routing.is_enabled(routing.SINK_SYSLOG)
        assert not routing.is_enabled(routing.SINK_EMAIL)


# ---------------------------------------------------------------- syslog ---
_TS = datetime(2026, 8, 13, 4, 5, 6, tzinfo=timezone.utc)
_CFG = {"host": "faz", "port": 514, "proto": "udp", "format": "rfc5424",
        "facility": "local0"}


def test_rfc5424_priority_is_facility_times_eight_plus_severity():
    """local0 (16) with an err (3) is 131. A collector filters on this number;
    getting it wrong files every alert under the wrong facility silently."""
    line = syslog.format_line(F("cert.expiry", "critical"), _CFG, "a1", _TS)
    assert line.startswith("<131>1 ")
    warn = syslog.format_line(F("cert.expiry", "warning"), _CFG, "a1", _TS)
    assert warn.startswith("<132>1 ")
    info = syslog.format_line(F("cert.expiry", "info"), _CFG, "a1", _TS)
    assert info.startswith("<134>1 ")


def test_rfc5424_carries_key_family_and_node_as_structured_data():
    line = syslog.format_line(F("action.error.7", "warning"), _CFG, "a1", _TS)
    assert '[satom@32473 key="action.error.7"' in line
    assert 'family="actions"' in line and 'node="a1"' in line
    # MSGID is the family — the field a collector can filter without parsing SD.
    assert " SATOM - actions [" in line


def test_structured_data_escapes_the_characters_that_close_it():
    r"""An unescaped ``"`` or ``]`` inside a value ends the SD block early and
    the rest of the event is parsed as free text."""
    line = syslog.format_line(
        F('drift.a]b"c\\d', "warning"), _CFG, "a1", _TS)
    assert 'key="drift.a\\]b\\"c\\\\d"' in line


def test_cef_header_escapes_the_pipe_that_separates_its_fields():
    """An alert title containing ``|`` would otherwise shift every field after
    it — the collector reads the severity out of the message text."""
    cfg = dict(_CFG, format="cef")
    line = syslog.format_line(
        F("cert.expiry", "critical", title="a|b"), cfg, "a1", _TS)
    assert "|a\\|b|9|" in line
    assert line.startswith("<131>Aug 13 04:05:06 a1 CEF:0|Vision EBC|SATOM|")


def test_the_cef_header_is_local_time_and_carries_an_unambiguous_epoch():
    """RFC 3164 has no timezone field, so a collector reads that header as the
    sender's local clock. Emitting UTC there files every event at the wrong
    hour on any install that is not on UTC — invisibly, because the event
    itself is perfectly well formed. ``rt`` states the instant outright.

    The clock is pinned to Zurich for the duration: a1 runs on UTC, so an
    assertion built from ``astimezone()`` would apply the same conversion the
    code does and pass whatever the code did. A guard that reproduces the
    transformation it is checking is not a guard.
    """
    prev = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Zurich"
    time.tzset()
    try:
        cfg = dict(_CFG, format="cef")
        line = syslog.format_line(F("cert.expiry", "info"), cfg, "a1", _TS)
        # 04:05:06Z is 06:05:06 in Zurich in August.
        assert line.startswith("<134>Aug 13 06:05:06 a1 CEF:0|"), line
        assert "|rt=%d " % int(_TS.timestamp() * 1000) in line
        # The RFC 5424 line is unaffected: it has a zone field and uses it.
        assert " 2026-08-13T04:05:06.000Z " in syslog.format_line(
            F("cert.expiry", "info"), _CFG, "a1", _TS)
    finally:
        if prev is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = prev
        time.tzset()


def test_rfc5424_states_its_timezone_explicitly():
    """The other half of the same problem: RFC 5424 has a zone field, so this
    one is emitted in UTC and says so."""
    line = syslog.format_line(F("cert.expiry", "info"), _CFG, "a1", _TS)
    assert " 2026-08-13T04:05:06.000Z " in line


def test_cef_extension_escapes_the_equals_that_separates_its_pairs():
    cfg = dict(_CFG, format="cef")
    line = syslog.format_line(
        F("cert.expiry", "info", detail="k=v"), cfg, "a1", _TS)
    assert "msg=k\\=v" in line


def test_cef_severity_uses_the_zero_to_ten_scale():
    cfg = dict(_CFG, format="cef")
    for sev, num in (("info", 3), ("warning", 6), ("critical", 9)):
        assert "|%d|" % num in syslog.format_line(F("cert.x", sev), cfg,
                                                  "a1", _TS)


def test_a_multiline_detail_is_collapsed_onto_one_line():
    """Both encodings are line-delimited on the wire: an embedded newline does
    not make a prettier event, it makes a second headerless unparseable one."""
    line = syslog.format_line(
        F("host.disk", "warning", detail="one\ntwo\r\nthree"), _CFG, "a1", _TS)
    assert "\n" not in line and "\r" not in line
    assert "one two three" in line


def test_emit_returns_none_when_the_sink_is_off(app):
    """"Disabled" and "enabled but delivered nothing" are different states and
    only the second one is a problem."""
    with app.app_context():
        AppSetting.set("alerts.sink.syslog.enabled", "0")
        assert syslog.emit([F("cert.expiry")], "a1") is None


def test_emit_reports_an_enabled_sink_with_no_collector_as_not_ok(app):
    with app.app_context():
        AppSetting.set("alerts.sink.syslog.enabled", "1")
        AppSetting.set("alerts.syslog.host", "")
        res = syslog.emit([F("cert.expiry")], "a1")
        assert res["ok"] is False and "no collector host" in res["detail"]


def test_a_dead_collector_never_raises_into_the_run(app):
    """The feed failing must not take the email path down with it."""
    with app.app_context():
        AppSetting.set("alerts.sink.syslog.enabled", "1")
        AppSetting.set("alerts.syslog.host", "127.0.0.1")
        AppSetting.set("alerts.syslog.port", "1")
        AppSetting.set("alerts.syslog.proto", "tcp")
        res = syslog.emit([F("cert.expiry")], "a1")
        assert res["ok"] is False and res["sent"] == 0


def test_syslog_config_falls_back_on_junk(app):
    with app.app_context():
        AppSetting.set("alerts.syslog.port", "not-a-port")
        AppSetting.set("alerts.syslog.proto", "carrier-pigeon")
        AppSetting.set("alerts.syslog.format", "hieroglyphs")
        AppSetting.set("alerts.syslog.facility", "nope")
        cfg = syslog.config()
        assert cfg["port"] == 514 and cfg["proto"] == "udp"
        assert cfg["format"] == "rfc5424" and cfg["facility"] == "local0"
