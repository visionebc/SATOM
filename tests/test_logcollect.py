"""Unit tests for the read-only log-collection service (pure helpers only).

``collect``/``start`` need a live appliance + SSH and are not exercised here;
these cover the network-free guards and filename/metadata parsing — the same
boundary the desktop service unit-tests.
"""
import pytest

from app.services import logcollect
from app.services.ssh_ops import ReadOnlyViolation


def test_battery_is_all_readonly():
    # Every battery command must pass the same read-only guard a custom run uses.
    for cmd in logcollect.DIAGNOSTIC_COMMANDS:
        # parse_commands raises on anything that isn't get/show/diagnose
        assert logcollect.parse_commands(cmd) == [cmd]


def test_parse_commands_drops_blanks_and_comments():
    text = "get system status\n\n# a comment\n  diagnose hardware cpu  \n"
    assert logcollect.parse_commands(text) == [
        "get system status",
        "diagnose hardware cpu",
    ]


def test_parse_commands_rejects_write():
    with pytest.raises(ReadOnlyViolation):
        logcollect.parse_commands("get system status\nset system hostname pwn")


def test_parse_commands_rejects_exec():
    with pytest.raises(ReadOnlyViolation):
        logcollect.parse_commands("execute reboot")


def test_report_filename_is_filesystem_safe():
    fn = logcollect.report_filename(7, "before/after incident", stamp="20260628-120000")
    assert fn == "7_logs_before_after_incident_20260628-120000.txt"
    assert "/" not in fn and " " not in fn


def test_report_filename_blank_label_defaults_manual():
    fn = logcollect.report_filename(3, "", stamp="20260628-120000")
    assert fn == "3_logs_manual_20260628-120000.txt"


def test_parse_meta_roundtrip_with_underscored_label():
    fn = logcollect.report_filename(12, "pre_upgrade", stamp="20260628-090000")
    meta = logcollect._parse_meta(fn)
    assert meta == {"device_id": "12", "label": "pre_upgrade", "stamp": "20260628-090000"}


def test_read_log_rejects_path_traversal():
    assert logcollect.read_log("../../etc/passwd") is None
    assert logcollect.read_log("nope") is None  # not a .txt
