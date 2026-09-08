"""Guards for the write-capable console (``services.ssh_console``).

The unit under test is a GATE, and a gate that is wrong in the permissive
direction fails silently: the command goes through, the appliance does what it
was told, and nothing anywhere reports a problem. So most of these assert a
REFUSAL, and the mutation harness exists to prove each refusal is load-bearing.
"""
from __future__ import annotations

import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import ssh_console as sc
from app.services.ssh_ops import FortiSSHError

ROOT = Path(__file__).resolve().parents[1]


# ============================================================ THE GATE =====

def test_the_appliance_enders_are_refused():
    for cmd in ("execute factoryreset",
                "execute factoryreset keepvmlicense",
                "execute formatlogdisk",
                "execute erase-disk port1",
                "execute format",
                "execute usb-disk format"):
        tier, why = sc.classify_command(cmd)
        assert tier == sc.TIER_FORBIDDEN, cmd
        assert why, "a refusal with no reason is a dead end for the operator"


def test_forbidden_beats_the_acknowledgement():
    """There is no flag, checkbox or permission that sends a factory reset.

    The disruptive tier exists so an operator can say "yes, reboot it". If
    ``allow_disruptive`` also unlocked the forbidden tier, the two tiers would
    be one tier with two labels.
    """
    with pytest.raises(sc.ConsoleViolation):
        sc.assert_console_command("execute factoryreset", allow_disruptive=True)


def test_the_forbidden_scan_ignores_quoted_text():
    """``set comment "never run execute factoryreset"`` is a comment, not a reset."""
    tier, _ = sc.classify_command('set comment "never run execute factoryreset"')
    assert tier == sc.TIER_SAFE


def test_the_forbidden_scan_is_not_anchored():
    """A destroyer is refused wherever it appears outside quotes.

    Anchoring the whole gate would be consistent and wrong: for these four
    commands a false positive costs one rephrase and a false negative costs the
    appliance.
    """
    tier, _ = sc.classify_command("end && execute factoryreset")
    assert tier == sc.TIER_FORBIDDEN


def test_the_disruptive_set_needs_an_acknowledgement():
    for cmd in ("execute reboot",
                "execute shutdown",
                "execute restore config tftp cfg.conf 192.0.2.9",
                "execute ha failover",
                "set password Hunter2",
                "execute backup config tftp cfg.conf 192.0.2.9"):
        tier, why = sc.classify_command(cmd)
        assert tier == sc.TIER_DISRUPTIVE, cmd
        assert why
        with pytest.raises(sc.ConsoleViolation):
            sc.assert_console_command(cmd)
        assert sc.assert_console_command(cmd, allow_disruptive=True) == cmd


def test_a_pasted_prompt_line_does_not_bypass_the_acknowledgement():
    """``FortiWeb # execute reboot`` is how a line comes out of a session log,
    and retyping a sequence from one is exactly what an operator does under
    pressure. Anchoring the disruptive scan to the start of the line — the
    first design — let that paste through without an acknowledgement."""
    tier, _ = sc.classify_command("FortiWeb # execute reboot")
    assert tier == sc.TIER_DISRUPTIVE
    with pytest.raises(sc.ConsoleViolation):
        sc.assert_console_command("FortiWeb # execute reboot")


def test_a_value_that_merely_mentions_a_reboot_is_not_a_reboot():
    """The false positive anchoring was meant to prevent cannot happen: FortiOS
    requires quotes around any value with whitespace, and quoted spans are
    blanked before the scan."""
    assert sc.classify_command('set comment "reboot window is saturday"')[0] == sc.TIER_SAFE
    assert sc.classify_command("set comment reboot-window-is-saturday")[0] == sc.TIER_SAFE
    assert sc.classify_command("get system status")[0] == sc.TIER_SAFE


def test_ordinary_configuration_is_allowed():
    for cmd in ("config system dns", "set primary 192.0.2.2", "end",
                "edit port1", "next", "delete stale-pool",
                "diagnose system ha status", "execute ping 192.0.2.9"):
        assert sc.classify_command(cmd)[0] == sc.TIER_SAFE, cmd


def test_an_empty_command_is_refused_not_ignored():
    assert sc.classify_command("   ")[0] == sc.TIER_FORBIDDEN


def test_the_read_only_module_is_untouched_by_this_one():
    """``ssh_ops.assert_readonly`` must still refuse every write.

    Six services import ``ssh_ops`` on the promise in its docstring. If the
    write path ever lands there instead of here, this is what says so.
    """
    from app.services.ssh_ops import ReadOnlyViolation, assert_readonly
    for cmd in ("config system dns", "set primary 192.0.2.2", "execute reboot"):
        with pytest.raises(ReadOnlyViolation):
            assert_readonly(cmd)


# ========================================================== PARSING =======

def test_comments_are_only_whole_lines():
    """A ``#`` inside a value is data.

    Stripping from the first ``#`` anywhere would silently truncate the command
    the operator is looking at, and they would watch a different one run.
    """
    got = sc.parse_script("# a note\nset passwd aa#bb\n\n   \nend\n")
    assert got == ["set passwd aa#bb", "end"]


# ================================================== READING THE ANSWER ====

def test_success_and_failure_are_told_apart_by_the_sign():
    assert sc.classify_output("Return code 0")[0] == "ok"
    assert sc.classify_output("Command fail. Return code -3")[0] == "error"


def test_silence_is_not_a_failure():
    """A FortiOS ``set`` that works prints nothing.

    Treating an empty answer as failure would mark every correct configuration
    line red — the opposite mistake from the reachability probes, where silence
    genuinely means nothing was learned.
    """
    assert sc.classify_output("")[0] == "ok"
    assert sc.classify_output("   \n")[0] == "ok"


def test_the_box_own_words_are_what_decide():
    for text, detail in (("Unknown action 0", "unknown action"),
                         ("permission denied", "permission denied"),
                         ("value parse error", "parse error"),
                         ("entry not found", "entry not found"),
                         ("The object is in use", "object still referenced")):
        status, got = sc.classify_output(text)
        assert (status, got) == ("error", detail), text


# ========================================================= REDACTION ======

def test_secrets_never_survive_into_a_transcript():
    text = ("config system admin\nset password S3cr3t!\nset psk abc123\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n")
    out = sc.redact(text)
    for leak in ("S3cr3t!", "abc123", "MIIE"):
        assert leak not in out, leak
    assert sc.REDACTED in out
    assert "set password" in out, "the COMMAND stays; only the value goes"


# ======================================================== RUN SCRIPT ======

class _FakeSession:
    """A console session that records what it was asked to send."""

    def __init__(self, answers=None, fail_connect=None, pager=""):
        self.answers = answers or {}
        self.fail_connect = fail_connect
        self.pager_output = pager
        self.sent: list[str] = []
        self.closed = False

    def connect(self):
        if self.fail_connect:
            raise FortiSSHError(self.fail_connect)
        return self

    def run(self, command, *, allow_disruptive=False, quiet=1.0, maxt=30.0):
        self.sent.append(command)
        sc.assert_console_command(command, allow_disruptive=allow_disruptive)
        return self.answers.get(command, "")

    def close(self):
        self.closed = True


_APP = SimpleNamespace(name="fortiweb12", host="192.0.2.12", kind="fortiweb",
                       ssh_port=22, username="admin", firmware="7.6.8")


def test_a_forbidden_line_stops_the_script_before_the_session_opens():
    """Half a configuration change is worse than none.

    A refusal discovered on line 3 after lines 1-2 already landed leaves the
    appliance in a state the operator cannot read off the page.
    """
    sess = _FakeSession()
    res = sc.run_script(_APP, ["config system dns", "set primary 192.0.2.2",
                               "execute factoryreset"],
                        session_factory=lambda: sess)
    assert sess.sent == [], "nothing may be sent when any line is forbidden"
    assert res.error
    assert [r.status for r in res.rows] == ["not_run", "not_run", "refused"]


def test_commands_after_a_failure_are_reported_not_dropped():
    sess = _FakeSession(answers={"config system dns": "Command fail. Return code -3"})
    res = sc.run_script(_APP, ["config system dns", "set primary 192.0.2.2", "end"],
                        session_factory=lambda: sess)
    assert [r.status for r in res.rows] == ["error", "not_run", "not_run"]
    assert sess.sent == ["config system dns"]
    assert res.notes and "modal" in res.notes[0]
    assert res.failed == 1


def test_running_on_is_possible_but_not_the_default():
    sess = _FakeSession(answers={"config system dns": "Command fail. Return code -3"})
    res = sc.run_script(_APP, ["config system dns", "end"],
                        stop_on_error=False, session_factory=lambda: sess)
    assert [r.status for r in res.rows] == ["error", "ok"]
    assert sess.sent == ["config system dns", "end"]


def test_an_oversized_script_is_cut_out_loud():
    cmds = [f"get system status {i}" for i in range(sc.MAX_COMMANDS + 5)]
    sess = _FakeSession()
    res = sc.run_script(_APP, cmds, session_factory=lambda: sess)
    assert len(res.rows) == sc.MAX_COMMANDS
    assert res.notes and "5 were not sent" in res.notes[0]


def test_a_session_that_never_opened_reports_every_line_as_not_run():
    """Not as failures. Nothing was tried, so nothing failed."""
    sess = _FakeSession(fail_connect="SSH auth failed for fortiweb12")
    res = sc.run_script(_APP, ["get system status"], session_factory=lambda: sess)
    assert res.error == "SSH auth failed for fortiweb12"
    assert [r.status for r in res.rows] == ["not_run"]
    assert res.transcript == ""


def test_the_session_is_closed_even_when_a_command_explodes():
    class _Boom(_FakeSession):
        def run(self, command, **kw):
            raise FortiSSHError("channel closed")

    sess = _Boom()
    res = sc.run_script(_APP, ["get system status"], session_factory=lambda: sess)
    assert sess.closed
    assert res.rows[0].status == "error"


def test_the_transcript_is_redacted():
    sess = _FakeSession(answers={"get system status": "Password: S3cr3t!"})
    res = sc.run_script(_APP, ["set password S3cr3t!", "get system status"],
                        allow_disruptive=True, session_factory=lambda: sess)
    assert "S3cr3t!" not in res.transcript.split("get system status")[0]
    assert sc.REDACTED in res.transcript


# ============================================== CREDENTIAL VERIFICATION ===

def _clock():
    t = {"v": 0.0}

    def tick(step=0.0):
        t["v"] += step
        return t["v"]
    return t, tick


def test_a_rejected_credential_is_not_an_unreachable_device():
    """They send the operator to two different places.

    "Wrong password" makes somebody reset a credential; "unreachable" makes
    them look at routing. Collapsing them wastes the wrong hour.
    """
    sc._cred_hits.clear()
    bad_auth = sc.verify_credentials(
        "192.0.2.12", "admin", "x", actor="t1", clock=lambda: 0.0,
        session_factory=lambda: _FakeSession(
            fail_connect="SSH auth failed for admin@192.0.2.12"))
    assert bad_auth.reachable and not bad_auth.authenticated

    sc._cred_hits.clear()
    no_route = sc.verify_credentials(
        "192.0.2.12", "admin", "x", actor="t2", clock=lambda: 0.0,
        session_factory=lambda: _FakeSession(
            fail_connect="SSH connect failed: timed out"))
    assert not no_route.reachable and not no_route.authenticated


def test_an_account_that_logs_in_and_reads_nothing_is_not_a_pass():
    """A real FortiOS state: an admin profile with no access.

    Anything that only checks authentication calls this a success and the
    operator plans a change on an account that cannot make it.
    """
    sc._cred_hits.clear()

    class _Mute(_FakeSession):
        def run_readonly(self, command, **kw):
            return ""

    res = sc.verify_credentials("192.0.2.12", "ro", "x", actor="t3",
                                clock=lambda: 0.0,
                                session_factory=lambda: _Mute())
    assert res.authenticated and not res.read_ok
    assert "no read access" in res.error


def test_a_good_credential_reports_what_the_box_says():
    sc._cred_hits.clear()

    class _Good(_FakeSession):
        def run_readonly(self, command, **kw):
            return "Version : FortiWeb-VM 7.6.8,build0123\nHostname : fortiweb12\n"

    res = sc.verify_credentials("192.0.2.12", "admin", "S3cr3t!", actor="t4",
                                clock=lambda: 0.0,
                                session_factory=lambda: _Good())
    assert res.authenticated and res.read_ok and not res.error
    assert res.firmware.startswith("FortiWeb-VM 7.6.8")
    assert res.hostname == "fortiweb12"
    assert "S3cr3t!" not in repr(res), "the password must not survive in the result"


def test_the_write_hint_is_text_and_never_a_verdict():
    """A box that refused the pager for an unrelated reason looks identical to
    a read-only account, so the raw words are handed over instead of a flag."""
    sc._cred_hits.clear()

    class _Ro(_FakeSession):
        def run_readonly(self, command, **kw):
            return "Version : 7.6.8\n"

    res = sc.verify_credentials("192.0.2.12", "ro", "x", actor="t5",
                                clock=lambda: 0.0,
                                session_factory=lambda: _Ro(pager="permission denied"))
    assert res.write_hint == "permission denied"
    assert not hasattr(res, "can_write")


def test_one_operator_cannot_drive_the_form_in_a_loop():
    """One check is troubleshooting; the same form in a loop is a sprayer, and
    the difference is only ever visible as a rate."""
    sc._cred_hits.clear()
    t, tick = _clock()
    for _ in range(sc.CRED_MAX):
        sc.verify_credentials("192.0.2.12", "admin", "x", actor="sprayer",
                              clock=lambda: t["v"],
                              session_factory=lambda: _FakeSession(
                                  fail_connect="SSH auth failed"))
    with pytest.raises(sc.ConsoleViolation):
        sc.verify_credentials("192.0.2.12", "admin", "x", actor="sprayer",
                              clock=lambda: t["v"],
                              session_factory=lambda: _FakeSession(
                                  fail_connect="SSH auth failed"))
    # the window slides — this is a throttle, not a ban
    tick(sc.CRED_WINDOW + 1)
    ok = sc.verify_credentials("192.0.2.12", "admin", "x", actor="sprayer",
                               clock=lambda: t["v"],
                               session_factory=lambda: _FakeSession(
                                   fail_connect="SSH auth failed"))
    assert ok.error


def test_the_throttle_is_per_operator():
    sc._cred_hits.clear()
    for _ in range(sc.CRED_MAX):
        sc.verify_credentials("192.0.2.12", "a", "x", actor="one",
                              clock=lambda: 0.0,
                              session_factory=lambda: _FakeSession(
                                  fail_connect="SSH auth failed"))
    other = sc.verify_credentials("192.0.2.12", "a", "x", actor="two",
                                  clock=lambda: 0.0,
                                  session_factory=lambda: _FakeSession(
                                      fail_connect="SSH auth failed"))
    assert other.error


# ========================================================= TAC BUNDLE =====

@pytest.fixture
def diag(tmp_path, monkeypatch):
    monkeypatch.setenv("FORTINET_DIAG_DIR", str(tmp_path))
    return tmp_path


def _names(path):
    with tarfile.open(path) as tar:
        return set(tar.getnames())


def _member(path, name):
    with tarfile.open(path) as tar:
        return tar.extractfile(name).read().decode()


def test_a_bundle_carries_the_transcript_the_battery_and_the_metadata(diag):
    meta = sc.build_tac_bundle(
        _APP, "$ get system status\nVersion : 7.6.8", stamp="20260908-120000",
        ticket="TAC-1", capture=lambda a: {"get system status": "Version : 7.6.8"})
    assert meta["name"] == "tac-fortiweb12-20260908-120000.tar.gz"
    assert _names(meta["path"]) == {"meta.json", "console-session.txt", "diagnostics.txt"}
    assert "TAC-1" in _member(meta["path"], "meta.json")


def test_a_bundle_that_leaves_the_building_carries_no_secrets(diag):
    meta = sc.build_tac_bundle(
        _APP, "$ set password S3cr3t!\n", stamp="20260908-120001",
        include_diagnostics=False)
    body = _member(meta["path"], "console-session.txt")
    assert "S3cr3t!" not in body and sc.REDACTED in body


def test_a_failed_battery_does_not_lose_the_transcript(diag):
    """The transcript is what the operator watched happen and what TAC asked
    for; dropping it to protect the annex is backwards."""
    def _boom(_a):
        raise FortiSSHError("box stopped answering")

    meta = sc.build_tac_bundle(_APP, "$ get system status\nok",
                               stamp="20260908-120002", capture=_boom)
    names = _names(meta["path"])
    assert "console-session.txt" in names and "DIAGNOSTICS-MISSING.txt" in names
    assert "diagnostics.txt" not in names
    assert not meta["diagnostics_included"]
    assert "box stopped answering" in _member(meta["path"], "DIAGNOSTICS-MISSING.txt")


# ============================================================ THE MENU ====

def test_the_console_is_in_every_admin_block():
    """An entry added to Global and forgotten in the other four is invisible
    without failing — exactly how Stored Assets and Monitoring drifted."""
    base = (ROOT / "app" / "templates" / "base.html").read_text()
    assert base.count("partials/nav_console.html") == \
        base.count("partials/nav_adom_assets.html") == 5


def test_every_admin_block_is_titled_the_same():
    """The user asked for Administrator in every ADOM. Two blocks said
    Administration, so the FortiADC and FortiAuthenticator sidebars carried a
    differently-named group holding the same pages."""
    base = (ROOT / "app" / "templates" / "base.html").read_text()
    assert 'data-nav-group="Administration"' not in base
    assert base.count('data-nav-group="Administrator"') == 5
