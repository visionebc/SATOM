"""Scheduling an HA failover: the rules that make it safe to automate.

The feature was asked for as "calendarizar un failover de los clusters", and the
first honest answer was that **there is no REST call for it on either product** --
verified 2026-09-08 by downloading fortiweb12's OWN 7.6.8 GUI bundle and finding
``system/ha``, ``ha/node``, ``ha-topology`` and ``ha-disconnect`` and no failover
call at all. So the action drives the product's CLI over the SSH console, and
everything below exists because a CLI command aimed at a live cluster fails in
ways a wrong REST path does not:

* ``execute ha failover`` **does not exist on FortiWeb 7.6**, which is what this
  fleet runs. It arrived in 8.0.0. Sending it anyway is a parse error delivered
  inside a maintenance window and discovered the next morning.
* Failing over a node that is **not the primary** either does nothing (and gets
  reported as success) or pins the standby out of election while the box you
  meant to drain keeps serving.
* Reading the role back **through a VIP** describes whichever node is primary
  now -- after a successful failover, the peer. It reports success either way.
"""
from __future__ import annotations

import pytest

from app.services import scheduled_actions as sa


# --------------------------------------------------------------------------- #
#  doubles                                                                     #
# --------------------------------------------------------------------------- #
class _Boom:
    def api_call(self, *a, **kw):  # pragma: no cover - must never run
        raise AssertionError("the device was contacted")


class _Appliance:
    def __init__(self, kind="fortiweb", name="dev",
                 firmware="FortiWeb-KVM 8.0.1,build0100(GA),260701",
                 is_cluster=False, ha_mode=None):
        self.kind, self.name, self.firmware = kind, name, firmware
        self.is_cluster, self.ha_mode = is_cluster, ha_mode
        self.calls = []

    def build_client(self, *a, **kw):
        self.calls.append(("build_client", a, kw))
        return _Boom()

    def _own_client(self, *a, **kw):
        self.calls.append(("_own_client", a, kw))
        return _Boom()


def _script_result(appliance_name, command, *, status="ok", detail="",
                   output="", error=""):
    from app.services.ssh_console import CommandRow, ScriptResult
    rows = [] if error else [CommandRow(command=command, tier="disruptive",
                                        status=status, detail=detail,
                                        output=output)]
    return ScriptResult(appliance=appliance_name, rows=rows,
                        transcript=output, error=error)


@pytest.fixture()
def wired(monkeypatch):
    """Patch BOTH device transports and record every call.

    ``sent`` staying empty is the assertion most of these tests actually make:
    a refusal that still opened an SSH session to the cluster is not a refusal.
    """
    state = {"roles": ["primary"], "sent": [], "reads": [],
             "result": None, "role_rest": "primary"}

    def _run_command(appliance, command, *, timeout=15.0):
        state["reads"].append((getattr(appliance, "name", "?"), command))
        role = state["roles"][min(len(state["reads"]) - 1, len(state["roles"]) - 1)]
        return {"primary": "Local: master", "secondary": "Local: slave",
                "standalone": "HA is disabled.",
                "unknown": "something the parser has never seen"}[role]

    def _run_script(appliance, commands, **kw):
        state["sent"].append((getattr(appliance, "name", "?"), list(commands), kw))
        return state["result"] or _script_result(
            getattr(appliance, "name", "?"), commands[0])

    def _member_role(appliance, timeout=6.0):
        state["reads"].append((getattr(appliance, "name", "?"), "<REST ha_status>"))
        return state["role_rest"]

    from app.services import ha as ha_svc, ssh_console, ssh_ops
    monkeypatch.setattr(ssh_ops, "run_command", _run_command)
    monkeypatch.setattr(ssh_console, "run_script", _run_script)
    monkeypatch.setattr(ha_svc, "member_role", _member_role)
    return state


def _run(dev, params=None, dry_run=False):
    return sa.run_action(sa.get_spec("ha_failover"), dev, params or {},
                         dry_run=dry_run)


# --------------------------------------------------------------------------- #
#  1. the spec arrives gated                                                   #
# --------------------------------------------------------------------------- #
def test_the_action_is_dangerous_one_shot_single_target_and_cr_bound():
    """Every one of these flags is load-bearing, and the registry is the ONE
    place that declares them: ``_cr_specs`` derives the Change Request menu from
    ``danger``, and ``execute_and_record`` derives the unbound refusal from
    ``requires_change_request``. 'upgrade_prep' once shipped destructive and
    ungated because a hand-kept list disagreed with the spec."""
    spec = sa.get_spec("ha_failover")
    assert spec is not None
    assert spec.danger is True
    assert spec.requires_change_request is True
    assert spec.forced_schedule_kind == "once"
    assert spec.single_target is True, (
        "a multi-target failover hands over several clusters on one confirmation")
    assert spec.needs_targets is True


def test_it_is_offered_by_the_change_request_and_calendar_picker():
    """Both forms read ``cr_type_entries``; planning a failover from a calendar
    cell must reach the SAME executor the Change Request page approves."""
    from app.views.change_requests import cr_type_entries

    entry = {e["key"]: e for e in cr_type_entries()}.get("ha_failover")
    assert entry is not None, "the action is registered but unplannable"
    assert entry["executable"] is True
    assert entry["single_target"] is True
    assert set(entry["products"]) == {"fortiweb", "fortiadc"}


# --------------------------------------------------------------------------- #
#  2. no product gets a guessed command                                        #
# --------------------------------------------------------------------------- #
def test_only_products_with_verified_evidence_have_a_transport():
    assert set(sa.FAILOVER_TRANSPORT) == {"fortiweb", "fortiadc"}, (
        "a failover command was added for another product - it must be verified "
        "against that product's own device or its own CLI reference first")


def test_every_transport_records_its_provenance_and_a_version_floor():
    for kind, tr in sa.FAILOVER_TRANSPORT.items():
        assert len(tr.provenance) > 80, f"{kind}: provenance is not evidence"
        assert len(tr.min_version) == 3 and tr.min_version >= (7, 0, 0), kind


@pytest.mark.parametrize("kind", ["fortianalyzer", "fortiauthenticator", "cisco"])
def test_an_unverified_product_is_refused_by_name_without_connecting(kind, wired):
    dev = _Appliance(kind=kind, name=f"{kind}-1")
    out = _run(dev)
    assert out["ok"] is False
    assert kind in out["summary"] and "NOTHING was sent" in out["summary"]
    assert wired["sent"] == [] and wired["reads"] == []
    assert dev.calls == []


# --------------------------------------------------------------------------- #
#  3. the firmware floor                                                       #
# --------------------------------------------------------------------------- #
def test_a_fortiweb_on_76_is_refused_by_version(wired):
    """The command arrived in 8.0.0 and this fleet runs 7.6.8. The refusal names
    BOTH versions, because 'not supported' without a number is a support ticket."""
    dev = _Appliance(firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
                     name="fortiweb12")
    out = _run(dev)
    assert out["ok"] is False
    assert "7.6.8" in out["summary"] and "8.0.0" in out["summary"]
    assert "NOTHING was sent" in out["summary"]
    assert wired["sent"] == []


def test_an_unrecorded_firmware_is_refused_not_assumed(wired):
    """Absence of evidence is not evidence of support. A box SATOM has never
    synced could be on any release."""
    dev = _Appliance(firmware=None, name="never-synced")
    out = _run(dev)
    assert out["ok"] is False
    assert "no recorded firmware" in out["summary"]
    assert wired["sent"] == []


@pytest.mark.parametrize("text,expected", [
    ("FortiWeb-KVM 7.6.8,build1128(GA.M),260602", (7, 6, 8)),
    ("FACVMKVM v8.0.3, build0099 (GA)", (8, 0, 3)),
    ("FortiADC-VM 7.6", (7, 6, 0)),
    ("FortiWeb-VM64", None),
    ("", None),
    (None, None),
])
def test_the_version_parser_reads_the_firmware_string_device_sync_stores(
        text, expected):
    assert sa._appliance_version(_Appliance(firmware=text)) == expected


# --------------------------------------------------------------------------- #
#  4. direction                                                                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("direction", ["failover", "toggle", "unse", "on"])
def test_only_set_and_unset_are_directions(direction, wired):
    out = _run(_Appliance(), {"direction": direction})
    assert out["ok"] is False and "NOTHING was sent" in out["summary"]
    assert wired["sent"] == []


@pytest.mark.parametrize("given", ["", None, "SET", " set "])
def test_an_absent_or_padded_direction_means_set(given, wired):
    """'set' is the default because it is what a planned maintenance window asks
    for; the refusal rules above are what make that default safe."""
    wired["roles"] = ["primary", "secondary"]
    out = _run(_Appliance(), {"direction": given})
    assert out["ok"] is True
    assert wired["sent"][0][1] == ["execute ha failover set"]


# --------------------------------------------------------------------------- #
#  5. the asymmetry: set refuses on doubt, unset does not                      #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("role", ["secondary", "standalone", "unknown"])
def test_set_refuses_anything_that_is_not_reporting_primary(role, wired):
    wired["roles"] = [role]
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"})
    assert out["ok"] is False
    assert role in out["summary"] and "NOTHING was sent" in out["summary"]
    assert wired["sent"] == [], "it failed over a node it had just refused"


def test_unset_proceeds_when_the_role_cannot_be_read(wired):
    """The two directions do NOT fail the same way. A refused ``set`` costs a
    maintenance window; a refused ``unset`` leaves a node pinned out of election
    -- the outage the failover existed to avoid, made permanent."""
    wired["roles"] = ["unknown"]
    out = _run(_Appliance(name="fwb-a"), {"direction": "unset"})
    assert out["ok"] is True
    assert wired["sent"], "it refused to un-pin a node it could not read"
    assert wired["sent"][0][1] == ["execute ha failover unset"]


def test_unset_still_refuses_a_box_with_no_ha_at_all(wired):
    wired["roles"] = ["standalone"]
    out = _run(_Appliance(name="fwb-a"), {"direction": "unset"})
    assert out["ok"] is False and "no HA configured" in out["summary"]
    assert wired["sent"] == []


# --------------------------------------------------------------------------- #
#  6. what actually goes over the wire                                         #
# --------------------------------------------------------------------------- #
def test_dry_run_reads_the_role_but_sends_nothing(wired):
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"}, dry_run=True)
    assert out["ok"] is True
    assert "dry-run" in out["summary"] and "Nothing was sent" in out["summary"]
    assert wired["sent"] == []


def test_set_sends_the_verified_command_and_declares_it_disruptive(wired):
    """``ssh_console`` classifies ``execute ha`` as DISRUPTIVE and refuses it
    without ``allow_disruptive``. Passing it here is not a bypass: the approved
    change request is the record that a human was told and said yes."""
    wired["roles"] = ["primary", "secondary"]
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"})
    assert out["ok"] is True
    name, commands, kw = wired["sent"][0]
    assert commands == ["execute ha failover set"]
    assert kw.get("allow_disruptive") is True
    assert "secondary" in out["summary"]


def test_a_session_that_never_opened_is_a_failure(wired):
    """``ScriptResult.error`` is a connect/auth failure — no command reached the
    box. It has no rows, so a handler that only inspects rows reads "nothing went
    wrong" and reports a failover that never happened."""
    wired["result"] = _script_result("fwb-a", "execute ha failover set",
                                     error="SSH auth failed for fwb-a")
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"})
    assert out["ok"] is False
    assert "auth failed" in out["summary"] and "NOTHING was sent" in out["summary"]


def test_a_role_read_that_raises_is_unknown_not_primary(wired, monkeypatch):
    """A box that refuses the read has not told us it is the primary. Treating a
    dead read as 'primary' is how ``set`` would fire against a standby — the one
    thing the pre-check exists to prevent."""
    from app.services import ssh_ops

    def _boom(appliance, command, *, timeout=15.0):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(ssh_ops, "run_command", _boom)
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"})
    assert out["ok"] is False
    assert "unknown" in out["summary"] and "NOTHING was sent" in out["summary"]
    assert wired["sent"] == []


def test_a_device_refusal_is_a_failure_not_a_success(wired):
    wired["result"] = _script_result("fwb-a", "execute ha failover set",
                                     status="error", detail="parse error",
                                     output="Command fail. CLI parsing error.")
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"})
    assert out["ok"] is False and "refused" in out["summary"]


def test_a_node_that_is_still_primary_afterwards_is_a_failure(wired):
    """The command was accepted and the role did not move. Reporting that as
    success is how a maintenance window starts against a box still serving."""
    wired["roles"] = ["primary", "primary"]
    out = _run(_Appliance(name="fwb-a"), {"direction": "set"})
    assert out["ok"] is False
    assert "STILL reports primary" in out["summary"]


# --------------------------------------------------------------------------- #
#  7. clusters                                                                 #
# --------------------------------------------------------------------------- #
def test_a_vip_cluster_is_never_read_back(wired, monkeypatch):
    """The VIP now lands on whichever node holds primary -- after a successful
    failover, the peer. A read here would describe a different box and report
    success either way, so it is not performed at all."""
    node0 = _Appliance(name="cluster-a", is_cluster=True, ha_mode="vip")
    from app.services import ha as ha_svc
    monkeypatch.setattr(ha_svc, "resolve_write_target", lambda n, timeout=6.0: n)
    wired["roles"] = ["primary"]
    out = _run(node0, {"direction": "set"})
    assert out["ok"] is True
    assert "VIP" in out["summary"]
    # exactly ONE read: the pre-check. No post-check through the VIP.
    assert len(wired["reads"]) == 1


def test_a_cluster_with_no_reachable_primary_is_refused(wired, monkeypatch):
    from app.services import ha as ha_svc

    def _boom(node0, timeout=6.0):
        raise ha_svc.HAError("no member is reporting HA primary right now")

    monkeypatch.setattr(ha_svc, "resolve_write_target", _boom)
    out = _run(_Appliance(name="cluster-a", is_cluster=True, ha_mode="per_node"),
               {"direction": "set"})
    assert out["ok"] is False and "primary" in out["summary"]
    assert wired["sent"] == []


# --------------------------------------------------------------------------- #
#  8. the role vocabulary is a translation, not a second parser                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,expected", [
    ("HA is disabled.", "standalone"),
    ("Local: master, peer: slave", "primary"),
    ("Local: slave", "secondary"),
    ("", "unknown"),
    ("Mode: Active-Passive", "unknown"),
    ("total gibberish", "unknown"),
])
def test_cli_output_resolves_through_the_one_role_parser(text, expected):
    """``ha.parse_ha_role`` stays the single authority on which words mean which
    role. This only translates a product's phrasing into words it already knows."""
    from app.services import ha as ha_svc
    assert ha_svc.parse_ha_role(sa._ha_role_vocabulary(text)) == expected


def test_unreadable_output_never_becomes_standalone():
    """``parse_ha_role({})`` answers 'standalone', so handing it an empty dict
    would turn "the box said something we cannot read" into "the box has no HA"
    -- and 'standalone' is one of the answers that decides an unset."""
    assert sa._ha_role_vocabulary("") != {}
    assert sa._ha_role_vocabulary("nothing here") != {}


# --------------------------------------------------------------------------- #
#  9. stickiness is a property of the product, not of the prose                #
# --------------------------------------------------------------------------- #
def test_a_sticky_product_says_the_node_stays_out_of_election(wired):
    """FortiWeb clears the forced failover on reboot; nothing documents FortiADC
    doing so. An operator who assumes the FortiWeb behaviour on a FortiADC leaves
    a node pinned out of election indefinitely."""
    assert sa.FAILOVER_TRANSPORT["fortiweb"].clears_on_reboot is True
    assert sa.FAILOVER_TRANSPORT["fortiadc"].clears_on_reboot is False

    wired["role_rest"] = "primary"
    out = _run(_Appliance(kind="fortiadc", name="adc-a",
                          firmware="FortiADC-VM 7.6.1,build0210"),
               {"direction": "set"}, dry_run=True)
    assert out["ok"] is True
    assert "sticky" in out["summary"] and "unset" in out["summary"]


def test_fortiadc_has_no_cli_role_read_so_it_uses_rest(wired):
    """An empty ``role_cmd`` is a deliberate admission: no CLI role read has been
    verified against a live FortiADC, so the REST ``ha_status`` its client
    already implements answers instead of a guessed command."""
    assert sa.FAILOVER_TRANSPORT["fortiadc"].role_cmd == ""
    wired["role_rest"] = "primary"
    _run(_Appliance(kind="fortiadc", name="adc-a",
                    firmware="FortiADC-VM 7.6.1,build0210"),
         {"direction": "set"}, dry_run=True)
    assert wired["reads"] == [("adc-a", "<REST ha_status>")]
