#!/usr/bin/env python3
"""Mutation harness for the scheduled HA failover.

Each entry breaks ONE rule the guards claim to defend. A mutation that survives
means the guard is decoration. Measured by RETURN CODE — pytest prints FAILED in
upper case and an earlier harness in this repo grepped for 'failed' and reported
nine biting mutations as survivors. Only rc==1 is a test failure; rc==4 is a
usage error and must not be counted as a bite.

The tree is restored by sha256 comparison and the suite is re-run green at the
end: a harness that leaves a mutated file behind is worse than no harness.
"""
from __future__ import annotations

import hashlib
import io
import subprocess
import sys

ROOT = "/opt/satom/"
SVC = "app/services/scheduled_actions.py"
TESTS = ["tests/test_ha_failover.py"]

MUTATIONS = [
    # -- the firmware floor ---------------------------------------------- #
    ("an unrecorded firmware is assumed new enough", SVC,
     '    m = re.search(r"(?<![\\d.])(\\d+)\\.(\\d+)(?![\\d.])", text)\n'
     "    return (int(m.group(1)), int(m.group(2)), 0) if m else None",
     '    m = re.search(r"(?<![\\d.])(\\d+)\\.(\\d+)(?![\\d.])", text)\n'
     "    return (int(m.group(1)), int(m.group(2)), 0) if m else (99, 0, 0)"),
    ("the version floor is not enforced", SVC,
     "    if running < transport.min_version:", "    if False:"),
    ("the FortiWeb floor is lowered to a release that has no such command", SVC,
     '        "diagnose system ha status",\n        (8, 0, 0), True,',
     '        "diagnose system ha status",\n        (7, 0, 0), True,'),
    ("an unrecorded firmware is not refused", SVC,
     "    if running is None:\n        return {\"ok\": False,",
     "    if False:\n        return {\"ok\": False,"),

    # -- products --------------------------------------------------------- #
    ("an unverified product falls back to the FortiWeb command", SVC,
     '    transport = FAILOVER_TRANSPORT.get(kind)\n    if transport is None:',
     '    transport = FAILOVER_TRANSPORT.get(kind, FAILOVER_TRANSPORT["fortiweb"])\n'
     "    if False:"),
    ("a failover command is added for an unverified product", SVC,
     "    # fortianalyzer / fortiauthenticator: deliberately absent, same rule as",
     '    "fortianalyzer": FailoverTransport(\n'
     '        "execute ha failover set", "execute ha failover unset", "",\n'
     "        (7, 0, 0), True, \"guessed\"),\n"
     "    # fortianalyzer / fortiauthenticator: deliberately absent, same rule as"),
    ("FortiADC gets a CLI role read nobody verified", SVC,
     '        "execute ha force failover-standby unset",\n        "",',
     '        "execute ha force failover-standby unset",\n        "get system ha-status",'),
    ("FortiADC is declared to clear its failover on reboot", SVC,
     '        (7, 6, 0), False,', '        (7, 6, 0), True,'),

    # -- direction -------------------------------------------------------- #
    ("any direction string is accepted", SVC,
     '    if direction not in ("set", "unset"):', "    if False:"),

    # -- the asymmetry ---------------------------------------------------- #
    ("set fails over a node that is not the primary", SVC,
     '    if direction == "set" and role != "primary":', "    if False:"),
    ("set accepts a standby as good enough", SVC,
     '    if direction == "set" and role != "primary":',
     '    if direction == "set" and role == "standalone":'),
    ("unset refuses whenever the role cannot be read", SVC,
     '    if direction == "unset" and role == "standalone":',
     '    if direction == "unset" and role != "secondary":'),
    ("unset runs against a box with no HA at all", SVC,
     '    if direction == "unset" and role == "standalone":', "    if False:"),

    # -- what goes over the wire ------------------------------------------ #
    ("the dry run sends the command anyway", SVC,
     "    if dry_run:\n        return {\"ok\": True,\n"
     '                "summary": (f"[dry-run] would send {cmd!r} to {tname} ({kind} "',
     "    if False:\n        return {\"ok\": True,\n"
     '                "summary": (f"[dry-run] would send {cmd!r} to {tname} ({kind} "'),
    ("the console is not told the command is disruptive", SVC,
     "    result = ssh_console.run_script(target, [cmd], allow_disruptive=True)",
     "    result = ssh_console.run_script(target, [cmd], allow_disruptive=False)"),
    ("unset sends the set command", SVC,
     '    cmd = transport.set_cmd if direction == "set" else transport.unset_cmd',
     "    cmd = transport.set_cmd"),

    # -- reading the answer ----------------------------------------------- #
    ("a device refusal is reported as success", SVC,
     '    if row is None or row.status != "ok":', "    if row is None:"),
    ("a session-level failure is reported as success", SVC,
     "    if result.error:", "    if False:"),
    ("a node that is still primary afterwards is called a success", SVC,
     '    if direction == "set" and after == "primary":', "    if False:"),
    ("the role is read back through the VIP", SVC,
     "    if via_vip:\n        return {\"ok\": True,", "    if False:\n        return {\"ok\": True,"),
    ("a cluster is treated as a plain box, ignoring the VIP", SVC,
     '        via_vip = (getattr(appliance, "ha_mode", "") or "").strip().lower() == "vip"',
     "        via_vip = False"),
    ("a cluster with no reachable primary is failed over anyway", SVC,
     "        try:\n            target = ha_svc.resolve_write_target(appliance)\n"
     "        except Exception as exc:  # noqa: BLE001 - HAError and anything under it\n"
     '            return {"ok": False, "summary": f"{name}: {exc}", "log": ""}',
     "        try:\n            target = ha_svc.resolve_write_target(appliance)\n"
     "        except Exception:  # noqa: BLE001\n            target = appliance"),

    # -- the role vocabulary ---------------------------------------------- #
    ("unreadable CLI output becomes 'standalone'", SVC,
     '    return {"haStatus": m.group(1).lower() if m else "unrecognized"}',
     '    return {"haStatus": m.group(1).lower()} if m else {}'),
    ("'HA is disabled' is no longer recognised", SVC,
     '    if re.search(r"HA is disabled", blob, re.I):', "    if False:"),
    ("a failed role read is optimistic instead of unknown", SVC,
     '            return "unknown", f"{transport.role_cmd}: {type(exc).__name__}: {exc}"',
     '            return "primary", f"{transport.role_cmd}: {type(exc).__name__}: {exc}"'),

    # -- the spec --------------------------------------------------------- #
    ("the action stops requiring a change request", SVC,
     '        products=("fortiweb", "fortiadc"),\n        requires_change_request=True,',
     '        products=("fortiweb", "fortiadc"),\n        requires_change_request=False,'),
    ("the action stops being single-target", SVC,
     '        "admin", needs_targets=True, single_target=True, danger=True,\n'
     '        forced_schedule_kind="once",',
     '        "admin", needs_targets=True, single_target=False, danger=True,\n'
     '        forced_schedule_kind="once",'),
    ("the action stops being dangerous, so it leaves the CR menu", SVC,
     '        "admin", needs_targets=True, single_target=True, danger=True,\n'
     '        forced_schedule_kind="once",',
     '        "admin", needs_targets=True, single_target=True, danger=False,\n'
     '        forced_schedule_kind="once",'),
    ("the action may be scheduled to repeat", SVC,
     '        "admin", needs_targets=True, single_target=True, danger=True,\n'
     '        forced_schedule_kind="once",',
     '        "admin", needs_targets=True, single_target=True, danger=True,\n'
     '        forced_schedule_kind="",'),
    ("the sticky warning is dropped, so a pinned FortiADC node looks routine", SVC,
     "    sticky = \"\" if transport.clears_on_reboot else (",
     "    sticky = \"\" if True else ("),
]


def sha(path):
    return hashlib.sha256(io.open(ROOT + path, "rb").read()).hexdigest()


def run_tests():
    p = subprocess.run(
        ["/opt/satom/venv/bin/python", "-m", "pytest", *TESTS, "-q", "-x",
         "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True)
    return p.returncode


def main():
    files = sorted({m[1] for m in MUTATIONS})
    baseline = {f: sha(f) for f in files}
    originals = {f: io.open(ROOT + f, encoding="utf-8").read() for f in files}

    rc = run_tests()
    if rc != 0:
        print(f"BASELINE NOT GREEN (rc={rc}) — aborting")
        return 2

    bites, survivors = 0, []
    for i, (name, path, old, new) in enumerate(MUTATIONS, 1):
        text = originals[path]
        if text.count(old) != 1:
            print(f"{i:2d}. ANCHOR x{text.count(old)}  {name}")
            survivors.append(f"{name} (bad anchor)")
            continue
        io.open(ROOT + path, "w", encoding="utf-8").write(text.replace(old, new))
        rc = run_tests()
        io.open(ROOT + path, "w", encoding="utf-8").write(text)
        assert sha(path) == baseline[path], f"restore failed for {path}"
        if rc == 1:
            bites += 1
            print(f"{i:2d}. BITES     {name}")
        else:
            survivors.append(name)
            print(f"{i:2d}. SURVIVES (rc={rc})  {name}")

    for f in files:
        assert sha(f) == baseline[f], f"tree not restored: {f}"
    post = run_tests()
    print(f"\n{bites}/{len(MUTATIONS)} bite · post-restore rc={post}")
    if survivors:
        print("SURVIVORS:\n  " + "\n  ".join(survivors))
    return 0 if (not survivors and post == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
