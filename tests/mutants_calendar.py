#!/usr/bin/env python3
"""Mutation harness for the Change Calendar.

Each entry breaks ONE rule the guards claim to defend. A mutation that survives
means the guard is decoration. Measured by RETURN CODE — pytest prints FAILED in
upper case and a previous harness in this repo grepped for 'failed', reporting
nine biting mutations as survivors. Only rc==1 is a test failure; rc==4 is a
usage error and must not be counted as a bite.

The tree is restored by sha256 comparison, and the suite is re-run green at the
end: a harness that leaves a mutated file behind is worse than no harness.
"""
from __future__ import annotations

import hashlib
import io
import subprocess
import sys

ROOT = "/opt/satom/"
SVC = "app/services/calendar_plan.py"
VIEW = "app/views/calendar.py"
CR = "app/views/change_requests.py"
NAV = "app/templates/partials/nav_calendar.html"
TESTS = ["tests/test_calendar_plan.py", "tests/test_calendar_view.py"]

MUTATIONS = [
    # -- timezone -------------------------------------------------------- #
    ("bucket days in UTC instead of the operator timezone", SVC,
     "    loc = local_dt(dt, tz)\n    return loc.date() if loc is not None else None",
     "    return dt.date() if dt is not None else None"),
    ("local_dt is a no-op", SVC,
     "    return (dt.replace(tzinfo=timezone.utc)\n"
     "              .astimezone(_zone(tz))\n"
     "              .replace(tzinfo=None))",
     "    return dt"),
    ("to_utc_bounds closes on day_to instead of the midnight after", SVC,
     "    nxt = day_to + timedelta(days=1)", "    nxt = day_to"),
    ("an unknown timezone raises instead of degrading to UTC", SVC,
     "    except Exception:  # noqa: BLE001 — an unknown tz must not 500 the page\n"
     "        return timezone.utc",
     "    except Exception:  # noqa: BLE001\n        raise"),

    # -- projection ------------------------------------------------------ #
    ("truncation is never reported", SVC,
     "    return out, bool(nxt is not None and cursor < nxt < end)",
     "    return out, False"),
    ("the loop guard against a non-advancing schedule is removed", SVC,
     "        if nxt is None or nxt >= end or nxt <= cursor:",
     "        if nxt is None or nxt >= end:"),
    ("a series that merely continues past the window reads as truncated", SVC,
     "        if nxt is None or nxt >= end or nxt <= cursor:\n            return out, False",
     "        if nxt is None or nxt >= end or nxt <= cursor:\n            return out, True"),

    # -- automations ----------------------------------------------------- #
    ("disabled automations are drawn", SVC,
     "        if not act.enabled:\n            continue\n        occurrences, truncated = project(",
     "        occurrences, truncated = project("),
    ("automations are drawn one row per fire again", SVC,
     "        for day in sorted(by_day):\n            times = by_day[day]",
     "        for day in sorted(by_day):\n          for _one in by_day[day]:\n            times = [_one]"),
    ("the per-day time list is not capped", SVC,
     '                "times": [local_dt(t, tz) for t in times[:MAX_TIMES_PER_DAY]],',
     '                "times": [local_dt(t, tz) for t in times],'),
    ("count reports the clipped list instead of the true number", SVC,
     '                "count": len(times),',
     '                "count": len(times[:MAX_TIMES_PER_DAY]),'),
    ("times_clipped is never set", SVC,
     '                "times_clipped": len(times) > MAX_TIMES_PER_DAY,',
     '                "times_clipped": False,'),

    # -- change events --------------------------------------------------- #
    ("a multi-day window is drawn only on its start date", SVC,
     "    return [start_d + timedelta(days=i) for i in range(n)], clipped",
     "    return [start_d], clipped"),
    ("a runaway span is painted in full", SVC,
     "    n = MAX_SPAN_DAYS if clipped else total",
     "    n = total"),
    ("a runaway span is clamped silently", SVC,
     "    clipped = total > MAX_SPAN_DAYS", "    clipped = False"),
    ("a zero-length window counts as valid", SVC,
     '    return "ok" if cr.window_end > cr.window_start else "invalid"',
     '    return "ok" if cr.window_end >= cr.window_start else "invalid"'),
    ("an inverted window is reported as ok", SVC,
     '    return "ok" if cr.window_end > cr.window_start else "invalid"',
     '    return "ok"'),
    ("owner does not fall back to the requester", SVC,
     '            "owner": (cr.owner or cr.requested_by or "").strip(),',
     '            "owner": (cr.owner or "").strip(),'),

    # -- runs ------------------------------------------------------------ #
    ("a run's status is assumed rather than read", SVC,
     '            "status": run.status or "running",', '            "status": "ok",'),

    # -- layout ---------------------------------------------------------- #
    ("history sorts above planned changes inside a day", SVC,
     '    rank = {"change": 0, "automation": 1, "run": 2}.get(ev["kind"], 3)',
     '    rank = {"change": 2, "automation": 1, "run": 0}.get(ev["kind"], 3)'),
    ("padding cells drop the neighbour month's events", SVC,
     '            items = buckets.get(day, [])\n            row.append({',
     '            items = [] if day.month != month else buckets.get(day, [])\n            row.append({'),
    ("the year view counts neighbouring months into each month", SVC,
     "            if day.month != m:\n                continue",
     "            pass"),
    ("the week starts on the anchor instead of on Monday", SVC,
     "    offset = (anchor.weekday() - first_weekday) % 7",
     "    offset = 0"),

    # -- conflicts ------------------------------------------------------- #
    ("any two overlapping windows conflict, shared device or not", SVC,
     '            shared = sorted(set(a["device_ids"]) & set(b["device_ids"]))\n'
     "            if shared:",
     '            shared = sorted(set(a["device_ids"]) | set(b["device_ids"]))\n'
     "            if shared:"),
    ("a handover at the exact boundary is called a collision", SVC,
     '            if b["start"] >= a["end"]:', '            if b["start"] > a["end"]:'),
    ("cancelled and completed changes still conflict", SVC,
     '            and e["status"] not in ("cancelled", "completed", "failed")\n',
     ""),
    ("an invalid window can conflict", SVC,
     '            and e["window_state"] == "ok"\n', ""),

    # -- the repair + the blueprint -------------------------------------- #
    ("the inverted-window refusal is removed", CR,
     "    if win_start is not None and win_end is not None and win_end <= win_start:",
     "    if False:"),
    ("the refusal misses the zero-length window", CR,
     "and win_end <= win_start:", "and win_end < win_start:"),
    ("the calendar drops to the VIEW permission", VIEW,
     "@require_permission(Permission.USER_MANAGE)\ndef index():",
     "@require_permission(Permission.VIEW)\ndef index():"),
    ("an empty group resolution creates the change anyway", VIEW,
     '        return [], "", (f"No visible appliance matches {desc}. Nothing was created.")',
     '        return [], desc, ""'),
    ("an unknown group dimension is accepted", VIEW,
     '            return [], "", "Unknown group dimension."',
     '            field = "zone"'),
    ("the nav entry loses its permission gate", NAV,
     "{% if current_user and current_user.can('user_manage') %}", "{% if True %}"),
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
