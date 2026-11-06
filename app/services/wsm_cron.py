"""Crontab text <-> rows the Cron Jobs page edits. Pure, no I/O.

A row is ``{"id", "minute", "hour", "dom", "month", "dow", "command",
"enabled", "comment", "special"}``. A job switched off in the page stays in
the crontab, commented with ``#satom-off `` so switching it on again restores
it exactly. Environment lines (``MAILTO=...``, ``PATH=...``) are rows of
their own (``env``) and stay where they were; every line the page does not
understand is kept verbatim (``raw``).
"""
from __future__ import annotations

import re

OFF = "#satom-off "
SPECIALS = ("@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight",
            "@hourly")
FIELD_RE = re.compile(r"^[0-9A-Za-z*/,\-]{1,60}$")
ENV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
PRESETS = {
    "minute": ("* * * * *", "Every minute"),
    "5min": ("*/5 * * * *", "Every 5 minutes"),
    "hourly": ("0 * * * *", "Every hour"),
    "daily": ("{m} {h} * * *", "Every day at a time"),
    "weekly": ("{m} {h} * * {dow}", "Every week on a day"),
    "monthly": ("{m} {h} {dom} * *", "Every month on a day"),
}


class CronFormatError(ValueError):
    pass


def parse(text: str) -> list[dict]:
    rows, comment = [], ""
    for n, line in enumerate((text or "").splitlines()):
        s = line.strip()
        enabled = True
        if s.startswith(OFF):
            s, enabled = s[len(OFF):].strip(), False
        elif s.startswith("#"):
            if s.startswith("# DO NOT EDIT") or s.startswith("# (") or not s[1:].strip():
                rows.append({"id": n, "kind": "raw", "text": line})
                continue
            comment = s[1:].strip()
            rows.append({"id": n, "kind": "comment", "text": line})
            continue
        if not s:
            rows.append({"id": n, "kind": "raw", "text": line})
            comment = ""
            continue
        m = ENV_RE.match(s)
        if m and not s.startswith("@") and " " not in s.split("=", 1)[0]:
            rows.append({"id": n, "kind": "env", "name": m.group(1), "value": m.group(2),
                         "enabled": enabled, "text": line})
            continue
        parts = s.split(None, 1)
        if parts and parts[0] in SPECIALS and len(parts) == 2:
            rows.append({"id": n, "kind": "job", "special": parts[0], "minute": "", "hour": "",
                         "dom": "", "month": "", "dow": "", "command": parts[1],
                         "enabled": enabled, "comment": comment})
            comment = ""
            continue
        parts = s.split(None, 5)
        if len(parts) == 6 and all(FIELD_RE.match(p) for p in parts[:5]):
            rows.append({"id": n, "kind": "job", "special": "", "minute": parts[0],
                         "hour": parts[1], "dom": parts[2], "month": parts[3], "dow": parts[4],
                         "command": parts[5], "enabled": enabled, "comment": comment})
            comment = ""
            continue
        rows.append({"id": n, "kind": "raw", "text": line})
    for r in rows:
        if r["kind"] == "job":
            r["schedule"] = r["special"] or " ".join(
                (r["minute"], r["hour"], r["dom"], r["month"], r["dow"]))
            r["human"] = describe(r["schedule"])
    return rows


def describe(expr: str) -> str:
    e = expr.strip()
    named = {"@reboot": "At every boot", "@hourly": "Every hour", "@daily": "Every day at 00:00",
             "@midnight": "Every day at 00:00", "@weekly": "Every Sunday at 00:00",
             "@monthly": "On the 1st of every month at 00:00", "@yearly": "Every 1 January",
             "@annually": "Every 1 January"}
    if e in named:
        return named[e]
    p = e.split()
    if len(p) != 5:
        return e
    m, h, dom, mon, dow = p
    if e == "* * * * *":
        return "Every minute"
    if m.startswith("*/") and h == dom == mon == dow == "*":
        return "Every %s minutes" % m[2:]
    if m.isdigit() and h == "*" and dom == mon == dow == "*":
        return "Every hour at minute %s" % m
    if m.isdigit() and h.isdigit():
        at = "%02d:%02d" % (int(h), int(m))
        days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
                "Sunday"]
        if dom == mon == dow == "*":
            return "Every day at %s" % at
        if dom == mon == "*" and dow.isdigit() and int(dow) <= 7:
            return "Every %s at %s" % (days[int(dow)], at)
        if dom.isdigit() and mon == dow == "*":
            return "On day %s of every month at %s" % (dom, at)
    return e


def validate_schedule(expr: str) -> str:
    e = (expr or "").strip()
    if e in SPECIALS:
        return e
    p = e.split()
    if len(p) != 5 or not all(FIELD_RE.match(x) for x in p):
        raise CronFormatError("a schedule is five fields (minute hour day month weekday) "
                              "or @daily, @hourly, @reboot ...")
    from .scheduler import CronError, parse_cron
    try:
        parse_cron(e)
    except CronError as exc:
        raise CronFormatError(str(exc)) from None
    return e


def validate_command(cmd: str) -> str:
    c = (cmd or "").strip()
    if not c or "\n" in c or "\r" in c or len(c) > 2000:
        raise CronFormatError("the command is one line, up to 2000 characters")
    return c


def job_line(job: dict) -> str:
    sched = validate_schedule(job.get("schedule") or "")
    cmd = validate_command(job.get("command") or "")
    line = "%s %s" % (sched, cmd)
    return line if job.get("enabled", True) else OFF + line


def render(rows: list[dict]) -> str:
    out = []
    for i, r in enumerate(rows):
        k = r.get("kind")
        if k == "job":
            if r.get("comment") and not (out and out[-1] == "# " + r["comment"]):
                out.append("# " + r["comment"].replace("\n", " ")[:200])
            out.append(job_line(r))
        elif k == "env":
            name = r.get("name") or ""
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) or "\n" in (r.get("value") or ""):
                raise CronFormatError("an environment line is NAME=value on one line")
            line = "%s=%s" % (name, r.get("value") or "")
            out.append(line if r.get("enabled", True) else OFF + line)
        elif k == "comment":
            nxt = rows[i + 1] if i + 1 < len(rows) else {}
            if nxt.get("kind") == "job" and nxt.get("comment") == r["text"].strip()[1:].strip():
                continue              # re-emitted with its job
            out.append(r.get("text") or "")
        else:
            out.append(r.get("text") or "")
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n"


def preset(kind: str, *, hour: int = 2, minute: int = 0, dow: int = 1, dom: int = 1) -> str:
    if kind not in PRESETS:
        raise CronFormatError("unknown frequency")
    return PRESETS[kind][0].format(m=int(minute), h=int(hour), dow=int(dow), dom=int(dom))
