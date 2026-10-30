"""Plugin Studio app steps for runbooks: look at an appliance, ask a person.

Since 2026-10-25 a runbook is a Plugin Studio app (operator: "this should be
part of an app that does the whole process"; the Process section was removed).
An app that recovers a device needs two things a data flow did not have:

* **checks** -- HTTP, TCP, one read-only console command, an inventory fact,
  the diagnostics battery. Each answers ``yes`` / ``no``, and raises (the
  ``error`` arrow) when SATOM could not look: SSH refused, no appliance, a
  target the network guard refuses. "I could not look" is a statement about
  the observer, never a ``no`` -- a ``no`` sends somebody to repair a device
  that may be fine. The cost, carried over from Process: a bug in a check also
  surfaces as ``error``, so a runbook is walked against the live system, not
  only against fixtures.
* **Ask a person** -- the run STOPS (status ``waiting``) and a person answers
  on the run page, minutes or hours later. The walk is a single cursor, so the
  whole position of a paused run is one step key plus the variables already
  saved; nothing is held open in a worker.

Nothing here decides anything it does not own: reachability is
``backend_probe``'s, the HTTP guard is ``service_probe``'s, what may be sent
over SSH is ``ssh_ops``'s, the battery is ``diag_battery``'s.
"""
from __future__ import annotations

import time

#: The outcome an "Ask a person" step hands the walk instead of yes/no.
WAIT = "wait"

#: Inventory columns ``appliance_fact`` may read. Never a credential.
FACT_FIELDS = ("hw_type", "kind", "model", "ha_mode", "is_cluster", "zone",
               "department", "line")

#: What ``{{ appliance.* }}`` holds after a *Load an appliance* step.
APPLIANCE_FIELDS = ("id", "name", "kind", "host", "port", "ssh_port", "model", "hw_type",
                    "firmware", "zone", "department", "line", "ha_vip", "ha_mode",
                    "is_cluster")

KIND_KEYS = ("appliance_load", "http_check", "tcp_check", "console_read",
             "appliance_fact", "collect_diagnostics", "ask", "activity")
#: The variable a step saves its result under when the draft leaves
#: *Save the result as* empty.
DEFAULT_SAVE_AS = {"appliance_load": "appliance", "collect_diagnostics": "diagnostics"}
#: Steps whose arrows are yes / no (and error when the step could not look).
YES_NO_KINDS = ("ask", "http_check", "tcp_check", "console_read", "appliance_fact")

_APPLIANCE_HELP = ("id or name of the appliance, e.g. {{ appliance.id }} after a Load "
                   "step, {{ form.appliance }} or {{ event.appliance_id }}")


def kinds() -> list:
    from .studio_flow import Kind, Param
    app_p = Param("appliance", "Appliance", default="{{ appliance.id }}", help=_APPLIANCE_HELP)
    return [
        Kind("appliance_load", "Load an appliance", "check",
             "Read one appliance from the inventory and save it, e.g. as {{ appliance }}: "
             "{{ appliance.host }}, {{ appliance.ssh_port }}, {{ appliance.name }}…",
             [Param("appliance", "Appliance", required=True, help=_APPLIANCE_HELP),
              Param("save_as", "Save the result as", default="appliance")]),
        Kind("http_check", "HTTP check", "check",
             "Fetch a URL: yes when it answers as expected, no when it does not.",
             [Param("url", "URL", required=True,
                    default="https://{{ appliance.host }}:{{ appliance.port }}/"),
              Param("expect_status", "Expect status", default="200",
                    help="0 accepts any HTTP answer."),
              Param("contains", "Body must contain"),
              Param("timeout", "Timeout (s)", default="10")]),
        Kind("tcp_check", "TCP check", "check",
             "One TCP handshake from this node. A refusal is a no that proves the host "
             "is up; SATOM cannot send ICMP, so this is also the 'ping' of a runbook.",
             [Param("host", "Host", required=True, default="{{ appliance.host }}"),
              Param("port", "Port", required=True, default="{{ appliance.ssh_port or 22 }}"),
              Param("timeout", "Timeout (s)", default="4")]),
        Kind("console_read", "Console read", "check",
             "Log in over SSH and run ONE read-only command (get / show / diagnose, "
             "or execute ping). yes when the output matches.",
             [app_p, Param("command", "Command", required=True, default="get system status"),
              Param("contains", "Output must contain"),
              Param("absent", "Output must NOT contain"),
              Param("timeout", "Timeout (s)", default="15")]),
        Kind("appliance_fact", "Appliance fact", "check",
             "Compare one inventory field (VM or hardware, product, model, HA mode…) "
             "with a value, without contacting the device.",
             [app_p, Param("field", "Field", "select", True, FACT_FIELDS, "hw_type"),
              Param("equals", "Equals", required=True,
                    help="hw_type is hardware or vm; is_cluster true or false. "
                         "A field SATOM does not know takes the error arrow.")]),
        Kind("collect_diagnostics", "Collect diagnostics", "check",
             "Run the product's read-only diagnostic battery over SSH and save the "
             "transcript on this node (Diagnose › Log Collection).",
             [app_p, Param("label", "Label", default="app"),
              Param("save_as", "Save the result as", default="diagnostics")]),
        Kind("ask", "Ask a person", "flow",
             "Stop the run and wait for a person to answer on the run page — yes / no, "
             "or one button for a task. The run keeps its variables while it waits.",
             [Param("prompt", "Question or task", "textarea", True),
              Param("pass_label", "Yes button", default="Yes"),
              Param("fail_label", "No button", default="No"),
              Param("buttons", "Buttons", "select", choices=("two", "one"), default="two",
                    help="one: a single button (the Yes button, e.g. 'Done') that "
                         "follows the yes arrow."),
              Param("acknowledge", "Must be acknowledged",
                    help="A list of warnings, e.g. {{ plan.warnings | rejectattr('blocking') "
                         "| map(attribute='text') | list }}: each one is a tick box, and Yes "
                         "is accepted only with every box ticked. The answer is saved as "
                         "{{ last_answer }} (answer, acknowledged, all_acknowledged, by, note)."),
              Param("blockers", "Blocks the Yes answer",
                    help="A list, e.g. {{ plan.warnings | selectattr('blocking') "
                         "| map(attribute='text') | list }}: while it is not empty, Yes is "
                         "refused and only No can be answered."),
              Param("confirm_text", "Type to confirm",
                    help="e.g. {{ plan.target.policy }}: Yes is accepted only when the "
                         "person types exactly this text.")]),
        Kind("activity", "Activity", "flow",
             "A documented box that passes at once — a heading such as "
             "'1 Connectivity tests'. Its instructions show on the run."),
    ]


# --------------------------------------------------------------------------- #
#  running                                                                     #
# --------------------------------------------------------------------------- #
def _appliance(node, ctx, required=True):
    from ..models import Appliance, db
    from .studio_flow import FlowError, _p, render
    raw = str(render(_p(node, "appliance", "{{ appliance.id }}"), ctx.scope()) or "").strip()
    row = None
    if raw:
        row = (db.session.get(Appliance, int(raw)) if raw.isdigit()
               else Appliance.query.filter_by(name=raw).first())
    if row is None and required:
        raise FlowError("no appliance %r" % raw if raw else "no appliance was given")
    return row


def appliance_dict(row) -> dict:
    return {k: getattr(row, k, None) for k in APPLIANCE_FIELDS}


#: Where an Ask step leaves what its answer must respect (``acknowledge``,
#: ``blockers``); ``studio_apps.answer`` enforces it, the run page draws it.
ASK_GATE = "_ask_gate"
MAX_GATE_ITEMS = 50


def _texts(v) -> list[str]:
    """A list parameter as short texts: a list (of texts, or of objects with
    a ``text``), or one text; empty values dropped."""
    if v is None or v == "":
        return []
    items = v if isinstance(v, (list, tuple)) else [v]
    out = []
    for x in items:
        t = x.get("text") if isinstance(x, dict) else x
        t = str(t if t is not None else "").strip()
        if t:
            out.append(t[:500])
    return out[:MAX_GATE_ITEMS]


def _int(v, default):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def run(node, ctx):
    """``(outcome, value, detail)`` for one of :data:`KIND_KEYS`. Raises
    ``FlowError`` when SATOM could not look (the error arrow)."""
    from .studio_flow import FlowError, _p, render
    kind = node.get("kind")
    scope = ctx.scope()
    P = lambda name, default="": render(_p(node, name, default), scope)  # noqa: E731

    if kind == "activity":
        first = (str((node.get("params") or {}).get("doc") or "").splitlines() or [""])[0]
        return "ok", None, first[:200]

    if kind == "ask":
        ctx.vars[ASK_GATE] = {"key": node.get("key") or "",
                              "acknowledge": _texts(P("acknowledge")),
                              "blockers": _texts(P("blockers")),
                              "confirm_text": str(P("confirm_text") or "").strip()[:200]}
        return WAIT, None, str(P("prompt") or "")

    if kind == "appliance_load":
        row = _appliance(node, ctx)
        return "ok", appliance_dict(row), "%s (%s)" % (row.name, row.host)

    if kind == "http_check":
        from .net_guard import TargetError
        from .service_probe import guarded_get
        url = str(P("url") or "").strip()
        if not url:
            raise FlowError("no URL")
        t0 = time.time()
        try:
            res = guarded_get(url, timeout=float(_int(P("timeout", "10"), 10) or 10))
        except TargetError as exc:
            raise FlowError("target refused: %s" % exc) from None
        except Exception as exc:  # noqa: BLE001 -- any transport/TLS failure is a no
            return "no", None, "no HTTP answer from %s: %s" % (url, str(exc)[:200])
        ms = int((time.time() - t0) * 1000)
        want = _int(P("expect_status", "200"), 200)
        if want and res.status_code != want:
            return "no", None, "expected HTTP %d, got %s" % (want, res.status_code)
        body = str(P("contains") or "")
        if body and body not in (res.text or ""):
            return "no", None, "HTTP %s: the answer does not contain %r" % (res.status_code, body)
        return "yes", None, "HTTP %s in %d ms" % (res.status_code, ms)

    if kind == "tcp_check":
        from .backend_probe import tcp_check
        host, port = str(P("host") or "").strip(), _int(P("port"), 0)
        if not host or not port:
            raise FlowError("no host or port")
        row = tcp_check(host, port, timeout=float(_int(P("timeout", "4"), 4) or 4))
        return ("yes" if row.get("ok") else "no"), None, "%s:%s — %s (%s)" % (
            host, port, row.get("verdict"), row.get("detail"))

    if kind == "console_read":
        from .ssh_ops import ReadOnlyViolation, run_command
        cmd = str(_p(node, "command") or "").strip()   # never rendered: see assert_console_read
        row = _appliance(node, ctx)
        try:
            assert_console_read(cmd)
        except ReadOnlyViolation as exc:
            raise FlowError("refused to send: %s" % exc) from None
        try:
            out = run_command(row, cmd, timeout=float(_int(P("timeout", "15"), 15) or 15))
        except Exception as exc:  # noqa: BLE001 -- a dead box is a blind spot
            raise FlowError("SSH did not answer: %s" % str(exc)[:200]) from None
        want, forbid = str(P("contains") or ""), str(P("absent") or "")
        if want and want not in out:
            return "no", out[-4000:], "output does not contain %r" % want
        if forbid and forbid in out:
            return "no", out[-4000:], "output contains %r" % forbid
        return "yes", out[-4000:], "%s on %s: %d bytes" % (cmd, row.name, len(out))

    if kind == "appliance_fact":
        row = _appliance(node, ctx)
        field = str(_p(node, "field", "hw_type") or "hw_type")
        if field not in FACT_FIELDS:
            raise FlowError("%r is not an inventory field this step reads" % field)
        got = getattr(row, field, None)
        if isinstance(got, bool):
            got = "true" if got else "false"
        got = "" if got is None else str(got).strip()
        if not got or got.lower() == "unknown":
            raise FlowError("SATOM does not know %s's %s" % (row.name, field))
        want = str(P("equals") or "")
        ok = got.lower() == want.lower()
        return ("yes" if ok else "no"), None, "%s is %r (expected %r)" % (field, got, want)

    if kind == "collect_diagnostics":
        from . import diag_battery
        from .logcollect import collect
        row = _appliance(node, ctx)
        pk = getattr(row, "kind", None) or "fortiweb"
        try:
            commands, _meta = diag_battery.get_battery(pk)
            steps = diag_battery.plan(pk, getattr(row, "firmware", None), commands)
            stats: dict = {}
            path = collect(row, label=str(P("label", "app") or "app"), commands=commands,
                           plan=steps, stats=stats)
        except Exception as exc:  # noqa: BLE001
            raise FlowError("the battery did not run: %s" % str(exc)[:200]) from None
        value = {"file": path.name, "ran": stats.get("ran"), "skipped": stats.get("skipped", 0)}
        return "ok", value, "diagnostics saved as %s (%s ran, %s skipped)" % (
            path.name, stats.get("ran", "?"), stats.get("skipped", 0))

    raise FlowError("unknown step kind %r" % kind)


def assert_console_read(command: str) -> str:
    """What a Console read may send: every line read-only (``assert_readonly``)
    OR the one probe the product permits (``execute ping <host>``). Named as
    the union of two existing gates, never by widening either."""
    from .ssh_ops import ReadOnlyViolation, assert_probe_command, assert_readonly
    try:
        return assert_readonly(command)
    except ReadOnlyViolation as read_err:
        try:
            return assert_probe_command(command)
        except ReadOnlyViolation:
            raise read_err from None


def problems(key: str, kind: str, p: dict) -> list[str]:
    """Save-time refusals: a mutating console command never reaches a run."""
    from .ssh_ops import ReadOnlyViolation
    out = []
    if kind == "console_read":
        cmd = str(p.get("command") or "").strip()
        if "{{" in cmd or "{%" in cmd:
            out.append("%s: the command is sent as written — no templates" % key)
        elif cmd:
            try:
                assert_console_read(cmd)
            except ReadOnlyViolation as exc:
                out.append("%s: %s" % (key, exc))
    return out
