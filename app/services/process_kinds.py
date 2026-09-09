"""Process node kinds — the catalogue of questions a process may ask.

ONE RULE GOVERNS THIS WHOLE MODULE: **nothing here decides anything it is not
the owner of.** Every executor is an adapter. Whether a URL is healthy is
``service_probe``'s answer; whether a TCP port is open is ``backend_probe``'s;
whether an appliance is graded critical is ``device_health``'s; whether a
command may be sent over SSH is ``ssh_ops``'s; whether a catalogue action may
fire is ``scheduled_actions``'s. A second author for any of those is how a page
starts saying one thing while the mail says another — the failure
``device_health`` itself was written to remove.

WHAT AN EXECUTOR RETURNS
------------------------
:class:`StepResult` — ``status`` from ``models_process`` (pass/fail/unknown),
a one-line ``detail`` an operator can act on, and ``output`` for the transcript.

* ``fail`` is a statement about the SYSTEM: something is broken.
* ``unknown`` is a statement about the OBSERVER: SATOM could not look — no
  appliance selected, SSH refused, the target denied by ``net_guard``, or the
  executor itself raised. Never rendered as health, never counted as a fail.

The cost of that rule is written down so nobody has to rediscover it: **a bug
in an executor surfaces as ``unknown``, indistinguishable from a genuine blind
spot.** Scout paid for this on 2026-09-09 with three defects that read exactly
like correct reports. A process must be walked against the live system, not
only against fixtures.

WRITE-CAPABLE NODES
-------------------
Only ``action`` can change an appliance, and only by invoking an
:class:`~app.services.scheduled_actions.ActionSpec` that already exists and
already carries its own guards. It runs with ``dry_run=not armed``, so an
unarmed run of a recovery plan is a rehearsal that is safe to point at
production. Actions marked ``requires_change_request`` are refused **when the
node is saved**, not when it fires: a process is not an approval, and finding
that out at 3 a.m. mid-walk is finding it out too late.

THE GENERIC WRITE DOOR (``console_script`` and ``hook``)
--------------------------------------------------------
Both were held back from the first round on purpose and both are here now,
under one rule that the ``action`` node does NOT share:

    **an unarmed run does not send them at all, and says ``unknown``.**

``action`` may return a verdict on an unarmed run because
``scheduled_actions.run_action(dry_run=True)`` is a real preview — the spec
computes what it would do and reports whether that computation worked. Neither
of the new nodes has such a mode. ``run_script`` has no dry run (classifying
the text is a fact about the TEXT, not about the appliance) and
``dispatch_one`` runs the hook for real even with ``sample=True``. So the
honest verdict differs because the available evidence differs, and a rehearsal
of a repair plan stops where the repair would have been rather than walking the
"and then it was fixed" branch against an appliance nobody fixed.

The cost, written down: **a plan whose whole point is the write cannot be
rehearsed end to end.** A rehearsal proves the script is sendable — validated,
classified, appliance dialable by name — not that it works.

WHO AGREED, AND TO WHAT
-----------------------
The web console asks a human to tick an acknowledgement and type the appliance
name at the moment of sending. A process has no human at 3 a.m., so the
agreement is recorded in the PLAN: a disruptive ``console_script`` node carries
the appliance name it is allowed to disrupt, and at run time that string must
equal the appliance the run is pointed at. Aiming the same process at a
different box makes the step refuse. That is strictly stronger than the page,
where the typed name only proves the operator read the warning.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..models_process import FAIL, PASS, UNKNOWN

#: A node executor may ask the engine to park the run instead of returning a
#: verdict. Only ``manual_gate`` does this.
GATE = "__gate__"


@dataclass
class StepResult:
    status: str = UNKNOWN
    detail: str = ""
    output: str = ""
    gate: bool = False


@dataclass(frozen=True)
class Param:
    name: str
    label: str
    kind: str = "text"          # text | number | select | textarea
    default: str = ""
    help: str = ""
    choices: tuple = ()
    required: bool = False


@dataclass(frozen=True)
class NodeKind:
    key: str
    label: str
    group: str                  # flow | check | act
    summary: str
    params: tuple = ()
    needs_appliance: bool = False
    writes: bool = False
    terminal: bool = False
    colour: str = "#3D4550"     # fw-badge palette; never a dark-theme pastel


def _s(node_params: dict, name: str, default: str = "") -> str:
    return str(node_params.get(name, default) or "").strip()


def _i(node_params: dict, name: str, default: int = 0) -> int:
    try:
        return int(str(node_params.get(name, default) or default).strip())
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# flow
# ---------------------------------------------------------------------------

def _run_start(node, ctx) -> StepResult:
    return StepResult(PASS, "process entered", "")


def _run_end(node, ctx) -> StepResult:
    return StepResult(PASS, _s(node.get("params", {}), "note") or "process finished")


def _run_manual_gate(node, ctx) -> StepResult:
    """Park the run and wait for a human.

    Not a checkbox in a wizard: the run is PERSISTED as ``waiting`` and can be
    answered minutes or hours later, because the thing on the other side of
    this node is usually somebody physically checking something.
    """
    return StepResult(UNKNOWN, _s(node.get("params", {}), "prompt")
                      or "waiting for an operator", gate=True)


def _run_decision(node, ctx) -> StepResult:
    """Branch on the outcome of a step that already ran.

    Edges alone can only branch on the node immediately upstream. This node
    exists so a plan can ask "did the DNS check earlier pass?" three steps
    later, without duplicating the check — a duplicated check is two answers to
    one question and they can disagree.
    """
    p = node.get("params", {})
    ref = _s(p, "when_node")
    want = _s(p, "when_status", PASS)
    seen = ctx.results.get(ref)
    if ref and seen is None:
        # The referenced step did not run on this path. That is not a failure
        # of the system; it is a question that was never asked.
        return StepResult(UNKNOWN,
                          "step %r did not run on this path, so its outcome "
                          "cannot be tested" % ref)
    got = seen.status if seen else ""
    ok = (got == want)
    return StepResult(PASS if ok else FAIL,
                      "%s ended %s (expected %s)" % (ref or "?", got or "—", want))


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def _run_http_check(node, ctx) -> StepResult:
    from .net_guard import MODE_FREE, TargetError, resolve_target
    from .service_probe import probe_url

    p = node.get("params", {})
    url = _s(p, "url")
    if not url:
        return StepResult(UNKNOWN, "no URL configured on this step")
    parts = urlsplit(url if "://" in url else "https://" + url)
    host = parts.hostname or ""
    port = parts.port or (80 if parts.scheme == "http" else 443)
    try:
        # The guard is the product's, not this module's: denied ports, loopback
        # and cloud-metadata answers are refused in ONE place for every tool.
        resolve_target(host, port, mode=MODE_FREE)
    except TargetError as exc:
        # SATOM refusing to dial is a fact about SATOM, not about the service.
        return StepResult(UNKNOWN, "target refused: %s" % exc)
    except Exception as exc:  # noqa: BLE001
        return StepResult(UNKNOWN, "could not resolve target: %s" % exc)

    res = probe_url(url, timeout=float(_i(p, "timeout", 10) or 10))
    if not res.ok:
        return StepResult(FAIL, "no HTTP answer: %s" % (res.error or "unreachable"),
                          "%s\n%s" % (url, res.error))
    want = _i(p, "expect_status", 200)
    max_ms = _i(p, "max_ms", 0)
    body = _s(p, "contains")
    bits = ["HTTP %s in %s ms" % (res.status, res.elapsed_ms)]
    if want and res.status != want:
        return StepResult(FAIL, "expected HTTP %d, got %s" % (want, res.status),
                          "\n".join(bits))
    if max_ms and (res.elapsed_ms or 0) > max_ms:
        return StepResult(FAIL, "answered in %s ms, budget is %d ms"
                          % (res.elapsed_ms, max_ms), "\n".join(bits))
    if body:
        # probe_url does not keep the body (only a length and a digest), so a
        # content assertion is refetched here rather than guessed from the hash.
        import httpx
        try:
            text = httpx.get(url, verify=False, timeout=10,
                             follow_redirects=False).text
        except Exception as exc:  # noqa: BLE001
            return StepResult(UNKNOWN, "could not re-read the body: %s" % exc)
        if body not in text:
            return StepResult(FAIL, "the answer does not contain %r" % body,
                              "\n".join(bits))
        bits.append("body contains %r" % body)
    return StepResult(PASS, "; ".join(bits), "\n".join(bits))


def _run_tcp_check(node, ctx) -> StepResult:
    from .backend_probe import tcp_check
    p = node.get("params", {})
    host, port = _s(p, "host"), _i(p, "port", 0)
    if not host or not port:
        return StepResult(UNKNOWN, "no host/port configured on this step")
    row = tcp_check(host, port, timeout=float(_i(p, "timeout", 3) or 3))
    # 'refused' is a fail, not an unknown: the host answered. The distinction
    # belongs to backend_probe and is preserved verbatim here.
    return StepResult(PASS if row.get("ok") else FAIL,
                      "%s:%s — %s (%s)" % (host, port, row.get("verdict"),
                                           row.get("detail")))


def _run_dns_check(node, ctx) -> StepResult:
    from .dns_tool import dig_lookup, dns_servers
    p = node.get("params", {})
    entry = _s(p, "entry")
    if not entry:
        return StepResult(UNKNOWN, "no name configured on this step")
    servers = [s for s in dns_servers() if s.get("enabled", True)]
    if not servers:
        return StepResult(UNKNOWN, "no DNS server is configured in Settings")
    srv = _s(p, "server") or servers[0]["server"]
    answers = dig_lookup(entry, srv)
    text = ", ".join(answers)
    if answers in ([], ["No result"], ["timeout"]):
        return StepResult(FAIL, "%s did not resolve on %s (%s)" % (entry, srv, text))
    want = _s(p, "expect")
    if want and not any(want in a for a in answers):
        return StepResult(FAIL, "%s resolves to %s, expected %s" % (entry, text, want),
                          text)
    return StepResult(PASS, "%s → %s" % (entry, text), text)


def assert_console_read(command: str) -> str:
    """Refuse anything a Process step may not send over SSH.

    TWO product gates, joined on purpose, and neither of them relaxed:

    * ``ssh_ops.assert_readonly`` — every line is ``get``/``show``/``diagnose``.
      This is the gate Log Collection uses.
    * ``ssh_ops.assert_probe_command`` — the whole-command match for
      ``execute ping <host>``, the one probe the product permits. This is the
      gate Backend Reachability uses.

    A reachability check is exactly the step a recovery plan needs, and it is
    spelled ``execute``, which ``assert_readonly`` refuses and must keep
    refusing. So the acceptable set is named as the union of two existing
    gates rather than by loosening either one — a verb allowlist widened "just
    for ping" is how a write door opens by accident.

    Raises :class:`ssh_ops.ReadOnlyViolation` with the read-only message, which
    is the informative one: an operator who typed ``set`` needs to be told that
    this step reads, not that it is not a ping.
    """
    from .ssh_ops import ReadOnlyViolation, assert_probe_command, assert_readonly
    try:
        return assert_readonly(command)
    except ReadOnlyViolation as read_err:
        try:
            return assert_probe_command(command)
        except ReadOnlyViolation:
            raise read_err from None


def _run_ssh_check(node, ctx) -> StepResult:
    """Run ONE read-only CLI command and assert on its output.

    The gate is ``ssh_ops.assert_probe_command`` — the same one Log Collection
    uses. It is re-asserted here even though the editor already refuses a
    mutating command at save time: the row in the database is not the only way
    a node can arrive (an import, a restored bundle), and this is the last
    place before the socket.
    """
    from .ssh_ops import ReadOnlyViolation, run_command
    p = node.get("params", {})
    cmd = _s(p, "command")
    if not cmd:
        return StepResult(UNKNOWN, "no command configured on this step")
    if ctx.appliance is None:
        return StepResult(UNKNOWN, "this step needs an appliance and none was chosen")
    try:
        assert_console_read(cmd)
    except ReadOnlyViolation as exc:
        return StepResult(UNKNOWN, "refused to send: %s" % exc)
    try:
        out = run_command(ctx.appliance, cmd, timeout=float(_i(p, "timeout", 15) or 15))
    except Exception as exc:  # noqa: BLE001 — a dead box is a blind spot here
        return StepResult(UNKNOWN, "SSH did not answer: %s" % exc)
    want = _s(p, "contains")
    forbid = _s(p, "absent")
    if want and want not in out:
        return StepResult(FAIL, "output does not contain %r" % want, out)
    if forbid and forbid in out:
        return StepResult(FAIL, "output contains %r" % forbid, out)
    return StepResult(PASS, "%s ran; %d bytes read" % (cmd, len(out)), out)


def _run_device_health(node, ctx) -> StepResult:
    from .device_health import collect_for
    if ctx.appliance is None:
        return StepResult(UNKNOWN, "this step needs an appliance and none was chosen")
    try:
        health = collect_for(ctx.appliance)
    except Exception as exc:  # noqa: BLE001
        return StepResult(UNKNOWN, "could not grade the appliance: %s" % exc)
    status = health.get("status", "unknown")
    worst = _s(node.get("params", {}), "allow_worst", "warn")
    rank = {"ok": 0, "warn": 1, "crit": 2, "unknown": 3}
    reasons = "; ".join("%s: %s" % (r.get("label"), r.get("text"))
                        for r in health.get("reasons", []))
    if status == "unknown":
        return StepResult(UNKNOWN, "the appliance could not be graded", reasons)
    ok = rank.get(status, 3) <= rank.get(worst, 1)
    return StepResult(PASS if ok else FAIL,
                      "graded %s (worst allowed: %s)%s"
                      % (status, worst, " — " + reasons if reasons else ""),
                      reasons)


def _run_logs_collect(node, ctx) -> StepResult:
    """Run the read-only diagnostic battery and save it.

    Writes a file on THIS node; it does not write to the appliance. The battery
    is FortiWeb syntax (``logcollect.DIAGNOSTIC_COMMANDS``), so pointing it at
    another product yields a log full of syntax errors rather than a lie — the
    step still passes, because the collection succeeded, and the operator reads
    the file.
    """
    from .logcollect import collect
    if ctx.appliance is None:
        return StepResult(UNKNOWN, "this step needs an appliance and none was chosen")
    label = _s(node.get("params", {}), "label") or "process"
    try:
        path = collect(ctx.appliance, label=label)
    except Exception as exc:  # noqa: BLE001
        return StepResult(UNKNOWN, "the battery did not run: %s" % exc)
    return StepResult(PASS, "diagnostics saved as %s" % path.name, str(path))


# ---------------------------------------------------------------------------
# act
# ---------------------------------------------------------------------------

def _run_action(node, ctx) -> StepResult:
    from .scheduled_actions import get_spec, run_action
    p = node.get("params", {})
    key = _s(p, "action_key")
    if not key:
        return StepResult(UNKNOWN, "no action chosen on this step")
    spec = get_spec(key)
    if spec is None:
        return StepResult(UNKNOWN, "action %r is not in the catalogue" % key)
    if spec.requires_change_request:
        # Defence in depth; the editor refuses this at save time with a longer
        # explanation. A process is a plan, not an approval.
        return StepResult(UNKNOWN,
                          "%s requires an approved change request and a process "
                          "is not an approval" % key)
    if spec.needs_targets and ctx.appliance is None:
        return StepResult(UNKNOWN, "%s acts on an appliance and none was chosen" % key)
    if spec.needs_targets and ctx.appliance is not None:
        kind = getattr(ctx.appliance, "kind", "") or "fortiweb"
        if kind not in spec.products:
            return StepResult(UNKNOWN, "%s does not act on a %s" % (key, kind))
    dry = not ctx.armed
    extra = p.get("action_params")
    try:
        res = run_action(spec, ctx.appliance, extra if isinstance(extra, dict) else {},
                         dry_run=dry)
    except Exception as exc:  # noqa: BLE001 — run_action documents that it never
        # raises, but "documents" is not "cannot"; my crash is not their outage.
        return StepResult(UNKNOWN, "the action raised: %s" % exc)
    prefix = "rehearsed (not armed): " if dry else ""
    return StepResult(PASS if res.get("ok") else FAIL,
                      prefix + (res.get("summary") or key), res.get("log") or "")


def _plan_text(plan: list) -> str:
    return "\n".join("[%s] %s%s" % (r["tier"], r["command"],
                                    ("  — " + r["reason"]) if r["reason"] else "")
                     for r in plan)


def _run_console_script(node, ctx) -> StepResult:
    """Send CLI lines to the chosen appliance. THE FIRST WRITE PATH A PROCESS HAS.

    Everything about *what may be sent* belongs to ``ssh_console``: the
    three-tier blacklist, the whole-script pre-gate, the modal-CLI stop, the
    transcript redaction. This adapter adds exactly two things the page adds
    too — who agreed to a disruptive line, and the audit row — and nothing else.
    """
    from .audit import log_action
    from . import ssh_console as sc

    p = node.get("params", {})
    raw = _s(p, "script")
    commands = sc.parse_script(raw)
    if not commands:
        return StepResult(UNKNOWN, "no commands configured on this step")
    if ctx.appliance is None:
        return StepResult(UNKNOWN, "this step needs an appliance and none was chosen")

    plan = sc.classify_script(commands)
    disruptive = [r for r in plan if r["tier"] == sc.TIER_DISRUPTIVE]

    if not ctx.armed:
        # NOT SENT. See the module docstring: there is no dry run for a CLI
        # script, so claiming pass or fail here would be inventing a result.
        return StepResult(
            UNKNOWN,
            "not armed — %d command(s) were validated and NOT sent" % len(plan),
            _plan_text(plan))

    retired = sc.retired_placeholder(ctx.appliance)
    if retired:
        return StepResult(UNKNOWN, retired, _plan_text(plan))

    allow = False
    if disruptive:
        want = _s(p, "confirm_name")
        got = str(getattr(ctx.appliance, "name", "") or "")
        if not want or want != got:
            return StepResult(
                UNKNOWN,
                "refused: this step is disruptive (%s) and names %r as the only "
                "appliance it may disrupt, but the run is pointed at %r"
                % (disruptive[0]["reason"], want or "—", got),
                _plan_text(plan))
        allow = True

    res = sc.run_script(ctx.appliance, commands, allow_disruptive=allow,
                        stop_on_error=_s(p, "stop_on_error", "1") != "0")

    # SAME action name the page uses. An operator auditing "what was sent over
    # the console" must not have to know there are two doors.
    log_action("console.run", target=getattr(ctx.appliance, "name", "") or "",
               extra={"via": "process", "run_id": getattr(ctx, "run_id", 0),
                      "commands": [sc.redact(c) for c in commands],
                      "tiers": sorted({r["tier"] for r in plan}),
                      "disruptive_ack": allow, "failed": res.failed,
                      "session_error": res.error})

    refused = [r for r in res.rows if r.status == "refused"]
    if refused:
        # The save-time gate should make this unreachable, but a node can arrive
        # by import or by a restored bundle. SATOM declining to send is a fact
        # about SATOM, so it is a blind spot and NOT a failure of the appliance
        # — and it must not be reported as "the session did not open", which is
        # a different event with a different fix.
        return StepResult(UNKNOWN, "SATOM refused to send: %s" % refused[0].detail,
                          _plan_text(plan))
    if res.error and not any(r.status in ("error", "ok") for r in res.rows):
        # The session never opened: SATOM could not look, so this is a blind
        # spot, not a verdict about the appliance's configuration.
        return StepResult(UNKNOWN, "the session did not open: %s" % res.error,
                          res.transcript or _plan_text(plan))
    if res.failed:
        bad = next((r for r in res.rows if r.status in ("error", "refused")), None)
        return StepResult(FAIL, "%d of %d command(s) failed — first: %s (%s)"
                          % (res.failed, len(res.rows),
                             bad.command if bad else "?",
                             bad.detail if bad else ""),
                          res.transcript)
    return StepResult(PASS, "%d command(s) accepted by %s"
                      % (len(res.rows), getattr(ctx.appliance, "name", "")),
                      res.transcript)


#: Grace added to a hook's own timeout before this step stops waiting. The
#: runner kills at the hook's timeout, so anything past that plus the time to
#: write the status file is the runner not being there at all.
HOOK_GRACE_S = 10.0
HOOK_POLL_S = 0.5


def _run_hook(node, ctx) -> StepResult:
    """Queue ONE named integration hook and wait for its verdict.

    ``integration_hooks.dispatch_one`` writes JSON; a systemd ``.path`` unit
    turns that file into a process, in another unit, as another concern. This
    step therefore does NOT execute anything — it enqueues and then polls the
    status file the runner writes.

    Waiting at all is a deliberate choice: a step you cannot branch on is not a
    step. The wait is bounded by the hook's OWN clamped timeout plus
    :data:`HOOK_GRACE_S`, and it cannot be raised from the diagram, because a
    longer wait cannot outlive a runner that already killed the job.

    A request still ``queued`` when the budget runs out is ``unknown`` and says
    which unit is probably not enabled. That exact failure is on record: the
    standby node sat on ``queued`` updates for weeks in July 2026 because its
    ``.path`` unit was never enabled, and "queued forever" looked like nothing
    at all.
    """
    import json
    import time

    from . import integration_hooks as ih

    p = node.get("params", {})
    slug = _s(p, "slug")
    if not slug:
        return StepResult(UNKNOWN, "no hook chosen on this step")
    try:
        hook = ih.get_hook(slug)
    except Exception as exc:  # noqa: BLE001
        return StepResult(UNKNOWN, "could not read hook %r: %s" % (slug, exc))
    if hook is None:
        return StepResult(UNKNOWN, "hook %r no longer exists" % slug)

    raw = _s(p, "payload")
    try:
        payload = json.loads(raw) if raw else {}
    except ValueError as exc:
        return StepResult(UNKNOWN, "the payload on this step is not JSON: %s" % exc)
    if not isinstance(payload, dict):
        return StepResult(UNKNOWN, "the payload on this step is not a JSON object")

    # Provenance the hook can act on, and that a human reading the queue can
    # trace back to a run without joining two systems. OVERWRITTEN, not
    # defaulted: this block is SATOM's claim about where the request came from,
    # and a field the operator can pre-set in the payload is a claim they can
    # forge. Forgeable provenance is worse than none, because it is believed.
    payload["satom_process"] = {
        "run_id": getattr(ctx, "run_id", 0),
        "step": str(node.get("key") or ""),
        "appliance": getattr(ctx.appliance, "name", "") or "",
        "armed": bool(ctx.armed),
    }

    if not ctx.armed:
        # A hook is operator-written Python holding real secrets. ``sample``
        # is not a dry run — it runs the hook with an example payload.
        return StepResult(
            UNKNOWN, "not armed — hook %r was NOT queued" % slug,
            "slug: %s\nevent: %s\ntimeout: %ss\nsecrets: %s"
            % (slug, hook.get("event"), ih.clamp_timeout(hook.get("timeout")),
               ", ".join(hook.get("secrets") or []) or "none"))

    try:
        queued = ih.dispatch_one(slug, sample=False, payload=payload,
                                 by=getattr(ctx, "user", "") or "process")
    except Exception as exc:  # noqa: BLE001
        return StepResult(UNKNOWN, "could not queue hook %r: %s" % (slug, exc))
    rid = str(queued.get("request_id") or "")
    if not rid:
        return StepResult(UNKNOWN, "hook %r produced no request id" % slug)

    if _s(p, "wait", "1") == "0":
        # The only claim being made is that the request was written, and it was.
        return StepResult(PASS, "hook %r queued as %s (not waited on)" % (slug, rid),
                          rid)

    budget = float(ih.clamp_timeout(hook.get("timeout"))) + HOOK_GRACE_S
    deadline = time.monotonic() + budget
    status = "queued"
    row: dict = {}
    while time.monotonic() < deadline:
        row = ih.result(rid) or {}
        status = str(row.get("status") or "queued")
        if status in ("ok", "failed", "timeout"):
            break
        time.sleep(HOOK_POLL_S)

    out = "%s\nexit: %s\n%s" % (rid, row.get("exit_code"), row.get("stdout") or "")
    if status == "ok":
        return StepResult(PASS, "hook %r finished in %s ms"
                          % (slug, row.get("duration_ms")), out)
    if status == "failed":
        return StepResult(FAIL, "hook %r failed: %s"
                          % (slug, row.get("error") or "exit %s" % row.get("exit_code")),
                          out)
    if status == "timeout":
        return StepResult(FAIL, "hook %r was killed at its %ss timeout"
                          % (slug, ih.clamp_timeout(hook.get("timeout"))), out)
    return StepResult(
        UNKNOWN,
        "hook %r was still %s after %.0fs — the request was written, so the "
        "runner is what did not pick it up (satom-integrations.path on THIS "
        "node)" % (slug, status, budget), out)


# ---------------------------------------------------------------------------
# catalogue
# ---------------------------------------------------------------------------

_KINDS: tuple[NodeKind, ...] = (
    NodeKind("start", "Start", "flow",
             "Where the walk begins. Exactly one per process.",
             colour="#15692A"),
    NodeKind("end", "End", "flow",
             "A terminal point. A process may have several — 'recovered' and "
             "'escalate' are both endings.",
             params=(Param("note", "Closing note", "text",
                           help="Printed on the run as the reason this ending "
                                "was reached."),),
             terminal=True, colour="#3D4550"),
    NodeKind("decision", "Decision", "flow",
             "Branch on the outcome of an earlier step, not just the previous one.",
             params=(Param("when_node", "Step key", "text", required=True,
                           help="The key of a step that runs earlier on this path."),
                     Param("when_status", "Ended as", "select", default="pass",
                           choices=("pass", "fail", "unknown"))),
             colour="#4C2A85"),
    NodeKind("manual_gate", "Manual gate", "flow",
             "Stop and wait for a person. The run is saved and can be answered "
             "later; it does not hold a worker open.",
             params=(Param("prompt", "Ask the operator", "textarea", required=True),),
             colour="#7A5700"),

    NodeKind("http_check", "HTTP check", "check",
             "Fetch a URL and assert status, latency and content.",
             params=(Param("url", "URL", "text", required=True),
                     Param("expect_status", "Expect status", "number", default="200"),
                     Param("max_ms", "Slower than (ms) fails", "number", default="0",
                           help="0 disables the latency assertion."),
                     Param("contains", "Body must contain", "text"),
                     Param("timeout", "Timeout (s)", "number", default="10"))),
    NodeKind("tcp_check", "TCP check", "check",
             "One handshake from this node. Keeps 'refused' apart from "
             "'timeout' — a refusal proves the host is up.",
             params=(Param("host", "Host or IP", "text", required=True),
                     Param("port", "Port", "number", required=True),
                     Param("timeout", "Timeout (s)", "number", default="3"))),
    NodeKind("dns_check", "DNS check", "check",
             "Resolve a name against a configured server and assert the answer.",
             params=(Param("entry", "Name", "text", required=True),
                     Param("server", "Server", "text",
                           help="Blank uses the first enabled server from Settings."),
                     Param("expect", "Answer must contain", "text"))),
    NodeKind("ssh_check", "Console read", "check",
             "Run ONE read-only CLI command on the chosen appliance and assert "
             "on its output. Mutating commands are refused when you save.",
             params=(Param("command", "Command", "text", required=True),
                     Param("contains", "Output must contain", "text"),
                     Param("absent", "Output must NOT contain", "text"),
                     Param("timeout", "Timeout (s)", "number", default="15")),
             needs_appliance=True),
    NodeKind("device_health", "Appliance health", "check",
             "The same grade Monitoring shows — sync, cache, probe and capacity.",
             params=(Param("allow_worst", "Worst acceptable", "select",
                           default="warn", choices=("ok", "warn", "crit")),),
             needs_appliance=True),
    NodeKind("logs_collect", "Collect diagnostics", "check",
             "Run the read-only battery over SSH and save the transcript on this "
             "node. Nothing is written to the appliance.",
             params=(Param("label", "Label", "text", default="process"),),
             needs_appliance=True),

    NodeKind("action", "Catalogue action", "act",
             "Invoke an automation from the Scheduled Actions catalogue. Runs as "
             "a rehearsal unless the run is armed. Actions that require an "
             "approved change request cannot be added.",
             params=(Param("action_key", "Action", "select", required=True),),
             needs_appliance=False, writes=True, colour="#8B1C2A"),
    NodeKind("console_script", "Console script", "act",
             "Send CLI lines to the chosen appliance. Nothing is sent unless "
             "the run is armed. Forbidden commands cannot be saved; disruptive "
             "ones must name the appliance they may disrupt.",
             params=(Param("script", "Commands", "textarea", required=True,
                           help="One per line. # comments and blank lines are "
                                "ignored, exactly as on the Console page."),
                     Param("stop_on_error", "On error", "select", default="1",
                           choices=("1", "0"),
                           help="1 stops the script — the FortiOS CLI is modal, "
                                "so lines after a failure run in the wrong "
                                "context. 0 sends every line regardless."),
                     Param("confirm_name", "Disruptive only on", "text",
                           help="Required when any line is disruptive. The run "
                                "must be pointed at exactly this appliance.")),
             needs_appliance=True, writes=True, colour="#8B1C2A"),
    NodeKind("hook", "Integration hook", "act",
             "Queue one integration hook on this node and wait for its verdict. "
             "Nothing is queued unless the run is armed.",
             params=(Param("slug", "Hook", "select", required=True),
                     Param("payload", "Payload (JSON object)", "textarea",
                           help="Merged with a satom_process block naming this "
                                "run and step."),
                     Param("wait", "Wait for the result", "select", default="1",
                           choices=("1", "0"),
                           help="0 passes as soon as the request is written — "
                                "use it for notifications you cannot branch on.")),
             needs_appliance=False, writes=True, colour="#8B1C2A"),
)

_RUNNERS = {
    "start": _run_start, "end": _run_end, "decision": _run_decision,
    "manual_gate": _run_manual_gate, "http_check": _run_http_check,
    "tcp_check": _run_tcp_check, "dns_check": _run_dns_check,
    "ssh_check": _run_ssh_check, "device_health": _run_device_health,
    "logs_collect": _run_logs_collect, "action": _run_action,
    "console_script": _run_console_script, "hook": _run_hook,
}

KIND_KEYS = tuple(k.key for k in _KINDS)


def kinds() -> tuple[NodeKind, ...]:
    return _KINDS


def get_kind(key: str) -> NodeKind | None:
    for k in _KINDS:
        if k.key == key:
            return k
    return None


def needs_appliance(graph: dict) -> bool:
    """True when ANY node in the graph needs a device.

    Asked once, at start, so the run refuses up front instead of walking three
    green steps and then discovering it has nothing to point at.
    """
    for n in graph.get("nodes", []):
        k = get_kind(n.get("kind", ""))
        if k and k.needs_appliance:
            return True
        if n.get("kind") == "action":
            from .scheduled_actions import get_spec
            spec = get_spec(str((n.get("params") or {}).get("action_key") or ""))
            if spec is not None and spec.needs_targets:
                return True
    return False


def kinds_used(graph: dict) -> set:
    """The set of step kinds in this diagram.

    Here rather than in the template so a page asking "does this plan send CLI
    lines" gets the answer from the same module that decides what a step kind
    is. Two authors for that is the shape of every drift this codebase has paid
    for.
    """
    return {str(n.get("kind") or "") for n in graph.get("nodes", [])}


def writes(graph: dict) -> bool:
    """True when the graph can change an appliance if armed."""
    return any((get_kind(n.get("kind", "")) or NodeKind("", "", "", "")).writes
               for n in graph.get("nodes", []))


def execute(node: dict, ctx) -> StepResult:
    """Run one node. NEVER raises.

    A crash in an executor is MY defect, not the appliance's outage, so it
    becomes ``unknown`` — and the docstring at the top of this module records
    what that rule costs.
    """
    runner = _RUNNERS.get(node.get("kind", ""))
    if runner is None:
        return StepResult(UNKNOWN, "unknown step kind %r" % node.get("kind"))
    try:
        return runner(node, ctx)
    except Exception as exc:  # noqa: BLE001
        return StepResult(UNKNOWN, "the step raised: %s: %s"
                          % (type(exc).__name__, exc))


# ---------------------------------------------------------------------------
# save-time validation
# ---------------------------------------------------------------------------

#: The one rule for a key in this module's vocabulary — step keys AND the
#: process key the view checks. Exported so there is a single author: two
#: copies of "what is a usable key" drift the day one of them grows a rule.
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_graph(graph: dict) -> list[str]:
    """Every reason this graph cannot be saved, all at once.

    Returning the FIRST problem would make fixing a diagram a game of
    whack-a-mole; the editor shows the whole list.
    """
    from .scheduled_actions import get_spec
    from .ssh_ops import ReadOnlyViolation

    errs: list[str] = []
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    keys = [str(n.get("key") or "") for n in nodes]

    if not nodes:
        errs.append("A process needs at least one step.")
    starts = [n for n in nodes if n.get("kind") == "start"]
    if len(starts) != 1:
        errs.append("A process needs exactly one Start step (found %d)." % len(starts))
    dupes = {k for k in keys if keys.count(k) > 1}
    for d in sorted(dupes):
        errs.append("Two steps share the key %r." % d)
    for k in keys:
        if not KEY_RE.match(k):
            errs.append("%r is not a usable step key (lowercase letters, digits, "
                        "- and _)." % k)
    known = set(keys)
    seen_branch: dict[tuple, int] = {}
    for e in edges:
        if str(e.get("src")) not in known:
            errs.append("An arrow starts at %r, which is not a step." % e.get("src"))
        if str(e.get("dst")) not in known:
            errs.append("An arrow ends at %r, which is not a step." % e.get("dst"))
        pair = (str(e.get("src")), str(e.get("branch") or "always"))
        seen_branch[pair] = seen_branch.get(pair, 0) + 1
    for (src, branch), n in sorted(seen_branch.items()):
        if n > 1:
            # ONE edge per outcome keeps the walk a single cursor. Outcomes are
            # mutually exclusive, so a graph built this way can never be in two
            # places at once — which is what makes a manual gate resumable
            # hours later from a database row instead of a live worker holding
            # an in-memory frontier. Concurrent paths are a different product.
            errs.append("Step %r has %d arrows for the same outcome (%s). A step "
                        "may have one arrow per outcome." % (src, n, branch))

    for n in nodes:
        kind = get_kind(str(n.get("kind") or ""))
        if kind is None:
            errs.append("Step %r has an unknown kind %r."
                        % (n.get("key"), n.get("kind")))
            continue
        p = n.get("params") or {}
        for par in kind.params:
            if par.required and not str(p.get(par.name, "") or "").strip():
                errs.append("Step %r needs %s." % (n.get("key"), par.label))
        if kind.key == "ssh_check":
            cmd = str(p.get("command") or "").strip()
            if cmd:
                try:
                    assert_console_read(cmd)
                except ReadOnlyViolation as exc:
                    # Caught HERE and not at run time on purpose: a plan that
                    # only reveals it cannot run halfway through a recovery is
                    # worse than one that refuses to be written.
                    errs.append("Step %r: %s" % (n.get("key"), exc))
        if kind.key == "action":
            akey = str(p.get("action_key") or "").strip()
            spec = get_spec(akey) if akey else None
            if akey and spec is None:
                errs.append("Step %r names an action %r that does not exist."
                            % (n.get("key"), akey))
            elif spec is not None and spec.requires_change_request:
                errs.append(
                    "Step %r uses %r, which only runs against an approved change "
                    "request. Raise the change request and let it schedule the "
                    "action; a process is a plan, not an approval."
                    % (n.get("key"), akey))
        if kind.key == "decision":
            ref = str(p.get("when_node") or "").strip()
            if ref and ref not in known:
                errs.append("Step %r tests %r, which is not a step."
                            % (n.get("key"), ref))
        if kind.key == "console_script":
            errs.extend(_console_script_errors(n, p))
        if kind.key == "hook":
            errs.extend(_hook_errors(n, p))
    return errs


def _console_script_errors(n, p) -> list[str]:
    """Everything wrong with a console step, at SAVE time.

    A forbidden line discovered mid-walk is discovered after the lines above it
    already changed the appliance. ``run_script`` re-gates before it opens the
    session for exactly that reason; this gate is earlier still, so the plan
    cannot be written down in the first place.
    """
    from . import ssh_console as sc

    key = n.get("key")
    errs: list[str] = []
    commands = sc.parse_script(str(p.get("script") or ""))
    if not commands:
        errs.append("Step %r has no commands (blank lines and # comments do not "
                    "count)." % key)
        return errs
    if len(commands) > sc.MAX_COMMANDS:
        # run_script would TRUNCATE and note it. A note on a run nobody reads is
        # not the same as refusing to save a plan that is 300 lines long.
        errs.append("Step %r has %d commands; the console sends at most %d."
                    % (key, len(commands), sc.MAX_COMMANDS))
    disruptive = []
    for row in sc.classify_script(commands):
        if row["tier"] == sc.TIER_FORBIDDEN:
            errs.append("Step %r: refused — %s (%r). This has no path through "
                        "SATOM at any permission level."
                        % (key, row["reason"], row["command"]))
        elif row["tier"] == sc.TIER_DISRUPTIVE:
            disruptive.append(row)
    if disruptive and not str(p.get("confirm_name") or "").strip():
        errs.append("Step %r contains a disruptive command (%s) and must name "
                    "the one appliance it may disrupt in 'Disruptive only on'."
                    % (key, disruptive[0]["reason"]))
    return errs


def _hook_errors(n, p) -> list[str]:
    import json

    from . import integration_hooks as ih

    key = n.get("key")
    errs: list[str] = []
    slug = str(p.get("slug") or "").strip()
    if slug:
        try:
            hook = ih.get_hook(slug)
        except Exception as exc:  # noqa: BLE001 — a broken meta file is a save error
            hook = None
            errs.append("Step %r names hook %r, which could not be read: %s"
                        % (key, slug, exc))
        else:
            if hook is None:
                errs.append("Step %r names a hook %r that does not exist."
                            % (key, slug))
    raw = str(p.get("payload") or "").strip()
    if raw:
        try:
            body = json.loads(raw)
        except ValueError as exc:
            errs.append("Step %r: the payload is not JSON (%s)." % (key, exc))
        else:
            if not isinstance(body, dict):
                errs.append("Step %r: the payload must be a JSON object." % key)
    return errs
