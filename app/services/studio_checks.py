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

import re
import threading
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
             "appliance_fact", "collect_diagnostics", "ask", "activity",
             "connection_test", "login_check", "power_state", "appliance_ping", "notify")
#: The variable a step saves its result under when the draft leaves
#: *Save the result as* empty.
DEFAULT_SAVE_AS = {"appliance_load": "appliance", "collect_diagnostics": "diagnostics"}
#: Steps whose arrows are yes / no (and error when the step could not look).
YES_NO_KINDS = ("ask", "http_check", "tcp_check", "console_read", "appliance_fact",
                "connection_test", "login_check", "power_state", "appliance_ping")

#: Test Connection verdicts that mean SATOM could not try (the error arrow),
#: never that the appliance failed the test (services/conn_test.py).
BLIND_VERDICTS = ("not permitted", "not installed", "refused", "no address")
#: A refused account is not tried again on the same appliance for this long:
#: every refusal counts towards the product's admin lockout (FortiWeb locks the
#: account after 3 by default), and a simulation walks a step many times.
LOGIN_REFUSED_HOLD_S = 600
_REFUSED: dict = {}
_REFUSED_LOCK = threading.Lock()
#: Products whose REST API takes a token or API key, never an administrator's
#: password: a RADIUS account cannot log in there (clients/fortigate.py,
#: clients/fortiauthenticator.py).
TOKEN_API_KINDS = ("fortigate", "fortiauthenticator")
#: Hypervisor power states, as the backends report them.
POWER_ON = ("running", "poweredon", "on")
POWER_OFF = ("stopped", "poweredoff", "off", "suspended", "paused")

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
                         "person types exactly this text."),
              Param("link", "Link (a SATOM page)",
                    help="A path on this SATOM, e.g. /appliances/{{ appliance.id }}/restore: "
                         "a button next to the question opens it in a new tab. Anything "
                         "else (another site, //host) is not shown and the question says so."),
              Param("link_label", "Link button", default="Open")]),
        Kind("activity", "Activity", "flow",
             "A documented box that passes at once — a heading such as "
             "'1 Connectivity tests'. Its instructions show on the run."),
        Kind("connection_test", "Connection test", "check",
             "Test Connection from this node, as on the Appliances page: the REST "
             "status call with SATOM's stored account (api), one TCP handshake, ping or "
             "traceroute. yes when every address answered; the error arrow when SATOM "
             "could not try (ping not permitted for the service user, traceroute not "
             "installed, an address the network guard refuses).",
             [app_p, Param("method", "Method", "select", True,
                           ("api", "tcp", "ping", "traceroute"), "ping"),
              Param("save_as", "Save the result as",
                    help="e.g. route: {{ route.summary }} is one line per address, "
                         "{{ route.output }} what ping or traceroute printed.")]),
        Kind("login_check", "Log in to the appliance", "check",
             "Log in to the appliance's REST API: with SATOM's stored account, or with "
             "the account of a Connection (Plugin Studio › Connections, HTTP with Basic "
             "auth — e.g. a remote RADIUS administrator). yes = accepted, no = refused "
             "(HTTP 401). A refused account is not tried again on that appliance for 10 "
             "minutes: every refusal counts towards the product's admin lockout.",
             [app_p, Param("connection", "Account from connection",
                           help="The connection's slug; empty = SATOM's stored account. "
                                "FortiGate and FortiAuthenticator take a token or API "
                                "key, never a RADIUS password: with a connection they "
                                "take the error arrow.")]),
        Kind("power_state", "Power state (hypervisor)", "check",
             "Ask the hypervisor whether the appliance's VM is running, through its "
             "topology mapping (Sentinel). yes = running, no = stopped; the error arrow "
             "for hardware, an unmapped VM or a hypervisor that does not answer.",
             [app_p]),
        Kind("appliance_ping", "Ping from the appliance", "check",
             "Log in over SSH and run execute ping <target> ON the appliance: does it "
             "reach its gateway, its RADIUS server…? yes when a reply came back, no "
             "when none did; the error arrow when SSH did not answer.",
             [app_p, Param("target", "Target", required=True,
                           help="An IP address or host name, e.g. {{ form.gateway }}. "
                                "Empty takes the error arrow."),
              Param("timeout", "Timeout (s)", default="30")]),
        Kind("notify", "Notify", "flow",
             "Ring the administrators' bell and/or send an e-mail. In a simulation only "
             "the bell of the person simulating rings; the step lists who would have "
             "been told. Sending nothing at all takes the error arrow.",
             [Param("title", "Title", required=True,
                    help="e.g. {{ appliance.name }}: escalation to the network team"),
              Param("body", "Message", "textarea"),
              Param("bell", "Administrators' bell", "select", choices=("yes", "no"),
                    default="yes"),
              Param("email_to", "E-mail to", help="Addresses, separated by commas."),
              Param("email_alerts", "E-mail the alert recipients", "select",
                    choices=("yes", "no"), default="no",
                    help="Settings › Alerts recipients.")]),
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


_SATOM_PATH = re.compile(r"/(?![/\\])[^\s\\]{0,499}")


def satom_path(v) -> str:
    """``v`` when it is a path on this SATOM (one leading slash, no host, no
    scheme, no blanks or backslashes), else "" -- an Ask step's link is a
    button on the run page and must never send the person to another site."""
    s = str(v if v is not None else "").strip()
    return s if _SATOM_PATH.fullmatch(s) else ""


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
        raw_link = str(P("link") or "").strip()
        link = satom_path(raw_link)
        ctx.vars[ASK_GATE] = {"key": node.get("key") or "",
                              "acknowledge": _texts(P("acknowledge")),
                              "blockers": _texts(P("blockers")),
                              "confirm_text": str(P("confirm_text") or "").strip()[:200],
                              "link": link,
                              "link_label": (str(P("link_label") or "").strip() or "Open")[:80]}
        prompt = str(P("prompt") or "")
        if raw_link and not link:
            prompt += "\n(Link not shown: %r is not a page of this SATOM.)" % raw_link[:200]
        return WAIT, None, prompt

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
        from .ssh_ops import ReadOnlyViolation, assert_readonly, run_command, run_probe_command
        cmd = str(_p(node, "command") or "").strip()   # never rendered: see assert_console_read
        row = _appliance(node, ctx)
        try:
            assert_console_read(cmd)
        except ReadOnlyViolation as exc:
            raise FlowError("refused to send: %s" % exc) from None
        secs = float(_int(P("timeout", "15"), 15) or 15)
        try:
            assert_readonly(cmd)
            send = run_command
        except ReadOnlyViolation:
            # the permitted probe (execute ping): run_command refuses it
            send = lambda r, c, timeout: run_probe_command(r, c, timeout=timeout,  # noqa: E731
                                                           maxt=max(45.0, timeout))
        try:
            out = send(row, cmd, timeout=secs)
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

    if kind == "connection_test":
        return _connection_test(node, ctx, P)
    if kind == "login_check":
        return _login_check(node, ctx, P)
    if kind == "power_state":
        return _power_state(node, ctx)
    if kind == "appliance_ping":
        return _appliance_ping(node, ctx, P)
    if kind == "notify":
        return _notify(node, ctx, P)

    raise FlowError("unknown step kind %r" % kind)


def _connection_test(node, ctx, P):
    from .. import clients
    from . import conn_test
    from .studio_flow import FlowError, _p
    row = _appliance(node, ctx)
    method = str(_p(node, "method", "ping") or "ping")
    if method not in conn_test.METHODS:
        raise FlowError("%r is not a Test Connection method" % method)
    res = conn_test.run(row, method, client_for=clients.client_for)
    results = res.get("results") or []
    label = conn_test.METHOD_LABELS[method]
    blind = [r for r in results if r.get("verdict") in BLIND_VERDICTS]
    if not results or blind:
        why = blind[0].get("detail") if blind else res.get("status")
        hint = (blind[0].get("hint") if blind else "") or ""
        raise FlowError("%s could not be tried from this node: %s%s"
                        % (label, why, (" — " + hint) if hint else ""))
    summary = "; ".join("%s %s: %s%s" % (r.get("label"), r.get("host"),
                                         r.get("verdict") or ("ok" if r.get("ok") else "failed"),
                                         (" — %s" % r["detail"]) if r.get("detail") else "")
                        for r in results)
    value = {"method": method, "ok": bool(res.get("ok")), "summary": summary[:1000],
             "output": "\n\n".join(str(r.get("output") or "") for r in results).strip()[-4000:],
             "results": [{k: r.get(k) for k in ("label", "host", "port", "ok", "verdict", "detail")}
                         for r in results]}
    return ("yes" if res.get("ok") else "no"), value, "%s: %s" % (label, summary[:400])


class _AsAccount:
    """The appliance as a product client reads it, with another account's
    credentials. Reads go to the row; nothing is ever written to it (a client
    that records a status writes on this wrapper)."""

    def __init__(self, row, username, password):
        object.__setattr__(self, "_row", row)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_row"), name)


def _login_check(node, ctx, P):
    from .. import clients
    from ..clients.base import DeviceAuthError
    from . import studio_connections as SC
    from .studio_flow import FlowError
    row = _appliance(node, ctx)
    slug = str(P("connection") or "").strip()
    target, who = row, "SATOM's stored account"
    if slug:
        c = SC.get(slug)
        if c is None:
            raise FlowError("no connection %r (Plugin Studio › Connections)" % slug)
        if c.kind != "http" or c.auth != "basic" or not c.username:
            raise FlowError("connection %s must be HTTP with Basic auth and a user name" % slug)
        if (row.kind or "") in TOKEN_API_KINDS:
            raise FlowError("%s logs in to its REST API with a token or API key, not with "
                            "an administrator's password: %s cannot be tried there"
                            % (row.kind, c.username))
        secret, problem = SC.secret_state(slug)
        if not secret:
            raise FlowError("connection %s has no password%s" % (slug, (": " + problem) if problem else ""))
        target, who = _AsAccount(row, c.username, secret), "account %s" % c.username
    memo = (row.id, slug or "")
    with _REFUSED_LOCK:
        held = _REFUSED.get(memo)
    if held and time.time() - held[0] < LOGIN_REFUSED_HOLD_S:
        return "no", None, ("%s was refused by %s at %s; not tried again for %d min (each "
                            "refusal counts towards the admin lockout): %s"
                            % (who, row.name, time.strftime("%H:%M:%S", time.localtime(held[0])),
                               LOGIN_REFUSED_HOLD_S // 60, held[1]))
    try:
        clients.client_for(target).status_check()
    except DeviceAuthError as exc:
        with _REFUSED_LOCK:
            _REFUSED[memo] = (time.time(), str(exc)[:200])
        return "no", None, "%s refused by %s: %s" % (who, row.name, str(exc)[:200])
    except Exception as exc:  # noqa: BLE001 -- not reached is not refused
        raise FlowError("could not reach %s's API: %s" % (row.name, str(exc)[:200])) from None
    with _REFUSED_LOCK:
        _REFUSED.pop(memo, None)
    return "yes", None, "%s logged in to %s's API" % (who, row.name)


def _power_state(node, ctx):
    from ..models import db
    from ..models_provision import HypervisorTarget
    from ..models_sentinel import SentinelTopology
    from . import hypervisors
    from .studio_flow import FlowError
    row = _appliance(node, ctx)
    if str(row.hw_type or "").lower() == "hardware":
        raise FlowError("%s is hardware: no hypervisor knows its power state" % row.name)
    topo = SentinelTopology.query.filter_by(appliance_id=row.id).first()
    if topo is None or not topo.complete:
        raise FlowError("%s has no complete topology mapping (Sentinel › Topology: "
                        "hypervisor, VM id and node)" % row.name)
    target = db.session.get(HypervisorTarget, topo.hypervisor_target_id)
    if target is None:
        raise FlowError("hypervisor target %s is gone" % topo.hypervisor_target_id)
    try:
        client = hypervisors.build_client(target, timeout=15)
        st = client.vm_status(hypervisors.VmRef(backend=target.backend, identifier=str(topo.vm_id),
                                                name=row.name, node=topo.node or ""))
    except Exception as exc:  # noqa: BLE001 -- the hypervisor did not answer
        raise FlowError("hypervisor %s did not answer: %s" % (target.name, str(exc)[:200])) from None
    state = str((st or {}).get("status") or "").strip()
    where = "VM %s on %s (%s)" % (topo.vm_id, target.name, topo.node or "-")
    if state.lower() in POWER_ON:
        return "yes", None, "%s is %s" % (where, state)
    if state.lower() in POWER_OFF:
        return "no", None, "%s is %s" % (where, state)
    raise FlowError("%s reports power state %r" % (where, state or "unknown"))


def _appliance_ping(node, ctx, P):
    import re
    from .ssh_ops import ReadOnlyViolation, run_probe_command
    from .studio_flow import FlowError
    row = _appliance(node, ctx)
    target = str(P("target") or "").strip()
    if not target:
        raise FlowError("no target to ping")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:\-]{0,252}", target):
        raise FlowError("%r is not an IP address or host name" % target[:80])
    cmd = "execute ping %s" % target
    try:
        assert_console_read(cmd)
    except ReadOnlyViolation as exc:
        raise FlowError("refused to send: %s" % exc) from None
    try:
        out = run_probe_command(row, cmd, timeout=15.0,
                                maxt=float(_int(P("timeout", "30"), 30) or 30))
    except Exception as exc:  # noqa: BLE001 -- a dead box is a blind spot
        raise FlowError("SSH did not answer: %s" % str(exc)[:200]) from None
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out or "")
    if not m:
        raise FlowError("%s on %s printed no ping statistics: %s"
                        % (cmd, row.name, (out or "").strip()[-200:]))
    sent, got = int(m.group(1)), int(m.group(2))
    return (("yes" if got else "no"), (out or "")[-4000:],
            "%s from %s: %d/%d replies" % (target, row.name, got, sent))


def _as_list(v) -> list:
    if isinstance(v, (list, tuple)):
        items = v
    else:
        items = str(v or "").replace(";", ",").split(",")
    return [str(x).strip() for x in items if str(x).strip()]


def _notify(node, ctx, P):
    from . import notifications as notify
    from .studio_flow import SCENARIO_VAR, FlowError
    title = str(P("title") or "").strip()[:200]
    body = str(P("body") or "").strip()[:4000]
    if not title:
        raise FlowError("no title")
    who = []
    if str(P("bell", "yes") or "yes") == "yes":
        from .alerts import _admin_ids
        n = len(_admin_ids())
        who.append("bell of %d administrator%s" % (n, "" if n == 1 else "s"))
    to = _as_list(P("email_to"))
    if str(P("email_alerts", "no") or "no") == "yes":
        from . import alerts
        to += list(alerts.recipients())
    to = sorted(set(to))
    if to:
        who.append("e-mail to %s" % ", ".join(to))
    if not who:
        raise FlowError("nobody to notify: the bell is off and there is no address")
    if not ctx.armed:
        sc = ctx.vars.get(SCENARIO_VAR) or {}
        quiet = isinstance(sc, dict) and sc.get("answers") is not None \
            and node.get("key") not in (sc.get("first") or ())
        uid = getattr(ctx.user_obj, "id", None)
        if uid and not quiet:
            notify.push_many([uid], "[simulation] " + title, kind=notify.Notification.KIND_INFO,
                             body=body[:1500])
            rang = "rang your bell"
        else:
            rang = ("already rang your bell earlier in this simulation" if quiet
                    else "rang nobody (no user)")
        return "ok", None, "simulation: %s; would notify %s" % (rang, "; ".join(who))
    sent, failed = [], []
    if str(P("bell", "yes") or "yes") == "yes":
        from .alerts import _admin_ids
        ids = _admin_ids()
        if ids:
            notify.push_many(ids, title, kind=notify.Notification.KIND_INFO, body=body[:1500])
            sent.append("bell (%d)" % len(ids))
        else:
            failed.append("bell: no administrator to notify")
    if to:
        from . import email_service
        res = email_service.send_email(to, title, body or title)
        if (res or {}).get("ok"):
            sent.append("e-mail (%d)" % len(to))
        else:
            failed.append("e-mail: %s" % ((res or {}).get("detail") or "send failed"))
    if not sent:
        raise FlowError("nobody was notified: %s" % "; ".join(failed))
    return "ok", None, "notified %s%s" % (", ".join(sent), ("; " + "; ".join(failed)) if failed else "")


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
