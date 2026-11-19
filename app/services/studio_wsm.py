"""Plugin Studio > Apps -- the Web Server Manager steps (Linux ADOM).

The Web Server Manager is delivered as PLUGINS, like Troubleshooting: the
bundle ``web-server-manager`` of the internal generator
(``satom-dev/satom-plugins``) holds one ``app`` plugin per module (servers,
files, sites, certificates, security, .htaccess, scripts, cron, packages,
services, logs, users, SSH), filed under the folder *Web Server Manager* of
Plugins and granted to the Linux ADOM. The pages under ``/webserver/`` stay
and keep answering by URL -- the file manager, the code editor and the live
logs need a page an app form cannot draw -- and every app links to its page.
Both call the same code.

Each step is an ADAPTER over :func:`services.wsm.execute`, the one function
every page operation goes through -- nothing is decided here a second time:

* ``wsm_servers``  -- the servers, whether their host key is trusted, whether
  SATOM may change them, and the credentials the person running may use;
* ``wsm_read``     -- one READ operation (``fs.list``, ``svc.list``,
  ``security.scan``...): only operations the catalogue marks as reads, so a
  rehearsal may run it;
* ``wsm_change``   -- one CHANGING operation (``svc.action``, ``pkg.apply``,
  ``vhost.create``...): a writing step, described by a rehearsal, never sent;
* ``wsm_htaccess`` -- an ``.htaccess`` template plus the operator's own lines,
  and what of it converts to nginx (pure: no server is touched).

THE PERSON WHO RUNS, NOT THE APP
--------------------------------
:func:`services.wsm.execute` is called with the run's user: the profile
(``webserver.view`` / ``.files`` / ``.sites`` / ``.system`` / ``.root``), the
credential (theirs or shared, active, allowed for the module), the server's
Allow changes switch and the run-as are checked exactly as for a page click.
An app never widens who may change a server. A run without a user (a
schedule, an event) is refused.

SECRETS
-------
A credential that keeps no secret, or sudo that asks for one, needs the
password for that one call: the app's ``password`` fields go in the step's
``password`` / ``passphrase`` / ``sudo_password`` parameters, are used for the
call and never saved (Plugin Studio masks password fields before a run is
stored; this module never puts them in a result or a detail line).

Every attempt leaves the page's audit row (three identities, sudo, credential,
session) and a change also the application audit line.
"""
from __future__ import annotations

import json
import re
import shlex

from . import studio_flow as F
from . import wsm as W
from . import wsm_transport as T

GROUP = "satom"
KIND_KEYS = ("wsm_servers", "wsm_read", "wsm_change", "wsm_htaccess")
WRITE_KINDS = ("wsm_change",)
DEVICE_KINDS: tuple = ()
DEFAULT_SAVE_AS = {"wsm_servers": "servers", "wsm_read": "ws", "wsm_change": "change",
                   "wsm_htaccess": "rules"}
READ_OPS = tuple(sorted(op for op, (_m, w) in W.OPS.items() if not w))
WRITE_OPS = tuple(sorted(op for op, (_m, w) in W.OPS.items() if w))
RUN_AS = ("", "self", "auto", "root")
#: The module pages a result links to (``/webserver/<slug>/<page>``).
PAGES = ("files", "sites", "certs", "security", "htaccess", "scripts", "cron", "packages",
         "services", "logs", "users", "ssh")
MAX_ROWS = 2000
MAX_TIMEOUT = 1800
#: Form values are text; the helper reads these as booleans, numbers or lists.
BOOL_ARGS = frozenset({"hidden", "recursive", "parents", "overwrite", "create_only", "text",
                       "dry_run", "staging", "enable", "replace", "https", "redirect_https",
                       "security_headers", "own_logs", "placeholder", "system", "create_home",
                       "remove_home", "lock", "all", "htaccess"})
INT_ARGS = frozenset({"lines", "max", "depth", "port", "upload_mb", "timeout_s", "timeout"})
#: One per line (a path may hold commas or spaces).
LINE_LIST_ARGS = frozenset({"paths", "keys", "docroots"})
#: Separated by commas, spaces or new lines.
WORD_LIST_ARGS = frozenset({"names", "domains", "groups", "add_groups", "remove_groups",
                            "server_names"})
#: Objects a form may give as JSON text.
OBJECT_ARGS = frozenset({"headers", "env", "settings"})
_TRUE = ("1", "true", "yes", "on", "y")
_FALSE = ("", "0", "false", "no", "off", "n", "none")
#: The list a result's table is drawn from, in this order of preference.
LIST_KEYS = ("entries", "services", "packages", "updates", "installed", "results", "matches",
             "vhosts", "sites", "certs", "certificates", "users", "groups", "findings", "rules",
             "jails", "keys", "sources", "versions", "history", "units", "plan", "lines",
             "listening", "jobs", "items")


# --------------------------------------------------------------------------- #
#  the step kinds                                                              #
# --------------------------------------------------------------------------- #
def kinds() -> list:
    from . import wsm_htaccess as HT
    P, K = F.Param, F.Kind

    def common(ops, what):
        return [
            P("server", "Server", required=True,
              help="A Web Server Manager server (its slug), e.g. {{ form.server }}."),
            P("credential", "Credential (id)",
              help="e.g. {{ form.credential }}. Empty: your own active credential for the "
                   "server, otherwise a shared one."),
            P("op", "Operation", "select", True, choices=ops,
              help="The %s operation the pages run." % what),
            P("args", "Arguments (JSON)", "json",
              help='An object with templates, e.g. {"name": "{{ form.service }}", '
                   '"action": "restart"}. Yes / no, numbers and lists typed in a form are '
                   'read as the operation expects them.'),
            P("run_as", "Run as",
              help="self, auto or root, or {{ form.run_as }}. Empty: the credential's own "
                   "setting. self = the SSH account, auto = the account first and sudo on "
                   "'permission denied', root = through sudo. Root needs webserver.root."),
            P("password", "Password", help="{{ form.password }} when the credential keeps no "
                                           "secret: used for this call only, never saved."),
            P("passphrase", "Key passphrase", help="{{ form.passphrase }}, same rule."),
            P("sudo_password", "sudo password",
              help="{{ form.sudo_password }} when sudo asks for one, same rule."),
            P("timeout", "Timeout (s)", default="120", help="10 to %d." % MAX_TIMEOUT),
            P("page", "Page", "select", choices=("",) + PAGES,
              help="The page the result links to (page_url). Empty: the operation's module."),
        ]
    return [
        K("wsm_servers", "Web servers", GROUP,
          "The Web Server Manager's servers: host, whether the host key is trusted, whether "
          "SATOM may change it, and the credentials the person running may use, each row with "
          "the links to its pages. Reads SATOM only. Needs webserver.view.",
          [F._save_as("servers")]),
        K("wsm_read", "Web server: read", GROUP,
          "Run one READ operation of the Web Server Manager on a server over SSH, as the "
          "person running the app (their profile, their or a shared credential): the same "
          "call as the pages. Saves result (the server's answer), rows (its list, as a "
          "table), summary (its single values), who (the effective Linux user), sudo, "
          "credential and page_url. Needs webserver.view.",
          common(READ_OPS, "reading") + [F._save_as("ws")]),
        K("wsm_change", "Web server: change", GROUP,
          "Run one CHANGING operation of the Web Server Manager on a server over SSH (start a "
          "service, install a package, create a site...), as the person running the app: "
          "their profile must hold the module's permission, the server must allow changes, "
          "and root needs webserver.root -- the same checks as the pages. A rehearsal "
          "describes it and sends nothing. Saves the same values as Web server: read.",
          common(WRITE_OPS, "changing") + [F._save_as("change")], writes=True),
        K("wsm_htaccess", "Web server: .htaccess rules", GROUP,
          "An .htaccess text from a template (WordPress, Laravel...) plus your own lines, and "
          "its nginx equivalent: which lines convert and which do not (an nginx server never "
          "reads .htaccess; a line that does not convert is listed, never applied). Touches "
          "no server. Needs webserver.view.",
          [P("template", "Template",
             help="%s, or {{ form.template }}. Empty: only your lines."
                  % ", ".join(HT.TEMPLATES)),
           P("content", "Your lines", "textarea", help="e.g. {{ form.content }}."),
           F._save_as("rules")]),
    ]


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #
def _s(node, ctx, name, default="") -> str:
    v = F.render(F._p(node, name, default), ctx.scope())
    return "" if v is None else str(v).strip()


def need(ctx) -> None:
    u = ctx.user_obj
    if u is None:
        raise F.FlowError("the Web Server Manager answers for the person who runs the app; a "
                          "run without a user (a schedule or an event) cannot use it")
    if not W.can(u, W.VIEW_PERM):
        raise F.FlowError("this step needs the %s permission (the Web Server Manager pages "
                          "ask the same); the user running the app does not hold it"
                          % W.VIEW_PERM)


def coerce_args(args: dict) -> dict:
    """Form text to what the helper reads: ``bool(args.get("hidden"))`` on
    the text 'no' would be True. Empty numbers are dropped (the helper's
    default applies)."""
    out = {}
    for k, v in args.items():
        if k in BOOL_ARGS and not isinstance(v, bool):
            t = str(v if v is not None else "").strip().lower()
            if t in _TRUE:
                v = True
            elif t in _FALSE:
                v = False
            else:
                raise F.FlowError("argument %s: %r is not yes or no" % (k, v))
        elif k in INT_ARGS and not isinstance(v, int):
            t = str(v if v is not None else "").strip()
            if not t:
                continue
            try:
                v = int(float(t))
            except ValueError:
                raise F.FlowError("argument %s: %r is not a number" % (k, v)) from None
        elif k in LINE_LIST_ARGS and isinstance(v, str):
            v = [x.strip() for x in v.splitlines() if x.strip()]
        elif k in WORD_LIST_ARGS and isinstance(v, str):
            v = [x for x in re.split(r"[\s,]+", v) if x]
        elif k == "args" and isinstance(v, str):
            try:
                v = shlex.split(v)
            except ValueError as exc:
                raise F.FlowError("argument args: %s" % exc) from None
        elif k in OBJECT_ARGS and isinstance(v, str):
            t = v.strip()
            try:
                v = json.loads(t) if t else {}
            except ValueError:
                raise F.FlowError("argument %s: not a JSON object" % k) from None
            if not isinstance(v, dict):
                raise F.FlowError("argument %s: not a JSON object" % k)
        out[k] = v
    return out


def _cell(v):
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        return v if len(v) <= 2000 else v[:2000] + "..."
    if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
        return ", ".join("" if x is None else str(x) for x in v)[:2000]
    t = json.dumps(v, default=str, sort_keys=True)
    return t if len(t) <= 500 else t[:500] + "..."


def rows_of(result) -> list[dict]:
    """The answer's list as table rows (``LIST_KEYS`` first, then the first
    list it holds); nested values become text so a table can show them."""
    lst = None
    if isinstance(result, list):
        lst = result
    elif isinstance(result, dict):
        for k in LIST_KEYS:
            if isinstance(result.get(k), list):
                lst = result[k]
                break
        if lst is None:
            lst = next((v for v in result.values() if isinstance(v, list)), None)
    out = []
    for x in (lst or [])[:MAX_ROWS]:
        out.append({k: _cell(v) for k, v in x.items()} if isinstance(x, dict)
                   else {"value": _cell(x)})
    return out


def summary_of(result) -> dict:
    """The answer's single values (and those one object down: ``props.X``)."""
    out = {}
    if not isinstance(result, dict):
        return out
    for k, v in result.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if not isinstance(v2, (dict, list)):
                    out["%s.%s" % (k, k2)] = _cell(v2)
        elif not isinstance(v, list):
            out[k] = _cell(v)
        if len(out) >= 80:
            break
    return out


def default_credential(c, user):
    """The person's own active credential for *c*, else a shared one."""
    me = getattr(user, "username", "")
    rows = [r for r in W.visible_credentials(c.slug, user)
            if W.usable(r, user) and r.state == "active"]
    rows.sort(key=lambda r: (r.owner != me, r.auth_type == "agent", r.id))
    if not rows:
        raise F.FlowError("you have no credential for %s: add your SSH account on its server "
                          "page (/webserver/%s/)" % (c.name, c.slug))
    return rows[0]


def _page_url(slug: str, op: str, page: str) -> str:
    module = W.OPS.get(op, ("", False))[0]
    page = page if page in PAGES else (module if module in PAGES else "")
    return "/webserver/%s/%s" % (slug, page)


def _timeout(node, ctx) -> float:
    try:
        return max(10.0, min(float(_s(node, ctx, "timeout", "120") or 120), MAX_TIMEOUT))
    except ValueError:
        return 120.0


def _resolve(node, ctx, ops: tuple):
    """Server, operation, arguments and credential -- checked, nothing sent."""
    slug = _s(node, ctx, "server")
    op = _s(node, ctx, "op")
    if op not in ops:
        raise F.FlowError("%r is not one of this step's operations" % op)
    try:
        c = W.server(slug)
    except W.WsmDenied as exc:
        raise F.FlowError(str(exc)) from None
    raw = F._p(node, "args", None)
    args = F._json(node, ctx, "args", "Arguments") if str(raw or "").strip() else {}
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise F.FlowError("the arguments are a JSON object")
    args = coerce_args(args)
    user = ctx.user_obj
    cid = _s(node, ctx, "credential")
    try:
        cred = W.pick_credential(c, user, int(cid)) if cid else default_credential(c, user)
    except ValueError:
        raise F.FlowError("credential %r is not an id" % cid) from None
    except W.WsmDenied as exc:
        raise F.FlowError(str(exc)) from None
    run_as = _s(node, ctx, "run_as")
    if run_as not in RUN_AS:
        raise F.FlowError("run as is self, auto or root (empty: the credential's)")
    return c, op, args, cred, run_as


def _result(c, op, page, r) -> dict:
    res = r["result"]
    who = r.get("who") or {}
    return {"server": c.slug, "server_name": c.name, "op": op, "result": res,
            "rows": rows_of(res), "summary": summary_of(res),
            "who": {"user": who.get("user"), "uid": who.get("uid")},
            "effective_user": who.get("user") or "", "sudo": bool(r.get("sudo")),
            "credential": r.get("credential") or "", "ms": r.get("ms"),
            "page_url": _page_url(c.slug, op, page)}


def _op(node, ctx, ops: tuple) -> tuple:
    from .studio_troubleshoot import fit
    c, op, args, cred, run_as = _resolve(node, ctx, ops)
    provided = {k: v for k, v in (("secret", _s(node, ctx, "password")),
                                  ("passphrase", _s(node, ctx, "passphrase")),
                                  ("sudo", _s(node, ctx, "sudo_password"))) if v}
    try:
        r = W.execute(c.slug, cred.id, op, args, user=ctx.user_obj, run_as=run_as,
                      provided=provided, timeout=_timeout(node, ctx))
    except W.NeedSecret as exc:
        asked = {"secret": "Password", "passphrase": "Key passphrase",
                 "sudo": "sudo password"}
        raise F.FlowError("credential %s needs %s for this call (%s): fill the field in the "
                          "app's form" % (exc.cred.name, ", ".join(asked.get(f, f)
                                                                    for f in exc.fields),
                                          exc.why or "it keeps no secret")) from None
    except W.WsmDenied as exc:
        raise F.FlowError(str(exc)) from None
    except T.WsmError as exc:
        raise F.FlowError("%s on %s: %s" % (op, c.name, exc)) from None
    res = fit(_result(c, op, _s(node, ctx, "page"), r), (("result",),))
    who = res["effective_user"] or "?"
    detail = "%s on %s as %s%s via %s, %s ms" % (op, c.name, who, " (sudo)" if res["sudo"] else "",
                                                 res["credential"], res["ms"])
    rows = res["rows"]
    if rows:
        detail += ", %d row(s)" % len(rows)
    return "ok", res, detail


def _servers(ctx) -> tuple:
    user = ctx.user_obj
    rows = []
    for c in W.servers():
        st = W.server_state(c)
        mine = [r for r in W.visible_credentials(c.slug, user)
                if W.usable(r, user) and r.state == "active"]
        rows.append({"Server": c.name, "Host": "%s:%s" % (c.host, c.port or 22),
                     "Host key": "trusted" if st["host_key"] else "not trusted",
                     "Changes": "allowed" if st["allow_writes"] else "read-only",
                     "Your credentials": ", ".join(r.name for r in mine) or "none",
                     "_slug": c.slug, "_cred": str(mine[0].id) if mine else "",
                     "_url": "/webserver/%s/" % c.slug})
    return "ok", {"rows": rows, "count": len(rows),
                  "usable": sum(1 for r in rows if r["_cred"])}, \
        "%d server(s), %d with a credential you may use" % (
            len(rows), sum(1 for r in rows if r["_cred"]))


def _htaccess(node, ctx) -> tuple:
    from . import wsm_htaccess as HT
    tpl = _s(node, ctx, "template")
    if tpl and tpl not in HT.TEMPLATES:
        raise F.FlowError("no .htaccess template %r" % tpl)
    own = str(F.render(F._p(node, "content", ""), ctx.scope()) or "").strip()
    parts = ([HT.TEMPLATES[tpl][1].strip()] if tpl else []) + ([own] if own else [])
    if not parts:
        raise F.FlowError("pick a template or write your lines")
    text = "\n\n".join(parts) + "\n"
    conv = HT.to_nginx(text)
    skipped = [{"Line": s.get("line"), "Why not": s.get("why")} for s in conv["skipped"]]
    res = {"content": text, "nginx": conv["nginx"], "converted": conv["converted"],
           "skipped": skipped, "all_converted": not skipped}
    return "ok", res, "%d line(s) convert to nginx, %d do not" % (len(conv["converted"]),
                                                                 len(skipped))


# --------------------------------------------------------------------------- #
#  the runner                                                                  #
# --------------------------------------------------------------------------- #
def rehearse(node: dict, ctx) -> tuple:
    """``wsm_change`` in a rehearsal: every SATOM check of a real call (the
    profile, the credential, Allow changes, root), the value with the real
    result's shape, and nothing sent to the server."""
    need(ctx)
    from .studio_dns import as_operator
    with as_operator(ctx):
        c, op, args, cred, run_as = _resolve(node, ctx, WRITE_OPS)
        run_as = run_as or cred.run_as
        try:
            W.check_op(ctx.user_obj, op, elevated=(run_as == "root" and cred.can_escalate))
        except W.WsmDenied as exc:
            raise F.FlowError(str(exc)) from None
        if not W.server_state(c)["allow_writes"]:
            raise F.FlowError("%s is read-only in SATOM: turn on Allow changes on its server "
                              "page" % c.name)
    res = {"server": c.slug, "server_name": c.name, "op": op, "result": {}, "rows": [],
           "summary": {}, "who": {"user": cred.ssh_user, "uid": None},
           "effective_user": cred.ssh_user, "sudo": False, "credential": cred.name, "ms": 0,
           "page_url": _page_url(c.slug, op, _s(node, ctx, "page")), "rehearsal": True}
    return "ok", res, "rehearsal: would run %s on %s with %s (run as %s)%s" % (
        op, c.name, cred.name, run_as, ": " + W._target_summary(args) if args else "")


def run(node: dict, ctx) -> tuple:
    from .studio_dns import as_operator
    kind = node.get("kind")
    if kind not in KIND_KEYS:
        raise F.FlowError("unknown step kind %r" % kind)
    need(ctx)
    if kind == "wsm_htaccess":
        return _htaccess(node, ctx)
    with as_operator(ctx):
        if kind == "wsm_servers":
            return _servers(ctx)
        return _op(node, ctx, READ_OPS if kind == "wsm_read" else WRITE_OPS)
