"""Result objects and rendering. STDLIB ONLY (see context.py)."""
import json
import sys

# Exit codes. Stable contract: scripts and the install docs depend on these.
EXIT_OK = 0
EXIT_FAIL = 1        # command ran, result is bad (unit dead, cert expired, ...)
EXIT_USAGE = 2       # operator typed something the parser cannot resolve
EXIT_DENIED = 3      # insufficient privilege — NOT a traceback
EXIT_DEGRADED = 4    # command could not run (missing dependency, no creds)

_C = {
    "ok": "\033[32m", "warn": "\033[33m", "bad": "\033[31m",
    "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m",
}


def _color(enabled):
    return _C if enabled else {k: "" for k in _C}


class Result:
    """What every handler returns.

    ``status`` drives both the badge and the exit code, so the text a human
    reads and the number a script branches on can never disagree.
    """

    def __init__(self, status="ok", title="", exit_code=None):
        self.status = status          # ok | warn | bad | info
        self.title = title
        self.sections = []            # list of (heading, rows|lines)
        self.notes = []
        self.data = {}                # machine payload for --json
        self._exit = exit_code

    def rows(self, heading, rows):
        self.sections.append((heading, ("rows", list(rows))))
        return self

    def lines(self, heading, lines):
        self.sections.append((heading, ("lines", list(lines))))
        return self

    def note(self, text):
        self.notes.append(text)
        return self

    def set(self, **kw):
        self.data.update(kw)
        return self

    def worst(self, status):
        """Fold in a child status; keeps the most severe."""
        order = {"ok": 0, "info": 0, "warn": 1, "bad": 2}
        if order.get(status, 0) > order.get(self.status, 0):
            self.status = status
        return self

    @property
    def exit_code(self):
        if self._exit is not None:
            return self._exit
        return EXIT_FAIL if self.status == "bad" else EXIT_OK


def render(res, ctx):
    if ctx.json_mode:
        out = {"status": res.status, "title": res.title, "notes": res.notes,
               "data": res.data,
               "sections": [{"heading": h, "kind": k, "body": b}
                            for h, (k, b) in res.sections]}
        print(json.dumps(out, indent=2, default=str))
        return res.exit_code

    c = _color(sys.stdout.isatty())
    badge = {"ok": c["ok"] + "[ ok ]", "warn": c["warn"] + "[warn]",
             "bad": c["bad"] + "[FAIL]", "info": c["dim"] + "[info]"}.get(res.status, "")
    if res.title:
        print("%s%s %s%s%s" % (badge, c["off"], c["b"], res.title, c["off"]))
    for heading, (kind, body) in res.sections:
        if heading:
            print("\n%s%s%s" % (c["b"], heading, c["off"]))
        if kind == "rows":
            width = max([len(str(k)) for k, _ in body] or [0])
            for k, v in body:
                print("  %-*s  %s" % (width, k, v))
        else:
            for line in body:
                print("  %s" % line)
    if res.notes:
        print("")
        for n in res.notes:
            print("%s! %s%s" % (c["warn"], n, c["off"]))
    return res.exit_code


def denied(path, node, ctx, rest=()):
    """Refusal for an unprivileged operator.

    Says WHAT is missing and HOW to get it, echoing the FULL command including
    its arguments — an operator who has to retype the arguments from memory
    will retype them wrong. A traceback here would be the worst possible
    outcome: they are already looking at a broken box.
    """
    cmd = " ".join(list(path) + list(rest))
    r = Result("bad", "permission denied: %s" % cmd, exit_code=EXIT_DENIED)
    r.rows("why", [
        ("running as", "%s (uid %s)" % (ctx.user, ctx.uid)),
        ("required", "root"),
        ("reason", node.help),
    ])
    r.lines("how", [
        "sudo satom %s" % cmd,
        "",
        "Diagnostics ('get', 'show', 'diagnose') work as any user — run those first.",
        "If your account has no sudo rights, print the rule to request:",
        "  satom show sudoers <your-account>",
    ])
    r.note("Never add 'satom' to the service account's sudoers: that would make "
           "a compromised web worker root. See docs/privilege-model.md.")
    return r
