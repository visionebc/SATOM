"""Result objects and rendering. STDLIB ONLY (see context.py).

PRESENTATION CONTRACT — the rule the rest of this file exists to keep:

    Decoration is for a TTY. Content is identical either way.

An operator redirects this tool into a ticket (``satom diagnose all > x.txt``),
pipes it into ``grep``, and pastes it into a chat window. So colour, rules and
box-drawing appear only when a human is looking at a terminal; through a pipe
the bytes stay plain and greppable. That is why every decision below is gated
on the resolved :class:`Style` and never on a hardcoded escape sequence.
"""
import json
import os
import shutil
import sys
import textwrap

# Exit codes. Stable contract: scripts and the install docs depend on these.
EXIT_OK = 0
EXIT_FAIL = 1        # command ran, result is bad (unit dead, cert expired, ...)
EXIT_USAGE = 2       # operator typed something the parser cannot resolve
EXIT_DENIED = 3      # insufficient privilege — NOT a traceback
EXIT_DEGRADED = 4    # command could not run (missing dependency, no creds)

# Only the 8 basic colours plus bold/dim. 256-colour and truecolour sequences
# render as literal garbage on a serial console, which is exactly where this
# tool gets used.
_PALETTE = {
    "ok": "\033[32m", "warn": "\033[33m", "bad": "\033[31m",
    "accent": "\033[36m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m",
}

_GLYPHS = {
    True: {"branch": "├─ ", "last": "└─ ",
           "pipe": "│  ", "gap": "   ", "rule": "─", "note": "!"},
    False: {"branch": "|- ", "last": "`- ",
            "pipe": "|  ", "gap": "   ", "rule": "-", "note": "!"},
}

# Words this CLI itself emits as a VERDICT. Deliberately tiny.
#
# 'active', 'inactive', 'enabled' and 'disabled' are NOT here: they are states,
# not verdicts, and whether they are good depends on the node's role. Painting
# 'inactive' red would flag satom-ha-datasync on the primary, where it is
# inert BY DESIGN — the same false positive that had to be removed from
# 'get system health'. A check that always complains is a check that gets
# ignored, and a colour that always complains is the same failure in paint.
_V_OK = frozenset(("ok", "OK", "pass", "PASS"))
_V_WARN = frozenset(("warn", "WARN"))
_V_BAD = frozenset(("FAIL", "fail", "error", "ERROR"))


# Typographic characters any handler may emit (em dashes in titles, middots in
# banners, an ellipsis from a truncation) folded to ASCII when the stream
# cannot carry them. Applied at the RENDER boundary, not at each call site:
# gating every handler is whack-a-mole, and the one that gets missed takes the
# recovery tool down with a UnicodeEncodeError on a node that is already broken.
_FOLD = {
    0x2014: "-", 0x2013: "-", 0x2012: "-", 0x00b7: "-", 0x2022: "*",
    0x2026: "...", 0x2018: "'", 0x2019: "'", 0x201c: '"', 0x201d: '"',
    0x2192: "->", 0x2190: "<-", 0x2264: "<=", 0x2265: ">=", 0x00a0: " ",
    0x2713: "ok", 0x2717: "x", 0x25b8: ">", 0x00b0: "deg",
}


def harden_stream(stream=None):
    """Make the output stream incapable of raising on un-encodable text.

    Second layer, on purpose. _FOLD handles the characters we know about;
    this handles the ones we do not — a device name, a certificate subject, a
    journal line. A diagnostic tool that dies while PRINTING its diagnosis is
    the worst failure mode available to it.
    """
    stream = stream if stream is not None else sys.stdout
    try:
        stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001  (StringIO and friends have no reconfigure)
        pass


class Style:
    """Resolved output policy: colour, glyph set and wrap width.

    Precedence, most explicit first: command-line flag, ``NO_COLOR`` /
    ``SATOM_CLI_COLOR``, ``TERM=dumb``, then whether stdout is a terminal.
    ``NO_COLOR`` is honoured because it is the cross-tool convention and an
    operator should not have to learn a SATOM-specific one.
    """

    def __init__(self, color=None, ascii_only=None, width=None, stream=None):
        stream = stream if stream is not None else sys.stdout
        try:
            self.tty = bool(stream.isatty())
        except Exception:  # noqa: BLE001
            self.tty = False

        if color is None:
            if os.environ.get("NO_COLOR") is not None:
                color = False
            elif os.environ.get("SATOM_CLI_COLOR") == "1":
                color = True
            elif os.environ.get("TERM", "") in ("dumb", ""):
                color = False
            else:
                color = self.tty
        self.color = bool(color)

        if ascii_only is None:
            if os.environ.get("SATOM_CLI_ASCII") == "1":
                ascii_only = True
            else:
                enc = (getattr(stream, "encoding", "") or "").lower()
                ascii_only = "utf" not in enc
        self.ascii = bool(ascii_only)
        self.g = _GLYPHS[not self.ascii]

        # width 0 means "never wrap". Through a pipe we must not reflow: a
        # wrapped line breaks the operator's grep and their copy-paste.
        if width:
            self.width = max(40, int(width))
        elif self.tty:
            self.width = max(40, shutil.get_terminal_size((100, 24)).columns)
        else:
            self.width = 0

    def fold(self, text):
        """ASCII-fold when the stream cannot carry typography."""
        return str(text).translate(_FOLD) if self.ascii else str(text)

    def c(self, key, text):
        if not self.color:
            return text
        return "%s%s%s" % (_PALETTE.get(key, ""), text, _PALETTE["off"])

    def rule(self, n):
        return self.g["rule"] * max(3, n)

    @property
    def decorate(self):
        """Rules and separators: only where a human is looking."""
        return self.tty or self.color


def style_of(ctx):
    return getattr(ctx, "style", None) or Style()


def _verdict(style, value):
    """Colour a leading verdict word, leaving the text byte-identical."""
    s = str(value)
    head = s.split(" ", 1)[0]
    if head in _V_OK:
        key = "ok"
    elif head in _V_WARN:
        key = "warn"
    elif head in _V_BAD:
        key = "bad"
    else:
        return s
    return style.c(key, head) + s[len(head):]


def _wrapped(style, text, indent):
    """Wrap a row VALUE so the key column survives. TTY only.

    Only row values are wrapped. ``lines`` bodies are left alone because they
    are frequently commands to copy and paste, and a wrapped command is a
    broken command.
    """
    text = str(text)
    if not style.width or indent + len(text) <= style.width:
        return [text]
    return textwrap.wrap(text, max(24, style.width - indent)) or [text]


class Result:
    """What every handler returns.

    ``status`` drives both the badge and the exit code, so the text a human
    reads and the number a script branches on can never disagree.
    """

    def __init__(self, status="ok", title="", exit_code=None):
        self.status = status          # ok | warn | bad | info
        self.title = title
        self.sections = []            # list of (heading, (kind, body))
        self.key_style = {}           # section index -> 'dim' | 'plain'
        self.notes = []
        self.data = {}                # machine payload for --json
        self._exit = exit_code

    def rows(self, heading, rows, keys="dim"):
        """A two-column section.

        ``keys`` says what the left column IS. In a state read-out the key is a
        label ('hostname', 'ha role') and dimming it pushes the eye to the
        value, which is the news. In a command listing the key is the command —
        the actionable thing — so dimming it inverts the emphasis and makes the
        whole table read as noise. The caller knows which it has; render does
        not, so it must not guess.
        """
        self.sections.append((heading, ("rows", list(rows))))
        self.key_style[len(self.sections) - 1] = keys
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


# The badge TEXT is frozen: docs/cli.md shows it and operators grep for
# '[FAIL]'. Colour is added around it, never instead of it.
_BADGE = {"ok": ("ok", "[ ok ]"), "warn": ("warn", "[warn]"),
          "bad": ("bad", "[FAIL]"), "info": ("dim", "[info]")}


def render(res, ctx):
    st = style_of(ctx)

    if ctx.json_mode:
        out = {"status": res.status, "title": res.title, "notes": res.notes,
               "data": res.data,
               "sections": [{"heading": h, "kind": k, "body": b}
                            for h, (k, b) in res.sections]}
        print(json.dumps(out, indent=2, default=str))
        return res.exit_code

    if res.title:
        key, text = _BADGE.get(res.status, ("dim", "[    ]"))
        print("%s %s" % (st.c(key, text), st.c("b", st.fold(res.title))))
        if st.decorate:
            print(st.c("dim", st.rule(min(st.width or 72, len(res.title) + 7))))

    for idx, (heading, (kind, body)) in enumerate(res.sections):
        # A blank line before every section, headed or not. Without this the
        # '?' listing runs its footer straight into the command table.
        if idx or res.title:
            print("")
        if heading:
            print(st.c("b", st.fold(heading)))
            if st.decorate:
                print(st.c("dim", st.rule(len(heading))))
        if kind == "rows":
            width = max([len(str(k)) for k, _ in body] or [0])
            keys = res.key_style.get(idx, "dim")
            for k, v in body:
                pieces = _wrapped(st, v, width + 4)
                label = "%-*s" % (width, st.fold(k))
                print("  %s  %s" % (st.c("dim", label) if keys == "dim" else label,
                                    _verdict(st, st.fold(pieces[0]))))
                for extra in pieces[1:]:
                    print("  %s  %s" % (" " * width, st.fold(extra)))
        else:
            for line in body:
                print(("  %s" % st.fold(line)) if str(line).strip() else "")

    if res.notes:
        print("")
        for n in res.notes:
            body = _wrapped(st, n, 4)
            print("%s %s" % (st.c("warn", st.g["note"]), st.fold(body[0])))
            for extra in body[1:]:
                print("  %s" % st.fold(extra))
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
