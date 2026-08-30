"""Entry point: ONE dispatcher, two front-ends.

The one-shot form is the contract (scripts, cron, documentation, a recovery
step in INSTALL.md). The interactive prompt is a discovery layer on top of the
same dispatcher — never a second implementation, because two parsers means the
day you need a command in a script it behaves differently than it did at the
prompt.

STDLIB ONLY: see context.py for why.
"""
import os
import sys

from .context import Ctx
from .render import (_PALETTE, EXIT_DENIED, EXIT_OK, EXIT_USAGE, Result, Style,
                     denied, harden_stream, render, style_of)
from .tree import ROOT, Node

BANNER = "SATOM operator CLI"
HINT = ("'?' lists commands here  ·  'show tree' is the whole map  ·  "
        "'exit' leaves")
HINT_ASCII = ("'?' lists commands here | 'show tree' is the whole map | "
              "'exit' leaves")

# --- console banner -------------------------------------------------------
#
# The wordmark is drawn from a table PER LETTER, not by slicing one string at
# fixed offsets: a slice makes every future edit a column-arithmetic problem
# and is how an earlier draft painted the M in the O's column.
#
# Blocks of '#' only. This CLI is used on serial consoles of broken nodes,
# where the alternate glyph set (_GLYPHS[False]) already exists because box
# drawing folds to garbage there; art built from Unicode blocks would have the
# same fate and would need a second variant. '#' renders identically in both
# modes and through a pipe.
_ART_GLYPHS = {
    "S": ("############",
          "##        ##",
          "##          ",
          "############",
          "          ##",
          "##        ##",
          "############"),
    "A": ("############",
          "##        ##",
          "##        ##",
          "############",
          "##        ##",
          "##        ##",
          "##        ##"),
    "T": ("############",
          "    ####    ",
          "    ####    ",
          "    ####    ",
          "    ####    ",
          "    ####    ",
          "    ####    "),
    "O": ("############",
          "##        ##",
          "##        ##",
          "##        ##",
          "##        ##",
          "##        ##",
          "############"),
    "M": ("###      ###",
          "####    ####",
          "## ##  ## ##",
          "##  ####  ##",
          "##   ##   ##",
          "##        ##",
          "##        ##"),
}
_ART_WORD = "SATOM"
_ART_ROWS = 7
_ART_GAP = "  "
_ART_INDENT = "  "

# Extra lead on the TOP row only, requested explicitly by the operator after
# being told what it does. It shifts the top bars of S/A/T/O and the peaks of
# the M two columns right of their own stems. Revert by setting this to "".
_ART_TOP_EXTRA = "  "

# Below this terminal width the art is suppressed and the short header is
# printed instead. A banner that wraps on a recovery console is worse than no
# banner. width == 0 means "piped": no reflow happens there, so nothing is
# suppressed.
_ART_MIN_WIDTH = 78
_RULE_W = 76

SUBTITLE = "System Automation & Task Orchestration Manager"
ATTRIBUTION = "Made by VisionEBC  \u00b7  https://visionebc.com"

# NINTH surface that declares the licence (LICENSE, NOTICE, README.md,
# CONTRIBUTING.md, DISCLAIMER, SECURITY.md, the curated site pages and the
# footer template in deploy/gen_site_docs.py are the other eight).
#
# Nothing fails when a licence surface goes stale -- the claim simply becomes
# false. That is how 'Version: 1.0' survived four releases in the README, and
# here it is worse: whoever acts on the wrong surface relies on a grant that
# was never made. tests/test_cli_banner.py pins these lines against the same
# assertions as the site footer.
LICENCE_LINES = (
    "Copyright 2026 Vision EBC  \u00b7  Licensed under the Elastic License 2.0",
    "Source-available, NOT OSI open source  \u00b7  provided AS IS, without warranty",
    "Offering SATOM to third parties as a hosted or managed service requires",
    "a commercial licence: licensing@visionebc.com",
)

# Escape hatch. Runbooks and operators who open this console dozens of times a
# day get the one-line header back without losing the console.
NO_BANNER_ENV = "SATOM_CLI_NO_BANNER"


def art_lines():
    """The wordmark, one string per row, trailing blanks stripped."""
    rows = []
    for i in range(_ART_ROWS):
        row = _ART_GAP.join(_ART_GLYPHS[ch][i] for ch in _ART_WORD)
        lead = _ART_INDENT + (_ART_TOP_EXTRA if i == 0 else "")
        rows.append((lead + row).rstrip())
    return rows


def banner_lines(ctx, st):
    """Every line the interactive console prints before its first prompt."""
    out = []
    # Narrow collapses to the SAME short form as the opt-out, not just "art
    # off". The licence prose is fixed-width, so suppressing only the art
    # leaves four 74-column sentences to wrap into confetti on the recovery
    # console this threshold exists to protect.
    short = (os.environ.get(NO_BANNER_ENV) == "1"
             or (st.width and st.width < _ART_MIN_WIDTH))
    if not short:
        out.extend(art_lines())
        out.append("")

    out.append("  " + st.c("b", "%s %s" % (BANNER, ctx.version())))
    if not short:
        out.append("  " + st.c("dim", st.fold(SUBTITLE)))
        out.append("  " + st.c("dim", st.fold(ATTRIBUTION)))
    out.append("  " + st.c("dim", st.fold("%s \u00b7 %s \u00b7 %s"
                                          % (ctx.host, ctx.role, ctx.user))))
    if not ctx.is_root:
        out.append("  " + st.c("warn", st.fold(
            "unprivileged \u2014 'execute' is unavailable; "
            "diagnostics all work")))

    rule = st.rule(min(st.width or _RULE_W, _RULE_W))
    out.append("  " + st.c("dim", rule))
    if not short:
        for line in LICENCE_LINES:
            out.append("  " + st.c("dim", st.fold(line)))
        out.append("  " + st.c("dim", rule))
    out.append("  " + st.c("dim", HINT_ASCII if st.ascii else HINT))
    return out




def help_for(node, path, ctx):
    st = style_of(ctx)
    title = " ".join(("satom",) + tuple(path)) if path else "satom"
    r = Result("info", title)

    if node.run and not node.children:
        r.rows("", [("usage", "satom " + (node.usage or " ".join(path))),
                    ("privilege", "root" if node.needs_root else "any user"),
                    ("effect", "CHANGES STATE" if node.needs_root else "read-only")])
        r.lines("", [node.help])
        if node.danger:
            r.note("Destructive. Read the on-screen confirmation before typing --yes.")
        return r

    rows = []
    for name in sorted(node.children):
        child = node.children[name]
        mark = "*" if (child.needs_root or _subtree_needs_root(child)) else " "
        if child.danger or _subtree_danger(child):
            mark += "!"
        rows.append(("%s %s" % (name, mark.strip()) if mark.strip() else name,
                     st.c("dim", child.help)))
    r.rows("", rows, keys="plain")

    foot = ["'*' needs root   '!' destructive",
            "'%s <name> ?' for that branch" % title]
    if not path:
        foot.append("'satom show tree' prints the whole command tree at once")
    r.lines("", foot)
    return r


def _subtree_needs_root(node):
    return any(n.needs_root for _, n in _walk(node))


def _subtree_danger(node):
    return any(n.danger for _, n in _walk(node))


def _walk(node, path=()):
    yield path, node
    for name, child in node.children.items():
        for item in _walk(child, path + (name,)):
            yield item


def dispatch(ctx, tokens):
    node = ROOT
    path = []
    tokens = list(tokens)
    while tokens:
        t = tokens[0]
        if t in ("?", "help", "--help", "-h"):
            return help_for(node, path, ctx)
        if t in node.children:
            node = node.children[t]
            path.append(t)
            tokens.pop(0)
            continue
        break

    if node.run is None:
        if tokens:
            r = Result("bad", "unknown command: %s" % " ".join(path + [tokens[0]]),
                       exit_code=EXIT_USAGE)
            r.lines("did you mean", _suggest(node, tokens[0]) or
                    ["(nothing similar here — type '?' at this level)"])
            r.lines("available here", sorted(node.children) or ["(none)"])
            return r
        return help_for(node, path, ctx)

    if node.needs_root and not ctx.is_root:
        return denied(path, node, ctx, tokens)

    try:
        return node.run(ctx, tokens)
    except KeyboardInterrupt:
        return Result("warn", "interrupted", exit_code=130)
    except Exception as exc:  # noqa: BLE001
        # A handler that blows up must still produce something actionable: the
        # operator is looking at a broken node and a bare traceback tells them
        # nothing they can do.
        r = Result("bad", "command failed: %s" % " ".join(path))
        r.rows("", [("error", "%s: %s" % (type(exc).__name__, exc))])
        r.lines("next", ["This is a bug in the CLI, not necessarily in the node.",
                         "The underlying state is still readable with:",
                         "  satom get system health",
                         "  satom get log web 50"])
        if os.environ.get("SATOM_CLI_TRACE"):
            import traceback
            r.lines("traceback", traceback.format_exc().splitlines())
        else:
            r.note("Re-run with SATOM_CLI_TRACE=1 for the traceback.")
        return r


# -- interactive ----------------------------------------------------------
def _completer(ctx):
    def complete(text, state):
        buf = __import__("readline").get_line_buffer()[:__import__("readline").get_endidx()]
        parts = buf.split()
        if buf.endswith(" "):
            parts.append("")
        node = ROOT
        for p in parts[:-1]:
            if p in node.children:
                node = node.children[p]
            else:
                return None
        opts = [n for n in sorted(node.children) if n.startswith(parts[-1] if parts else "")]
        if node.run and not node.children:
            opts = []
        return (opts + [None])[state]
    return complete


def _prompt_color(st, key, text):
    """Colour a PROMPT fragment.

    readline counts every byte between the start of the prompt and the cursor
    as visible width unless the non-printing run is bracketed by \\001 / \\002.
    Without those markers the cursor lands in the wrong column the moment the
    operator edits or recalls a line — the classic 'my shell is haunted' bug.
    """
    if not st.color:
        return text
    return "\001%s\002%s\001%s\002" % (_PALETTE[key], text, _PALETTE["off"])


def repl(ctx):
    st = style_of(ctx)
    try:
        import readline
    except ImportError:
        readline = None
    if readline:
        histfile = os.path.expanduser("~/.satom_history")
        try:
            readline.read_history_file(histfile)
        except Exception:  # noqa: BLE001
            pass
        readline.set_completer(_completer(ctx))
        readline.set_completer_delims(" \t")
        readline.parse_and_bind("tab: complete")

    print("")
    for line in banner_lines(ctx, st):
        print(line)
    print("")

    sigil = "#" if ctx.is_root else ">"
    prompt = "%s %s " % (_prompt_color(st, "accent", "satom(%s)" % ctx.host),
                         _prompt_color(st, "b", sigil))
    last = EXIT_OK
    while True:
        try:
            line = input(prompt)
        except EOFError:
            print("")
            break
        except KeyboardInterrupt:
            # Ctrl-C abandons the LINE, like a shell — it does not throw the
            # operator out of the console they opened to fix a broken node.
            print("^C")
            continue
        line = line.strip()
        if not line:
            continue
        if line in ("exit", "quit", "end"):
            break
        last = render(dispatch(ctx, line.split()), ctx)
    if readline:
        try:
            readline.write_history_file(os.path.expanduser("~/.satom_history"))
        except Exception:  # noqa: BLE001
            pass
    return last


def _take(argv, *names):
    hit = False
    for n in names:
        while n in argv:
            argv.remove(n)
            hit = True
    return hit


def _take_value(argv, name):
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            v = argv[i + 1]
            del argv[i:i + 2]
            return v
        if a.startswith(name + "="):
            del argv[i]
            return a.split("=", 1)[1]
    return None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    json_mode = _take(argv, "--json")
    no_color = _take(argv, "--no-color", "--nocolor")
    force_color = _take(argv, "--color")
    ascii_only = _take(argv, "--ascii")
    width = _take_value(argv, "--width")

    color = None
    if no_color:
        color = False
    elif force_color:
        color = True
    # --json is a machine contract: never decorate it.
    if json_mode:
        color = False

    harden_stream()
    ctx = Ctx(json_mode=json_mode)
    ctx.style = Style(color=color, ascii_only=(True if ascii_only else None),
                      width=int(width) if width and width.isdigit() else None)

    if not argv:
        if json_mode or not sys.stdin.isatty():
            return render(help_for(ROOT, [], ctx), ctx)
        return repl(ctx)
    return render(dispatch(ctx, argv), ctx)


def _suggest(node, token):
    import difflib
    return difflib.get_close_matches(token, list(node.children), n=3, cutoff=0.5)


if __name__ == "__main__":
    sys.exit(main())
