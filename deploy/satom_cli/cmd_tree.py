"""'show tree' — the whole command surface in one view. STDLIB ONLY.

Why this exists as a command and not as a page in docs/: the command tree is
DATA (see tree.py), so any hand-written list of commands is a copy that goes
stale the first time someone adds a node. This renders the live registry, which
means it cannot lie about what this build actually supports — including on a
node with no web UI and no route to the documentation.

The tree module imports THIS module (it registers the handler), so the import
of the registry happens inside the function. That is the same lazy-import
pattern the rest of the CLI uses, and tests/test_cli.py's AST check only
governs module level.
"""
from .render import EXIT_USAGE, Result, style_of

MARK_ROOT = "*"
MARK_DANGER = "!"

# Label column cap. Beyond this the help text starts at a silly indent and the
# whole point of the aligned column is lost, so deep labels overflow instead.
LABEL_CAP = 46


class _Opts:
    def __init__(self):
        self.flat = False
        self.depth = None
        self.root_only = False
        self.danger_only = False


def _fit(st, text, used):
    """Trim help to the remaining width — TTY only.

    One line per command is the whole value of this view: it stays scannable
    and greppable. Letting a long help string soft-wrap would re-flow it into
    the tree's branch characters and destroy the alignment. Through a pipe
    there is no width to fit, so the text is emitted whole.
    """
    if not st.width:
        return text
    room = st.width - used - 2
    if room < 12 or len(text) <= room:
        return text
    return text[:room - 1].rstrip() + ("\u2026" if not st.ascii else "...")


def _parse(tokens):
    o = _Opts()
    rest = []
    it = list(tokens)
    while it:
        t = it.pop(0)
        if t in ("--commands", "-c", "--flat"):
            o.flat = True
        elif t in ("--root", "-r"):
            o.root_only = True
        elif t in ("--danger", "-d"):
            o.danger_only = True
        elif t in ("--depth", "-L"):
            o.depth = int(it.pop(0)) if it and it[0].isdigit() else None
        elif t.startswith("--depth="):
            v = t.split("=", 1)[1]
            o.depth = int(v) if v.isdigit() else None
        elif t.startswith("-"):
            raise ValueError(t)
        else:
            rest.append(t)
    return o, rest


def _plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _descend(node):
    """Every descendant, self included."""
    yield node
    for child in node.children.values():
        for item in _descend(child):
            yield item


def _marks(node):
    m = ""
    if any(n.needs_root for n in _descend(node)):
        m += MARK_ROOT
    if any(n.danger for n in _descend(node)):
        m += MARK_DANGER
    return m


def _keep(node, opts):
    if opts.root_only and not any(n.needs_root for n in _descend(node)):
        return False
    if opts.danger_only and not any(n.danger for n in _descend(node)):
        return False
    return True


def _emit(node, opts, st, out, prefix="", depth=0):
    kids = [(n, c) for n, c in sorted(node.children.items()) if _keep(c, opts)]
    for i, (name, child) in enumerate(kids):
        last = (i == len(kids) - 1)
        mk = _marks(child)
        label = "%s%s%s%s" % (prefix, st.g["last"] if last else st.g["branch"],
                              name, (" " + mk) if mk else "")
        out.append((label, child.help, child))
        if child.children and (opts.depth is None or depth + 1 < opts.depth):
            _emit(child, opts, st, out,
                  prefix + (st.g["gap"] if last else st.g["pipe"]), depth + 1)


def _leaves(node, path, out):
    if node.run is not None and not node.children:
        out.append((path, node))
        return
    for name in sorted(node.children):
        _leaves(node.children[name], path + (name,), out)


def tree(ctx, tokens):
    from .tree import ROOT  # lazy: tree.py imports this module

    st = style_of(ctx)
    try:
        opts, rest = _parse(tokens)
    except ValueError as bad:
        r = Result("bad", "unknown option: %s" % bad, exit_code=EXIT_USAGE)
        r.lines("usage", [
            "satom show tree [<prefix>...] [--commands] [--depth N] "
            "[--root] [--danger]",
            "",
            "  --commands   flat list of runnable commands (grep- and doc-friendly)",
            "  --depth N    stop N levels down",
            "  --root       only branches that require root",
            "  --danger     only destructive commands",
        ])
        return r

    node, path = ROOT, []
    for t in rest:
        if t in node.children:
            node = node.children[t]
            path.append(t)
        else:
            r = Result("bad", "no such command: %s" % " ".join(rest),
                       exit_code=EXIT_USAGE)
            r.lines("available at '%s'" % (" ".join(path) or "satom"),
                    sorted(node.children) or ["(none)"])
            return r

    where = " ".join(["satom"] + path)
    every = list(_descend(node))
    groups = sum(1 for n in every if n.children)
    cmds = sum(1 for n in every if n.run is not None and not n.children)
    roots = sum(1 for n in every if n.needs_root)
    dangers = sum(1 for n in every if n.danger)

    r = Result("info", "%s — %s in %s" % (where, _plural(cmds, "command"),
                                         _plural(groups, "group")))
    r.set(path=path, commands=cmds, groups=groups,
          needs_root=roots, destructive=dangers,
          tree=_as_dict(node))

    if opts.flat:
        leaves = []
        _leaves(node, tuple(path), leaves)
        leaves = [(p, n) for p, n in leaves if _keep(n, opts)]
        width = min(LABEL_CAP, max([len(" ".join(p)) for p, _ in leaves] or [0]))
        body = []
        for p, n in leaves:
            mk = _marks(n)
            # Fixed columns, ALWAYS two spaces between them. --flat exists to
            # be cut/awk'd; on the widest row the padding is zero, so a single
            # separator space would fuse the path, the mark and the help into
            # one unsplittable field exactly for the longest command.
            lead = "satom %-*s  %-2s " % (width, " ".join(p), mk)
            body.append(lead + _fit(st, n.help, len(lead)))
        r.lines("", body or ["(nothing matches)"])
    else:
        out = []
        _emit(node, opts, st, out)
        if not out:
            r.lines("", ["(nothing matches)"])
        else:
            width = min(LABEL_CAP, max(len(lbl) for lbl, _, _ in out))
            body = []
            for lbl, help_text, _n in out:
                pad = lbl if len(lbl) >= width else "%-*s" % (width, lbl)
                body.append("%s  %s" % (
                    pad, st.c("dim", _fit(st, help_text, len(pad) + 4))))
            r.lines("", body)

    # A legend line for a mark that appears nowhere is noise, and noise in
    # a legend is how operators learn to skip legends.
    legend = []
    if roots:
        legend.append("%s requires root (%d)" % (MARK_ROOT, roots))
    if dangers:
        legend.append("%s destructive, needs --yes (%d)" % (MARK_DANGER, dangers))
    r.lines("legend", legend + ([""] if legend else []) + [
        "satom show tree <prefix>      just that branch, e.g.  show tree execute",
        "satom show tree --commands    flat list, one runnable command per line",
        "satom <any prefix> ?          help at that level",
    ])
    return r


def _as_dict(node):
    """Nested payload for --json: the registry as a machine can consume it."""
    d = {"help": node.help, "needs_root": node.needs_root,
         "destructive": node.danger, "runnable": node.run is not None}
    if node.usage:
        d["usage"] = node.usage
    if node.children:
        d["children"] = {n: _as_dict(c) for n, c in sorted(node.children.items())}
    return d
