#!/usr/bin/env python3
"""Regenerate the command reference inside ``docs/cli.md`` from the LIVE registry.

WHY THIS EXISTS
---------------
``deploy/satom_cli/tree.py`` is the single source of truth for what the operator
console can do — the parser, ``?``, tab completion, the privilege gate and
``show tree`` all read it. A reference table typed by hand is a *copy* of that
structure, and copies rot: the fifth command someone adds will not be in the
manual, and the operator who most needs the manual is the one whose web UI is
down and who cannot check.

So the table is generated, and ``tests/test_docs_publication.py`` fails the suite
when ``docs/cli.md`` no longer matches the registry. Adding a command therefore
stays what it was designed to be — ONE entry in ``tree.py`` — plus running::

    python3 deploy/gen_cli_reference.py

Only the text between the two markers is touched; every hand-written section of
``docs/cli.md`` (the rationale, the sudo rule, the extension contract) is left
exactly as it is. Documentation that explains *why* is written by a human;
documentation that enumerates *what* is derived from the code.

Stdlib only, and no Flask — same rule as the CLI itself, so this runs on a node
whose venv is broken.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "deploy"))

from satom_cli import tree as cli_tree  # noqa: E402

DOC = ROOT_DIR / "docs" / "cli.md"
BEGIN = "<!-- BEGIN GENERATED COMMAND REFERENCE -->"
END = "<!-- END GENERATED COMMAND REFERENCE -->"

# Blurbs for the top-level verbs. The registry stores one-liners per node; the
# verb-level framing is editorial and belongs here, next to the renderer.
VERB_LEAD = {
    "get": "Read state. Every command below works as **any user** — this is the half "
           "of the console that has to keep working when everything else does not.",
    "show": "Configuration, reference material and the console's own map. Also "
            "unprivileged: `show sudoers` prints the rule you need *before* you have it.",
    "diagnose": "Active probes that reach out — sockets, database handshakes, "
                "compilers, peers. Unprivileged, but they take longer than `get`.",
    "execute": "Everything that changes state. **Root required.** Without it each "
               "command refuses with the full command line you tried and exit code 3, "
               "never a traceback.",
}


def _cell(text: str) -> str:
    """Table-safe cell: pipes would break the Markdown row."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def commands():
    """(path, node) for every runnable leaf, in registry order."""
    for path, node in cli_tree.walk():
        if node.run is not None:
            yield path, node


def groups():
    """(path, node) for every node that only groups other nodes."""
    for path, node in cli_tree.walk():
        if node.run is None and path:
            yield path, node


def render() -> str:
    cmds = list(commands())
    n_groups = len(list(groups()))
    by_verb: dict[str, list] = {}
    for path, node in cmds:
        by_verb.setdefault(path[0], []).append((path, node))

    out: list[str] = []
    out.append(BEGIN)
    out.append("")
    out.append(
        f"*{len(cmds)} commands in {n_groups} groups. This table is generated from "
        "`deploy/satom_cli/tree.py` by `deploy/gen_cli_reference.py` — it cannot "
        "drift from the console you are running. `!` marks a command that changes "
        "state destructively and demands `--yes`.*"
    )
    out.append("")

    for verb, items in by_verb.items():
        out.append(f"### `{verb}`")
        out.append("")
        lead = VERB_LEAD.get(verb)
        if lead:
            out.append(lead)
            out.append("")
        out.append("| Command | Root | ! | What it does |")
        out.append("|---|:--:|:--:|---|")
        for path, node in items:
            usage = node.usage or "satom " + " ".join(path)
            if not usage.startswith("satom "):
                usage = "satom " + usage
            out.append(
                "| `{}` | {} | {} | {} |".format(
                    _cell(usage),
                    "yes" if node.needs_root else "—",
                    "!" if node.danger else "—",
                    _cell(node.help),
                )
            )
        out.append("")

    out.append(END)
    return "\n".join(out)


def current_block(text: str) -> str | None:
    if BEGIN not in text or END not in text:
        return None
    head, _, rest = text.partition(BEGIN)
    body, _, _tail = rest.partition(END)
    return BEGIN + body + END


def apply(text: str, block: str) -> str:
    head, _, rest = text.partition(BEGIN)
    _body, _, tail = rest.partition(END)
    return head + block + tail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if docs/cli.md is stale; write nothing")
    args = ap.parse_args()

    text = DOC.read_text(encoding="utf-8")
    want = render()
    have = current_block(text)

    if have is None:
        print(f"error: markers not found in {DOC}", file=sys.stderr)
        print(f"       add {BEGIN} / {END} where the table should go", file=sys.stderr)
        return 2

    if have.strip() == want.strip():
        print(f"docs/cli.md is current ({len(list(commands()))} commands)")
        return 0

    if args.check:
        print("docs/cli.md is STALE — run: python3 deploy/gen_cli_reference.py",
              file=sys.stderr)
        return 1

    DOC.write_text(apply(text, want), encoding="utf-8")
    print(f"docs/cli.md regenerated ({len(list(commands()))} commands)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
