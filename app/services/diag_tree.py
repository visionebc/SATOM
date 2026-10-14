"""Discover the ``diagnose`` commands a device's build really has, by asking it.

Why a walk and not a list. A curated battery written for one build breaks on the
next: on 2026-10-14 the desktop battery carried two commands that FortiWeb 7.6.8
and 8.0.6 answer with "you must specify cmd" / "The number of parameters is
incorrect." FortiGate and FortiAnalyzer print their ``diagnose`` tree inside
``tree``; FortiWeb, FortiADC and FortiAuthenticator do not. All five answer the
CLI's interactive help: type ``diagnose system ?`` and the shell lists the
children of ``diagnose system`` with one line of description each, then
re-types the line after the prompt. That is the one mechanism every product
shares, so it is the one used here.

How a node is asked (measured on fortiweb17, fortiadc10, faz02 and fac01):

* send ``<path> ?`` (no newline) and read until the shell re-types ``<path>``
  after its prompt (``#`` on four products, ``>`` on FortiAuthenticator);
* send Ctrl-U (``\\x15``) to erase the re-typed line — the next ``get system
  status`` on the same session came back clean on every product;
* NUL bytes the shells pad the redraw with are dropped before parsing.

What makes it safe:

* a node is classified by NAME and by the device's own DESCRIPTION
  (:func:`app.services.diag_policy.battery_reason`) BEFORE ``?`` is sent to it.
  On FortiWeb some leaves run when ``?`` is typed after them, so ``?`` on a
  blocked node is never sent: ``diagnose system kill ?`` would be the kill;
* if the prompt does not come back within ``node_timeout`` (a leaf that ran and
  does not stop), the walk sends Ctrl-C, erases the line, records the node as
  blocked ("did not return to the prompt") and goes on;
* a node budget and a wall-clock deadline bound the whole walk.

The parser (:func:`parse_help`) is pure and pinned against help captured from
all five products (``tests/fixtures/diag_help/lab_help.json``).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from typing import Callable

from .diag_policy import battery_reason

ROOT = "diagnose"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
# One help entry: optional indent, a name, then (two+ spaces) a description.
_ENTRY = re.compile(r"^\s*(\S+)(?:\s{2,}(.*?))?\s*$")
# What the shells answer for a path that is not a command on this build.
_ERROR = re.compile(
    r"parsing error|unknown action|command fail|command parse error|"
    r"invalid (?:input|command)|incomplete command|not (?:a )?valid|"
    r"no such command|unknown command", re.I)
# Argument placeholders: ``<signal>``, ``<Enter>``, ADC's ``arg``, and FortiGate's
# "[Take 0-11 arg(s)]" suffix in a description.
_PLACEHOLDER = re.compile(r"^<[^>]+>$")
_TAKES_ARGS = re.compile(r"\[take \d+(?:-\d+)? arg", re.I)
# Names a CLI can have. Anything else in a help listing is noise (a stray
# banner line, a wrapped description) and is never walked.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")


def clean(raw: str) -> str:
    """Strip ANSI, CR and the NUL padding the shells redraw with."""
    return _ANSI.sub("", raw or "").replace("\r", "").replace("\x00", "")


@dataclass
class Help:
    """What ``<path> ?`` answered."""
    children: list[tuple[str, str]] = field(default_factory=list)  # (name, desc)
    runnable: bool = False       # ``<Enter>`` listed: runs with no argument
    takes_args: bool = False     # an argument placeholder was listed
    arg_hint: str = ""           # e.g. ``<signal> Signal number.``
    error: str = ""              # the shell refused the path on this build
    executed: bool = False       # no listing at all: ``?`` ran the command
    sample: str = ""             # first lines of what it printed when it ran


def _strip_frame(lines: list[str], path: str) -> list[str]:
    """Drop the echoed ``<path> ?`` line and the re-typed prompt line."""
    out = list(lines)
    want = path.strip()
    while out and not out[0].strip():
        out.pop(0)
    if out and out[0].strip().rstrip("?").strip() == want:
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    if out and out[-1].rstrip().endswith(want):
        out.pop()
    return out


def parse_help(raw: str, path: str) -> Help:
    """Parse the answer to ``<path> ?``. Pure."""
    lines = _strip_frame(clean(raw).split("\n"), path)
    h = Help()
    body = [ln for ln in lines if ln.strip()]
    if not body:
        return h
    for ln in body:
        if _ERROR.search(ln):
            h.error = ln.strip()[:160]
            return h
    parsed: list[tuple[str, str]] = []
    for ln in body:
        m = _ENTRY.match(ln)
        if not m:
            continue
        name, desc = m.group(1), (m.group(2) or "").strip()
        if name.lower() == "<enter>":
            h.runnable = True
            continue
        if _PLACEHOLDER.match(name) or (name == "arg" and "argument" in desc.lower()):
            h.takes_args = True
            h.arg_hint = h.arg_hint or f"{name} {desc}".strip()
            continue
        if not _NAME.match(name):
            continue
        parsed.append((name, desc))
    # A help listing is a column of ``name  description`` rows. Output that
    # parsed into nothing recognisable is the command having RUN (FortiWeb runs
    # some leaves on ``?``): keep a sample, walk nothing below it.
    if not parsed and not h.runnable and not h.takes_args:
        h.executed = True
        h.sample = "\n".join(body[:6])[:400]
        return h
    h.children = parsed
    return h


@dataclass
class Node:
    path: str
    desc: str = ""
    branch: bool = False       # has children on this build
    runnable: bool = False     # may be sent as-is (``<Enter>`` or a leaf)
    takes_args: bool = False
    arg_hint: str = ""
    blocked: str = ""          # why a battery may not run it ('' = allowed)
    probed: bool = False       # ``?`` was sent to it
    note: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", False) or k == "path"}


class Walker:
    """Breadth-first walk of ``diagnose`` over one interactive SSH session.

    ``session`` is a connected :class:`app.services.ssh_ops.FortiWebReadonlySSH`
    (its ``ask_help`` method is the only thing used). ``on_progress(n, path)``
    is called after each probed node.
    """

    def __init__(self, session, *, budget: int = 6000, max_depth: int = 8,
                 deadline_s: float = 3600.0, node_timeout: float = 10.0,
                 on_progress: Callable[[int, str], None] | None = None):
        self.session = session
        self.budget = budget
        self.max_depth = max_depth
        self.deadline = time.monotonic() + deadline_s
        self.node_timeout = node_timeout
        self.on_progress = on_progress or (lambda _n, _p: None)
        self.nodes: dict[str, Node] = {}
        self.truncated = ""
        #: Set when the device closed the session while answering ``?`` for a
        #: node: that node is recorded as blocked and the walk stops with the
        #: rest of its queue in :attr:`pending`, for a new session to resume.
        self.lost_at = ""
        self.pending: list[tuple[str, str]] = []
        self.probed = 0

    def walk(self, roots: list[tuple[str, str]] | None = None) -> list[Node]:
        queue: list[tuple[str, str]] = list(roots or [(ROOT, "")])
        self.pending = []
        while queue:
            path, desc = queue.pop(0)
            node = self.nodes.setdefault(path, Node(path=path, desc=desc))
            if path != ROOT:
                reason = battery_reason(path, desc)
                if reason:
                    node.blocked = reason
                    continue
            if path.count(" ") >= self.max_depth:
                node.note = "deeper than the walk goes"
                continue
            if self.probed >= self.budget:
                self.truncated = f"node budget of {self.budget} reached"
                break
            if time.monotonic() > self.deadline:
                self.truncated = "time limit reached"
                break
            try:
                raw, returned = self.session.ask_help(path, timeout=self.node_timeout)
            except (OSError, EOFError) as exc:
                # The device dropped the session on this node (seen on
                # FortiWeb and FortiADC, 2026-10-14). Never ask it again.
                node.probed = True
                node.blocked = ("the device closed the SSH session when asked "
                                "for help on it (%s)" % (str(exc)[:60] or "closed"))
                self.lost_at = path
                self.pending = queue
                self.on_progress(self.probed, path)
                break
            self.probed += 1
            node.probed = True
            if not returned:
                node.blocked = ("did not return to the prompt after '?': it runs "
                                "until interrupted")
                self.on_progress(self.probed, path)
                continue
            h = parse_help(raw, path)
            if h.error:
                node.note = h.error
                node.runnable = False
            elif h.executed:
                node.runnable = True
                node.note = "ran when asked for help"
            else:
                node.runnable = h.runnable or not h.children
                node.takes_args = h.takes_args
                node.arg_hint = h.arg_hint
                node.branch = bool(h.children)
                for name, cdesc in h.children:
                    child = f"{path} {name}"
                    if child not in self.nodes:
                        self.nodes[child] = Node(path=child, desc=cdesc)
                        queue.append((child, cdesc))
            self.on_progress(self.probed, path)
        return list(self.nodes.values())


# ── presence of a battery command on a discovered build ───────────────────
PRESENT, ABSENT, UNKNOWN = "present", "absent", "unknown"


def presence(command: str, nodes: dict[str, dict]) -> tuple[str, str]:
    """``(state, detail)`` of ``command`` against one build's discovered nodes.

    ``present``: the walk reached it, or it is a node that takes arguments
    followed by arguments. ``absent``: the deepest probed ancestor lists its
    children and the next word is not among them. ``unknown``: the walk never
    probed far enough to say (blocked ancestor, budget) — the command is then
    run and its own answer decides.
    """
    toks = (command or "").split()
    if not toks:
        return UNKNOWN, ""
    if toks[0].lower() in ("diag",):
        toks[0] = "diagnose"
    if toks[0] != ROOT:
        return UNKNOWN, "not a diagnose command"
    for i in range(len(toks), 0, -1):
        path = " ".join(toks[:i])
        n = nodes.get(path)
        if n is None:
            continue
        if i == len(toks):
            return PRESENT, ""
        if n.get("takes_args"):
            return PRESENT, "arguments to " + path
        if n.get("probed") and n.get("branch"):
            return ABSENT, f"'{toks[i]}' is not under '{path}' on this build"
        return UNKNOWN, ""
    return UNKNOWN, ""


__all__ = ["ROOT", "clean", "Help", "parse_help", "Node", "Walker",
           "presence", "PRESENT", "ABSENT", "UNKNOWN"]
