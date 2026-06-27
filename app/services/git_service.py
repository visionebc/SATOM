"""Git service — read repo state, pull, publish reports, run manual commands.

Ported from the desktop app's ``services/inspector.py`` git helpers.
Scoped to the web-app root (the directory containing ``wsgi.py``).
"""
from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path


# ── helpers ──────────────────────────────────────────────────────────────────

def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent  # app/services → app → root


def _git_out(root: Path, *args: str, default: str = "") -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return default
    return (r.stdout or "").strip() if r.returncode == 0 else default


def _run_git(root: Path, args: tuple, lines: list, redact: tuple = ()) -> int:
    def scrub(t: str) -> str:
        for s in redact:
            if s:
                t = t.replace(s, "***")
        return t

    try:
        r = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=120,
        )
    except Exception as e:
        lines.append(scrub(f"$ git {' '.join(str(a) for a in args)}\n[error: {e}]"))
        return 1
    body = "\n".join(p for p in ((r.stdout or "").strip(), (r.stderr or "").strip()) if p)
    lines.append(scrub(f"$ git {' '.join(str(a) for a in args)}\n{body}").rstrip())
    return r.returncode


def _redact_remote(url: str) -> str:
    """Remove credentials embedded in an HTTP remote URL."""
    return re.sub(r'(https?://)([^@]+@)', r'\1', url)


def _authed_remote(clean: str, token: str) -> str | None:
    m = re.match(r'(https?://)(.*)', clean)
    if not m:
        return None
    return f"{m.group(1)}{token}@{m.group(2)}"


def _git_token() -> str:
    """Extract the token from the current origin remote URL (if embedded)."""
    root = _repo_root()
    raw = _git_out(root, "remote", "get-url", "origin")
    m = re.match(r'https?://([^@/]+)@', raw)
    return m.group(1) if m else ""


# ── public API ────────────────────────────────────────────────────────────────

def git_info() -> dict:
    """Snapshot of the repo for the Settings → Git tab."""
    root = _repo_root()

    def out(*args, default="—") -> str:
        return _git_out(root, *args, default=default)

    raw_remote = out("remote", "get-url", "origin", default="")
    remote = _redact_remote(raw_remote)
    branch = out("rev-parse", "--abbrev-ref", "HEAD")
    commit = out("log", "-1", "--format=%h %cs %s")
    dirty_raw = out("status", "--porcelain", default="")
    dirty = bool(dirty_raw.strip())
    ahead_behind = out("rev-list", "--left-right", "--count", "@{upstream}...HEAD", default="")
    ahead = behind = 0
    if ahead_behind and "\t" in ahead_behind:
        b, a = ahead_behind.split("\t", 1)
        try:
            behind, ahead = int(b), int(a)
        except ValueError:
            pass
    recent = []
    log_raw = out("log", "-8", "--format=%h|%cs|%s", default="")
    for line in log_raw.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            recent.append({"hash": parts[0], "date": parts[1], "subject": parts[2]})

    return {
        "remote": remote or "—",
        "branch": branch,
        "commit": commit,
        "dirty": dirty,
        "ahead": ahead,
        "behind": behind,
        "recent": recent,
        "root": str(root),
    }


def git_pull() -> str:
    """Pull latest from origin (ff-only)."""
    root = _repo_root()
    token = _git_token()
    clean = _redact_remote(_git_out(root, "remote", "get-url", "origin"))
    lines: list[str] = []

    if token and clean:
        authed = _authed_remote(clean, token)
        if authed:
            branch = _git_out(root, "rev-parse", "--abbrev-ref", "HEAD") or "HEAD"
            _run_git(root, ("pull", "--ff-only", authed, branch), lines, (token,))
        else:
            _run_git(root, ("pull", "--ff-only"), lines)
    else:
        _run_git(root, ("pull", "--ff-only"), lines)
    return "\n\n".join(lines)


def run_git_script(script: str) -> str:
    """Run an operator-typed block of git commands (git-only escape hatch)."""
    root = _repo_root()
    token = _git_token()
    redact = (token,) if token else ()
    lines: list[str] = []
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            args = shlex.split(line)
        except ValueError as e:
            lines.append(f"$ {line}\n[parse error: {e}]")
            continue
        if args and args[0] == "git":
            args = args[1:]
        if not args:
            continue
        _run_git(root, tuple(args), lines, redact)
    return "\n\n".join(lines)


def git_configure(remote_url: str, token: str, branch: str) -> str:
    """Update remote URL (with optional embedded token) and/or switch branch."""
    root = _repo_root()
    lines: list[str] = []

    # Build final remote URL
    if token and remote_url:
        m = re.match(r"(https?://)(.*)", remote_url)
        if m:
            final_url = f"{m.group(1)}{token}@{m.group(2)}"
        else:
            final_url = remote_url
    else:
        final_url = remote_url

    if final_url:
        _run_git(root, ("remote", "set-url", "origin", final_url), lines, (token,) if token else ())
    if branch:
        current = _git_out(root, "rev-parse", "--abbrev-ref", "HEAD")
        if current != branch:
            _run_git(root, ("checkout", "-B", branch, f"origin/{branch}"), lines)
        else:
            lines.append(f"# branch is already {branch!r}")
    return "\n\n".join(lines)
