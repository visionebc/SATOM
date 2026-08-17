"""Resolve every ``url_for()`` endpoint written in the Jinja templates against
the application's real ``url_map``.

WHY THIS EXISTS (2026-08-17). The standby node served HTTP 500 on every
authenticated page for ~15 hours while *every* verification the updater ran
reported success:

* ``import app`` succeeded — it imports the new code in a NEW interpreter, so
  it is green precisely when the running workers are stale.
* ``GET /healthz`` returned 200 — it renders no template, so a template that
  references an endpoint the process never registered is invisible to it.

The actual failure was ``base.html`` calling ``url_for('bookmarks.panel')``
against a process whose ``url_map`` predated the ``bookmarks`` blueprint:
a ``BuildError``, i.e. HTTP 500, on every page that extends the base layout.

Nothing *fails* when a template names an endpoint that does not exist. The
template renders fine until the branch that contains it is reached, and then it
raises at request time, in production, for a user. This module turns that into
a check that can run before anyone is served.

SCOPE, stated so it is not mistaken for more than it is: this reads TEMPLATES.
A ``url_for`` written in Python is not covered (those raise on the code path
that runs them, which the test-suite exercises). Endpoints built from a
variable cannot be resolved statically and are reported separately as
``dynamic`` — counted, never silently dropped.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# A literal first argument: url_for('bp.view'  /  url_for("static"
_LITERAL_RE = re.compile(r"""url_for\(\s*(['"])([A-Za-z0-9_.]+)\1""")
# Anything else in the first position: url_for(var), url_for(request...)
_DYNAMIC_RE = re.compile(r"""url_for\(\s*(?!['"])""")
# Jinja comments are never evaluated, so an endpoint named inside one is not a
# reference. HTML comments ARE evaluated by Jinja and are deliberately kept.
_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[1] / "templates"


def _strip_jinja_comments(text: str) -> str:
    """Blank out {# ... #} while preserving line numbering."""
    def _blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    return _JINJA_COMMENT_RE.sub(_blank, text)


def scan_template_endpoints(root=None):
    """Return (refs, dynamic, template_count).

    ``refs`` is a list of (template_relpath, lineno, endpoint) for every
    literal endpoint named in a template. ``dynamic`` is the same shape minus
    the endpoint, for calls whose first argument is an expression.
    """
    root = Path(root) if root else _default_root()
    refs, dynamic, count = [], [], 0
    for path in sorted(root.rglob("*.html")):
        count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = _strip_jinja_comments(text)
        rel = str(path.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in _LITERAL_RE.finditer(line):
                refs.append((rel, lineno, m.group(2)))
            for _ in _DYNAMIC_RE.finditer(line):
                dynamic.append((rel, lineno))
    return refs, dynamic, count


def audit_template_endpoints(app, root=None):
    """Resolve the scanned endpoints against ``app.url_map``.

    Returns a dict with ``missing`` (the findings), ``relative`` (``url_for('.x')``
    forms, which depend on the rendering blueprint and are not resolvable
    statically), ``dynamic``, ``checked`` and ``templates``.
    """
    refs, dynamic, templates = scan_template_endpoints(root)
    known = {rule.endpoint for rule in app.url_map.iter_rules()}
    missing, relative = [], []
    for rel, lineno, endpoint in refs:
        if endpoint.startswith("."):
            relative.append({"template": rel, "line": lineno, "endpoint": endpoint})
        elif endpoint not in known:
            missing.append({"template": rel, "line": lineno, "endpoint": endpoint})
    return {
        "missing": missing,
        "relative": relative,
        "dynamic": [{"template": r, "line": n} for r, n in dynamic],
        "checked": len(refs),
        "templates": templates,
        "endpoints": len(known),
    }


def format_report(result) -> str:
    lines = ["templates=%d url_for=%d endpoints=%d missing=%d dynamic=%d" % (
        result["templates"], result["checked"], result["endpoints"],
        len(result["missing"]), len(result["dynamic"]))]
    for m in result["missing"]:
        lines.append("  MISSING %s -> %s:%d" % (m["endpoint"], m["template"], m["line"]))
    return "\n".join(lines)


def _load_env_file(path):
    """Mirror systemd's ``EnvironmentFile=`` so a standalone run sees the same
    configuration as the unit.

    Without this, ``create_app()`` from a bare script silently falls back to the
    default SQLite URI and dies with 'unable to open database file' — a failure
    that says nothing about the code being checked.
    """
    try:
        for raw in Path(path).read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)
    except OSError:
        pass


#: exit codes -- 'could not check' is NOT 'checked and clean'. A caller that
#: collapses the two would gate an update on a check that never ran.
EXIT_OK = 0
EXIT_MISSING = 1
EXIT_UNMEASURED = 3


def main(argv=None):
    app_dir = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
    cwd = os.getcwd()
    try:
        _load_env_file(app_dir / ".env")
        os.chdir(str(app_dir))
        from app import create_app  # imported late: needs the env above
        app = create_app()
    except Exception as exc:  # noqa: BLE001
        print("unmeasured: could not build the app: %s: %s"
              % (type(exc).__name__, exc))
        return EXIT_UNMEASURED
    finally:
        # Leave the caller's working directory alone; this runs inside the
        # test process too.
        os.chdir(cwd)
    result = audit_template_endpoints(app)
    print(format_report(result))
    return EXIT_MISSING if result["missing"] else EXIT_OK


if __name__ == "__main__":  # pragma: no cover - operational entrypoint
    raise SystemExit(main())
