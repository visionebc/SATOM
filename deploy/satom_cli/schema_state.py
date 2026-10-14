"""Where the database schema stands against the migrations on disk.

Why this exists. Only the self-update runner and the container entrypoint ran
``flask db upgrade``. The deploy every session actually uses -- ``git pull``
then ``satom execute restart-all`` -- never did: boot-time ``create_all()`` +
``_ensure_columns()`` add the new tables and columns, so nothing broke, and
a1's ``alembic_version`` sat at ``sigidx01`` while four revisions (sshpw01,
tplbind01, netarch01, diagbat01) shipped on top of it (found 2026-10-14).
Additive revisions survive that; the first one that TRANSFORMS data would
have been skipped in silence.

So ``restart-all`` now migrates on the primary before the web restarts, and
``get system health`` says when the schema is behind head.

The head is read from ``migrations/versions/*.py`` (revision/down_revision),
not from ``flask db heads``: that imports the whole app, and the health roll-up
must stay cheap. The current revision is one ``SELECT`` with the app's own
database credentials (``ctx.psql``).
"""
from __future__ import annotations

import re
from pathlib import Path

_REV = re.compile(r"^revision\s*=\s*['\"]([^'\"]+)['\"]", re.M)
_DOWN = re.compile(r"^down_revision\s*=\s*(.+)$", re.M)
_ID = re.compile(r"['\"]([^'\"]+)['\"]")


def graph(app_dir) -> dict[str, tuple[str, ...]]:
    """``{revision: (down_revision, ...)}`` read from the migration files."""
    out: dict[str, tuple[str, ...]] = {}
    for f in sorted((Path(app_dir) / "migrations" / "versions").glob("*.py")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _REV.search(text)
        if not m:
            continue
        d = _DOWN.search(text)
        out[m.group(1)] = tuple(_ID.findall(d.group(1))) if d else ()
    return out


def heads(app_dir) -> list[str]:
    g = graph(app_dir)
    parents = {p for ps in g.values() for p in ps}
    return sorted(r for r in g if r not in parents)


def behind(app_dir, current: str | None) -> int | None:
    """How many revisions lie between ``current`` and the (single) head.

    None when it cannot be said: several heads, or ``current`` not in the tree
    (a database newer than the code, or a foreign revision).
    """
    hs = heads(app_dir)
    if len(hs) != 1:
        return None
    g = graph(app_dir)
    n, rev = 0, hs[0]
    while rev != current:
        ps = g.get(rev)
        if ps is None:
            return None
        if not ps:
            # reached the root: with no version at all, every revision is due
            return None if current else n + 1
        if len(ps) != 1:
            return None
        rev, n = ps[0], n + 1
    return n


def current(ctx) -> tuple[str | None, str]:
    """``(revision or None, error)`` from ``alembic_version``."""
    rc, out, err = ctx.psql("SELECT version_num FROM alembic_version;")
    if rc != 0:
        return None, (err or out or "query failed").strip()[:200]
    rev = (out or "").strip().splitlines()
    return (rev[0].strip() if rev else None), ""


__all__ = ["graph", "heads", "behind", "current"]
