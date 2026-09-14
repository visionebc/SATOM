"""Where the release-notes corpus lives, and how it is scoped to one product.

ONE author, on purpose. Two pages now read this corpus and they ask it different
questions: the Release-Notes page asks "which bugs change hands", the Upgrade
page asks Scout "will this target version ruin the window". A second copy of
"where the JSON is, and which rows belong to this product" would fail SILENTLY —
a loader pointed at the wrong directory renders exactly like a corpus that had
nothing to say, and only one of those is a finding. This repo has already paid
for that duplication twice (the sidebar blueprint lists, the status badge written
by two scripts); neither of those could brick an appliance.

The view helpers that used to live in :mod:`app.views.release_notes` now delegate
here, so the test isolation (never read/write the production ``data/``) and the
product filter are defined once.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import current_app

from . import release_notes as rn

#: The products whose release notes are harvested. A kind outside this set has
#: no corpus, which is NOT the same as a corpus that says nothing — callers must
#: say so rather than render an empty, reassuring panel.
SUPPORTED_PRODUCTS: tuple[str, ...] = ("fortiweb", "fortiadc")


def root() -> Path:
    """Where ``_release_notes.json`` lives.

    Production = the ``reports/`` dir, a symlink into the gitignored
    ``data/reports/`` — not version controlled, replicated to the standby by
    ``satom-ha-datasync``. Under tests it is isolated next to the throwaway
    SQLite DB so the suite never reads or writes the live corpus (same trick as
    the firmware repository)."""
    cfg = current_app.config.get("RELEASE_NOTES_DIR")
    if cfg:
        p = Path(cfg)
        p.mkdir(parents=True, exist_ok=True)
        return p
    if current_app.config.get("TESTING"):
        uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
        if uri.startswith("sqlite:///"):
            p = Path(os.path.dirname(uri[len("sqlite:///"):])) / "reports"
            p.mkdir(parents=True, exist_ok=True)
            return p
    return rn.reports_root()


def load(product: str) -> rn.ReleaseNotesDB:
    """The corpus SCOPED to ``product``.

    Issues and sections are filtered, and the version list is rebuilt from the
    surviving rows — never the flat cross-product ``db.versions`` — so a FortiADC
    reader never sees FortiWeb rows and vice-versa, even though both live in the
    one shared JSON, tagged per row."""
    db = rn.load_db(root=root()) or rn.ReleaseNotesDB(generated_at="")
    issues = [i for i in db.issues if i.product == product]
    sections = [s for s in db.sections if s.product == product]
    versions = sorted({i.version for i in issues} | {s.version for s in sections},
                      key=rn.version_key)
    return rn.ReleaseNotesDB(generated_at=db.generated_at, versions=versions,
                             issues=issues, sections=sections)


__all__ = ["SUPPORTED_PRODUCTS", "root", "load"]
