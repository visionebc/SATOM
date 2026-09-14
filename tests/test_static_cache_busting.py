"""Every app-owned script/stylesheet in base.html goes through `asset()`.

`SEND_FILE_MAX_AGE_DEFAULT` is 86400 and nothing revalidates inside that window,
so a bare `url_for('static', ...)` on a file we actually edit ships the change
to nobody for a day. That is not a slow rollout, it is a silent one: the operator
opens the page, sees the previous build and reports the fix as not deployed.
`release_notes.js` sat like that (found 2026-09-14, while shipping the version
picker); `asset()` appends `?v=<mtime>` and every other app-owned tag uses it.
"""
from __future__ import annotations

import re
from pathlib import Path

_BASE = Path("app/templates/base.html")

# Version-pinned vendor drops: their filename changes when the dependency does,
# which is the cache key. Named, so adding a third is a deliberate act.
_VENDORED = {"js/turbo.min.js"}


def _markup() -> str:
    src = (Path(__file__).resolve().parents[1] / _BASE).read_text(encoding="utf-8")
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    return re.sub(r"<!--.*?-->", "", src, flags=re.S)


def test_app_owned_scripts_are_cache_busted():
    raw = re.findall(r"url_for\('static',\s*filename='(js/[^']+)'\)", _markup())
    unbusted = sorted(set(raw) - _VENDORED)
    assert not unbusted, (
        "served behind a 24h cache with no cache key, so edits land invisible: "
        + ", ".join(unbusted))


def test_the_release_notes_modal_script_is_among_them():
    """The file this guard was written for — pinned by name so a future edit
    cannot quietly drop it back to a bare url_for."""
    mk = _markup()
    assert "asset('js/release_notes.js')" in mk
    assert "filename='js/release_notes.js'" not in mk
