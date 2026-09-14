"""Guards for the Release-Notes modal after git was taken out of it (2026-09-14).

Why this file exists, in the order the defects were found:

1. The two git controls ("⤓ Sync from git" / "Publish to git") **could not work**.
   ``reports/`` is a symlink into the gitignored ``data/reports/``; git refuses a
   path under it outright (``fatal: pathspec ... is beyond a symbolic link``).
   True since the git SoT was retired on 2026-08-05 — every scan since then
   logged "(git publish reported an issue — corpus saved locally)".
2. Worse, and invisible: ``POST /release-notes/sync`` ran ``git pull`` over the
   **running code tree** for anyone holding ``VIEW``. The identical operation is
   gated behind ``USER_MANAGE`` in ``settings.git_pull``, and belongs to
   ``satom-reconciler``. That is a privilege gap, not a dead button.
3. Its success message was false either way: ``_load`` re-reads the JSON on every
   request, so "Ingested N … from the shared reference" always described the
   local file.

Nothing here asserts on prose that mentions git — the replacement's own docstring
explains the removal, so a substring guard would match its own explanation (the
recurring trap in this repo). The behavioural guards **sabotage** ``git_service``
and drive the routes; the static one walks the **AST**, where comments and
docstrings do not exist.
"""
from __future__ import annotations

import ast
import re
import time
from pathlib import Path

from app.services import release_notes as rn
from tests.conftest import login, make_user, profile_id
from tests.test_release_notes import _fake_fetch

_VIEW = Path("app/views/release_notes.py")
_TPL = Path("app/templates/partials/release_notes_modal.html")
_JS = Path("app/static/js/release_notes.js")


def _src(rel: Path) -> str:
    return (Path(__file__).resolve().parents[1] / rel).read_text(encoding="utf-8")


def _markup(rel: Path) -> str:
    """The template with its comments stripped — i.e. what the browser gets.

    The guards below forbid the names of the dead controls, and the comment
    that explains WHY they are dead has to name them. Asserting over the raw
    source makes the explanation fail the guard (it did, first run). What is
    actually forbidden is a control, and a comment is not one."""
    src = _src(rel)
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)      # Jinja
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)      # HTML
    return src


def _code(rel: Path) -> str:
    """JS with comments stripped, for the same reason."""
    src = _src(rel)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"^\s*//.*$", "", src, flags=re.M)
    return src


def _admin(app):
    return make_user(app, "ngadmin", role="admin", profile_id=profile_id(app, "admin"))


def _viewer(app):
    return make_user(app, "ngview", role="readonly", profile_id=profile_id(app, "readonly"))


def _seed(app, db):
    from app.views.release_notes import _corpus_root
    with app.app_context():
        rn.save_db(db, root=_corpus_root())


def _sabotage_git(monkeypatch):
    """Make ANY use of the git helpers an immediate, named failure.

    The view imports them lazily inside the function body, so patching the
    module attribute is what a re-introduced ``from ..services.git_service
    import git_pull`` would pick up. This is the guard that drives the code
    instead of reading it."""
    from app.services import git_service

    def _boom(*a, **k):  # noqa: ANN002, ANN003
        raise AssertionError("release_notes must not call git_service")

    monkeypatch.setattr(git_service, "git_pull", _boom)
    monkeypatch.setattr(git_service, "git_publish", _boom)


def _wait_scan(client, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = client.get("/release-notes/scan/status").get_json()
        if not st.get("running"):
            return st
        time.sleep(0.1)
    raise AssertionError("scan never finished")


# --------------------------------------------------------------------------- #
#  The route itself                                                            #
# --------------------------------------------------------------------------- #
def test_sync_route_is_gone(app, client):
    """The old URL must not answer. A bookmark, a stale cached JS bundle or a
    curl against ``/sync`` would otherwise still fire ``git pull`` on the code
    tree — hiding a button never disabled its endpoint."""
    login(client, _viewer(app))
    assert client.post("/release-notes/sync").status_code == 404


def test_reload_works_with_git_sabotaged(app, client, monkeypatch):
    _seed(app, rn.scan_release_notes(_fake_fetch, ["8.0.5"]))
    _sabotage_git(monkeypatch)
    login(client, _viewer(app))
    r = client.post("/release-notes/reload")
    assert r.status_code == 200
    d = r.get_json()
    assert d["counts"]["issues"] == 3


def test_reload_reports_where_and_how_old(app, client):
    db = rn.scan_release_notes(_fake_fetch, ["8.0.5"])
    _seed(app, db)
    login(client, _viewer(app))
    d = client.post("/release-notes/reload").get_json()
    # where: the actual file it read, not a label
    assert d["source"].endswith(rn.DB_NAME)
    assert Path(d["source"]).exists()
    # how old: the corpus timestamp, echoed in the message the operator sees
    assert d["generated_at"] == db.generated_at
    assert d["generated_at"] and d["generated_at"] in d["message"]
    assert "3" in d["message"]


def test_reload_on_empty_corpus_says_scan_here_not_sync(app, client):
    """An empty corpus used to be reported as "No release-notes reference found
    in git yet" — which sent the operator looking for a remote that never had
    it. The instruction has to be the one that works: scan, on this node."""
    login(client, _viewer(app))
    d = client.post("/release-notes/reload").get_json()
    assert d["counts"]["issues"] == 0
    assert "scan" in d["message"].lower()
    assert "node" in d["message"].lower()


def test_reload_requires_login(app, client):
    r = client.post("/release-notes/reload")
    assert r.status_code != 200


def test_scan_ignores_a_legacy_publish_flag(app, client, monkeypatch):
    """A cached JS bundle may still post ``publish: true``. That must neither
    publish (impossible) nor fail the scan (an outage in exchange for a dead
    flag). It must simply be ignored."""
    monkeypatch.setattr(rn, "make_fetcher", lambda **k: _fake_fetch)
    monkeypatch.setattr(rn, "discover_versions", lambda fetch, **k: ["8.0.5"])
    _sabotage_git(monkeypatch)
    login(client, _admin(app))
    r = client.post("/release-notes/scan",
                    json={"all": True, "use_direct": True, "publish": True})
    assert r.status_code == 202
    st = _wait_scan(client)
    assert st.get("error") is None, st.get("error")
    assert st["result"]["scanned"] == 1
    # and the result no longer carries a publication verdict at all
    assert "published" not in st["result"]


# --------------------------------------------------------------------------- #
#  Static guards — AST and markup, never prose                                  #
# --------------------------------------------------------------------------- #
def test_view_module_contains_no_git_calls():
    """Walk the AST: comments and docstrings do not survive parsing, so this
    cannot be satisfied (or broken) by the explanation of why git is gone."""
    tree = ast.parse(_src(_VIEW))
    banned = {"git_pull", "git_publish", "git_service"}
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in banned:
            hits.append(f"name:{node.id}:{node.lineno}")
        elif isinstance(node, ast.Attribute) and node.attr in banned:
            hits.append(f"attr:{node.attr}:{node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if "git_service" in mod:
                hits.append(f"import:{mod}:{node.lineno}")
            for alias in node.names:
                if alias.name in banned:
                    hits.append(f"import:{alias.name}:{node.lineno}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if "git_service" in alias.name:
                    hits.append(f"import:{alias.name}:{node.lineno}")
    assert not hits, f"release_notes view reaches for git again: {hits}"


def test_modal_has_no_git_controls_and_has_the_reload_button():
    tpl = _markup(_TPL)
    for dead in ("Sync from git", "Publish to git", "rnSyncBtn", "rnPublish"):
        assert dead not in tpl, f"{dead!r} is still in the modal"
    assert 'id="rnReloadBtn"' in tpl


def test_js_posts_reload_and_not_sync():
    js = _code(_JS)
    assert "/reload" in js
    assert "/sync" not in js
    assert "rnPublish" not in js


def test_every_js_element_id_exists_somewhere():
    """Rename-in-one-place guard.

    ``$('rnSyncBtn')`` returning null throws inside the click handler and the
    button does nothing — silently. Every id the JS looks up must either be in
    the modal template or be built by the JS itself (the Scout enable button
    is)."""
    js = _code(_JS)
    tpl = _markup(_TPL)
    looked_up = set(re.findall(r"\$\('(rn[A-Za-z0-9_]+)'\)", js))
    assert "rnReloadBtn" in looked_up, "the reload button is not wired at all"
    built_by_js = set(re.findall(r'id="(rn[A-Za-z0-9_]+)"', js))
    missing = sorted(i for i in looked_up
                     if f'id="{i}"' not in tpl and i not in built_by_js)
    assert not missing, f"JS looks up ids that nothing creates: {missing}"
