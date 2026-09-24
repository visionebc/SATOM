"""Guards for the mode of ``.git/config``.

Why this exists: this repo's remote carries the push token EMBEDDED in the
URL, and git writes that file as 644. The credential that authenticates every
push ends up readable by any account on the machine — and nothing fails, which
is exactly why it survived until someone looked at the ``ls -l``.

git has no setting for this: the mode has to be re-asserted from the code that
writes the file, and from the code that finds it already written (a repo cloned
by the installer never goes through the writer).
"""
from pathlib import Path

from app.services import git_service as gs


def _repo(tmp_path, mode=0o644, body="[remote \"origin\"]\n\turl = https://tok@git/x.git\n"):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    cfg = root / ".git" / "config"
    cfg.write_text(body)
    cfg.chmod(mode)
    return root, cfg


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_a_world_readable_config_is_narrowed(tmp_path):
    root, cfg = _repo(tmp_path, 0o644)
    gs._harden_git_config(root)
    assert _mode(cfg) == 0o600


def test_a_group_readable_config_is_narrowed(tmp_path):
    """640 is not good enough either: the service group does not own the token."""
    root, cfg = _repo(tmp_path, 0o640)
    gs._harden_git_config(root)
    assert _mode(cfg) == 0o600


def test_an_already_private_config_is_left_alone(tmp_path):
    root, cfg = _repo(tmp_path, 0o600)
    gs._harden_git_config(root)
    assert _mode(cfg) == 0o600


def test_a_missing_repository_is_not_an_error(tmp_path):
    gs._harden_git_config(tmp_path / "does-not-exist")   # must not raise


def test_the_contents_are_not_touched(tmp_path):
    root, cfg = _repo(tmp_path, 0o644)
    before = cfg.read_text()
    gs._harden_git_config(root)
    assert cfg.read_text() == before


def test_configure_hardens_after_writing_the_remote(tmp_path, monkeypatch):
    """The writer: ``remote set-url`` has just put the token into the file."""
    root, cfg = _repo(tmp_path, 0o644)
    monkeypatch.setattr(gs, "_repo_root", lambda: root)
    monkeypatch.setattr(gs, "_run_git", lambda *a, **k: 0)
    monkeypatch.setattr(gs, "_git_out", lambda *a, **k: "main")
    gs.git_configure("https://git.test/x.git", "tok3n", "")
    assert _mode(cfg) == 0o600


def test_git_info_hardens_a_repo_it_did_not_write(tmp_path, monkeypatch):
    """The installer clones with the token URL and never goes through the writer."""
    root, cfg = _repo(tmp_path, 0o644)
    monkeypatch.setattr(gs, "_repo_root", lambda: root)
    monkeypatch.setattr(gs, "_git_out", lambda *a, **k: "—")
    monkeypatch.setattr(gs, "_git_try", lambda *a, **k: (False, ""))
    gs.git_info()
    assert _mode(cfg) == 0o600


def test_the_installer_narrows_the_config_it_clones():
    """The defect is in the PRODUCT: every new installation reintroduces it."""
    src = Path(gs.__file__).resolve().parents[2] / "installers" / "install-satom.sh"
    body = src.read_text()
    assert 'git clone --depth 1 --branch main "$GIT_URL"' in body
    clone_at = body.index('git clone --depth 1 --branch main "$GIT_URL"')
    tail = body[clone_at:clone_at + 400]
    assert 'chmod 600 "$APP_DIR/.git/config"' in tail
