"""Guardias del modo de ``.git/config``.

Por que existe: el remote de este repo lleva el token de push EMBEBIDO en la
URL, y git escribe ese fichero en 644. La credencial que autentica cada push
queda legible por cualquier cuenta de la maquina — y nada falla, que es
exactamente por lo que sobrevivio hasta que alguien miro el ``ls -l``.

git no tiene ajuste para esto: el modo hay que re-afirmarlo desde el codigo que
escribe el fichero, y desde el que se lo encuentra ya escrito (un repo clonado
por el instalador nunca pasa por el escritor).
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
    """640 tampoco vale: el grupo del servicio no es el dueno del token."""
    root, cfg = _repo(tmp_path, 0o640)
    gs._harden_git_config(root)
    assert _mode(cfg) == 0o600


def test_an_already_private_config_is_left_alone(tmp_path):
    root, cfg = _repo(tmp_path, 0o600)
    gs._harden_git_config(root)
    assert _mode(cfg) == 0o600


def test_a_missing_repository_is_not_an_error(tmp_path):
    gs._harden_git_config(tmp_path / "no-existe")   # no debe levantar


def test_the_contents_are_not_touched(tmp_path):
    root, cfg = _repo(tmp_path, 0o644)
    before = cfg.read_text()
    gs._harden_git_config(root)
    assert cfg.read_text() == before


def test_configure_hardens_after_writing_the_remote(tmp_path, monkeypatch):
    """El escritor: ``remote set-url`` acaba de meter el token en el fichero."""
    root, cfg = _repo(tmp_path, 0o644)
    monkeypatch.setattr(gs, "_repo_root", lambda: root)
    monkeypatch.setattr(gs, "_run_git", lambda *a, **k: 0)
    monkeypatch.setattr(gs, "_git_out", lambda *a, **k: "main")
    gs.git_configure("https://git.test/x.git", "tok3n", "")
    assert _mode(cfg) == 0o600


def test_git_info_hardens_a_repo_it_did_not_write(tmp_path, monkeypatch):
    """El instalador clona con la URL con token y nunca pasa por el escritor."""
    root, cfg = _repo(tmp_path, 0o644)
    monkeypatch.setattr(gs, "_repo_root", lambda: root)
    monkeypatch.setattr(gs, "_git_out", lambda *a, **k: "—")
    monkeypatch.setattr(gs, "_git_try", lambda *a, **k: (False, ""))
    gs.git_info()
    assert _mode(cfg) == 0o600


def test_the_installer_narrows_the_config_it_clones():
    """El defecto es del PRODUCTO: cada instalacion nueva lo reintroduce."""
    src = Path(gs.__file__).resolve().parents[2] / "installers" / "install-satom.sh"
    body = src.read_text()
    assert 'git clone --depth 1 --branch main "$GIT_URL"' in body
    clone_at = body.index('git clone --depth 1 --branch main "$GIT_URL"')
    tail = body[clone_at:clone_at + 400]
    assert 'chmod 600 "$APP_DIR/.git/config"' in tail
