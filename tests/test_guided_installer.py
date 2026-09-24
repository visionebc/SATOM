"""Guards for the 2.1.2 install fixes and the guided installer.

v2.1.1 as published installed nowhere, and the guided installer that first
shipped outside the product got it running with WORKAROUNDS: it seeded the
site publication rules behind install-satom.sh's back and "repaired" network
literals in the downloaded code. Those defects are fixed in the product now,
and each fix below is asserted by BEHAVIOUR where it can be -- the function is
extracted from the shipped script and run -- because a grep for the name of a
fix passes just as well against the comment that explains it.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLERS = ROOT / "installers"
INSTALL_SATOM = INSTALLERS / "install-satom.sh"
SETUP = INSTALLERS / "satom-setup.sh"
ENTRYPOINT = ROOT / "deploy" / "docker" / "entrypoint.sh"
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "deploy" / "docker" / "compose.yaml"
STAMPER = ROOT / "deploy" / "stamp_site_assets.py"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
OVERLAY = "publication-rules.local.json"
BUILDERS = ("build-offline-bundle.sh", "build-offline-bundle-rhel.sh",
            "build-offline-bundle-suse.sh")

# The release pipeline's contract: it reads the FIRST line of each shipped
# installer matching this and refuses to publish unless it equals the release.
PIPELINE_VERSION_LINE = re.compile(r'^(?:SATOM_|SETUP_)?VERSION="(\d+\.\d+\.\d+)"$', re.M)


def _extract(func: str, text: str) -> str:
    m = re.search(r"^%s\(\) \{.*?^\}$" % re.escape(func), text, re.M | re.S)
    assert m, "function %s() not found" % func
    return m.group(0)


def _executed(text: str) -> list[str]:
    """Lines that EXECUTE: comments and blank lines removed."""
    return [s for s in (l.strip() for l in text.splitlines())
            if s and not s.startswith("#")]


# --------------------------------------------------------------------------- #
#  [SATOM-OVERLAY-SEED] install-satom.sh                                       #
# --------------------------------------------------------------------------- #

def _run_installer_seed(app_dir: pathlib.Path) -> list[str]:
    """Run install-satom.sh's own ensure_publication_overlay() on app_dir.

    chown is stubbed and recorded: as an unprivileged test user the real one
    cannot hand the file to another account, and the call is the contract.
    """
    calls = app_dir.parent / "chown.calls"
    script = "\n".join([
        "set -euo pipefail",
        'APP_DIR="%s"' % app_dir,
        "APP_USER=satomtest",
        "ok() { :; }",
        'chown() { printf "%%s\\n" "$*" >> "%s"; }' % calls,
        _extract("ensure_publication_overlay", INSTALL_SATOM.read_text(encoding="utf-8")),
        "ensure_publication_overlay",
    ])
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return calls.read_text().splitlines() if calls.exists() else []


def test_installer_seeds_an_empty_overlay_when_absent(tmp_path):
    app = tmp_path / "satom"
    app.mkdir()
    chowns = _run_installer_seed(app)
    f = app / "data" / OVERLAY
    assert f.is_file(), "fresh install left no publication rules: create-db dies"
    assert json.loads(f.read_text()) == {}
    assert oct(f.stat().st_mode & 0o777) == "0o644"
    assert chowns == ["satomtest:satomtest %s" % f], (
        "the seeded file must belong to the service account: %r" % chowns)


def test_installer_never_overwrites_existing_rules(tmp_path):
    app = tmp_path / "satom"
    (app / "data").mkdir(parents=True)
    f = app / "data" / OVERLAY
    real = json.dumps({"redactions": [{"pattern": "x", "replacement": "y"}]})
    f.write_text(real)
    os.utime(f, (1_000_000_000, 1_000_000_000))
    chowns = _run_installer_seed(app)
    assert f.read_text() == real
    assert f.stat().st_mtime == 1_000_000_000
    assert chowns == []


def test_installer_does_not_shadow_the_legacy_root_rules(tmp_path):
    """The loader reads data/ FIRST: seeding it over a node whose real rules
    still sit at the legacy root path would empty them in silence."""
    app = tmp_path / "satom"
    app.mkdir()
    (app / OVERLAY).write_text('{"redactions": []}')
    _run_installer_seed(app)
    assert not (app / "data" / OVERLAY).exists()


def test_installer_seeds_before_anything_imports_the_app():
    """Before .env exists, before the seal passphrase import, before create-db."""
    lines = _executed(INSTALL_SATOM.read_text(encoding="utf-8"))

    def first(pred, what):
        for i, l in enumerate(lines):
            if pred(l):
                return i
        raise AssertionError("not found in install-satom.sh: %s" % what)

    seed = first(lambda l: l == "ensure_publication_overlay", "the seed call")
    env = first(lambda l: l.startswith('cat > "$APP_DIR/.env"'), ".env write")
    seal = first(lambda l: "from app.services.recovery_seal import" in l, "seal import")
    createdb = first(lambda l: "flask create-db" in l, "create-db")
    assert seed < env < createdb and seed < seal, (seed, env, seal, createdb)


# --------------------------------------------------------------------------- #
#  [SATOM-OVERLAY-SEED] container entrypoint                                   #
# --------------------------------------------------------------------------- #

def _run_entrypoint_seed(app_dir: pathlib.Path) -> subprocess.CompletedProcess:
    script = "\n".join([
        "set -eu",
        'log() { echo "$*" >&2; }',
        _extract("ensure_publication_overlay", ENTRYPOINT.read_text(encoding="utf-8")),
        "ensure_publication_overlay",
    ])
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                          env={**os.environ, "SATOM_APP_DIR": str(app_dir)})


def test_entrypoint_seeds_an_empty_overlay_when_absent(tmp_path):
    (tmp_path / "data").mkdir()
    r = _run_entrypoint_seed(tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads((tmp_path / "data" / OVERLAY).read_text()) == {}


def test_entrypoint_never_overwrites_or_shadows(tmp_path):
    (tmp_path / "data").mkdir()
    f = tmp_path / "data" / OVERLAY
    f.write_text('{"forbidden": []}')
    assert _run_entrypoint_seed(tmp_path).returncode == 0
    assert f.read_text() == '{"forbidden": []}'

    legacy = tmp_path / "legacy"
    (legacy / "data").mkdir(parents=True)
    (legacy / OVERLAY).write_text("{}")
    assert _run_entrypoint_seed(legacy).returncode == 0
    assert not (legacy / "data" / OVERLAY).exists()


def test_entrypoint_seeds_for_every_app_role_before_dispatch():
    lines = _executed(ENTRYPOINT.read_text(encoding="utf-8"))
    call = [i for i, l in enumerate(lines)
            if l.startswith("case") and "ensure_publication_overlay" in l]
    assert call, "the entrypoint defines the seed but never calls it"
    m = re.search(r"case \"\$role\" in (\S+)\)", lines[call[0]])
    assert m and set(m.group(1).split("|")) >= {"web", "scheduler", "cron"}, lines[call[0]]
    dispatch = lines.index('case "$role" in')
    assert call[0] < dispatch


# --------------------------------------------------------------------------- #
#  Container image: home directory, generated admin password                   #
# --------------------------------------------------------------------------- #

def test_the_image_account_has_a_home_it_owns():
    """-M left $HOME=/home/satom nonexistent: gunicorn's control socket (and
    anything else under ~) failed on every start."""
    run = " ".join(l for l in _executed(DOCKERFILE.read_text()) if not l.startswith("#"))
    m = re.search(r"useradd\b[^&]*\bsatom\b", run)
    assert m, "the satom account is no longer created in the Dockerfile"
    flags = m.group(0).split()
    assert "-M" not in flags and "--no-create-home" not in flags, m.group(0)
    assert "-m" in flags or "--create-home" in flags, m.group(0)


def test_the_generated_admin_password_lands_on_a_writable_volume():
    text = DOCKERFILE.read_text()
    m = re.search(r"SATOM_ADMIN_PASSWORD_FILE=(\S+)", text)
    assert m, "no SATOM_ADMIN_PASSWORD_FILE: the default is the root-owned app dir"
    target_dir = str(pathlib.PurePosixPath(m.group(1)).parent)
    compose = COMPOSE.read_text()
    assert re.search(r"-\s*satom-\w+:%s\s*$" % re.escape(target_dir), compose, re.M), (
        "%s is not a volume: the password would die with the container" % target_dir)
    chown = re.search(r"chown -R satom:satom([^\n\\]*(?:\\\n[^\n\\]*)*)", text)
    assert chown and target_dir in chown.group(1), (
        "%s is not handed to the satom account in the image" % target_dir)


# --------------------------------------------------------------------------- #
#  [SATOM-FIREWALL] install-satom.sh opens ufw as well as firewalld            #
# --------------------------------------------------------------------------- #

def test_installer_opens_ufw_and_firewalld_for_the_same_ports():
    lines = _executed(INSTALL_SATOM.read_text(encoding="utf-8"))
    assert 'FW_PORTS="${WEB_PORT} 80"' in lines
    assert 'ufw allow "${_p}/tcp" >>"$INSTALL_LOG" 2>&1 || true' in lines
    assert ('firewall-cmd --permanent --add-port="${_p}/tcp" >>"$INSTALL_LOG" 2>&1 || true'
            in lines)
    assert any(l.startswith("elif command -v ufw") and "Status: active" in l for l in lines)


# --------------------------------------------------------------------------- #
#  installers/satom-setup.sh                                                   #
# --------------------------------------------------------------------------- #

def test_setup_parses():
    r = subprocess.run(["bash", "-n", str(SETUP)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("script", [INSTALL_SATOM, SETUP], ids=lambda p: p.name)
def test_shipped_installer_declares_the_release_version(script):
    """What the release pipeline checks before it publishes the file."""
    m = PIPELINE_VERSION_LINE.search(script.read_text(encoding="utf-8"))
    assert m, "%s has no top-level VERSION line the pipeline can read" % script.name
    assert m.group(1) == VERSION, (
        "%s declares %s, VERSION says %s -- run python3 deploy/stamp_site_assets.py"
        % (script.name, m.group(1), VERSION))


def test_setup_installs_the_version_it_declares_by_default():
    text = SETUP.read_text(encoding="utf-8")
    assert re.search(r'^VERSION="\$SETUP_VERSION"$', text, re.M), (
        "the default install target is no longer the pinned SETUP_VERSION")


def _stamper():
    spec = importlib.util.spec_from_file_location("_stamper212", STAMPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_stamper_owns_the_setup_version():
    mod = _stamper()
    assert str(SETUP) in [str(p) for p in mod.INSTALLERS], (
        "stamp_site_assets.py does not stamp satom-setup.sh: the cut leaves it stale")
    out = mod.stamp_installer('#!/bin/bash\nSETUP_VERSION="0.0.1"\nVERSION="$SETUP_VERSION"\n', "9.9.9")
    assert out == '#!/bin/bash\nSETUP_VERSION="9.9.9"\nVERSION="$SETUP_VERSION"\n'
    # install-satom.sh's shape still works, and nested assignments stay put.
    assert mod.stamp_installer('VERSION="0.0.1"\nf() {\n  VERSION="x"\n}\n', "9.9.9") \
        == 'VERSION="9.9.9"\nf() {\n  VERSION="x"\n}\n'


def _run_net_check(tree: pathlib.Path) -> subprocess.CompletedProcess:
    text = SETUP.read_text(encoding="utf-8")
    script = "\n".join([
        "set -Eeuo pipefail",
        "LOG=/dev/null",
        "log_raw() { :; }",
        'ok() { echo "OK $*"; }',
        'die() { echo "DIE $*" >&2; exit 1; }',
        _extract("bad_network_literals", text),
        _extract("refuse_bad_network_literals", text),
        _extract("assert_sane_network_literals", text),
        'assert_sane_network_literals "%s" "test tree"' % tree,
    ])
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def _tree(tmp_path, files: dict) -> pathlib.Path:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return tmp_path


@pytest.mark.parametrize("rel,body", [
    ("app/services/intel.py", "PRIVATE = ('192.0.2.0/8', '172.16.0.0/12')\n"),
    ("deploy/docker/compose.yaml", "subnet: ${SATOM_NETWORK_SUBNET:-203.0.113.0/16}\n"),
    ("app/services/resolver.py", "x = ['10.9.8.0/16']\n"),
])
def test_setup_refuses_a_tree_with_an_invalid_network(tmp_path, rel, body):
    r = _run_net_check(_tree(tmp_path, {rel: body}))
    assert r.returncode != 0, "an uninstallable tree was accepted: %s" % r.stdout
    assert rel in r.stderr, "the refusal does not name the file: %s" % r.stderr


def test_setup_accepts_valid_networks_and_interface_notation(tmp_path):
    r = _run_net_check(_tree(tmp_path, {
        "app/a.py": "NETS = ['10.0.0.0/8', '172.28.0.0/16', '192.168.0.0/16']\n"
                    "IFACE = '192.0.2.41/24'  # address/prefix, legitimate\n",
        "deploy/docker/compose.yaml": "subnet: 172.28.0.0/16\n",
        # Not runtime code: documentation may quote the broken value.
        "docs/x.md": "the mirror wrote 192.0.2.0/8\n",
        "app/templates/t.html": "inside 192.0.2.0/8\n",
    }))
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout


def test_setup_repairs_nothing_it_now_leaves_to_the_product():
    """The workarounds are gone: no seeding of the rules file behind the
    installer's back, no rewriting of downloaded code or of nginx configs."""
    code = "\n".join(_executed(SETUP.read_text(encoding="utf-8")))
    assert OVERLAY not in code
    assert "proxy_set_header" not in code
    assert not re.search(r"sed -i\b", code), "satom-setup.sh edits files in place again"


@pytest.mark.parametrize("builder", BUILDERS)
def test_every_offline_bundle_carries_the_guided_installer(builder):
    """Next to install-satom.sh, which is what it runs from inside a bundle."""
    lines = _executed((INSTALLERS / builder).read_text(encoding="utf-8"))
    assert any(l.startswith('cp "$REPO_DIR/installers/satom-setup.sh" "$STAGE/"') for l in lines)
    assert any(l.startswith('cp "$REPO_DIR/installers/install-satom.sh" "$STAGE/"') for l in lines)


def test_setup_uses_the_sibling_installer_inside_a_bundle():
    text = SETUP.read_text(encoding="utf-8")
    body = _extract("install_native", text)
    code = "\n".join(_executed(body))
    assert '"$SCRIPT_DIR/install-satom.sh"' in code
    assert '[ -f "$SCRIPT_DIR/bundle/app.tar.gz" ] && in_bundle=1' in code
    assert 'installer="$sibling"' in code
    # installer_version() reads the sibling's own declaration.
    r = subprocess.run(
        ["bash", "-c", _extract("installer_version", text)
         + '\ninstaller_version "%s"' % INSTALL_SATOM],
        capture_output=True, text=True)
    assert r.stdout.strip() == VERSION, r.stderr
