"""Guards for the app-side half of offline update packages.

The worker's job is to be helpful and to be harmless. Helpful: say why a
package will not apply before anyone applies it. Harmless: never let a name, a
path or a stale page turn into a privileged action.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_up():
    spec = importlib.util.spec_from_file_location(
        "satom_update_package", REPO / "deploy" / "update_package.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


up = _load_up()


@pytest.fixture()
def svc(tmp_path, monkeypatch):
    """The service pointed at a scratch app dir and a scratch trust store."""
    monkeypatch.setenv("FM_APP_DIR", str(tmp_path))
    monkeypatch.setenv("SATOM_TRUST_DIR", str(tmp_path / "keys"))
    import app.services.update_package_service as m
    import importlib
    m = importlib.reload(m)
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    seed = bytes(range(32))
    (tmp_path / "keys" / "t.pub").write_text(
        up.format_public_key(up.ed25519_public_from_seed(seed), "test"))
    (tmp_path / "VERSION").write_text("1.3.5\n")
    # preflight() compares against ``app.version.app_version()``, which reads the
    # REPOSITORY's VERSION -- not the scratch file above. Without this patch the
    # scratch file is dead weight and every "a newer package" case in this module
    # is silently pinned to whatever the tree happens to ship: they passed while
    # the repo was below 1.4.0 and turned red the moment it was bumped past it.
    # Same class as a hardcoded version literal in a template, which this repo
    # already guards against -- a test must not depend on the release it runs on.
    import app.version as appver
    monkeypatch.setattr(appver, "app_version",
                        lambda: (tmp_path / "VERSION").read_text().strip())
    m._seed = seed
    yield m
    importlib.reload(m)


# ===========================================================================
# names
# ===========================================================================
@pytest.mark.parametrize("name", [
    "../../../etc/passwd", "/etc/shadow", "..",
    "sat om.tar.gz", "evil.sh", "satom-update-1.0.tar.gz.sh",
])
def test_safe_name_refuses_anything_that_is_not_a_package_basename(svc, name):
    with pytest.raises(svc.PackageError):
        svc.safe_name(name)


def test_safe_name_strips_a_directory_the_browser_sent(svc):
    """Some browsers send a full path in the multipart filename. Keeping only
    the basename is what makes the staging directory the only destination."""
    assert svc.safe_name("C:\\Users\\me\\satom-update-1.3.6.tar.gz") == \
        "satom-update-1.3.6.tar.gz"
    assert svc.safe_name("/tmp/satom-update-1.3.6.tar.gz") == \
        "satom-update-1.3.6.tar.gz"
    # A relative path is stripped the same way, and the result is only kept
    # because the BASENAME is a valid package name -- the directory part never
    # survives to be joined anywhere.
    assert svc.safe_name("../satom-update-1.3.6.tar.gz") == \
        "satom-update-1.3.6.tar.gz"


# ===========================================================================
# upload
# ===========================================================================
class _Stream:
    def __init__(self, data, chunk=4096):
        self.data, self.i, self.chunk = data, 0, chunk

    def read(self, n=None):
        n = n or self.chunk
        out = self.data[self.i:self.i + n]
        self.i += len(out)
        return out


def test_an_oversized_upload_is_refused_before_it_fills_the_disk(svc, monkeypatch):
    monkeypatch.setattr(svc, "MAX_UPLOAD_BYTES", 1024)
    with pytest.raises(svc.PackageError) as exc:
        svc.save_upload(_Stream(b"x" * 5000), "satom-update-1.0.tar.gz")
    assert "limit" in str(exc.value)
    assert not list(svc.upload_dir().glob("*.tar.gz")), \
        "a refused upload must leave nothing behind"


def test_an_empty_upload_is_refused(svc):
    with pytest.raises(svc.PackageError):
        svc.save_upload(_Stream(b""), "satom-update-1.0.tar.gz")


def test_a_partial_upload_is_never_visible_under_the_real_name(svc):
    """The file is written to a temporary name and renamed on success, so a
    connection dropped mid-upload cannot leave a truncated 'package' that
    looks staged."""
    class Boom(_Stream):
        def read(self, n=None):
            raise OSError("connection reset")
    with pytest.raises(OSError):
        svc.save_upload(Boom(b""), "satom-update-1.0.tar.gz")
    assert not (svc.upload_dir() / "satom-update-1.0.tar.gz").exists()
    assert not list(svc.upload_dir().glob("*.tmp"))


def test_uploads_are_pruned_but_never_the_one_just_staged(svc, monkeypatch):
    monkeypatch.setattr(svc, "KEEP_UPLOADS", 2)
    for i in range(4):
        svc.save_upload(_Stream(b"data%d" % i), "satom-update-1.%d.tar.gz" % i)
    names = {p.name for p in svc.upload_dir().glob("*.tar.gz")}
    assert "satom-update-1.3.tar.gz" in names
    assert len(names) <= 2


# ===========================================================================
# trust state
# ===========================================================================
def test_trust_state_does_not_call_the_list_of_keys_keys(svc):
    """In Jinja ``trust.keys`` resolves to the dict METHOD, not the item, so a
    template iterating it gets a bound method and the page 500s. The name is
    the fix; this test is what keeps it."""
    state = svc.trust_state()
    assert "entries" in state
    assert not isinstance(state.get("keys"), list), \
        "naming this list 'keys' reintroduces the Jinja attribute-lookup trap"


def test_trust_state_reports_an_empty_store_as_unusable(svc):
    for p in Path(svc.TRUST_DIR).glob("*.pub"):
        p.unlink()
    assert svc.trust_state()["usable"] is False


# ===========================================================================
# preflight
# ===========================================================================
def _package(svc, tmp_path, version, seed=None, *, sign=True, python_tags=None,
             requirements=None, wheels=None, min_from="1.0"):
    import tarfile
    root = tmp_path / "build" / ("satom-update-%s" % version)
    (root / "wheels").mkdir(parents=True, exist_ok=True)
    (root / "app.tar.gz").write_bytes(b"tree")
    for w in (wheels or ["Flask-3.1.3-py3-none-any.whl"]):
        (root / "wheels" / w).write_bytes(b"wheel")
    files = {str(p.relative_to(root)): {"sha256": up.sha256_file(p),
                                        "size": p.stat().st_size}
             for p in sorted(root.rglob("*")) if p.is_file()}
    manifest = up.build_manifest(
        version=version, commit="b" * 40, built_at="2026-01-01T00:00:00Z",
        python_tags=python_tags or ["*"],
        requirements=requirements or ["Flask==3.1.3"],
        files=files, min_from_version=min_from)
    (root / "manifest.json").write_bytes(up.dump_manifest(manifest))
    if sign:
        sig = up.ed25519_sign(seed if seed is not None else svc._seed,
                              (root / "manifest.json").read_bytes())
        (root / "manifest.sig").write_text(base64.b64encode(sig).decode())
    name = "satom-update-%s.tar.gz" % version
    out = svc.upload_dir() / name
    with tarfile.open(out, "w:gz") as tf:
        tf.add(root, arcname=root.name)
    return name


def _ids(pre, status):
    return {c["id"] for c in pre["checks"] if c["status"] == status}


def test_preflight_accepts_a_genuine_newer_package(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    name = _package(svc, tmp_path, "1.4.0")
    pre = svc.preflight(name)
    assert pre["can_apply"] is True
    assert pre["is_downgrade"] is False
    assert not _ids(pre, "fail")


def test_preflight_refuses_an_unsigned_package(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    name = _package(svc, tmp_path, "1.4.0", sign=False)
    pre = svc.preflight(name)
    assert pre["can_apply"] is False
    assert "signature" in pre["blocking"]


def test_preflight_refuses_a_package_signed_by_an_untrusted_key(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    name = _package(svc, tmp_path, "1.4.0", seed=os.urandom(32))
    pre = svc.preflight(name)
    assert "signature" in pre["blocking"]


def test_preflight_flags_a_downgrade_without_blocking_it(svc, tmp_path, monkeypatch):
    """Downgrades are allowed by policy. The job here is to make the
    consequence -- migrations are not reversed -- impossible to miss."""
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    name = _package(svc, tmp_path, "1.2.0")
    pre = svc.preflight(name)
    assert pre["is_downgrade"] is True
    assert pre["can_apply"] is True
    version = [c for c in pre["checks"] if c["id"] == "version"][0]
    assert version["status"] == "warn"
    assert "migration" in version["detail"].lower()


def test_preflight_refuses_a_package_built_for_another_python(svc, tmp_path, monkeypatch):
    """The RHEL-9 trap: system python 3.9 against cp311 wheels. Without this
    the apply dies deep inside pip on a node with no network to fall back to."""
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    monkeypatch.setattr(svc, "_venv_python_tag", lambda: "cp39")
    name = _package(svc, tmp_path, "1.4.0", python_tags=["cp311"])
    pre = svc.preflight(name)
    assert "python" in pre["blocking"]


def test_preflight_refuses_a_dependency_change_with_no_wheel(svc, tmp_path, monkeypatch):
    """An offline node cannot reach PyPI, so a missing wheel is not a warning
    -- it is an apply that will stop halfway with the tree already replaced."""
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    monkeypatch.setattr(svc, "_installed_versions", lambda: {"flask": "3.0.0"})
    name = _package(svc, tmp_path, "1.4.0",
                    requirements=["Flask==3.1.3", "brandnew==9.9.9"],
                    wheels=["Flask-3.1.3-py3-none-any.whl"])
    pre = svc.preflight(name)
    assert "deps" in pre["blocking"]
    deps = [c for c in pre["checks"] if c["id"] == "deps"][0]
    assert "brandnew==9.9.9" in deps["detail"]


def test_preflight_refuses_a_package_that_needs_a_newer_starting_point(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    name = _package(svc, tmp_path, "2.0.0", min_from="1.9.0")
    pre = svc.preflight(name)
    assert "min_from" in pre["blocking"]


def test_preflight_refuses_everything_when_the_trust_store_is_unsafe(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(svc.up, "trust_store_problem",
                        lambda _d=None: "owned by uid 999, not root")
    name = _package(svc, tmp_path, "1.4.0")
    pre = svc.preflight(name)
    assert pre["can_apply"] is False
    assert "trust" in pre["blocking"]


def test_preflight_on_a_missing_package_does_not_raise(svc):
    pre = svc.preflight("satom-update-9.9.9.tar.gz")
    assert pre["can_apply"] is False
    assert "package" in pre["blocking"]


# ===========================================================================
# enqueue
# ===========================================================================
def test_the_request_carries_a_basename_and_nothing_else(svc, tmp_path, monkeypatch):
    """Everything else in the request is advice. The name is the only field the
    root runner acts on, and it must not be able to become a path."""
    monkeypatch.setattr(svc.up, "trust_store_problem", lambda _d=None: None)
    monkeypatch.setattr(svc, "self_update", None, raising=False)

    import types
    fake = types.SimpleNamespace(this_node_name=lambda: "n1",
                                 node_role=lambda: "primary")
    import sys
    sys.modules["app.services.self_update"] = fake

    name = _package(svc, tmp_path, "1.4.0")
    uid = svc.request_package_apply(name, by="admin", allow_downgrade=False)
    req = json.loads((Path(svc.REQ_DIR) / (uid + ".json")).read_text())
    assert req["package"] == name
    assert "/" not in req["package"] and ".." not in req["package"]
    assert req["kind"] == "package"
    assert req["allow_downgrade"] is False
    del sys.modules["app.services.self_update"]


def test_enqueue_refuses_a_package_that_is_not_staged(svc, monkeypatch):
    with pytest.raises(svc.PackageError):
        svc.request_package_apply("satom-update-9.9.9.tar.gz", by="admin")
