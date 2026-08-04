"""Guards for signed offline update packages and the runner privilege boundary.

Three things are being protected here, in descending order of how badly they
fail if they break:

1. The privileged runner must not execute or read code the service account can
   write. If it does, signature verification is decoration.
2. The verifier must refuse every package it did not sign, and refuse it for
   the right reason.
3. The verifier must need nothing but the standard library, because it runs to
   repair nodes whose venv is broken.
"""
from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
UP_PATH = REPO / "deploy" / "update_package.py"
RUNNER_PATH = REPO / "deploy" / "self_update_runner.py"
INSTALL_RUNNER = REPO / "deploy" / "install-runner.sh"


def _load(path, name="satom_update_package"):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


up = _load(UP_PATH)


# ===========================================================================
# 1. the verifier is standard library only
# ===========================================================================
_STDLIB_OK = {
    "base64", "hashlib", "json", "os", "re", "stat", "tarfile", "pathlib",
    "__future__", "importlib", "importlib.util", "shutil", "tempfile", "sys",
}


def test_the_verifier_imports_nothing_but_the_standard_library():
    """An offline update package exists to repair a node whose venv is broken.
    A verifier that needs a pip-installed package cannot run in exactly the
    situation it was built for."""
    tree = ast.parse(UP_PATH.read_text())
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bad += [a.name for a in node.names
                    if a.name.split(".")[0] not in _STDLIB_OK]
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if node.level == 0 and root not in _STDLIB_OK:
                bad.append(node.module)
    assert not bad, "update_package.py imports non-stdlib modules: %s" % bad


def test_the_verifier_does_not_import_the_application():
    src = UP_PATH.read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("app"), node.module
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name != "app" and not a.name.startswith("app."), a.name


# ===========================================================================
# 2. Ed25519 against the RFC 8032 vectors and the reference implementation
# ===========================================================================
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
     "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac1"
     "8ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC8032)
def test_ed25519_matches_the_rfc8032_vectors(seed_hex, pub_hex, msg_hex, sig_hex):
    """Hand-written crypto is only acceptable when it is checked against the
    published vectors. These come from RFC 8032 section 7.1."""
    seed = bytes.fromhex(seed_hex)
    msg = bytes.fromhex(msg_hex)
    assert up.ed25519_public_from_seed(seed).hex() == pub_hex
    assert up.ed25519_sign(seed, msg).hex() == sig_hex
    assert up.ed25519_verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig_hex))


def test_ed25519_rejects_a_signature_for_a_different_message():
    seed = bytes(range(32))
    pub = up.ed25519_public_from_seed(seed)
    sig = up.ed25519_sign(seed, b"the real message")
    assert up.ed25519_verify(pub, b"the real message", sig)
    assert not up.ed25519_verify(pub, b"the real messagf", sig)


def test_ed25519_never_raises_on_malformed_input():
    """A malformed key or signature is not an error condition to propagate —
    it is simply not a valid signature. Raising here would turn a hostile
    package into a 500 instead of a refusal."""
    for pub, sig in ((b"", b""), (b"\x00" * 31, b"\x00" * 64),
                     (b"\xff" * 32, b"\xff" * 64), (b"\x00" * 32, b"")):
        assert up.ed25519_verify(pub, b"x", sig) is False


def test_pure_python_agrees_with_the_reference_implementation():
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    seed = bytes(range(1, 33))
    key = crypto.Ed25519PrivateKey.from_private_bytes(seed)
    msg = b"cross-implementation check"
    ref = key.sign(msg)
    assert up.ed25519_sign(seed, msg) == ref, "signatures must match (Ed25519 is deterministic)"
    assert up.ed25519_verify(up.ed25519_public_from_seed(seed), msg, ref)


# ===========================================================================
# 3. trust store
# ===========================================================================
@pytest.fixture()
def trust(tmp_path):
    d = tmp_path / "update-keys"
    d.mkdir()
    seed = bytes(range(32))
    pub = up.ed25519_public_from_seed(seed)
    (d / "test.pub").write_text(up.format_public_key(pub, "test key"))
    return d, seed, pub


def test_a_non_root_owned_trust_store_is_refused(trust, monkeypatch):
    """The whole scheme rests on root choosing the keys. If the service account
    can add one, it can sign its own package — which is the escalation the
    signature was supposed to prevent."""
    d, _, _ = trust
    monkeypatch.setattr(up, "_one_path_problem",
                        lambda p: "owned by uid 999, not root" if p == d else None)
    assert up.trust_store_problem(str(d))


def test_a_world_writable_trust_store_is_refused(trust):
    d, _, _ = trust
    os.chmod(d, 0o777)
    problem = up.trust_store_problem(str(d))
    assert problem and "writable" in problem


def test_a_missing_trust_store_is_refused(tmp_path):
    problem = up.trust_store_problem(str(tmp_path / "nope"))
    assert problem and "does not exist" in problem


def test_a_malformed_key_file_does_not_disable_the_others(trust):
    d, _, pub = trust
    (d / "junk.pub").write_text("this is not a key\n")
    keys = up.load_trust_store(str(d))
    assert [k["key"] for k in keys] == [pub]


@pytest.mark.parametrize("text", [
    "ssh-ed25519 AAAA comment",                 # wrong type
    "satom-ed25519 not-base64!! comment",       # not base64
    "satom-ed25519 %s c" % base64.b64encode(b"short").decode(),  # wrong length
    "",                                          # empty
])
def test_parse_public_key_rejects_junk(text):
    with pytest.raises(up.PackageError):
        up.parse_public_key(text)


def test_fingerprint_is_stable_and_distinguishing():
    a = up.ed25519_public_from_seed(bytes(range(32)))
    b = up.ed25519_public_from_seed(bytes(range(1, 33)))
    assert up.key_fingerprint(a) == up.key_fingerprint(a)
    assert up.key_fingerprint(a) != up.key_fingerprint(b)
    assert up.key_fingerprint(a).startswith("SHA256:")


# ===========================================================================
# 4. package verification — every refusal, and the acceptance
# ===========================================================================
def _make_package(tmp_path, seed, *, version="2.0.0", product="satom",
                  sign=True, extra_file=None, tamper=None):
    pkg = tmp_path / ("satom-update-%s" % version)
    (pkg / "wheels").mkdir(parents=True, exist_ok=True)
    (pkg / "app.tar.gz").write_bytes(b"pretend application tree")
    (pkg / "wheels" / "Flask-3.1.3-py3-none-any.whl").write_bytes(b"pretend wheel")
    files = {}
    for p in sorted(pkg.rglob("*")):
        if p.is_file():
            files[str(p.relative_to(pkg))] = {"sha256": up.sha256_file(p),
                                              "size": p.stat().st_size}
    manifest = up.build_manifest(
        version=version, commit="a" * 40, built_at="2026-01-01T00:00:00Z",
        python_tags=["*"], requirements=["Flask==3.1.3"], files=files,
        min_from_version="1.0")
    manifest["product"] = product
    (pkg / "manifest.json").write_bytes(up.dump_manifest(manifest))
    if sign:
        sig = up.ed25519_sign(seed, (pkg / "manifest.json").read_bytes())
        (pkg / "manifest.sig").write_text(base64.b64encode(sig).decode())
    if extra_file:
        (pkg / extra_file).write_text("smuggled")
    if tamper:
        tamper(pkg)
    return pkg


def test_a_genuine_package_verifies(tmp_path, trust, monkeypatch):
    d, seed, _ = trust
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    pkg = _make_package(tmp_path, seed)
    res = up.verify_package(pkg, str(d))
    assert res["manifest"]["version"] == "2.0.0"
    assert res["key"]["comment"] == "test key"


@pytest.mark.parametrize("name,kwargs,expect", [
    ("unsigned", dict(sign=False), "unsigned"),
    ("wrong product", dict(product="other"), "is for product"),
    ("extra unlisted file", dict(extra_file="wheels/evil.txt"), "unlisted extra file"),
])
def test_bad_packages_are_refused(tmp_path, trust, monkeypatch, name, kwargs, expect):
    d, seed, _ = trust
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    pkg = _make_package(tmp_path, seed, **kwargs)
    with pytest.raises(up.PackageError) as exc:
        up.verify_package(pkg, str(d))
    assert expect.lower() in str(exc.value).lower()


def test_a_payload_altered_after_signing_is_refused(tmp_path, trust, monkeypatch):
    d, seed, _ = trust
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    pkg = _make_package(tmp_path, seed)
    (pkg / "app.tar.gz").write_bytes(b"a DIFFERENT application tree")
    with pytest.raises(up.PackageError) as exc:
        up.verify_package(pkg, str(d))
    assert "sha256 mismatch" in str(exc.value)


def test_an_edited_manifest_is_refused(tmp_path, trust, monkeypatch):
    """The signature covers the manifest's exact bytes, so any edit at all --
    even one that keeps the JSON semantically identical -- invalidates it."""
    d, seed, _ = trust
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    pkg = _make_package(tmp_path, seed)
    m = json.loads((pkg / "manifest.json").read_text())
    m["version"] = "9.9.9"
    (pkg / "manifest.json").write_bytes(up.dump_manifest(m))
    with pytest.raises(up.PackageError) as exc:
        up.verify_package(pkg, str(d))
    assert "no key in the trust store" in str(exc.value)


def test_a_package_signed_by_an_untrusted_key_is_refused(tmp_path, trust, monkeypatch):
    d, _, _ = trust
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    pkg = _make_package(tmp_path, os.urandom(32))
    with pytest.raises(up.PackageError) as exc:
        up.verify_package(pkg, str(d))
    assert "no key in the trust store" in str(exc.value)


def test_an_empty_trust_store_accepts_nothing(tmp_path, trust, monkeypatch):
    d, seed, _ = trust
    (d / "test.pub").unlink()
    monkeypatch.setattr(up, "trust_store_problem", lambda _d=None: None)
    pkg = _make_package(tmp_path, seed)
    with pytest.raises(up.PackageError) as exc:
        up.verify_package(pkg, str(d))
    assert "no usable public key" in str(exc.value)


def test_an_unsafe_trust_store_is_checked_before_the_signature(tmp_path, trust, monkeypatch):
    """Order is the guarantee. Verifying first and checking the store second
    would mean a package that a planted key signed had already been declared
    valid by the time the store was questioned."""
    d, seed, _ = trust
    monkeypatch.setattr(up, "trust_store_problem",
                        lambda _d=None: "owned by uid 999, not root")
    called = []
    monkeypatch.setattr(up, "verify_signature",
                        lambda *a, **k: called.append(1))
    pkg = _make_package(tmp_path, seed)
    with pytest.raises(up.PackageError) as exc:
        up.verify_package(pkg, str(d))
    assert "trust store is not safe" in str(exc.value)
    assert not called, "the signature was checked despite an unsafe trust store"


# ===========================================================================
# 5. archive extraction
# ===========================================================================
def _tar_with(tmp_path, arcname, *, symlink_to=None):
    """Build a hostile tarball.

    Member names are written through ``addfile`` and a hand-made ``TarInfo``
    because ``TarFile.add`` NORMALISES the name -- it strips a leading '/', so
    an "absolute path" case built with add() silently tests nothing at all.
    """
    import io
    out = tmp_path / "bad.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        info = tarfile.TarInfo(name=arcname)
        if symlink_to:
            info.type = tarfile.SYMTYPE
            info.linkname = symlink_to
            tf.addfile(info)
        else:
            data = b"x"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return out


@pytest.mark.parametrize("arcname", [
    "../escape", "../../../../etc/satom/update-keys/evil.pub", "/etc/passwd",
])
def test_the_app_tree_extractor_refuses_traversal(tmp_path, arcname):
    bad = _tar_with(tmp_path, arcname)
    with pytest.raises(up.PackageError) as exc:
        up.extract_app_tree(bad, tmp_path / "dest")
    assert "unsafe path" in str(exc.value)


def test_the_app_tree_extractor_refuses_links(tmp_path):
    """A link is rejected, never resolved. A link that points inside the tree
    when it is checked can point outside it after a later member lands — the
    ordering is the attacker's to choose."""
    bad = _tar_with(tmp_path, "app/secret", symlink_to="/etc/shadow")
    with pytest.raises(up.PackageError) as exc:
        up.extract_app_tree(bad, tmp_path / "dest")
    assert "link" in str(exc.value)


def test_the_package_extractor_refuses_traversal(tmp_path):
    bad = _tar_with(tmp_path, "pkg/../../escape")
    with pytest.raises(up.PackageError):
        up.extract_package(bad, tmp_path / "dest")


def test_a_package_must_have_exactly_one_top_level_directory(tmp_path):
    a = tmp_path / "a"
    a.write_text("1")
    out = tmp_path / "two.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        tf.add(a, arcname="one/a")
        tf.add(a, arcname="two/a")
    with pytest.raises(up.PackageError) as exc:
        up.extract_package(out, tmp_path / "dest")
    assert "exactly one top-level directory" in str(exc.value)


# ===========================================================================
# 6. names and versions
# ===========================================================================
@pytest.mark.parametrize("name", [
    "../../etc/passwd", "/etc/passwd", "satom-update-1.0.tar.gz/../x",
    "..", "", "sat om.tar.gz", "satom-update-1.0.zip", ".hidden.tar.gz",
])
def test_package_names_that_are_paths_are_rejected(name):
    assert not up.PKG_NAME_RE.match(name), "%r should not be an acceptable name" % name


@pytest.mark.parametrize("name", [
    "satom-update-1.3.6.tar.gz", "satom-update-1.3.6-rc1.tar.gz", "a.tar.gz",
])
def test_real_package_names_are_accepted(name):
    assert up.PKG_NAME_RE.match(name)


@pytest.mark.parametrize("a,b,expect", [
    ("1.3.6", "1.3.5", 1), ("1.3.5", "1.3.6", -1), ("1.3.5", "1.3.5", 0),
    ("2.0", "1.9.9", 1), ("1.10", "1.9", 1), ("1.3.5", "1.3", 1),
    ("1.3", "1.3.0", 0),
])
def test_version_comparison(a, b, expect):
    assert up.compare_versions(a, b) == expect


# ===========================================================================
# 7. the runner privilege boundary  [SATOM-RUNNER-ROOT-COPY]
# ===========================================================================
def test_the_root_runner_does_not_import_application_code():
    """satom-updater.service runs as root. Importing app.* there executes the
    entire Flask package -- as root, out of a tree the service account owns."""
    tree = ast.parse(RUNNER_PATH.read_text())
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app"):
            bad.append(node.module)
        if isinstance(node, ast.Import):
            bad += [a.name for a in node.names
                    if a.name == "app" or a.name.startswith("app.")]
    assert not bad, "the root runner imports application code: %s" % bad


def test_the_runner_allowlist_still_matches_the_curated_library_list():
    """The runner stopped importing system_info._LIBRARIES to close an
    escalation. That is only safe while its own copy says the same thing."""
    sys.path.insert(0, str(REPO))
    from app.services.system_info import _LIBRARIES  # noqa: E402

    src = RUNNER_PATH.read_text()
    tree = ast.parse(src)
    fallback = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_pip_allowlist":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and getattr(
                        sub.targets[0], "id", "") == "fallback":
                    fallback = ast.literal_eval(sub.value)
    assert fallback is not None, "could not find the runner's fallback allowlist"
    assert set(fallback) == set(_LIBRARIES), (
        "the runner's allowlist has drifted from system_info._LIBRARIES: "
        "only in runner %s, only in system_info %s"
        % (set(fallback) - set(_LIBRARIES), set(_LIBRARIES) - set(fallback)))


def test_the_runner_loads_its_verifier_from_its_own_directory():
    """Loading the verifier from the app tree while running hardened would
    hand the decision back to the account the hardening excludes."""
    src = RUNNER_PATH.read_text()
    tree = ast.parse(src)
    fn = [n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "_load_update_package"]
    assert fn, "_load_update_package is missing"
    # Strip the docstring first: the function's own explanation necessarily
    # contains the words this assertion looks for, so checking the raw source
    # matches the documentation instead of the code. (Eighth time in this
    # repo that a substring guard matched prose -- assert on the AST.)
    node = fn[0]
    body_nodes = [n for n in node.body
                  if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                          and isinstance(n.value.value, str))]
    body = "\n".join(ast.unparse(n) for n in body_nodes)
    assert "__file__" in body, "the verifier path must be derived from __file__"
    assert "APP" not in body, \
        "the runner must not load its verifier from the application tree"


def test_the_runner_refuses_a_package_when_it_is_not_hardened():
    """The gate is the first thing package_change() does. If it can be reached
    later than the signature check, a rewritten runner has already decided."""
    src = RUNNER_PATH.read_text()
    tree = ast.parse(src)
    fn = [n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "package_change"]
    assert fn, "package_change is missing"
    body = ast.unparse(fn[0])
    i_guard = body.find("runner_integrity_problem")
    i_verify = body.find("verify_package")
    assert i_guard != -1 and i_verify != -1
    assert i_guard < i_verify, \
        "the hardening gate must run BEFORE the signature is verified"


def test_the_runner_resolves_the_package_from_a_name_not_a_path():
    """The request JSON is written by the unprivileged worker. If the runner
    took a path from it, the worker would choose what root opens."""
    src = RUNNER_PATH.read_text()
    tree = ast.parse(src)
    fn = [n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "package_change"][0]
    body = ast.unparse(fn)
    assert "PKG_NAME_RE.match(name)" in body, "the name must be pattern-checked"
    assert "UPLOADS / name" in body, \
        "the runner must join a validated name to its OWN staging directory"


def test_the_installer_hardens_the_unit_with_a_dropin_not_an_edit():
    """self_update_runner re-copies deploy/<unit> on every update, so an edited
    unit silently reverts -- that is exactly how the standby went back to
    User=root after the de-privilege."""
    src = INSTALL_RUNNER.read_text()
    assert "satom-updater.service.d" in src or "DROPIN_DIR" in src
    assert "ExecStart=\n" in src or "ExecStart=$" in src or "ExecStart=" in src
    assert "chown -R root:root" in src


def test_the_hardened_copy_is_a_copy_and_not_a_symlink():
    src = INSTALL_RUNNER.read_text()
    assert "cp -a" in src, "the runner must be copied, not linked"
    assert "ln -s" not in src


def test_the_installer_refuses_a_verifier_that_fails_its_self_test():
    """Installing a broken verifier would fail OPEN at the worst moment."""
    src = INSTALL_RUNNER.read_text()
    assert "ed25519_verify" in src and "refusing to install" in src


def test_the_installer_will_not_use_an_interpreter_from_the_app_tree():
    src = INSTALL_RUNNER.read_text()
    assert '"${APP_DIR}"/*) continue' in src, \
        "the runner's interpreter must never come from the app tree"


def test_the_apply_stages_only_what_the_package_touched():
    """`git add -A` would also commit whatever else happened to be uncommitted
    in the tree -- another session's work in progress, attributed to a commit
    that says 'apply update package'. The first live apply did exactly that:
    it swept 4553 lines of an unrelated feature into its own commit."""
    tree = ast.parse(RUNNER_PATH.read_text())
    fn = [n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "package_change"][0]
    body = "\n".join(ast.unparse(n) for n in fn.body
                     if not (isinstance(n, ast.Expr)
                             and isinstance(n.value, ast.Constant)))
    assert "git('add', '-A')" not in body, \
        "the apply stages the whole tree instead of the package's own paths"
    assert "git('add', '--'" in body, "the apply must stage explicit paths"


def test_the_apply_removes_files_the_new_revision_dropped():
    """A tarball laid over a checkout adds and overwrites but never deletes.
    Without this a module removed upstream stays on disk and keeps importing,
    so the update half-applies and nothing says so."""
    tree = ast.parse(RUNNER_PATH.read_text())
    fn = [n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "package_change"][0]
    body = "\n".join(ast.unparse(n) for n in fn.body
                     if not (isinstance(n, ast.Expr)
                             and isinstance(n.value, ast.Constant)))
    assert "ls-files" in body, "the tracked set must be captured before extraction"
    assert "stale" in body, "the dropped-file set must be computed"
    # 'unlink' alone would also be satisfied by the rollback path, which
    # already unlinks. Anchor on the marker that only this block carries.
    assert "[SATOM-PKG-DELETIONS]" in RUNNER_PATH.read_text()


def test_only_tracked_paths_can_be_removed_by_an_apply(tmp_path):
    """The deletion set is (tracked before) - (in the package). Ignored trees --
    data/, pki/, .env -- are not in `git ls-files`, so an apply structurally
    cannot delete node state, however wrong the package is."""
    tracked_before = {"app/x.py", "app/gone.py", "docs/a.md"}
    written = ["app/x.py", "docs/a.md", "app/new.py"]
    stale = sorted(tracked_before - set(written))
    assert stale == ["app/gone.py"]
    for ignored in ("data/db.sqlite", "pki/server.key", ".env", "venv/bin/python"):
        assert ignored not in stale


def test_extract_app_tree_reports_what_it_wrote(tmp_path):
    """The caller cannot scope the commit or compute the deletions without
    this list, so returning a bare count is not enough."""
    import io
    src = tmp_path / "app.tar.gz"
    with tarfile.open(src, "w:gz") as tf:
        for name in ("app/a.py", "docs/b.md"):
            info = tarfile.TarInfo(name=name)
            data = b"x"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    written = up.extract_app_tree(src, tmp_path / "dest")
    assert sorted(written) == ["app/a.py", "docs/b.md"]


def test_parking_local_state_ignores_untracked_files():
    """`git reset --hard` does not touch untracked files, so they never needed
    parking -- and `git stash create` does not include them either, so it
    returned empty and the step reported FAIL on every run whose only local
    state was untracked. A guard that always complains is one operators learn
    to scroll past."""
    tree = ast.parse(RUNNER_PATH.read_text())
    fn = [n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "preserve_local_commits"]
    assert fn, "preserve_local_commits is missing"
    # Assert on the CALL ARGUMENTS, not on the source text: the comment that
    # explains this flag necessarily contains it, so a substring check would
    # match its own documentation.
    found = False
    for node in ast.walk(fn[0]):
        if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "git"
                and any(isinstance(a, ast.Constant) and a.value == "status"
                        for a in node.args)):
            values = [a.value for a in node.args if isinstance(a, ast.Constant)]
            assert "--untracked-files=no" in values, \
                "git status here must exclude untracked files: %s" % values
            found = True
    assert found, "no git status call found in preserve_local_commits"
