"""[SATOM-RELEASE-TRUST] Signed-release resolution for everything ROOT runs from deploy/.

Shared by the privileged update runner (``deploy/self_update_runner.py``, which
loads this file as a SIBLING of its root-owned copy -- install-runner.sh puts it
there) and by the root operator CLI (this package). STDLIB ONLY, like the rest
of the CLI.

THE RULE
--------
Root installs units and runs ``install-*.sh`` out of deploy/. deploy/ lives in a
tree the SERVICE ACCOUNT owns and commits to, so without a trust anchor that
account chooses what root runs. With a root-owned anchor installed
(``/etc/satom/release-trust.allowed_signers``), root-side content is pinned to
the newest commit SIGNED by a release key:

* target signed                                   -> stage deploy/ from the target;
* target unsigned, deploy/ tree identical to the
  newest signed first-parent ancestor             -> stage deploy/ from that
                                                     signed commit (same bytes);
* otherwise                                       -> HOLD: root-side steps are
                                                     skipped until a signed commit
                                                     (``satom execute sign-release``).

App code is NOT gated: it runs as the service account anyway, so an unsigned
app commit is no escalation. Holding only the root-side refresh keeps HA
converging on unsigned operator commits.

WHY A ROOT-ONLY MIRROR AND NOT ``git -C /opt/satom ...`` AS ROOT
---------------------------------------------------------------
Running git as root inside a repository another account owns runs THAT
account's configuration: ``gpg.ssh.program`` is executed by ``verify-commit``,
a ``filter.<x>.smudge`` named from ``.git/info/attributes`` is executed by
``git archive``. Measured on 2026-10-14 against the first version of this
enforcement: both run a planted script. So root never runs git in the app
repository. The objects are FETCHED into a root-only bare mirror
(``/var/lib/satom-release/mirror.git``, 0700) through ``upload-pack`` running
AS THE SERVICE ACCOUNT -- it only produces a pack stream, and the receiving
side recomputes every object id, so a forged object cannot pose as a signed
one. Verification, the ancestor walk, the tree comparison and the staging
``git archive`` all run in that mirror, with system/global config switched off.
"""
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

TRUST_ANCHOR = Path("/etc/satom/release-trust.allowed_signers")
TRUST_PUB_FALLBACK = Path("/etc/satom/release-trust.pub")
MIRROR = Path("/var/lib/satom-release/mirror.git")
# The private release key 'satom execute sign-release' signs with. Root only.
SIGNING_KEY = Path("/root/.satom-release/release_ed25519")
PRINCIPAL = "satom-release"
WALK_LIMIT = 500

_HEX = set("0123456789abcdef")


class ReleaseTrustError(Exception):
    """Something that prevents a trust decision. Callers fail SAFE on it:
    the runner holds the root-side refresh, the CLI refuses."""


def is_full_sha(value):
    return (isinstance(value, str) and len(value) == 40
            and set(value.lower()) <= _HEX)


def find_anchor(paths=None):
    """The root-owned anchor, or None when enforcement is OFF.

    Counts only when it is a regular file, owned by root and non-empty: a
    half-written or non-root file must never weaken the check into passing.
    """
    for p in paths or (TRUST_ANCHOR, TRUST_PUB_FALLBACK):
        try:
            ss = os.stat(p)
        except OSError:
            continue
        if stat.S_ISREG(ss.st_mode) and ss.st_uid == 0 and ss.st_size > 0:
            return Path(p)
    return None


def app_user_prefix(app_user):
    """``runuser -u <account> --`` when running as root for another account."""
    if app_user and app_user != "root" and os.geteuid() == 0:
        return ["runuser", "-u", app_user, "--"]
    return []


def clean_env(extra=None):
    """Environment for every git call made here: no system or global config
    (a deterministic, root-controlled configuration), no prompts, no agent."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k != "SSH_AUTH_SOCK"}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    env.update(extra or {})
    return env


def _private_dir(path):
    """Create (0700) or check ``path``: a real directory, owned by us, closed
    to everyone else. Anything else is refused, never repaired in place."""
    path = Path(path)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    ss = os.lstat(path)
    if not stat.S_ISDIR(ss.st_mode):
        raise ReleaseTrustError("%s is not a directory" % path)
    if ss.st_uid != os.geteuid():
        raise ReleaseTrustError("%s is owned by uid %d, not by this process"
                                % (path, ss.st_uid))
    if ss.st_mode & 0o077:
        raise ReleaseTrustError("%s is mode %o; it must be closed to other "
                                "accounts (0700)" % (path, ss.st_mode & 0o777))


def mirror_git(mirror, args, signers=None, timeout=300, input_=None, text=True):
    cmd = ["git", "--git-dir", str(mirror)]
    if signers:
        cmd += ["-c", "gpg.format=ssh",
                "-c", "gpg.ssh.allowedSignersFile=%s" % signers,
                "-c", "gpg.ssh.program=ssh-keygen"]
    return subprocess.run(cmd + list(args), capture_output=True, text=text,
                          timeout=timeout, input=input_, env=clean_env(), cwd="/")


def ensure_mirror(mirror=None):
    mirror = Path(mirror or MIRROR)
    _private_dir(mirror.parent)
    if not os.path.lexists(mirror):
        # Create the directory 0700 OURSELVES: `git init` would make it 0755
        # (umask), and a mirror other accounts can read or traverse is refused.
        os.mkdir(mirror, 0o700)
        r = subprocess.run(["git", "init", "-q", "--bare", str(mirror)],
                           capture_output=True, text=True, timeout=60,
                           env=clean_env(), cwd="/")
        if r.returncode != 0:
            shutil.rmtree(str(mirror), ignore_errors=True)
            raise ReleaseTrustError("cannot create the release mirror: %s"
                                    % (r.stderr or "").strip()[-200:])
    _private_dir(mirror)
    return mirror


def fetch(app_dir, sha, app_user=None, mirror=None, ref="refs/satom/head",
          timeout=900):
    """Copy ``sha`` and its history from the app repository into the mirror.

    ``upload-pack`` runs as the service account (it only produces bytes); the
    receiving side recomputes every object id."""
    if not is_full_sha(sha):
        raise ReleaseTrustError("refusing to fetch a non-commit target %r" % (sha,))
    mirror = ensure_mirror(mirror)
    up = app_user_prefix(app_user) + [
        "git", "-c", "uploadpack.allowAnySHA1InWant=true", "upload-pack"]
    r = mirror_git(mirror, ["fetch", "--quiet", "--no-tags",
                            "--no-write-fetch-head",
                            "--upload-pack=%s" % " ".join(shlex.quote(x) for x in up),
                            str(app_dir), "+%s:%s" % (sha, ref)],
                   timeout=timeout)
    if r.returncode != 0:
        raise ReleaseTrustError("cannot copy %s into the release mirror: %s"
                                % (sha[:12], (r.stderr or r.stdout or "").strip()[-300:]))
    return mirror


class signers_file:
    """Context manager yielding an ssh allowed-signers file for ``anchor``.

    The ``.pub`` fallback holds a bare public key, which ssh-keygen rejects as
    an allowed-signers line ("invalid key"), so it is wrapped into one in a
    root-only temp directory. The ``.allowed_signers`` form is used as is.
    """

    def __init__(self, anchor):
        self.anchor = Path(anchor)
        self._tmp = None

    def __enter__(self):
        if self.anchor.name.endswith(".allowed_signers"):
            return str(self.anchor)
        self._tmp = tempfile.mkdtemp(prefix="satom-signers-")
        os.chmod(self._tmp, 0o700)
        lines = []
        for ln in self.anchor.read_text().splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                lines.append('%s namespaces="git" %s' % (PRINCIPAL, ln))
        out = Path(self._tmp) / "allowed_signers"
        out.write_text("\n".join(lines) + "\n")
        return str(out)

    def __exit__(self, *exc):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
        return False


def is_signed(mirror, sha, signers):
    """(ok, detail) -- git's own ssh signature check, in the mirror."""
    r = mirror_git(mirror, ["verify-commit", sha], signers=signers, timeout=60)
    return r.returncode == 0, (r.stderr or r.stdout or "").strip()[-300:]


def newest_signed(mirror, start, signers, limit=WALK_LIMIT):
    """Newest commit on the first-parent chain of ``start`` (itself included,
    at most ``limit`` commits) that verifies against the anchor, or None."""
    r = mirror_git(mirror, ["log", "--first-parent", "-n", str(int(limit)),
                            "--format=%H %G?", start], signers=signers)
    if r.returncode != 0:
        raise ReleaseTrustError("cannot walk the history of %s: %s"
                                % (start[:12], (r.stderr or "").strip()[-200:]))
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "G":
            ok, _ = is_signed(mirror, parts[0], signers)
            if ok:
                return parts[0]
    return None


def deploy_tree(mirror, rev):
    """Tree id of ``rev:deploy`` (None when the commit has no deploy/)."""
    r = mirror_git(mirror, ["rev-parse", "--verify", "--quiet",
                            "%s:deploy" % rev], timeout=60)
    return (r.stdout or "").strip() if r.returncode == 0 else None


def resolve(app_dir, target, anchor, app_user=None, mirror=None,
            limit=WALK_LIMIT, fetch_timeout=900):
    """Decide where root-side content comes from for commit ``target``.

    Returns a dict: ``mode`` is ``signed`` (target is signed), ``pinned``
    (target unsigned, deploy/ byte-identical to signed commit ``signed``) or
    ``held`` (deploy/ differs from the last signed release, or there is none).
    ``signed`` is the commit to stage from (None when held). Raises
    ReleaseTrustError when no decision can be made at all.
    """
    mirror = fetch(app_dir, target, app_user=app_user, mirror=mirror,
                   timeout=fetch_timeout)
    with signers_file(anchor) as signers:
        signed = newest_signed(mirror, target, signers, limit=limit)
    out = {"target": target, "signed": None, "last_signed": signed,
           "mode": "held", "mirror": str(mirror)}
    if signed == target:
        out.update(mode="signed", signed=target,
                   detail="ok: %s is signed by a trusted release key" % target[:12])
        return out
    if signed is None:
        out["detail"] = ("no commit signed by a trusted release key in the last "
                         "%d first-parent commits of %s: root-side refresh held "
                         "until a signed commit (satom execute sign-release)"
                         % (int(limit), target[:12]))
        return out
    if deploy_tree(mirror, target) == deploy_tree(mirror, signed):
        out.update(mode="pinned", signed=signed,
                   detail="ok: %s is unsigned but its deploy/ is identical to "
                          "signed release %s; root-side files staged from %s"
                          % (target[:12], signed[:12], signed[:12]))
        return out
    out["detail"] = ("deploy/ changed since the last signed release %s: "
                     "root-side refresh held until a signed commit "
                     "(satom execute sign-release)" % signed[:12])
    return out


def stage_deploy(sha, dest, mirror=None):
    """Extract ``deploy/`` at ``sha`` from the mirror into ``dest`` (a root-only
    directory the caller owns and removes). Returns ``dest/deploy``."""
    mirror = Path(mirror or MIRROR)
    arch = subprocess.run(["git", "--git-dir", str(mirror), "archive",
                           "--format=tar", sha, "deploy"],
                          capture_output=True, timeout=300, env=clean_env(), cwd="/")
    if arch.returncode != 0:
        raise ReleaseTrustError("git archive failed: %s"
                                % (arch.stderr or b"").decode("utf-8", "replace")[-200:])
    tar = subprocess.run(["tar", "-x", "--no-same-owner", "-C", str(dest)],
                         input=arch.stdout, capture_output=True, timeout=300,
                         cwd="/")
    if tar.returncode != 0:
        raise ReleaseTrustError("staging tar -x failed: %s"
                                % (tar.stderr or b"").decode("utf-8", "replace")[-200:])
    return Path(dest) / "deploy"


def root_only_dir(prefix="satom-rel-"):
    """A fresh 0700 directory under /run (tmpfs) when usable, else the default
    temp dir. The caller removes it."""
    base = "/run" if os.path.isdir("/run") and os.access("/run", os.W_OK) else None
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    os.chmod(d, 0o700)
    return Path(d)
