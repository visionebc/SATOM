"""Signed releases: what root may install or run from deploy/. [SATOM-RELEASE-TRUST]

Three things live here:

* ``DeploySource`` -- the gate every root CLI verb that installs or runs
  something from deploy/ goes through (``reinstall cli|runner|metrics-store|
  units``). With no release trust anchor it is the app tree's deploy/, exactly
  as before. With an anchor it is a root-only staged copy of the newest SIGNED
  release whose deploy/ tree equals HEAD's -- and when deploy/ has unsigned
  changes the verb refuses, with the command that fixes it.
* ``execute sign-release`` -- the operator's attestation: ONE signed, empty
  commit on top of main, made with the root-only release key.
* ``get release trust`` -- anchor, newest signed commit, and whether HEAD's
  deploy/ matches it.

Root never runs git inside the service account's repository (its config can
name programs git executes); see release_trust.py.
"""
import os
import pwd
import shutil
import stat
import tempfile
from pathlib import Path

from . import release_trust as rt
from .context import run
from .render import Result

RUNNER_LIB = Path("/usr/local/lib/satom-runner")
SIGN_USAGE = "execute sign-release [--yes]"


# ---------------------------------------------------------------------------
# git in the APP repository -- always as the service account
# ---------------------------------------------------------------------------
def _app_git(ctx, *args, timeout=120, input_=None):
    """``git -C <app>`` as the service account (as ourselves when not root).

    The service account's own HOME, so its own git configuration (remote
    credentials) applies to its own process -- and none of it reaches root."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    cmd = ["git", "-C", str(ctx.app_dir)] + list(args)
    prefix = rt.app_user_prefix(ctx.app_user)
    if prefix:
        try:
            env["HOME"] = pwd.getpwnam(ctx.app_user).pw_dir
        except KeyError:
            pass
        cmd = ["runuser", "-m", "-u", ctx.app_user, "--"] + cmd
    return run(cmd, timeout=timeout, cwd="/", env=env, input_=input_)


def _head(ctx):
    rc, out, err = _app_git(ctx, "rev-parse", "--verify", "HEAD")
    sha = (out or "").strip()
    if rc != 0 or not rt.is_full_sha(sha):
        raise rt.ReleaseTrustError("cannot read HEAD of %s: %s"
                                   % (ctx.app_dir, (err or out)[-200:]))
    return sha


def _refusal(title, lines, exit_code=1):
    r = Result("bad", title, exit_code=exit_code)
    r.lines("", lines)
    return r


# ---------------------------------------------------------------------------
# the gate for root verbs that install/run something from deploy/
# ---------------------------------------------------------------------------
class DeploySource:
    """``with DeploySource(ctx, title) as src:`` then use ``src.dir`` and
    ``src.env`` -- or return ``src.refusal`` when it is set.

    No anchor: ``dir`` is ``<app>/deploy`` and ``env`` is None (the historical
    call, unchanged). Anchor present: ``dir`` is a root-only staged copy of
    deploy/ at the newest signed commit whose deploy/ tree equals HEAD's, and
    ``env`` points the install scripts at it (``SATOM_DEPLOY_SRC``) while their
    drop-ins keep aiming at the real app (``FM_APP_DIR``). Uncommitted edits in
    the working tree are therefore never installed either."""

    def __init__(self, ctx, title):
        self.ctx = ctx
        self.title = title
        self.dir = ctx.app_dir / "deploy"
        self.env = None
        self.refusal = None
        self.note = ""
        self._stage = None

    def __enter__(self):
        anchor = rt.find_anchor()
        if anchor is None:
            return self
        try:
            head = _head(self.ctx)
            res = rt.resolve(self.ctx.app_dir, head, anchor,
                             app_user=self.ctx.app_user)
        except Exception as exc:  # noqa: BLE001 -- fail closed for root verbs
            self.refusal = _refusal(self.title, [
                "refusing: a release trust anchor is installed (%s) and the "
                "release signature could not be checked: %s" % (anchor, str(exc)[:300]),
                "",
                "satom get release trust   -- what this node sees"])
            return self
        if res["mode"] == "held":
            since = res.get("last_signed")
            first = ("deploy/ has unsigned changes since %s; run `satom execute "
                     "sign-release` first" % since[:12]) if since else (
                     "no signed release in the last %d commits of %s; run "
                     "`satom execute sign-release` first" % (rt.WALK_LIMIT, head[:12]))
            self.refusal = _refusal(self.title, [
                first,
                "",
                "A release trust anchor is installed (%s), so root only installs "
                "what a release key signed." % anchor,
                "satom get release trust   -- the newest signed commit and the diff"])
            return self
        try:
            self._stage = rt.root_only_dir("satom-cli-rel-")
            self.dir = rt.stage_deploy(res["signed"], self._stage)
        except Exception as exc:  # noqa: BLE001
            self.__exit__(None, None, None)
            self.refusal = _refusal(self.title, [
                "refusing: staging signed release %s failed: %s"
                % (res["signed"][:12], str(exc)[:300])])
            return self
        self.env = dict(os.environ, FM_APP_DIR=str(self.ctx.app_dir),
                        SATOM_DEPLOY_SRC=str(self.dir))
        self.note = ("Installed from signed release %s (%s)."
                     % (res["signed"][:12], res["mode"]))
        return self

    def __exit__(self, *exc):
        if self._stage is not None:
            shutil.rmtree(str(self._stage), ignore_errors=True)
            self._stage = None
        return False

    def annotate(self, result):
        if self.note:
            result.note(self.note)
        return result


def run_deploy_script(ctx, title, script, timeout, runner=None):
    """Run ``deploy/<script>`` as root through the gate.

    Returns ``(refusal, rc, out, err, note)``: ``refusal`` is a Result when the
    gate refused or the script is missing (the caller returns it as is);
    ``note`` says which signed release the script came from ("" when no
    anchor is installed). With no anchor the call is exactly the historical
    ``run(["bash", <app>/deploy/<script>], timeout=...)``."""
    runner = runner or run
    with DeploySource(ctx, title) as src:
        if src.refusal is not None:
            return src.refusal, None, "", "", ""
        path = src.dir / script
        if not path.exists():
            return Result("bad", "missing %s" % path), None, "", "", ""
        if src.env is None:
            rc, out, err = runner(["bash", str(path)], timeout=timeout)
        else:
            rc, out, err = runner(["bash", str(path)], timeout=timeout, env=src.env)
        return None, rc, out, err, src.note


# ---------------------------------------------------------------------------
# get release trust
# ---------------------------------------------------------------------------
def release_trust(ctx, args):
    anchor = rt.find_anchor()
    r = Result("ok", "release trust")
    rows = [("anchor", str(anchor) if anchor else
             "absent -- enforcement OFF (%s)" % rt.TRUST_ANCHOR),
            ("runner helper", "installed" if (RUNNER_LIB / "release_trust.py").is_file()
             else "MISSING at %s -- satom execute reinstall runner" % RUNNER_LIB)]
    if not (RUNNER_LIB / "release_trust.py").is_file() and anchor:
        r.worst("warn")
    if ctx.is_root:
        rows.append(("signing key", "present" if rt.SIGNING_KEY.is_file()
                     else "absent on this node (%s)" % rt.SIGNING_KEY))
    if anchor is None:
        r.rows("", rows)
        r.note("With no anchor, root installs deploy/ from the working tree as it "
               "always did. To turn enforcement on: install a root-owned ssh "
               "allowed-signers file at %s on every node, then sign main with "
               "'sudo satom execute sign-release' on the primary." % rt.TRUST_ANCHOR)
        return r
    if not ctx.is_root:
        r.rows("", rows)
        r.note("Signatures are checked in a root-only mirror. Run with sudo to see "
               "the newest signed commit and whether HEAD's deploy/ matches it.")
        return r
    try:
        head = _head(ctx)
        res = rt.resolve(ctx.app_dir, head, anchor, app_user=ctx.app_user)
    except Exception as exc:  # noqa: BLE001
        rows.append(("check", "FAILED: %s" % str(exc)[:300]))
        r.status = "bad"
        r.rows("", rows)
        return r
    rows += [("HEAD", head[:12]),
             ("newest signed", (res.get("last_signed") or "none in the last %d commits"
                                % rt.WALK_LIMIT)[:40]),
             ("HEAD deploy/ matches it",
              "yes" if res["mode"] in ("signed", "pinned") else "NO"),
             ("root-side refresh", {"signed": "from HEAD (signed)",
                                    "pinned": "from %s (identical deploy/)"
                                              % (res.get("signed") or "")[:12],
                                    "held": "HELD"}[res["mode"]])]
    r.rows("", rows)
    if res["mode"] == "held":
        r.worst("warn")
        r.note(res["detail"])
        if res.get("last_signed"):
            rc = rt.mirror_git(res["mirror"], ["diff", "--stat", res["last_signed"],
                                               head, "--", "deploy"])
            r.lines("deploy/ changes not yet signed",
                    (rc.stdout or "").splitlines()[-25:] or ["(none)"])
    return r


# ---------------------------------------------------------------------------
# execute sign-release
# ---------------------------------------------------------------------------
def _key_problem(key):
    """Why ``key`` must not be used, or None. Root only, closed to everyone."""
    try:
        ks = os.lstat(key)
        ds = os.lstat(key.parent)
    except OSError as exc:
        return "no release key at %s (%s)" % (key, exc.strerror or exc)
    if not stat.S_ISREG(ks.st_mode):
        return "%s is not a regular file" % key
    for p, s in ((key, ks), (key.parent, ds)):
        if s.st_uid != os.geteuid():
            return "%s is owned by uid %d, not by root" % (p, s.st_uid)
        if s.st_mode & 0o077:
            return ("%s is mode %o; it must be readable by root only (key 0600, "
                    "directory 0700)" % (p, s.st_mode & 0o777))
    return None


def _pubkey(key):
    rc, out, err = run(["ssh-keygen", "-y", "-f", str(key)], timeout=30,
                       env=rt.clean_env())
    if rc != 0 or not out.strip():
        raise rt.ReleaseTrustError("cannot read the public half of %s: %s"
                                   % (key, (err or out)[-200:]))
    return out.strip().splitlines()[0]


def sign_release(ctx, args):
    title = "sign release"
    if not ctx.is_root:
        return _refusal(title, ["refusing: must run as root (sudo satom %s)" % SIGN_USAGE],
                        exit_code=3)
    if ctx.role != "primary":
        return _refusal(title, [
            "refusing: this node is '%s'. Sign on the PRIMARY: the standby "
            "fetches the signed commit from it." % ctx.role])
    key = rt.SIGNING_KEY
    problem = _key_problem(key)
    if problem:
        return _refusal(title, [
            "refusing: %s" % problem, "",
            "The release key lives ONLY on the primary, root-only:",
            "  install -d -m 0700 %s" % key.parent,
            "  ssh-keygen -t ed25519 -N '' -C satom-release -f %s" % key])

    rc, out, err = _app_git(ctx, "fetch", "--quiet", "origin", "main", timeout=300)
    if rc != 0:
        return _refusal(title, ["refusing: 'git fetch origin main' failed as %s: %s"
                                % (ctx.app_user, (err or out)[-300:])])
    rc, branch, _ = _app_git(ctx, "symbolic-ref", "-q", "HEAD")
    if branch.strip() != "refs/heads/main":
        return _refusal(title, ["refusing: %s is on %r, not on main"
                                % (ctx.app_dir, branch.strip() or "a detached HEAD")])
    try:
        head = _head(ctx)
    except rt.ReleaseTrustError as exc:
        return _refusal(title, ["refusing: %s" % exc])
    rc, om, _ = _app_git(ctx, "rev-parse", "--verify", "refs/remotes/origin/main")
    om = om.strip()
    if rc != 0 or om != head:
        return _refusal(title, [
            "refusing: HEAD %s is not origin/main %s" % (head[:12], (om or "?")[:12]),
            "Sign exactly what every node will converge to: get main and "
            "origin/main to the same commit (push or pull), then re-run."])

    anchor = rt.find_anchor()
    tmp = Path(tempfile.mkdtemp(prefix="satom-sign-"))
    os.chmod(str(tmp), 0o700)
    try:
        try:
            mirror = rt.fetch(ctx.app_dir, head, app_user=ctx.app_user)
            own = tmp / "own.allowed_signers"
            own.write_text('%s namespaces="git" %s\n' % (rt.PRINCIPAL, _pubkey(key)))
            if rt.is_signed(mirror, head, str(own))[0] or (
                    anchor and _signed_by_anchor(mirror, head, anchor)):
                r = Result("ok", "%s: HEAD %s is already signed" % (title, head[:12]))
                return r
            last = rt.newest_signed(mirror, head, str(own))
        except rt.ReleaseTrustError as exc:
            return _refusal(title, ["refusing: %s" % exc])

        if last:
            d = rt.mirror_git(mirror, ["diff", "--stat", last, head, "--", "deploy"])
            diff = (d.stdout or "").splitlines() or ["(deploy/ unchanged)"]
        else:
            diff = ["no earlier release signed by this key: the WHOLE deploy/ "
                    "at %s is being attested" % head[:12]]
        if "--yes" not in args:
            r = Result("warn", "%s (dry run)" % title, exit_code=2)
            r.rows("would sign", [("commit", "release: sign %s" % head[:12]),
                                  ("on top of", "%s (main == origin/main)" % head),
                                  ("tree", "unchanged (an empty commit)"),
                                  ("last signed", (last or "none")[:12]),
                                  ("anchor", str(anchor) if anchor else
                                   "absent on this node (enforcement OFF here)")])
            r.lines("deploy/ changes you are attesting", diff[-30:])
            r.note("Signing tells every node with the anchor that root may install "
                   "and run this deploy/. Review the changes above, then re-run: "
                   "sudo satom %s --yes" % "execute sign-release")
            return r

        operator = os.environ.get("SUDO_USER") or ctx.user
        cfg = ["-c", "user.name=SATOM release", "-c", "user.email=release@satom.invalid",
               "-c", "gpg.format=ssh", "-c", "user.signingkey=%s" % key,
               "-c", "gpg.ssh.program=ssh-keygen"]
        c = rt.mirror_git(mirror, cfg + [
            "commit-tree", "-S", "%s^{tree}" % head, "-p", head,
            "-m", "release: sign %s" % head[:12],
            "-m", "Release attested by %s on %s with satom execute sign-release."
                  % (operator, ctx.host)], timeout=120)
        new = (c.stdout or "").strip()
        if c.returncode != 0 or not rt.is_full_sha(new):
            return _refusal(title, ["refusing: signing failed: %s"
                                    % (c.stderr or c.stdout or "")[-300:]])
        ok, detail = rt.is_signed(mirror, new, str(own))
        if not ok:
            return _refusal(title, ["refusing: the new commit does not verify: %s" % detail])
        if anchor and not _signed_by_anchor(mirror, new, anchor):
            return _refusal(title, [
                "refusing: %s is not in the trust anchor %s -- the commit would "
                "be ignored. Nothing was written." % (key, anchor)])
        raw = rt.mirror_git(mirror, ["cat-file", "commit", new]).stdout or ""

        # Written by the SERVICE ACCOUNT: root never creates files in .git
        # (root-owned objects break the standby's fetch).
        rc, out, err = _app_git(ctx, "hash-object", "-t", "commit", "-w", "--stdin",
                                input_=raw)
        if rc != 0 or out.strip() != new:
            return _refusal(title, ["refusing: writing the commit as %s gave %r "
                                    "(expected %s): %s"
                                    % (ctx.app_user, out.strip()[:40], new[:12], err[-200:])])
        rc, out, err = _app_git(ctx, "update-ref", "-m", "release: sign %s" % head[:12],
                                "refs/heads/main", new, head)
        if rc != 0:
            return _refusal(title, ["refusing: main moved while signing (%s); "
                                    "nothing pushed -- re-run" % (err or out)[-200:]])
        rc, out, err = _app_git(ctx, "push", "--quiet", "origin", "main", timeout=300)
        if rc != 0:
            _app_git(ctx, "update-ref", "refs/heads/main", head, new)
            return _refusal(title, [
                "push to origin failed, local main put back to %s: %s"
                % (head[:12], (err or out)[-300:]),
                "Usually origin moved on meanwhile: re-run sign-release."])
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)

    r = Result("ok", "%s: %s" % (title, new[:12]))
    r.rows("", [("signed commit", new), ("attests", head),
                ("pushed", "origin main"), ("node", "%s (%s)" % (ctx.host, ctx.role))])
    r.note("The standby converges on its next reconcile. There, 'sudo satom "
           "execute update status' shows: ok verify release signature ok: %s is "
           "signed by a trusted release key" % new[:12])
    return r


def _signed_by_anchor(mirror, sha, anchor):
    with rt.signers_file(anchor) as signers:
        return rt.is_signed(mirror, sha, signers)[0]

