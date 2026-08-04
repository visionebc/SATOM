"""Update trust store and offline update packages, from the console.

The web console is the normal path. This exists because the console is not
always reachable when it matters: a node whose venv is broken cannot serve the
page that would fix it, and a management network may have no browser at all.
Everything here goes through the SAME privileged runner as the web button — one
apply path, one set of guarantees — except ``show trust`` and ``show package``,
which only read.
"""
import base64
import importlib.util
import json
import os
import shutil
import time
from pathlib import Path

from .context import run
from .render import Result

TRUST_DIR = Path(os.environ.get("SATOM_TRUST_DIR", "/etc/satom/update-keys"))
RUNNER_LIB = Path("/usr/local/lib/satom-runner")


def _up(ctx):
    """The signature verifier, preferring the ROOT-OWNED copy.

    Falling back to the app tree keeps ``show trust`` useful on a node that has
    not been hardened yet, but a decision that MATTERS never rests on the
    fallback: applying a package goes through the runner, which loads its own
    sibling and refuses if that sibling is not root-owned.
    """
    for path in (RUNNER_LIB / "update_package.py",
                 ctx.app_dir / "deploy" / "update_package.py"):
        if path.is_file():
            spec = importlib.util.spec_from_file_location("satom_update_package", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod._loaded_from = str(path)
            return mod
    return None


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------
def show_trust(ctx, args):
    """Which keys this node will accept an update package from."""
    up = _up(ctx)
    r = Result("ok", "update trust store")
    if up is None:
        return Result("bad", "update trust store").lines(
            "", ["update_package.py not found — this build has no package support"])

    problem = up.trust_store_problem(str(TRUST_DIR))
    keys = up.load_trust_store(str(TRUST_DIR))
    r.rows("store", [("path", str(TRUST_DIR)),
                     ("keys", str(len(keys))),
                     ("usable", "no — %s" % problem if problem else "yes")])
    if problem:
        r.status = "bad"
        r.note("A trust store that is not root-owned is not a trust store: "
               "whoever can add a key can mint packages this node accepts.")
    if keys:
        r.rows("trusted keys",
               [(k["fingerprint"], "%s  (%s)" % (k["comment"] or "-", k["name"]))
                for k in keys], keys="plain")
    else:
        r.worst("warn")
        r.note("No key installed, so every package is refused. Install one with: "
               "satom execute trust add-key <file.pub>")
    r.set(path=str(TRUST_DIR), problem=problem,
          keys=[{"name": k["name"], "fingerprint": k["fingerprint"],
                 "comment": k["comment"]} for k in keys])
    return r


def show_package(ctx, args):
    """Inspect an update package without applying it."""
    if not args:
        return Result("info", "show package").lines(
            "", ["usage: satom show package <file.tar.gz>"])
    up = _up(ctx)
    if up is None:
        return Result("bad", "show package").lines("", ["no package support in this build"])
    path = Path(args[0]).expanduser()
    if not path.is_file():
        return Result("bad", "show package").lines("", ["%s is not a file" % path])

    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="satom-show-pkg-"))
    try:
        pkg = up.extract_package(path, tmp)
        manifest = up.read_manifest(pkg)
        r = Result("ok", "update package %s" % path.name)
        r.rows("package", [
            ("product", str(manifest.get("product"))),
            ("version", str(manifest.get("version"))),
            ("commit", str(manifest.get("commit") or "")[:12]),
            ("built at", str(manifest.get("built_at"))),
            ("python", ", ".join(manifest.get("python_tags") or [])),
            ("applies from", str(manifest.get("min_from_version") or "any")),
            ("files", str(len(manifest.get("files") or {}))),
        ])
        try:
            v = up.verify_package(pkg, str(TRUST_DIR))
            r.rows("signature", [("verified", "yes"),
                                 ("key", v["key"]["fingerprint"]),
                                 ("comment", v["key"]["comment"] or v["key"]["name"])])
        except up.PackageError as exc:
            r.status = "bad"
            r.rows("signature", [("verified", "NO"), ("reason", str(exc))])
        r.set(manifest=manifest)
        return r
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "show package").lines("", [str(exc)])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------
def trust_add_key(ctx, args):
    """Install a public key into the trust store.

    Deliberately root-only and deliberately a COPY: the key file the operator
    points at may live anywhere, but what the runner reads must be root-owned
    inside the store.
    """
    if not args:
        return Result("info", "trust add-key").lines("", [
            "usage: satom execute trust add-key <file.pub> [--name <slug>]",
            "",
            "The .pub ships with the release, or comes from your own",
            "'sign_update_package.py genkey'. It can only VERIFY — publishing",
            "it is safe; it is the private half that must never reach a node."])
    up = _up(ctx)
    if up is None:
        return Result("bad", "trust add-key").lines("", ["no package support in this build"])

    src = Path(args[0]).expanduser()
    if not src.is_file():
        return Result("bad", "trust add-key").lines("", ["%s is not a file" % src])
    try:
        raw, comment = up.parse_public_key(src.read_text())
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "trust add-key").lines("", [str(exc)])

    name = ""
    if "--name" in args:
        i = args.index("--name")
        if i + 1 < len(args):
            name = args[i + 1]
    slug = "".join(c for c in (name or src.stem) if c.isalnum() or c in "._-")
    if not slug:
        slug = "key"
    dest = TRUST_DIR / (slug + ".pub")

    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(TRUST_DIR, 0, 0)
    os.chmod(TRUST_DIR, 0o755)
    parent = TRUST_DIR.parent
    try:
        os.chown(parent, 0, 0)
        os.chmod(parent, 0o755)
    except OSError:
        pass

    existing = {k["fingerprint"] for k in up.load_trust_store(str(TRUST_DIR))}
    fp = up.key_fingerprint(raw)
    dest.write_text(up.format_public_key(raw, comment or name))
    os.chown(dest, 0, 0)
    os.chmod(dest, 0o644)

    r = Result("ok", "trust add-key")
    r.rows("installed", [("file", str(dest)), ("fingerprint", fp),
                         ("comment", comment or "-"),
                         ("already trusted", "yes" if fp in existing else "no")])
    problem = up.trust_store_problem(str(TRUST_DIR))
    if problem:
        r.status = "bad"
        r.note(problem)
    else:
        r.note("Compare the fingerprint against the one published with the "
               "release before trusting it. This node now accepts any package "
               "signed by the matching private key.")
    return r


def trust_remove_key(ctx, args):
    """Remove a key from the trust store."""
    plain = [a for a in args if not a.startswith("--")]
    if not plain:
        return Result("info", "trust remove-key").lines("", [
            "usage: satom execute trust remove-key <file-name|fingerprint> --yes"])
    up = _up(ctx)
    if up is None:
        return Result("bad", "trust remove-key").lines("", ["no package support"])
    want = plain[0]
    keys = up.load_trust_store(str(TRUST_DIR))
    hit = [k for k in keys if k["name"] == want or k["fingerprint"] == want
           or k["name"] == want + ".pub"]
    if not hit:
        return Result("bad", "trust remove-key").lines(
            "", ["no trusted key matches %r" % want])
    if "--yes" not in args:
        r = Result("warn", "trust remove-key")
        r.rows("would remove", [(k["fingerprint"], k["name"]) for k in hit],
               keys="plain")
        r.note("Packages signed by this key stop being accepted. Re-run with "
               "--yes to apply.")
        return r
    for k in hit:
        (TRUST_DIR / k["name"]).unlink(missing_ok=True)
    r = Result("ok", "trust remove-key")
    r.rows("removed", [(k["fingerprint"], k["name"]) for k in hit], keys="plain")
    if not up.load_trust_store(str(TRUST_DIR)):
        r.worst("warn")
        r.note("The trust store is now empty: this node accepts no update "
               "package at all.")
    return r


def reinstall_runner(ctx, args):
    """Reinstall the root-owned copy of the privileged update runner."""
    script = ctx.app_dir / "deploy" / "install-runner.sh"
    if not script.exists():
        return Result("bad", "reinstall runner").lines("", ["missing %s" % script])
    rc, out, err = run(["bash", str(script)], timeout=180)
    r = Result("ok" if rc == 0 else "bad", "reinstall runner")
    r.lines("", (out or err).splitlines())
    r.note("Verify the privilege boundary afterwards: satom diagnose updates")
    return r


def update_package(ctx, args):
    """Apply a signed offline update package from the console.

    Stages the file where the web console would put it and enqueues the same
    request the web button writes, so there is exactly ONE apply path. Then it
    follows the runner's status log until it settles.
    """
    plain = [a for a in args if not a.startswith("--")]
    if not plain:
        return Result("info", "update package").lines("", [
            "usage: satom execute update package <file.tar.gz> [--yes] "
            "[--allow-downgrade] [--no-backup]",
            "",
            "The package must be signed by a key in this node's trust store",
            "(satom show trust). The privileged runner verifies it again."])
    up = _up(ctx)
    if up is None:
        return Result("bad", "update package").lines("", ["no package support"])

    src = Path(plain[0]).expanduser()
    if not src.is_file():
        return Result("bad", "update package").lines("", ["%s is not a file" % src])

    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="satom-cli-pkg-"))
    try:
        pkg = up.extract_package(src, tmp)
        verified = up.verify_package(pkg, str(TRUST_DIR))
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(tmp, ignore_errors=True)
        return Result("bad", "update package").lines("", [
            "refusing: %s" % exc,
            "", "satom show trust  — which keys this node accepts"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    manifest = verified["manifest"]
    new = str(manifest.get("version") or "")
    cur = ctx.version if isinstance(getattr(ctx, "version", None), str) else _version(ctx)
    is_downgrade = up.compare_versions(new, cur) < 0

    if "--yes" not in args:
        r = Result("warn", "update package (dry run)")
        r.rows("would apply", [
            ("package", src.name),
            ("version", "%s -> %s%s" % (cur, new, "  DOWNGRADE" if is_downgrade else "")),
            ("signed by", verified["key"]["fingerprint"]),
            ("this node", "%s (%s)" % (ctx.host, ctx.role)),
        ])
        r.note("Re-run with --yes to apply. The service restarts; a failed "
               "health check rolls this node back automatically.")
        if is_downgrade:
            r.note("Downgrade: database migrations are NOT reversed. The apply "
                   "takes a database backup first — keep it.")
        return r
    if is_downgrade and "--allow-downgrade" not in args:
        return Result("bad", "update package").lines("", [
            "%s is older than the installed %s." % (new, cur),
            "Add --allow-downgrade to confirm. Migrations are not reversed."])

    problem = _runner_problem(ctx)
    if problem:
        return Result("bad", "update package").lines("", [
            "the privileged runner is not hardened, so it will refuse:",
            "  " + problem,
            "fix with: satom execute reinstall runner"])

    # Stage where the runner looks, with the ownership the app expects.
    uploads = ctx.app_dir / "data" / "update-uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    name = src.name
    if not up.PKG_NAME_RE.match(name):
        return Result("bad", "update package").lines("", [
            "%r is not an acceptable package name" % name])
    dest = uploads / name
    if dest.resolve() != src.resolve():
        shutil.copy2(src, dest)
    _chown_app(ctx, uploads)
    _chown_app(ctx, dest)

    uid = _enqueue(ctx, name, allow_downgrade=is_downgrade,
                   do_backup="--no-backup" not in args)
    return _follow(ctx, uid, new)


def _version(ctx):
    try:
        return (ctx.app_dir / "VERSION").read_text().strip()
    except OSError:
        return "unknown"


def _chown_app(ctx, path):
    if ctx.app_user and ctx.app_user != "root":
        try:
            import pwd
            e = pwd.getpwnam(ctx.app_user)
            os.chown(path, e.pw_uid, e.pw_gid)
        except (KeyError, OSError):
            pass


def _runner_problem(ctx):
    up = _up(ctx)
    if up is None:
        return "update_package.py not found"
    runner = RUNNER_LIB / "self_update_runner.py"
    if not runner.is_file():
        return "%s does not exist (the hardened runner is not installed)" % runner
    return up.root_owned_problem(RUNNER_LIB, "*.py")


def _enqueue(ctx, name, *, allow_downgrade, do_backup):
    import socket
    import uuid
    from datetime import datetime
    req_dir = ctx.app_dir / "data" / "update-requests"
    sta_dir = ctx.app_dir / "data" / "update-status"
    req_dir.mkdir(parents=True, exist_ok=True)
    sta_dir.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    req = {"id": uid, "kind": "package", "package": name,
           "allow_downgrade": bool(allow_downgrade), "do_backup": bool(do_backup),
           "requested_by": "%s (cli)" % ctx.user,
           "requested_at": datetime.utcnow().isoformat() + "Z",
           "node": socket.gethostname(), "role": ctx.role, "origin": "cli"}
    (sta_dir / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "package",
        "package": name, "requested_by": req["requested_by"],
        "node": req["node"], "role": req["role"], "origin": "cli",
        "updated_at": req["requested_at"]}))
    _chown_app(ctx, sta_dir / (uid + ".json"))
    tmp = req_dir / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    _chown_app(ctx, tmp)
    tmp.rename(req_dir / (uid + ".json"))
    return uid


def _follow(ctx, uid, target, timeout=2400):
    """Print the runner's steps as they land.

    The apply restarts the web service, so a console operator has no page to
    watch. Without this the command would look hung for minutes during the very
    operation most likely to need attention.
    """
    path = ctx.app_dir / "data" / "update-status" / (uid + ".json")
    deadline = time.time() + timeout
    seen = 0
    state = "queued"
    steps = []
    while time.time() < deadline:
        try:
            d = json.loads(path.read_text())
        except Exception:  # noqa: BLE001
            time.sleep(2)
            continue
        steps = d.get("steps") or []
        for s in steps[seen:]:
            if not ctx.json_mode:
                print("  %s %s%s" % ("[ ok ]" if s.get("ok") else "[FAIL]",
                                     s.get("name", ""),
                                     (" — " + s["detail"]) if s.get("detail") else ""))
        seen = len(steps)
        state = d.get("state") or "running"
        if state in ("success", "failed"):
            break
        time.sleep(2)

    r = Result("ok" if state == "success" else "bad",
               "update package %s" % ("applied" if state == "success" else state))
    r.rows("result", [("request", uid), ("state", state),
                      ("version", _version(ctx)), ("target", target)])
    if state != "success":
        r.note("Full log: satom execute update status %s" % uid)
        r.note("The runner rolls back automatically when the health check "
               "fails; confirm with: satom get system health")
    r.set(id=uid, state=state, steps=steps)
    return r


# ---------------------------------------------------------------------------
# diagnose
# ---------------------------------------------------------------------------
def diagnose_updates(ctx, args):
    """Can this node accept an offline update package, and is that safe?"""
    r = Result("ok", "update path")
    up = _up(ctx)
    if up is None:
        return Result("bad", "update path").lines(
            "", ["update_package.py not found in this build"])

    # 1. the runner must be code the service account cannot rewrite
    problem = _runner_problem(ctx)
    if problem:
        r.status = "bad"
        r.rows("privileged runner", [("hardened", "NO"), ("reason", problem)])
        r.note("satom-updater.service runs as root. While its code lives in "
               "the app tree, the service account can choose what root runs — "
               "and a signature checked by that code proves nothing. "
               "Fix: satom execute reinstall runner")
    else:
        r.rows("privileged runner", [("hardened", "yes"), ("path", str(RUNNER_LIB))])

    # 2. what the unit actually starts (the drop-in may be missing)
    rc, out, _ = run(["systemctl", "show", "-p", "ExecStart", "--value",
                      "satom-updater.service"], timeout=15)
    exec_start = (out or "").strip()
    if str(RUNNER_LIB) in exec_start:
        r.rows("unit", [("ExecStart", "root-owned copy")])
    else:
        r.worst("bad")
        r.rows("unit", [("ExecStart", exec_start[:160] or "unknown")])
        r.note("satom-updater.service does not start the hardened copy.")

    # 3. trust store
    tproblem = up.trust_store_problem(str(TRUST_DIR))
    keys = up.load_trust_store(str(TRUST_DIR))
    if tproblem:
        r.worst("bad")
        r.rows("trust store", [("path", str(TRUST_DIR)), ("problem", tproblem)])
    elif not keys:
        r.worst("warn")
        r.rows("trust store", [("path", str(TRUST_DIR)), ("keys", "0")])
        r.note("No trusted key: every offline package is refused. That is a "
               "safe default, not a working one — install the release key with "
               "satom execute trust add-key.")
    else:
        r.rows("trust store", [("path", str(TRUST_DIR)),
                               ("keys", str(len(keys)))])

    # 4. staged uploads
    uploads = ctx.app_dir / "data" / "update-uploads"
    staged = sorted(uploads.glob("*.tar.gz")) if uploads.is_dir() else []
    r.rows("staged packages",
           [(p.name, "%.1f MB" % (p.stat().st_size / 1048576.0)) for p in staged]
           or [("none", "-")], keys="plain")

    r.set(hardened=not problem, trust_keys=len(keys),
          staged=[p.name for p in staged])
    return r
