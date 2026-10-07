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
#: Operator-managed API-pack keys, one sub-directory per lane (SATOM 3.0).
PACK_KEY_DIR = Path(os.environ.get("SATOM_PACK_KEY_DIR", "/etc/satom/pack-keys"))
RUNNER_LIB = Path("/usr/local/lib/satom-runner")
#: One key, one use: ``update`` verifies update packages (and legacy 2.x API
#: packs); each pack lane verifies only the /2 packs of that lane.
PURPOSES = ("update", "api_pack", "knowledge")
PURPOSE_HELP = {
    "update": "update packages (and legacy 2.x API packs)",
    "api_pack": "API packs of the api_pack lane (pinned to a SATOM release)",
    "knowledge": "API packs of the knowledge lane (rolling satom-harvester snapshots)",
}
ADD_USAGE = ("execute trust add-key <file.pub> [--purpose update|api_pack|knowledge] "
             "[--name <slug>]")


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
def _purpose_dirs(ctx, purpose):
    """``[(dir, managed)]`` holding the keys of ``purpose``. ``managed`` is
    False for the keys shipped in the code tree (deploy/pack-keys): they come
    with the release and are replaced by the next one, not by this command."""
    if purpose == "update":
        return [(TRUST_DIR, True)]
    return [(ctx.app_dir / "deploy" / "pack-keys" / purpose, False),
            (PACK_KEY_DIR / purpose, True)]


def _keys_of(up, ctx, purpose):
    """Every usable key of ``purpose``, de-duplicated by fingerprint."""
    out, seen = [], set()
    for d, managed in _purpose_dirs(ctx, purpose):
        for k in up.load_trust_store(str(d)):
            if k["fingerprint"] in seen:
                continue
            seen.add(k["fingerprint"])
            out.append(dict(k, dir=str(d), managed=managed))
    return out


def _purpose_arg(args):
    """``(purpose, error)`` from ``--purpose X`` / ``--purpose=X`` (default update)."""
    val = "update"
    for i, a in enumerate(args):
        if a == "--purpose":
            val = args[i + 1] if i + 1 < len(args) else ""
        elif a.startswith("--purpose="):
            val = a.split("=", 1)[1]
    if val not in PURPOSES:
        return None, "unknown purpose %r (one of: %s)" % (val, ", ".join(PURPOSES))
    return val, ""


def show_trust(ctx, args):
    """Which keys this node accepts, per purpose: update packages, api_pack
    packs, knowledge packs. One key, one use."""
    up = _up(ctx)
    r = Result("ok", "trust stores")
    if up is None:
        return Result("bad", "trust stores").lines(
            "", ["update_package.py not found — this build has no package support"])

    data = {}
    for purpose in PURPOSES:
        keys = _keys_of(up, ctx, purpose)
        problems = []
        for d, managed in _purpose_dirs(ctx, purpose):
            if managed and (purpose == "update" or d.exists()):
                problem = up.trust_store_problem(str(d))
                if problem:
                    problems.append(problem)
        rows = [("verifies", PURPOSE_HELP[purpose]),
                ("key dirs", " + ".join(str(d) for d, _m in _purpose_dirs(ctx, purpose))),
                ("keys", str(len(keys))),
                ("usable", "no — %s" % "; ".join(problems) if problems else "yes")]
        rows += [(k["fingerprint"], "%s  (%s%s)" % (k["comment"] or "-", k["name"],
                                                    "" if k["managed"] else ", shipped"))
                 for k in keys]
        r.rows(purpose, rows, keys="plain")
        if problems:
            r.status = "bad"
        elif not keys:
            r.worst("warn")
        data[purpose] = {"problem": "; ".join(problems) or None,
                         "keys": [{"name": k["name"], "fingerprint": k["fingerprint"],
                                   "comment": k["comment"], "dir": k["dir"],
                                   "shipped": not k["managed"]} for k in keys]}
    if data["update"]["problem"]:
        r.note("A trust store that is not root-owned is not a trust store: "
               "whoever can add a key can mint packages this node accepts.")
    if not data["update"]["keys"]:
        r.note("No update key installed, so every update package is refused. Install "
               "one with: satom execute trust add-key <file.pub>")
    # back-compat keys for scripts that read `show trust --json`
    r.set(path=str(TRUST_DIR), problem=data["update"]["problem"],
          keys=data["update"]["keys"], purposes=data)
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
    """Install a public key into the trust store of one purpose.

    Deliberately root-only and deliberately a COPY: the key file the operator
    points at may live anywhere, but what is read must be root-owned inside
    the store. One key, one use: a key already trusted for another purpose is
    refused, so the release key can never start signing API packs (or a pack
    key update packages) by accident.
    """
    plain = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("--name", "--purpose"):
            skip = True
            continue
        if not a.startswith("--"):
            plain.append(a)
    if not plain:
        return Result("info", "trust add-key").lines("", [
            "usage: satom " + ADD_USAGE,
            "",
            "--purpose update     (default) " + PURPOSE_HELP["update"],
            "--purpose api_pack   " + PURPOSE_HELP["api_pack"],
            "--purpose knowledge  " + PURPOSE_HELP["knowledge"],
            "",
            "The .pub ships with the release, or comes from your own",
            "'sign_update_package.py genkey'. It can only VERIFY — publishing",
            "it is safe; it is the private half that must never reach a node."])
    purpose, err = _purpose_arg(args)
    if err:
        return Result("bad", "trust add-key").lines("", [err, "usage: satom " + ADD_USAGE])
    up = _up(ctx)
    if up is None:
        return Result("bad", "trust add-key").lines("", ["no package support in this build"])

    src = Path(plain[0]).expanduser()
    if not src.is_file():
        return Result("bad", "trust add-key").lines("", ["%s is not a file" % src])
    try:
        raw, comment = up.parse_public_key(src.read_text())
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "trust add-key").lines("", [str(exc)])
    fp = up.key_fingerprint(raw)
    for other in PURPOSES:
        if other != purpose and fp in {k["fingerprint"] for k in _keys_of(up, ctx, other)}:
            return Result("bad", "trust add-key").lines("", [
                "%s is already trusted for '%s'. One key, one use: a key that signs %s"
                % (fp, other, PURPOSE_HELP[other]),
                "must not also be accepted for %s. Use the key published for that purpose."
                % PURPOSE_HELP[purpose]])

    name = ""
    if "--name" in args:
        i = args.index("--name")
        if i + 1 < len(args):
            name = args[i + 1]
    slug = "".join(c for c in (name or src.stem) if c.isalnum() or c in "._-")
    if not slug:
        slug = "key"
    store = _purpose_dirs(ctx, purpose)[-1][0]
    dest = store / (slug + ".pub")

    store.mkdir(parents=True, exist_ok=True)
    chain = [store] if purpose == "update" else [store, PACK_KEY_DIR]
    for d in chain:
        os.chown(d, 0, 0)
        os.chmod(d, 0o755)
    parent = chain[-1].parent
    try:
        os.chown(parent, 0, 0)
        os.chmod(parent, 0o755)
    except OSError:
        pass

    existing = {k["fingerprint"] for k in _keys_of(up, ctx, purpose)}
    dest.write_text(up.format_public_key(raw, comment or name))
    os.chown(dest, 0, 0)
    os.chmod(dest, 0o644)

    r = Result("ok", "trust add-key")
    r.rows("installed", [("purpose", purpose), ("file", str(dest)), ("fingerprint", fp),
                         ("comment", comment or "-"),
                         ("already trusted", "yes" if fp in existing else "no")])
    problem = up.trust_store_problem(str(store))
    if problem:
        r.status = "bad"
        r.note(problem)
    else:
        r.note("Compare the fingerprint against the one published with the "
               "release before trusting it. This node now accepts %s signed by the "
               "matching private key." % PURPOSE_HELP[purpose])
    return r


def trust_remove_key(ctx, args):
    """Remove a key from an operator-managed trust store (any purpose, or the
    one named with --purpose). Keys shipped in the code tree are not removable
    here: they come and go with the release."""
    plain = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--purpose":
            skip = True
            continue
        if not a.startswith("--"):
            plain.append(a)
    if not plain:
        return Result("info", "trust remove-key").lines("", [
            "usage: satom execute trust remove-key <file-name|fingerprint> "
            "[--purpose update|api_pack|knowledge] --yes"])
    up = _up(ctx)
    if up is None:
        return Result("bad", "trust remove-key").lines("", ["no package support"])
    want = plain[0]
    only = None
    if any(a == "--purpose" or a.startswith("--purpose=") for a in args):
        only, err = _purpose_arg(args)
        if err:
            return Result("bad", "trust remove-key").lines("", [err])
    hit, shipped = [], []
    for purpose in PURPOSES:
        if only and purpose != only:
            continue
        for k in _keys_of(up, ctx, purpose):
            if k["name"] == want or k["fingerprint"] == want or k["name"] == want + ".pub":
                (hit if k["managed"] else shipped).append(dict(k, purpose=purpose))
    if not hit:
        lines = ["no removable trusted key matches %r" % want]
        if shipped:
            lines.append("%s is shipped in the code tree (%s); it is replaced by the "
                         "release, not removed here" % (want, shipped[0]["dir"]))
        return Result("bad", "trust remove-key").lines("", lines)
    if "--yes" not in args:
        r = Result("warn", "trust remove-key")
        r.rows("would remove", [(k["fingerprint"], "%s (%s)" % (k["name"], k["purpose"]))
                                for k in hit], keys="plain")
        r.note("What this key signed stops being accepted. Re-run with --yes to apply.")
        return r
    for k in hit:
        (Path(k["dir"]) / k["name"]).unlink(missing_ok=True)
    r = Result("ok", "trust remove-key")
    r.rows("removed", [(k["fingerprint"], "%s (%s)" % (k["name"], k["purpose"]))
                       for k in hit], keys="plain")
    if any(k["purpose"] == "update" for k in hit) and not up.load_trust_store(str(TRUST_DIR)):
        r.worst("warn")
        r.note("The update trust store is now empty: this node accepts no update "
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


FETCH_USAGE = "execute update fetch [--yes] [--download-only] [--feed <https-url>]"


def _feed_module():
    """``upgrade_feed.py`` from the ROOT-OWNED runner library only. This runs
    as root; loading it from the app tree would execute code the service
    account can rewrite."""
    path = RUNNER_LIB / "upgrade_feed.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("satom_upgrade_feed", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def update_fetch(ctx, args):
    """Download the newest signed package from the system-upgrade feed and
    apply it — the online alternative to download + copy + ``update package``.

    The feed (``satom-system-upgrades/latest.json``) is only an address: the
    download must match the sha256 it declares, and the package then goes
    through ``update_package`` exactly like an uploaded one (signature against
    the trust store here, and again as root by the runner).
    """
    fd = _feed_module()
    if fd is None:
        return Result("bad", "update fetch").lines("", [
            "%s/upgrade_feed.py is missing — this node's runner predates the "
            "upgrade feed." % RUNNER_LIB,
            "Refresh it with: satom execute reinstall runner"])
    url = ""
    if "--feed" in args:
        i = args.index("--feed")
        url = args[i + 1] if i + 1 < len(args) else ""
    try:
        doc = fd.fetch_feed(url)
    except fd.FeedError as exc:
        return Result("bad", "update fetch").lines("", [
            str(exc), "",
            "Offline node: download satom-update-<version>.tar.gz from the",
            "release (satom-system-upgrades/ in the repository lists them) and run",
            "  satom execute update package <file> --yes"])

    pkg = doc["package"]
    new = doc["version"]
    cur = _version(ctx)
    up = _up(ctx)
    newer = up.compare_versions(new, cur) > 0 if up else True
    rows = [("feed", doc["_feed_url"]), ("installed", cur),
            ("offered", "%s (%s)" % (new, doc.get("released") or "?")),
            ("package", "%s  %.1f MB" % (pkg["name"], pkg["size"] / 1048576.0)),
            ("sha256", pkg["sha256"])]
    if not newer:
        r = Result("ok", "update fetch")
        r.rows("", rows)
        r.note("Already on %s or newer — nothing to download." % new)
        return r
    if "--yes" not in args and "--download-only" not in args:
        r = Result("warn", "update fetch (dry run)")
        r.rows("would download and apply", rows)
        r.note("Re-run with --yes to download, verify and apply it, or with "
               "--download-only to stage it for the console.")
        return r

    uploads = ctx.app_dir / "data" / "update-uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    _chown_app(ctx, uploads)
    start = time.monotonic()

    def progress(done, total):
        print("  [ .. ] downloading %s: %d of %d MB (%s)"
              % (pkg["name"], done >> 20, total >> 20, _elapsed(time.monotonic() - start)),
              flush=True)

    try:
        path = fd.download_package(doc, uploads, progress=progress)
    except fd.FeedError as exc:
        return Result("bad", "update fetch").lines("", ["download refused: %s" % exc])
    _chown_app(ctx, path)

    if "--download-only" in args:
        r = Result("ok", "update fetch")
        r.rows("staged", rows + [("file", str(path))])
        r.note("sha256 matches the feed. Review and apply it in Software Update, "
               "or: satom execute update package %s --yes" % path)
        return r
    return update_package(ctx, [str(path)] + [a for a in args if a in
                                               ("--yes", "--no-backup")])


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


def _elapsed(seconds):
    seconds = int(max(0, seconds))
    return "%dm%02ds" % divmod(seconds, 60) if seconds >= 60 else "%ds" % seconds


def _follow(ctx, uid, target, timeout=2400, heartbeat=15, queued_warn=30):
    """Print the runner's steps as they land, and what it is doing meanwhile.

    The apply restarts the web service, so a console operator has no page to
    watch. Finished steps alone were not enough: the slow ones (database
    backup, offline pip install, migrations) printed nothing for minutes and
    the command looked hung during the very operation most likely to need
    attention. So the step in flight is printed when it starts, a heartbeat
    line repeats every ``heartbeat`` seconds while it runs, and a request the
    runner never picks up is called out instead of waited on in silence.
    """
    path = ctx.app_dir / "data" / "update-status" / (uid + ".json")
    say = (lambda *a: None) if ctx.json_mode else (lambda m: print(m, flush=True))
    say("Queued as %s. Waiting for the update runner (satom-updater) to start..."
        % uid)
    t0 = time.time()
    deadline = t0 + timeout
    seen = 0
    state = "queued"
    steps = []
    current, current_t = None, t0
    last_beat = t0
    warned_queued = False
    while time.time() < deadline:
        try:
            d = json.loads(path.read_text())
        except Exception:  # noqa: BLE001
            time.sleep(2)
            continue
        steps = d.get("steps") or []
        for st_ in steps[seen:]:
            say("  %s %s%s" % ("[ ok ]" if st_.get("ok") else "[FAIL]",
                               st_.get("name", ""),
                               (" — " + st_["detail"]) if st_.get("detail") else ""))
        if len(steps) > seen:
            last_beat = current_t = time.time()
        seen = len(steps)
        state = d.get("state") or "running"
        if state in ("success", "failed"):
            break
        name = (d.get("current") or {}).get("name")
        if name and name != current:
            say("  [ .. ] %s ..." % name)
            last_beat = current_t = time.time()
        current = name
        now_ = time.time()
        if state == "queued" and not warned_queued and now_ - t0 >= queued_warn:
            warned_queued = True
            say("  [WARN] still queued after %s — the runner has not picked the "
                "request up. Check: systemctl status satom-updater.path"
                % _elapsed(now_ - t0))
        elif state != "queued" and now_ - last_beat >= heartbeat:
            last_beat = now_
            say("         %s (%s)" % (
                ("still running: %s" % current) if current
                else "working", _elapsed(now_ - current_t)))
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
