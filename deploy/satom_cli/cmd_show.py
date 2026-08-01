"""'show' — dump configuration and the privilege model. Read-only, any user."""
from .context import UNITS, run
from .render import Result

# Substrings that mark a value as secret. Deliberately broad: showing one masked
# value that did not need masking costs nothing; leaking one key costs a
# rotation. The repo history already contains a FERNET_KEY that was committed
# and deleted — that is what this list exists to never repeat.
SECRET_HINTS = ("KEY", "SECRET", "PASSWORD", "PASS", "TOKEN", "URI", "DSN", "CRED")


def config(ctx, args):
    if not ctx.env_readable:
        r = Result("warn", "configuration — .env unreadable", exit_code=4)
        r.lines("why", [
            ".env is 640 root:%s ON PURPOSE — the app only reads it, so a write" % ctx.app_user,
            "primitive in the web worker cannot rewrite its own secrets.",
            "",
            "You are %s. Re-run as root to see the (redacted) values." % ctx.user,
        ])
        return r
    r = Result("info", "configuration — %s/.env (secrets redacted)" % ctx.app_dir)
    rows = []
    for k in sorted(ctx.env):
        v = ctx.env[k]
        if any(h in k.upper() for h in SECRET_HINTS):
            v = "<redacted: %d chars>" % len(v)
        rows.append((k, v))
    r.rows("", rows)
    r.note("Values are redacted by pattern. 'satom' never prints a secret, and "
           "no command accepts one on the command line (it would land in your "
           "shell history and in the process table).")
    return r


def units(ctx, args):
    r = Result("info", "systemd units")
    rows = []
    for alias, unit in sorted(UNITS.items()):
        st = ctx.unit_state(alias)
        rows.append((alias, "%-26s %s  (%s)" % (unit, st["enabled"], st["active"])))
    r.rows("alias -> unit", rows)
    r.lines("notes", [
        "'updater' (satom-updater.path/.service) is the privileged root runner.",
        "It is intentionally NOT restartable from this CLI: a verb that touches",
        "the privileged runner is a verb that re-enters the privilege boundary.",
    ])
    return r


def privilege(ctx, args):
    """The model, printed where the operator is standing. This text is the
    reason the CLI can be a root tool without weakening the service account."""
    r = Result("info", "privilege model")
    r.rows("right now", [
        ("you", "%s (uid %s)" % (ctx.user, ctx.uid)),
        ("effective", "root — every verb available" if ctx.is_root
         else "unprivileged — 'get', 'show' and 'diagnose' only"),
        ("service account", ctx.app_user),
    ])
    r.lines("the rule", [
        "1. The APP runs as '%s'. Its sudo rights are exactly two commands:" % ctx.app_user,
        "     /usr/sbin/nginx -t",
        "     /usr/bin/systemctl reload nginx",
        "   That is all cert activation needs. Nothing else is granted.",
        "",
        "2. This CLI is a ROOT tool for a HUMAN. Reinstalling a venv, writing",
        "   unit files or installing packages IS root — there is no subset that",
        "   is 'a bit less than root' (a .deb runs its own maintainer scripts as",
        "   root, so permission to install packages IS root).",
        "",
        "3. Therefore: NEVER add 'satom' to %s's sudoers." % ctx.app_user,
        "   NOPASSWD on this binary would equal NOPASSWD: ALL, and would turn a",
        "   compromised web worker into root — undoing the whole model.",
        "",
        "4. The operator uses their OWN named sudo. That buys: no root password",
        "   handed out, a nominal audit trail (journalctl _COMM=sudo), temporary",
        "   privilege, and — critically — what keeps running afterwards is not root.",
    ])
    r.lines("integrity", [
        "The binary lives at /usr/local/sbin/satom (root:root 0755) and its code",
        "at /usr/local/lib/satom-cli/ (root:root). Both are COPIES.",
        "It never executes from %s, because that tree is writable by the" % ctx.app_dir,
        "service account: a compromised worker could then rewrite what you are",
        "about to run with sudo. Verify with 'diagnose privilege'.",
    ])
    return r


def sudoers(ctx, args):
    """Print the rule to hand to whoever administers the box. Needs no
    privilege and changes nothing — that is the point: you can produce it from
    the account that does not yet have rights."""
    acct = args[0] if args else "satomadmin"
    if not acct.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return Result("bad", "invalid account name: %r" % acct, exit_code=2)
    r = Result("info", "sudoers rule for operator account '%s'" % acct)
    r.lines("/etc/sudoers.d/satom-operator", [
        "# SATOM operator CLI. Install with:",
        "#   visudo -cf /etc/sudoers.d/satom-operator && chmod 0440 /etc/sudoers.d/satom-operator",
        "# The path is FIXED and the target must be root:root — if the operator can",
        "# write /usr/local/sbin/satom, this rule equals NOPASSWD: ALL.",
        "%s ALL=(root) /usr/local/sbin/satom" % acct,
    ])
    r.lines("what this grants", [
        "Everything under 'execute' and 'config': service control, venv and unit",
        "reinstall, queued code/pip updates, promote, cert operations.",
        "It does NOT grant a shell: the CLI has no 'run arbitrary command' verb,",
        "and package installs go through the curated allowlist, not free-form pip.",
    ])
    r.note("Do NOT grant this to %s (the service account). See 'show privilege'."
           % ctx.app_user)
    return r


def version(ctx, args):
    r = Result("info", "SATOM %s" % ctx.version())
    rc, py, _ = run(["python3", "-V"])
    r.rows("", [
        ("app version", ctx.version()),
        ("git head", ctx.git_head()),
        ("app dir", str(ctx.app_dir)),
        ("cli", "%s (root-owned copy)" % _cli_home()),
        ("python", py or "?"),
        ("node", "%s (%s)" % (ctx.host, ctx.role)),
    ])
    return r


def _cli_home():
    import os
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
