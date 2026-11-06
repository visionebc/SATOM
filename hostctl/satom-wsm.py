#!/usr/bin/python3
# SPDX-License-Identifier: Elastic-2.0
"""satom-wsm -- the Web Server Manager helper SATOM runs on a managed server.

WHY THIS EXISTS
The Web Server Manager (Linux ADOM) administers a Linux web server over SSH
WITH THE IDENTITY OF THE PERSON WHO SIGNED IN: an operator adds their own SSH
account (password, or key with an optional passphrase) and every operation
runs as that account. When the account cannot do something, SATOM repeats it
through ``sudo`` -- with the account's own password, or a NOPASSWD rule the
server's administrator wrote -- exactly as the operator chose on the
credential. Nothing is installed on the server for this: SATOM sends this
program over the SSH session it opened, the server's own ``python3`` runs it
once, and it is gone when the operation ends.

This file is NOT installed and NOT a forced command (that is
``satom-webctl.py``, the restricted agent mode, which this helper reuses:
SATOM sends both files concatenated, webctl first). Whatever the server's
policy lets the account do, this helper can do -- the account's permissions
and the server's sudoers ARE the boundary, by design.

PROTOCOL (on stdin, after the bootstrap SATOM passes to ``python3 -c``)
    {"op": "fs.list", "args": {"path": "/var/www"}}
    -> {"ok": true, "result": {...}, "who": {"user": "eric", "uid": 1000}}
    -> {"ok": false, "error": "<code>", "detail": "<text>", "who": {...}}

WHAT IT GUARANTEES
* No shell, ever: every program runs from an argument list; every name a
  request carries (package, unit, user, path) is checked against a strict
  pattern before it reaches one.
* A file it overwrites is kept first (history), a configuration it changes is
  backed up, tested by the server's own tool (``nginx -t``,
  ``apachectl configtest``, ``sshd -t``) and restored when the test fails.
* Its answer carries no control characters and no bidi marks; secrets it is
  handed (a private key to import, a password to set) are never echoed.

Python 3.6+ standard library only (SUSE 15 ships 3.6).
"""
import base64
import datetime
import fnmatch
import grp
import hashlib
import http.client
import io
import json
import os
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

if "op_vhosts_list" not in globals():   # imported on its own (tests, --selftest)
    import importlib.util as _ilu
    _wpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "satom-webctl.py")
    _wspec = _ilu.spec_from_file_location("satom_webctl", _wpath)
    _wmod = _ilu.module_from_spec(_wspec)
    _wspec.loader.exec_module(_wmod)
    globals().update({k: v for k, v in vars(_wmod).items()
                      if not k.startswith("__") and k not in ("main",)})

WSM_VERSION = "2.0.0"
MAX_FILE = 8 * 1024 * 1024
MAX_LIST = 5000
MAX_OUT = 256 * 1024
PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,127}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:\\-]{0,199}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$")
MODE_RE = re.compile(r"^[0-7]{3,4}$")
PORT_RE = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?$")
IP_RE = re.compile(r"^[0-9A-Fa-f.:]{2,45}(/[0-9]{1,3})?$")
HOST_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})$")
CTRL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PROTECTED = ("/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
             "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/usr", "/var",
             "/var/www", "/srv/www", "/var/log", "/var/lib", "/tmp")
INTERPRETERS = {"bash": "bash", "sh": "sh", "python": "python3", "php": "php", "perl": "perl"}
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SSHD_KEYS = ("Port", "PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication",
             "KbdInteractiveAuthentication", "ChallengeResponseAuthentication",
             "MaxAuthTries", "LoginGraceTime", "AllowUsers", "AllowGroups", "DenyUsers",
             "DenyGroups", "X11Forwarding", "AllowTcpForwarding", "ClientAliveInterval",
             "ClientAliveCountMax", "PermitEmptyPasswords", "UsePAM", "Banner")


# ── small helpers ───────────────────────────────────────────────────────────

def clean(value, limit=None):
    """Text as it may leave this program: no control characters but tab and
    newline, no ANSI colour codes, no bidi or zero-width marks."""
    s = ANSI_RE.sub("", str(value if value is not None else ""))
    s = CTRL_RE.sub("?", s)
    return s[-limit:] if limit and len(s) > limit else s


def run(argv, *, timeout=120, stdin=None, env=None, cwd=None, limit=MAX_OUT):
    """(rc, stdout, stderr) of an argument list; never a shell. A missing
    program is rc 127, a timeout rc 124."""
    e = dict(os.environ)
    e.update({"LC_ALL": "C", "LANG": "C", "SYSTEMD_PAGER": "", "PAGER": "cat",
              "SYSTEMD_COLORS": "0", "DEBIAN_FRONTEND": "noninteractive"})
    if env:
        e.update(env)
    try:
        p = subprocess.run(list(argv), input=stdin, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, env=e, cwd=cwd)
    except FileNotFoundError:
        return 127, "", "%s: not installed" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s: no answer within %ds" % (argv[0], timeout)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    return p.returncode, clean(out, limit), clean(err, limit)


def which(name):
    for d in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which(name) or ""


def need(cond, code, detail):
    if not cond:
        raise Refused(code, detail)


def is_root():
    return os.geteuid() == 0


def require_root(what):
    if not is_root():
        raise Refused("permission_denied", "%s needs administrator rights" % what)


def _abs(path, *, must_exist=True):
    """A normalized absolute path or Refused. Symlinks are NOT followed here:
    the account's own permissions decide what it may touch."""
    need(isinstance(path, str) and path.startswith("/") and "\x00" not in path
         and len(path) <= 4096, "bad_path", "an absolute path is expected")
    p = os.path.normpath(path)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    for bad in ("/proc", "/sys", "/dev"):
        need(not (p == bad or p.startswith(bad + "/")), "bad_path",
             "%s is not a place for files" % bad)
    if must_exist:
        need(os.path.lexists(p), "not_found", "no such file or directory")
    return p


def _name(value, rx, what):
    need(isinstance(value, str) and bool(rx.match(value)), "bad_" + what,
         "invalid %s" % what.replace("_", " "))
    return value


def _names(values, rx, what, most=50):
    need(isinstance(values, list) and 0 < len(values) <= most, "bad_" + what,
         "1 to %d %s" % (most, what))
    return [_name(v, rx, what) for v in values]


def _state_dir():
    if is_root():
        base = "/var/lib/satom-wsm"
    else:
        base = os.path.join(os.path.expanduser("~"), ".local", "share", "satom-wsm")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return base


def _owner(uid, gid):
    try:
        u = pwd.getpwuid(uid).pw_name
    except KeyError:
        u = str(uid)
    try:
        g = grp.getgrgid(gid).gr_name
    except KeyError:
        g = str(gid)
    return clean(u, 64), clean(g, 64)


def _write_file(path, data, mode=None, owner=None):
    d = os.path.dirname(path) or "/"
    fd, tmp = tempfile.mkstemp(prefix=".satom-wsm-", dir=d)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, mode if mode is not None else 0o644)
        if owner is not None and is_root():
            os.chown(tmp, owner[0], owner[1])
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── host facts ──────────────────────────────────────────────────────────────

def os_release():
    info = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    info[k] = v.strip().strip('"')
    except OSError:
        pass
    family = ""
    for i in (info.get("ID", "") + " " + info.get("ID_LIKE", "")).split():
        if i in ("debian", "ubuntu"):
            family = "debian"
        elif i in ("rhel", "centos", "fedora", "rocky", "almalinux"):
            family = "rhel"
        elif i.startswith("suse") or i in ("sles", "opensuse", "opensuse-leap"):
            family = "suse"
        if family:
            break
    return {"id": clean(info.get("ID", ""), 40), "name": clean(info.get("PRETTY_NAME", ""), 120),
            "version": clean(info.get("VERSION_ID", ""), 40), "family": family}


def pkg_manager():
    for name in ("apt-get", "dnf", "zypper", "yum"):
        if which(name):
            return {"apt-get": "apt"}.get(name, name)
    return ""


def detect_conf():
    """The satom-webctl configuration this server would have, found from its
    layout -- so the vhost and certificate operations of the agent run here
    unchanged, as the signed-in account."""
    fam = os_release()["family"]
    systemctl = which("systemctl") or "systemctl"
    servers = {}
    nginx = which("nginx")
    if nginx:
        if os.path.isdir("/etc/nginx/sites-available"):
            servers["nginx"] = {"layout": "debian", "available": "/etc/nginx/sites-available",
                                "enabled": "/etc/nginx/sites-enabled"}
        elif fam == "suse" and os.path.isdir("/etc/nginx/vhosts.d"):
            servers["nginx"] = {"layout": "confd", "available": "/etc/nginx/vhosts.d"}
        elif os.path.isdir("/etc/nginx/conf.d"):
            servers["nginx"] = {"layout": "confd", "available": "/etc/nginx/conf.d"}
        if "nginx" in servers:
            servers["nginx"].update({"test": [nginx, "-t"],
                                     "reload": [systemctl, "reload", "nginx.service"],
                                     "unit": "nginx.service"})
    apachectl = which("apache2ctl") or which("apachectl")
    if apachectl:
        if os.path.isdir("/etc/apache2/sites-available"):
            spec = {"layout": "debian", "available": "/etc/apache2/sites-available",
                    "enabled": "/etc/apache2/sites-enabled", "unit": "apache2.service"}
        elif os.path.isdir("/etc/httpd/conf.d"):
            spec = {"layout": "confd", "available": "/etc/httpd/conf.d", "unit": "httpd.service"}
        elif os.path.isdir("/etc/apache2/vhosts.d"):
            spec = {"layout": "confd", "available": "/etc/apache2/vhosts.d",
                    "unit": "apache2.service"}
        else:
            spec = None
        if spec:
            spec.update({"test": [apachectl, "configtest"],
                         "reload": [systemctl, "reload", spec["unit"]]})
            servers["apache"] = spec
    state = _state_dir()
    return {"servers": servers, "roots": ["/"], "backup_dir": os.path.join(state, "backups"),
            "log": os.path.join(state, "wsm.log"), "max_file_bytes": MAX_FILE,
            "max_list": MAX_LIST, "keep_backups": 300, "read_only": False,
            "command_timeout": 120, "cert_dir": "/etc/satom-webctl/certs", "openssl": "",
            "expiring_days": 30}


def php_versions():
    found = []
    for pattern_dir in ("/run/php", "/var/run/php", "/run/php-fpm", "/var/run/php-fpm"):
        try:
            for f in sorted(os.listdir(pattern_dir)):
                if f.endswith(".sock"):
                    m = re.search(r"(\d+\.\d+)", f)
                    found.append({"version": m.group(1) if m else "",
                                  "socket": os.path.join(pattern_dir, f)})
        except OSError:
            pass
    php = which("php")
    cli = ""
    if php:
        rc, out, _ = run([php, "-r", "echo PHP_VERSION;"], timeout=15)
        cli = out.strip()[:20] if rc == 0 else ""
    return {"cli": cli, "fpm": found[:20]}


def firewall_kind():
    if which("ufw"):
        return "ufw"
    if which("firewall-cmd"):
        return "firewalld"
    return ""


def op_whoami(conf, args):
    u = pwd.getpwuid(os.geteuid())
    groups = []
    for gid in os.getgroups():
        try:
            groups.append(clean(grp.getgrgid(gid).gr_name, 64))
        except KeyError:
            groups.append(str(gid))
    sudo = {"installed": bool(which("sudo")), "nopasswd": False, "rules": ""}
    if sudo["installed"] and not is_root():
        rc, out, err = run(["sudo", "-n", "-l"], timeout=15, limit=4000)
        sudo["nopasswd"] = rc == 0 and "NOPASSWD" in out
        sudo["rules"] = out[-2000:] if rc == 0 else clean(err, 300)
    web = {}
    for key, spec in conf["servers"].items():
        web[key] = {"layout": spec["layout"], "available": spec["available"],
                    "unit": spec.get("unit", "")}
    return {"user": clean(u.pw_name, 64), "uid": u.pw_uid, "gid": u.pw_gid,
            "home": clean(u.pw_dir, 256), "shell": clean(u.pw_shell, 128),
            "groups": sorted(set(groups))[:100], "root": is_root(),
            "hostname": clean(socket.gethostname(), 128), "os": os_release(),
            "pkg_manager": pkg_manager(), "systemd": bool(which("systemctl")),
            "web": web, "php": php_versions(), "firewall": firewall_kind(),
            "certbot": bool(which("certbot")), "sudo": sudo,
            "python": "%d.%d.%d" % sys.version_info[:3], "helper": WSM_VERSION}


# ── file manager ────────────────────────────────────────────────────────────

def _entry_of(path, name):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        kind = "link"
    elif stat.S_ISDIR(st.st_mode):
        kind = "dir"
    elif stat.S_ISREG(st.st_mode):
        kind = "file"
    else:
        kind = "other"
    o, g = _owner(st.st_uid, st.st_gid)
    e = {"name": name, "type": kind, "size": st.st_size if kind == "file" else 0,
         "mtime": int(st.st_mtime), "mode": "%04o" % stat.S_IMODE(st.st_mode),
         "owner": o, "group": g}
    if kind == "link":
        try:
            e["target"] = clean(os.readlink(path), 1024)
            e["target_dir"] = os.path.isdir(path)
        except OSError:
            e["target"] = ""
    return e


def op_fs_list(conf, args):
    path = _abs(args.get("path") or "/")
    need(os.path.isdir(path), "not_a_dir", "not a directory")
    hidden = bool(args.get("hidden"))
    entries, skipped = [], 0
    names = sorted(os.listdir(path))
    for name in names:
        if not hidden and name.startswith("."):
            continue
        if CTRL_RE.search(name):
            skipped += 1
            continue
        try:
            entries.append(_entry_of(os.path.join(path, name), name))
        except OSError:
            skipped += 1
        if len(entries) >= MAX_LIST:
            break
    entries.sort(key=lambda e: (e["type"] != "dir" and not e.get("target_dir"), e["name"].lower()))
    return {"path": path, "parent": os.path.dirname(path) if path != "/" else "",
            "entries": entries, "truncated": len(entries) >= MAX_LIST, "skipped": skipped,
            "writable": os.access(path, os.W_OK)}


def op_fs_stat(conf, args):
    path = _abs(args.get("path"))
    e = _entry_of(path, os.path.basename(path) or "/")
    e["path"] = path
    e["readable"] = os.access(path, os.R_OK)
    e["writable"] = os.access(path, os.W_OK)
    return e


TEXT_EXT = (".txt", ".md", ".html", ".htm", ".css", ".js", ".json", ".php", ".py", ".sh",
            ".conf", ".ini", ".yml", ".yaml", ".xml", ".htaccess", ".log", ".csv", ".env")


def _is_text(data):
    if b"\x00" in data[:8192]:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def op_fs_read(conf, args):
    path = _abs(args.get("path"))
    need(os.path.isfile(path), "not_a_file", "not a regular file")
    size = os.path.getsize(path)
    limit = min(int(args.get("max") or MAX_FILE), MAX_FILE)
    need(size <= limit, "too_large", "the file is %d bytes; this view opens up to %d"
         % (size, limit))
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    out = {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
           "mode": "%04o" % stat.S_IMODE(os.stat(path).st_mode)}
    if args.get("text", True) and _is_text(data):
        text = data.decode("utf-8")
        if CTRL_RE.search(text.replace("\r", "")):
            out.update({"binary": True, "content_b64": base64.b64encode(data).decode("ascii")})
        else:
            out.update({"binary": False, "content": text})
    else:
        out.update({"binary": True, "content_b64": base64.b64encode(data).decode("ascii")})
    return out


def _history_dir(path):
    d = os.path.join(_state_dir(), "history",
                     hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:20])
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        with open(os.path.join(d, "PATH"), "w") as fh:
            fh.write(path)
    except OSError:
        pass
    return d


def keep_version(path, keep=25):
    """Copy the current content of ``path`` into its history; '' if none."""
    if not os.path.isfile(path):
        return ""
    if os.path.getsize(path) > 32 * 1024 * 1024:
        return ""
    d = _history_dir(path)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
    dest = os.path.join(d, stamp)
    shutil.copy2(path, dest)
    os.chmod(dest, 0o600)
    versions = sorted(f for f in os.listdir(d) if f[:1].isdigit())
    for old in versions[:-keep]:
        try:
            os.unlink(os.path.join(d, old))
        except OSError:
            pass
    return stamp


def op_fs_write(conf, args):
    path = _abs(args.get("path"), must_exist=False)
    if "content_b64" in args:
        try:
            data = base64.b64decode(args["content_b64"], validate=True)
        except (ValueError, TypeError):
            raise Refused("bad_content", "content_b64 is not base64")
    else:
        need(isinstance(args.get("content"), str), "bad_content", "content must be text")
        data = args["content"].encode("utf-8")
    need(len(data) <= MAX_FILE, "too_large", "files up to %d bytes" % MAX_FILE)
    exists = os.path.lexists(path)
    if exists:
        need(not args.get("create_only"), "exists", "a file with that name already exists")
        need(os.path.isfile(path), "not_a_file", "not a regular file")
        with open(path, "rb") as fh:
            old = fh.read()
        base = args.get("base_sha256")
        if base and base != hashlib.sha256(old).hexdigest():
            raise Refused("conflict", "the file changed since it was opened")
        st = os.stat(path)
        mode, owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
        version = keep_version(path)
    else:
        need(os.path.isdir(os.path.dirname(path)), "not_found", "the folder does not exist")
        mode, owner, version = None, None, ""
        if args.get("mode"):
            mode = int(_name(str(args["mode"]), MODE_RE, "mode"), 8)
    _write_file(path, data, mode, owner)
    return {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "history": version, "created": not exists}


def op_fs_mkdir(conf, args):
    path = _abs(args.get("path"), must_exist=False)
    need(not os.path.lexists(path), "exists", "already exists")
    if args.get("parents"):
        os.makedirs(path, mode=0o755)
    else:
        os.mkdir(path, 0o755)
    return {"path": path}


def _not_protected(path):
    need(os.path.normpath(path) not in PROTECTED, "protected",
         "%s is a system folder: it cannot be moved or deleted from here" % path)


def op_fs_move(conf, args):
    src = _abs(args.get("path"))
    dst = _abs(args.get("to"), must_exist=False)
    _not_protected(src)
    if os.path.isdir(dst) and not os.path.islink(dst):
        dst = os.path.join(dst, os.path.basename(src))
    need(not os.path.lexists(dst) or args.get("overwrite"), "exists",
         "the destination already exists")
    need(not (dst + "/").startswith(src.rstrip("/") + "/"), "bad_path",
         "a folder cannot move inside itself")
    shutil.move(src, dst)
    return {"path": dst}


def op_fs_copy(conf, args):
    src = _abs(args.get("path"))
    dst = _abs(args.get("to"), must_exist=False)
    if os.path.isdir(dst) and not os.path.islink(dst):
        dst = os.path.join(dst, os.path.basename(src))
    need(not os.path.lexists(dst), "exists", "the destination already exists")
    need(not (dst + "/").startswith(src.rstrip("/") + "/"), "bad_path",
         "a folder cannot be copied inside itself")
    if os.path.isdir(src) and not os.path.islink(src):
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)
    return {"path": dst}


def _tree_size(path, cap):
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
            if total > cap:
                return total
    return total


def op_fs_delete(conf, args):
    paths = args.get("paths")
    need(isinstance(paths, list) and 0 < len(paths) <= 200, "bad_paths", "1 to 200 paths")
    paths = [_abs(p) for p in paths]
    for p in paths:
        _not_protected(p)
        if os.path.isdir(p) and not os.path.islink(p):
            need(bool(args.get("recursive")) or not os.listdir(p), "not_empty",
                 "%s is not empty: tick 'including everything inside'" % p)
    cap = 64 * 1024 * 1024
    size = sum(_tree_size(p, cap) if os.path.isdir(p) and not os.path.islink(p)
               else os.lstat(p).st_size for p in paths)
    bk = ""
    if size <= cap:
        bdir = os.path.join(_state_dir(), "trash")
        os.makedirs(bdir, mode=0o700, exist_ok=True)
        bk = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%f") + ".tar.gz"
        with tarfile.open(os.path.join(bdir, bk), "w:gz") as tar:
            for p in paths:
                tar.add(p, arcname=p.lstrip("/"), recursive=True)
        os.chmod(os.path.join(bdir, bk), 0o600)
    for p in paths:
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.unlink(p)
    return {"deleted": paths, "backup": bk, "backup_dir": os.path.join(_state_dir(), "trash")
            if bk else "", "bytes": size}


def _walk_paths(paths, recursive):
    for p in paths:
        yield p
        if recursive and os.path.isdir(p) and not os.path.islink(p):
            for root, dirs, files in os.walk(p):
                for n in dirs + files:
                    yield os.path.join(root, n)


def op_fs_chmod(conf, args):
    paths = [_abs(p) for p in (args.get("paths") or [])][:200]
    need(paths, "bad_paths", "no path")
    mode = int(_name(str(args.get("mode") or ""), MODE_RE, "mode"), 8)
    dmode = args.get("dir_mode")
    dmode = int(_name(str(dmode), MODE_RE, "mode"), 8) if dmode else None
    count = 0
    for p in _walk_paths(paths, bool(args.get("recursive"))):
        if os.path.islink(p):
            continue
        os.chmod(p, dmode if (dmode is not None and os.path.isdir(p)) else mode)
        count += 1
    return {"changed": count}


def op_fs_chown(conf, args):
    paths = [_abs(p) for p in (args.get("paths") or [])][:200]
    need(paths, "bad_paths", "no path")
    owner, group = args.get("owner") or "", args.get("group") or ""
    uid = pwd.getpwnam(_name(owner, USER_RE, "user")).pw_uid if owner else -1
    gid = grp.getgrnam(_name(group, USER_RE, "group")).gr_gid if group else -1
    need(uid != -1 or gid != -1, "bad_owner", "an owner, a group or both")
    count = 0
    for p in _walk_paths(paths, bool(args.get("recursive"))):
        os.lchown(p, uid, gid)
        count += 1
    return {"changed": count}


def op_fs_search(conf, args):
    base = _abs(args.get("path") or "/")
    need(os.path.isdir(base), "not_a_dir", "search in a folder")
    pattern = args.get("name") or "*"
    need(isinstance(pattern, str) and 0 < len(pattern) <= 200, "bad_pattern", "name pattern")
    needle = args.get("content") or ""
    need(isinstance(needle, str) and len(needle) <= 200, "bad_pattern", "content text")
    needle_b = needle.encode("utf-8")
    most = min(int(args.get("max") or 300), 1000)
    depth_cap = min(int(args.get("depth") or 12), 30)
    hits, scanned = [], 0
    start = time.time()
    bdepth = base.rstrip("/").count("/")
    for root, dirs, files in os.walk(base):
        if root.count("/") - bdepth >= depth_cap:
            dirs[:] = []
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))
                   and os.path.join(root, d) not in ("/proc", "/sys", "/dev")]
        for n in files + ([d for d in dirs] if not needle else []):
            if not fnmatch.fnmatch(n, pattern) or CTRL_RE.search(n):
                continue
            p = os.path.join(root, n)
            line = ""
            if needle:
                try:
                    if os.path.getsize(p) > 4 * 1024 * 1024:
                        continue
                    with open(p, "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                scanned += 1
                i = data.find(needle_b)
                if i < 0:
                    continue
                ls = data.rfind(b"\n", 0, i) + 1
                le = data.find(b"\n", i)
                line = clean(data[ls:le if le > 0 else len(data)].decode("utf-8", "replace"), 300)
            hits.append({"path": clean(p, 4096), "line": line,
                         "type": "dir" if os.path.isdir(p) else "file"})
            if len(hits) >= most:
                return {"hits": hits, "truncated": True, "scanned": scanned}
        if time.time() - start > 60:
            return {"hits": hits, "truncated": True, "scanned": scanned}
    return {"hits": hits, "truncated": False, "scanned": scanned}


def op_fs_archive(conf, args):
    paths = [_abs(p) for p in (args.get("paths") or [])][:500]
    need(paths, "bad_paths", "no path")
    dest = _abs(args.get("dest"), must_exist=False)
    need(not os.path.lexists(dest), "exists", "the archive already exists")
    fmt = args.get("format") or ("zip" if dest.endswith(".zip") else "tar.gz")
    need(fmt in ("zip", "tar.gz"), "bad_format", "zip or tar.gz")
    common = os.path.dirname(paths[0]) if len(paths) == 1 else os.path.commonpath(paths)
    if fmt == "zip":
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for p in _walk_paths(paths, True):
                if os.path.islink(p):
                    continue
                z.write(p, os.path.relpath(p, common))
    else:
        with tarfile.open(dest, "w:gz") as tar:
            for p in paths:
                tar.add(p, arcname=os.path.relpath(p, common))
    return {"path": dest, "size": os.path.getsize(dest)}


MAX_EXTRACT_BYTES = 4 * 1024 ** 3
MAX_EXTRACT_FILES = 50000


def _safe_member(dest, name):
    need(not name.startswith("/") and "\x00" not in name, "unsafe_archive",
         "the archive holds an absolute path: refused")
    target = os.path.normpath(os.path.join(dest, name))
    need(target == dest or target.startswith(dest.rstrip("/") + "/"), "unsafe_archive",
         "the archive holds a path that leaves the destination ('..'): refused")
    return target


def op_fs_extract(conf, args):
    src = _abs(args.get("path"))
    dest = _abs(args.get("dest") or os.path.dirname(src), must_exist=False)
    os.makedirs(dest, exist_ok=True)
    dest = os.path.realpath(dest)
    count, total = 0, 0
    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            infos = z.infolist()
            need(len(infos) <= MAX_EXTRACT_FILES, "too_large", "too many files in the archive")
            for i in infos:
                _safe_member(dest, i.filename)
                total += i.file_size
                need(total <= MAX_EXTRACT_BYTES, "too_large", "the archive expands past 4 GiB")
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    raise Refused("unsafe_archive", "the archive holds a symbolic link: refused")
            for i in infos:
                z.extract(i, dest)
                count += 1
    elif tarfile.is_tarfile(src):
        with tarfile.open(src) as tar:
            members = tar.getmembers()
            need(len(members) <= MAX_EXTRACT_FILES, "too_large", "too many files in the archive")
            for m in members:
                _safe_member(dest, m.name)
                need(m.isfile() or m.isdir(), "unsafe_archive",
                     "the archive holds links or device files (%s): refused" % clean(m.name, 200))
                total += m.size
                need(total <= MAX_EXTRACT_BYTES, "too_large", "the archive expands past 4 GiB")
            for m in members:
                m.mode &= 0o777
                if not is_root():
                    m.uid = m.gid = -1
                tar.extract(m, dest, set_attrs=is_root())
                count += 1
    elif src.endswith(".gz"):
        import gzip
        out = os.path.join(dest, os.path.basename(src)[:-3])
        need(not os.path.lexists(out), "exists", "%s already exists" % out)
        with gzip.open(src, "rb") as fi, open(out, "wb") as fo:
            while True:
                chunk = fi.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                need(total <= MAX_EXTRACT_BYTES, "too_large", "expands past 4 GiB")
                fo.write(chunk)
        count = 1
    else:
        raise Refused("bad_format", "not a zip, tar or gzip file")
    return {"dest": dest, "files": count, "bytes": total}


def op_fs_history(conf, args):
    path = _abs(args.get("path"), must_exist=False)
    d = _history_dir(path)
    out = []
    for v in sorted((f for f in os.listdir(d) if f[:1].isdigit()), reverse=True):
        st = os.stat(os.path.join(d, v))
        out.append({"version": v, "size": st.st_size, "mtime": int(st.st_mtime)})
    return {"path": path, "versions": out}


def op_fs_restore(conf, args):
    path = _abs(args.get("path"), must_exist=False)
    v = args.get("version") or ""
    need(re.match(r"^[0-9T]{15,30}$", v or ""), "bad_version", "unknown version")
    src = os.path.join(_history_dir(path), v)
    need(os.path.isfile(src), "not_found", "no such version")
    with open(src, "rb") as fh:
        data = fh.read()
    if os.path.isfile(path):
        st = os.stat(path)
        keep = keep_version(path)
        _write_file(path, data, stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid))
    else:
        keep = ""
        _write_file(path, data, 0o644)
    return {"path": path, "restored": v, "history": keep}


def op_fs_version(conf, args):
    path = _abs(args.get("path"), must_exist=False)
    v = args.get("version") or ""
    need(re.match(r"^[0-9T]{15,30}$", v or ""), "bad_version", "unknown version")
    src = os.path.join(_history_dir(path), v)
    need(os.path.isfile(src), "not_found", "no such version")
    with open(src, "rb") as fh:
        data = fh.read(MAX_FILE + 1)
    need(len(data) <= MAX_FILE, "too_large", "version too large to show")
    if _is_text(data):
        return {"path": path, "version": v, "content": clean(data.decode("utf-8"))}
    return {"path": path, "version": v, "content_b64": base64.b64encode(data).decode("ascii")}


# ── virtual hosts: richer create, snippets, HTTP check ──────────────────────

def _php_include(family):
    if os.path.isfile("/etc/nginx/snippets/fastcgi-php.conf"):
        return "        include snippets/fastcgi-php.conf;\n"
    return ("        try_files $uri =404;\n        include fastcgi_params;\n"
            "        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")


HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
HEADER_VALUE_RE = re.compile(r"^[^\"\\\x00-\x1f\x7f;{}]{0,500}$")
SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN",
                    "Referrer-Policy": "strict-origin-when-cross-origin"}


def op_vhost_create2(conf, args):
    """A new virtual host with the Web Server Manager's options. Same rules as
    satom-webctl's create: write, test, restore on failure, reload."""
    server = args.get("server")
    spec = server_spec(conf, server)
    name = args.get("name")
    if spec["layout"] == "confd" and isinstance(name, str) and not name.endswith(".conf"):
        name = name + ".conf"
    name = _check_name(spec, name)
    main, other = _vhost_paths(spec, name)
    need(not (os.path.lexists(main) or os.path.lexists(other)), "exists",
         "a virtual host with that name already exists")
    names = args.get("server_names") or []
    need(isinstance(names, list) and 0 < len(names) <= 20
         and all(isinstance(n, str) and SERVER_NAME_RE.match(n) for n in names),
         "bad_server_names", "1 to 20 host names")
    kind = args.get("kind") or "static"
    need(kind in ("static", "php", "proxy"), "bad_kind", "static, php or proxy")
    docroot = args.get("docroot") or ""
    need(isinstance(docroot, str) and SAFE_PATH_RE.match(docroot) and ".." not in docroot,
         "bad_docroot", "an absolute document root path")
    index = args.get("index") or ("index.php index.html" if kind == "php" else "index.html index.htm")
    need(re.match(r"^[A-Za-z0-9._ -]{1,200}$", index), "bad_index", "index file names")
    upstream = args.get("proxy_to") or ""
    if kind == "proxy":
        need(re.match(r"^https?://[A-Za-z0-9.\-:\[\]]{1,200}(/[A-Za-z0-9._~/-]*)?$", upstream),
             "bad_upstream", "a http(s)://host:port address")
    https = bool(args.get("https"))
    cert, key = args.get("cert") or "", args.get("key") or ""
    if https and args.get("cert_name"):
        mp = _managed_paths(conf, _check_cert_name(args["cert_name"]))
        cert, key = mp["cert"], mp["key"]
    if https:
        need(SAFE_PATH_RE.match(cert) and SAFE_PATH_RE.match(key), "bad_cert",
             "HTTPS needs a certificate (pick one, or give the cert and key paths)")
    redirect = https and args.get("redirect_https", True)
    sock = args.get("php_socket") or ""
    if kind == "php" and not sock:
        fpm = php_versions()["fpm"]
        sock = fpm[0]["socket"] if fpm else ("127.0.0.1:9000" if server == "apache"
                                             else "/run/php-fpm/www.sock")
    if sock:
        need(SAFE_PATH_RE.match(sock) or re.match(r"^127\.0\.0\.1:[0-9]{2,5}$", sock),
             "bad_socket", "a PHP-FPM socket path or 127.0.0.1:port")
    upload = int(args.get("upload_mb") or 0)
    need(0 <= upload <= 10240, "bad_limit", "upload limit 0-10240 MB")
    tmo = int(args.get("timeout_s") or 0)
    need(0 <= tmo <= 3600, "bad_limit", "time limit 0-3600 s")
    headers = dict(SECURITY_HEADERS) if args.get("security_headers") else {}
    for k, v in (args.get("headers") or {}).items():
        need(HEADER_NAME_RE.match(str(k)) and HEADER_VALUE_RE.match(str(v)), "bad_header",
             "header names are letters/digits/'-', values without quotes or ';'")
        headers[str(k)] = str(v)
    own_logs = bool(args.get("own_logs", True))
    fam = os_release()["family"]
    logdir = "/var/log/nginx" if server == "nginx" else (
        "/var/log/httpd" if fam == "rhel" else "/var/log/apache2")
    base = re.sub(r"\.conf$", "", name)
    stamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    if server == "nginx":
        body = []
        if kind == "proxy":
            body.append("    location / {\n        proxy_pass %s;\n"
                        "        proxy_set_header Host $host;\n"
                        "        proxy_set_header X-Real-IP $remote_addr;\n"
                        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                        "        proxy_set_header X-Forwarded-Proto $scheme;\n%s    }\n"
                        % (upstream, ("        proxy_read_timeout %ds;\n" % tmo) if tmo else ""))
        else:
            body.append("    root %s;\n    index %s;\n" % (docroot, index))
            body.append("    location / {\n        try_files $uri $uri/ %s;\n    }\n"
                        % ("/index.php?$args" if kind == "php" else "=404"))
            if kind == "php":
                target = sock if sock.startswith("127.") else "unix:" + sock
                body.append("    location ~ \\.php$ {\n%s        fastcgi_pass %s;\n%s    }\n"
                            % (_php_include(fam), target,
                               ("        fastcgi_read_timeout %ds;\n" % tmo) if tmo else ""))
            body.append("    location ~ /\\.(?!well-known) {\n        deny all;\n    }\n")
        if upload:
            body.append("    client_max_body_size %dm;\n" % upload)
        for k, v in headers.items():
            body.append('    add_header %s "%s" always;\n' % (k, v))
        if own_logs:
            body.append("    access_log %s/%s.access.log;\n    error_log %s/%s.error.log;\n"
                        % (logdir, base, logdir, base))
        site = "".join(body)
        text = ("# Managed by SATOM Web Server Manager (satom-wsm %s) -- created %s\n"
                "server {\n    listen 80;\n    listen [::]:80;\n    server_name %s;\n"
                % (WSM_VERSION, stamp, " ".join(names)))
        if redirect:
            text += ("    location /.well-known/acme-challenge/ {\n        root %s;\n    }\n"
                     "    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n"
                     % (docroot,))
        else:
            text += site + "}\n"
        if https:
            text += ("server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n"
                     "    server_name %s;\n    ssl_certificate %s;\n    ssl_certificate_key %s;\n"
                     "    ssl_protocols TLSv1.2 TLSv1.3;\n%s}\n"
                     % (" ".join(names), cert, key, site))
    else:
        aliases = "    ServerAlias %s\n" % " ".join(names[1:]) if len(names) > 1 else ""
        body = []
        if kind == "proxy":
            body.append("    ProxyPreserveHost On\n    ProxyPass / %s/\n    ProxyPassReverse / %s/\n"
                        % (upstream.rstrip("/"), upstream.rstrip("/")))
            if tmo:
                body.append("    ProxyTimeout %d\n" % tmo)
        else:
            body.append('    DocumentRoot "%s"\n    DirectoryIndex %s\n    <Directory "%s">\n'
                        '        Require all granted\n        AllowOverride %s\n'
                        '        Options -Indexes +FollowSymLinks\n    </Directory>\n'
                        % (docroot, index, docroot, "All" if args.get("htaccess", True) else "None"))
            if kind == "php":
                target = ("fcgi://%s" % sock) if sock.startswith("127.") else \
                    "unix:%s|fcgi://localhost" % sock
                body.append('    <FilesMatch "\\.php$">\n        SetHandler "proxy:%s"\n'
                            '    </FilesMatch>\n' % target)
        if upload:
            body.append("    LimitRequestBody %d\n" % (upload * 1024 * 1024))
        if tmo and kind != "proxy":
            body.append("    Timeout %d\n" % tmo)
        for k, v in headers.items():
            body.append('    Header always set %s "%s"\n' % (k, v))
        if own_logs:
            body.append("    ErrorLog %s/%s-error.log\n    CustomLog %s/%s-access.log combined\n"
                        % (logdir, base, logdir, base))
        site = "".join(body)
        text = ("# Managed by SATOM Web Server Manager (satom-wsm %s) -- created %s\n"
                "<VirtualHost *:80>\n    ServerName %s\n%s" % (WSM_VERSION, stamp, names[0], aliases))
        if redirect:
            text += ('    DocumentRoot "%s"\n    RewriteEngine On\n'
                     '    RewriteCond %%{REQUEST_URI} !^/\\.well-known/acme-challenge/\n'
                     '    RewriteRule ^/?(.*) https://%%{SERVER_NAME}/$1 [R=301,L]\n</VirtualHost>\n'
                     % docroot)
        else:
            text += site + "</VirtualHost>\n"
        if https:
            text += ("<VirtualHost *:443>\n    ServerName %s\n%s    SSLEngine on\n"
                     "    SSLCertificateFile %s\n    SSLCertificateKeyFile %s\n"
                     "    SSLProtocol -all +TLSv1.2 +TLSv1.3\n%s</VirtualHost>\n"
                     % (names[0], aliases, cert, key, site))
    made_root = False
    if kind != "proxy" and not os.path.isdir(docroot):
        os.makedirs(docroot, mode=0o755)
        made_root = True
        if args.get("owner"):
            u = pwd.getpwnam(_name(args["owner"], USER_RE, "user"))
            os.chown(docroot, u.pw_uid, u.pw_gid)
        if args.get("placeholder", True):
            with open(os.path.join(docroot, "index.html"), "w") as fh:
                fh.write("<!doctype html><title>%s</title><h1>%s</h1>"
                         "<p>Site created by SATOM Web Server Manager.</p>\n" % (names[0], names[0]))
    _write_atomic(main, text.encode("utf-8"), 0o644)
    if spec["layout"] == "debian":
        os.symlink(main, other)

    def undo():
        if spec["layout"] == "debian" and os.path.islink(other):
            os.unlink(other)
        if os.path.exists(main):
            os.unlink(main)

    res = _apply(conf, spec, undo)
    res.update({"created": not res.get("restored"), "name": name, "docroot": docroot,
                "docroot_created": made_root, "content": text})
    return res


def _server_blocks(text):
    """(start, end) of the body of each nginx ``server {`` block."""
    out = []
    for m in re.finditer(r"(?m)^\s*server\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out.append((m.end(), i - 1))
    return out


def op_vhost_snippet(conf, args):
    """Put (or remove, with empty content) a ``# BEGIN SATOM <marker>`` block
    at the end of every nginx server block of a virtual host that serves
    content (not the ones that only redirect); test, restore or reload."""
    spec = server_spec(conf, args.get("server"))
    need(args.get("server") == "nginx", "bad_server", "snippets are for nginx sites")
    name = _check_name(spec, args.get("name"))
    marker = _name(args.get("marker") or "", re.compile(r"^[a-z0-9-]{1,40}$"), "marker")
    content = args.get("content") or ""
    need(isinstance(content, str) and len(content) <= 64 * 1024, "bad_content", "text")
    depth = 0
    for ch in content:
        depth += 1 if ch == "{" else -1 if ch == "}" else 0
        need(depth >= 0, "bad_content", "the snippet must keep its braces balanced")
    need(depth == 0, "bad_content", "the snippet must keep its braces balanced")
    path, enabled = vhost_state(spec, name)
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8", "replace")
    begin, end = "    # BEGIN SATOM %s" % marker, "    # END SATOM %s" % marker
    text = re.sub(r"(?s)\n?    # BEGIN SATOM %s\n.*?    # END SATOM %s\n" % (marker, marker),
                  "\n", text)
    if content.strip():
        block = "%s\n%s%s\n" % (begin, "".join("    " + l + "\n" for l in content.strip("\n")
                                               .splitlines()), end)
        spans = _server_blocks(text)
        targets = [s for s in spans if not re.search(r"(?m)^\s*return\s+30[18]", text[s[0]:s[1]])
                   or re.search(r"(?m)^\s*(root|proxy_pass)\s", text[s[0]:s[1]])]
        need(targets, "no_server", "no server block serves content in this file")
        for s, e in sorted(targets, reverse=True):
            text = text[:e].rstrip(" ") + block + text[e:]
    data = text.encode("utf-8")
    if data == raw:
        return {"changed": False, "applied": True, "restored": False}
    mode = stat.S_IMODE(os.stat(path).st_mode)
    bk = backup(conf, "vhost.snippet", [path])
    _write_atomic(path, data, mode)
    res = _apply(conf, spec, lambda: _write_atomic(path, raw, mode)) if enabled else \
        {"applied": True, "test_output": "", "restored": False}
    res.update({"changed": not res.get("restored"), "backup": bk})
    return res


def op_vhost_test(conf, args):
    spec = server_spec(conf, args.get("server"))
    rc, out = _run(conf, spec.get("test"))
    return {"ok": rc == 0, "output": clean(out, 4000)}


def http_check(host, port=80, path="/", scheme="http", timeout=10):
    need(HOST_RE.match(host or "") or host == "localhost", "bad_host", "invalid host")
    need(isinstance(path, str) and path.startswith("/") and len(path) < 500, "bad_path",
         "a path starting with /")
    started = time.time()
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection(("127.0.0.1", int(port)), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=host)
            conn = http.client.HTTPSConnection("127.0.0.1", int(port), timeout=timeout,
                                               context=ctx)
            conn.sock = sock
        else:
            conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
        conn.request("GET", path, headers={"Host": host, "User-Agent": "satom-wsm-check"})
        r = conn.getresponse()
        r.read(65536)
        out = {"status": r.status, "reason": clean(r.reason, 80),
               "server": clean(r.getheader("Server") or "", 120),
               "location": clean(r.getheader("Location") or "", 300),
               "ms": int((time.time() - started) * 1000)}
        conn.close()
        return out
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return {"status": 0, "reason": clean(exc.__class__.__name__ + ": " + str(exc), 200),
                "server": "", "location": "", "ms": int((time.time() - started) * 1000)}


def op_http_check(conf, args):
    return http_check(args.get("host"), int(args.get("port") or 80), args.get("path") or "/",
                      "https" if args.get("scheme") == "https" else "http")


def op_htaccess_apply(conf, args):
    """Write a .htaccess and ask the site for a page: an Apache that answers
    500 because of the new rules gets the previous file back."""
    path = _abs(args.get("path"), must_exist=False)
    need(os.path.basename(path) == ".htaccess", "bad_path", "the file is .htaccess")
    content = args.get("content")
    need(isinstance(content, str) and len(content) <= 512 * 1024, "bad_content", "text")
    old = None
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            old = fh.read()
        st = os.stat(path)
        mode, owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
    else:
        dst = os.stat(os.path.dirname(path))
        mode, owner = 0o644, (dst.st_uid, dst.st_gid)
    version = keep_version(path) if old is not None else ""
    if content.strip():
        _write_file(path, content.encode("utf-8"), mode, owner)
    elif old is not None:
        os.unlink(path)
    host = args.get("host") or ""
    check = http_check(host, int(args.get("port") or 80), "/",
                       "https" if args.get("scheme") == "https" else "http") if host else None
    restored = False
    if check and check["status"] >= 500:
        if old is None:
            if os.path.exists(path):
                os.unlink(path)
        else:
            _write_file(path, old, mode, owner)
        restored = True
    return {"path": path, "history": version, "check": check, "restored": restored,
            "applied": not restored}


def op_apache_override(conf, args):
    """Whether Apache reads .htaccess under ``path`` (AllowOverride of the
    <Directory> blocks that contain it, last match wins)."""
    path = _abs(args.get("path"), must_exist=False)
    found, where = None, ""
    files = []
    for d in ("/etc/apache2", "/etc/httpd"):
        for root, dirs, fs in os.walk(d):
            for f in fs:
                if f.endswith(".conf") or f in ("apache2.conf", "httpd.conf"):
                    files.append(os.path.join(root, f))
    best = -1
    for f in files:
        try:
            with open(f, errors="replace") as fh:
                text = _strip_comments(fh.read(512 * 1024))
        except OSError:
            continue
        for m in re.finditer(r'(?is)<Directory\s+"?([^">]+)"?\s*>(.*?)</Directory>', text):
            d = m.group(1).rstrip("/") or "/"
            if path == d or path.startswith(d + "/") or d == "/":
                o = re.search(r"(?im)^\s*AllowOverride\s+(.+)$", m.group(2))
                if o and len(d) >= best:
                    best, found, where = len(d), o.group(1).strip(), f
    return {"path": path, "allow_override": clean(found or "None (default)", 100),
            "enabled": bool(found) and found.lower() != "none", "file": clean(where, 300)}


# ── certificates: import, certbot, TLS check ────────────────────────────────

PEM_KEY_RE = re.compile(r"-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[A-Za-z0-9+/=\s]+"
                        r"-----END \1-----")


def op_cert_import(conf, args):
    """An existing certificate + private key into the managed folder. The key
    is checked against the certificate and never repeated in the answer."""
    require_root("importing a certificate")
    name = _check_cert_name(args.get("name"))
    certs = args.get("certificate") or ""
    key = args.get("private_key") or ""
    chain = args.get("chain") or ""
    need(isinstance(certs, str) and _pem_blocks(certs), "bad_cert", "a PEM certificate")
    need(isinstance(key, str) and PEM_KEY_RE.search(key), "bad_key", "a PEM private key")
    need("ENCRYPTED" not in key, "bad_key", "the private key must not be passphrase-protected")
    need(not chain or _pem_blocks(chain), "bad_chain", "the chain is PEM certificates")
    mp = _managed_paths(conf, name)
    need(not os.path.exists(mp["cert"]) or args.get("replace"), "exists",
         "a certificate with that name exists (tick replace)")
    full = "".join("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n"
                   % "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
                   for b in _pem_blocks(certs) + _pem_blocks(chain))
    tmp = tempfile.mkdtemp(prefix="satom-wsm-imp-")
    try:
        os.chmod(tmp, 0o700)
        kp, cp = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
        with open(kp, "w") as fh:
            fh.write(PEM_KEY_RE.search(key).group(0) + "\n")
        os.chmod(kp, 0o600)
        with open(cp, "w") as fh:
            fh.write(full)
        info = _cert_info(cp)
        need(info is not None, "bad_cert", "the certificate cannot be read")
        need(info["days_left"] >= 0, "expired", "the certificate has expired")
        need(_pubkey(conf, cp, False) and _pubkey(conf, cp, False) == _pubkey(conf, kp, True),
             "key_mismatch", "the private key does not belong to the certificate")
        os.makedirs(mp["dir"], mode=0o700, exist_ok=True)
        bk = backup(conf, "cert.import", [mp["cert"], mp["key"]]) if os.path.exists(mp["cert"]) \
            else ""
        for p in (mp["cert"], mp["key"]):
            if os.path.islink(p):
                os.unlink(p)
        shutil.copyfile(kp, mp["key"])
        os.chmod(mp["key"], 0o600)
        shutil.copyfile(cp, mp["cert"])
        os.chmod(mp["cert"], 0o644)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    servers = _servers_using(conf, os.path.realpath(mp["cert"]))
    res = {"name": name, "installed": True, "subject": info["subject"],
           "not_after": info["not_after"], "days_left": info["days_left"], "backup": bk}
    if servers:
        res["reload"] = _test_reload(conf, servers, lambda: None)
    return res


def _certbot():
    exe = which("certbot")
    need(exe, "no_certbot", "certbot is not installed (install it from Packages)")
    return exe


def op_acme_status(conf, args):
    exe = which("certbot")
    out = {"certbot": "", "certs": [], "timer": ""}
    if not exe:
        return out
    rc, v, err = run([exe, "--version"], timeout=30)
    out["certbot"] = clean((v or err).strip(), 80)
    if is_root():
        rc, text, err = run([exe, "certificates"], timeout=60)
        cur = None
        for line in text.splitlines():
            m = re.match(r"\s*Certificate Name:\s*(\S+)", line)
            if m:
                cur = {"name": clean(m.group(1), 100), "domains": [], "expiry": "",
                       "path": "", "valid": ""}
                out["certs"].append(cur)
            elif cur is not None:
                for key, rx in (("domains", r"\s*Domains:\s*(.+)"),
                                ("expiry", r"\s*Expiry Date:\s*(.+)"),
                                ("path", r"\s*Certificate Path:\s*(\S+)")):
                    m2 = re.match(rx, line)
                    if m2:
                        cur[key] = m2.group(1).split() if key == "domains" else clean(m2.group(1), 200)
    for t in ("certbot.timer", "certbot-renew.timer", "snap.certbot.renew.timer"):
        rc, st, _ = run(["systemctl", "is-enabled", t], timeout=15)
        if rc == 0 or st.strip() in ("enabled", "disabled"):
            out["timer"] = "%s (%s)" % (t, st.strip())
            break
    return out


def op_acme_issue(conf, args):
    require_root("asking Let's Encrypt for a certificate")
    exe = _certbot()
    domains = _names(args.get("domains") or [], SERVER_NAME_RE, "domains", 50)
    method = args.get("method") or "webroot"
    need(method in ("webroot", "nginx", "apache", "standalone"), "bad_method", "method")
    email = args.get("email") or ""
    need(not email or re.match(r"^[^@\s\"']{1,64}@[A-Za-z0-9.-]{1,190}$", email), "bad_email",
         "email")
    name = _check_cert_name(args.get("name") or domains[0].lstrip("*.").lower())
    argv = [exe, "certonly", "--non-interactive", "--agree-tos", "--cert-name", name,
            "--key-type", "ecdsa" if args.get("key_type") == "ecdsa" else "rsa"]
    argv += ["-m", email] if email else ["--register-unsafely-without-email"]
    if args.get("staging"):
        argv.append("--staging")
    if method == "webroot":
        argv += ["--webroot", "-w", _abs(args.get("webroot"))]
    else:
        argv.append("--" + method)
    for d in domains:
        argv += ["-d", d]
    rc, out, err = run(argv, timeout=600)
    result = {"ok": rc == 0, "name": name, "output": clean((out + "\n" + err).strip(), 6000)}
    if rc == 0:
        live = "/etc/letsencrypt/live/%s" % name
        mp = _managed_paths(conf, name)
        os.makedirs(mp["dir"], mode=0o700, exist_ok=True)
        for src, dst in ((live + "/fullchain.pem", mp["cert"]), (live + "/privkey.pem", mp["key"])):
            if os.path.lexists(dst):
                os.unlink(dst)
            os.symlink(src, dst)
        result["linked"] = mp["dir"]
    return result


def op_acme_renew(conf, args):
    require_root("renewing certificates")
    argv = [_certbot(), "renew", "--non-interactive"]
    if args.get("name"):
        argv += ["--cert-name", _check_cert_name(args["name"])]
    if args.get("dry_run"):
        argv.append("--dry-run")
    rc, out, err = run(argv, timeout=900)
    return {"ok": rc == 0, "output": clean((out + "\n" + err).strip(), 6000)}


def op_acme_revoke(conf, args):
    require_root("revoking a certificate")
    name = _check_cert_name(args.get("name"))
    rc, out, err = run([_certbot(), "revoke", "--non-interactive", "--cert-name", name,
                        "--delete-after-revoke"], timeout=300)
    return {"ok": rc == 0, "output": clean((out + "\n" + err).strip(), 4000)}


def op_acme_autorenew(conf, args):
    require_root("changing automatic renewal")
    enable = bool(args.get("enable", True))
    for t in ("certbot.timer", "certbot-renew.timer", "snap.certbot.renew.timer"):
        rc, st, _ = run(["systemctl", "cat", t], timeout=15)
        if rc == 0:
            rc, out, err = run(["systemctl", "enable" if enable else "disable", "--now", t],
                               timeout=60)
            return {"ok": rc == 0, "timer": t, "output": clean(out + err, 2000)}
    raise Refused("no_timer", "this certbot has no renewal timer (systemd)")


def op_tls_check(conf, args):
    host = args.get("host") or ""
    need(HOST_RE.match(host), "bad_host", "a host name")
    port = int(args.get("port") or 443)
    target = args.get("connect") or "127.0.0.1"
    need(IP_RE.match(target) or HOST_RE.match(target), "bad_host", "address to connect to")
    protos = {}
    names = (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"),
             ("TLSv1.3", "TLSv1_3"))
    for label, attr in names:
        try:
            if hasattr(ssl, "TLSVersion"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = getattr(ssl.TLSVersion, attr)
                ctx.maximum_version = getattr(ssl.TLSVersion, attr)
            else:                                    # Python 3.6
                proto = getattr(ssl, "PROTOCOL_" + attr, None)
                if proto is None:
                    raise ValueError(label)
                ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if label in ("TLSv1", "TLSv1.1"):
                ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, AttributeError, ssl.SSLError):
            protos[label] = "untested"
            continue
        try:
            with socket.create_connection((target, port), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    protos[label] = "accepted"
        except ssl.SSLError:
            protos[label] = "refused"
        except OSError as exc:
            protos[label] = "error: " + clean(exc.__class__.__name__, 40)
    verify = {"trusted": False, "hostname_ok": False, "error": ""}
    cert = {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                verify = {"trusted": True, "hostname_ok": True, "error": ""}
                cert = t.getpeercert() or {}
                verify["cipher"] = clean(t.cipher()[0], 80)
                verify["version"] = clean(t.version(), 20)
    except getattr(ssl, "SSLCertVerificationError", ssl.CertificateError) as exc:
        verify["error"] = clean(getattr(exc, "verify_message", "") or str(exc), 300)
        verify["hostname_ok"] = "hostname" not in verify["error"].lower()
    except (ssl.SSLError, OSError) as exc:
        verify["error"] = clean(exc.__class__.__name__ + ": " + str(exc), 300)
    if not cert:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((target, port), timeout=8) as s:
                with ctx2.wrap_socket(s, server_hostname=host) as t:
                    der = t.getpeercert(binary_form=True)
            tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
            tmp.write(ssl.DER_cert_to_PEM_cert(der))
            tmp.close()
            info = _cert_info(tmp.name) or {}
            os.unlink(tmp.name)
        except (ssl.SSLError, OSError):
            info = {}
    else:
        info = {"not_after": int(ssl.cert_time_to_seconds(cert["notAfter"])),
                "sans": [clean(v, 253) for k, v in cert.get("subjectAltName", ()) if k == "DNS"]}
        info["days_left"] = int((info["not_after"] - time.time()) // 86400)
    weak = [p for p in ("TLSv1", "TLSv1.1") if protos.get(p) == "accepted"]
    return {"host": host, "port": port, "protocols": protos, "weak_protocols": weak,
            "verify": verify, "days_left": info.get("days_left"),
            "not_after": info.get("not_after"), "sans": info.get("sans", [])[:100],
            "subject": info.get("subject", "")}


# ── packages ────────────────────────────────────────────────────────────────

def _pm():
    pm = pkg_manager()
    need(pm, "no_pkg_manager", "no apt, dnf, zypper or yum on this server")
    return pm


def op_pkg_search(conf, args):
    q = _name(args.get("q") or "", re.compile(r"^[A-Za-z0-9.+_:~@-]{2,64}$"), "query")
    pm = _pm()
    out = []
    if pm == "apt":
        rc, text, err = run(["apt-cache", "search", "--names-only", q], timeout=120)
        for line in text.splitlines()[:300]:
            n, _, s = line.partition(" - ")
            out.append({"name": clean(n.strip(), 128), "summary": clean(s, 200)})
    elif pm in ("dnf", "yum"):
        rc, text, err = run([pm, "-q", "search", q], timeout=300)
        for line in text.splitlines():
            if " : " in line and not line.startswith("="):
                n, _, s = line.partition(" : ")
                out.append({"name": clean(n.strip().rsplit(".", 1)[0], 128),
                            "summary": clean(s, 200)})
    else:
        rc, text, err = run(["zypper", "-n", "-q", "se", "-t", "package", q], timeout=300)
        for line in text.splitlines():
            cols = [c.strip() for c in line.split("|")]
            if len(cols) >= 3 and cols[1] and cols[1] != "Name" and not set(cols[1]) <= set("-+"):
                out.append({"name": clean(cols[1], 128), "summary": clean(cols[2], 200),
                            "installed": cols[0].startswith("i")})
    inst = _installed_set()
    for o in out:
        o.setdefault("installed", o["name"] in inst)
    return {"manager": pm, "results": out[:300], "error": clean(err, 500) if not out else ""}


def _installed_set():
    if which("dpkg-query"):
        rc, text, _ = run(["dpkg-query", "-W", "-f", "${Package}\t${Status}\n"], timeout=120,
                          limit=8 * 1024 * 1024)
        return {l.split("\t")[0] for l in text.splitlines() if "install ok installed" in l}
    rc, text, _ = run(["rpm", "-qa", "--qf", "%{NAME}\n"], timeout=120, limit=8 * 1024 * 1024)
    return set(text.split())


def op_pkg_installed(conf, args):
    flt = (args.get("filter") or "").lower()
    rows = []
    if which("dpkg-query"):
        rc, text, _ = run(["dpkg-query", "-W", "-f",
                           "${Package}\t${Version}\t${Architecture}\t${Status}\t${binary:Summary}\n"],
                          timeout=120, limit=16 * 1024 * 1024)
        for l in text.splitlines():
            c = l.split("\t")
            if len(c) >= 5 and "install ok installed" in c[3]:
                rows.append({"name": c[0], "version": c[1], "arch": c[2], "summary": c[4]})
    else:
        rc, text, _ = run(["rpm", "-qa", "--qf",
                           "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n"],
                          timeout=120, limit=16 * 1024 * 1024)
        for l in text.splitlines():
            c = l.split("\t")
            if len(c) >= 4:
                rows.append({"name": c[0], "version": c[1], "arch": c[2], "summary": c[3]})
    rows = [{k: clean(v, 200) for k, v in r.items()} for r in rows
            if not flt or flt in r["name"].lower()]
    rows.sort(key=lambda r: r["name"])
    return {"manager": pkg_manager(), "packages": rows[:3000], "total": len(rows),
            "truncated": len(rows) > 3000}


def op_pkg_show(conf, args):
    n = _name(args.get("name"), PKG_RE, "package")
    pm = _pm()
    if pm == "apt":
        rc, text, err = run(["apt-cache", "show", "--no-all-versions", n], timeout=60)
        rc2, pol, _ = run(["apt-cache", "policy", n], timeout=60)
        text = text + "\n" + pol
    elif pm in ("dnf", "yum"):
        rc, text, err = run([pm, "-q", "info", n], timeout=300)
        rc2, deps, _ = run([pm, "-q", "repoquery", "--requires", "--resolve", n], timeout=300)
        text += "\nDependencies:\n" + deps
    else:
        rc, text, err = run(["zypper", "-n", "info", "--requires", n], timeout=300)
    return {"name": n, "text": clean(text or err, 30000), "found": rc == 0 and bool(text.strip())}


def op_pkg_updates(conf, args):
    pm = _pm()
    rows = []
    if pm == "apt":
        rc, text, err = run(["apt", "list", "--upgradable"], timeout=120)
        for l in text.splitlines():
            m = re.match(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", l)
            if m:
                rows.append({"name": m.group(1), "new": m.group(2), "old": m.group(3)})
    elif pm in ("dnf", "yum"):
        rc, text, err = run([pm, "-q", "check-update"], timeout=600)
        for l in text.splitlines():
            c = l.split()
            if len(c) == 3 and "." in c[0] and not l.startswith(" "):
                rows.append({"name": c[0].rsplit(".", 1)[0], "new": c[1], "old": ""})
    else:
        rc, text, err = run(["zypper", "-n", "-q", "lu"], timeout=600)
        for l in text.splitlines():
            c = [x.strip() for x in l.split("|")]
            if len(c) >= 6 and c[0] == "v":
                rows.append({"name": c[2], "old": c[3], "new": c[4]})
    rows = [{k: clean(v, 128) for k, v in r.items()} for r in rows]
    return {"manager": pm, "updates": rows[:2000], "total": len(rows)}


def op_pkg_refresh(conf, args):
    require_root("refreshing the package lists")
    pm = _pm()
    argv = {"apt": ["apt-get", "update", "-q"], "dnf": ["dnf", "-q", "makecache"],
            "yum": ["yum", "-q", "makecache"], "zypper": ["zypper", "-n", "refresh"]}[pm]
    rc, out, err = run(argv, timeout=900)
    return {"ok": rc == 0, "output": clean((out + "\n" + err).strip(), 6000)}


def _pkg_argv(pm, action, names, dry):
    if pm == "apt":
        verb = {"install": "install", "remove": "remove", "upgrade": "install"}[action]
        if action == "upgrade" and not names:
            verb = "upgrade"
        argv = ["apt-get", "-s" if dry else "-y", verb]
        if action == "upgrade" and names:
            argv.append("--only-upgrade")
        return argv + names
    if pm in ("dnf", "yum"):
        verb = {"install": "install", "remove": "remove", "upgrade": "upgrade"}[action]
        return [pm, "--assumeno" if dry else "-y", verb] + names
    verb = {"install": "install", "remove": "remove", "upgrade": "update"}[action]
    argv = ["zypper", "-n", verb]
    if dry:
        argv.append("--dry-run")
    return argv + names


def _parse_plan(pm, text):
    plan = {"install": [], "upgrade": [], "remove": [], "other": []}
    if pm == "apt":
        for l in text.splitlines():
            m = re.match(r"^(Inst|Remv|Purg)\s+(\S+)(?:\s+\[([^\]]+)\])?(?:\s+\((\S+))?", l)
            if m:
                kind = "remove" if m.group(1) != "Inst" else ("upgrade" if m.group(3) else "install")
                plan[kind].append({"name": m.group(2), "version": m.group(4) or "",
                                   "from": m.group(3) or ""})
    elif pm in ("dnf", "yum"):
        section = None
        for l in text.splitlines():
            s = l.strip().lower()
            if s.startswith("installing") or s.startswith("installing dependencies"):
                section = "install"
            elif s.startswith("upgrading"):
                section = "upgrade"
            elif s.startswith("removing"):
                section = "remove"
            elif s.startswith("transaction summary"):
                section = None
            elif section and l.startswith(" ") and len(l.split()) >= 3:
                c = l.split()
                plan[section].append({"name": c[0], "version": c[2] if len(c) > 2 else "",
                                      "from": ""})
    else:
        section = None
        for l in text.splitlines():
            s = l.lower()
            if "going to be installed" in s or "new package" in s and "going to" in s:
                section = "install"
            elif "going to be upgraded" in s:
                section = "upgrade"
            elif "going to be removed" in s:
                section = "remove"
            elif not l.strip():
                section = None
            elif section and l.startswith("  "):
                for n in l.split():
                    plan[section].append({"name": n, "version": "", "from": ""})
    for k in plan:
        plan[k] = [{kk: clean(vv, 128) for kk, vv in r.items()} for r in plan[k][:1000]]
    return plan


def op_pkg_plan(conf, args):
    pm = _pm()
    action = args.get("action")
    need(action in ("install", "remove", "upgrade"), "bad_action", "install, remove or upgrade")
    names = args.get("names") or []
    names = _names(names, PKG_RE, "package", 100) if (names or action != "upgrade") else []
    rc, out, err = run(_pkg_argv(pm, action, names, True), timeout=900)
    if pm in ("dnf", "yum") and rc == 1 and "Operation aborted" in (out + err):
        rc = 0
    plan = _parse_plan(pm, out + "\n" + err)
    return {"manager": pm, "action": action, "names": names, "plan": plan,
            "ok": rc == 0 or any(plan.values()), "output": clean((out + "\n" + err).strip(), 8000),
            "needs_root": not is_root()}


def op_pkg_apply(conf, args):
    require_root("installing, removing or upgrading packages")
    pm = _pm()
    action = args.get("action")
    need(action in ("install", "remove", "upgrade"), "bad_action", "install, remove or upgrade")
    names = args.get("names") or []
    names = _names(names, PKG_RE, "package", 100) if (names or action != "upgrade") else []
    rc, out, err = run(_pkg_argv(pm, action, names, False), timeout=1800)
    return {"ok": rc == 0, "exit_code": rc, "action": action, "names": names,
            "output": clean((out + "\n" + err).strip(), 20000)}


# ── services ────────────────────────────────────────────────────────────────

def _unit(name):
    name = _name(name, UNIT_RE, "unit")
    return name if "." in name else name + ".service"


def op_svc_list(conf, args):
    rc, text, err = run(["systemctl", "list-units", "--type=service", "--all", "--no-legend",
                         "--plain", "--no-pager"], timeout=60, limit=4 * 1024 * 1024)
    need(rc == 0, "no_systemd", clean(err, 300) or "systemctl failed")
    units = {}
    for l in text.splitlines():
        c = l.split(None, 4)
        if len(c) >= 4 and c[0].endswith(".service"):
            units[c[0]] = {"name": clean(c[0], 200), "load": c[1], "active": c[2], "sub": c[3],
                           "description": clean(c[4] if len(c) > 4 else "", 200), "enabled": ""}
    rc, text, _ = run(["systemctl", "list-unit-files", "--type=service", "--no-legend",
                       "--no-pager"], timeout=60, limit=4 * 1024 * 1024)
    for l in text.splitlines():
        c = l.split()
        if len(c) >= 2 and c[0].endswith(".service") and "@" not in c[0]:
            u = units.setdefault(c[0], {"name": clean(c[0], 200), "load": "loaded",
                                        "active": "inactive", "sub": "dead",
                                        "description": "", "enabled": ""})
            u["enabled"] = clean(c[1], 20)
    rows = sorted(units.values(), key=lambda u: u["name"])
    return {"services": rows[:3000]}


def op_svc_status(conf, args):
    u = _unit(args.get("name"))
    props = "Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID," \
            "ExecMainStartTimestamp,MemoryCurrent,FragmentPath,Restart,User"
    rc, text, err = run(["systemctl", "show", u, "-p", props, "--no-pager"], timeout=30)
    info = {}
    for l in text.splitlines():
        k, _, v = l.partition("=")
        info[k] = clean(v, 300)
    rc, st, _ = run(["systemctl", "status", u, "--no-pager", "-n", "0"], timeout=30)
    return {"name": u, "props": info, "status": clean(st, 4000)}


def op_svc_action(conf, args):
    u = _unit(args.get("name"))
    action = args.get("action")
    need(action in ("start", "stop", "restart", "reload", "enable", "disable"),
         "bad_action", "start, stop, restart, reload, enable or disable")
    rc, out, err = run(["systemctl", action, u, "--no-pager"], timeout=180)
    if rc != 0 and ("Access denied" in err or "authentication" in err.lower()
                    or "Interactive authentication required" in err):
        raise Refused("permission_denied", "%s %s needs administrator rights" % (action, u))
    rc2, active, _ = run(["systemctl", "is-active", u], timeout=15)
    rc3, enabled, _ = run(["systemctl", "is-enabled", u], timeout=15)
    return {"name": u, "action": action, "ok": rc == 0, "output": clean(out + err, 3000),
            "active": active.strip(), "enabled": enabled.strip()}


def op_svc_deps(conf, args):
    u = _unit(args.get("name"))
    rc, fwd, _ = run(["systemctl", "list-dependencies", "--plain", "--no-pager", u], timeout=30)
    rc, rev, _ = run(["systemctl", "list-dependencies", "--reverse", "--plain", "--no-pager", u],
                     timeout=30)
    return {"name": u, "requires": clean(fwd, 20000), "required_by": clean(rev, 20000)}


def _journal(argv_tail, lines, grep):
    argv = ["journalctl", "--no-pager", "-o", "short-iso", "-n", str(lines)] + argv_tail
    if grep:
        argv += ["-g", grep]
    rc, out, err = run(argv, timeout=60, limit=4 * 1024 * 1024)
    if rc != 0 and grep and "grep" in err.lower():
        rc, out, err = run(argv[:-2], timeout=60, limit=4 * 1024 * 1024)
        out = "\n".join(l for l in out.splitlines() if grep.lower() in l.lower())
    return rc, out, err


def _since(value):
    if not value:
        return []
    need(re.match(r"^[0-9A-Za-z :.+-]{1,40}$", value), "bad_since", "a time like '2 hours ago'")
    return ["--since", value]


def op_svc_logs(conf, args):
    u = _unit(args.get("name"))
    lines = max(1, min(int(args.get("lines") or 200), 5000))
    grep = args.get("grep") or ""
    need(isinstance(grep, str) and len(grep) <= 200, "bad_grep", "text")
    rc, out, err = _journal(["-u", u] + _since(args.get("since")), lines, grep)
    return {"name": u, "lines": out.splitlines()[-lines:],
            "error": clean(err, 500) if rc != 0 else ""}


# ── cron ────────────────────────────────────────────────────────────────────

def _cron_user(args):
    me = pwd.getpwuid(os.geteuid()).pw_name
    user = args.get("user") or me
    _name(user, USER_RE, "user")
    try:
        pwd.getpwnam(user)
    except KeyError:
        raise Refused("no_user", "no user %s on this server" % user)
    return user, me


def op_cron_get(conf, args):
    user, me = _cron_user(args)
    argv = ["crontab", "-l"] + ([] if user == me else ["-u", user])
    rc, out, err = run(argv, timeout=30, limit=1024 * 1024)
    if rc != 0 and "no crontab" in err.lower():
        out = ""
    elif rc != 0:
        if "not allowed" in err.lower() or "permission" in err.lower() or \
                "must be privileged" in err.lower() or "only root" in err.lower():
            raise Refused("permission_denied", "reading the crontab of %s needs administrator "
                                               "rights" % user)
        raise Refused("cron_error", clean(err, 300))
    return {"user": user, "content": out,
            "sha256": hashlib.sha256(out.encode("utf-8")).hexdigest()}


def op_cron_put(conf, args):
    user, me = _cron_user(args)
    content = args.get("content")
    need(isinstance(content, str) and len(content) <= 256 * 1024, "bad_content", "text")
    if not content.endswith("\n"):
        content += "\n"
    cur = op_cron_get(conf, {"user": user})
    base = args.get("base_sha256")
    if base and base != cur["sha256"]:
        raise Refused("conflict", "the crontab changed since it was read")
    hist = os.path.join(_state_dir(), "cron-history")
    os.makedirs(hist, mode=0o700, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
    with open(os.path.join(hist, "%s-%s" % (user, stamp)), "w") as fh:
        fh.write(cur["content"])
    argv = ["crontab"] + ([] if user == me else ["-u", user]) + ["-"]
    rc, out, err = run(argv, stdin=content.encode("utf-8"), timeout=30)
    if rc != 0:
        if "privileged" in err.lower() or "not allowed" in err.lower():
            raise Refused("permission_denied", "changing the crontab of %s needs administrator "
                                               "rights" % user)
        raise Refused("cron_rejected", "crontab refused the table: %s" % clean(err, 400))
    return {"user": user, "saved": True, "backup": "%s-%s" % (user, stamp),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}


def op_cron_users(conf, args):
    require_root("listing every user's crontab")
    users = []
    for d in ("/var/spool/cron/crontabs", "/var/spool/cron/tabs", "/var/spool/cron"):
        try:
            for f in sorted(os.listdir(d)):
                p = os.path.join(d, f)
                if os.path.isfile(p) and USER_RE.match(f) and f not in users:
                    users.append(f)
        except OSError:
            pass
    sysfiles = []
    for f in (["/etc/crontab"] + [os.path.join("/etc/cron.d", n)
                                  for n in sorted(os.listdir("/etc/cron.d"))]
              if os.path.isdir("/etc/cron.d") else ["/etc/crontab"]):
        if os.path.isfile(f):
            sysfiles.append(f)
    return {"users": users, "system_files": sysfiles}


def op_cron_log(conf, args):
    lines = max(1, min(int(args.get("lines") or 200), 3000))
    for path in ("/var/log/cron", "/var/log/cron.log"):
        if os.path.isfile(path):
            return {"source": path, "lines": _tail(path, lines, "")}
    for unit in ("cron.service", "crond.service"):
        rc, out, err = _journal(["-u", unit], lines, "")
        if rc == 0 and out.strip() and "No entries" not in out:
            return {"source": "journal: " + unit, "lines": out.splitlines()[-lines:]}
    rc, out, err = _journal(["-t", "CRON"], lines, "")
    return {"source": "journal: CRON", "lines": out.splitlines()[-lines:]}


# ── logs ────────────────────────────────────────────────────────────────────

LOG_CANDIDATES = [
    ("nginx access", "/var/log/nginx/access.log"), ("nginx error", "/var/log/nginx/error.log"),
    ("Apache access", "/var/log/apache2/access.log"), ("Apache error", "/var/log/apache2/error.log"),
    ("Apache access", "/var/log/apache2/access_log"), ("Apache error", "/var/log/apache2/error_log"),
    ("Apache access", "/var/log/httpd/access_log"), ("Apache error", "/var/log/httpd/error_log"),
    ("Apache SSL access", "/var/log/httpd/ssl_access_log"),
    ("Apache SSL error", "/var/log/httpd/ssl_error_log"),
    ("PHP-FPM", "/var/log/php-fpm/error.log"), ("PHP-FPM", "/var/log/php-fpm/www-error.log"),
    ("PHP-FPM", "/var/log/php8-fpm.log"),
    ("System", "/var/log/syslog"), ("System", "/var/log/messages"),
    ("Authentication", "/var/log/auth.log"), ("Authentication", "/var/log/secure"),
    ("Cron", "/var/log/cron"), ("Cron", "/var/log/cron.log"),
    ("Let's Encrypt", "/var/log/letsencrypt/letsencrypt.log"),
    ("Mail", "/var/log/mail.log"), ("Mail", "/var/log/maillog"),
    ("MariaDB/MySQL", "/var/log/mysql/error.log"), ("MariaDB/MySQL", "/var/log/mariadb/mariadb.log"),
]


def _tail(path, lines, grep):
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        end = fh.tell()
        size = min(end, 8 * 1024 * 1024 if grep else max(256 * 1024, lines * 400))
        fh.seek(end - size)
        data = fh.read(size)
    text = data.decode("utf-8", "replace").splitlines()
    if size < end and text:
        text = text[1:]
    if grep:
        g = grep.lower()
        text = [l for l in text if g in l.lower()]
    return [clean(l, 4000) for l in text[-lines:]]


def op_logs_sources(conf, args):
    out, seen = [], set()
    for label, path in LOG_CANDIDATES:
        if os.path.isfile(path) and path not in seen:
            seen.add(path)
            out.append({"label": label, "path": path, "size": os.path.getsize(path),
                        "readable": os.access(path, os.R_OK)})
    for d, label in (("/var/log/nginx", "nginx"), ("/var/log/apache2", "Apache"),
                     ("/var/log/httpd", "Apache"), ("/var/log/php-fpm", "PHP-FPM")):
        try:
            for f in sorted(os.listdir(d)):
                p = os.path.join(d, f)
                if p not in seen and os.path.isfile(p) and re.search(r"(\.log|_log)$", f):
                    seen.add(p)
                    out.append({"label": "%s %s" % (label, f), "path": p,
                                "size": os.path.getsize(p), "readable": os.access(p, os.R_OK)})
        except OSError:
            pass
    st = _state_dir()
    own = os.path.join(st, "wsm.log")
    if os.path.isfile(own):
        out.append({"label": "SATOM operations on this server", "path": own,
                    "size": os.path.getsize(own), "readable": True})
    return {"files": out[:300], "journal": bool(which("journalctl"))}


def op_logs_read(conf, args):
    path = _abs(args.get("path"))
    need(path.startswith("/var/log/") or path.startswith(_state_dir() + "/")
         or path.startswith(os.path.expanduser("~") + "/"), "bad_path",
         "logs are read from /var/log or your home folder")
    need(os.path.isfile(path), "not_a_file", "not a file")
    lines = max(1, min(int(args.get("lines") or 200), 5000))
    grep = args.get("grep") or ""
    need(isinstance(grep, str) and len(grep) <= 200, "bad_grep", "text")
    if not os.access(path, os.R_OK):
        raise Refused("permission_denied", "reading %s needs administrator rights" % path)
    return {"path": path, "lines": _tail(path, lines, grep), "size": os.path.getsize(path)}


def op_journal_read(conf, args):
    lines = max(1, min(int(args.get("lines") or 200), 5000))
    tail = _since(args.get("since"))
    if args.get("unit"):
        tail += ["-u", _unit(args["unit"])]
    pr = args.get("priority") or ""
    if pr:
        need(pr in ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"),
             "bad_priority", "priority")
        tail += ["-p", pr]
    grep = args.get("grep") or ""
    need(isinstance(grep, str) and len(grep) <= 200, "bad_grep", "text")
    rc, out, err = _journal(tail, lines, grep)
    return {"lines": out.splitlines()[-lines:], "error": clean(err, 500) if rc != 0 else ""}


# ── security ────────────────────────────────────────────────────────────────

SENSITIVE = (".env", ".git", ".svn", ".htpasswd", "id_rsa", "id_ed25519", "wp-config.php.bak",
             "config.php.bak", "database.sql", "dump.sql", "backup.sql", ".DS_Store",
             "phpinfo.php", ".bash_history")
SENSITIVE_EXT = (".sql", ".bak", ".old", ".swp", ".orig", ".tar.gz", ".zip", ".pem", ".key")


def _listening():
    rc, out, err = run(["ss", "-H", "-tulnp"], timeout=30)
    rows = []
    if rc == 0:
        for l in out.splitlines():
            c = l.split()
            if len(c) >= 5:
                proc = re.search(r'users:\(\("([^"]+)"', l)
                rows.append({"proto": c[0], "local": clean(c[4], 80),
                             "process": clean(proc.group(1) if proc else "", 60)})
    return rows


def op_security_scan(conf, args):
    findings = []

    def add(sev, title, detail, fix="", path=""):
        findings.append({"severity": sev, "title": title, "detail": clean(detail, 600),
                         "fix": fix, "path": clean(path, 1024)})

    roots = []
    for v in list_vhosts(conf):
        for r in v["docroots"]:
            if r not in roots and os.path.isdir(r):
                roots.append(r)
    for r in args.get("docroots") or []:
        if isinstance(r, str) and r.startswith("/") and os.path.isdir(r) and r not in roots:
            roots.append(r)
    ww, scanned = [], 0
    for r in roots[:50]:
        for root, dirs, files in os.walk(r):
            dirs[:] = [d for d in dirs if d not in ("node_modules",)]
            for n in dirs + files:
                p = os.path.join(root, n)
                scanned += 1
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if st.st_mode & 0o002:
                    ww.append(p)
                low = n.lower()
                if n in SENSITIVE or (low.endswith(SENSITIVE_EXT) and stat.S_ISREG(st.st_mode)):
                    add("high" if n in (".env", ".git", "id_rsa", "id_ed25519", ".htpasswd")
                        or low.endswith((".sql", ".pem", ".key")) else "medium",
                        "Sensitive file inside a public folder",
                        "%s can be downloaded from the website" % p,
                        "Move it outside the document root or delete it", p)
                if scanned > 200000:
                    break
    for p in ww[:200]:
        add("high", "World-writable file or folder",
            "%s can be changed by any account on the server" % p,
            "Change permissions to 755 (folders) / 644 (files)", p)
    if len(ww) > 200:
        add("high", "More world-writable items", "%d more not listed" % (len(ww) - 200))
    # web servers
    for server, name, path, enabled, st, text in iter_vhost_files(conf):
        t = _strip_comments(text)
        if re.search(r"(?im)^\s*ssl_protocols[^;]*\bTLSv1(\.1)?\b(?!\.[23])", t) or \
                re.search(r"(?im)^\s*SSLProtocol\b.*\+?TLSv1(\.1)?\b(?!\.[23])", t):
            add("medium", "Old TLS versions enabled", "%s/%s allows TLS 1.0 or 1.1" % (server, name),
                "Use TLS 1.2 and 1.3 only", path)
        if re.search(r"(?im)^\s*autoindex\s+on", t) or re.search(r"(?im)^\s*Options\s.*\+?Indexes", t):
            if not re.search(r"(?im)-Indexes", t):
                add("medium", "Directory listing enabled", "%s/%s lists folder contents"
                    % (server, name), "Turn listing off (autoindex off / Options -Indexes)", path)
    for f in ("/etc/nginx/nginx.conf",):
        try:
            with open(f) as fh:
                t = _strip_comments(fh.read())
            if "server_tokens off" not in t:
                add("low", "nginx shows its version", "server_tokens is not off in %s" % f,
                    "Add 'server_tokens off;' to the http block", f)
        except OSError:
            pass
    php = php_versions()
    ver = php["cli"] or (php["fpm"][0]["version"] if php["fpm"] else "")
    if ver:
        try:
            major, minor = [int(x) for x in ver.split(".")[:2]]
            if (major, minor) < (8, 1):
                add("high", "Unsupported PHP version", "PHP %s no longer gets security fixes" % ver,
                    "Upgrade PHP to 8.1 or newer (Packages)")
        except ValueError:
            pass
    # ssh
    sshd = {}
    if is_root() and which("sshd"):
        rc, out, _ = run([which("sshd"), "-T"], timeout=30)
        for l in out.splitlines():
            k, _, v = l.partition(" ")
            sshd[k.lower()] = v.strip()
    else:
        try:
            with open("/etc/ssh/sshd_config") as fh:
                for l in fh:
                    l = l.split("#", 1)[0].strip()
                    if l and " " in l and not l.lower().startswith("match"):
                        k, v = l.split(None, 1)
                        sshd.setdefault(k.lower(), v.strip())
        except OSError:
            pass
    if sshd.get("permitrootlogin") == "yes":
        add("high", "Root can log in over SSH with a password", "PermitRootLogin yes",
            "Set PermitRootLogin to prohibit-password or no (SSH Configuration)")
    if sshd.get("permitemptypasswords") == "yes":
        add("critical", "Empty passwords allowed over SSH", "PermitEmptyPasswords yes",
            "Set PermitEmptyPasswords no")
    if sshd.get("passwordauthentication", "yes") == "yes":
        add("info", "SSH accepts passwords", "Key-only login is stronger against guessing",
            "Consider PasswordAuthentication no once every admin has a key")
    # services that rarely belong on a web server
    risky = ("telnet.socket", "vsftpd.service", "rpcbind.service", "avahi-daemon.service",
             "cups.service", "xinetd.service", "rsh.socket", "tftp.socket")
    for u in risky:
        rc, out, _ = run(["systemctl", "is-active", u], timeout=10)
        if out.strip() == "active":
            add("medium", "Service rarely needed on a web server is running", u,
                "Stop and disable it in Services if nothing uses it")
    ports = _listening()
    fw = {"kind": firewall_kind(), "active": None, "detail": ""}
    if fw["kind"] == "ufw":
        rc, out, err = run(["ufw", "status"], timeout=30)
        fw["active"] = "Status: active" in out if rc == 0 else None
        fw["detail"] = clean(out or err, 3000)
    elif fw["kind"] == "firewalld":
        rc, out, _ = run(["firewall-cmd", "--state"], timeout=30)
        fw["active"] = out.strip() == "running"
        rc, out2, err2 = run(["firewall-cmd", "--list-all"], timeout=30)
        fw["detail"] = clean(out2 or err2, 3000)
    if fw["active"] is False or not fw["kind"]:
        add("medium", "No active firewall", "Every listening port is reachable from the network",
            "Enable ufw or firewalld and allow only the ports you need")
    f2b = {"installed": bool(which("fail2ban-client")), "jails": [], "detail": ""}
    if f2b["installed"] and is_root():
        rc, out, err = run(["fail2ban-client", "status"], timeout=30)
        m = re.search(r"Jail list:\s*(.*)", out)
        f2b["jails"] = [j.strip() for j in (m.group(1).split(",") if m else []) if j.strip()]
        f2b["detail"] = clean(out or err, 2000)
    failed = 0
    rc, out, err = _journal(["--since", "24 hours ago"], 5000, "Failed password")
    if rc == 0:
        failed = sum(1 for l in out.splitlines() if "Failed password" in l)
    else:
        for p in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.isfile(p) and os.access(p, os.R_OK):
                failed = len(_tail(p, 5000, "Failed password"))
                break
    if failed > 50:
        add("medium", "Many failed SSH logins", "%d failed password attempts in 24 h" % failed,
            "Install fail2ban, or allow SSH only from known addresses")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    score = max(0, 100 - sum({"critical": 30, "high": 15, "medium": 6, "low": 2}.get(f["severity"],
                                                                                       0)
                             for f in findings))
    return {"score": score, "findings": findings[:500], "ports": ports[:300], "firewall": fw,
            "fail2ban": f2b, "failed_logins_24h": failed, "docroots": roots[:50],
            "php": php, "scanned": scanned, "complete": is_root(),
            "sshd": {k: clean(v, 200) for k, v in sshd.items()
                     if k in ("permitrootlogin", "passwordauthentication", "port",
                              "pubkeyauthentication", "maxauthtries", "x11forwarding")}}


def op_fw_rule(conf, args):
    require_root("changing the firewall")
    kind = firewall_kind()
    need(kind, "no_firewall", "neither ufw nor firewalld is installed")
    action = args.get("action")
    need(action in ("allow", "deny", "remove"), "bad_action", "allow, deny or remove")
    port = _name(str(args.get("port") or ""), PORT_RE, "port")
    proto = args.get("proto") or "tcp"
    need(proto in ("tcp", "udp"), "bad_proto", "tcp or udp")
    src = args.get("source") or ""
    if src:
        _name(src, IP_RE, "source")
    if kind == "ufw":
        if action == "remove":
            argv = ["ufw", "--force", "delete", "allow", "%s/%s" % (port, proto)]
        elif src:
            argv = ["ufw", action, "from", src, "to", "any", "port", port.replace("-", ":"),
                    "proto", proto]
        else:
            argv = ["ufw", action, "%s/%s" % (port.replace("-", ":"), proto)]
    else:
        if src or action == "deny":
            rule = 'rule family="ipv%d" %sport port="%s" protocol="%s" %s' % (
                6 if ":" in src else 4, ('source address="%s" ' % src) if src else "", port, proto,
                "accept" if action == "allow" else "reject")
            argv = ["firewall-cmd", "--permanent",
                    "--remove-rich-rule" if action == "remove" else "--add-rich-rule", rule]
        else:
            argv = ["firewall-cmd", "--permanent",
                    "--remove-port" if action == "remove" else "--add-port",
                    "%s/%s" % (port, proto)]
    rc, out, err = run(argv, timeout=60)
    if kind == "firewalld" and rc == 0:
        run(["firewall-cmd", "--reload"], timeout=60)
    return {"ok": rc == 0, "firewall": kind, "output": clean(out + err, 2000)}


def op_fw_enable(conf, args):
    require_root("turning the firewall on or off")
    kind = firewall_kind()
    need(kind, "no_firewall", "neither ufw nor firewalld is installed")
    on = bool(args.get("enable", True))
    if kind == "ufw":
        if on:
            run(["ufw", "allow", "OpenSSH"], timeout=30)
            run(["ufw", "allow", "22/tcp"], timeout=30)
        rc, out, err = run(["ufw", "--force", "enable" if on else "disable"], timeout=60)
    else:
        rc, out, err = run(["systemctl", "enable" if on else "disable", "--now",
                            "firewalld.service"], timeout=120)
        if on:
            run(["firewall-cmd", "--permanent", "--add-service=ssh"], timeout=60)
            run(["firewall-cmd", "--reload"], timeout=60)
    return {"ok": rc == 0, "firewall": kind, "enabled": on, "output": clean(out + err, 2000)}


def op_f2b_status(conf, args):
    require_root("reading fail2ban")
    exe = which("fail2ban-client")
    need(exe, "no_fail2ban", "fail2ban is not installed (install it from Packages)")
    jail = args.get("jail") or ""
    argv = [exe, "status"] + ([_name(jail, re.compile(r"^[A-Za-z0-9_.-]{1,64}$"), "jail")]
                              if jail else [])
    rc, out, err = run(argv, timeout=30)
    banned = []
    m = re.search(r"Banned IP list:\s*(.*)", out)
    if m:
        banned = m.group(1).split()
    return {"jail": jail, "output": clean(out or err, 4000), "banned": banned[:1000]}


def op_f2b_unban(conf, args):
    require_root("unbanning an address")
    exe = which("fail2ban-client")
    need(exe, "no_fail2ban", "fail2ban is not installed")
    jail = _name(args.get("jail") or "", re.compile(r"^[A-Za-z0-9_.-]{1,64}$"), "jail")
    ip = _name(args.get("ip") or "", IP_RE, "address")
    rc, out, err = run([exe, "set", jail, "unbanip", ip], timeout=30)
    return {"ok": rc == 0, "output": clean(out + err, 1000)}


# ── users and groups ────────────────────────────────────────────────────────

def op_users_list(conf, args):
    allu = bool(args.get("all"))
    groups = {g.gr_name: list(g.gr_mem) for g in grp.getgrall()}
    admin_groups = ("sudo", "wheel", "admin")
    locked = {}
    if is_root():
        try:
            with open("/etc/shadow") as fh:
                for l in fh:
                    c = l.split(":")
                    if len(c) > 1:
                        locked[c[0]] = c[1].startswith("!") or c[1].startswith("*")
        except OSError:
            pass
    users = []
    for u in pwd.getpwall():
        if not allu and ((u.pw_uid < 1000 and u.pw_uid != 0) or u.pw_uid == 65534):
            continue
        member = sorted(g for g, mem in groups.items() if u.pw_name in mem)
        try:
            primary = grp.getgrgid(u.pw_gid).gr_name
        except KeyError:
            primary = str(u.pw_gid)
        users.append({"name": clean(u.pw_name, 64), "uid": u.pw_uid, "gid": u.pw_gid,
                      "primary_group": clean(primary, 64), "home": clean(u.pw_dir, 256),
                      "shell": clean(u.pw_shell, 128), "comment": clean(u.pw_gecos, 120),
                      "groups": [clean(g, 64) for g in member][:100],
                      "admin": any(g in admin_groups for g in member) or u.pw_uid == 0,
                      "locked": locked.get(u.pw_name)})
    out_groups = [{"name": clean(g.gr_name, 64), "gid": g.gr_gid,
                   "members": [clean(m, 64) for m in g.gr_mem][:500]}
                  for g in grp.getgrall() if allu or g.gr_gid >= 1000 or g.gr_name in admin_groups
                  or g.gr_name in ("www-data", "nginx", "apache", "wwwrun", "www")]
    shells = []
    try:
        with open("/etc/shells") as fh:
            shells = [clean(l.strip(), 100) for l in fh if l.strip().startswith("/")]
    except OSError:
        pass
    return {"users": users[:2000], "groups": out_groups[:2000], "shells": shells,
            "complete": is_root()}


def _shell(value):
    if not value:
        return ""
    need(SAFE_PATH_RE.match(value), "bad_shell", "a shell path")
    return value


def _set_password(user, password):
    need(isinstance(password, str) and 8 <= len(password) <= 256 and "\n" not in password
         and ":" not in user, "bad_password", "a password of 8 to 256 characters")
    rc, out, err = run(["chpasswd"], stdin=("%s:%s\n" % (user, password)).encode("utf-8"),
                       timeout=30)
    need(rc == 0, "password_rejected", clean(err, 300) or "chpasswd refused the password")


def op_user_add(conf, args):
    require_root("creating an account")
    name = _name(args.get("name"), USER_RE, "user")
    need(not _exists_user(name), "exists", "the account already exists")
    argv = ["useradd"]
    argv += ["-m"] if args.get("create_home", True) else ["-M"]
    if args.get("system"):
        argv.append("-r")
    sh = _shell(args.get("shell") or "/bin/bash")
    argv += ["-s", sh]
    if args.get("comment"):
        argv += ["-c", _name(args["comment"], re.compile(r"^[A-Za-z0-9 ._@-]{1,100}$"), "comment")]
    groups = [_name(g, USER_RE, "group") for g in (args.get("groups") or [])][:50]
    if groups:
        argv += ["-G", ",".join(groups)]
    argv.append(name)
    rc, out, err = run(argv, timeout=60)
    need(rc == 0, "useradd_failed", clean(err, 400))
    if args.get("password"):
        _set_password(name, args["password"])
    return {"name": name, "created": True}


def _exists_user(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def op_user_mod(conf, args):
    require_root("changing an account")
    name = _name(args.get("name"), USER_RE, "user")
    need(_exists_user(name), "no_user", "no such account")
    done = []
    if args.get("shell"):
        rc, out, err = run(["usermod", "-s", _shell(args["shell"]), name], timeout=30)
        need(rc == 0, "usermod_failed", clean(err, 300))
        done.append("shell")
    for g in (args.get("add_groups") or [])[:50]:
        rc, out, err = run(["usermod", "-aG", _name(g, USER_RE, "group"), name], timeout=30)
        need(rc == 0, "usermod_failed", clean(err, 300))
        done.append("+" + g)
    for g in (args.get("remove_groups") or [])[:50]:
        g = _name(g, USER_RE, "group")
        rc, out, err = run(["gpasswd", "-d", name, g], timeout=30)
        need(rc == 0, "usermod_failed", clean(err, 300))
        done.append("-" + g)
    if args.get("lock") is True:
        rc, out, err = run(["usermod", "-L", name], timeout=30)
        need(rc == 0, "usermod_failed", clean(err, 300))
        done.append("locked")
    elif args.get("lock") is False:
        rc, out, err = run(["usermod", "-U", name], timeout=30)
        need(rc == 0, "usermod_failed", clean(err, 300))
        done.append("unlocked")
    if args.get("password"):
        _set_password(name, args["password"])
        done.append("password")
    return {"name": name, "changed": done}


def op_user_del(conf, args):
    require_root("deleting an account")
    name = _name(args.get("name"), USER_RE, "user")
    u = pwd.getpwnam(name) if _exists_user(name) else None
    need(u, "no_user", "no such account")
    need(u.pw_uid != 0, "protected", "root cannot be deleted")
    need(name != os.environ.get("SUDO_USER", "") and name != os.environ.get("USER", ""),
         "protected", "the account SATOM is signed in with cannot delete itself")
    argv = ["userdel"] + (["-r"] if args.get("remove_home") else []) + [name]
    rc, out, err = run(argv, timeout=120)
    need(rc == 0 or (rc == 12 and args.get("remove_home")), "userdel_failed", clean(err, 300))
    return {"name": name, "deleted": True}


def op_group_add(conf, args):
    require_root("creating a group")
    name = _name(args.get("name"), USER_RE, "group")
    rc, out, err = run(["groupadd"] + (["-r"] if args.get("system") else []) + [name], timeout=30)
    need(rc == 0, "groupadd_failed", clean(err, 300))
    return {"name": name, "created": True}


def op_group_del(conf, args):
    require_root("deleting a group")
    name = _name(args.get("name"), USER_RE, "group")
    need(name not in ("root", "sudo", "wheel", "adm", "users"), "protected",
         "%s is a system group" % name)
    rc, out, err = run(["groupdel", name], timeout=30)
    need(rc == 0, "groupdel_failed", clean(err, 300))
    return {"name": name, "deleted": True}


# ── SSH server ──────────────────────────────────────────────────────────────

SSHD_CONFIG = "/etc/ssh/sshd_config"


def _sshd_unit():
    for u in ("ssh.service", "sshd.service"):
        rc, out, _ = run(["systemctl", "cat", u], timeout=15)
        if rc == 0:
            return u
    return "sshd.service"


def op_sshd_get(conf, args):
    effective = {}
    sshd = which("sshd")
    if is_root() and sshd:
        rc, out, _ = run([sshd, "-T"], timeout=30)
        for l in out.splitlines():
            k, _, v = l.partition(" ")
            effective[k] = clean(v, 300)
    content, sha = "", ""
    try:
        with open(SSHD_CONFIG, "rb") as fh:
            raw = fh.read(512 * 1024)
        content, sha = clean(raw.decode("utf-8", "replace")), hashlib.sha256(raw).hexdigest()
    except OSError:
        pass
    managed = {}
    for k in SSHD_KEYS:
        managed[k] = effective.get(k.lower(), "")
    return {"effective": managed, "all": effective, "content": content, "sha256": sha,
            "complete": is_root(), "unit": _sshd_unit() if which("systemctl") else ""}


def op_sshd_set(conf, args):
    require_root("changing the SSH server")
    settings = args.get("settings") or {}
    need(isinstance(settings, dict) and settings, "bad_settings", "settings to change")
    for k, v in settings.items():
        need(k in SSHD_KEYS, "bad_settings", "%s cannot be set here" % k)
        need(isinstance(v, str) and re.match(r"^[A-Za-z0-9 ,._@*?:/-]{0,300}$", v), "bad_settings",
             "invalid value for %s" % k)
    with open(SSHD_CONFIG, "rb") as fh:
        raw = fh.read()
    base = args.get("base_sha256")
    if base and base != hashlib.sha256(raw).hexdigest():
        raise Refused("conflict", "sshd_config changed since it was read")
    lines = raw.decode("utf-8", "replace").splitlines()
    match_at = next((i for i, l in enumerate(lines) if re.match(r"(?i)^\s*Match\s", l)), len(lines))
    for k, v in settings.items():
        idx = next((i for i, l in enumerate(lines[:match_at])
                    if re.match(r"(?i)^\s*%s\s" % k, l)), None)
        new = "%s %s" % (k, v) if v != "" else None
        if idx is not None:
            if new is None:
                del lines[idx]
                match_at -= 1
            else:
                lines[idx] = new
        elif new is not None:
            lines.insert(match_at, new)
            match_at += 1
    data = ("\n".join(lines) + "\n").encode("utf-8")
    mode = stat.S_IMODE(os.stat(SSHD_CONFIG).st_mode)
    bk = backup(conf, "sshd.set", [SSHD_CONFIG])
    _write_atomic(SSHD_CONFIG, data, mode)
    rc, out, err = run([which("sshd") or "sshd", "-t"], timeout=30)
    if rc != 0:
        _write_atomic(SSHD_CONFIG, raw, mode)
        return {"applied": False, "restored": True, "test_output": clean(out + err, 2000),
                "backup": bk}
    rc, out2, err2 = run(["systemctl", "reload", _sshd_unit()], timeout=60)
    return {"applied": rc == 0, "restored": False, "test_output": "",
            "reload_output": clean(out2 + err2, 1000), "backup": bk}


AUTHKEY_RE = re.compile(r"^(?:[A-Za-z0-9,=\"._@: -]+ )?(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|"
                        r"sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) "
                        r"[A-Za-z0-9+/=]{40,}( .{0,200})?$")


def _authkeys_path(user):
    u = pwd.getpwnam(_name(user, USER_RE, "user"))
    return u, os.path.join(u.pw_dir, ".ssh", "authorized_keys")


def op_authkeys_get(conf, args):
    me = pwd.getpwuid(os.geteuid()).pw_name
    u, path = _authkeys_path(args.get("user") or me)
    if not os.path.exists(path):
        return {"user": u.pw_name, "keys": [], "sha256": ""}
    with open(path, "rb") as fh:
        raw = fh.read(256 * 1024)
    keys = []
    for l in raw.decode("utf-8", "replace").splitlines():
        if l.strip() and not l.startswith("#"):
            parts = l.split()
            kt = next((p for p in parts if p.startswith(("ssh-", "ecdsa-", "sk-"))), "")
            comment = parts[-1] if len(parts) >= 3 and not parts[-1].startswith("AAAA") else ""
            fp = ""
            try:
                blob = parts[parts.index(kt) + 1]
                fp = "SHA256:" + base64.b64encode(hashlib.sha256(
                    base64.b64decode(blob)).digest()).decode().rstrip("=")
            except (ValueError, IndexError):
                pass
            keys.append({"type": kt, "fingerprint": fp, "comment": clean(comment, 200),
                         "options": parts[0] != kt, "line": clean(l, 2000)})
    return {"user": u.pw_name, "keys": keys, "sha256": hashlib.sha256(raw).hexdigest()}


def op_authkeys_put(conf, args):
    me = pwd.getpwuid(os.geteuid()).pw_name
    u, path = _authkeys_path(args.get("user") or me)
    lines = args.get("keys") or []
    need(isinstance(lines, list) and len(lines) <= 500, "bad_keys", "a list of keys")
    for l in lines:
        need(isinstance(l, str) and AUTHKEY_RE.match(l.strip()), "bad_keys",
             "not an OpenSSH public key line: %s" % clean(str(l)[:60], 60))
    raw = b""
    if os.path.exists(path):
        with open(path, "rb") as fh:
            raw = fh.read()
    base = args.get("base_sha256")
    if base and raw and base != hashlib.sha256(raw).hexdigest():
        raise Refused("conflict", "authorized_keys changed since it was read")
    d = os.path.dirname(path)
    if not os.path.isdir(d):
        os.makedirs(d, mode=0o700)
        if is_root():
            os.chown(d, u.pw_uid, u.pw_gid)
    if raw:
        keep_version(path)
    _write_file(path, ("\n".join(l.strip() for l in lines) + "\n").encode("utf-8"), 0o600,
                (u.pw_uid, u.pw_gid))
    return {"user": u.pw_name, "keys": len(lines), "saved": True}


# ── scripts ─────────────────────────────────────────────────────────────────

def op_script_run(conf, args):
    interp = args.get("interpreter") or "bash"
    content = args.get("content")
    need(isinstance(content, str) and 0 < len(content) <= 1024 * 1024, "bad_script",
         "the script text (up to 1 MiB)")
    if interp == "custom":
        need(content.startswith("#!"), "bad_script", "a custom script starts with #!")
        exe = None
    else:
        need(interp in INTERPRETERS, "bad_interpreter", "bash, sh, python, php, perl or custom")
        exe = which(INTERPRETERS[interp])
        need(exe, "no_interpreter", "%s is not installed on this server" % INTERPRETERS[interp])
    argv_extra = args.get("args") or []
    need(isinstance(argv_extra, list) and len(argv_extra) <= 50
         and all(isinstance(a, str) and len(a) <= 2000 and "\x00" not in a for a in argv_extra),
         "bad_args", "up to 50 text arguments")
    cwd = args.get("cwd") or os.path.expanduser("~")
    cwd = _abs(cwd)
    need(os.path.isdir(cwd), "not_a_dir", "the working folder does not exist")
    env = {}
    for k, v in (args.get("env") or {}).items():
        need(ENV_RE.match(str(k)) and isinstance(v, str) and len(v) <= 4000, "bad_env",
             "environment names are letters, digits and _")
        env[str(k)] = v
    timeout = max(1, min(int(args.get("timeout") or 300), 3600))
    tmp = tempfile.mkdtemp(prefix="satom-wsm-run-")
    try:
        os.chmod(tmp, 0o700)
        path = os.path.join(tmp, "script")
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, 0o700)
        argv = ([exe, path] if exe else [path]) + argv_extra
        started = time.time()
        rc, out, err = run(argv, timeout=timeout, env=env, cwd=cwd, limit=1024 * 1024)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"exit_code": rc, "stdout": out, "stderr": err,
            "seconds": round(time.time() - started, 3), "cwd": cwd,
            "timed_out": rc == 124, "interpreter": interp}


# ── dispatch ────────────────────────────────────────────────────────────────

SESSION_OPS = {
    "whoami": op_whoami,
    "info": lambda c, a: dict(op_info(c, a), mode="session"),
    "vhosts.list": op_vhosts_list, "vhost.get": op_vhost_get, "vhost.put": op_vhost_put,
    "vhost.create": op_vhost_create2,
    "vhost.enable": lambda c, a: op_vhost_toggle(c, a, True),
    "vhost.disable": lambda c, a: op_vhost_toggle(c, a, False),
    "vhost.delete": op_vhost_delete, "vhost.snippet": op_vhost_snippet,
    "vhost.test": op_vhost_test, "http.check": op_http_check,
    "htaccess.apply": op_htaccess_apply, "apache.override": op_apache_override,
    "fs.list": op_fs_list, "fs.stat": op_fs_stat, "fs.read": op_fs_read, "fs.write": op_fs_write,
    "fs.mkdir": op_fs_mkdir, "fs.move": op_fs_move, "fs.copy": op_fs_copy,
    "fs.delete": op_fs_delete, "fs.chmod": op_fs_chmod, "fs.chown": op_fs_chown,
    "fs.search": op_fs_search, "fs.archive": op_fs_archive, "fs.extract": op_fs_extract,
    "fs.history": op_fs_history, "fs.restore": op_fs_restore, "fs.version": op_fs_version,
    "certs.list": op_certs_list, "cert.get": op_cert_get, "cert.csr": op_cert_csr,
    "cert.install": op_cert_install, "cert.assign": op_cert_assign, "cert.delete": op_cert_delete,
    "cert.import": op_cert_import, "acme.status": op_acme_status, "acme.issue": op_acme_issue,
    "acme.renew": op_acme_renew, "acme.revoke": op_acme_revoke,
    "acme.autorenew": op_acme_autorenew, "tls.check": op_tls_check,
    "pkg.search": op_pkg_search, "pkg.installed": op_pkg_installed, "pkg.show": op_pkg_show,
    "pkg.updates": op_pkg_updates, "pkg.refresh": op_pkg_refresh, "pkg.plan": op_pkg_plan,
    "pkg.apply": op_pkg_apply,
    "svc.list": op_svc_list, "svc.status": op_svc_status, "svc.action": op_svc_action,
    "svc.deps": op_svc_deps, "svc.logs": op_svc_logs,
    "cron.get": op_cron_get, "cron.put": op_cron_put, "cron.users": op_cron_users,
    "cron.log": op_cron_log,
    "logs.sources": op_logs_sources, "logs.read": op_logs_read, "journal.read": op_journal_read,
    "security.scan": op_security_scan, "fw.rule": op_fw_rule, "fw.enable": op_fw_enable,
    "f2b.status": op_f2b_status, "f2b.unban": op_f2b_unban,
    "users.list": op_users_list, "user.add": op_user_add, "user.mod": op_user_mod,
    "user.del": op_user_del, "group.add": op_group_add, "group.del": op_group_del,
    "sshd.get": op_sshd_get, "sshd.set": op_sshd_set,
    "authkeys.get": op_authkeys_get, "authkeys.put": op_authkeys_put,
    "script.run": op_script_run,
}


def _who():
    try:
        name = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        name = str(os.geteuid())
    return {"user": clean(name, 64), "uid": os.geteuid()}


def _scrub(obj):
    if isinstance(obj, str):
        return clean(obj)
    if isinstance(obj, dict):
        return {str(k): _scrub(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub(v) for v in obj]
    return obj


def session_handle(raw):
    """bytes in -> response dict. Never raises."""
    entry = {"ts": datetime.datetime.utcnow().isoformat() + "Z", "uid": os.geteuid()}
    conf = None
    try:
        try:
            req = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise Refused("bad_request", "the request is not JSON")
        if not isinstance(req, dict) or not isinstance(req.get("args", {}), dict):
            raise Refused("bad_request", "expected {\"op\": ..., \"args\": {...}}")
        op = req.get("op")
        entry["op"] = op if isinstance(op, str) else "?"
        entry["by"] = str(req.get("by") or "")[:64]
        fn = SESSION_OPS.get(op)
        if fn is None:
            raise Refused("unknown_op", "unknown operation")
        conf = detect_conf()
        result = fn(conf, req.get("args") or {})
        entry["ok"] = True
        _log(conf, entry)
        return {"ok": True, "result": _scrub(result), "who": _who()}
    except Refused as exc:
        entry.update({"ok": False, "error": exc.code})
        _log(conf, entry)
        return {"ok": False, "error": exc.code, "detail": clean(exc.detail, 500), "who": _who()}
    except PermissionError as exc:
        entry.update({"ok": False, "error": "permission_denied"})
        _log(conf, entry)
        return {"ok": False, "error": "permission_denied",
                "detail": clean("%s: %s" % (exc.strerror or "Permission denied",
                                            exc.filename or ""), 500), "who": _who()}
    except (KeyError, ValueError, TypeError) as exc:
        entry.update({"ok": False, "error": "bad_request"})
        _log(conf, entry)
        return {"ok": False, "error": "bad_request",
                "detail": clean("%s: %s" % (exc.__class__.__name__, exc), 300), "who": _who()}
    except OSError as exc:
        entry.update({"ok": False, "error": "os_error"})
        _log(conf, entry)
        return {"ok": False, "error": "os_error",
                "detail": clean("%s (%s) %s" % (exc.strerror or exc.__class__.__name__,
                                                exc.errno, exc.filename or ""), 500),
                "who": _who()}
    except Exception as exc:  # noqa: BLE001 -- the answer must always be JSON
        entry.update({"ok": False, "error": "internal"})
        _log(conf, entry)
        return {"ok": False, "error": "internal", "detail": exc.__class__.__name__, "who": _who()}


def session_main(stream):
    """Entry point when SATOM runs this file over SSH: the rest of stdin is
    the request; the answer is one JSON object on stdout."""
    os.umask(0o022)
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    out = session_handle(raw) if len(raw) <= MAX_REQUEST_BYTES else {
        "ok": False, "error": "too_large", "detail": "request too large", "who": _who()}
    sys.stdout.write(json.dumps(out, sort_keys=True))
    sys.stdout.flush()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--version"]:
        print(WSM_VERSION)
    elif sys.argv[1:2] == ["--selftest"]:
        print(json.dumps(session_handle(b'{"op": "whoami", "args": {}}'), indent=2))
    else:
        session_main(sys.stdin.buffer)
