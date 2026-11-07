#!/usr/bin/python3
# SPDX-License-Identifier: Elastic-2.0
"""satom-webctl -- the only program SATOM may run on a managed web server.

WHY THIS EXISTS
SATOM manages nginx and Apache virtual hosts, and the files under their
document roots, over SSH. The SSH key SATOM holds is installed for the
unprivileged account ``satom-mon`` with ``restrict,command="satom-webctl"``:
whatever the client asks for, sshd runs THIS program and nothing else. So the
key opens no shell, forwards nothing, and can only ask for the operations
listed in OPERATIONS below -- even if SATOM itself were compromised.

PROTOCOL
One JSON object on stdin, one JSON object on stdout, then exit:

    {"op": "files.list", "args": {"server": "nginx", "name": "shop", "path": ""}}
    -> {"ok": true, "result": {...}}
    -> {"ok": false, "error": "<code>", "detail": "<text>"}

The connection is always opened by SATOM. This program never connects
anywhere, holds no credential of SATOM's and listens on nothing.

WHAT IT GUARANTEES (on the server, whatever the caller sends)
* Files: every path is resolved and must stay inside the document root of the
  virtual host named in the request, and that document root must itself be
  inside one of the configured roots (default /var/www, /srv/www). ``..``,
  absolute paths and symlinks that lead outside are refused.
* Configuration: a virtual host file is backed up before any change; after the
  change the server's own test (``nginx -t`` / ``apachectl configtest``) runs;
  if it fails the previous file is restored and nothing is reloaded. A change
  that passes is applied with a reload, never a restart.
* Privilege: it runs as ``satom-mon``. Writing relies on ACLs the installer
  set on the configured roots and the sites directories; the test and reload
  run through two exact sudoers lines per server -- nothing else.
* ``"read_only": true`` in the configuration refuses every write on this host,
  whatever SATOM's own setting says.

Python 3.6+ standard library only (SUSE 15 ships 3.6).
"""
import base64
import datetime
import hashlib
import io
import ipaddress
import json
import os
import re
import select
import ssl
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

VERSION = "1.2.0"
CONF_PATH = os.environ.get("SATOM_WEBCTL_CONF", "/etc/satom-webctl.json")
MAX_REQUEST_BYTES = 16 * 1024 * 1024
READ_TIMEOUT = 30
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
SERVER_NAME_RE = re.compile(r"^(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})$|^_$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]{1,255}$")
#: Control characters and the Unicode bidi/zero-width marks. A name that holds
#: one is left out of a listing (and counted) instead of being sent: SATOM's
#: ingestion gate refuses a whole answer for one such value, and one hostile
#: file name must not make a folder impossible to browse.
TEXT_UNSAFE_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
UNSAFE_TEXT_RE = re.compile("[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
DEFAULTS = {
    "servers": {},
    "roots": ["/var/www", "/srv/www"],
    "backup_dir": "/var/lib/satom-webctl/backups",
    "log": "/var/log/satom-webctl/webctl.log",
    "max_file_bytes": 4 * 1024 * 1024,
    "max_list": 5000,
    "keep_backups": 200,
    "read_only": False,
    "command_timeout": 60,
    "cert_dir": "/etc/satom-webctl/certs",
    "openssl": "",
    "expiring_days": 30,
}
WRITE_OPS = ("vhost.put", "vhost.create", "vhost.enable", "vhost.disable",
             "vhost.delete", "files.write", "files.mkdir", "files.rename",
             "files.delete", "cert.csr", "cert.install", "cert.assign", "cert.delete")


class Refused(Exception):
    """A request this program will not carry out. ``code`` is stable."""

    def __init__(self, code, detail=""):
        Exception.__init__(self, detail or code)
        self.code = code
        self.detail = detail


# ── configuration ───────────────────────────────────────────────────────────

def load_conf(path=None):
    path = path or CONF_PATH
    try:
        with open(path, "r") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        raise Refused("config", "cannot read %s: %s" % (path, exc.__class__.__name__))
    conf = dict(DEFAULTS)
    conf.update(raw if isinstance(raw, dict) else {})
    servers = {}
    for key, spec in (conf.get("servers") or {}).items():
        if key not in ("nginx", "apache") or not isinstance(spec, dict):
            continue
        if spec.get("layout") not in ("debian", "confd"):
            continue
        servers[key] = spec
    conf["servers"] = servers
    conf["roots"] = [os.path.realpath(r) for r in conf.get("roots") or []
                     if isinstance(r, str) and r.startswith("/") and r != "/"]
    return conf


def server_spec(conf, server):
    spec = conf["servers"].get(server)
    if not spec:
        raise Refused("unknown_server", "no %r server is configured on this host" % (server,))
    return spec


# ── virtual host parsing ────────────────────────────────────────────────────

def _strip_comments(text):
    out = []
    for line in text.splitlines():
        quote = None
        cut = len(line)
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch
            elif ch == "#":
                cut = i
                break
        out.append(line[:cut])
    return "\n".join(out)


def _unquote(word):
    word = word.strip()
    if len(word) >= 2 and word[0] == word[-1] and word[0] in ("'", '"'):
        return word[1:-1]
    return word


def parse_nginx(text):
    """Server blocks of one nginx file: names, roots, listens, ssl."""
    text = _strip_comments(text)
    blocks = []
    for m in re.finditer(r"\bserver\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[m.end():i - 1]
        # Only directives at the block's own level count for root/listen; a
        # ``root`` inside ``location {}`` is a sub-root, still a docroot.
        names, roots, listens = [], [], []
        for d in re.finditer(r"(?m)^\s*(server_name|root|listen)\s+([^;{}]+);", body):
            key, val = d.group(1), d.group(2).strip()
            if key == "server_name":
                names.extend(_unquote(w) for w in val.split())
            elif key == "root":
                roots.append(_unquote(val))
            else:
                listens.append(val)
        ssl = any(re.search(r"(^|\s)ssl(\s|$)", l) or re.search(r"(^|[\s:\]])443(\s|$)", l)
                  for l in listens)
        blocks.append({"server_names": names, "docroots": roots,
                       "listen": listens, "ssl": bool(ssl)})
    return blocks


def parse_apache(text):
    text = _strip_comments(text)
    blocks = []
    for m in re.finditer(r"(?is)<VirtualHost\s+([^>]*)>(.*?)</VirtualHost\s*>", text):
        body = m.group(2)
        names, roots = [], []
        ssl = False
        for d in re.finditer(r"(?im)^\s*(ServerName|ServerAlias|DocumentRoot|SSLEngine)\s+(.+?)\s*$", body):
            key, val = d.group(1).lower(), d.group(2)
            if key in ("servername", "serveralias"):
                names.extend(_unquote(w) for w in val.split())
            elif key == "documentroot":
                roots.append(_unquote(val))
            elif key == "sslengine":
                ssl = val.strip().lower() == "on"
        listen = [w for w in m.group(1).split()]
        ssl = ssl or any(w.endswith(":443") for w in listen)
        blocks.append({"server_names": names, "docroots": roots,
                       "listen": listen, "ssl": ssl})
    return blocks


def parse_vhost(server, text):
    return parse_nginx(text) if server == "nginx" else parse_apache(text)


# ── virtual host files ──────────────────────────────────────────────────────

def _check_name(spec, name):
    if not isinstance(name, str) or not NAME_RE.match(name) or ".." in name:
        raise Refused("bad_name", "a virtual host name is letters, digits, '.', '_' or '-'")
    if spec["layout"] == "confd":
        if name.endswith(".conf.disabled"):
            name = name[:-len(".disabled")]
        if not name.endswith(".conf"):
            raise Refused("bad_name", "on this layout a virtual host file ends in .conf")
    return name


def _vhost_paths(spec, name):
    """(file_when_enabled_or_available, link_or_disabled_path)."""
    avail = spec["available"]
    if spec["layout"] == "debian":
        return os.path.join(avail, name), os.path.join(spec["enabled"], name)
    return os.path.join(avail, name), os.path.join(avail, name + ".disabled")


def vhost_state(spec, name):
    """(path_of_the_file, enabled) or Refused if it does not exist."""
    main, other = _vhost_paths(spec, name)
    if spec["layout"] == "debian":
        if not os.path.isfile(main) or os.path.islink(main):
            raise Refused("not_found", "no virtual host %r" % name)
        enabled = os.path.islink(other) and os.path.realpath(other) == os.path.realpath(main)
        return main, enabled
    if os.path.isfile(main) and not os.path.islink(main):
        return main, True
    if os.path.isfile(other) and not os.path.islink(other):
        return other, False
    raise Refused("not_found", "no virtual host %r" % name)


def iter_vhost_files(conf):
    """(server, name, path, enabled, stat, text) of every virtual host file
    of the configured servers, text cut at 512 KiB."""
    for server in sorted(conf["servers"]):
        spec = conf["servers"][server]
        avail = spec["available"]
        try:
            names = sorted(os.listdir(avail))
        except OSError:
            continue
        for fname in names:
            path = os.path.join(avail, fname)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if spec["layout"] == "confd":
                if fname.endswith(".conf"):
                    name, enabled = fname, True
                elif fname.endswith(".conf.disabled"):
                    name, enabled = fname[:-len(".disabled")], False
                else:
                    continue
            else:
                if not NAME_RE.match(fname):
                    continue
                name = fname
                link = os.path.join(spec["enabled"], fname)
                enabled = os.path.islink(link) and os.path.realpath(link) == os.path.realpath(path)
            if not NAME_RE.match(name):
                continue
            try:
                st = os.stat(path)
                with open(path, "r", errors="replace") as fh:
                    text = fh.read(512 * 1024)
            except OSError:
                continue
            yield server, name, path, enabled, st, text


def list_vhosts(conf):
    out = []
    for server, name, path, enabled, st, text in iter_vhost_files(conf):
        blocks = parse_vhost(server, text)
        if not blocks:
            continue          # a conf.d snippet, not a virtual host
        names_ = []
        roots, listens = [], []
        for b in blocks:
            names_.extend(n for n in b["server_names"]
                          if n not in names_ and SERVER_NAME_RE.match(n))
            roots.extend(r for r in b["docroots"] if r not in roots
                         and r.startswith("/") and not UNSAFE_TEXT_RE.search(r)
                         and len(r) <= 1024)
            listens.extend(l[:128] for l in b["listen"] if l not in listens
                           and not UNSAFE_TEXT_RE.search(l))
        out.append({"server": server, "name": name, "enabled": enabled,
                    "server_names": names_[:50], "docroots": roots[:20],
                    "listen": listens[:20], "ssl": any(b["ssl"] for b in blocks),
                    "bytes": st.st_size, "mtime": int(st.st_mtime),
                    "managed_root": all(_inside_roots(conf, r) for r in roots) and bool(roots)})
    return out


# ── server test / reload with rollback ──────────────────────────────────────

def _run(conf, argv):
    if not argv:
        return 0, ""
    try:
        p = subprocess.run(list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=conf["command_timeout"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, exc.__class__.__name__
    return p.returncode, (p.stdout or "")[-4000:]


def _apply(conf, spec, undo):
    """Test the configuration; on failure run ``undo`` and test again; on
    success reload. Returns the result dict -- never raises on a failed test."""
    rc, out = _run(conf, spec.get("test"))
    if rc != 0:
        undo()
        rc2, _ = _run(conf, spec.get("test"))
        return {"applied": False, "test_output": out,
                "restored": True, "restored_config_valid": rc2 == 0}
    rrc, rout = _run(conf, spec.get("reload"))
    return {"applied": rrc == 0, "test_output": out,
            "reload_output": rout if rrc != 0 else "", "restored": False}


# ── backups ─────────────────────────────────────────────────────────────────

def backup(conf, op, paths):
    """tar.gz of ``paths`` (files or directories) in the backup dir. Returns
    the backup file name, or '' when there was nothing to keep."""
    paths = [p for p in paths if os.path.lexists(p)]
    if not paths:
        return ""
    bdir = conf["backup_dir"]
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
    digest = hashlib.sha256("\n".join(paths).encode("utf-8", "replace")).hexdigest()[:8]
    name = "%s-%s-%s.tar.gz" % (stamp, op.replace(".", "-"), digest)
    with tarfile.open(os.path.join(bdir, name), "w:gz") as tar:
        for p in paths:
            tar.add(p, arcname=p.lstrip("/"), recursive=True)
    _prune(conf)
    return name


def _prune(conf):
    bdir = conf["backup_dir"]
    try:
        files = sorted(f for f in os.listdir(bdir) if f.endswith(".tar.gz"))
    except OSError:
        return
    for f in files[:-int(conf["keep_backups"])] if len(files) > int(conf["keep_backups"]) else []:
        try:
            os.unlink(os.path.join(bdir, f))
        except OSError:
            pass


# ── file confinement ────────────────────────────────────────────────────────

def _inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _planned_real(path):
    """Where ``path`` would really live once created: the real path of its
    nearest existing ancestor plus the part that does not exist yet."""
    path = os.path.normpath(path)
    rest = []
    cur = path
    while not os.path.lexists(cur) and cur not in ("/", ""):
        cur, tail = os.path.split(cur)
        rest.insert(0, tail)
    return os.path.join(os.path.realpath(cur or "/"), *rest) if rest else os.path.realpath(cur)


def _inside_roots(conf, path):
    real = os.path.realpath(path)
    return any(_inside(real, r) for r in conf["roots"])


def docroot_for(conf, args):
    """The document root a file request works in: one of the roots of the
    named virtual host, itself inside a configured root."""
    spec = server_spec(conf, args.get("server"))
    name = _check_name(spec, args.get("name"))
    path, _ = vhost_state(spec, name)
    with open(path, "r", errors="replace") as fh:
        blocks = parse_vhost(args.get("server"), fh.read(512 * 1024))
    roots = []
    for b in blocks:
        roots.extend(r for r in b["docroots"] if r not in roots)
    if not roots:
        raise Refused("no_docroot", "the virtual host declares no document root")
    wanted = args.get("docroot") or roots[0]
    if wanted not in roots:
        raise Refused("bad_docroot", "not a document root of this virtual host")
    real = os.path.realpath(wanted)
    if not any(_inside(real, r) for r in conf["roots"]):
        raise Refused("root_not_managed",
                      "the document root is outside the roots this host lets SATOM manage")
    return real


def resolve(docroot, rel, must_exist=True):
    """``rel`` under ``docroot`` -> real absolute path, or Refused."""
    if rel is None:
        rel = ""
    if not isinstance(rel, str) or "\x00" in rel or len(rel) > 1024:
        raise Refused("bad_path", "invalid path")
    if rel.startswith("/") or rel.startswith("\\"):
        raise Refused("bad_path", "paths are relative to the document root")
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise Refused("bad_path", "'..' is not allowed")
    target = os.path.join(docroot, *parts) if parts else docroot
    parent = os.path.realpath(os.path.dirname(target)) if parts else docroot
    if not _inside(parent, docroot):
        raise Refused("outside_docroot", "the path leaves the document root")
    if os.path.lexists(target):
        real = os.path.realpath(target)
        if not _inside(real, docroot):
            raise Refused("outside_docroot", "the path leads outside the document root")
    elif must_exist:
        raise Refused("not_found", "no such file or directory")
    return target


def _rel(docroot, path):
    r = os.path.relpath(path, docroot)
    return "" if r == "." else r


def _sha(data):
    return hashlib.sha256(data).hexdigest()


# ── operations ──────────────────────────────────────────────────────────────

def op_info(conf, args):
    servers = {}
    for key, spec in conf["servers"].items():
        servers[key] = {"layout": spec["layout"], "available": spec["available"],
                        "enabled": spec.get("enabled") or ""}
    try:
        cert_dir = _cert_dir(conf)
    except Refused:
        cert_dir = ""
    try:
        exe = _openssl(conf)
        p = subprocess.run([exe, "version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
        openssl = _safe_text(p.stdout.strip(), 120) if p.returncode == 0 else ""
    except (Refused, OSError, subprocess.TimeoutExpired):
        openssl = ""
    return {"version": VERSION, "servers": servers, "roots": conf["roots"],
            "read_only": bool(conf["read_only"]),
            "max_file_bytes": int(conf["max_file_bytes"]),
            "cert_dir": cert_dir, "certs_ready": bool(openssl and cert_dir
                                                      and os.path.isdir(cert_dir)),
            "openssl": openssl}


def op_vhosts_list(conf, args):
    return {"vhosts": list_vhosts(conf)}


def op_vhost_get(conf, args):
    spec = server_spec(conf, args.get("server"))
    name = _check_name(spec, args.get("name"))
    path, enabled = vhost_state(spec, name)
    with open(path, "rb") as fh:
        data = fh.read(int(conf["max_file_bytes"]) + 1)
    if len(data) > int(conf["max_file_bytes"]):
        raise Refused("too_large", "the file is larger than this host allows")
    return {"server": args["server"], "name": name, "enabled": enabled,
            "content": data.decode("utf-8", "replace"), "sha256": _sha(data)}


def _write_atomic(path, data, mode=None):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".satom-webctl-", dir=d)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _content_bytes(args, conf, key="content"):
    content = args.get(key)
    if not isinstance(content, str):
        raise Refused("bad_content", "content must be text")
    data = content.encode("utf-8")
    if len(data) > int(conf["max_file_bytes"]):
        raise Refused("too_large", "the content is larger than this host allows")
    return data


def op_vhost_put(conf, args):
    spec = server_spec(conf, args.get("server"))
    name = _check_name(spec, args.get("name"))
    path, enabled = vhost_state(spec, name)
    data = _content_bytes(args, conf)
    with open(path, "rb") as fh:
        old = fh.read()
    base = args.get("base_sha256")
    if base and base != _sha(old):
        raise Refused("conflict", "the file changed since it was read")
    if old == data:
        return {"changed": False, "sha256": _sha(old)}
    mode = stat.S_IMODE(os.stat(path).st_mode)
    bk = backup(conf, "vhost.put", [path])
    _write_atomic(path, data, mode)

    def undo():
        _write_atomic(path, old, mode)

    res = _apply(conf, spec, undo) if enabled else {"applied": True, "test_output": "",
                                                       "restored": False}
    res.update({"changed": not res.get("restored"), "backup": bk,
                "sha256": _sha(old if res.get("restored") else data)})
    return res


def _link_or_rename(spec, name, enable):
    main, other = _vhost_paths(spec, name)
    if spec["layout"] == "debian":
        if enable:
            os.symlink(main, other)
        else:
            os.unlink(other)
    else:
        if enable:
            os.rename(other, main)
        else:
            os.rename(main, other)


def op_vhost_toggle(conf, args, enable):
    spec = server_spec(conf, args.get("server"))
    name = _check_name(spec, args.get("name"))
    path, enabled = vhost_state(spec, name)
    if enabled == enable:
        return {"changed": False, "enabled": enabled}
    _link_or_rename(spec, name, enable)
    res = _apply(conf, spec, lambda: _link_or_rename(spec, name, not enable))
    res.update({"changed": not res.get("restored"),
                "enabled": enable if not res.get("restored") else enabled})
    return res


def op_vhost_delete(conf, args):
    spec = server_spec(conf, args.get("server"))
    name = _check_name(spec, args.get("name"))
    path, enabled = vhost_state(spec, name)
    main, other = _vhost_paths(spec, name)
    with open(path, "rb") as fh:
        old = fh.read()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    bk = backup(conf, "vhost.delete", [path])
    link = other if spec["layout"] == "debian" and enabled else None
    if link:
        os.unlink(link)
    os.unlink(path)

    def undo():
        _write_atomic(path, old, mode)
        if link:
            os.symlink(main, link)

    res = _apply(conf, spec, undo) if enabled else {"applied": True, "test_output": "",
                                                       "restored": False}
    res.update({"deleted": not res.get("restored"), "backup": bk})
    return res


NGINX_TEMPLATE = """# Managed by SATOM (satom-webctl {version}) -- created {stamp}
server {{
    listen 80;
    listen [::]:80;
    server_name {names};
{http_body}}}
{https_block}"""

NGINX_SITE = """    root {docroot};
    index {index};
    location / {{
        try_files $uri $uri/ ={not_found};
    }}
{php}    location ~ /\\. {{
        deny all;
    }}
"""

NGINX_PHP = """    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{socket};
    }}
"""

APACHE_TEMPLATE = """# Managed by SATOM (satom-webctl {version}) -- created {stamp}
<VirtualHost *:80>
    ServerName {first}
{aliases}{http_body}</VirtualHost>
{https_block}"""


def op_vhost_create(conf, args):
    server = args.get("server")
    spec = server_spec(conf, server)
    name = args.get("name")
    if spec["layout"] == "confd" and isinstance(name, str) and not name.endswith(".conf"):
        name = name + ".conf"
    name = _check_name(spec, name)
    main, other = _vhost_paths(spec, name)
    if os.path.lexists(main) or os.path.lexists(other):
        raise Refused("exists", "a virtual host with that name already exists")
    names = args.get("server_names") or []
    if (not isinstance(names, list) or not names or len(names) > 20
            or not all(isinstance(n, str) and SERVER_NAME_RE.match(n) for n in names)):
        raise Refused("bad_server_names", "1 to 20 host names")
    kind = args.get("kind") or "static"
    if kind not in ("static", "php"):
        raise Refused("bad_kind", "kind is static or php")
    docroot = args.get("docroot")
    if not isinstance(docroot, str) or not SAFE_PATH_RE.match(docroot) or ".." in docroot:
        raise Refused("bad_docroot", "an absolute document root path")
    if not any(_inside(_planned_real(docroot), r) for r in conf["roots"]):
        raise Refused("root_not_managed", "the document root must be inside a managed root")
    https = bool(args.get("https"))
    cert, key = args.get("cert") or "", args.get("key") or ""
    if https and not (SAFE_PATH_RE.match(cert) and SAFE_PATH_RE.match(key)):
        raise Refused("bad_cert", "https needs absolute cert and key paths")
    socket_ = args.get("php_socket") or "/run/php/php-fpm.sock"
    if not SAFE_PATH_RE.match(socket_):
        raise Refused("bad_socket", "invalid PHP-FPM socket path")
    stamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    if server == "nginx":
        body = NGINX_SITE.format(docroot=docroot,
                                 index="index.php index.html" if kind == "php" else "index.html",
                                 not_found="404",
                                 php=NGINX_PHP.format(socket=socket_) if kind == "php" else "")
        https_block = ""
        if https:
            https_block = ("server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n"
                           "    server_name %s;\n    ssl_certificate %s;\n    ssl_certificate_key %s;\n%s}\n"
                           % (" ".join(names), cert, key, body))
            http_body = "    return 301 https://$host$request_uri;\n"
        else:
            http_body = body
        text = NGINX_TEMPLATE.format(version=VERSION, stamp=stamp, names=" ".join(names),
                                     http_body=http_body, https_block=https_block)
    else:
        aliases = "    ServerAlias %s\n" % " ".join(names[1:]) if len(names) > 1 else ""
        site = '    DocumentRoot "%s"\n    <Directory "%s">\n        Require all granted\n' \
               '        AllowOverride None\n    </Directory>\n' % (docroot, docroot)
        if kind == "php":
            site += '    <FilesMatch "\\.php$">\n        SetHandler "proxy:unix:%s|fcgi://localhost"\n' \
                    '    </FilesMatch>\n' % socket_
        https_block = ""
        if https:
            https_block = ("<VirtualHost *:443>\n    ServerName %s\n%s    SSLEngine on\n"
                           "    SSLCertificateFile %s\n    SSLCertificateKeyFile %s\n%s</VirtualHost>\n"
                           % (names[0], aliases, cert, key, site))
            http_body = "    Redirect permanent / https://%s/\n" % names[0]
        else:
            http_body = site
        text = APACHE_TEMPLATE.format(version=VERSION, stamp=stamp, first=names[0],
                                      aliases=aliases, http_body=http_body,
                                      https_block=https_block)
    made_root = False
    if not os.path.isdir(docroot):
        os.makedirs(docroot, mode=0o755)
        made_root = True
    real = os.path.realpath(docroot)
    if not any(_inside(real, r) for r in conf["roots"]):
        if made_root:
            os.rmdir(docroot)
        raise Refused("root_not_managed", "the document root resolves outside the managed roots")
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
                "docroot_created": made_root})
    return res


def op_files_list(conf, args):
    root = docroot_for(conf, args)
    target = resolve(root, args.get("path"))
    if not os.path.isdir(target):
        raise Refused("not_a_directory", "not a directory")
    entries, truncated, skipped = [], False, 0
    names = sorted(os.listdir(target))
    for fname in names:
        if UNSAFE_TEXT_RE.search(fname) or len(fname) > 255:
            skipped += 1
            continue
        if len(entries) >= int(conf["max_list"]):
            truncated = True
            break
        p = os.path.join(target, fname)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            kind = "link"
        elif stat.S_ISDIR(st.st_mode):
            kind = "dir"
        elif stat.S_ISREG(st.st_mode):
            kind = "file"
        else:
            continue
        entries.append({"name": fname, "type": kind, "size": int(st.st_size),
                        "mtime": int(st.st_mtime), "mode": "%o" % stat.S_IMODE(st.st_mode)})
    return {"docroot": root, "path": _rel(root, target), "entries": entries,
            "truncated": truncated, "skipped": skipped}


def op_files_read(conf, args):
    root = docroot_for(conf, args)
    target = resolve(root, args.get("path"))
    if not os.path.isfile(target):
        raise Refused("not_a_file", "not a regular file")
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(int(conf["max_file_bytes"]) + 1)
    if len(data) > int(conf["max_file_bytes"]):
        raise Refused("too_large", "the file is larger than this host allows")
    out = {"path": _rel(root, target), "size": len(data), "sha256": _sha(data)}
    if args.get("text"):
        # As text when it IS text: valid UTF-8 with no control character other
        # than tab, newline and carriage return (what SATOM's gate accepts in
        # a text field). Anything else is sent as base64, and says so.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is not None and not TEXT_UNSAFE_RE.search(text):
            out.update(content=text, binary=False)
            return out
        out["binary"] = True
    out["content_b64"] = base64.b64encode(data).decode("ascii")
    return out


def op_files_write(conf, args):
    root = docroot_for(conf, args)
    target = resolve(root, args.get("path"), must_exist=False)
    if target == root:
        raise Refused("bad_path", "a file name is required")
    if isinstance(args.get("content"), str):
        data = args["content"].encode("utf-8")
    else:
        try:
            data = base64.b64decode(args.get("content_b64") or "", validate=True)
        except (ValueError, TypeError):
            raise Refused("bad_content", "content_b64 is not base64")
    if len(data) > int(conf["max_file_bytes"]):
        raise Refused("too_large", "the content is larger than this host allows")
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        if not args.get("create_dirs"):
            raise Refused("not_found", "the folder does not exist")
        os.makedirs(parent, mode=0o755)
        if not _inside(os.path.realpath(parent), root):
            raise Refused("outside_docroot", "the folder leaves the document root")
    bk, mode = "", 0o644
    if os.path.lexists(target):
        if os.path.islink(target) or not os.path.isfile(target):
            raise Refused("not_a_file", "only regular files can be overwritten")
        with open(target, "rb") as fh:
            old = fh.read()
        base = args.get("base_sha256")
        if base and base != _sha(old):
            raise Refused("conflict", "the file changed since it was read")
        mode = stat.S_IMODE(os.stat(target).st_mode)
        bk = backup(conf, "files.write", [target])
    elif args.get("base_sha256"):
        raise Refused("conflict", "the file no longer exists")
    _write_atomic(target, data, mode)
    return {"path": _rel(root, target), "size": len(data), "sha256": _sha(data),
            "backup": bk}


def op_files_mkdir(conf, args):
    root = docroot_for(conf, args)
    target = resolve(root, args.get("path"), must_exist=False)
    if os.path.lexists(target):
        raise Refused("exists", "already exists")
    os.mkdir(target, 0o755)
    return {"path": _rel(root, target)}


def op_files_rename(conf, args):
    root = docroot_for(conf, args)
    src = resolve(root, args.get("path"))
    dst = resolve(root, args.get("to"), must_exist=False)
    if src == root or dst == root:
        raise Refused("bad_path", "the document root itself cannot be renamed")
    if os.path.lexists(dst):
        raise Refused("exists", "the destination already exists")
    if os.path.isdir(src) and _inside(dst, src):
        raise Refused("bad_path", "a folder cannot move into itself")
    os.rename(src, dst)
    return {"path": _rel(root, dst)}


def op_files_delete(conf, args):
    root = docroot_for(conf, args)
    target = resolve(root, args.get("path"))
    if target == root:
        raise Refused("bad_path", "the document root itself cannot be deleted")
    is_dir = os.path.isdir(target) and not os.path.islink(target)
    if is_dir and os.listdir(target) and not args.get("recursive"):
        raise Refused("not_empty", "the folder is not empty (set recursive)")
    bk = backup(conf, "files.delete", [target])
    if is_dir:
        shutil.rmtree(target)
    else:
        os.unlink(target)
    return {"path": _rel(root, target), "backup": bk}


# ── certificates ────────────────────────────────────────────────────────────
#
# Managed certificates live in ``cert_dir`` (default /etc/satom-webctl/certs),
# one folder per certificate, owned by satom-mon, mode 0700:
#
#     <name>/privkey.pem    the private key. cert.csr generates it HERE (mode
#                           0600) and it never leaves this server: no
#                           operation returns it, none accepts one.
#     <name>/fullchain.pem  the certificate and its chain (public).
#     <name>/request.csr    the request the certificate was issued for.
#     <name>/pending/       a renewal: the new key and request, moved into
#                           place when a certificate for that key is installed.
#
# nginx and Apache read the key as root, so 0600 for satom-mon is enough. A
# key and certificate an administrator copies here by hand (privkey.pem and
# fullchain.pem in a new folder) are ADOPTED: listed, renewed and assigned
# like any other. Certificates that virtual hosts use from elsewhere are
# listed read-only, with the hosts that use them.

CERT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KEY_TYPES = {
    "ec256": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "ec384": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
    "rsa2048": ["-newkey", "rsa:2048"],
    "rsa4096": ["-newkey", "rsa:4096"],
}
MAX_CHAIN_BYTES = 64 * 1024
MAX_CHAIN_CERTS = 8
PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")
SAN_RE = re.compile(r"^(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})$|^[0-9a-fA-F.:]{2,45}$")
NGINX_TLS_RE = re.compile(r"(?m)^(\s*)(ssl_certificate|ssl_certificate_key)(\s+)([^;\s]+)(\s*;)")
APACHE_TLS_RE = re.compile(r"(?im)^(\s*)(SSLCertificateFile|SSLCertificateKeyFile)(\s+)(\S+)(\s*)$")
APACHE_CHAIN_RE = re.compile(r"(?im)^(\s*)(SSLCertificateChainFile\s+\S+\s*)$")


def _cert_dir(conf):
    d = conf.get("cert_dir") or DEFAULTS["cert_dir"]
    if not isinstance(d, str) or not d.startswith("/") or d == "/":
        raise Refused("config", "cert_dir must be an absolute path")
    return d


def _openssl(conf):
    exe = conf.get("openssl") or shutil.which("openssl") or ""
    if not exe or not os.path.isfile(exe):
        raise Refused("no_openssl", "openssl is not installed on this server")
    return exe


def _check_cert_name(name):
    if not isinstance(name, str) or not CERT_NAME_RE.match(name) or ".." in name:
        raise Refused("bad_cert_name",
                      "a certificate name is lowercase letters, digits, '.', '_' or '-'")
    return name


def _safe_text(value, limit=200):
    return TEXT_UNSAFE_RE.sub("", str(value or ""))[:limit]


def _pem_blocks(text):
    return ["".join(b.split()) for b in PEM_CERT_RE.findall(text)]


def _cert_info(path):
    """What the first certificate of ``path`` says (the stdlib decoder; no
    third-party module), or None when there is no readable certificate."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_CHAIN_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_CHAIN_BYTES:
        return None
    blocks = _pem_blocks(data.decode("ascii", "replace"))
    if not blocks:
        return None
    try:
        der = base64.b64decode(blocks[0])
        d = ssl._ssl._test_decode_cert(path)
    except Exception:  # noqa: BLE001 -- any undecodable file is "no certificate"
        return None

    def first(rdns, key):
        for rdn in rdns or ():
            for k, v in rdn:
                if k == key:
                    return _safe_text(v)
        return ""
    try:
        not_after = int(ssl.cert_time_to_seconds(d["notAfter"]))
        not_before = int(ssl.cert_time_to_seconds(d["notBefore"]))
    except (KeyError, ValueError):
        return None
    sans = []
    for kind, value in d.get("subjectAltName") or ():
        value = _safe_text(value, 253)
        if kind in ("DNS", "IP Address") and SAN_RE.match(value) and value not in sans:
            sans.append(value)
    left = int((not_after - time.time()) // 86400)
    return {"subject": first(d.get("subject"), "commonName"),
            "issuer": first(d.get("issuer"), "commonName") or first(d.get("issuer"),
                                                                     "organizationName"),
            "sans": sans[:100], "not_before": not_before, "not_after": not_after,
            "days_left": left, "serial": _safe_text(d.get("serialNumber"), 64).lower(),
            "sha256": hashlib.sha256(der).hexdigest(),
            "self_signed": d.get("subject") == d.get("issuer"),
            "chain_length": len(blocks)}


def _status(info, expiring_days):
    if info is None:
        return "unreadable"
    if info["days_left"] < 0:
        return "expired"
    if info["days_left"] < expiring_days:
        return "expiring"
    return "valid"


def _pubkey(conf, path, is_key):
    """The public key of a certificate or private key file as PEM text, or ""
    when it cannot be read (an unmanaged key only root can read)."""
    argv = ([_openssl(conf), "pkey", "-pubout", "-in", path] if is_key
            else [_openssl(conf), "x509", "-noout", "-pubkey", "-in", path])
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=conf["command_timeout"])
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return "".join(p.stdout.split()) if p.returncode == 0 else ""


def _tls_refs(server, text):
    """(cert path, key path) pairs a virtual host file names, in order."""
    text = _strip_comments(text)
    if server == "nginx":
        found = [(m.group(2), _unquote(m.group(4))) for m in NGINX_TLS_RE.finditer(text)]
        certs = [v for k, v in found if k == "ssl_certificate" and "$" not in v]
        keys = [v for k, v in found if k == "ssl_certificate_key" and "$" not in v]
    else:
        found = [(m.group(2).lower(), _unquote(m.group(4))) for m in APACHE_TLS_RE.finditer(text)]
        certs = [v for k, v in found if k == "sslcertificatefile"]
        keys = [v for k, v in found if k == "sslcertificatekeyfile"]
    out = []
    for i, c in enumerate(certs):
        pair = (c, keys[i] if i < len(keys) else "")
        if pair not in out:
            out.append(pair)
    return out


def _usage(conf):
    """real cert path -> [{"server", "vhost", "enabled", "key"}] over every
    virtual host file, enabled or not."""
    used = {}
    for server, name, _path, enabled, _st, text in iter_vhost_files(conf):
        for cert, key in _tls_refs(server, text):
            if not cert.startswith("/"):
                continue
            used.setdefault(os.path.realpath(cert), []).append(
                {"server": server, "vhost": name, "enabled": enabled, "key": key})
    return used


def _managed_paths(conf, name):
    base = os.path.join(_cert_dir(conf), name)
    return {"dir": base, "key": os.path.join(base, "privkey.pem"),
            "cert": os.path.join(base, "fullchain.pem"),
            "csr": os.path.join(base, "request.csr"),
            "pending": os.path.join(base, "pending"),
            "pending_key": os.path.join(base, "pending", "privkey.pem"),
            "pending_csr": os.path.join(base, "pending", "request.csr")}


def _entry(conf, path, *, name="", key_path="", used=None, expiring=30):
    info = _cert_info(path) if os.path.isfile(path) else None
    e = {"name": name, "managed": bool(name), "path": path, "key_path": key_path,
         "used_by": [{"server": u["server"], "vhost": u["vhost"], "enabled": u["enabled"]}
                     for u in (used or [])][:100]}
    if not os.path.exists(path):
        e["status"] = "requested" if name else "missing"
    else:
        e["status"] = _status(info, expiring)
    e.update(info or {"subject": "", "issuer": "", "sans": [], "not_before": 0,
                      "not_after": 0, "days_left": 0, "serial": "", "sha256": "",
                      "self_signed": False, "chain_length": 0})
    km = None
    if info is not None and key_path and os.path.exists(key_path):
        kp, cp = _pubkey(conf, key_path, True), _pubkey(conf, path, False)
        km = (kp == cp) if (kp and cp) else None
    e["key_matches"] = km
    return e


def op_certs_list(conf, args):
    used = _usage(conf)
    expiring = int(conf.get("expiring_days") or 30)
    out, seen = [], set()
    base = _cert_dir(conf)
    try:
        names = sorted(os.listdir(base))
    except OSError:
        names = []
    for name in names:
        if not CERT_NAME_RE.match(name) or not os.path.isdir(os.path.join(base, name)):
            continue
        mp = _managed_paths(conf, name)
        e = _entry(conf, mp["cert"], name=name, key_path=mp["key"],
                   used=used.get(os.path.realpath(mp["cert"])), expiring=expiring)
        e["pending"] = os.path.isfile(mp["pending_csr"]) or (
            not os.path.exists(mp["cert"]) and os.path.isfile(mp["csr"]))
        out.append(e)
        seen.add(os.path.realpath(mp["cert"]))
    for real, users in sorted(used.items()):
        if real in seen or UNSAFE_TEXT_RE.search(real) or len(real) > 1024:
            continue
        e = _entry(conf, real, key_path=users[0]["key"], used=users, expiring=expiring)
        e["pending"] = False
        out.append(e)
    return {"cert_dir": base, "expiring_days": expiring, "certs": out[:500]}


def op_cert_get(conf, args):
    """One certificate: what certs.list says about it, the certificate and
    chain as PEM (public), and the request waiting for a certificate."""
    used = _usage(conf)
    if args.get("name"):
        name = _check_cert_name(args.get("name"))
        mp = _managed_paths(conf, name)
        if not os.path.isdir(mp["dir"]):
            raise Refused("not_found", "no certificate %r" % name)
        e = _entry(conf, mp["cert"], name=name, key_path=mp["key"],
                   used=used.get(os.path.realpath(mp["cert"])),
                   expiring=int(conf.get("expiring_days") or 30))
        csr_path = mp["pending_csr"] if os.path.isfile(mp["pending_csr"]) else mp["csr"]
        cert_path = mp["cert"]
    else:
        path = args.get("path")
        if not isinstance(path, str) or os.path.realpath(path) not in used:
            raise Refused("not_found", "not a certificate a virtual host of this server uses")
        cert_path = os.path.realpath(path)
        users = used[cert_path]
        e = _entry(conf, cert_path, key_path=users[0]["key"], used=users,
                   expiring=int(conf.get("expiring_days") or 30))
        csr_path = ""
    e["pending"] = bool(csr_path) and os.path.isfile(csr_path) and (
        csr_path.endswith("/pending/request.csr") or not os.path.exists(cert_path))
    e["certificate"] = ""
    if os.path.isfile(cert_path):
        with open(cert_path, "r", errors="replace") as fh:
            blocks = _pem_blocks(fh.read(MAX_CHAIN_BYTES))
        e["certificate"] = "\n".join(_pem_text(b) for b in blocks[:MAX_CHAIN_CERTS])
    e["csr"] = ""
    if e["pending"]:
        with open(csr_path, "r", errors="replace") as fh:
            e["csr"] = fh.read(16 * 1024)
    return e


def _pem_text(b64):
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % "\n".join(lines)


def op_cert_csr(conf, args):
    """A new private key and its request, made on this server. On a
    certificate that already has one, the pair waits in ``pending/`` until
    the renewed certificate is installed, so the running sites keep working."""
    name = _check_cert_name(args.get("name"))
    cn = args.get("common_name")
    if not isinstance(cn, str) or not SERVER_NAME_RE.match(cn) or cn == "_":
        raise Refused("bad_common_name", "the common name is a host name")
    sans = args.get("sans") or []
    if isinstance(sans, str):
        sans = sans.replace(",", " ").split()
    if (not isinstance(sans, list) or len(sans) > 50
            or not all(isinstance(s, str) and SAN_RE.match(s) for s in sans)):
        raise Refused("bad_sans", "up to 50 host names or addresses")
    names = [cn] + [s for s in sans if s != cn]
    key_type = args.get("key_type") or "ec256"
    if key_type not in KEY_TYPES:
        raise Refused("bad_key_type", "key type: " + ", ".join(sorted(KEY_TYPES)))
    exe = _openssl(conf)
    mp = _managed_paths(conf, name)
    renewal = os.path.isfile(mp["cert"])
    target_dir = mp["pending"] if renewal else mp["dir"]
    base = _cert_dir(conf)
    if not os.path.isdir(base):
        raise Refused("no_cert_dir", "%s does not exist: run the installer again" % base)
    old = [p for p in (mp["pending"] if renewal else mp["dir"],) if os.path.exists(p)]
    bk = backup(conf, "cert.csr", old) if old else ""
    work = tempfile.mkdtemp(prefix=".satom-webctl-", dir=base)
    try:
        os.chmod(work, 0o700)
        cfg = os.path.join(work, "req.cnf")
        alt = ",".join(("IP:" if _is_ip(n) else "DNS:") + n for n in names)
        with open(cfg, "w") as fh:
            fh.write("[req]\ndistinguished_name = dn\nreq_extensions = ext\nprompt = no\n"
                     "[dn]\nCN = %s\n[ext]\nsubjectAltName = %s\n" % (cn, alt))
        key, csr = os.path.join(work, "privkey.pem"), os.path.join(work, "request.csr")
        old_umask = os.umask(0o077)
        try:
            p = subprocess.run([exe, "req", "-new", "-nodes", "-config", cfg, "-keyout", key,
                                "-out", csr] + KEY_TYPES[key_type],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, timeout=conf["command_timeout"])
        finally:
            os.umask(old_umask)
        if p.returncode != 0 or not os.path.isfile(key) or not os.path.isfile(csr):
            raise Refused("csr_failed", _safe_text(p.stdout, 400))
        os.chmod(key, 0o600)
        os.chmod(csr, 0o644)
        os.unlink(cfg)
        if renewal:
            if os.path.exists(mp["pending"]):
                shutil.rmtree(mp["pending"])
            os.rename(work, mp["pending"])
        else:
            if os.path.exists(mp["dir"]):
                shutil.rmtree(mp["dir"])
            os.rename(work, mp["dir"])
        work = ""
    finally:
        if work and os.path.exists(work):
            shutil.rmtree(work, ignore_errors=True)
    with open(mp["pending_csr"] if renewal else mp["csr"], "r") as fh:
        text = fh.read()
    return {"name": name, "csr": text, "common_name": cn, "sans": names, "key_type": key_type,
            "renewal": renewal, "backup": bk}


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _servers_using(conf, real_cert):
    """Servers with an ENABLED virtual host that uses this certificate."""
    return sorted({u["server"] for u in _usage(conf).get(real_cert, []) if u["enabled"]})


def _test_reload(conf, servers, undo):
    """Test every server; if one fails run ``undo`` and test again; if all
    pass reload each. Returns the result dict."""
    outs = []
    for s in servers:
        rc, out = _run(conf, conf["servers"][s].get("test"))
        outs.append(out)
        if rc != 0:
            undo()
            valid = all(_run(conf, conf["servers"][x].get("test"))[0] == 0 for x in servers)
            return {"applied": False, "restored": True, "restored_config_valid": valid,
                    "test_output": "\n".join(outs)[-4000:], "reloaded": []}
    reloaded, routs = [], []
    for s in servers:
        rrc, rout = _run(conf, conf["servers"][s].get("reload"))
        if rrc == 0:
            reloaded.append(s)
        else:
            routs.append(rout)
    return {"applied": len(reloaded) == len(servers), "restored": False,
            "test_output": "\n".join(outs)[-4000:], "reload_output": "\n".join(routs)[-4000:],
            "reloaded": reloaded}


def op_cert_install(conf, args):
    """Install the certificate (and chain) issued for this server's key. It
    must be for the pending key (a renewal) or the current one; a private key
    is never accepted. The sites using it are tested and reloaded; a failed
    test puts the previous files back."""
    name = _check_cert_name(args.get("name"))
    text = args.get("certificate")
    if not isinstance(text, str) or not text.strip():
        raise Refused("bad_certificate", "paste the certificate (PEM)")
    if len(text.encode("utf-8")) > MAX_CHAIN_BYTES:
        raise Refused("too_large", "a certificate chain is at most %d bytes" % MAX_CHAIN_BYTES)
    if "PRIVATE KEY" in text:
        raise Refused("private_key_sent",
                      "never send a private key: the key is made on this server (cert.csr)")
    blocks = _pem_blocks(text)
    if not blocks or len(blocks) > MAX_CHAIN_CERTS:
        raise Refused("bad_certificate", "1 to %d PEM certificates" % MAX_CHAIN_CERTS)
    mp = _managed_paths(conf, name)
    if not os.path.isdir(mp["dir"]):
        raise Refused("not_found", "no certificate %r: make a request first (cert.csr)" % name)
    data = "".join(_pem_text(b) for b in blocks).encode("ascii")
    fd, tmp = tempfile.mkstemp(prefix=".satom-webctl-", dir=mp["dir"])
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o644)
        info = _cert_info(tmp)
        if info is None:
            raise Refused("bad_certificate", "the certificate cannot be decoded")
        if info["days_left"] < 0:
            raise Refused("expired", "the certificate has already expired")
        pub = _pubkey(conf, tmp, False)
        if not pub:
            raise Refused("bad_certificate", "openssl cannot read the certificate")
        renewal = os.path.isfile(mp["pending_key"]) and _pubkey(conf, mp["pending_key"], True) == pub
        if not renewal and not (os.path.isfile(mp["key"]) and _pubkey(conf, mp["key"], True) == pub):
            raise Refused("key_mismatch",
                          "the certificate is not for this server's key: issue it for the "
                          "request (cert.csr) of %s" % name)
        old = {}
        for k in ("cert", "key", "csr"):
            if os.path.isfile(mp[k]):
                with open(mp[k], "rb") as fh:
                    old[k] = fh.read()
        bk = backup(conf, "cert.install", [mp["dir"]])
        os.replace(tmp, mp["cert"])
        tmp = ""
        if renewal:
            os.replace(mp["pending_key"], mp["key"])
            if os.path.isfile(mp["pending_csr"]):
                os.replace(mp["pending_csr"], mp["csr"])
            shutil.rmtree(mp["pending"], ignore_errors=True)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)

    def undo():
        for k, mode in (("cert", 0o644), ("key", 0o600), ("csr", 0o644)):
            if k in old:
                _write_atomic(mp[k], old[k], mode)
            elif k == "cert" and os.path.exists(mp[k]):
                os.unlink(mp[k])

    servers = _servers_using(conf, os.path.realpath(mp["cert"]))
    res = _test_reload(conf, servers, undo) if servers else {
        "applied": True, "restored": False, "test_output": "", "reloaded": []}
    res.update({"name": name, "installed": not res.get("restored"), "renewal": renewal,
                "not_after": info["not_after"], "days_left": info["days_left"],
                "subject": info["subject"], "backup": bk})
    return res


def op_cert_assign(conf, args):
    """Point a virtual host's TLS lines at a managed certificate: backup,
    rewrite, test, reload -- or restore."""
    spec = server_spec(conf, args.get("server"))
    vname = _check_name(spec, args.get("name"))
    cname = _check_cert_name(args.get("cert"))
    mp = _managed_paths(conf, cname)
    if not (os.path.isfile(mp["cert"]) and os.path.isfile(mp["key"])):
        raise Refused("not_ready", "certificate %r has no installed certificate yet" % cname)
    if _pubkey(conf, mp["cert"], False) != _pubkey(conf, mp["key"], True):
        raise Refused("key_mismatch", "certificate %r does not match its key" % cname)
    path, enabled = vhost_state(spec, vname)
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8", "replace")
    base = args.get("base_sha256")
    if base and base != _sha(raw):
        raise Refused("conflict", "the file changed since it was read")
    files = {"ssl_certificate": mp["cert"], "ssl_certificate_key": mp["key"],
             "sslcertificatefile": mp["cert"], "sslcertificatekeyfile": mp["key"]}
    count = [0]

    def repl(m):
        count[0] += 1
        return "%s%s%s%s%s" % (m.group(1), m.group(2), m.group(3),
                               files[m.group(2).lower()], m.group(5))
    if args.get("server") == "nginx":
        new = NGINX_TLS_RE.sub(repl, text)
    else:
        new = APACHE_TLS_RE.sub(repl, text)
        new = APACHE_CHAIN_RE.sub(lambda m: "%s# satom-webctl: the chain is in fullchain.pem -- %s"
                                  % (m.group(1), m.group(2)), new)
    if not count[0]:
        raise Refused("no_tls", "the virtual host has no HTTPS certificate lines: create it "
                                "with HTTPS, or add its HTTPS block first")
    data = new.encode("utf-8")
    if data == raw:
        return {"changed": False, "applied": True, "restored": False, "cert": cname,
                "sha256": _sha(raw), "name": vname}
    mode = stat.S_IMODE(os.stat(path).st_mode)
    bk = backup(conf, "cert.assign", [path])
    _write_atomic(path, data, mode)

    def undo():
        _write_atomic(path, raw, mode)

    res = _apply(conf, spec, undo) if enabled else {"applied": True, "test_output": "",
                                                       "restored": False}
    res.update({"changed": not res.get("restored"), "backup": bk, "cert": cname, "name": vname,
                "sha256": _sha(raw if res.get("restored") else data)})
    return res


def op_cert_delete(conf, args):
    name = _check_cert_name(args.get("name"))
    mp = _managed_paths(conf, name)
    if not os.path.isdir(mp["dir"]):
        raise Refused("not_found", "no certificate %r" % name)
    mine = {os.path.realpath(mp["cert"]), os.path.realpath(mp["key"])}
    users = [u for real, us in _usage(conf).items() for u in us
             if real in mine or (u["key"] and os.path.realpath(u["key"]) in mine)]
    if users:
        raise Refused("in_use", "used by %s" % ", ".join(sorted(
            {"%s/%s" % (u["server"], u["vhost"]) for u in users})))
    bk = backup(conf, "cert.delete", [mp["dir"]])
    shutil.rmtree(mp["dir"])
    return {"name": name, "deleted": True, "backup": bk}


# ── host health (read only, no privilege) ───────────────────────────────────
#
# Memory, file systems, load, CPU, processes and systemd units, read from
# /proc, statvfs() and ``systemctl list-units`` -- everything an unprivileged
# account may read. No sudo, no write, no shell. The answer has exactly the
# shape of SATOM's closed HOST_HEALTH schema (services/server_ingest.py).

#: File systems that are not storage: never reported.
PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "pstore",
    "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "bpf", "autofs",
    "binfmt_misc", "rpc_pipefs", "nsfs", "efivarfs", "selinuxfs", "fuse.lxcfs",
    "fuse.gvfsd-fuse", "fuse.portal", "squashfs", "ramfs", "overlay", "nfsd", "tmpfs",
    "devfs", "ecryptfs",
}
HEALTH_SAMPLE_S = 0.5
HEALTH_TOP = 15
UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]+\.(service|socket|timer|mount|path|target)$")
UNIT_ACTIVE = ("active", "inactive", "failed", "activating", "deactivating", "reloading",
               "maintenance", "refreshing")
USER_RE = re.compile(r"^[A-Za-z0-9_.@\\$-]{1,64}$")


def _read(path):
    with open(path) as fh:
        return fh.read()


def _meminfo():
    kb = {}
    for line in _read("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            kb[parts[0].rstrip(":")] = int(parts[1]) * 1024
    total = kb.get("MemTotal", 0)
    avail = kb.get("MemAvailable", kb.get("MemFree", 0) + kb.get("Cached", 0))
    out = {"total_bytes": max(1, total), "available_bytes": max(0, min(avail, total))}
    if "SwapTotal" in kb:
        st = kb["SwapTotal"]
        out["swap_total_bytes"] = st
        out["swap_used_bytes"] = max(0, min(st, st - kb.get("SwapFree", st)))
    return out


def _unescape_mount(text):
    """/proc/self/mounts writes space, tab, newline and backslash as \\ooo."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)


def _filesystems():
    out, seen = [], set()
    for line in _read("/proc/self/mounts").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mount, fstype = _unescape_mount(parts[1]), parts[2].lower()
        if fstype in PSEUDO_FS or mount in seen or not mount.startswith("/") \
                or UNSAFE_TEXT_RE.search(mount) or len(mount) > 512 \
                or not re.match(r"^[a-z0-9][a-z0-9._+-]{0,31}$", fstype):
            continue
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        size = st.f_blocks * st.f_frsize
        if size <= 0:
            continue
        used = max(0, min(size, (st.f_blocks - st.f_bfree) * st.f_frsize))
        row = {"mount": mount, "fstype": fstype, "size_bytes": size, "used_bytes": used}
        if st.f_files > 0:
            row["inodes_total"] = st.f_files
            row["inodes_used"] = max(0, min(st.f_files, st.f_files - st.f_ffree))
        seen.add(mount)
        out.append(row)
        if len(out) >= 64:
            break
    return out


def _cpu_times():
    """(busy, total) jiffies of all CPUs together."""
    vals = [int(v) for v in _read("/proc/stat").splitlines()[0].split()[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals[:8])
    return total - idle, total


def _proc_table():
    """pid -> [comm, state, uid, jiffies, rss]; what this account may read."""
    page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
    rows = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            raw = _read("/proc/%s/stat" % name)
            comm = raw[raw.index("(") + 1:raw.rindex(")")]
            rest = raw[raw.rindex(")") + 2:].split()
            uid = os.stat("/proc/%s" % name).st_uid
            rss = int(_read("/proc/%s/statm" % name).split()[1]) * page
        except (OSError, ValueError, IndexError):
            continue                       # gone between listdir and read
        rows[int(name)] = [comm, rest[0], uid, int(rest[11]) + int(rest[12]), rss]
    return rows


def _username(uid, cache):
    if uid not in cache:
        try:
            import pwd
            name = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            name = str(uid)
        cache[uid] = name if USER_RE.match(name) else str(uid)
    return cache[uid]


def _processes(before, after, delta_total, cpus):
    users = {}
    counts = {"total": 0, "running": 0, "sleeping": 0, "zombie": 0}
    rows = []
    for pid, (comm, state, uid, jif, rss) in after.items():
        counts["total"] += 1
        if state == "R":
            counts["running"] += 1
        elif state in ("S", "D", "I"):
            counts["sleeping"] += 1
        elif state == "Z":
            counts["zombie"] += 1
        prev = before.get(pid)
        used = max(0, jif - prev[3]) if prev and prev[0] == comm else 0
        pct = 100.0 * cpus * used / delta_total if delta_total > 0 else 0.0
        name = TEXT_UNSAFE_RE.sub("?", comm)[:128] or "?"
        rows.append({"pid": pid, "user": _username(uid, users), "name": name,
                     "state": state if state in "RSDZTtIWXPK" else "S",
                     "cpu_pct": round(min(pct, 409600.0), 1), "rss_bytes": rss})
    by_cpu = sorted(rows, key=lambda r: (-r["cpu_pct"], -r["rss_bytes"]))[:HEALTH_TOP]
    by_mem = sorted(rows, key=lambda r: -r["rss_bytes"])[:HEALTH_TOP]
    top, seen = [], set()
    for r in by_cpu + by_mem:
        if r["pid"] not in seen:
            seen.add(r["pid"])
            top.append(r)
    return {"counts": counts, "top": top}


def _units(conf):
    exe = shutil.which("systemctl")
    if not exe or not os.path.isdir("/run/systemd/system"):
        return False, []
    try:
        res = subprocess.run(
            [exe, "list-units", "--type=service", "--all", "--no-legend", "--plain",
             "--no-pager"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=int(conf.get("command_timeout") or 60))
    except (OSError, subprocess.TimeoutExpired):
        return True, []
    out = []
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        unit, active, sub = parts[0].lstrip("●* "), parts[2], parts[3]
        if not UNIT_RE.match(unit) or len(unit) > 256 or active not in UNIT_ACTIVE \
                or not re.match(r"^[a-z][a-z-]{0,31}$", sub):
            continue
        out.append({"unit": unit, "active": active, "sub": sub})
        if len(out) >= 2048:
            break
    return True, out


def _container():
    """What systemd says this host runs in ('' = not a container / unknown)."""
    try:
        kind = _read("/run/systemd/container").strip().lower()
    except OSError:
        return ""
    return kind if re.match(r"^[a-z0-9-]{1,32}$", kind) else "other"


def op_host_health(conf, args):
    """One reading of the host: two CPU samples HEALTH_SAMPLE_S apart."""
    cpus = os.cpu_count() or 1
    busy0, total0 = _cpu_times()
    procs0 = _proc_table()
    time.sleep(HEALTH_SAMPLE_S)
    busy1, total1 = _cpu_times()
    procs1 = _proc_table()
    dt = total1 - total0
    load = [float(x) for x in _read("/proc/loadavg").split()[:3]]
    systemd, units = _units(conf)
    uname = os.uname()
    return {
        "hostname": TEXT_UNSAFE_RE.sub("?", uname.nodename)[:255] or "?",
        "kernel": TEXT_UNSAFE_RE.sub("?", uname.release)[:128] or "?",
        "cpus": max(1, min(cpus, 4096)),
        "cpu_pct": round(max(0.0, min(100.0, 100.0 * (busy1 - busy0) / dt)) if dt > 0
                         else 0.0, 1),
        "load1": max(0.0, load[0]), "load5": max(0.0, load[1]), "load15": max(0.0, load[2]),
        "uptime_s": int(float(_read("/proc/uptime").split()[0])),
        "memory": _meminfo(),
        "filesystems": _filesystems(),
        "processes": _processes(procs0, procs1, dt, cpus),
        # hidepid=: this account sees only its own processes, and PID 1 is hidden
        "proc_restricted": not os.path.exists("/proc/1/stat")
        or not os.access("/proc/1/stat", os.R_OK),
        "systemd": systemd,
        "services": units,
        # LXC/docker/...: /proc/loadavg is then usually the HOST's, so load is
        # shown but not judged (SATOM's evaluate()).
        "container": _container(),
    }


OPERATIONS = {
    "host.health": op_host_health,
    "info": op_info,
    "vhosts.list": op_vhosts_list,
    "vhost.get": op_vhost_get,
    "vhost.put": op_vhost_put,
    "vhost.create": op_vhost_create,
    "vhost.enable": lambda c, a: op_vhost_toggle(c, a, True),
    "vhost.disable": lambda c, a: op_vhost_toggle(c, a, False),
    "vhost.delete": op_vhost_delete,
    "files.list": op_files_list,
    "files.read": op_files_read,
    "files.write": op_files_write,
    "files.mkdir": op_files_mkdir,
    "files.rename": op_files_rename,
    "files.delete": op_files_delete,
    "certs.list": op_certs_list,
    "cert.get": op_cert_get,
    "cert.csr": op_cert_csr,
    "cert.install": op_cert_install,
    "cert.assign": op_cert_assign,
    "cert.delete": op_cert_delete,
}


# ── entry point ─────────────────────────────────────────────────────────────

def _log(conf, entry):
    path = (conf or {}).get("log") or DEFAULTS["log"]
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass


def handle(raw, conf=None):
    """bytes in -> response dict. Never raises."""
    entry = {"ts": datetime.datetime.utcnow().isoformat() + "Z",
             "peer": (os.environ.get("SSH_CLIENT") or "").split(" ")[0]}
    try:
        if len(raw) > MAX_REQUEST_BYTES:
            raise Refused("too_large", "request over %d bytes" % MAX_REQUEST_BYTES)
        try:
            req = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise Refused("bad_request", "the request is not JSON")
        if not isinstance(req, dict) or not isinstance(req.get("args", {}), dict):
            raise Refused("bad_request", "expected {\"op\": ..., \"args\": {...}}")
        op = req.get("op")
        entry["op"] = op if isinstance(op, str) else "?"
        fn = OPERATIONS.get(op)
        if fn is None:
            raise Refused("unknown_op", "unknown operation")
        conf = conf or load_conf()
        if op in WRITE_OPS and conf["read_only"]:
            raise Refused("read_only", "this host is read-only for SATOM")
        args = req.get("args") or {}
        for k in ("server", "name", "path", "to", "cert"):
            if k in args and isinstance(args[k], str):
                entry[k] = args[k][:200]
        result = fn(conf, args)
        entry["ok"] = True
        _log(conf, entry)
        return {"ok": True, "result": result}
    except Refused as exc:
        entry.update({"ok": False, "error": exc.code})
        _log(conf, entry)
        return {"ok": False, "error": exc.code, "detail": exc.detail[:500]}
    except OSError as exc:
        entry.update({"ok": False, "error": "os_error"})
        _log(conf, entry)
        return {"ok": False, "error": "os_error",
                "detail": "%s (errno %s)" % (exc.__class__.__name__, exc.errno)}
    except Exception as exc:  # noqa: BLE001 -- the answer must always be JSON
        entry.update({"ok": False, "error": "internal"})
        _log(conf, entry)
        return {"ok": False, "error": "internal", "detail": exc.__class__.__name__}


def read_request(stream, timeout):
    """All of stdin up to EOF, within ``timeout`` seconds in total, capped at
    MAX_REQUEST_BYTES + 1. ``None`` when the deadline passes first: a client
    that never closes its side must not hold this process forever."""
    deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=timeout)
    fd = stream.fileno()
    chunks, size = [], 0
    while size <= MAX_REQUEST_BYTES:
        left = (deadline - datetime.datetime.utcnow()).total_seconds()
        if left <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], left)
        if not ready:
            return None
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--version"]:
        print(VERSION)
        return 0
    if argv[:1] == ["--selftest"]:
        out = handle(b'{"op": "info", "args": {}}')
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0 if out.get("ok") else 1
    os.umask(0o022)
    raw = read_request(sys.stdin.buffer, READ_TIMEOUT)
    out = handle(raw) if raw is not None else {
        "ok": False, "error": "timeout", "detail": "no complete request within %ds" % READ_TIMEOUT}
    sys.stdout.write(json.dumps(out, sort_keys=True))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
