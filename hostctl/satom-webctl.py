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
import json
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

VERSION = "1.0.0"
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
}
WRITE_OPS = ("vhost.put", "vhost.create", "vhost.enable", "vhost.disable",
             "vhost.delete", "files.write", "files.mkdir", "files.rename",
             "files.delete")


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


def list_vhosts(conf):
    out = []
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
    return {"version": VERSION, "servers": servers, "roots": conf["roots"],
            "read_only": bool(conf["read_only"]),
            "max_file_bytes": int(conf["max_file_bytes"])}


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


OPERATIONS = {
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
        for k in ("server", "name", "path", "to"):
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
