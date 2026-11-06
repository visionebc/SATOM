""".htaccess without writing Apache: wizard rules, templates, nginx conversion.

Pure functions, no database, no network.

* :func:`render` turns the wizard's rules (a list of dicts the form builds)
  into ``.htaccess`` text between ``# BEGIN SATOM rules`` / ``# END SATOM
  rules`` markers; what the operator wrote outside the markers is kept.
* :data:`TEMPLATES` -- WordPress, Joomla, Laravel, generic PHP, static site,
  custom application.
* :func:`to_nginx` converts what nginx can express and lists, line by line,
  what it cannot. nginx never reads ``.htaccess``: on an nginx site the
  manager applies only the CONVERTED directives (into the site's server
  block, tested and reverted like every vhost change) and shows the rest as
  "not converted" -- a rule is never presented as active where the server
  cannot read it.
"""
from __future__ import annotations

import ipaddress
import re

BEGIN, END = "# BEGIN SATOM rules", "# END SATOM rules"
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~%/+-]{0,400}$")
URL_RE = re.compile(r"^(https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?)?/[A-Za-z0-9._~%/?=&+-]{0,400}$")
FILE_RE = re.compile(r"^[A-Za-z0-9*?._-]{1,100}$")
AGENT_RE = re.compile(r"^[A-Za-z0-9 ._/-]{2,60}$")

RULE_TYPES = {
    "force_https": "Send every visitor to HTTPS",
    "force_www": "Always use www.",
    "no_www": "Never use www.",
    "redirect": "Redirect a page or folder",
    "redirect_domain": "Redirect the whole site to another domain",
    "block_ip": "Block addresses",
    "allow_only": "Allow only these addresses",
    "protect_dir": "Password-protect this folder",
    "deny_files": "Hide sensitive files",
    "no_listing": "Do not list folder contents",
    "error_page": "Custom error page",
    "block_bots": "Block bots by name",
    "rewrite": "Rewrite (advanced)",
    "front_controller": "Friendly URLs (send everything to index.php)",
    "cache_static": "Let browsers cache images, CSS and JS",
}


class RuleError(ValueError):
    pass


def _ips(values) -> list[str]:
    out = []
    for v in values if isinstance(values, list) else str(values or "").replace(",", " ").split():
        v = str(v).strip()
        if not v:
            continue
        try:
            out.append(str(ipaddress.ip_network(v, strict=False)) if "/" in v
                       else str(ipaddress.ip_address(v)))
        except ValueError:
            raise RuleError("%r is not an IP address or network" % v) from None
    if not out:
        raise RuleError("give at least one address")
    return out[:500]


def _need(cond, msg):
    if not cond:
        raise RuleError(msg)


def rule_apache(r: dict) -> str:
    t = r.get("type")
    if t == "force_https":
        return ("RewriteEngine On\nRewriteCond %{HTTPS} !=on\n"
                "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]")
    if t == "force_www":
        return ("RewriteEngine On\nRewriteCond %{HTTP_HOST} !^www\\. [NC]\n"
                "RewriteRule ^ %{REQUEST_SCHEME}://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]")
    if t == "no_www":
        return ("RewriteEngine On\nRewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n"
                "RewriteRule ^ %{REQUEST_SCHEME}://%1%{REQUEST_URI} [L,R=301]")
    if t == "redirect":
        src, dst = r.get("from") or "", r.get("to") or ""
        _need(PATH_RE.match(src), "the old address is a path like /old-page")
        _need(URL_RE.match(dst), "the new address is a path or https://site/path")
        code = "301" if r.get("permanent", True) else "302"
        return "Redirect %s %s %s" % (code, src, dst)
    if t == "redirect_domain":
        host = r.get("to") or ""
        _need(HOST_RE.match(host), "the new domain is a host name like example.org")
        return ("RewriteEngine On\nRewriteRule ^(.*)$ https://%s/$1 [L,R=301]" % host)
    if t == "block_ip":
        ips = _ips(r.get("ips"))
        return "<RequireAll>\n    Require all granted\n%s\n</RequireAll>" % "\n".join(
            "    Require not ip %s" % i for i in ips)
    if t == "allow_only":
        ips = _ips(r.get("ips"))
        return "\n".join("Require ip %s" % i for i in ips)
    if t == "protect_dir":
        f = r.get("htpasswd") or ""
        _need(re.match(r"^/[A-Za-z0-9._/-]{1,300}$", f), "the password file is an absolute path")
        realm = re.sub(r'["\\\n]', "", r.get("realm") or "Restricted area")[:80]
        return ('AuthType Basic\nAuthName "%s"\nAuthUserFile %s\nRequire valid-user'
                % (realm, f))
    if t == "deny_files":
        pats = r.get("files") or [".env", "*.sql", "*.bak", "*.log", ".git*", "composer.*",
                                  "*.ini"]
        if isinstance(pats, str):
            pats = pats.replace(",", " ").split()
        for p in pats:
            _need(FILE_RE.match(p), "%r is not a file pattern" % p)
        rx = "|".join(re.escape(p).replace("\\*", ".*").replace("\\?", ".") for p in pats)
        return '<FilesMatch "^(%s)$">\n    Require all denied\n</FilesMatch>' % rx
    if t == "no_listing":
        return "Options -Indexes"
    if t == "error_page":
        code = str(r.get("code") or "404")
        _need(code in ("400", "401", "403", "404", "500", "502", "503"), "an HTTP error code")
        page = r.get("page") or ""
        _need(PATH_RE.match(page), "the error page is a path like /404.html")
        return "ErrorDocument %s %s" % (code, page)
    if t == "block_bots":
        bots = r.get("agents") or ["AhrefsBot", "SemrushBot", "MJ12bot", "DotBot"]
        if isinstance(bots, str):
            bots = [b.strip() for b in bots.split(",") if b.strip()]
        for b in bots:
            _need(AGENT_RE.match(b), "%r is not a bot name" % b)
        return ("RewriteEngine On\nRewriteCond %%{HTTP_USER_AGENT} (%s) [NC]\n"
                "RewriteRule .* - [F,L]" % "|".join(re.escape(b) for b in bots))
    if t == "rewrite":
        pat, sub = r.get("pattern") or "", r.get("target") or ""
        flags = r.get("flags") or "L"
        _need(0 < len(pat) <= 300 and "\n" not in pat and " " not in pat, "a pattern without spaces")
        _need(0 < len(sub) <= 400 and "\n" not in sub and " " not in sub, "a target without spaces")
        _need(re.match(r"^[A-Z0-9=,]{1,40}$", flags), "flags like L or L,R=301")
        return "RewriteEngine On\nRewriteRule %s %s [%s]" % (pat, sub, flags)
    if t == "front_controller":
        return ("RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\n"
                "RewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^ index.php [L]")
    if t == "cache_static":
        return ("<IfModule mod_expires.c>\n    ExpiresActive On\n"
                "    ExpiresByType image/png \"access plus 1 month\"\n"
                "    ExpiresByType image/jpeg \"access plus 1 month\"\n"
                "    ExpiresByType image/webp \"access plus 1 month\"\n"
                "    ExpiresByType text/css \"access plus 1 week\"\n"
                "    ExpiresByType application/javascript \"access plus 1 week\"\n</IfModule>")
    raise RuleError("unknown rule %r" % t)


def render(rules: list[dict], existing: str = "") -> str:
    """The new .htaccess: the rules between the SATOM markers, everything else
    of ``existing`` kept as it was."""
    body = []
    for r in rules:
        body.append("# %s" % RULE_TYPES.get(r.get("type"), r.get("type")))
        body.append(rule_apache(r))
    block = "%s\n%s\n%s\n" % (BEGIN, "\n".join(body), END) if rules else ""
    outside = strip_block(existing)
    return (block + ("\n" if block and outside.strip() else "") + outside.lstrip("\n")) \
        if outside.strip() else block


def strip_block(text: str) -> str:
    return re.sub(r"(?s)%s\n.*?%s\n?" % (re.escape(BEGIN), re.escape(END)), "", text or "")


TEMPLATES = {
    "wordpress": ("WordPress", """# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
<Files wp-config.php>
    Require all denied
</Files>
<Files xmlrpc.php>
    Require all denied
</Files>
Options -Indexes
"""),
    "joomla": ("Joomla", """Options +FollowSymlinks -Indexes
RewriteEngine On
RewriteCond %{QUERY_STRING} base64_encode[^(]*\\([^)]*\\) [OR]
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|\\[|\\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|\\[|\\%[0-9A-Z]{0,2})
RewriteRule .* index.php [F]
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteCond %{REQUEST_URI} !^/index\\.php
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .* index.php [L]
"""),
    "laravel": ("Laravel (in public/)", """<IfModule mod_rewrite.c>
    <IfModule mod_negotiation.c>
        Options -MultiViews -Indexes
    </IfModule>
    RewriteEngine On
    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/$
    RewriteRule ^ %1 [L,R=301]
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>
"""),
    "php": ("Generic PHP", """Options -Indexes
DirectoryIndex index.php index.html
<FilesMatch "^(\\.env|composer\\.(json|lock)|.*\\.(sql|bak|log|ini))$">
    Require all denied
</FilesMatch>
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ index.php [L]
"""),
    "static": ("Static site", """Options -Indexes
DirectoryIndex index.html
ErrorDocument 404 /404.html
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType text/css "access plus 1 week"
    ExpiresByType application/javascript "access plus 1 week"
</IfModule>
"""),
    "custom": ("Custom application", """# Your own rules. Keep secrets out of the public folder.
Options -Indexes
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>
"""),
}


# --------------------------------------------------------------------------- #
#  nginx conversion                                                            #
# --------------------------------------------------------------------------- #
def _flags(raw: str) -> list[str]:
    return [f.strip().upper() for f in raw.strip("[]").split(",") if f.strip()]


def to_nginx(text: str) -> dict:
    """``{"nginx": str, "converted": [line], "skipped": [{"line", "why"}]}``.

    Handled: Redirect / RedirectMatch, the common RewriteRule forms (with
    the HTTPS, www/no-www and front-controller conditions), Require ip / not
    ip, Deny/Allow from, ErrorDocument, Options -Indexes, FilesMatch deny,
    a user-agent block. Everything else is listed as not converted."""
    out, converted, skipped = [], [], []
    lines = [l.rstrip() for l in (text or "").splitlines()]
    conds: list[str] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        m = re.match(r"(?i)^Redirect(?:Permanent)?\s+(?:(301|302|permanent|temp)\s+)?(\S+)\s+(\S+)$",
                     line)
        if m:
            code = "302" if (m.group(1) or "").lower() in ("302", "temp") else "301"
            out.append("location = %s { return %s %s; }" % (m.group(2), code, m.group(3)))
            converted.append(line)
            continue
        m = re.match(r"(?i)^RedirectMatch\s+(?:(301|302)\s+)?(\S+)\s+(\S+)$", line)
        if m:
            out.append("location ~ %s { return %s %s; }" % (m.group(2), m.group(1) or "302",
                                                             m.group(3).replace("$", "$")))
            converted.append(line)
            continue
        if low.startswith("rewriteengine") or low.startswith("rewritebase") or \
                low.startswith("<ifmodule") or low.startswith("</ifmodule"):
            converted.append(line)
            continue
        if low.startswith("rewritecond"):
            conds.append(line)
            continue
        m = re.match(r"(?i)^RewriteRule\s+(\S+)\s+(\S+)(?:\s+(\[[^\]]*\]))?$", line)
        if m:
            pat, sub, flags = m.group(1), m.group(2), _flags(m.group(3) or "")
            joined = " ".join(conds).lower()
            if "%{https}" in joined and "https://" in sub:
                out.append("if ($scheme != https) { return 301 https://$host$request_uri; }")
                converted.extend(conds + [line])
            elif "%{http_host} !^www" in joined:
                out.append("if ($host !~* ^www\\.) { return 301 $scheme://www.$host$request_uri; }")
                converted.extend(conds + [line])
            elif "%{http_host} ^www" in joined:
                out.append("if ($host ~* ^www\\.(.+)$) { return 301 $scheme://$1$request_uri; }")
                converted.extend(conds + [line])
            elif "%{request_filename} !-f" in joined and sub.lstrip("/").startswith("index.php"):
                out.append("location / { try_files $uri $uri/ /index.php?$args; }")
                converted.extend(conds + [line])
            elif "%{http_user_agent}" in joined and "F" in flags:
                am = re.search(r"\(([^)]+)\)", " ".join(conds))
                if am:
                    out.append("if ($http_user_agent ~* (%s)) { return 403; }" % am.group(1))
                    converted.extend(conds + [line])
                else:
                    skipped.extend({"line": l, "why": "user-agent condition not understood"}
                                   for l in conds + [line])
            elif conds:
                skipped.extend({"line": l, "why": "RewriteCond combinations have no general "
                                                  "nginx equivalent: write it by hand"}
                               for l in conds + [line])
            elif sub == "-" and "F" in flags:
                out.append("location ~ %s { return 403; }" % pat)
                converted.append(line)
            elif sub == "-":
                converted.append(line)      # "leave the URL alone": nginx's default
            else:
                redirect = next((f for f in flags if f.startswith("R")), "")
                if redirect:
                    code = redirect.split("=")[1] if "=" in redirect else "302"
                    out.append("rewrite %s %s %s;" % (pat, sub,
                                                     "permanent" if code == "301" else "redirect"))
                else:
                    out.append("rewrite %s /%s last;" % (pat, sub.lstrip("/")))
                converted.append(line)
            conds = []
            continue
        m = re.match(r"(?i)^Require\s+(not\s+)?ip\s+(.+)$", line)
        if m:
            for ip in m.group(2).split():
                out.append("%s %s;" % ("deny" if m.group(1) else "allow", ip))
            if not m.group(1):
                if "deny all;" not in out:
                    out.append("__DENY_ALL__")
            converted.append(line)
            continue
        m = re.match(r"(?i)^(Deny|Allow)\s+from\s+(.+)$", line)
        if m:
            for ip in m.group(2).split():
                out.append("%s %s;" % (m.group(1).lower(), "all" if ip.lower() == "all" else ip))
            converted.append(line)
            continue
        if re.match(r"(?i)^Require\s+all\s+granted$", line) or \
                re.match(r"(?i)^</?RequireAll>$", line) or re.match(r"(?i)^Order\s", line):
            converted.append(line)
            continue
        m = re.match(r"(?i)^ErrorDocument\s+(\d{3})\s+(/\S*)$", line)
        if m:
            out.append("error_page %s %s;" % (m.group(1), m.group(2)))
            converted.append(line)
            continue
        if re.match(r"(?i)^Options\s+.*-Indexes", line):
            out.append("autoindex off;")
            converted.append(line)
            continue
        m = re.match(r'(?i)^<FilesMatch\s+"([^"]+)">$', line)
        if m and i + 1 < len(lines) and re.match(r"(?i)^\s*(Require all denied|Deny from all)\s*$",
                                                 lines[i]) and \
                re.match(r"(?i)^\s*</FilesMatch>\s*$", lines[i + 1]):
            out.append("location ~ %s { deny all; return 404; }" % m.group(1))
            converted.extend([line, lines[i].strip(), lines[i + 1].strip()])
            i += 2
            continue
        m = re.match(r"(?i)^<Files\s+\"?([^\">]+)\"?>$", line)
        if m and i + 1 < len(lines) and re.match(r"(?i)^\s*(Require all denied|Deny from all)\s*$",
                                                 lines[i]) and \
                re.match(r"(?i)^\s*</Files>\s*$", lines[i + 1]):
            out.append("location = /%s { deny all; return 404; }" % m.group(1).lstrip("/"))
            converted.extend([line, lines[i].strip(), lines[i + 1].strip()])
            i += 2
            continue
        skipped.append({"line": line, "why": "no nginx equivalent the manager can apply safely"})
    if conds:
        skipped.extend({"line": l, "why": "a condition with no rule after it"} for l in conds)
    if "__DENY_ALL__" in out:
        out = [l for l in out if l != "__DENY_ALL__"] + ["deny all;"]
    return {"nginx": "\n".join(out), "converted": converted, "skipped": skipped}
