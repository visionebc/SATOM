"""Read-only reader of the FortiAuthenticator web GUI (server-rendered Django).

FortiAuthenticator's REST API is a user-management API: of the 93 pages of its
GUI that SATOM has a layout for (8.0.3), 72 have no REST resource and no CLI
object behind them -- remote LDAP / RADIUS / SAML / OAuth servers, realms,
certificate authorities, FSSO, guest portals, TACACS+ servers... Before this
reader, SATOM held nothing of them: their pages drew the columns and fields
and left every value empty. The configuration sweep now reads them here.

What it does, and what it never does:

* logs in through the login form -- the ONLY non-GET request it ever sends
  (``POST /login/``), with the appliance's CLI/GUI admin login
  (``Appliance.ssh_login`` / ``ssh_secret``: the REST API key does not open the
  GUI, measured on fac01 8.0.3);
* GETs only paths it was given (the layout endpoints of the device's build)
  and the change forms their change lists link to (``<endpoint><pk>/change/``);
  anything else -- and any path carrying an action word (``delete``,
  ``export``, ``backup``, ``logout``...) that is not one of the given paths --
  is refused before a request leaves (:func:`refused`);
* reads a change list (``<table id="result_list">``, every page of its
  paginator) and the change form of each object, or a settings page's form;
* NEVER returns a secret: password inputs, fields whose name says secret /
  password / key / token, and masked values (``****``, ``ENC ...``) are
  dropped, not blanked;
* logs out (``GET /logout/``) when done, so an hourly sweep does not leave
  admin sessions behind.
"""
from __future__ import annotations

import re
import time
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

import httpx

#: Path words that name an action, a download or a state change done with a
#: GET (the satom-harvester crawl gate, gui_bind_fac.DANGER_TOKENS). A path
#: given explicitly (a layout endpoint) is exempt; a discovered one is not.
DANGER_TOKENS = frozenset("""
logout reboot shutdown restore backup upgrade firmware license licence factory reset
debug diagnose export download purge revoke sync test start stop clear flush
regenerate renew kill disconnect unlock lock import apply restart format execute exec
csv dump generate approve reject activate deactivate provision send resend
delete remove trigger run poll refresh reauth reauthorize enroll unenroll
""".split())
_ACTION_QUERY = re.compile(r"(?:^|&)(?:action|_action|op|cmd)=", re.I)

#: Django form bookkeeping that is no field of the object.
BOOKKEEPING = re.compile(r"^(csrfmiddlewaretoken|_save|_continue|_addanother|next|_popup"
                         r"|_changelist_filters|index|select_across|wizard_goto_step|action"
                         r"|_selected_action|q)$|"
                         r"-(TOTAL_FORMS|INITIAL_FORMS|MIN_NUM_FORMS|MAX_NUM_FORMS|current_step)$")
#: A field name that holds a secret. ``_key``/``_token`` as a WORD (api_key,
#: seed_token), not every name containing it (``key_size``, ``token_algo``).
SECRET_NAME = re.compile(r"(passw|passwd|passphrase|secret|psk|private[-_]?key|credential"
                         r"|shared[-_]?key|preshared)|(^|[-_])(key|seed|token)$", re.I)
MASKED = re.compile(r"^\*{3,}$|^(?:ENC|SH2)\s")
#: An inline formset field: ``<prefix>-<n>-<field>``.
_INLINE = re.compile(r"^(?P<prefix>.+?)-(?P<i>\d+)-(?P<field>[^-].*)$")
_PK_HREF = re.compile(r"/(\d+)/(?:change/)?$")

#: Objects whose change form is read per change list and sweep. A list longer
#: than this keeps its list columns for the rest and says so (``truncated``).
MAX_FORMS_PER_LIST = 500
#: Change-list pages followed per list.
MAX_LIST_PAGES = 100


class FacGuiError(RuntimeError):
    """The GUI refused the login or a read."""


def tokens(path: str) -> set:
    return {t for t in re.split(r"[/_.\-]+", (path or "").lower()) if t}


def refused(path: str, allowed: frozenset) -> str:
    """Why *path* must not be requested (``""`` = it may)."""
    p = urlsplit(path)
    if p.scheme or p.netloc:
        return "absolute URL"
    base = p.path or "/"
    if base in allowed:
        return ""
    if _ACTION_QUERY.search(p.query or ""):
        return "an action query"
    hit = tokens(base) & DANGER_TOKENS
    if hit:
        return "an action path (%s)" % ", ".join(sorted(hit))
    return ""


def is_secret(name: str, input_type: str = "") -> bool:
    return (input_type or "").lower() == "password" or bool(SECRET_NAME.search(name or ""))


# --------------------------------------------------------------------------- #
#  HTML parsing (stdlib only)                                                   #
# --------------------------------------------------------------------------- #
class _FormParser(HTMLParser):
    """The fields of the first POST form that carries a csrf token (the
    object's form), as ``[(name, kind, value, extra)]`` in page order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[list] = []
        self._in_form = False
        self._fields: list = []
        self._select = None          # [name, multiple, [(value, label, selected)]]
        self._option = None          # [value, selected, label-parts]
        self._textarea = None        # [name, parts]

    def handle_starttag(self, tag, attrs):
        a = {k: (v if v is not None else "") for k, v in attrs}
        if tag == "form" and (a.get("method") or "").lower() == "post":
            self._in_form, self._fields = True, []
            return
        if not self._in_form:
            return
        if tag == "input":
            self._fields.append((a.get("name", ""), (a.get("type") or "text").lower(),
                                 a.get("value", ""), "checked" in a))
        elif tag == "select":
            self._select = [a.get("name", ""), "multiple" in a, []]
        elif tag == "option" and self._select is not None:
            self._option = [a.get("value"), "selected" in a, []]
        elif tag == "textarea":
            self._textarea = [a.get("name", ""), []]

    def handle_data(self, data):
        if self._option is not None:
            self._option[2].append(data)
        elif self._textarea is not None:
            self._textarea[1].append(data)

    def handle_endtag(self, tag):
        if tag == "option" and self._option is not None and self._select is not None:
            label = " ".join("".join(self._option[2]).split())
            value = self._option[0] if self._option[0] is not None else label
            self._select[2].append((value, label, self._option[1]))
            self._option = None
        elif tag == "select" and self._select is not None:
            self._fields.append((self._select[0], "select", self._select[2], self._select[1]))
            self._select = None
        elif tag == "textarea" and self._textarea is not None:
            self._fields.append((self._textarea[0], "textarea", "".join(self._textarea[1]), False))
            self._textarea = None
        elif tag == "form" and self._in_form:
            self.forms.append(self._fields)
            self._in_form = False


def parse_form(html: str) -> dict:
    """``{field: value}`` of the object form on a page, secrets dropped.

    checkbox -> bool (several boxes of one name -> the checked values);
    radio -> the checked value; select -> the selected value (``multiple`` ->
    list); an inline formset ``<prefix>-<n>-<field>`` -> ``row[prefix]`` = list
    of rows. ``_labels`` = ``{field: option label}`` of each select, for
    display."""
    p = _FormParser()
    p.feed(html or "")
    if p._in_form:                      # an unclosed form still counts
        p.forms.append(p._fields)
    form = next((f for f in p.forms if any(n == "csrfmiddlewaretoken" for n, *_r in f)),
                p.forms[0] if p.forms else [])
    out: dict = {}
    labels: dict = {}
    boxes: dict = {}
    inline: dict = {}

    def put(name, value, label=None):
        m = _INLINE.match(name)
        if m and m.group("i").isdigit():
            rows = inline.setdefault(m.group("prefix"), {})
            rows.setdefault(int(m.group("i")), {})[m.group("field")] = value
            return
        out[name] = value
        if label is not None:
            labels[name] = label

    for name, kind, value, extra in form:
        if not name or BOOKKEEPING.search(name) or "__prefix__" in name:
            continue
        if kind in ("submit", "button", "image", "reset", "file"):
            continue
        if is_secret(name, kind):
            continue
        if kind == "checkbox":
            boxes.setdefault(name, []).append((value, extra))
            continue
        if kind == "radio":
            if extra:
                put(name, value)
            else:
                out.setdefault(name, None) if not _INLINE.match(name) else None
            continue
        if kind == "select":
            chosen = [(v, lab) for v, lab, sel in value if sel]
            if extra:                                  # multiple
                put(name, [v for v, _l in chosen], ", ".join(lab for _v, lab in chosen))
            else:
                v, lab = chosen[0] if chosen else ((value[0][0], value[0][1]) if value else ("", ""))
                put(name, v, lab)
            continue
        if isinstance(value, str) and MASKED.search(value.strip()):
            continue
        put(name, unescape(value) if isinstance(value, str) else value)
    for name, vals in boxes.items():
        if len(vals) == 1:
            put(name, bool(vals[0][1]))
        else:
            put(name, [v for v, on in vals if on])
    for prefix, rows in inline.items():
        clean = [r for _i, r in sorted(rows.items())
                 if any(v not in ("", None, False) for k, v in r.items() if k not in ("id", "DELETE"))]
        for r in clean:
            r.pop("DELETE", None)
        out[prefix] = clean
    if labels:
        out["_labels"] = labels
    return out


class _ListParser(HTMLParser):
    """Rows of a Django change list: ``[{_href, _cells: {field: text}}]`` and
    the paginator links (``?p=N``)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[dict] = []
        self.pages: set = set()
        self.found = False
        self._in_table = False
        self._depth = 0
        self._row = None
        self._cell = None            # [field, parts]
        self._in_paginator = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v if v is not None else "") for k, v in attrs}
        cls = a.get("class", "")
        if tag == "table" and a.get("id") == "result_list":
            self._in_table, self.found, self._depth = True, True, 0
        elif self._in_table and tag == "table":
            self._depth += 1
        if tag == "p" and "paginator" in cls:
            self._in_paginator = True
        if tag == "a" and self._in_paginator:
            q = dict(parse_qsl(urlsplit(a.get("href", "")).query))
            if "p" in q:
                self.pages.add(q["p"])
        if not self._in_table or self._depth:
            # a table nested in a cell: its rows are part of the outer cell
            return
        if tag == "tr":
            self._row = {"_href": "", "_cells": {}}
        elif tag in ("td", "th") and self._row is not None:
            field = next((c[len("field-"):] for c in cls.split() if c.startswith("field-")), "")
            self._cell = [field, []]
        elif tag == "a" and self._row is not None and not self._row["_href"]:
            href = a.get("href", "")
            if _PK_HREF.search(urlsplit(href).path or ""):
                self._row["_href"] = href

    def handle_data(self, data):
        if self._cell is not None:
            self._cell[1].append(data)

    def handle_endtag(self, tag):
        if tag == "p" and self._in_paginator:
            self._in_paginator = False
        if not self._in_table:
            return
        if self._depth and tag != "table":
            return
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            if self._cell[0]:
                self._row["_cells"][self._cell[0]] = " ".join("".join(self._cell[1]).split())
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row["_href"] or self._row["_cells"]:
                self.rows.append(self._row)
            self._row = None
        elif tag == "table":
            if self._depth:
                self._depth -= 1
            else:
                self._in_table = False


def parse_list(html: str) -> tuple[bool, list, set]:
    """``(is_change_list, rows, paginator page params)``."""
    p = _ListParser()
    p.feed(html or "")
    return p.found, p.rows, p.pages


# --------------------------------------------------------------------------- #
#  Session                                                                      #
# --------------------------------------------------------------------------- #
class FacGuiReader:
    """One logged-in GUI session; use as a context manager."""

    def __init__(self, appliance, *, timeout: float = 20.0, allowed=()):
        self.base = "https://%s:%s" % (appliance.host, appliance.port or 443)
        self._user = appliance.ssh_login
        self._secret = appliance.ssh_secret
        self._verify = bool(getattr(appliance, "verify_ssl", False))
        self.timeout = timeout
        self.allowed = frozenset(allowed)
        self._c: httpx.Client | None = None
        self.requests = 0

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def login(self) -> None:
        self._c = httpx.Client(verify=self._verify, timeout=self.timeout,
                               follow_redirects=False)
        url = self.base + "/login/?next=/"
        r = self._c.get(url)
        self.requests += 1
        m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text or "")
        data = {"username": self._user, "password": self._secret, "next": "/"}
        if m:
            data["csrfmiddlewaretoken"] = m.group(1)
        r = self._c.post(url, data=data, headers={"Referer": url})
        self.requests += 1
        loc = r.headers.get("location") or ""
        if r.status_code not in (301, 302) or "/login" in loc:
            self.close(logout=False)
            raise FacGuiError("the GUI refused the login of %r (HTTP %s)"
                              % (self._user, r.status_code))

    def close(self, logout: bool = True) -> None:
        if self._c is None:
            return
        try:
            if logout:
                self._c.get(self.base + "/logout/")
                self.requests += 1
        except Exception:  # noqa: BLE001 — the session expires on its own
            pass
        finally:
            self._c.close()
            self._c = None

    def get(self, path: str, *, also=()) -> str:
        why = refused(path, self.allowed | frozenset(also))
        if why:
            raise FacGuiError("refused to GET %s: %s" % (path, why))
        if self._c is None:
            raise FacGuiError("not logged in")
        r = self._c.get(self.base + path)
        self.requests += 1
        if r.status_code in (301, 302) and "/login" in (r.headers.get("location") or ""):
            raise FacGuiError("the session expired")
        if r.status_code != 200:
            raise FacGuiError("GET %s: HTTP %s" % (path, r.status_code))
        return r.text or ""

    def read_page(self, path: str, *, deadline: float | None = None) -> dict:
        """``{kind: list|form, rows, truncated, total}`` of one layout endpoint."""
        html = self.get(path)
        is_list, rows, pages = parse_list(html)
        if not is_list:
            row = parse_form(html)
            return {"kind": "form", "rows": [row] if row else [], "truncated": False,
                    "total": 1 if row else 0}
        seen_pages = {""}
        todo = sorted(pages, key=lambda x: (len(x), x))
        while todo and len(seen_pages) < MAX_LIST_PAGES:
            pg = todo.pop(0)
            if pg in seen_pages:
                continue
            seen_pages.add(pg)
            _l, more, more_pages = parse_list(self.get("%s?p=%s" % (path, pg), also=(path,)))
            rows.extend(more)
            todo.extend(sorted(set(more_pages) - seen_pages, key=lambda x: (len(x), x)))
        uniq, keys = [], set()
        for r in rows:
            k = r["_href"] or repr(sorted(r["_cells"].items()))
            if k not in keys:
                keys.add(k)
                uniq.append(r)
        out, truncated = [], False
        for i, r in enumerate(uniq):
            obj: dict = {}
            href = urlsplit(r["_href"]).path if r["_href"] else ""
            m = _PK_HREF.search(href)
            if href and i < MAX_FORMS_PER_LIST and (deadline is None or time.monotonic() < deadline):
                if href.startswith(path) and m:
                    try:
                        obj = parse_form(self.get(href, also=(href,)))
                    except FacGuiError:
                        obj = {}
            elif href:
                truncated = True
            cells = {k: v for k, v in r["_cells"].items()
                     if not is_secret(k) and not MASKED.search(str(v).strip())}
            obj["_list"] = cells
            if m:
                obj["_id"] = m.group(1)
            for k, v in cells.items():
                obj.setdefault(k, v)
            out.append(obj)
        return {"kind": "list", "rows": out, "truncated": truncated, "total": len(uniq)}
