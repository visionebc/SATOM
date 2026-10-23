"""Sidebar entries the administrator took out (Settings › Appearance › Sidebar menu).

Operator, 2026-10-23: "in Settings, Appearance, add the option to remove
entries of the menu and of the submenus, for example remove the Architecture
menu when it is not needed".

ONE setting for the whole console (every ADOM, every user), like the theme it
sits next to. It holds KEYS, never labels, so it means the same thing in every
console language:

* ``e:<endpoint>`` -- an entry, named by the endpoint its link opens (plus the
  path arguments when the route has some: one Plugin Studio app, one
  FortiAnalyzer section). The disabled form of an entry
  (``partials/_nav_off.html``) carries the same endpoint, so hiding
  Upgrade Flow hides it where it is live AND where it is drawn disabled;
* ``g:<data-nav-group>`` -- a whole first-level group (Administrator, ...);
* ``s:<data-nav-subgroup>`` -- a whole submenu (Monitoring, Troubleshooting, ...).

An entry or a submenu is hidden wherever it appears: Architecture is one key,
not one per ADOM.

Hiding is NOT a permission. The page still opens from a direct link, a
bookmark or a search result, and a profile still needs the page's own key to
open it -- permissions stay in the profiles, where they are enforced.

What can never be hidden (:data:`PROTECTED_ENDPOINTS`, :data:`PROTECTED`):
Settings (it is where this is undone), the ADOM back-link and the ADOM list
(the only way between ADOMs), and the Device picker. The device's own menu
(``.fw-nav-device``: FortiWeb, FortiGate, ... built from the measured GUI
layouts) can be hidden as a whole, never page by page -- its pages differ per
device and per build.

Done server-side, in the same pass that opens the active section
(``nav_state.autoopen``), so a hidden entry is never painted and then removed.
A group or submenu that loses every entry goes with it: an empty toggle would
promise a section that is not there.
"""
from __future__ import annotations

import re
from html import unescape
from typing import Iterable
from urllib.parse import urlencode, urlsplit

SETTING_KEY = "ui.nav_hidden"

#: Endpoints whose entry is never hidden, wherever it is drawn.
PROTECTED_ENDPOINTS = frozenset({"settings.index", "product.enter"})

#: Containers that are never hidden and whose entries are never hidden.
PROTECTED = frozenset({"g:ADOMs", "c:ADOM", "c:Device"})

#: At most this many keys are stored (the catalog has well under 200).
MAX_KEYS = 600
_KEY_RE = re.compile(r"^[egs]:[^\s<>\"']{1,200}$")

_TAG = re.compile(r"<(/?)(div|a|span)\b([^>]*)>", re.I)
_ATTR = re.compile(r'([\w:-]+)\s*=\s*"([^"]*)"')
_LABEL = re.compile(r"<span\b[^>]*>([^<]+)</span>")


# -- the setting ---------------------------------------------------------

def valid_key(key) -> bool:
    if not isinstance(key, str) or not _KEY_RE.match(key):
        return False
    if key in PROTECTED:
        return False
    if key.startswith("e:") and key[2:].split("?", 1)[0] in PROTECTED_ENDPOINTS:
        return False
    return True


def hidden() -> frozenset[str]:
    """The stored keys, once per request. A broken row hides nothing."""
    from flask import g, has_request_context
    if has_request_context():
        cached = getattr(g, "_nav_hidden", None)
        if cached is not None:
            return cached
    from .services import settings_store
    raw = settings_store.get_json(SETTING_KEY, [])
    keys = frozenset(k for k in raw if valid_key(k)) if isinstance(raw, list) else frozenset()
    if has_request_context():
        g._nav_hidden = keys
    return keys


def save(keys: Iterable[str]) -> list[str]:
    """Store *keys* (invalid and protected ones dropped); returns what was stored."""
    from flask import g, has_request_context
    from .services import settings_store
    out = sorted({k for k in keys if valid_key(k)})[:MAX_KEYS]
    settings_store.set_json(SETTING_KEY, out)
    if has_request_context():
        g._nav_hidden = frozenset(out)
    return out


# -- keys ----------------------------------------------------------------

def entry_key(endpoint: str, args: dict | None = None) -> str:
    if not args:
        return "e:" + endpoint
    return "e:%s?%s" % (endpoint, urlencode(sorted((k, str(v)) for k, v in args.items())))


def href_key(href: str) -> str | None:
    """``e:<endpoint>`` for a sidebar link, ``None`` for anything that is not
    a page of this console (a ``#`` fallback, another host, an unknown path)."""
    from flask import current_app, request
    href = unescape(href or "").strip()
    if not href or href.startswith(("#", "javascript:", "mailto:")):
        return None
    parts = urlsplit(href)
    if parts.scheme or parts.netloc:
        return None
    path = parts.path
    root = request.script_root or ""
    if root and path.startswith(root):
        path = path[len(root):] or "/"
    try:
        adapter = current_app.url_map.bind("localhost")
        endpoint, args = adapter.match(path, method="GET")
    except Exception:  # noqa: BLE001 -- not a route of ours: not hideable
        return None
    return entry_key(endpoint, args)


# -- the markup ----------------------------------------------------------

class _El:
    __slots__ = ("kind", "key", "start", "end", "attrs", "classes", "parent")

    def __init__(self, kind, key, start, end, attrs, classes):
        self.kind, self.key, self.start, self.end = kind, key, start, end
        self.attrs, self.classes, self.parent = attrs, classes, None

    def inside(self, other) -> bool:
        return other.start <= self.start and self.end <= other.end


def _elements(html: str) -> list[_El]:
    """Containers (contexts, groups, submenus) and entries of *html*, in order,
    each with its extent and its closest container. Unbalanced markup is
    tolerated: an unmatched closing tag is ignored, an unclosed one dropped."""
    stack: list[tuple[str, int, str]] = []
    found: list[_El] = []
    for m in _TAG.finditer(html):
        closing, tag, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if not closing:
            if not attrs.rstrip().endswith("/"):
                stack.append((tag, m.start(), attrs))
            continue
        for i in range(len(stack) - 1, -1, -1):
            if stack[i][0] == tag:
                _, start, a = stack[i]
                del stack[i:]
                el = _classify(tag, a, start, m.end())
                if el is not None:
                    found.append(el)
                break
    found.sort(key=lambda e: (e.start, -e.end))
    open_: list[_El] = []
    for el in found:
        while open_ and not el.inside(open_[-1]):
            open_.pop()
        el.parent = open_[-1] if open_ else None
        if el.kind != "entry":
            open_.append(el)
    return found


def _classify(tag: str, attrs: str, start: int, end: int) -> _El | None:
    a = dict(_ATTR.findall(attrs))
    classes = a.get("class", "").split()
    if tag == "div":
        for attr, prefix in (("data-nav-context", "c:"), ("data-nav-group", "g:"),
                             ("data-nav-subgroup", "s:")):
            if attr in a:
                kind = {"c:": "context", "g:": "group", "s:": "sub"}[prefix]
                return _El(kind, prefix + unescape(a[attr]).strip(), start, end, a, classes)
        return None
    if "fw-nav-item" not in classes:
        return None
    if tag == "a" and "href" in a:
        return _El("entry", href_key(a["href"]), start, end, a, classes)
    if tag == "span" and a.get("data-nav-ep"):
        return _El("entry", "e:" + unescape(a["data-nav-ep"]).strip(), start, end, a, classes)
    if tag == "span" and "data-nav-off" in a:
        return _El("entry", None, start, end, a, classes)
    return None


def _locked(el: _El) -> bool:
    """Inside a protected container or the device's own menu: left alone."""
    p = el.parent
    while p is not None:
        if p.key in PROTECTED or "fw-nav-device" in p.classes:
            return True
        p = p.parent
    return False


def apply(html, keys: Iterable[str] | None = None) -> str:
    """*html* without the hidden entries, submenus and groups, and without
    the containers that lost every entry because of them."""
    html = str(html or "")
    hide = frozenset(keys if keys is not None else hidden())
    if not hide:
        return html
    els = _elements(html)
    gone: list[_El] = []
    for el in els:
        if el.key not in hide or el.key in PROTECTED or _locked(el):
            continue
        if el.kind == "context":
            continue
        if el.kind == "entry" and not valid_key(el.key):
            continue
        gone.append(el)
    if not gone:
        return html

    def removed(el: _El) -> bool:
        return any(el.inside(g) for g in gone)

    # A container that had entries and lost them all goes too.
    for el in sorted((e for e in els if e.kind != "entry"), key=lambda e: e.end - e.start):
        if removed(el) or el.key in PROTECTED:
            continue
        entries = [e for e in els if e.kind == "entry" and e.inside(el)]
        if entries and all(removed(e) for e in entries):
            gone.append(el)

    spans = sorted((g.start, g.end) for g in gone)
    out, pos = [], 0
    for s, e in spans:
        if s < pos:          # nested in a span already cut
            continue
        out.append(html[pos:s])
        pos = e
    out.append(html[pos:])
    return "".join(out)


# -- the catalog the Settings card draws ---------------------------------

def _label(html: str, el: _El) -> str:
    m = _LABEL.search(html, el.start, el.end)
    return " ".join(unescape(m.group(1)).split()) if m else ""


def tree(html: str) -> list[dict]:
    """The hideable structure of ONE rendered sidebar, as nested nodes
    ``{key, kind, label, children, device}``. Protected containers are
    left out; the Global context shows as a header that cannot be hidden."""
    html = str(html or "")
    els = _elements(html)
    nodes: dict[int, dict] = {}
    roots: list[dict] = []
    for el in els:
        if el.kind == "entry" and (el.key is None or not valid_key(el.key)):
            continue
        if el.key in PROTECTED or _locked(el):
            continue
        node = {"key": el.key, "kind": el.kind, "label": _label(html, el),
                "children": [], "device": "fw-nav-device" in el.classes}
        nodes[id(el)] = node
        p = el.parent
        while p is not None and id(p) not in nodes:
            p = p.parent
        (nodes[id(p)]["children"] if p is not None else roots).append(node)
    # A context or container left with nothing hideable is not worth a row.
    def keep(n):
        n["children"] = [c for c in n["children"] if keep(c)]
        return n["kind"] in ("entry", "group", "sub") or n["children"]
    return [n for n in roots if keep(n)]


def merge(trees: dict[str, list[dict]]) -> list[dict]:
    """One tree for every ADOM: nodes with the same key at the same place are
    one node, and each node lists the ADOMs it appears in (``adoms``)."""
    out: list[dict] = []

    def fold(into: list[dict], nodes: list[dict], adom: str):
        index = {n["key"]: n for n in into}
        for n in nodes:
            tgt = index.get(n["key"])
            if tgt is None:
                tgt = {"key": n["key"], "kind": n["kind"], "label": n["label"],
                       "device": n["device"], "children": [], "adoms": []}
                into.append(tgt)
                index[n["key"]] = tgt
            if adom not in tgt["adoms"]:
                tgt["adoms"].append(adom)
            fold(tgt["children"], n["children"], adom)

    for adom, nodes in trees.items():
        fold(out, nodes, adom)
    return out


def keys_of(nodes: list[dict]) -> list[str]:
    """Every hideable key of a (merged) tree, in order."""
    out: list[str] = []
    for n in nodes:
        if n["kind"] != "context" and n["key"] not in out:
            out.append(n["key"])
        out += [k for k in keys_of(n["children"]) if k not in out]
    return out


def render_sidebar(adom: str) -> str:
    """The sidebar of *adom* as the current user gets it, BEFORE this module
    and nav_state touch it: the ``sidebar_menu`` block of base.html rendered
    with that ADOM's context."""
    from flask import current_app, g
    tmpl = current_app.jinja_env.get_template("base.html")
    had = "product" in g.__dict__
    prev = g.__dict__.get("product")
    g.product = adom
    try:
        ctx: dict = {}
        current_app.update_template_context(ctx)
        context = tmpl.new_context(ctx)
        return "".join(tmpl.blocks["sidebar_menu"](context))
    finally:
        if had:
            g.product = prev
        else:
            g.__dict__.pop("product", None)


def catalog(adoms: Iterable[str]) -> list[dict]:
    """The merged hideable tree of every ADOM in *adoms*. An ADOM whose
    sidebar does not render is skipped: the card must never 500 Settings."""
    from flask import current_app
    trees: dict[str, list[dict]] = {}
    for adom in adoms:
        try:
            trees[adom] = tree(render_sidebar(adom))
        except Exception:  # noqa: BLE001
            current_app.logger.exception("nav_hide: sidebar of ADOM %s did not render", adom)
    return merge(trees)
