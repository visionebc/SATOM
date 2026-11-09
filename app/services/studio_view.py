"""Plugin Studio > Apps -- an app's own VIEW: a page its author writes.

Why it exists (operator, 2026-11-09: "make everything of DNS Lookup a plugin,
lose no function and no view; implement everything so this kind of plugin
can be made"). The designer (services.studio_design) lays a page out from
blocks, and an app's result is drawn by apps_run.js: enough for a form and a
table, not for a page like DNS & LB Lookup (rows that open other rows,
dialogs with a picker and a live check, inline editors). A VIEW is that page
written by hand -- a template, its CSS and its JavaScript -- with the app's
diagram as its back end. It is edited in Plugin Studio (the app's View tab),
travels in the app package (``app.view``) and is shown in "How it is built".

What a view is (``StudioApp.view_json``, published with the rest)::

    {"title": "...", "breadcrumb": "...",       the console's title and crumb
     "jinja": "...", "css": "...", "js": "...",  the page
     "uses": ["dns-records", ...],               other apps its page may run
     "context": [{"key", "kind", "params"}]}     read-only steps run per render

THE TRUST BOUNDARY
------------------
The view is author code, so it NEVER runs in SATOM's origin:

* the template renders in a jinja2 SANDBOX (no attribute gadgets, no
  callables but the ones handed in) with autoescape on;
* the document is served for an ``<iframe sandbox="allow-scripts
  allow-modals">`` WITHOUT ``allow-same-origin``: its script runs in an opaque
  origin and cannot read the console's cookies, DOM or session, nor call
  SATOM (CSP ``connect-src 'none'``, ``form-action 'none'``);
* it reaches SATOM only through the BRIDGE (static/js/app_view_bridge.js in
  the frame, apps_view_host.js in the console): postMessage commands the
  console answers only from THAT frame with THAT load's token -- run this
  app or one it ``uses`` (each step still asks the permission of the person
  running it; the run is audited), open or go to a LOCAL path, copy text,
  open another app's form. Nothing else.

Data a view sees is what its person may see: the run's form and outputs
(``apps.run_status`` rules), the context steps' values (each step checks the
person's permission) and ``can(<permission>)``.

Who may write a view: ``studio.plugin_studio`` -- the key Plugin Studio's
own views and widgets (author HTML and JavaScript, the same sandbox) ask.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets as _secrets

from markupsafe import Markup

from . import studio_flow as F

#: The permission that writes a view (module docstring).
VIEW_PERMISSION = "studio.plugin_studio"
JINJA_MAX = 256 * 1024
CSS_MAX = 128 * 1024
JS_MAX = 256 * 1024
TEXT_MAX = 160
MAX_USES = 12
MAX_CONTEXT = 6
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_KEYS = ("title", "breadcrumb", "jinja", "css", "js", "uses", "context")


class ViewError(ValueError):
    pass


# --------------------------------------------------------------------------- #
#  cleaning                                                                    #
# --------------------------------------------------------------------------- #
def has(view) -> bool:
    return isinstance(view, dict) and bool(str(view.get("jinja") or "").strip())


def _text(raw, name, limit) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ViewError("%s: text expected" % name)
    if len(raw.encode("utf-8")) > limit:
        raise ViewError("%s: larger than %d KiB" % (name, limit // 1024))
    return raw


def clean(raw, *, kinds: dict | None = None) -> dict:
    """The view to store, or ``{}`` (no template = no view). *kinds* is
    ``studio_flow.kind_map()``: given, every context step must be one of them
    and read only."""
    if raw in (None, "", {}):
        return {}
    if not isinstance(raw, dict):
        raise ViewError("a view is an object")
    unknown = sorted(set(raw) - set(_KEYS))
    if unknown:
        raise ViewError("unknown view key(s): %s" % ", ".join(unknown))
    jinja = _text(raw.get("jinja"), "template", JINJA_MAX)
    if not jinja.strip():
        return {}
    out = {"title": _text(raw.get("title"), "title", TEXT_MAX).strip()[:TEXT_MAX],
           "breadcrumb": _text(raw.get("breadcrumb"), "breadcrumb", TEXT_MAX).strip()[:TEXT_MAX],
           "jinja": jinja,
           "css": _text(raw.get("css"), "CSS", CSS_MAX),
           "js": _text(raw.get("js"), "JavaScript", JS_MAX)}
    uses = raw.get("uses") or []
    if not isinstance(uses, list) or len(uses) > MAX_USES:
        raise ViewError("uses: a list of at most %d app slugs" % MAX_USES)
    clean_uses = []
    for s in uses:
        s = str(s or "").strip()
        if not _SLUG.match(s):
            raise ViewError("uses: %r is not an app slug" % s)
        if s not in clean_uses:
            clean_uses.append(s)
    out["uses"] = clean_uses
    ctx = raw.get("context") or []
    if not isinstance(ctx, list) or len(ctx) > MAX_CONTEXT:
        raise ViewError("context: a list of at most %d steps" % MAX_CONTEXT)
    seen, clean_ctx = set(), []
    for item in ctx:
        if not isinstance(item, dict):
            raise ViewError("context: each step is an object of key, kind, params")
        key = str(item.get("key") or "").strip()
        kind = str(item.get("kind") or "").strip()
        params = item.get("params") or {}
        if not F._VAR_RE.match(key) or key in seen:
            raise ViewError("context: %r is not a (new) variable name" % key)
        if not isinstance(params, dict) or not all(isinstance(v, str) for v in params.values()):
            raise ViewError("context %s: params are text values" % key)
        node = {"key": key, "kind": kind, "params": dict(params)}
        if kinds is not None:
            if kind not in kinds or kind in ("start", "end", "output", "fail", "ask", "decision"):
                raise ViewError("context %s: %r is not a step a view can read" % (key, kind))
            if F.step_writes(node):
                raise ViewError("context %s: %s writes; a view's context only reads" % (key, kind))
        seen.add(key)
        clean_ctx.append(node)
    out["context"] = clean_ctx
    return out


def problems(view: dict, *, app_slug: str = "") -> list[str]:
    """What stops a publish: a template that does not even parse, an app in
    ``uses`` that is not here (its calls would fail), the app itself in it."""
    if not has(view):
        return []
    errs = []
    try:
        _env().parse(view["jinja"])
    except Exception as exc:  # noqa: BLE001 -- TemplateSyntaxError and kin
        errs.append("view: the template does not parse: %s" % exc)
    from . import studio_apps as SA
    for s in view.get("uses") or []:
        if s == app_slug:
            errs.append("view: uses names the app itself (it can always run itself)")
        elif SA.get(s) is None:
            errs.append("view: uses %s, which is not an app here" % s)
    return errs


# --------------------------------------------------------------------------- #
#  rendering                                                                   #
# --------------------------------------------------------------------------- #
def _tojson(value) -> Markup:
    """``tojson`` as Flask's: safe inside a <script> and inside an attribute."""
    from .plugin_frame import json_island
    return Markup(json_island(value).replace("'", "\\u0027"))


def _env():
    # SandboxedEnvironment, not the Immutable one: a template building its own
    # list ({% set picks = [] %}...{% set _ = picks.append(x) %}, as the pages
    # do) mutates only what it made; everything handed in is a plain copy
    # (json round trip), so there is nothing of SATOM's to mutate.
    from jinja2.sandbox import SandboxedEnvironment
    env = SandboxedEnvironment(autoescape=True, trim_blocks=False, lstrip_blocks=False)
    env.filters["tojson"] = _tojson
    return env


def _plain(value):
    return json.loads(json.dumps(value, default=str))


def render(view: dict, *, form: dict, outputs: dict, run: dict | None, data: dict,
           errors: dict, user, adom: str) -> tuple[str, str]:
    """``(html, error)``: the template rendered, or an error card (a broken
    view never takes the console down)."""
    from flask_babel import gettext, ngettext

    def can(perm) -> bool:
        return bool(user is not None and getattr(user, "can", None) and user.can(str(perm)))

    scope = {"form": _plain(form or {}), "outputs": _plain(outputs or {}),
             "run": _plain(run) if run else None, "data": _plain(data or {}),
             "errors": dict(errors or {}), "adom": adom or "global",
             "user": {"name": getattr(user, "username", "") or ""},
             "can": can, "_": gettext, "gettext": gettext, "ngettext": ngettext}
    try:
        return _env().from_string(view["jinja"]).render(scope), ""
    except Exception as exc:  # noqa: BLE001 -- sandbox SecurityError, undefined, syntax
        msg = "%s: %s" % (type(exc).__name__, exc)
    return ('<div class="alert alert-danger m-3" style="font-family:monospace;font-size:13px;'
            'white-space:pre-wrap;">View render error:\n%s</div>' % Markup.escape(msg)), msg


def load_context(view: dict, *, user, product: str) -> tuple[dict, dict]:
    """``(values, errors)`` of the view's context steps, run now as *user* in
    ADOM *product*. Read-only kinds only (clean); a step that fails leaves its
    key out of *values* and says why in *errors* -- never a silent empty."""
    from . import studio_apps as SA
    values, errors = {}, {}
    kinds = F.kind_map(SA.choices())
    for item in view.get("context") or []:
        node = {"key": item["key"], "kind": item["kind"], "params": item.get("params") or {}}
        if node["kind"] not in kinds or F.step_writes(node):
            errors[node["key"]] = "%s is not a step a view can read" % node["kind"]
            continue
        ctx = F.Ctx(form={}, armed=False, user=getattr(user, "username", "") or "",
                    user_obj=user, product=product or "")
        try:
            _outcome, value, _detail = F.run_single(node, ctx)
        except F.FlowError as exc:
            errors[node["key"]] = str(exc)
            continue
        values[node["key"]] = value
    return values, errors


# --------------------------------------------------------------------------- #
#  the frame                                                                   #
# --------------------------------------------------------------------------- #
_STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
_KIT_FILES = ("vendor/bootstrap/bootstrap.min.css",
              "vendor/bootstrap-icons/bootstrap-icons.min.css", "css/fortiweb.css")
BOOTSTRAP_JS = "/static/vendor/bootstrap/bootstrap.bundle.min.js"
_kit: dict = {}
_bridge: dict = {}


def _data_uri(path: str, mime: str) -> str:
    with open(path, "rb") as fh:
        return "data:%s;base64,%s" % (mime, base64.b64encode(fh.read()).decode())


def _inline_fonts(css: str, base_dir: str) -> str:
    """Every ``url(...woff2...)`` of a stylesheet as a data: URI. A frame of
    an opaque origin loads a font only through CORS, which /static does not
    answer; ``font-src data:`` it does. The .woff fallbacks are dropped."""
    def sub(m):
        ref = m.group(1).strip("'\"").split("?")[0].split("#")[0]
        if ref.endswith(".woff"):
            return "url(data:,)"
        if not ref.endswith(".woff2") or ref.startswith("data:"):
            return m.group(0)
        path = os.path.normpath(os.path.join(base_dir, ref))
        if not path.startswith(_STATIC + os.sep) or not os.path.isfile(path):
            return m.group(0)
        return "url(%s)" % _data_uri(path, "font/woff2")
    return re.sub(r"url\(([^)]+)\)", sub, css)


def kit() -> tuple[str, str]:
    """``(css, version)``: SATOM's stylesheets as the console loads them
    (Bootstrap, Bootstrap Icons, fortiweb.css), fonts inlined, built once per
    worker and rebuilt when a file changes (its size and mtime)."""
    stamp = []
    for rel in _KIT_FILES:
        st = os.stat(os.path.join(_STATIC, rel))
        stamp.append("%s:%d:%d" % (rel, st.st_size, int(st.st_mtime)))
    key = "|".join(stamp)
    if _kit.get("key") != key:
        parts = []
        for rel in _KIT_FILES:
            path = os.path.join(_STATIC, rel)
            with open(path, encoding="utf-8") as fh:
                parts.append(_inline_fonts(fh.read(), os.path.dirname(path)))
        css = "\n".join(parts)
        _kit.update(key=key, css=css, version=hashlib.sha256(css.encode()).hexdigest()[:16])
    return _kit["css"], _kit["version"]


def bridge_js() -> str:
    path = os.path.join(_STATIC, "js", "app_view_bridge.js")
    st = os.stat(path)
    key = "%d:%d" % (st.st_size, int(st.st_mtime))
    if _bridge.get("key") != key:
        with open(path, encoding="utf-8") as fh:
            _bridge.update(key=key, js=fh.read())
    return _bridge["js"]


def new_token() -> str:
    return _secrets.token_urlsafe(24)


TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def document(view: dict, html: str, island: dict, *, kit_url: str, bootstrap_url: str,
             theme_css: str) -> str:
    """The whole document of the frame. Order: SATOM's stylesheets, the
    active theme, the view's CSS; the body; the data island; Bootstrap's
    script, the bridge, the view's script. *kit_url* and *bootstrap_url* are
    ABSOLUTE: in an opaque origin a path, or 'self', matches nothing."""
    from .plugin_frame import json_island
    css = (view.get("css") or "").replace("</", "<\\/")
    js = (view.get("js") or "").replace("</script", "<\\/script")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<link rel='stylesheet' href='{kit_url}'>"
        f"<style id='satom-theme'>{theme_css or ''}</style>"
        "<style>html,body{background:var(--fw-content-bg,#F3F6FC);}"
        "body{margin:0;padding:0 2px 24px 0;}</style>"
        f"<style id='view-css'>{css}</style></head><body class='satom-app-view'>"
        f"{html}"
        f"<script id='satom-view' type='application/json'>{json_island(island)}</script>"
        f"<script src='{bootstrap_url}'></script>"
        f"<script>{bridge_js()}</script>"
        f"<script>{js}</script>"
        "</body></html>")


def csp(kit_url: str, bootstrap_url: str) -> str:
    """The frame's policy: its own inline code, SATOM's kit and Bootstrap's
    script, data: images and fonts -- no request anywhere else, no form, no
    base, framed only by SATOM, and a sandbox even if opened directly."""
    for u in (kit_url, bootstrap_url):
        if not re.match(r"^https?://[A-Za-z0-9.:\[\]-]+/[A-Za-z0-9/._-]+$", u):
            raise ViewError("not an absolute SATOM address: %r" % u)
    return ("default-src 'none'; style-src 'unsafe-inline' %s; "
            "script-src 'unsafe-inline' %s; img-src data:; font-src data:; "
            "connect-src 'none'; form-action 'none'; base-uri 'none'; "
            "frame-ancestors 'self'; sandbox allow-scripts allow-modals"
            % (kit_url, bootstrap_url))
