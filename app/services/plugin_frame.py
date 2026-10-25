"""The document a view or widget renders into: SATOM's frame around a body.

One builder for every place a plugin is shown -- the console page, the
editor's preview, the Builder rehearsal on this server -- and, through the
rules pack, the SATOM Builder's local preview with test data. That last one
is why this module is pure: it imports only the generated token registry, and
the two pieces that live elsewhere (the active theme, which is in the
database, and the class kit, which is a static file) are passed in by the
caller or read lazily here, on the server.

Order inside the document: the design tokens, the class kit, the plugin's
CSS (so the plugin can refine both), the body, the data and params as JSON
islands, then the plugin's JavaScript.
"""
from __future__ import annotations

import json
import os
import re

from .theme_tokens import DEFAULTS, TOKEN_NAMES

KIT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "static", "css", "plugin-kit.css")
_kit_cache: "str | None" = None


def kit_css_from(text: str) -> str:
    """The class kit as the frame inlines it: comments stripped."""
    return re.sub(r"/\*.*?\*/\n?", "", text or "", flags=re.S)


def kit_css() -> str:
    """The published plugin class kit (``static/css/plugin-kit.css``).

    Read once per worker and INLINED: the frame's CSP is ``default-src 'none'``,
    so a ``<link>`` to the file would simply not load."""
    global _kit_cache
    if _kit_cache is None:
        with open(KIT_PATH, encoding="utf-8") as fh:
            _kit_cache = kit_css_from(fh.read())
    return _kit_cache


def default_tokens_css() -> str:
    """``:root`` with every ``--fw-*`` token at its default (no theme)."""
    return ":root{%s}" % "".join("--fw-%s:%s;" % (k, DEFAULTS[k]) for k in TOKEN_NAMES)


def tokens_css() -> str:
    """The defaults, then the active theme's overrides.

    The overrides come from ``theme_service.active_css()`` -- Settings >
    Appearance, re-validated per token kind there, cached, and never raising
    -- so a customer theme reaches every plugin exactly as it reaches the
    console."""
    from . import theme_service
    return "%s\n%s" % (default_tokens_css(), theme_service.active_css())


def frame_document(plugin, body_html: str, data: dict, params: dict | None = None, *,
                   tokens: str | None = None, kit: str | None = None) -> str:
    """The full HTML document of a rendered plugin.

    *plugin* is anything with ``css`` and ``js`` attributes. *tokens* and *kit*
    default to this server's active theme and class kit; the Builder passes
    the defaults it carries in the rules pack."""
    css = getattr(plugin, "css", "") or ""
    js = getattr(plugin, "js", "") or ""
    # A ``</style`` in the plugin's CSS would end the element and turn the rest
    # into HTML. ``<\/`` is the same text to the CSS parser (``\/`` is ``/``).
    css = css.replace("</", "<\\/")
    # Neutralise any ``</script>`` in the injected JSON so a dataset/param value
    # (e.g. a device policy comment synced from a FortiWeb) can never break out
    # of its <script> island -- the same guard the editor's JSON islands use.
    data_json = json.dumps(data).replace("</", "<\\/")
    params_json = json.dumps(params or {}).replace("</", "<\\/")
    tokens = tokens_css() if tokens is None else tokens
    kit = kit_css() if kit is None else kit
    # Datasets are ALSO exposed to the plugin JS as a JSON island (it can't fetch
    # them back -- opaque origin -- so we inject them here).
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<style id='satom-tokens'>{tokens}</style>"
        f"<style id='satom-kit'>{kit}</style>"
        f"<style id='plugin-css'>{css}</style></head><body>"
        f"{body_html}"
        f"<script id='plugin-data' type='application/json'>{data_json}</script>"
        f"<script id='plugin-params' type='application/json'>{params_json}</script>"
        "<script>window.pluginData=JSON.parse("
        "document.getElementById('plugin-data').textContent||'{}');"
        "window.pluginParams=JSON.parse("
        "document.getElementById('plugin-params').textContent||'{}');</script>"
        f"<script>{js}</script>"
        "</body></html>"
    )
