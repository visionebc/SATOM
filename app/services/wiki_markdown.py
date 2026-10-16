"""Markdown → HTML for text users write (Wiki articles, and comments in 1b).

Anyone with ``wiki.write`` writes here and everyone in the audience reads it,
so the output is the XSS surface of the Wiki. python-markdown (already a
dependency) passes raw HTML through and does not look at link targets; both
are closed here instead of adding a sanitiser:

* the raw-HTML block preprocessor and inline pattern are removed, so ``<tag>``
  is text and the serializer escapes it;
* a tree pass keeps ``href``/``src`` only for http(s), mailto, in-page and
  relative targets — ``javascript:``, ``data:``, ``vbscript:`` and anything
  else are dropped, scheme case, embedded whitespace and entity-encoded
  colons (``javascript&#58;``) included;
* every link gets ``rel="noopener noreferrer nofollow"``; external ones open
  in a new tab.

The rich-text editor (Toast UI, vendored) writes GitHub-flavoured Markdown:
``~~struck~~`` becomes ``<del>`` and its line breaks, which it writes as a
literal ``<br>`` (also inside table cells), become a ``<br>`` element — the
one tag recognised, built here with no attributes, never passed through.

No extension that re-enables HTML (``md_in_html``) may be added to
``_EXTENSIONS``; tests/test_wiki_markdown.py pins the dangerous cases.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

import xml.etree.ElementTree as etree

import markdown
from markdown.inlinepatterns import InlineProcessor, SimpleTagInlineProcessor
from markdown.treeprocessors import Treeprocessor
from markupsafe import Markup

_EXTENSIONS = ("fenced_code", "tables", "sane_lists", "nl2br", "toc")
_SAFE_SCHEMES = {"http", "https", "mailto"}
_WS = re.compile(r"[\x00-\x20\x7f]+")


def _decoded(raw: str) -> str:
    """``raw`` with HTML entities decoded until nothing changes.
    python-markdown keeps ``&#58;`` in an href as written and the browser
    decodes it, so ``javascript&#58;`` IS ``javascript:`` — the scheme is
    judged on what the browser will see, and that is what gets emitted (a
    fixpoint holds no entity left to decode)."""
    for _ in range(8):
        nxt = html.unescape(raw)
        if nxt == raw:
            return raw
        raw = nxt
    return ""


def safe_url(raw: str | None, *, image: bool = False) -> str | None:
    """``raw`` if it is safe to put in href/src, else ``None``."""
    url = _WS.sub("", _decoded(str(raw or "")))
    if not url:
        return None
    if url.startswith(("#", "/")) and not url.startswith("//"):
        return url
    scheme = urlsplit(url).scheme.lower()
    if not scheme:
        # "page", "./img.png" — relative. A colon before any slash would
        # have been parsed as a scheme above.
        return url
    allowed = {"http", "https"} if image else _SAFE_SCHEMES
    return url if scheme in allowed else None


class _LinkGuard(Treeprocessor):
    def run(self, root):
        for el in root.iter():
            if el.tag == "a":
                href = safe_url(el.get("href"))
                if href is None:
                    el.attrib.pop("href", None)
                else:
                    el.set("href", href)
                    el.set("rel", "noopener noreferrer nofollow")
                    if urlsplit(href).scheme in ("http", "https"):
                        el.set("target", "_blank")
            elif el.tag == "img":
                src = safe_url(el.get("src"), image=True)
                if src is None:
                    el.attrib.pop("src", None)
                else:
                    el.set("src", src)
                el.set("loading", "lazy")
            for attr in list(el.attrib):
                if attr.lower().startswith("on"):
                    del el.attrib[attr]
        return None


class _LineBreak(InlineProcessor):
    """``<br>`` / ``<br/>`` / ``<br />`` → an empty ``br`` element."""
    def handleMatch(self, m, data):
        return etree.Element("br"), m.start(0), m.end(0)


def _converter() -> markdown.Markdown:
    md = markdown.Markdown(extensions=list(_EXTENSIONS),
                           extension_configs={"toc": {"permalink": False}})
    md.preprocessors.deregister("html_block")
    md.inlinePatterns.deregister("html")
    # Below backticks (190) so `<br>` and ~~ inside code spans stay text.
    md.inlinePatterns.register(_LineBreak(r"(?i:<br\s*/?>)", md), "wiki_br", 95)
    md.inlinePatterns.register(SimpleTagInlineProcessor(r"(~~)(?=\S)(.+?)(?<=\S)~~", "del"),
                               "wiki_del", 94)
    md.treeprocessors.register(_LinkGuard(md), "wiki_link_guard", 0)
    return md


def render(text: str | None) -> Markup:
    """Safe HTML for ``text``. A fresh converter per call: python-markdown
    keeps state (footnotes, toc) between ``convert`` calls."""
    return Markup(_converter().convert(str(text or "")))


def plain_excerpt(text: str | None, limit: int = 220) -> str:
    """A one-line, markup-free preview for lists (escaped by Jinja)."""
    s = re.sub(r"```.*?```", " ", str(text or ""), flags=re.S)
    s = re.sub(r"<br\s*/?>", " ", s, flags=re.I)
    s = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", s)
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[#>*_`|~-]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"
