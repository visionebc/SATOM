"""Regex calculator ("laboratorio") — server-side pattern testing, rewrite/
backreference preview, and the FortiWeb/FortiADC-oriented reference library.

FortiWeb AND FortiADC both evaluate regular expressions with a PCRE-compatible
engine, and BOTH reference capture groups in rewrite/redirect replacements as
``$0 $1 … $9``. Python's ``re`` is the closest server-side approximation we can
test against without shipping a PCRE binding (differences are edge-case:
possessive quantifiers and recursion aren't supported here — flagged in the UI
notes). The point is to let the operator PROVE a pattern — and the string it
rewrites to — against sample requests BEFORE it lands in a rule, instead of
authoring blind.

Guards: pattern/sample/replacement sizes are capped and the sample count
limited, so a hostile/costly pattern can't be used to stall a worker (Python
``re`` has no timeout; the caps keep the worst case tiny).
"""
from __future__ import annotations

import re

MAX_PATTERN = 2048
MAX_SAMPLES = 100
MAX_SAMPLE_LEN = 4096
MAX_REPLACEMENT = 2048

# Products the regex lab covers. Derived LIVE from the ADOM registry
# (``cap_regex``) — a live sequence, so ``p in PRODUCTS`` re-reads the registry.
from ..branding import live_products as _live_products  # noqa: E402

PRODUCTS = _live_products("regex")


def _norm_product(product: str) -> str:
    p = (product or "").strip().lower()
    return p if p in PRODUCTS else "fortiweb"


# ---------------------------------------------------------------------------
# Flavor notes — general PCRE truths plus per-product practical guidance.
# ---------------------------------------------------------------------------
_COMMON_NOTES = [
    "Both FortiWeb and FortiADC use a PCRE-compatible engine — the patterns you prove here behave the same on the appliance (edge cases: possessive quantifiers `a++` and recursion aren't supported in this tester).",
    "An unanchored pattern matches ANYWHERE in the value. Anchor with `^` (start) and `$` (end) when you mean the whole string.",
    "Escape literal dots: `\\.php$`. A bare `.` matches ANY single character.",
    "Capture groups `( … )` are referenced in rewrite/redirect replacements as `$0 $1 … $9` on BOTH products (not `\\1`).",
    "Keep deny/match patterns specific — a broad `.*` in a deny rule or content-route can swallow the whole site.",
]

FORTIWEB_NOTES = [
    "FortiWeb URL patterns are matched against the WHOLE request path — start them with `/` (e.g. `^/admin`, not `admin`).",
    "URL Rewriting: the rule's regex captures feed the replacement as `$0 $1 …`; `$0` is the first `( … )` group of THAT rule.",
    "Signature / custom-rule matching is case-sensitive unless you use the `(?i)` inline flag or the field's case option.",
    "Protected-hostname and Allow-Method exceptions match host/URL with the same PCRE flavor — test both host and path samples.",
] + _COMMON_NOTES

FORTIADC_NOTES = [
    "FortiADC Content Rewriting can capture from the Host-header regex AND the URL regex in the same rule; captures are indexed GLOBALLY, so `$0` may come from the Host match and `$1` from the URL match.",
    "HTTP redirect actions accept a regex-built Location (`https://$0/$1`); other rewrite actions want the full URL as a literal string.",
    "Content Routing / Virtual-Server matching (Host, URL, referer, source) uses the same PCRE flavor — anchor host rules with `^…$` to avoid substring surprises.",
    "Real-server / SLB health-check response matching also takes a regex — test it against the exact body the backend returns.",
] + _COMMON_NOTES

# Backward-compatible alias used by older callers.
DEFAULT_NOTES = FORTIWEB_NOTES


# ---------------------------------------------------------------------------
# Token cheat sheet — a real reference, grouped the way an operator scans it.
# ---------------------------------------------------------------------------
CHEATSHEET = [
    {"group": "Anchors", "items": [
        {"tok": "^", "desc": "Start of string/line", "ex": "^/api"},
        {"tok": "$", "desc": "End of string/line", "ex": "\\.php$"},
        {"tok": "\\b", "desc": "Word boundary", "ex": "\\badmin\\b"},
    ]},
    {"group": "Character classes", "items": [
        {"tok": ".", "desc": "Any char except newline", "ex": "a.c"},
        {"tok": "[abc]", "desc": "One of a, b or c", "ex": "[Gg]et"},
        {"tok": "[^abc]", "desc": "Any char NOT a, b, c", "ex": "[^/]+"},
        {"tok": "[a-z]", "desc": "Range a to z", "ex": "[a-z0-9-]+"},
        {"tok": "\\d \\w \\s", "desc": "Digit / word char / whitespace", "ex": "\\d{1,5}"},
        {"tok": "\\D \\W \\S", "desc": "Negated digit / word / space", "ex": "\\S+"},
    ]},
    {"group": "Quantifiers", "items": [
        {"tok": "*", "desc": "0 or more", "ex": "/.*"},
        {"tok": "+", "desc": "1 or more", "ex": "[0-9]+"},
        {"tok": "?", "desc": "0 or 1 (optional)", "ex": "s?"},
        {"tok": "{n} {n,} {n,m}", "desc": "Exactly n / n+ / n..m", "ex": "[a-f0-9]{32}"},
        {"tok": "*?  +?", "desc": "Lazy (shortest match)", "ex": "<.*?>"},
    ]},
    {"group": "Groups & alternation", "items": [
        {"tok": "( … )", "desc": "Capture group → $1, $2 …", "ex": "^/(.*)$"},
        {"tok": "(?: … )", "desc": "Non-capturing group", "ex": "(?:www\\.)?"},
        {"tok": "a|b", "desc": "a OR b", "ex": "\\.(zip|tar\\.gz)$"},
        {"tok": "(?i)", "desc": "Case-insensitive from here", "ex": "(?i)union\\s+select"},
    ]},
    {"group": "Lookarounds", "items": [
        {"tok": "(?= … )", "desc": "Positive lookahead", "ex": "^(?=.*admin)"},
        {"tok": "(?! … )", "desc": "Negative lookahead", "ex": "^(?!/public/).*"},
    ]},
    {"group": "Escapes", "items": [
        {"tok": "\\. \\/ \\? \\+", "desc": "Literal metacharacter", "ex": "index\\.php\\?id="},
        {"tok": "\\\\", "desc": "Literal backslash", "ex": "C:\\\\Windows"},
    ]},
]


# ---------------------------------------------------------------------------
# Example library. Each example carries an optional `replacement` so the
# Rewrite tab can demo the produced string; `products` scopes it (default: both).
# ---------------------------------------------------------------------------
GENERIC = [
    {"pattern": r"^/admin(/.*)?$", "sample": "/admin/login.php",
     "note": "The /admin area and everything under it"},
    {"pattern": r"\.(php|asp|aspx|jsp)$", "sample": "/shop/checkout.php",
     "note": "Requests for dynamic-script extensions"},
    {"pattern": r"^/api/v[0-9]+/", "sample": "/api/v2/users",
     "note": "Any versioned API prefix (v1, v2, …)"},
    {"pattern": r"^(?!/public/).*$", "sample": "/private/report.pdf",
     "note": "Everything EXCEPT /public/… (negative lookahead)"},
]

_EXAMPLES: dict[str, list[dict]] = {
    "url": [
        {"pattern": r"^/wp-(admin|login|content)(/.*)?$", "sample": "/wp-login.php",
         "note": "WordPress admin/login surface"},
        {"pattern": r"^/download/.*\.(zip|tar\.gz)$", "sample": "/download/build-2.4.zip",
         "note": "Only archive downloads under /download/"},
        {"pattern": r"^/[a-z]{2}(-[A-Z]{2})?/shop/", "sample": "/es-MX/shop/cart",
         "note": "Locale-prefixed shop URLs (es, es-MX, en-US…)"},
    ] + GENERIC,
    "host": [
        {"pattern": r"^(www\.)?example\.com$", "sample": "www.example.com",
         "note": "Bare and www host"},
        {"pattern": r"^[a-z0-9-]+\.example\.com$", "sample": "api.example.com",
         "note": "Any single-level subdomain"},
    ],
    "parameter": [
        {"pattern": r"^[0-9]{1,10}$", "sample": "48213",
         "note": "Strictly numeric id (validation allow-pattern)"},
        {"pattern": r"^[A-Za-z0-9_-]{8,64}$", "sample": "sess_Xk29rQ-71",
         "note": "Token/slug: alphanumerics, _ and -, 8-64 chars"},
        {"pattern": r"^[^<>\"']*$", "sample": "plain text value",
         "note": "Reject HTML metacharacters in a form field"},
    ],
    "header": [
        {"pattern": r"^Mozilla/5\.0.*$", "sample": "Mozilla/5.0 (X11; Linux x86_64)",
         "note": "Browser-like User-Agent"},
        {"pattern": r"^(curl|python-requests|wget)/", "sample": "curl/8.5.0",
         "note": "Common script/bot User-Agents"},
    ],
    "rewrite": [
        {"pattern": r"^/old-shop/(.*)$", "sample": "/old-shop/item/42",
         "replacement": r"/new-shop/$1", "note": "Move /old-shop/* → /new-shop/*"},
        {"pattern": r"^/(.*)\.html$", "sample": "/about.html",
         "replacement": r"/$1", "note": "Strip the .html suffix"},
        {"pattern": r"^/product/([0-9]+)/?$", "sample": "/product/42",
         "replacement": r"/item?id=$1", "note": "Pretty URL → query string"},
    ],
    "signature": [
        {"pattern": r"(?i)union[\s/*]+select", "sample": "1 UNION SELECT password FROM users",
         "note": "Classic SQLi probe (case-insensitive inline flag)"},
        {"pattern": r"<script[^>]*>", "sample": "<script src=//evil.js>",
         "note": "Script-tag XSS probe"},
        {"pattern": r"\.\./\.\./", "sample": "/download?f=../../etc/passwd",
         "note": "Directory traversal"},
    ],
}

# Product-specific highlights, shown at the top of the library on each product.
_PRODUCT_EXAMPLES: dict[str, list[dict]] = {
    "fortiweb": [
        {"pattern": r"^/(.*)$", "sample": "/legacy/report", "replacement": r"/app/$1",
         "note": "URL Rewriting: prefix every path with /app/ (rule capture $0=first group)"},
        {"pattern": r"(?i)(<|%3c)script", "sample": "%3Cscript>alert(1)",
         "note": "Custom signature: catch encoded and literal <script"},
    ],
    "fortiadc": [
        {"pattern": r"(.*)", "sample": "shop.example.com", "replacement": r"https://$0/$1",
         "note": "Content Rewriting: Host regex captures $0; pair with a URL regex that captures $1"},
        {"pattern": r"^/(.*)$", "sample": "/cart", "replacement": r"/$1",
         "note": "Content Rewriting URL regex — the $1 half of https://$0/$1"},
        {"pattern": r"^/(en|es|fr)/", "sample": "/es/checkout",
         "note": "Content Routing: send locale-prefixed traffic to a virtual server"},
    ],
}

# spec kind → example family. Anything not listed falls back to GENERIC+url.
_FAMILY: dict[str, str] = {
    "url_access_rule": "url", "url_access_policy": "url",
    "http_constraint_exception": "url", "allow_method_exception": "url",
    "url_encryption_rule": "url", "link_cloaking_rule": "url",
    "hidden_fields_rule": "url", "csrf_protection": "url",
    "user_tracking_rule": "url", "file_upload_rule": "url",
    "url_rewrite_rule": "rewrite", "url_rewrite_policy": "rewrite",
    "content_rewriting": "rewrite", "content_routing": "url",
    "http_header_security_exception": "url",
    "cookie_security": "parameter", "parameter_validation_rule": "parameter",
    "custom_rule": "parameter", "syntax_based_detection": "parameter",
    "signature": "signature", "signature_group_rule": "signature",
    "signature_filter_item": "url",
    "bot_exception_policy": "url", "bot_known_bots": "header",
    "x_forward": "header", "http_header_security": "header",
    "cors_protection_rule": "header",
    "allow_hosts": "host", "allow_host_item": "host",
}


def examples_for(context: str, product: str = "fortiweb") -> list[dict]:
    """Curated examples for a spec-kind context on a given product, merged with
    any admin-guide examples harvested into waf_help.json for that section."""
    product = _norm_product(product)
    fam = _FAMILY.get(context or "", "")
    out: list[dict] = list(_PRODUCT_EXAMPLES.get(product, []))
    out += list(_EXAMPLES.get(fam, [])) if fam else []
    if not fam:
        out += list(_EXAMPLES["url"])
    # Merge harvested per-section examples (waf_help.json), if present.
    try:
        from . import waf_specs
        sec = waf_specs.section_help(context or "")
        for ex in sec.get("examples", []):
            pat = ex.get("pattern-or-value") or ex.get("pattern") or ""
            if pat and any(ch in pat for ch in "^$[]()*+?\\|"):
                out.append({"pattern": pat, "sample": ex.get("sample", ""),
                            "note": ex.get("note", "") or ex.get("field", "")})
    except Exception:  # noqa: BLE001 — examples are best-effort
        pass
    # De-dup by pattern, keep order.
    seen, uniq = set(), []
    for ex in out:
        key = ex.get("pattern", "")
        if key and key not in seen:
            seen.add(key)
            uniq.append(ex)
    return uniq[:16]


def guide_notes(product: str = "fortiweb") -> list[str]:
    """FortiWeb/FortiADC regex-flavor notes (harvested guide first, then the
    product-specific static set)."""
    product = _norm_product(product)
    base = FORTIADC_NOTES if product == "fortiadc" else FORTIWEB_NOTES
    if product == "fortiweb":
        try:
            from . import waf_specs
            g = waf_specs.regex_guide()
            notes = list(g.get("notes") or [])
            if g.get("flavor"):
                notes.insert(0, g["flavor"])
            if notes:
                return (notes + base)[:10]
        except Exception:  # noqa: BLE001
            pass
    return base[:10]


def cheatsheet() -> list[dict]:
    """The PCRE token reference groups shown in the calculator's Cheat-sheet tab."""
    return CHEATSHEET


def _to_python_repl(replacement: str) -> str:
    r"""Translate a FortiWeb/FortiADC replacement string (``$0 $1 … $9`` and
    ``${0}``) into Python's ``\g<n>`` form so ``re.sub`` renders it. Literal
    ``\1`` backrefs are also accepted (some operators write them). ``$$`` and a
    literal ``$`` are preserved."""
    out = []
    i, n = 0, len(replacement)
    while i < n:
        c = replacement[i]
        if c == "$" and i + 1 < n:
            nxt = replacement[i + 1]
            if nxt == "$":            # $$ -> literal $
                out.append("$")
                i += 2
                continue
            if nxt == "{":            # ${12}
                j = replacement.find("}", i + 2)
                if j != -1 and replacement[i + 2:j].isdigit():
                    out.append("\\g<%s>" % replacement[i + 2:j])
                    i = j + 1
                    continue
            if nxt.isdigit():         # $1, $0 …
                out.append("\\g<%s>" % nxt)
                i += 2
                continue
        if c == "\\" and i + 1 < n and replacement[i + 1].isdigit():
            out.append("\\g<%s>" % replacement[i + 1])   # \1 -> group 1
            i += 2
            continue
        # Escape a lone backslash for re.sub's template parser.
        out.append("\\\\" if c == "\\" else c)
        i += 1
    return "".join(out)


def test_pattern(pattern: str, samples: list[str],
                 case_insensitive: bool = False) -> dict:
    """Test one pattern against up to ``MAX_SAMPLES`` sample values.

    Returns ``{ok, error, results:[{sample, match, span, groups}]}`` — *match*
    uses ``re.search`` (FortiWeb/FortiADC match anywhere unless the pattern
    anchors), *span* is the matched substring's [start, end), *groups* the
    captures ($1, $2 … as used by rewrite/redirect replacements).
    """
    pattern = (pattern or "")[:MAX_PATTERN]
    if not pattern:
        return {"ok": False, "error": "empty pattern", "results": []}
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        return {"ok": False, "error": "invalid regex: %s" % exc, "results": []}
    results = []
    for raw in (samples or [])[:MAX_SAMPLES]:
        s = str(raw)[:MAX_SAMPLE_LEN]
        m = rx.search(s)
        results.append({
            "sample": s,
            "match": bool(m),
            "span": [m.start(), m.end()] if m else None,
            "groups": list(m.groups()) if m else [],
        })
    return {"ok": True, "error": "", "results": results,
            "matched": sum(1 for r in results if r["match"]),
            "total": len(results)}


def render_rewrite(pattern: str, replacement: str, samples: list[str],
                   case_insensitive: bool = False) -> dict:
    r"""Show what each sample REWRITES to — the marquee feature for URL
    Rewriting (FortiWeb) and Content Rewriting (FortiADC), where you build a
    new URL from ``$0 $1 …`` captures.

    Returns ``{ok, error, results:[{sample, match, output, groups}]}``. *output*
    is the sample with the matched portion substituted by the rendered
    replacement (``re.sub`` count=1 — one rewrite, as the appliance does).
    """
    pattern = (pattern or "")[:MAX_PATTERN]
    replacement = (replacement or "")[:MAX_REPLACEMENT]
    if not pattern:
        return {"ok": False, "error": "empty pattern", "results": []}
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        return {"ok": False, "error": "invalid regex: %s" % exc, "results": []}
    py_repl = _to_python_repl(replacement)
    results = []
    for raw in (samples or [])[:MAX_SAMPLES]:
        s = str(raw)[:MAX_SAMPLE_LEN]
        m = rx.search(s)
        if not m:
            results.append({"sample": s, "match": False, "output": None, "groups": []})
            continue
        try:
            out = rx.sub(py_repl, s, count=1)
            err = ""
        except re.error as exc:
            out = None
            err = "invalid replacement: %s" % exc
        row = {"sample": s, "match": True, "output": out,
               "groups": list(m.groups())}
        if err:
            row["error"] = err
        results.append(row)
    return {"ok": True, "error": "", "results": results,
            "matched": sum(1 for r in results if r["match"]),
            "total": len(results)}


__all__ = ["test_pattern", "render_rewrite", "examples_for", "guide_notes",
           "cheatsheet", "PRODUCTS"]
