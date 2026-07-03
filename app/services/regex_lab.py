"""Regex calculator ("laboratorio") — server-side pattern testing + the
per-section example library.

FortiWeb evaluates regular expressions with a PCRE-compatible engine; Python's
``re`` is the closest server-side approximation we can test against without
shipping a PCRE binding (differences are edge-case: possessive quantifiers and
recursion are not supported here — flagged in the UI notes). The point is to
let the operator PROVE a pattern against sample requests BEFORE it lands in a
WAF rule, instead of authoring blind.

Guards: pattern/sample sizes are capped and the sample count limited, so a
hostile/costly pattern can't be used to stall a worker (Python ``re`` has no
timeout; the caps keep the worst case tiny).
"""
from __future__ import annotations

import re

MAX_PATTERN = 2048
MAX_SAMPLES = 100
MAX_SAMPLE_LEN = 4096

# FortiWeb regex flavor notes shown in the lab (overridden/extended by the
# admin-guide harvest in waf_help.json → waf_specs.regex_guide()).
DEFAULT_NOTES = [
    "FortiWeb uses a PCRE-compatible engine; most patterns you test here behave identically on the appliance.",
    "URL patterns must match the WHOLE path FortiWeb compares (start them with / — e.g. ^/admin, not admin).",
    "Use ^ and $ to anchor; an unanchored pattern matches anywhere in the value.",
    "In URL Rewriting, capture groups are referenced as $0, $1 … in the replacement.",
    "Escape literal dots: \\.php$ — an unescaped . matches ANY character.",
    "Keep patterns specific: a broad pattern (.*) in a deny rule can block the whole site.",
]

# Curated, FortiWeb-realistic examples per context FAMILY. A context is the
# spec kind (waf_specs); _FAMILY maps kinds to a family; unknown kinds get GENERIC.
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
         "note": "Capture the tail — replacement /new-shop/$1"},
        {"pattern": r"^/(.*)\.html$", "sample": "/about.html",
         "note": "Strip .html — replacement /$1"},
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

# spec kind → example family. Anything not listed falls back to GENERIC+url.
_FAMILY: dict[str, str] = {
    "url_access_rule": "url", "url_access_policy": "url",
    "http_constraint_exception": "url", "allow_method_exception": "url",
    "url_encryption_rule": "url", "link_cloaking_rule": "url",
    "hidden_fields_rule": "url", "csrf_protection": "url",
    "user_tracking_rule": "url", "file_upload_rule": "url",
    "url_rewrite_rule": "rewrite", "url_rewrite_policy": "rewrite",
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


def examples_for(context: str) -> list[dict]:
    """Curated examples for a spec-kind context, merged with any admin-guide
    examples harvested into waf_help.json for that section."""
    fam = _FAMILY.get(context or "", "")
    out = list(_EXAMPLES.get(fam, [])) if fam else []
    if not out:
        out = list(_EXAMPLES["url"])
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
    return out[:12]


def guide_notes() -> list[str]:
    """FortiWeb regex-flavor notes (harvested guide first, static fallback)."""
    try:
        from . import waf_specs
        g = waf_specs.regex_guide()
        notes = list(g.get("notes") or [])
        if g.get("flavor"):
            notes.insert(0, g["flavor"])
        if notes:
            return notes[:8]
    except Exception:  # noqa: BLE001
        pass
    return DEFAULT_NOTES


def test_pattern(pattern: str, samples: list[str],
                 case_insensitive: bool = False) -> dict:
    """Test one pattern against up to ``MAX_SAMPLES`` sample values.

    Returns ``{ok, error, results:[{sample, match, span, groups}]}`` — *match*
    uses ``re.search`` (FortiWeb matches anywhere unless the pattern anchors),
    *span* is the matched substring's [start, end), *groups* the captures
    ($1, $2 … as used by URL Rewriting replacements).
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


__all__ = ["test_pattern", "examples_for", "guide_notes"]
