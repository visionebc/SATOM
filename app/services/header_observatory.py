# app/services/header_observatory.py
"""HTTP Observatory scoring — what a browser-facing security header review
would grade a published site, test by test.

The tests, the score modifiers, the "penalties first, bonuses only from 90"
rule and the grade chart follow the MDN HTTP Observatory, algorithm version 6
(github.com/mdn/mdn-http-observatory, MPL-2.0; see NOTICE). The rules were read
from its source, not recalled, and re-implemented here; the texts are SATOM's
own. Keeping the scoring identical is the point: an operator who checks the
same site on developer.mozilla.org/observatory must get the same grade, or one
of the two numbers is worthless.

This module is PURE: it scores a description of what was fetched (see
:func:`analyze`) and never opens a socket. Fetching is
:mod:`app.services.observatory_scan`; deciding which setting on the appliance
would fix a failed test is :mod:`app.services.observatory_fix`.

Three documented differences from mozilla.org:

* **The HSTS preload list is not consulted.** It is a Chromium data file the
  node does not carry. ``hsts-preloaded`` (+5) and
  ``redirection-all-redirects-preloaded`` are therefore never awarded; a site
  that is preloaded scores what its own headers earn.
* **The registrable domain used by the SRI test** is read with a short
  built-in list of multi-label public suffixes instead of the full Public
  Suffix List (no PSL library on the node). It only decides whether an
  external script is "same site"; :func:`registrable_domain` names the list.
* **A non-numeric HSTS max-age is invalid.** The reference parses it with
  JavaScript's ``parseInt``, gets ``NaN``, and ``NaN < 15552000`` is false, so
  ``max-age=abc`` passes there as "at least six months". Browsers ignore such
  a header; SATOM scores it ``hsts-header-invalid``.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

ALGORITHM_VERSION = 6

#: Score → grade, in steps of 5 (scores above 100 read the 100 row).
GRADE_CHART = {
    100: "A+", 95: "A", 90: "A", 85: "A-", 80: "B+", 75: "B", 70: "B",
    65: "B-", 60: "C+", 55: "C", 50: "C", 45: "C-", 40: "D+", 35: "D",
    30: "D", 25: "D-", 20: "F", 15: "F", 10: "F", 5: "F", 0: "F",
}
GRADES = ("A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F")
#: Bonuses count only when the penalties alone leave the site at an A.
MINIMUM_SCORE_FOR_EXTRA_CREDIT = 90

#: ``(name, title)`` in the order the results are listed.
TESTS = (
    ("content-security-policy", "Content Security Policy (CSP)"),
    ("cookies", "Cookies"),
    ("cross-origin-embedder-policy", "Cross Origin Embedder Policy"),
    ("cross-origin-opener-policy", "Cross Origin Opener Policy"),
    ("cross-origin-resource-sharing", "Cross Origin Resource Sharing (CORS)"),
    ("redirection", "Redirection"),
    ("referrer-policy", "Referrer Policy"),
    ("strict-transport-security", "Strict Transport Security (HSTS)"),
    ("subresource-integrity", "Subresource Integrity"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("cross-origin-resource-policy", "Cross Origin Resource Policy"),
)
TEST_TITLES = dict(TESTS)

#: Reference pages on MDN, per test.
TOPIC_LINKS = {
    "content-security-policy": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CSP",
    "cookies": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies",
    "cross-origin-embedder-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy",
    "cross-origin-opener-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CORP",
    "cross-origin-resource-sharing": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CORS",
    "redirection": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#http_redirection",
    "referrer-policy": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Referrer_policy",
    "strict-transport-security": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#http_strict_transport_security_implementation",
    "subresource-integrity": "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    "x-content-type-options": "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/MIME_types",
    "x-frame-options": "https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Clickjacking",
}

# --------------------------------------------------------------------------- #
#  Results: modifier, what it means, what to do                               #
# --------------------------------------------------------------------------- #
#: ``result -> (modifier, description, recommendation)``. Modifiers are the
#: Observatory's; a change there is a change of algorithm version.
SCORE_TABLE: dict[str, tuple[int, str, str]] = {
    # CSP
    "csp-implemented-with-no-unsafe-default-src-none": (
        10, "CSP implemented with default-src 'none', nothing unsafe, and "
            "form-action restricted.", ""),
    "csp-implemented-with-no-unsafe": (
        5, "CSP implemented without 'unsafe-inline' or 'unsafe-eval'.",
        "Set default-src to 'none' for the bonus."),
    "csp-implemented-with-unsafe-inline-in-style-src-only": (
        0, "CSP implemented; only style-src allows unsafe sources "
           "('unsafe-inline', data: or a broad scheme).",
        "Lock down style-src: remove 'unsafe-inline', data: and broad sources."),
    "csp-implemented-with-insecure-scheme-in-passive-content-only": (
        -10, "CSP implemented, but images or media may load over plain HTTP.",
        "Load images and media over HTTPS and restrict img-src/media-src "
        "(or default-src) to HTTPS sources."),
    "csp-implemented-with-unsafe-eval": (
        -10, "CSP implemented, but allows 'unsafe-eval'.",
        "Remove eval() from the code, then remove 'unsafe-eval' from the CSP."),
    "csp-implemented-with-unsafe-inline": (
        -20, "CSP implemented unsafely: 'unsafe-inline' or data: in "
             "script-src, broad sources in script-src/object-src, or those "
             "two directives not restricted at all.",
        "Remove 'unsafe-inline' and data: from script-src, remove broad "
        "sources, and set both script-src and object-src."),
    "csp-implemented-with-insecure-scheme": (
        -20, "CSP implemented, but an HTTPS site allows resources over HTTP.",
        "Load every resource over HTTPS and remove http: sources from the CSP."),
    "csp-header-invalid": (
        -25, "The Content-Security-Policy header cannot be parsed.",
        "Check the policy syntax (duplicate directives, a policy shorter than "
        "one directive, 'strict-dynamic' without a nonce or hash)."),
    "csp-not-implemented": (
        -25, "No Content-Security-Policy header.",
        "Implement a Content Security Policy."),
    "csp-not-implemented-but-reporting-enabled": (
        -25, "Only Content-Security-Policy-Report-Only is sent: nothing is "
             "enforced.",
        "Enforce a policy with the Content-Security-Policy header."),
    "csp-implemented-but-duplicate-directives": (
        0, "CSP implemented, but repeats report-uri or report-to.",
        "Remove the duplicate directives."),
    # Cookies
    "cookies-secure-with-httponly-sessions-and-samesite": (
        5, "Every cookie is Secure, session cookies are HttpOnly and SameSite "
           "is set.", ""),
    "cookies-secure-with-httponly-sessions": (
        0, "Every cookie is Secure and session cookies are HttpOnly.",
        "Add SameSite."),
    "cookies-not-found": (0, "No cookies were set.", ""),
    "cookies-without-secure-flag-but-protected-by-hsts": (
        -5, "Cookies without Secure, but HSTS keeps them off plain HTTP.",
        "Add the Secure flag."),
    "cookies-session-without-secure-flag-but-protected-by-hsts": (
        -10, "A session cookie without Secure, but HSTS keeps it off plain "
             "HTTP.", "Add the Secure flag."),
    "cookies-without-secure-flag": (
        -20, "Cookies set without Secure, or set over HTTP.",
        "Add the Secure flag and set up HSTS."),
    "cookies-samesite-flag-invalid": (
        -20, "SameSite is set to something other than Strict, Lax or None, or "
             "None is used without Secure.",
        "Use SameSite=Strict or SameSite=Lax."),
    "cookies-anticsrf-without-samesite-flag": (
        -20, "An anti-CSRF cookie without SameSite.",
        "Use SameSite=Strict or SameSite=Lax."),
    "cookies-session-without-httponly-flag": (
        -30, "A session cookie without HttpOnly: page scripts can read it.",
        "Add HttpOnly."),
    "cookies-session-without-secure-flag": (
        -40, "A session cookie without Secure, or set over HTTP.",
        "Add the Secure flag and set up HSTS."),
    # CORS
    "cross-origin-resource-sharing-not-implemented": (
        0, "Content is not exposed through CORS.", ""),
    "cross-origin-resource-sharing-implemented-with-public-access": (
        0, "Public content is exposed with Access-Control-Allow-Origin: *.", ""),
    "cross-origin-resource-sharing-implemented-with-restricted-access": (
        0, "Content is exposed through CORS, restricted to specific origins.", ""),
    "cross-origin-resource-sharing-implemented-with-universal-access": (
        -50, "The site reflects any Origin with credentials allowed: any site "
             "can read authenticated content (CSRF exposure).",
        "Allow only named origins for credentialed access, or use * without "
        "Access-Control-Allow-Credentials for public content."),
    # Redirection
    "redirection-all-redirects-preloaded": (
        0, "Every host redirected to is on the HSTS preload list.", ""),
    "redirection-to-https": (
        0, "HTTP redirects first to HTTPS on the same host and ends on HTTPS.", ""),
    "redirection-not-needed-no-http": (
        0, "The site does not answer plain HTTP, so no redirect is needed.", ""),
    "redirection-off-host-from-http": (
        -5, "The first redirect from HTTP goes to HTTPS on a DIFFERENT host, "
            "so the HSTS header of this host is never seen.",
        "Redirect to HTTPS on the same host first, then to the final host."),
    "redirection-not-to-https-on-initial-redirection": (
        -10, "Ends on HTTPS, but the first redirect is to another HTTP URL.",
        "Redirect to HTTPS on the same host first, then to the final host."),
    "redirection-not-to-https": (
        -20, "Redirects, but the final destination is not HTTPS.",
        "Redirect to HTTPS on the same host first, then to the final host."),
    "redirection-missing": (
        -20, "Plain HTTP does not redirect to HTTPS.",
        "Redirect HTTP to HTTPS on the same host."),
    "redirection-invalid-cert": (
        -20, "An untrusted certificate was met while following the redirects.",
        "Install a certificate browsers trust."),
    # Referrer
    "referrer-policy-private": (
        5, "Referrer-Policy is no-referrer, same-origin, strict-origin or "
           "strict-origin-when-cross-origin.", ""),
    "referrer-policy-not-implemented": (
        0, "No Referrer-Policy.",
        "Set strict-origin-when-cross-origin at least."),
    "referrer-policy-unsafe": (
        -5, "Referrer-Policy is origin, origin-when-cross-origin, unsafe-url "
            "or no-referrer-when-downgrade.",
        "Set strict-origin-when-cross-origin at least."),
    "referrer-policy-header-invalid": (
        -5, "Referrer-Policy cannot be recognised.",
        "Set strict-origin-when-cross-origin at least."),
    # HSTS
    "hsts-preloaded": (5, "On the HSTS preload list.", ""),
    "hsts-implemented-max-age-at-least-six-months": (
        0, "Strict-Transport-Security with max-age of at least six months "
           "(15552000).",
        "For preloading: add preload and includeSubDomains, max-age of at "
        "least 31536000, and submit the site to hstspreload.org."),
    "hsts-implemented-max-age-less-than-six-months": (
        -10, "Strict-Transport-Security with max-age under six months.",
        "Raise max-age to at least 15552000."),
    "hsts-not-implemented": (
        -20, "No Strict-Transport-Security header.", "Add HSTS."),
    "hsts-header-invalid": (
        -20, "Strict-Transport-Security cannot be recognised (no max-age, or "
             "sent more than once).", "Send one header with a max-age."),
    "hsts-not-implemented-no-https": (
        -20, "HSTS cannot be set: the site is not served over HTTPS.",
        "Serve the site over HTTPS."),
    "hsts-invalid-cert": (
        -20, "HSTS cannot take effect: the certificate is not trusted.",
        "Install a certificate browsers trust; HSTS only works over a valid "
        "TLS session."),
    # SRI
    "sri-implemented-and-all-scripts-loaded-securely": (
        5, "SRI is used and every script comes from the same site.", ""),
    "sri-implemented-and-external-scripts-loaded-securely": (
        5, "SRI is used and every script is loaded securely.", ""),
    "sri-not-implemented-response-not-html": (
        0, "SRI only applies to HTML; this response is not HTML.", ""),
    "sri-not-implemented-but-no-scripts-loaded": (
        0, "No script tags, so SRI is not needed.", ""),
    "sri-not-implemented-but-all-scripts-loaded-from-secure-origin": (
        0, "No SRI, but every script comes from the same site.",
        "Add SRI for the bonus."),
    "sri-not-implemented-but-external-scripts-loaded-securely": (
        -5, "External scripts over HTTPS without SRI.",
        "Add integrity attributes to the external scripts."),
    "sri-implemented-but-external-scripts-not-loaded-securely": (
        -20, "SRI is used, but external scripts load over HTTP or a "
             "protocol-relative //URL.", "Load external scripts over HTTPS."),
    "sri-not-implemented-and-external-scripts-not-loaded-securely": (
        -50, "External scripts over HTTP or a protocol-relative //URL, without "
             "SRI.", "Load external scripts over HTTPS and add SRI."),
    # X-Content-Type-Options
    "x-content-type-options-nosniff": (0, "X-Content-Type-Options: nosniff.", ""),
    "x-content-type-options-not-implemented": (
        -5, "No X-Content-Type-Options header.", "Set it to nosniff."),
    "x-content-type-options-header-invalid": (
        -5, "X-Content-Type-Options cannot be recognised.", "Set it to nosniff."),
    # X-Frame-Options
    "x-frame-options-implemented-via-csp": (
        5, "Framing is controlled by the CSP frame-ancestors directive.", ""),
    "x-frame-options-sameorigin-or-deny": (
        5, "X-Frame-Options is SAMEORIGIN or DENY.", ""),
    "x-frame-options-allow-from-origin": (
        0, "X-Frame-Options uses ALLOW-FROM.", "Use CSP frame-ancestors."),
    "x-frame-options-not-implemented": (
        -20, "No X-Frame-Options and no CSP frame-ancestors: the site can be "
             "framed (clickjacking).", "Use CSP frame-ancestors."),
    "x-frame-options-header-invalid": (
        -20, "X-Frame-Options cannot be recognised.", "Use CSP frame-ancestors."),
    # CORP
    "corp-header-invalid": (
        -5, "Cross-Origin-Resource-Policy cannot be recognised.",
        "Use same-site, same-origin or cross-origin."),
    "corp-implemented-with-cross-origin": (
        0, "Cross-Origin-Resource-Policy allows cross-origin use.", ""),
    "corp-implemented-with-same-origin": (
        10, "Cross-Origin-Resource-Policy: same-origin.", ""),
    "corp-implemented-with-same-site": (
        10, "Cross-Origin-Resource-Policy: same-site.", ""),
    "corp-not-implemented": (
        0, "No Cross-Origin-Resource-Policy (browsers default to "
           "cross-origin).", ""),
    # COEP
    "coep-implemented-with-require-corp": (
        10, "Cross-Origin-Embedder-Policy: require-corp.", ""),
    "coep-implemented-with-credentialless": (
        10, "Cross-Origin-Embedder-Policy: credentialless.", ""),
    "coep-implemented-with-unsafe-none": (
        0, "Cross-Origin-Embedder-Policy: unsafe-none (the default).",
        "Use require-corp or credentialless."),
    "coep-not-implemented": (
        0, "No Cross-Origin-Embedder-Policy.",
        "Use require-corp or credentialless."),
    "coep-header-invalid": (
        -5, "Cross-Origin-Embedder-Policy cannot be recognised.",
        "Use require-corp, credentialless or unsafe-none."),
    # COOP
    "coop-implemented-with-same-origin": (
        10, "Cross-Origin-Opener-Policy: same-origin.", ""),
    "coop-implemented-with-same-origin-allow-popups": (
        10, "Cross-Origin-Opener-Policy: same-origin-allow-popups.", ""),
    "coop-implemented-with-noopener-allow-popups": (
        10, "Cross-Origin-Opener-Policy: noopener-allow-popups.", ""),
    "coop-implemented-with-unsafe-none": (
        0, "Cross-Origin-Opener-Policy: unsafe-none.",
        "Use same-origin, same-origin-allow-popups or noopener-allow-popups."),
    "coop-not-implemented": (
        0, "No Cross-Origin-Opener-Policy.",
        "Use same-origin, same-origin-allow-popups or noopener-allow-popups."),
    "coop-header-invalid": (
        -5, "Cross-Origin-Opener-Policy cannot be recognised.",
        "Use same-origin, same-origin-allow-popups, noopener-allow-popups or "
        "unsafe-none."),
    # generic
    "html-not-parseable": (
        -20, "The response claims to be HTML but cannot be parsed.",
        "Return valid HTML."),
}


def grade_for(score: int) -> str:
    """The letter for a final score (negative scores read as 0)."""
    score = max(int(score), 0)
    return GRADE_CHART[min(score - (score % 5), 100)]


# --------------------------------------------------------------------------- #
#  Response helpers                                                            #
# --------------------------------------------------------------------------- #
def header_values(resp: dict | None, name: str) -> list[str]:
    """Every value of header ``name`` (case-insensitive), in order.

    A repeated header is ONE value joined with ``", "`` — what the HTTP client
    the Observatory uses hands its tests, and what makes a twice-sent HSTS
    header read as invalid there. ``Set-Cookie`` is never joined.
    """
    if not resp:
        return []
    want = name.lower()
    vals = [str(v) for k, v in (resp.get("headers") or []) if str(k).lower() == want]
    if not vals:
        return []
    if want == "set-cookie":
        return vals
    return [", ".join(vals)]


def first_header(resp: dict | None, name: str) -> str | None:
    vals = header_values(resp, name)
    return vals[0] if vals else None


HTML_TYPES = ("text/html", "application/xhtml+xml")


def _is_html(resp: dict | None) -> bool:
    ctype = (first_header(resp, "content-type") or "").split(";", 1)[0]
    return ctype in HTML_TYPES


class _Collect(HTMLParser):
    """Start tags of the wanted names, attributes lower-cased and decoded."""

    def __init__(self, tags):
        super().__init__(convert_charrefs=True)
        self.tags = set(tags)
        self.found: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.tags:
            self.found.append((tag, {k: (v if v is not None else "")
                                     for k, v in attrs}))

    handle_startendtag = handle_starttag


def collect_elements(html: str, tag: str) -> list[dict]:
    p = _Collect((tag,))
    p.feed(html or "")
    p.close()
    return [a for _t, a in p.found]


def http_equiv(resp: dict | None) -> dict[str, list[str]]:
    """``<meta http-equiv="Content-Security-Policy">`` and
    ``<meta name="referrer">`` of an HTML response — the two the Observatory
    reads from the page. Anything else in a meta tag does not count."""
    out: dict[str, list[str]] = {"content-security-policy": []}
    if not resp or not _is_html(resp) or not resp.get("body"):
        return out
    try:
        metas = collect_elements(resp.get("body") or "", "meta")
    except Exception:  # noqa: BLE001 — unparseable meta = none counted
        return out
    for m in metas:
        if "http-equiv" in m and "content" in m:
            if m["content"] and m["http-equiv"].lower().strip() == "content-security-policy":
                out["content-security-policy"].append(m["content"])
        elif (m.get("name") or "").lower().strip() == "referrer":
            if m.get("content"):
                out["referrer-policy"] = [m["content"]]
    return out


def _only_if_worse(new: str, old: str | None, order: list[str]) -> str:
    if not old:
        return new
    return new if order.index(new) > order.index(old) else old


_SF_TOKEN = re.compile(r"^[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*$")


def sf_token(value: str) -> str | None:
    """The bare token of an RFC 8941 item (``same-origin; report-to="x"`` →
    ``same-origin``), or ``None`` when the item is not a token (a quoted
    string, a number, garbage)."""
    bare = str(value or "").split(";", 1)[0].strip()
    return bare if _SF_TOKEN.match(bare) else None


#: Multi-label public suffixes SATOM recognises without the full PSL.
MULTI_LABEL_SUFFIXES = frozenset((
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    "com.br", "net.br", "org.br", "gov.br", "com.ar", "gob.ar", "com.co",
    "com.au", "net.au", "org.au", "gov.au", "co.nz", "co.jp", "ne.jp",
    "or.jp", "co.kr", "com.cn", "com.tw", "com.hk", "com.sg", "co.in",
    "co.za", "com.tr", "com.es", "co.il", "com.pe", "com.ve", "com.ec",
))


def registrable_domain(host: str) -> str:
    """``www.shop.example.co.uk`` → ``example.co.uk``; an IP stays itself."""
    host = str(host or "").strip().lower().rstrip(".")
    if not host or re.match(r"^[0-9.]+$", host) or ":" in host:
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_of(url: str) -> str:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(\[[^\]]+\]|[^/:?#]*)", url or "")
    return (m.group(1) if m else "").strip("[]").lower()


def _scheme_of(url: str) -> str:
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url or "")
    return (m.group(1).lower() + ":") if m else ""


# --------------------------------------------------------------------------- #
#  CSP parsing                                                                 #
# --------------------------------------------------------------------------- #
_SHORTEST_DIRECTIVE_LENGTH = len("img-src") - 1
_META_DISALLOWED = ("frame-ancestors", "report-uri", "sandbox")
_ALLOWED_DUPLICATES = ("report-uri", "report-to")
DUPLICATE_KEY = "_duplicate_directive_warnings"


class CspError(ValueError):
    pass


def _path_part_match(a: str, b: str) -> bool:
    from urllib.parse import unquote
    if len(a) == 0 or (a == "/" and len(b) == 0):
        return True
    exact = not a.endswith("/")
    la, lb = a.split("/"), b.split("/")
    if len(la) > len(lb) or (exact and len(la) != len(lb)):
        return False
    if not exact:
        la.pop()
    for i, pa in enumerate(la):
        if unquote(pa) != unquote(lb[i]):
            return False
    return True


def parse_csp(policies: list[str]) -> dict[str, set]:
    """One or more policies → ``{directive: {sources}}``.

    Several policies are combined the way a browser enforces them (each must
    allow a load), so a source survives only when every later policy
    re-allows it. Raises :class:`CspError` for a policy shorter than one
    directive or a directive repeated inside one policy (``report-uri`` and
    ``report-to`` are tolerated and flagged under :data:`DUPLICATE_KEY`).
    """
    clean = [re.sub(r"[\r\n]", "", p).strip() for p in policies]
    if not clean:
        return {}
    for p in clean:
        if not p or len(p) < _SHORTEST_DIRECTIVE_LENGTH:
            raise CspError("invalid policy: %r" % p)
    csp: dict[str, list[dict]] = {}
    dupes: set = set()
    for idx, policy in enumerate(clean):
        seen: set = set()
        for entry in policy.split(";"):
            parts = entry.strip().split()
            if not parts:
                continue
            directive, values_raw = parts[0].lower(), parts[1:]
            if directive in seen:
                if directive in _ALLOWED_DUPLICATES:
                    dupes.add(directive)
                else:
                    raise CspError("duplicate directive %s in policy %d"
                                   % (directive, idx))
            else:
                seen.add(directive)
            keep = idx == 0
            values = [{"source": v.strip().lower(), "index": idx, "keep": keep}
                      for v in values_raw]
            if not values_raw and directive.endswith("-src"):
                values = [{"source": "'none'", "index": idx, "keep": keep}]
            combined = list(values) if idx == 0 else list(csp.get(directive, [])) + values
            combined.sort(key=lambda s: s["source"])
            for i in range(1, len(combined)):
                cur, prev = combined[i], combined[i - 1]
                if cur["index"] == prev["index"] and cur["source"].startswith(prev["source"]):
                    cur["keep"] = False
                if cur["index"] != prev["index"] and _path_part_match(prev["source"], cur["source"]):
                    cur["keep"] = True
            csp[directive] = [s for s in combined if s["keep"]]
            if idx == 0 and len(policies) > 1:
                for s in csp[directive]:
                    s["keep"] = False
    out = {d: ({s["source"] for s in srcs} if srcs else {"'none'"})
           for d, srcs in csp.items()}
    if dupes:
        out[DUPLICATE_KEY] = dupes
    return out


def parse_csp_meta(policies: list[str]) -> dict[str, set]:
    out = parse_csp(policies)
    for d in _META_DISALLOWED:
        out.pop(d, None)
    return out


def _split_csp(values: list[str]) -> list[str]:
    return [s.strip() for v in values for s in v.split(",")]


_BROAD = frozenset(("ftp:", "http:", "https:", "*", "http://*", "http://*.*",
                    "https://*", "https://*.*"))
_UNSAFE_INLINE = frozenset(("'unsafe-inline'", "data:"))
_BROAD_AND_INLINE = _BROAD | _UNSAFE_INLINE
_PASSIVE = ("img-src", "media-src")
_NONCES_HASHES = ("'sha256-", "'sha384-", "'sha512-", "'nonce-")


def _has_nonce_or_hash(sources) -> bool:
    return any(s.startswith(p) for s in sources for p in _NONCES_HASHES)


# --------------------------------------------------------------------------- #
#  The twelve tests                                                            #
# --------------------------------------------------------------------------- #
def _out(name: str, result: str | None = None, **data) -> dict:
    return {"name": name, "result": result, "pass": False, "data": data}


def test_csp(req: dict) -> dict:
    out = _out("content-security-policy")
    resp = req.get("auto")
    url = req.get("auto_url") or ""
    if not resp or not url:
        out["result"] = "csp-not-implemented"
        return out
    http_pol = _split_csp(header_values(resp, "content-security-policy"))
    meta_pol = _split_csp(http_equiv(resp).get("content-security-policy") or [])
    out["data"]["policies"] = len(http_pol) + len(meta_pol)
    try:
        csp = parse_csp(http_pol + meta_pol)
    except CspError as exc:
        out["result"] = "csp-header-invalid"
        out["data"]["error"] = str(exc)
        return out
    try:
        header_only = parse_csp(http_pol)
    except CspError:
        header_only = {}
    try:
        meta_csp = parse_csp_meta(meta_pol)
    except CspError:
        meta_csp = {}
    if len(header_only) + len(meta_csp) == 0:
        out["result"] = ("csp-not-implemented-but-reporting-enabled"
                         if first_header(resp, "content-security-policy-report-only")
                         else "csp-not-implemented")
        return out
    out["data"]["http"] = bool(http_pol)
    out["data"]["meta"] = bool(meta_pol)
    policy: dict = {}

    def get(d):
        return csp.get(d)

    base_uri = get("base-uri") if get("base-uri") is not None else {"*"}
    frame_anc = header_only.get("frame-ancestors")
    frame_anc = frame_anc if frame_anc is not None else {"*"}
    form_action = get("form-action") if get("form-action") is not None else {"*"}

    def src(d):
        v = get(d)
        if v is None:
            v = get("default-src")
        return v if v is not None else {"*"}

    object_src, script_src, style_src = src("object-src"), src("script-src"), src("style-src")
    # The same set object may stand for several directives (all from
    # default-src); editing it edits all of them, exactly as the reference does.
    for sl in (script_src, style_src):
        if _has_nonce_or_hash(sl) and "'unsafe-inline'" in sl:
            sl.discard("'unsafe-inline'")
    result = None
    if _has_nonce_or_hash(script_src) and "'strict-dynamic'" in script_src:
        for s in list(script_src):
            if any(s.startswith(b) for b in _BROAD) or s in ("'self'", "'unsafe-inline'"):
                script_src.discard(s)
        policy["strict_dynamic"] = True
    elif "'strict-dynamic'" in script_src and result is None:
        result = "csp-header-invalid"
    active = [s for d, sl in csp.items() if d not in _PASSIVE and d != "script-src"
              for s in sl]
    active.extend(script_src)
    passive = []
    for d in _PASSIVE:
        v = get(d)
        if v is None:
            v = get("default-src") or set()
        passive.extend(v)
    https = url.lower().startswith("https:")
    if (script_src & _BROAD_AND_INLINE) or (object_src & _BROAD):
        result = result or "csp-implemented-with-unsafe-inline"
        policy["unsafe_inline"] = True
    if https and any(s.startswith("http:") or s.startswith("ftp:") for s in active):
        result = result or "csp-implemented-with-insecure-scheme"
        policy["insecure_scheme_active"] = True
    if "'unsafe-eval'" in (script_src | style_src):
        result = result or "csp-implemented-with-unsafe-eval"
        policy["unsafe_eval"] = True
    if https and any(s.startswith("http:") or s.startswith("ftp:") for s in passive):
        result = result or "csp-implemented-with-insecure-scheme-in-passive-content-only"
        policy["insecure_scheme_passive"] = True
    if style_src & _BROAD_AND_INLINE:
        result = result or "csp-implemented-with-unsafe-inline-in-style-src-only"
        policy["unsafe_inline_style"] = True
    dsrc = get("default-src")
    if dsrc is not None and "'none'" in dsrc and len(dsrc) == 1:
        result = result or "csp-implemented-with-no-unsafe-default-src-none"
        policy["default_none"] = True
    else:
        result = result or "csp-implemented-with-no-unsafe"
    policy["anti_clickjacking"] = not (frame_anc & _BROAD)
    policy["insecure_base_uri"] = bool(base_uri & _BROAD_AND_INLINE)
    policy["insecure_form_action"] = bool(form_action & _BROAD)
    policy["unsafe_objects"] = bool(object_src & _BROAD)
    out["result"] = result
    if result in ("csp-implemented-with-no-unsafe",
                  "csp-implemented-with-no-unsafe-default-src-none",
                  "csp-implemented-with-unsafe-inline-in-style-src-only",
                  "csp-implemented-with-insecure-scheme-in-passive-content-only"):
        out["pass"] = True
        if DUPLICATE_KEY in csp:
            out["result"] = "csp-implemented-but-duplicate-directives"
    out["data"]["policy"] = policy
    out["data"]["directives"] = {d: sorted(v) for d, v in csp.items()
                                 if d != DUPLICATE_KEY}
    return out


def test_hsts(req: dict) -> dict:
    out = _out("strict-transport-security", "hsts-not-implemented")
    resp = req.get("https")
    if not resp:
        out["result"] = "hsts-not-implemented-no-https"
    elif not resp.get("verified"):
        out["result"] = "hsts-invalid-cert"
        hdr = first_header(resp, "strict-transport-security")
        if hdr:
            # Not scored (an untrusted session makes the header inert), but
            # an operator who just enabled HSTS needs to see it arrived.
            out["data"]["header"] = hdr[:1024]
    elif first_header(resp, "strict-transport-security"):
        hdr = (first_header(resp, "strict-transport-security") or "")[:1024]
        out["data"]["header"] = hdr
        max_age = None
        try:
            if "," in hdr:
                raise ValueError("header set multiple times")
            for p in (x.strip().lower() for x in hdr.split(";")):
                if p.startswith("max-age="):
                    m = re.match(r"^\s*[+-]?\d+", p[8:128])
                    if not m:
                        raise ValueError("max-age is not a number")
                    max_age = int(m.group(0))
                elif p == "includesubdomains":
                    out["data"]["include_subdomains"] = True
                elif p == "preload":
                    out["data"]["preload"] = True
            if max_age is None:
                raise ValueError("max-age missing")
            out["data"]["max_age"] = max_age
            out["result"] = ("hsts-implemented-max-age-less-than-six-months"
                             if max_age < 15_552_000
                             else "hsts-implemented-max-age-at-least-six-months")
        except ValueError as exc:
            out["result"] = "hsts-header-invalid"
            out["data"]["error"] = str(exc)
    out["pass"] = out["result"] in ("hsts-implemented-max-age-at-least-six-months",
                                    "hsts-preloaded")
    return out


_COOKIE_ORDER = [
    "cookies-without-secure-flag-but-protected-by-hsts",
    "cookies-without-secure-flag",
    "cookies-session-without-secure-flag-but-protected-by-hsts",
    "cookies-samesite-flag-invalid",
    "cookies-anticsrf-without-samesite-flag",
    "cookies-session-without-httponly-flag",
    "cookies-session-without-secure-flag",
]


def _samesite_raw_invalid(c: dict) -> bool:
    v = c.get("samesite")
    if v is True:
        return True                      # ``SameSite`` with no value
    if not v:
        return False
    return str(v).strip().lower() not in ("lax", "strict", "none")


def is_session_cookie(name: str) -> bool:
    n = str(name or "").lower()
    return "login" in n or "sess" in n


def test_cookies(req: dict) -> dict:
    out = _out("cookies")
    hsts = test_hsts(req)["pass"]
    result = None
    auto = req.get("auto")
    for c in (auto or {}).get("set_cookie") or []:
        if isinstance(c, dict) and _samesite_raw_invalid(c):
            result = _only_if_worse("cookies-samesite-flag-invalid", result, _COOKIE_ORDER)
    cookies = [c for c in (req.get("cookies") or []) if isinstance(c, dict) and c.get("name")]
    if not cookies:
        out["result"] = "cookies-not-found"
        out["pass"] = True
        return out
    missing_samesite = False
    per_cookie = []
    for c in cookies:
        name = str(c.get("name"))
        secure = bool(c.get("secure"))
        same = c.get("samesite")
        same = same if isinstance(same, str) and same.strip() else ""
        session = is_session_cookie(name)
        anticsrf = "csrf" in name.lower()
        if not secure and same.lower() == "none":
            result = _only_if_worse("cookies-samesite-flag-invalid", result, _COOKIE_ORDER)
        if not secure and hsts:
            result = _only_if_worse("cookies-without-secure-flag-but-protected-by-hsts", result, _COOKIE_ORDER)
        elif not secure:
            result = _only_if_worse("cookies-without-secure-flag", result, _COOKIE_ORDER)
        if anticsrf and not same:
            result = _only_if_worse("cookies-anticsrf-without-samesite-flag", result, _COOKIE_ORDER)
        if session and not secure and hsts:
            result = _only_if_worse("cookies-session-without-secure-flag-but-protected-by-hsts", result, _COOKIE_ORDER)
        elif session and not secure:
            result = _only_if_worse("cookies-session-without-secure-flag", result, _COOKIE_ORDER)
        if session and not c.get("httponly"):
            result = _only_if_worse("cookies-session-without-httponly-flag", result, _COOKIE_ORDER)
        if not same:
            missing_samesite = True
        per_cookie.append({"name": name, "secure": secure,
                           "httponly": bool(c.get("httponly")),
                           "samesite": same, "session": session,
                           "path": c.get("path") or "", "domain": c.get("domain") or ""})
    if not result:
        result = ("cookies-secure-with-httponly-sessions" if missing_samesite
                  else "cookies-secure-with-httponly-sessions-and-samesite")
    out["result"] = result
    out["data"]["cookies"] = per_cookie
    out["pass"] = result in ("cookies-not-found",
                             "cookies-secure-with-httponly-sessions-and-samesite",
                             "cookies-secure-with-httponly-sessions")
    return out


def test_cors(req: dict) -> dict:
    out = _out("cross-origin-resource-sharing",
               "cross-origin-resource-sharing-not-implemented")
    resp = req.get("cors")
    acao = first_header(resp, "access-control-allow-origin")
    if resp and acao:
        val = acao[:256].strip().lower()
        out["data"]["allow_origin"] = val
        origin = req.get("cors_origin") or ""
        cred = (first_header(resp, "access-control-allow-credentials") or "").strip().lower()
        if val == "*":
            out["result"] = "cross-origin-resource-sharing-implemented-with-public-access"
        elif origin and acao == origin and cred == "true":
            out["result"] = "cross-origin-resource-sharing-implemented-with-universal-access"
        else:
            out["result"] = "cross-origin-resource-sharing-implemented-with-restricted-access"
    out["pass"] = out["result"] != "cross-origin-resource-sharing-implemented-with-universal-access"
    return out


def test_redirection(req: dict) -> dict:
    out = _out("redirection")
    resp = req.get("http")
    route = req.get("http_route") or []
    dest = (route[-1]["url"] if route else
            ((req.get("https_route") or [{}])[-1].get("url")))
    out["data"]["destination"] = dest or None
    out["data"]["status"] = resp.get("status") if resp else None
    if not resp:
        out["result"] = "redirection-not-needed-no-http"
    elif not resp.get("verified"):
        out["result"] = "redirection-invalid-cert"
    else:
        urls = [r["url"] for r in route]
        out["data"]["route"] = urls
        if len(urls) <= 1:
            out["result"] = "redirection-missing"
        elif _scheme_of(urls[-1]) != "https:":
            out["result"] = "redirection-not-to-https"
        elif _scheme_of(urls[1]) == "http:":
            out["result"] = "redirection-not-to-https-on-initial-redirection"
        elif (_scheme_of(urls[0]) == "http:" and _scheme_of(urls[1]) == "https:"
              and _host_of(urls[0]) != _host_of(urls[1])):
            out["result"] = "redirection-off-host-from-http"
        else:
            out["result"] = "redirection-to-https"
    out["pass"] = out["result"] in ("redirection-not-needed-no-http",
                                    "redirection-all-redirects-preloaded",
                                    "redirection-to-https")
    return out


_REF_GOOD = ("no-referrer", "same-origin", "strict-origin",
             "strict-origin-when-cross-origin")
_REF_BAD = ("origin", "origin-when-cross-origin", "unsafe-url",
            "no-referrer-when-downgrade")


def test_referrer(req: dict) -> dict:
    out = _out("referrer-policy")
    resp = req.get("auto")
    if not resp:
        out["result"] = "referrer-policy-not-implemented"
        return out
    http_vals = header_values(resp, "referrer-policy")
    meta_vals = http_equiv(resp).get("referrer-policy") or []
    out["data"]["http"] = bool(http_vals)
    out["data"]["meta"] = bool(meta_vals)
    if not (http_vals or meta_vals):
        out["result"] = "referrer-policy-not-implemented"
        out["pass"] = True
        return out
    data = ", ".join(http_vals + meta_vals)
    out["data"]["value"] = data
    valid = [e.strip().lower() for e in data.split(",")
             if e.strip().lower() in _REF_GOOD + _REF_BAD]
    policy = valid[-1] if valid else ""
    if policy in _REF_GOOD:
        out["result"] = "referrer-policy-private"
    elif policy in _REF_BAD:
        out["result"] = "referrer-policy-unsafe"
    else:
        out["result"] = "referrer-policy-header-invalid"
    out["pass"] = out["result"] in ("referrer-policy-private",
                                    "referrer-policy-not-implemented")
    return out


_SRI_ORDER = [
    "sri-implemented-and-all-scripts-loaded-securely",
    "sri-implemented-and-external-scripts-loaded-securely",
    "sri-implemented-but-external-scripts-not-loaded-securely",
    "sri-not-implemented-but-external-scripts-loaded-securely",
    "sri-not-implemented-and-external-scripts-not-loaded-securely",
    "sri-not-implemented-response-not-html",
]


def test_sri(req: dict) -> dict:
    out = _out("subresource-integrity")
    resp = req.get("auto")
    if not resp:
        out["result"] = "sri-not-implemented-but-no-scripts-loaded"
        return out
    mime = (first_header(resp, "content-type") or "").split(";", 1)[0]
    result = None
    scripts_data = {}
    if mime and mime not in HTML_TYPES:
        result = "sri-not-implemented-response-not-html"
    else:
        try:
            scripts = collect_elements(resp.get("body") or "", "script")
        except Exception:  # noqa: BLE001
            out["result"] = "html-not-parseable"
            return out
        site_domain = registrable_domain(req.get("host") or _host_of(req.get("auto_url") or ""))
        page_https = (req.get("auto_url") or "").lower().startswith("https:")
        foreign = False
        for s in scripts:
            src = s.get("src") or ""
            if not src:
                continue
            integrity = s.get("integrity") or None
            crossorigin = s.get("crossorigin") or None
            relative_origin = relative_protocol = False
            if re.match(r"^(//)[^/]", src):
                relative_protocol = True
                same_sld = True
            elif re.match(r"^https?://", src):
                same_sld = registrable_domain(_host_of(src)) == site_domain
            else:
                relative_origin = True
                same_sld = True
            secure_origin = relative_origin or (same_sld and not relative_protocol)
            if not secure_origin:
                foreign = True
            scheme = None if (relative_protocol or relative_origin) else _scheme_of(src)
            secure_scheme = scheme == "https:" or (relative_origin and page_https)
            if not secure_origin:
                scripts_data[src[:512]] = {"integrity": integrity, "crossorigin": crossorigin}
                if integrity and not secure_scheme:
                    result = _only_if_worse("sri-implemented-but-external-scripts-not-loaded-securely", result, _SRI_ORDER)
                elif not integrity and secure_scheme:
                    result = _only_if_worse("sri-not-implemented-but-external-scripts-loaded-securely", result, _SRI_ORDER)
                elif not integrity and not secure_scheme:
                    result = _only_if_worse("sri-not-implemented-and-external-scripts-not-loaded-securely", result, _SRI_ORDER)
            elif integrity and secure_scheme and not result:
                result = "sri-implemented-and-all-scripts-loaded-securely"
        if not scripts:
            result = "sri-not-implemented-but-no-scripts-loaded"
        elif not result:
            result = ("sri-implemented-and-external-scripts-loaded-securely" if foreign
                      else "sri-not-implemented-but-all-scripts-loaded-from-secure-origin")
    out["result"] = result
    out["data"]["external_scripts"] = scripts_data
    out["pass"] = result in (
        "sri-implemented-and-all-scripts-loaded-securely",
        "sri-implemented-and-external-scripts-loaded-securely",
        "sri-not-implemented-response-not-html",
        "sri-not-implemented-but-all-scripts-loaded-from-secure-origin",
        "sri-not-implemented-but-no-scripts-loaded")
    return out


def test_xcto(req: dict) -> dict:
    out = _out("x-content-type-options")
    resp = req.get("auto")
    hdr = first_header(resp, "x-content-type-options") if resp else None
    if hdr:
        out["data"]["value"] = hdr[:256]
        out["result"] = ("x-content-type-options-nosniff"
                         if hdr[:256].strip().lower() == "nosniff"
                         else "x-content-type-options-header-invalid")
    else:
        out["result"] = "x-content-type-options-not-implemented"
    out["pass"] = out["result"] == "x-content-type-options-nosniff"
    return out


def test_xfo(req: dict) -> dict:
    out = _out("x-frame-options")
    resp = req.get("auto")
    if not resp:
        out["result"] = "x-frame-options-not-implemented"
        return out
    hdr = first_header(resp, "x-frame-options")
    if hdr:
        v = hdr[:1024].strip().lower()
        out["data"]["value"] = hdr[:1024]
        if v in ("deny", "sameorigin"):
            out["result"] = "x-frame-options-sameorigin-or-deny"
        elif v.startswith("allow-from"):
            out["result"] = "x-frame-options-allow-from-origin"
        else:
            out["result"] = "x-frame-options-header-invalid"
    else:
        out["result"] = "x-frame-options-not-implemented"
    csp = test_csp(req)
    if "frame-ancestors" in (csp["data"].get("directives") or {}):
        out["result"] = "x-frame-options-implemented-via-csp"
    out["pass"] = out["result"] in ("x-frame-options-allow-from-origin",
                                    "x-frame-options-sameorigin-or-deny",
                                    "x-frame-options-implemented-via-csp")
    return out


def test_corp(req: dict) -> dict:
    out = _out("cross-origin-resource-policy", "corp-not-implemented")
    resp = req.get("auto")
    if resp:
        vals = header_values(resp, "cross-origin-resource-policy")
        if vals and vals[0]:
            v = vals[0][:256].strip().lower()
            out["data"]["value"] = v
            out["result"] = {"same-site": "corp-implemented-with-same-site",
                             "same-origin": "corp-implemented-with-same-origin",
                             "cross-origin": "corp-implemented-with-cross-origin",
                             }.get(v, "corp-header-invalid")
    out["pass"] = out["result"] != "corp-header-invalid"
    return out


def _coxp(req: dict, name: str, header: str, prefix: str, values: dict) -> dict:
    out = _out(name, prefix + "-not-implemented")
    resp = req.get("auto")
    if resp:
        raw = [str(v) for k, v in (resp.get("headers") or [])
               if str(k).lower() == header]
        if len(raw) > 1:
            out["result"] = prefix + "-header-invalid"
        elif raw:
            v = raw[0][:1024].strip()
            out["data"]["value"] = v
            out["result"] = values.get(sf_token(v) or "", prefix + "-header-invalid")
    out["pass"] = out["result"] != prefix + "-header-invalid"
    return out


def test_coop(req: dict) -> dict:
    return _coxp(req, "cross-origin-opener-policy", "cross-origin-opener-policy",
                 "coop", {
                     "same-origin": "coop-implemented-with-same-origin",
                     "same-origin-allow-popups": "coop-implemented-with-same-origin-allow-popups",
                     "noopener-allow-popups": "coop-implemented-with-noopener-allow-popups",
                     "unsafe-none": "coop-implemented-with-unsafe-none"})


def test_coep(req: dict) -> dict:
    return _coxp(req, "cross-origin-embedder-policy", "cross-origin-embedder-policy",
                 "coep", {
                     "require-corp": "coep-implemented-with-require-corp",
                     "credentialless": "coep-implemented-with-credentialless",
                     "unsafe-none": "coep-implemented-with-unsafe-none"})


ALL_TESTS = {
    "content-security-policy": test_csp,
    "cookies": test_cookies,
    "cross-origin-embedder-policy": test_coep,
    "cross-origin-opener-policy": test_coop,
    "cross-origin-resource-sharing": test_cors,
    "redirection": test_redirection,
    "referrer-policy": test_referrer,
    "strict-transport-security": test_hsts,
    "subresource-integrity": test_sri,
    "x-content-type-options": test_xcto,
    "x-frame-options": test_xfo,
    "cross-origin-resource-policy": test_corp,
}


class SiteDown(Exception):
    """Nothing answered, or the answer is not one the Observatory grades."""


def analyze(req: dict) -> dict:
    """Score one fetched site.

    ``req`` describes what was fetched (built by
    :func:`app.services.observatory_scan.retrieve`)::

        host        the site name the requests carried (Host / SNI)
        https       final response of the HTTPS chain, or None
        http        final response of the plain-HTTP chain, or None
        http_route  [{url, status}] — every hop of the HTTP chain, first included
        https_route the same for HTTPS
        auto        the response the header tests read (HTTPS when it answered)
        auto_url    its URL
        cors        response to an OPTIONS preflight with ``cors_origin``
        cookies     every Set-Cookie seen in the ``auto`` session, as shapes
                    (``txn_trace._cookie_shape``: flags only, never values)

    A response is ``{status, headers: [[k, v]], verified, set_cookie, body}``.
    Raises :class:`SiteDown` like the Observatory does: no answer at all, or a
    status other than 2xx, 3xx, 401 and 403.
    """
    auto = req.get("auto")
    if not auto or auto.get("status") is None:
        raise SiteDown("the site did not answer")
    status = int(auto["status"])
    if status < 200 or (status >= 400 and status not in (401, 403)):
        raise SiteDown("HTTP %d is not graded (only 2xx, 3xx, 401 and 403 are)" % status)
    results = []
    with_extra = uncurved = 100
    passed = 0
    for name, _title in TESTS:
        r = ALL_TESTS[name](req)
        mod, desc, rec = SCORE_TABLE.get(r["result"], (0, "", ""))
        r.update(title=TEST_TITLES[name], modifier=mod, description=desc,
                 recommendation=rec, link=TOPIC_LINKS.get(name, ""))
        passed += 1 if r["pass"] else 0
        with_extra += mod
        if mod < 0:
            uncurved += mod
        results.append(r)
    score = with_extra if uncurved >= MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved
    score = max(score, 0)
    return {"algorithm_version": ALGORITHM_VERSION, "score": score,
            "grade": grade_for(score), "status_code": status,
            "tests_passed": passed, "tests_failed": len(TESTS) - passed,
            "tests_quantity": len(TESTS), "tests": results,
            "bonus_withheld": uncurved < MINIMUM_SCORE_FOR_EXTRA_CREDIT
            and with_extra != uncurved}
