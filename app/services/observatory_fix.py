# app/services/observatory_fix.py
"""Who is responsible for each Observatory finding, and the FortiWeb setting
that fixes it.

A grade alone sends the operator to a search engine. SATOM holds the
configuration of the appliance in front of the site, so for every test it can
say WHO produced what was seen and WHAT to change:

* ``fortiweb``     — the appliance sets (or is configured to set) it;
* ``application``  — the backend sent it, the appliance passed it through;
* ``certificate``  — the score is lost to an untrusted certificate, not to a
  header (Cert Manager is the place to fix it);
* ``missing``      — nobody sends it; either side can, the appliance in one
  write.

Every fix below was MEASURED on fortiweb18 (8.0.6) with real traffic before it
was written down (2026-10-16): the field names, the values the device accepts
and the header the client then receives. Two behaviours the plans rely on:

* a header the HTTP Header Security profile adds **replaces** the one the
  backend sent (backend ``X-Frame-Options: DENY`` + profile ``SAMEORIGIN`` →
  the client sees only ``SAMEORIGIN``), so a fix never produces a duplicate;
* ``internal-cookie-secure`` marks the appliance's own ``cookiesession1``
  Secure only on HTTPS responses, and a Cookie Security profile with
  ``security-mode no`` adds Secure/HttpOnly/SameSite to the BACKEND's cookies
  without signing or encrypting them.

Which header names and values a profile row accepts is per build, read from
the API library (``waf/http-header-security/http-header-security-list``): the
Cross-Origin-* headers exist on 8.0.6 and not on 7.6.8, and a fix the build
cannot carry is offered as unavailable with that reason — never sent to fail.

Writes go through :class:`app.services.fortiweb_ops.FortiWebOps` (dry-run
first, ChangeHistory, audit, re-read verification) behind the same gates as
the object editor: a template-managed Web Protection Profile is refused, an
edit lease held by someone else is refused, and a profile or WPP shared with
other server policies needs an explicit acknowledgement naming them.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import quote

from . import header_observatory as ho

POLICY_EP = "/api/v2.0/cmdb/server-policy/policy"
WPP_EP = "/api/v2.0/cmdb/waf/web-protection-profile.inline-protection"
HHS_EP = "/api/v2.0/cmdb/waf/http-header-security"
HHS_ROWS_EP = HHS_EP + "/http-header-security-list"
CKS_EP = "/api/v2.0/cmdb/waf/cookie-security"

#: The appliance's own session cookie (measured, 7.6.8 and 8.0.6).
FORTIWEB_COOKIE = "cookiesession1"
#: Recommended HSTS lifetime (one year: preload-eligible). The Observatory
#: passes anything from 15552000 (six months).
HSTS_MAX_AGE = 31_536_000
HSTS_MIN_PASS = 15_552_000

#: A starting policy an operator can deploy and then tighten: everything from
#: the site itself, no plugins, no framing by others, forms only to itself.
#: Scores ``csp-implemented-with-no-unsafe`` (+5) and frame-ancestors (+5).
CSP_STARTER = ("default-src 'self'; object-src 'none'; base-uri 'self'; "
               "frame-ancestors 'self'; form-action 'self'")

#: Header row specs: test → (row name, value field, default value, values
#: that make the test pass, risk note).
HEADER_ROWS = {
    "x-frame-options": ("x-frame-options", "value", "sameorigin",
                        ("sameorigin", "deny"), ""),
    "x-content-type-options": ("x-content-type-options", "value", "nosniff",
                               ("nosniff",), ""),
    "referrer-policy": ("referrer-policy", "referrer-policy-value",
                        "strict-origin-when-cross-origin",
                        ("no-referrer", "same-origin", "strict-origin",
                         "strict-origin-when-cross-origin"), ""),
    "content-security-policy": (
        "content-security-policy", "custom-value", CSP_STARTER, (),
        "A Content Security Policy blocks every script, style, image or "
        "frame source it does not list. Deploy it on a test policy first or "
        "review the browser console after applying."),
    "cross-origin-resource-policy": (
        "cross-origin-resource-policy", "value", "same-site",
        ("same-site", "same-origin", "cross-origin"),
        "Other sites can no longer embed this site's resources (images, "
        "scripts) unless they share its registrable domain."),
    "cross-origin-opener-policy": (
        "cross-origin-opener-policy", "value", "same-origin",
        ("same-origin", "same-origin-allow-popups"),
        "Pop-ups opened to other origins (OAuth, payment windows) lose "
        "window.opener; use same-origin-allow-popups if the site relies on it."),
    "cross-origin-embedder-policy": (
        "cross-origin-embedder-policy", "value", "credentialless",
        ("require-corp", "credentialless"),
        "Cross-origin resources load without cookies (credentialless) or must "
        "opt in with CORP (require-corp); third-party widgets can break."),
}
#: What a 7.x profile row is known to accept when the build was never
#: measured: the names in every FortiWeb spec SATOM ships.
BASE_ROW_NAMES = ("x-frame-options", "x-content-type-options",
                  "content-security-policy", "referrer-policy")


class FixRefused(ValueError):
    """A fix that will not be planned or applied, with the reason."""


# --------------------------------------------------------------------------- #
#  Context: what the appliance has configured for one policy                  #
# --------------------------------------------------------------------------- #
def _refs(obj: dict, kind: str) -> list[str]:
    """Names in a FortiWeb ``q_ref_string`` of one kind
    (``inline-protection(a)\\npolicy(b)`` → ``['a']`` for inline-protection)."""
    out = []
    for m in re.finditer(r"([\w.-]+)\(([^)]*)\)", str((obj or {}).get("q_ref_string") or "")):
        if m.group(1) == kind and m.group(2) not in out:
            out.append(m.group(2))
    return out


ROWS_ENDPOINT = "waf/http-header-security/http-header-security-list"


def _row_options(version: str) -> dict:
    """``{"names", "values", "referrer", "measured"}`` — what a profile row
    accepts on one FortiWeb build, from the API library. An unmeasured build
    falls back to :data:`BASE_ROW_NAMES` and to the values the tests need."""
    try:
        from . import api_library

        def opts(field):
            return api_library.field_options_at("fortiweb", ROWS_ENDPOINT, version or "", field) or []

        names, values, referrer = opts("name"), opts("value"), opts("referrer-policy-value")
    except Exception:  # noqa: BLE001 — no library: unmeasured
        names, values, referrer = [], [], []
    return {"measured": bool(names), "names": names or list(BASE_ROW_NAMES),
            "values": values, "referrer": referrer}


def read_context(appliance, policy: str) -> dict:
    """Everything the attribution and the plans read, in one pass over the
    device (a handful of REST reads). Raises on a device that cannot be read:
    a fix planned against a guessed configuration is worse than none."""
    from ..clients import client_for
    client = client_for(appliance)
    q = lambda v: quote(v, safe="")  # noqa: E731
    pol = client.get_server_policy(policy)
    if not pol:
        raise FixRefused("server policy %r was not found on %s" % (policy, appliance.name))
    wpp_name = str(pol.get("web-protection-profile") or "")
    wpp = client._safe_one("%s?mkey=%s" % (WPP_EP, q(wpp_name))) if wpp_name else {}
    hhs_name = str((wpp or {}).get("http-header-security") or "")
    hhs = client._safe_one("%s?mkey=%s" % (HHS_EP, q(hhs_name))) if hhs_name else {}
    rows = client._safe_list("%s?mkey=%s" % (HHS_ROWS_EP, q(hhs_name))) if hhs_name else []
    cks_name = str((wpp or {}).get("cookie-security-policy") or "")
    cks = client._safe_one("%s?mkey=%s" % (CKS_EP, q(cks_name))) if cks_name else {}
    try:
        from .templates import managed_wpp_names
        managed = wpp_name in managed_wpp_names(appliance.id)
    except Exception:  # noqa: BLE001
        managed = False
    version = str(getattr(client, "fw_version", "") or "")
    wpp_policies = _refs(wpp, "policy") if wpp_name else []
    if wpp_name and policy not in wpp_policies:
        wpp_policies = [policy] + wpp_policies
    return {"appliance_id": appliance.id, "appliance": appliance.name,
            "product": appliance.kind, "policy": policy, "version": version,
            "policy_obj": pol, "wpp": wpp_name, "wpp_obj": wpp or {},
            "wpp_managed": managed, "wpp_policies": wpp_policies,
            "hhs": hhs_name, "hhs_obj": hhs or {}, "hhs_rows": rows or [],
            "hhs_wpps": _refs(hhs, "inline-protection") if hhs_name else [],
            "cks": cks_name, "cks_obj": cks or {},
            "cks_wpps": _refs(cks, "inline-protection") if cks_name else [],
            "rows": _row_options(version)}


def _on(v) -> bool:
    return str(v or "").strip().lower() in ("enable", "enabled", "on", "1", "true")


def _row_filtered(row: dict) -> list[str]:
    """Why a profile row does not apply to every response (empty = always)."""
    why = []
    if _on(row.get("request-status")):
        why.append("URL filter %s" % (row.get("request-file") or "?"))
    if _on(row.get("client-ip-filter-status")):
        why.append("client IP filter %s" % (row.get("client-ip") or "?"))
    if _on(row.get("header-filter-status")):
        why.append("request header filter %s" % (row.get("header-filter-name") or "?"))
    if row.get("exception"):
        why.append("exception %s" % row.get("exception"))
    return why


def _rows_named(ctx: dict, name: str) -> list[dict]:
    return [r for r in ctx.get("hhs_rows") or [] if str(r.get("name") or "").lower() == name]


# --------------------------------------------------------------------------- #
#  Findings                                                                    #
# --------------------------------------------------------------------------- #
def _test(analysis: dict, name: str) -> dict:
    for t in (analysis or {}).get("tests") or []:
        if t.get("name") == name:
            return t
    return {}


def _header_present(retrieval: dict, header: str) -> bool:
    return bool(ho.first_header((retrieval or {}).get("auto"), header))


def _unavailable(fix_id, label, why):
    return {"id": fix_id, "label": label, "available": False, "why_not": why}


def _header_fix(ctx: dict, test: str, wanted: bool) -> dict | None:
    """The profile-row fix for one header test, or None when nothing to do."""
    if not wanted:
        return None
    row_name, field, default, _passing, risk = HEADER_ROWS[test]
    label = "Set %s on the FortiWeb" % ho.TEST_TITLES.get(test, row_name)
    fix_id = "header:" + row_name
    if ctx.get("product") != "fortiweb":
        return _unavailable(fix_id, label, "SATOM applies header fixes on FortiWeb only.")
    if row_name not in ctx["rows"]["names"]:
        return _unavailable(fix_id, label, (
            "FortiWeb %s cannot add this header from HTTP Header Security "
            "(the build's profile rows accept: %s). Set it on the application."
            % (ctx.get("version") or "?", ", ".join(ctx["rows"]["names"]))))
    if not ctx.get("wpp"):
        return _unavailable(fix_id, label, (
            "Server policy %s has no Web Protection Profile; HTTP Header Security "
            "is part of one. Attach a profile to the policy first." % ctx["policy"]))
    if ctx.get("wpp_managed"):
        return _unavailable(fix_id, label, (
            "Web Protection Profile %s is template-managed: change it in "
            "Administrator → Template Library." % ctx["wpp"]))
    rows = _rows_named(ctx, row_name)
    filtered = [r for r in rows if _row_filtered(r)]
    if rows and len(filtered) == len(rows):
        return _unavailable(fix_id, label, (
            "Profile %s already has a %s row, limited by %s, so this response "
            "does not get it. Widen or remove that limit in the profile."
            % (ctx["hhs"], row_name, "; ".join(_row_filtered(filtered[0])))))
    values = None
    if field == "value":
        known = ctx["rows"]["values"] or None
        values = [v for v in HEADER_ROWS[test][3] if known is None or v in known] or [default]
    elif field == "referrer-policy-value":
        known = ctx["rows"]["referrer"] or None
        values = [v for v in HEADER_ROWS[test][3] if known is None or v in known] or [default]
    if values and default not in values:
        default = values[0]
    return {"id": fix_id, "label": label, "available": True, "risk": risk,
            "option": {"field": field, "default": default, "choices": values},
            "update_row": next((str(r.get("id")) for r in rows if not _row_filtered(r)), "")}


def findings(analysis: dict, retrieval: dict, ctx: dict | None,
             target: dict | None = None) -> list[dict]:
    """One entry per test: who produced the result, why, and the fixes.

    ``ctx`` is :func:`read_context` (None = the device could not be read: the
    findings still say what is missing, every fix is unavailable)."""
    out = []
    pol = (ctx or {}).get("policy_obj") or {}
    target = target or {}
    https_port = target.get("https_port")
    http_port = target.get("http_port")
    for t in (analysis or {}).get("tests") or []:
        name, result = t["name"], t["result"]
        f = {"test": name, "title": t.get("title"), "result": result,
             "modifier": t.get("modifier"), "pass": t.get("pass"),
             "who": "none", "explain": "", "fixes": []}
        if ctx is None:
            f["explain"] = "The appliance configuration could not be read."
        elif name in HEADER_ROWS:
            header = HEADER_ROWS[name][0]
            rows = _rows_named(ctx, header)
            live = [r for r in rows if not _row_filtered(r)]
            present = _header_present(retrieval, header)
            if name == "x-frame-options" and result == "x-frame-options-implemented-via-csp":
                present = True
            if live:
                f["who"] = "fortiweb"
                f["explain"] = ("Set by FortiWeb: HTTP Header Security profile %s (row %s) "
                                "on Web Protection Profile %s. It replaces whatever the "
                                "application sends." % (ctx["hhs"], live[0].get("id"), ctx["wpp"]))
            elif present:
                f["who"] = "application"
                f["explain"] = "Sent by the application; FortiWeb passes it through."
            else:
                f["who"] = "missing"
                f["explain"] = "Neither the application nor FortiWeb sends it."
            wants = (not t.get("pass")) or (t.get("modifier", 0) <= 0 and name in (
                "referrer-policy", "cross-origin-resource-policy",
                "cross-origin-opener-policy", "cross-origin-embedder-policy")
                and result.endswith(("not-implemented", "unsafe-none", "cross-origin")))
            if name == "content-security-policy":
                wants = result in ("csp-not-implemented", "csp-not-implemented-but-reporting-enabled",
                                   "csp-header-invalid") or (f["who"] == "fortiweb" and not t.get("pass"))
            if name == "x-frame-options":
                wants = not t.get("pass")
            fx = _header_fix(ctx, name, wants)
            if fx:
                f["fixes"].append(fx)
        elif name == "strict-transport-security":
            on = _on(pol.get("hsts-header"))
            if result == "hsts-invalid-cert":
                f["who"] = "certificate"
                tls = (retrieval or {}).get("tls") or {}
                f["explain"] = ("The certificate is not trusted (%s), so browsers ignore "
                                "HSTS. Replace it in Cert Manager." % (tls.get("verify_error") or "untrusted"))
            elif result == "hsts-not-implemented-no-https":
                f["who"] = "fortiweb"
                f["explain"] = ("Server policy %s has no HTTPS service, so there is no "
                                "HTTPS response to carry HSTS." % ctx["policy"])
            elif on:
                f["who"] = "fortiweb"
                f["explain"] = "Added by FortiWeb (server policy %s, HSTS max-age %s)." % (
                    ctx["policy"], pol.get("hsts-max-age"))
            elif _header_present(retrieval, "strict-transport-security"):
                f["who"] = "application"
                f["explain"] = "Sent by the application."
            else:
                f["who"] = "missing"
                f["explain"] = "Nobody sends Strict-Transport-Security."
            needs = (result in ("hsts-not-implemented", "hsts-header-invalid",
                                "hsts-implemented-max-age-less-than-six-months")
                     or (result == "hsts-invalid-cert" and not t.get("data", {}).get("header")))
            if needs:
                if ctx.get("product") != "fortiweb":
                    f["fixes"].append(_unavailable("hsts", "Enable HSTS on the FortiWeb",
                                                   "SATOM applies this fix on FortiWeb only."))
                elif not https_port:
                    f["fixes"].append(_unavailable("hsts", "Enable HSTS on the FortiWeb",
                                                   "The policy has no HTTPS service."))
                else:
                    cur = int(pol.get("hsts-max-age") or 0)
                    f["fixes"].append({"id": "hsts", "label": "Enable HSTS on server policy %s" % ctx["policy"],
                                       "available": True,
                                       "risk": ("Browsers will refuse plain HTTP to this name for "
                                                "max-age seconds; with includeSubDomains, to every "
                                                "subdomain too."),
                                       "option": {"max_age": cur if cur >= HSTS_MIN_PASS else HSTS_MAX_AGE,
                                                  "include_subdomains": _on(pol.get("hsts-include-subdomains")),
                                                  "preload": _on(pol.get("hsts-preload"))}})
            if result == "hsts-invalid-cert":
                f["fixes"].append({"id": "certificate", "label": "Replace the certificate (Cert Manager)",
                                   "available": True, "link": "/cert-manager/"})
        elif name == "redirection":
            on = _on(pol.get("http-to-https"))
            if result == "redirection-invalid-cert":
                f["who"] = "certificate"
                f["explain"] = "The redirect lands on HTTPS with an untrusted certificate."
                f["fixes"].append({"id": "certificate", "label": "Replace the certificate (Cert Manager)",
                                   "available": True, "link": "/cert-manager/"})
            elif on:
                f["who"] = "fortiweb"
                f["explain"] = "FortiWeb redirects HTTP to HTTPS (server policy %s)." % ctx["policy"]
            elif result == "redirection-missing":
                f["who"] = "missing"
                f["explain"] = "Plain HTTP is served as is."
            elif result != "redirection-not-needed-no-http":
                f["who"] = "application"
                f["explain"] = "The redirects come from the application."
            if result in ("redirection-missing", "redirection-not-to-https",
                          "redirection-not-to-https-on-initial-redirection"):
                if ctx.get("product") != "fortiweb":
                    f["fixes"].append(_unavailable("redirect", "Redirect HTTP to HTTPS on the FortiWeb",
                                                   "SATOM applies this fix on FortiWeb only."))
                elif not (http_port and https_port):
                    f["fixes"].append(_unavailable("redirect", "Redirect HTTP to HTTPS on the FortiWeb",
                                                   "The policy needs both an HTTP and an HTTPS service."))
                else:
                    f["fixes"].append({"id": "redirect", "available": True,
                                       "label": "Redirect HTTP to HTTPS on server policy %s" % ctx["policy"],
                                       "risk": "Clients of plain HTTP get a 301 to the HTTPS service port."})
            if result == "redirection-off-host-from-http" and _on(pol.get("redirect-naked-domain")):
                f["explain"] += (" Server policy %s has redirect-naked-domain on, which "
                                 "sends the apex to www." % ctx["policy"])
        elif name == "cookies":
            cookies = (t.get("data") or {}).get("cookies") or []
            own = [c for c in cookies if c.get("name") == FORTIWEB_COOKIE]
            app_c = [c for c in cookies if c.get("name") != FORTIWEB_COOKIE]
            bad_own = [c for c in own if not (c.get("secure") and c.get("httponly") and c.get("samesite"))]
            bad_app = [c for c in app_c if not (c.get("secure") and c.get("samesite")
                                                and (c.get("httponly") or not c.get("session")))]
            parts = []
            if own:
                parts.append("%s is FortiWeb's own session cookie (server policy %s)."
                             % (FORTIWEB_COOKIE, ctx["policy"]))
            if app_c:
                parts.append("%s set by the application%s." % (
                    ", ".join(c["name"] for c in app_c),
                    (" — FortiWeb Cookie Security profile %s rewrites their flags" % ctx["cks"])
                    if ctx.get("cks") else ""))
            f["explain"] = " ".join(parts) or "No cookies."
            f["who"] = ("fortiweb" if own and not app_c else
                        "application" if app_c else "none")
            if bad_own and ctx.get("product") == "fortiweb":
                f["fixes"].append({"id": "internal-cookie", "available": True,
                                   "label": "Harden FortiWeb's own cookie (server policy %s)" % ctx["policy"],
                                   "risk": "None for the application: it never reads this cookie."})
            if bad_app:
                fx_label = "Add Secure/HttpOnly/SameSite to the application's cookies on the FortiWeb"
                if ctx.get("product") != "fortiweb":
                    f["fixes"].append(_unavailable("cookie-security", fx_label,
                                                   "SATOM applies this fix on FortiWeb only."))
                elif not ctx.get("wpp"):
                    f["fixes"].append(_unavailable("cookie-security", fx_label, (
                        "Server policy %s has no Web Protection Profile; Cookie Security "
                        "is part of one." % ctx["policy"])))
                elif ctx.get("wpp_managed"):
                    f["fixes"].append(_unavailable("cookie-security", fx_label, (
                        "Web Protection Profile %s is template-managed." % ctx["wpp"])))
                else:
                    need_http_only = any(c.get("session") and not c.get("httponly") for c in bad_app)
                    f["fixes"].append({
                        "id": "cookie-security", "available": True, "label": fx_label,
                        "risk": ("HttpOnly hides a cookie from the page's JavaScript; leave it "
                                 "off if the application reads a cookie in the browser (a "
                                 "CSRF token, for example)."),
                        "option": {"secure": True, "http_only": need_http_only,
                                   "samesite": "Lax"}})
        elif name == "subresource-integrity":
            f["who"] = "application" if not t.get("pass") or result.startswith("sri-implemented") else "none"
            f["explain"] = ("Script tags are page content: add integrity attributes in the "
                            "application. FortiWeb's Client-Side Security can also watch "
                            "third-party scripts, which does not change this test.")
        elif name == "cross-origin-resource-sharing":
            f["who"] = "application" if result != "cross-origin-resource-sharing-not-implemented" else "none"
            f["explain"] = ("CORS answers come from the application." if f["who"] == "application"
                            else "Content is not exposed through CORS.")
        out.append(f)
    return out


# --------------------------------------------------------------------------- #
#  Projection: the grade a fix would give                                     #
# --------------------------------------------------------------------------- #
_RECOMPUTE = ("content-security-policy", "x-frame-options", "x-content-type-options",
              "referrer-policy", "cross-origin-resource-policy",
              "cross-origin-opener-policy", "cross-origin-embedder-policy",
              "strict-transport-security", "cookies", "redirection")


def _set_header(resp: dict, name: str, value: str) -> None:
    hs = [h for h in resp.get("headers") or [] if str(h[0]).lower() != name.lower()]
    hs.append([name, value])
    resp["headers"] = hs


def project(analysis: dict, retrieval: dict, effects: dict) -> dict:
    """Score again with *effects* applied to what was fetched.

    ``effects``: ``headers`` {name: value} (FortiWeb replaces the backend's),
    ``hsts`` header value, ``redirect`` (bool), ``cookies`` {secure, httponly,
    samesite} applied to the application's cookies, ``own_cookie`` (bool) and
    ``trust_certificate`` (bool). Tests that read the page body (SRI) or a
    second request (CORS) keep their measured result.
    """
    req = copy.deepcopy({k: v for k, v in (retrieval or {}).items()})
    for k in ("https", "http", "auto", "cors"):
        if req.get(k):
            req[k].setdefault("body", "")
    auto = req.get("auto")
    https = req.get("https")
    if not auto:
        return {}
    for n, v in (effects.get("headers") or {}).items():
        _set_header(auto, n, v)
    if effects.get("hsts") and https:
        _set_header(https, "Strict-Transport-Security", effects["hsts"])
        if auto is not https and req.get("auto_url", "").startswith("https:"):
            _set_header(auto, "Strict-Transport-Security", effects["hsts"])
    if effects.get("trust_certificate"):
        for k in ("https", "http", "auto"):
            if req.get(k):
                req[k]["verified"] = True
    if effects.get("redirect") and req.get("https_route"):
        dest = req["https_route"][0]["url"]
        start = (req.get("http_route") or [{"url": dest.replace("https:", "http:", 1)}])[0]["url"]
        req["http_route"] = [{"url": start, "status": 301}, {"url": dest, "status": 200}]
        if https:
            req["http"] = copy.deepcopy(https)
    ck = effects.get("cookies")
    if ck or effects.get("own_cookie"):
        for c in req.get("cookies") or []:
            own = c.get("name") == FORTIWEB_COOKIE
            if own and effects.get("own_cookie"):
                c.update(secure=True, httponly=True, samesite=c.get("samesite") or "Lax")
            elif not own and ck:
                if ck.get("secure"):
                    c["secure"] = True
                if ck.get("httponly"):
                    c["httponly"] = True
                if ck.get("samesite"):
                    c["samesite"] = ck["samesite"]
    recomputed = {}
    for name in _RECOMPUTE:
        r = ho.ALL_TESTS[name](req)
        r["modifier"] = ho.SCORE_TABLE.get(r["result"], (0, "", ""))[0]
        recomputed[name] = r
    with_extra = uncurved = 100
    tests = []
    for t in (analysis or {}).get("tests") or []:
        r = recomputed.get(t["name"]) or t
        mod = r.get("modifier", 0)
        with_extra += mod
        if mod < 0:
            uncurved += mod
        tests.append({"name": t["name"], "result": r["result"], "modifier": mod,
                      "changed": r["result"] != t["result"]})
    score = max(with_extra if uncurved >= ho.MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved, 0)
    return {"score": score, "grade": ho.grade_for(score), "tests": tests}


def effects_of(fix_id: str, options: dict, ctx: dict) -> dict:
    """What a fix changes in the response, for :func:`project`."""
    options = options or {}
    if fix_id.startswith("header:"):
        name = fix_id.split(":", 1)[1]
        test = next(k for k, v in HEADER_ROWS.items() if v[0] == name)
        _row, _field, default, _p, _r = HEADER_ROWS[test]
        value = str(options.get("value") or default)
        shown = value.upper() if name == "x-frame-options" else value
        return {"headers": {name: shown}}
    if fix_id == "hsts":
        v = "max-age=%d" % int(options.get("max_age") or HSTS_MAX_AGE)
        if options.get("include_subdomains"):
            v += "; includeSubDomains"
        if options.get("preload"):
            v += "; preload"
        return {"hsts": v}
    if fix_id == "redirect":
        return {"redirect": True}
    if fix_id == "internal-cookie":
        return {"own_cookie": True}
    if fix_id == "cookie-security":
        return {"cookies": {"secure": bool(options.get("secure", True)),
                            "httponly": bool(options.get("http_only")),
                            "samesite": options.get("samesite") or ""}}
    if fix_id == "certificate":
        return {"trust_certificate": True}
    return {}


# --------------------------------------------------------------------------- #
#  Plans                                                                       #
# --------------------------------------------------------------------------- #
def _write(action, endpoint, mkey, data, describe, sub_mkey=None):
    return {"action": action, "endpoint": endpoint, "mkey": mkey,
            "sub_mkey": sub_mkey, "data": {"data": data}, "describe": describe}


def _free_name(existing: set, base: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]", "-", base)[:30].strip("-") or "satom"
    name, n = base, 2
    while name in existing:
        name = "%s-%d" % (base[:27], n)
        n += 1
    return name


def _existing_names(appliance, endpoint) -> set:
    from ..clients import client_for
    try:
        return {str(r.get("name") or "") for r in client_for(appliance)._safe_list(endpoint)}
    except Exception:  # noqa: BLE001
        return set()


def _validate_csp(value: str) -> None:
    v = (value or "").strip()
    if not v:
        raise FixRefused("the Content Security Policy is empty")
    if any(ch in v for ch in "\r\n\"") or len(v) > 1024:
        raise FixRefused("the Content Security Policy must be one line, without "
                         "double quotes, at most 1024 characters")
    try:
        ho.parse_csp([s.strip() for s in v.split(",")])
    except ho.CspError as exc:
        raise FixRefused("the Content Security Policy does not parse: %s" % exc) from None


def plan(appliance, policy: str, fix_id: str, options: dict | None, ctx: dict) -> dict:
    """The writes one fix needs, and who else they affect. Pure apart from a
    name-collision read when it creates a profile."""
    options = dict(options or {})
    if appliance.kind != "fortiweb":
        raise FixRefused("SATOM applies Observatory fixes on FortiWeb only.")
    writes: list[dict] = []
    affected = [policy]
    objects: list[str] = []
    risk = ""
    if fix_id == "hsts":
        max_age = int(options.get("max_age") or HSTS_MAX_AGE)
        if max_age < 1 or max_age > 999_999_999:
            raise FixRefused("max-age must be between 1 and 999999999 seconds")
        data = {"hsts-header": "enable", "hsts-max-age": max_age,
                "hsts-include-subdomains": "enable" if options.get("include_subdomains") else "disable",
                "hsts-preload": "enable" if options.get("preload") else "disable"}
        writes.append(_write("update", POLICY_EP, policy, data,
                             "server policy %s: HSTS on, max-age %d" % (policy, max_age)))
        objects.append("server policy %s" % policy)
    elif fix_id == "redirect":
        writes.append(_write("update", POLICY_EP, policy, {"http-to-https": "enable"},
                             "server policy %s: redirect HTTP to HTTPS" % policy))
        objects.append("server policy %s" % policy)
    elif fix_id == "internal-cookie":
        writes.append(_write("update", POLICY_EP, policy, {
            "internal-cookie-secure": "enable", "internal-cookie-httponly": "enable",
            "internal-cookie-samesite": "enable", "internal-cookie-samesite-value": "lax"},
            "server policy %s: FortiWeb's own cookie Secure, HttpOnly, SameSite=Lax" % policy))
        objects.append("server policy %s" % policy)
    elif fix_id.startswith("header:") or fix_id == "cookie-security":
        if not ctx.get("wpp"):
            raise FixRefused("server policy %s has no Web Protection Profile" % policy)
        if ctx.get("wpp_managed"):
            raise FixRefused("Web Protection Profile %s is template-managed: change it in "
                             "Administrator → Template Library" % ctx["wpp"])
        wpp = ctx["wpp"]
        if fix_id.startswith("header:"):
            name = fix_id.split(":", 1)[1]
            test = next((k for k, v in HEADER_ROWS.items() if v[0] == name), None)
            if test is None:
                raise FixRefused("unknown header fix %r" % fix_id)
            if name not in ctx["rows"]["names"]:
                raise FixRefused("FortiWeb %s does not offer %s in HTTP Header Security"
                                 % (ctx.get("version") or "?", name))
            _row, field, default, passing, risk = HEADER_ROWS[test]
            value = str(options.get("value") or default).strip()
            if field == "custom-value":
                _validate_csp(value)
            else:
                allowed = (ctx["rows"]["values"] if field == "value" else ctx["rows"]["referrer"]) \
                    or list(passing) or [default]
                if value not in allowed:
                    raise FixRefused("%s is not a value FortiWeb %s accepts for %s (%s)"
                                     % (value, ctx.get("version") or "?", name, ", ".join(allowed)))
                if passing and value not in passing:
                    raise FixRefused("%s=%s would not pass the test (use one of: %s)"
                                     % (name, value, ", ".join(passing)))
            row = {"name": name, field: value}
            if ctx.get("hhs"):
                live = [r for r in _rows_named(ctx, name) if not _row_filtered(r)]
                if live:
                    writes.append(_write("update", HHS_ROWS_EP, ctx["hhs"], row,
                                         "HTTP Header Security %s, row %s: %s = %s"
                                         % (ctx["hhs"], live[0].get("id"), name, value),
                                         sub_mkey=str(live[0].get("id"))))
                else:
                    writes.append(_write("create", HHS_ROWS_EP, ctx["hhs"], row,
                                         "HTTP Header Security %s: add %s = %s" % (ctx["hhs"], name, value)))
                objects.append("HTTP Header Security %s" % ctx["hhs"])
                shared_wpps = [w for w in ctx.get("hhs_wpps") or [] if w != wpp]
            else:
                new = _free_name(_existing_names(appliance, HHS_EP), "satom-hdr-%s" % policy)
                writes.append(_write("create", HHS_EP, None, {"name": new},
                                     "create HTTP Header Security profile %s" % new))
                writes.append(_write("create", HHS_ROWS_EP, new, row,
                                     "HTTP Header Security %s: add %s = %s" % (new, name, value)))
                writes.append(_write("update", WPP_EP, wpp, {"http-header-security": new},
                                     "Web Protection Profile %s: use %s" % (wpp, new)))
                objects += ["HTTP Header Security %s (new)" % new, "Web Protection Profile %s" % wpp]
                shared_wpps = []
        else:
            secure = bool(options.get("secure", True))
            http_only = bool(options.get("http_only"))
            samesite = str(options.get("samesite") or "Lax")
            if samesite not in ("Lax", "Strict", "None", ""):
                raise FixRefused("SameSite must be Lax, Strict or None")
            if samesite == "None" and not secure:
                raise FixRefused("SameSite=None needs Secure: browsers reject the cookie otherwise")
            data = {"secure-cookie": "enable" if secure else "disable",
                    "http-only": "enable" if http_only else "disable",
                    "samesite": "enable" if samesite else "disable"}
            if samesite:
                data["samesite-value"] = samesite
            risk = ("HttpOnly hides cookies from the page's JavaScript." if http_only else "")
            if ctx.get("cks"):
                writes.append(_write("update", CKS_EP, ctx["cks"], data,
                                     "Cookie Security %s: %s" % (ctx["cks"], _flags(data))))
                objects.append("Cookie Security %s" % ctx["cks"])
                shared_wpps = [w for w in ctx.get("cks_wpps") or [] if w != wpp]
            else:
                new = _free_name(_existing_names(appliance, CKS_EP), "satom-ck-%s" % policy)
                writes.append(_write("create", CKS_EP, None, dict(name=new, **{"security-mode": "no"}, **data),
                                     "create Cookie Security profile %s (no signing or "
                                     "encryption): %s" % (new, _flags(data))))
                writes.append(_write("update", WPP_EP, wpp, {"cookie-security-policy": new},
                                     "Web Protection Profile %s: use %s" % (wpp, new)))
                objects += ["Cookie Security %s (new)" % new, "Web Protection Profile %s" % wpp]
                shared_wpps = []
        affected = list(ctx.get("wpp_policies") or [policy])
        if shared_wpps:
            from ..clients import client_for
            client = client_for(appliance)
            for w in shared_wpps:
                obj = client._safe_one("%s?mkey=%s" % (WPP_EP, quote(w, safe="")))
                for p in _refs(obj, "policy") or ["(Web Protection Profile %s)" % w]:
                    if p not in affected:
                        affected.append(p)
    elif fix_id == "certificate":
        raise FixRefused("certificates are replaced in Cert Manager")
    else:
        raise FixRefused("unknown fix %r" % fix_id)
    others = [p for p in affected if p != policy]
    return {"fix": fix_id, "policy": policy, "writes": writes, "objects": objects,
            "affected_policies": affected, "shared": bool(others),
            "others": others, "risk": risk}


def plan_many(appliance, policy: str, items, ctx: dict) -> dict:
    """Several fixes as ONE ordered plan: a profile the first fix creates is
    the profile the next one adds its row to (two header fixes never create
    two profiles). ``items`` = ``[(fix_id, options), ...]``."""
    ctx = copy.deepcopy(ctx)
    merged = {"fixes": [], "policy": policy, "writes": [], "objects": [],
              "affected_policies": [], "others": [], "risks": []}
    for fix_id, options in items:
        p = plan(appliance, policy, fix_id, options, ctx)
        merged["fixes"].append(fix_id)
        merged["writes"] += p["writes"]
        for key in ("objects", "affected_policies", "others"):
            for v in p[key]:
                if v not in merged[key]:
                    merged[key].append(v)
        if p.get("risk"):
            merged["risks"].append(p["risk"])
        for w in p["writes"]:
            body = (w.get("data") or {}).get("data") or {}
            if w["action"] == "create" and w["endpoint"] == HHS_EP:
                ctx.update(hhs=body.get("name"), hhs_rows=[], hhs_wpps=[ctx.get("wpp")])
            elif w["action"] == "create" and w["endpoint"] == CKS_EP:
                ctx.update(cks=body.get("name"), cks_wpps=[ctx.get("wpp")])
    merged["shared"] = bool(merged["others"])
    return merged


def merge_effects(effects_list) -> dict:
    out: dict = {"headers": {}}
    for e in effects_list:
        out["headers"].update(e.get("headers") or {})
        for k, v in e.items():
            if k != "headers" and v:
                out[k] = v
    return out


def _flags(data: dict) -> str:
    parts = []
    if data.get("secure-cookie") == "enable":
        parts.append("Secure")
    if data.get("http-only") == "enable":
        parts.append("HttpOnly")
    if data.get("samesite") == "enable":
        parts.append("SameSite=%s" % data.get("samesite-value"))
    return ", ".join(parts) or "no flags"


def _lease_holder(appliance_id, writes, me) -> str:
    """The first object of the plan someone ELSE holds an edit lease on."""
    from . import lock_service, objform
    for w in writes:
        if not w.get("mkey"):
            continue
        coll = objform.collection_of(w["endpoint"])
        parts = coll.split("/")
        for i in range(len(parts), 0, -1):
            info = lock_service.status(appliance_id, "%s:%s" % ("/".join(parts[:i]), w["mkey"]))
            if info and info.get("owner_user_id") != me:
                return "%s is being edited by %s" % (w["mkey"], info.get("owner_label") or "another user")
    return ""


def apply(appliance, the_plan: dict, *, ack_shared: bool, user_id=None, dry_run=False) -> dict:
    """Run a plan's writes in order through FortiWebOps. Stops at the first
    failure and reports what was written before it."""
    from .fortiweb_ops import FortiWebOps
    from . import object_refresh
    if the_plan.get("shared") and not ack_shared and not dry_run:
        raise FixRefused("this change also applies to: %s. Confirm to apply it to all of them."
                         % ", ".join(the_plan.get("others") or []))
    held = _lease_holder(appliance.id, the_plan.get("writes") or [], user_id)
    if held:
        raise FixRefused(held + "; nothing was sent to the device.")
    ops = FortiWebOps(appliance)
    results = []
    for w in the_plan.get("writes") or []:
        if w["action"] == "create":
            res = ops.create(w["endpoint"], w["data"], mkey=w.get("mkey"), dry_run=dry_run)
        else:
            res = ops.update(w["endpoint"], w["mkey"], w["data"], dry_run=dry_run,
                             sub_mkey=w.get("sub_mkey"))
        res = object_refresh.enforce(res)
        results.append({"describe": w["describe"], "ok": bool(res.get("ok")),
                        "error": res.get("error") or "", "request": res.get("request"),
                        "verify": (res.get("verify") or {}).get("verdict") if isinstance(res.get("verify"), dict) else res.get("verify")})
        if not res.get("ok"):
            return {"ok": False, "results": results,
                    "error": "%s failed: %s" % (w["describe"], res.get("error") or "rejected")}
    return {"ok": True, "results": results, "error": ""}
