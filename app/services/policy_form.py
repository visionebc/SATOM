"""GUI-faithful Server Policy form model — the web port of the desktop
``ui/pages/policy_view.py`` ``_SECTIONS``.

The generic ``fortiweb_field_schema.build_groups`` just buckets whatever keys the
device returns; it can't reproduce the FortiWeb GUI's **ordered sections**, its
**curated labels**, the **restricted Deployment Mode** dropdown, or the **live
show/hide** of fields as drivers change (Deployment Mode, an HTTPS Service, the
Client-Real-IP / Syn-Cookie / Scripting toggles…). This module encodes exactly
that — the same sections, order, labels, kinds and visibility predicates the
standalone curates — so the web form behaves like FortiWeb's own
*Policy > Server Policy* page.

Each field carries a JSON-serialisable ``vis`` rule; the browser
(``policy_detail.html``) re-evaluates them live as the operator edits, mirroring
the desktop ``_refresh_conditionals``. Nothing here touches the device — it only
shapes the policy dict the view already loads.
"""
from __future__ import annotations

from .fortiweb_field_schema import REF_CREATE, REF_ENDPOINTS, is_on

# ── field kinds (mirror the standalone) ───────────────────────────────────────
_T = "text"
_ON = "onoff"
_NUM = "num"
_DEPLOY = "deploy"
_REF = "ref"
_WPP = "wpp"
_ENUM = "enum"

# ── deployment modes ──────────────────────────────────────────────────────────
# Raw value → the label FortiWeb shows in the GUI.
_DEPLOY_LABELS = {
    "server-pool": "Single Server/Server Balance",
    "http-content-routing": "HTTP Content Routing",
    "offline-protection": "Offline Protection",
    "transparent-servers": "Transparent Servers",
    "wccp-servers": "WCCP Servers",
}

# In Reverse Proxy mode (what this app manages) FortiWeb offers ONLY these two
# Deployment Modes; the combo restricts to them but still preserves an out-of-list
# value a loaded policy happens to carry. (FortiWeb Admin Guide, "Configuring an
# HTTP server policy".)
DEPLOY_MODES_OFFERED = [
    ("server-pool", _DEPLOY_LABELS["server-pool"]),
    ("http-content-routing", _DEPLOY_LABELS["http-content-routing"]),
]

_CR_MODE = "http-content-routing"
_RP_MODES = ("server-pool", "http-content-routing")               # Reverse Proxy
_POOL_MODES = ("server-pool", "offline-protection",               # direct pool
               "transparent-servers", "wccp-servers")


def deployment_label(value) -> str:
    v = "" if value is None else str(value).strip()
    return _DEPLOY_LABELS.get(v, v)


# ── fixed-choice (_ENUM) vocabularies — editable, device value always survives ─
ENUM_CHOICES: dict[str, tuple[str, ...]] = {
    "ssl-cipher": ("medium", "high", "custom"),
    "traffic-mirror-type": ("client-side", "server-side", "both-side"),
    "certificate-type": ("certificate", "letsencrypt"),
    "protocol": ("HTTP", "FTP"),
}


# ── visibility rule builders (emit JSON the browser evaluates live) ───────────
# ALWAYS / AUTO  → always rendered AND always visible (AUTO would be hidden-when-
# empty in the desktop GUI, but the web shows it so the operator can populate or
# create it — the user wants the full form, not a trimmed one).
def _always():
    return {"t": "always"}


def _mode(*modes):
    return {"t": "mode", "modes": list(modes)}


def _on(key):
    return {"t": "on", "key": key}


def _set(key):
    return {"t": "set", "key": key}


def _https():
    # FortiWeb gates the HTTPS / SSL options on an HTTPS Service being set OR SSL on.
    return {"t": "https"}


def _all(*rules):
    return {"t": "all", "of": list(rules)}


# AUTO == always render + always visible for the web (see note above).
AUTO = _always()
ALWAYS = _always()

# ── the form, section by section (label, key, kind, vis) ──────────────────────
# Mirrors ``policy_view._SECTIONS`` (FortiWeb 7.6/8.0 *Policy > Server Policy*).
# ``name`` is omitted (shown locked in the page header). ``web-protection-profile``
# stays in Security Configuration where FortiWeb shows it.
POLICY_SECTIONS: list[tuple[str, list[tuple[str, str, str, dict]]]] = [
    ("Network Configuration", [
        ("Status", "status", _ON, ALWAYS),
        ("Deployment Mode", "deployment-mode", _DEPLOY, ALWAYS),
        ("Virtual Server", "vserver", _REF, _mode(*_RP_MODES)),
        ("Data Capture Port", "data-capture-port", _REF, _mode("offline-protection")),
        ("V-Zone", "v-zone", _REF, _mode("transparent-servers")),
        ("Match Once", "prefer-current-session", _ON, _mode(_CR_MODE)),
        ("Server Pool", "server-pool", _REF, _mode(*_POOL_MODES)),
        ("Protected Hostnames", "allow-hosts", _REF, ALWAYS),
        ("Blocking Port", "block-port", _REF, _mode("offline-protection")),
        ("Client Real IP", "client-real-ip", _ON, _mode(*_RP_MODES)),
        ("IP/IP Range", "real-ip-addr", _T, _on("client-real-ip")),
        ("Use Random Port", "client-real-ip-random-port", _ON, _on("client-real-ip")),
        ("Protocol", "protocol", _ENUM, ALWAYS),
        ("HTTP Service", "service", _REF, ALWAYS),
        ("HTTPS Service", "https-service", _REF, ALWAYS),
        ("HTTP/3 Service", "http3-service", _REF, AUTO),
        ("HTTP/2", "http2", _ON, _all(_mode(*_RP_MODES), _https())),
        ("Redirect HTTP to HTTPS", "http-to-https", _ON, _mode(*_RP_MODES)),
        ("Redirect Naked Domain", "redirect-naked-domain", _ON, _mode(*_RP_MODES)),
        ("Traffic Mirror", "traffic-mirror", _ON, ALWAYS),
        ("Traffic Mirror Type", "traffic-mirror-type", _ENUM, _on("traffic-mirror")),
        ("Traffic Mirror Policy", "traffic-mirror-profile", _REF, _on("traffic-mirror")),
    ]),
    ("HTTPS / SSL", [
        ("SSL", "ssl", _ON, _https()),
        ("Multi-Certificate", "multi-certificate", _ON, _https()),
        ("Certificate Type", "certificate-type", _ENUM, _https()),
        ("Certificate", "certificate", _REF, _https()),
        ("Letsencrypt Certificate", "lets-certificate", _REF, _https()),
        ("Certificate Intermediate Group", "intermediate-certificate-group", _REF, _https()),
        ("SSL Client Verify", "ssl-client-verify", _REF, _https()),
        ("Enable SNI", "sni", _ON, _https()),
        ("SNI Policy", "sni-certificate", _REF, _on("sni")),
        ("Enable Strict SNI", "sni-strict", _ON, _on("sni")),
        ("URL Based Client Certificate", "urlcert", _ON, _https()),
        ("URL Cert Group", "urlcert-group", _REF, _on("urlcert")),
        ("Max HTTP Request Length", "urlcert-hlen", _NUM, _on("urlcert")),
    ]),
    ("SSL Protocols & Ciphers", [
        ("TLS 1.0", "tls-v10", _ON, _https()),
        ("TLS 1.1", "tls-v11", _ON, _https()),
        ("TLS 1.2", "tls-v12", _ON, _https()),
        ("TLS 1.3", "tls-v13", _ON, _https()),
        ("Enable SSL Ciphers Group", "use-ciphers-group", _ON, _https()),
        ("SSL Ciphers Group", "ssl-ciphers-group", _REF, _on("use-ciphers-group")),
        ("SSL/TLS Encryption Level", "ssl-cipher", _ENUM, _https()),
        ("RFC-9719 Comply", "rfc7919-comply", _ON, _https()),
        ("Disable Client-Initiated SSL Renegotiation", "ssl-noreg", _ON, _https()),
        ("SSL Session Timeout", "ssl-session-timeout", _NUM, _https()),
    ]),
    ("HTTPS Header Insertion", [
        ("Client Certificate Forwarding", "client-certificate-forwarding", _ON, _https()),
        ("Custom Header of CCF Subject", "client-certificate-forwarding-sub-header", _T,
         _all(_https(), _on("client-certificate-forwarding"))),
        ("Custom Header of CCF Certificate", "client-certificate-forwarding-cert-header", _T,
         _all(_https(), _on("client-certificate-forwarding"))),
        ("Add HSTS Header", "hsts-header", _ON, _https()),
        ("HSTS Max-Age", "hsts-max-age", _NUM, _all(_https(), _on("hsts-header"))),
        ("Include Sub Domains", "hsts-include-subdomains", _ON, _all(_https(), _on("hsts-header"))),
        ("Preload", "hsts-preload", _ON, _all(_https(), _on("hsts-header"))),
        ("Add HPKP Header", "hpkp-header", _REF, _https()),
    ]),
    ("Application Delivery", [
        ("Proxy Protocol", "proxy-protocol", _ON, ALWAYS),
        ("Use Proxy Protocol Address", "use-proxy-protocol-addr", _ON, _on("proxy-protocol")),
        ("Retry On", "retry-on", _ON, ALWAYS),
        ("Retry On TCP Connection Failure", "retry-on-connect-failure", _ON, _on("retry-on")),
        ("Retry Times On Connection Failure", "retry-times-on-connect-failure", _NUM,
         _all(_on("retry-on"), _on("retry-on-connect-failure"))),
        ("Retry On Cache Size", "retry-on-cache-size", _NUM, _on("retry-on")),
        ("Retry On HTTP Failure", "retry-on-http-layer", _ON, _on("retry-on")),
        ("Retry Times On HTTP Failure", "retry-times-on-http-layer", _NUM,
         _all(_on("retry-on"), _on("retry-on-http-layer"))),
        ("Retry On HTTP Return Code", "retry-on-http-response-codes", _T,
         _all(_on("retry-on"), _on("retry-on-http-layer"))),
        ("Replacemsg On Connect Failure", "replacemsg-on-connect-failure", _REF, _on("retry-on")),
        ("Web Cache", "web-cache", _ON, ALWAYS),
        ("Comments", "comment", _T, AUTO),
    ]),
    ("Scripting", [
        ("Scripting", "scripting", _ON, ALWAYS),
        ("Scripting List", "scripting-list", _REF, _on("scripting")),
    ]),
    ("Security Configuration", [
        ("Monitor Mode", "monitor-mode", _ON, ALWAYS),
        ("Syn Cookie", "syncookie", _ON, ALWAYS),
        ("Half Open Threshold", "half-open-threshold", _NUM, _on("syncookie")),
        ("ZTNA Profile", "ztna-profile", _REF, _set("https-service")),
        ("Web Protection Profile", "web-protection-profile", _WPP, ALWAYS),
        ("Allow List", "allow-list", _REF, AUTO),
        ("Replacement Message", "replacemsg", _REF, AUTO),
        ("URL Case Sensitivity", "case-sensitive", _ON, ALWAYS),
    ]),
    ("Log Config", [
        ("Enable Traffic Log", "tlog", _ON, ALWAYS),
    ]),
]


def _field(label: str, key: str, kind: str, value) -> dict:
    """One spec field → a render descriptor (widget forced by the curated kind,
    not guessed from the value, so an empty field still gets the right widget)."""
    d = {"key": key, "label": label, "value": "" if value is None else value,
         "options": []}
    if kind == _ON:
        d["widget"] = "toggle"
        d["on"] = is_on(value)
    elif kind == _NUM:
        d["widget"] = "number"
    elif kind == _ENUM:
        d["widget"] = "enum"
        d["options"] = list(ENUM_CHOICES.get(key, ()))
    elif kind == _DEPLOY:
        d["widget"] = "deploy"
        opts = [{"value": v, "label": l} for v, l in DEPLOY_MODES_OFFERED]
        cur = "" if value is None else str(value).strip()
        if cur and cur not in {v for v, _ in DEPLOY_MODES_OFFERED}:
            opts.insert(0, {"value": cur, "label": deployment_label(cur)})
        d["options"] = opts
    elif kind in (_REF, _WPP):
        d["widget"] = "ref"
        d["ref"] = REF_ENDPOINTS.get(key, "")
        d["create_new"] = key in REF_CREATE
        d["is_wpp"] = (kind == _WPP)
    else:  # _T
        d["widget"] = "text"
    return d


def build_policy_sections(policy: dict) -> list[dict]:
    """The full, ordered, GUI-faithful Server Policy form.

    Every spec field is rendered (even when the device value is empty) so the
    operator sees the whole form; conditional rows carry a ``vis`` rule the
    browser toggles live. Returns ``[{title, fields: [descriptor+vis]}]``.
    """
    out = []
    for title, rows in POLICY_SECTIONS:
        fields = []
        for label, key, kind, vis in rows:
            f = _field(label, key, kind, (policy or {}).get(key))
            f["vis"] = vis
            fields.append(f)
        out.append({"title": title, "fields": fields})
    return out


__all__ = ["POLICY_SECTIONS", "DEPLOY_MODES_OFFERED", "ENUM_CHOICES",
           "deployment_label", "build_policy_sections"]
