#!/usr/bin/env python3
"""EfficientIP SOLIDserver DNS-01 hook for the ACME ``exec`` provider.

No ACME client ships a SOLIDserver provider, so it is driven through the
generic ``exec`` hook. The client calls this script as:

    <script> present <fqdn> <token> <keyauth>
    <script> cleanup <fqdn> <token> <keyauth>

In the default (non-RAW) mode the client already resolves ``<fqdn>`` to the
``_acme-challenge.<domain>.`` record name and ``<keyauth>`` to the TXT value to
publish, so this script only adds/removes one TXT RR.

The REST verbs mirror :mod:`app.services.dns_providers.efficientip` — same flat
``/rest/<class>_<action>`` API, same HTTP Basic auth — so both paths behave
identically against the same appliance. It is deliberately STANDALONE (stdlib
only, no DB, no app import): the DNS challenge must still work while the web
app is restarting, and the client runs it as a bare subprocess.

Configuration comes from the environment (Settings → Certificate Manager → DNS
providers → EfficientIP SOLIDserver). Nothing is hardcoded:

    EFFICIENTIP_HOST       host, IP or full base URL          (required)
    EFFICIENTIP_USER       API user                           (required)
    EFFICIENTIP_PASSWORD   API password                       (required)
    EFFICIENTIP_DNS_NAME   dns_name of the target DNS server  (required)
    EFFICIENTIP_VIEW_NAME  dnsview_name, if views are used    (optional)
    EFFICIENTIP_TTL        TTL of the challenge record        (default 60)
    EFFICIENTIP_INSECURE   1 = skip TLS verification          (optional)

SATOM keeps the password Fernet-encrypted at rest and hands it to this process
ONLY through the environment — never on the command line.
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30


def _env(name, default=None, required=False):
    v = (os.environ.get(name) or "").strip()
    if not v and required:
        sys.exit(f"efficientip hook: {name} is not set")
    return v or default


def _base_url():
    host = _env("EFFICIENTIP_HOST", required=True)
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return "https://" + host.rstrip("/")


def _ctx():
    if _env("EFFICIENTIP_INSECURE") in ("1", "true", "yes", "on"):
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    return None


def _call(method, path, params):
    url = f"{_base_url()}/rest/{path}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method)
    cred = f"{_env('EFFICIENTIP_USER', required=True)}:{_env('EFFICIENTIP_PASSWORD', required=True)}"
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(cred.encode()).decode())
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"efficientip hook: {method} {path} failed: {exc}")


def _rows(body):
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return [data] if isinstance(data, dict) else []


def _fail(action, status, body):
    msg = f"HTTP {status}"
    for row in _rows(body):
        if row.get("errmsg") or row.get("err_msg"):
            msg = str(row.get("errmsg") or row.get("err_msg"))
            break
    sys.exit(f"efficientip hook: {action} failed — {msg}")


def _common(fqdn):
    p = {"dns_name": _env("EFFICIENTIP_DNS_NAME", required=True),
         "rr_name": fqdn.rstrip("."),
         "rr_type": "TXT"}
    view = _env("EFFICIENTIP_VIEW_NAME")
    if view:
        p["dnsview_name"] = view
    return p


def present(fqdn, value):
    p = _common(fqdn)
    p["value1"] = value
    p["rr_ttl"] = _env("EFFICIENTIP_TTL", "60")
    # new_edit, not new_only: a retried order must not fail on "already exists".
    p["add_flag"] = "new_edit"
    status, body = _call("POST", "dns_rr_add", p)
    if status >= 300:
        _fail("present", status, body)


def cleanup(fqdn, value):
    """Delete by rr_id — dns_rr_delete keys on the native id, so look the record
    up first and match on our exact TXT value (never wipe a sibling record)."""
    p = _common(fqdn)
    status, body = _call("GET", "dns_rr_list", dict(p, WHERE=f"rr_full_name='{fqdn.rstrip('.')}'"))
    if status >= 300:
        return  # nothing to clean up (or the zone is gone) — not fatal
    for row in _rows(body):
        if str(row.get("rr_type") or "").upper() != "TXT":
            continue
        if str(row.get("value1") or "").strip('"') != value:
            continue
        rid = str(row.get("rr_id") or "")
        if rid:
            _call("DELETE", "dns_rr_delete", {"rr_id": rid})


def main():
    if len(sys.argv) < 5:
        sys.exit("usage: efficientip.sh present|cleanup <fqdn> <token> <keyauth>")
    action, fqdn, _token, keyauth = sys.argv[1:5]
    if action == "present":
        present(fqdn, keyauth)
    elif action == "cleanup":
        cleanup(fqdn, keyauth)
    else:
        sys.exit(f"efficientip hook: unknown action {action!r}")


if __name__ == "__main__":
    main()
