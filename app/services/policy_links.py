"""Dynamic Policy Links — admin-configurable deep links shown on every Server
Policy detail page, with that policy's own context substituted into the URL.

The value is *dynamic*: an admin defines a link once (e.g. a Splunk search) with
``{token}`` placeholders, and each policy renders it filled with its own name /
VIP / pool / device, so from ``pol-demo-ecom`` the Splunk button jumps straight
to that policy's logs.

Storage: one GLOBAL ``AppSetting`` key ``policy.links`` holding a JSON list of
rows ``{label, url, enabled, new_tab}``. Same variable-length, parallel-array
edit form as the DNS Lookup resolver list (Settings → admin console). All ADOMs
share it; it never holds secrets.
"""
from __future__ import annotations

import json
import re
from urllib.parse import quote

LINKS_KEY = "policy.links"
MAX_LINKS = 10

# The tokens an admin may drop into a link URL, each mapped to a policy-context
# key filled at render time in ``workspace.policy_detail``. Order = help display.
TOKENS = [
    ("policy", "Server-policy name"),
    ("device", "Appliance name (as shown in the manager)"),
    ("device_ip", "Appliance management IP"),
    ("vip", "Virtual IP address(es)"),
    ("port", "HTTP/HTTPS service name"),
    ("pool", "Server-pool name"),
    ("vserver", "Virtual-server name"),
    ("wpp", "Web Protection Profile name"),
]
TOKEN_KEYS = {t for t, _ in TOKENS}

_TOKEN_RE = re.compile(r"\{([a-z_]+)\}")


def links() -> list[dict]:
    """The configured links (raw, unrendered). Malformed rows are dropped."""
    from ..models import AppSetting
    raw = AppSetting.get(LINKS_KEY)
    if not raw:
        return []
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError):
        return []
    out: list[dict] = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        label = str(r.get("label") or "").strip()
        url = str(r.get("url") or "").strip()
        if label and url:
            out.append({
                "label": label[:80],
                "url": url[:1000],
                "enabled": bool(r.get("enabled", True)),
                "new_tab": bool(r.get("new_tab", True)),
            })
    return out


def save_links(rows):
    """Validate + persist the link list — PERMISSIVELY.

    A row is saved as long as it has BOTH a label and a URL. We never discard a
    link for using a token we don't recognise (those are kept and rendered
    literally) and a scheme-less URL gets ``https://`` prepended — so a link the
    admin typed can't silently vanish. Only genuinely incomplete rows (missing
    label OR url) are skipped, and that is reported. Returns ``(clean, errors)``
    where ``errors`` is a list of human-readable notes/warnings (never fatal to
    the other rows). Fully blank rows are dropped silently."""
    from ..extensions import db
    from ..models import AppSetting
    clean: list[dict] = []
    errors: list[str] = []
    for r in (rows or []):
        label = str(r.get("label") or "").strip()[:80]
        url = str(r.get("url") or "").strip()[:1000]
        if not label and not url:
            continue  # fully blank row → drop silently
        if not label or not url:
            errors.append(
                "Skipped a row missing its %s."
                % ("URL" if label else "label"))
            continue
        low = url.lower()
        if not (low.startswith("http://") or low.startswith("https://")):
            # Be forgiving: assume https for a scheme-less host instead of
            # discarding the link the admin clearly intended.
            url = "https://" + url
        # Unknown tokens are ALLOWED — kept literal at render time — but noted
        # so the admin knows they won't be substituted.
        bad = [t for t in _TOKEN_RE.findall(url) if t not in TOKEN_KEYS]
        if bad:
            errors.append(
                "Note: %r uses %s, which no policy fills — it will appear "
                "literally. Valid tokens: %s."
                % (label, ", ".join("{%s}" % b for b in dict.fromkeys(bad)),
                   ", ".join("{%s}" % t for t, _ in TOKENS)))
        if len(clean) >= MAX_LINKS:
            errors.append(
                "Only the first %d links were kept (limit reached)." % MAX_LINKS)
            break
        clean.append({"label": label, "url": url,
                      "enabled": bool(r.get("enabled", True)),
                      "new_tab": bool(r.get("new_tab", True))})
    AppSetting.set(LINKS_KEY, json.dumps(clean))
    db.session.commit()
    return clean, errors


def render_one(row: dict, ctx: dict) -> str | None:
    """Substitute ``{tokens}`` in the row URL against ``ctx``.

    Returns ``None`` only when a KNOWN token has no value for this policy (so a
    ``{vip}`` link never renders broken on a policy with no VIP). Unknown tokens
    are left literal — a link with a typo'd token still shows, it just isn't
    substituted, which is far less surprising than the link vanishing."""
    url = row.get("url") or ""
    for tok in _TOKEN_RE.findall(url):
        if tok in TOKEN_KEYS and not str(ctx.get(tok) or "").strip():
            return None

    def _sub(m):
        t = m.group(1)
        if t in TOKEN_KEYS:
            return quote(str(ctx.get(t, "")), safe="")
        return m.group(0)  # unknown token → leave literal

    return _TOKEN_RE.sub(_sub, url)


def rendered_links(ctx: dict) -> list[dict]:
    """Enabled links resolved for THIS policy context; broken ones dropped."""
    out: list[dict] = []
    for row in links():
        if not row.get("enabled"):
            continue
        url = render_one(row, ctx)
        if url:
            out.append({"label": row["label"], "url": url,
                        "new_tab": bool(row.get("new_tab", True))})
    return out
