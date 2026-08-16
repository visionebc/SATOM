# app/services/fp_triage.py
"""False-positive triage from a pasted attack-log entry or raw request.

The operator's most common WAF question is not "what is this signature" — it is
*"the WAF blocked something legitimate; what exactly do I create so it stops,
and nothing else stops with it?"*. SATOM could already answer that, but ONLY
from an entry read live off a device through the attack-search panel. The entry
an operator actually has in front of them arrives in a ticket, a syslog line, a
screenshot transcription or a curl reproduction — none of which are on a device.

So this module turns pasted text into the same ``row`` dict
:mod:`app.services.attack_carveout` already consumes, and then calls that
module. There is no second recommendation engine here; a second engine is the
one that drifts.

**This path never saves, and that is a design decision, not an omission.**
``attack_carveout``'s own contract is that a carve-out is assembled from the
entry *as the device reported it*, never from values the browser sent back —
"a page that lets a client supply the evidence lets a client author the
exception". Pasted text is by definition client-supplied. So the standalone tool
explains, recommends and renders the exact payload for review, and the SAVE
action stays where the evidence is device-read: Attack Search → the entry →
Carve-out. Every response says so in :func:`triage`'s ``save`` block, because a
tool that quietly lacks a button teaches people it is broken.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import unquote_plus, urlsplit

from . import attack_carveout, attack_log

#: Row keys this module will emit — taken from the attack-log column vocabulary
#: rather than typed out again, so a column added there cannot silently become
#: a field the parser drops on the floor.
ROW_KEYS = tuple(k for k, _label in attack_log.PRIMARY_FIELDS)

#: Input spellings → the canonical row key. FortiWeb's syslog, its REST payload
#: and its CSV export do not agree with each other on these names, and an
#: operator pastes whichever one their pipeline produced.
ALIASES: dict[str, str] = {
    "srcip": "src", "src_ip": "src", "source": "src", "clientip": "src",
    "dstip": "dst", "dst_ip": "dst", "destination": "dst",
    "srcport": "src_port", "dstport": "dst_port",
    "url": "http_url", "request_url": "http_url", "uri": "http_url",
    "host": "http_host", "http_hostname": "http_host",
    "method": "http_method", "http_verb": "http_method",
    "agent": "http_agent", "user_agent": "http_agent", "useragent": "http_agent",
    "referer": "http_refer", "referrer": "http_refer", "http_referer": "http_refer",
    "sigid": "signature_id", "sig_id": "signature_id",
    "signatureid": "signature_id", "signature": "signature_id",
    "subtype": "sub_type", "maintype": "main_type", "type": "main_type",
    "msgid": "msg_id", "id": "msg_id",
    "srcpolicy": "policy", "policy_name": "policy", "server_policy": "policy",
    "severity": "severity_level", "level": "severity_level",
    "threat_weight": "threat_level", "cve": "signature_cve_id",
    "owasp": "owasp_top10", "pool": "server_pool_name",
    "message": "msg", "reason": "msg",
}

#: Fields without which a specific question cannot be answered. Each entry is
#: ``(key, what it decides)`` and the missing ones are REPORTED — the operator
#: has to know which of the tool's answers rest on a field it never saw.
DECIDES: tuple[tuple[str, str], ...] = (
    ("main_type", "which WAF module produced the block, and therefore where the "
                  "exception belongs"),
    ("signature_id", "whether a per-signature exception (the narrowest fix) is "
                     "available at all"),
    ("http_url", "the path the exception is scoped to — without it most "
                 "carve-out types cannot be saved"),
    ("http_host", "which site the exception is limited to, when the profile "
                  "serves several"),
    ("policy", "which Server Policy, and therefore which Web Protection "
               "Profile, the exception has to be created on"),
)

_MAX_INPUT = 64 * 1024
_MAX_DECODE_ROUNDS = 4

_KV_RX = re.compile(r'([A-Za-z_][\w.\-]*)\s*=\s*("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;]+)')
_REQLINE_RX = re.compile(
    r'^\s*(?P<m>[A-Z]{3,10})\s+(?P<u>\S+)\s+HTTP/(?P<v>[\d.]+)\s*$')


# --------------------------------------------------------------------------- #
#  Format detection + parsing                                                  #
# --------------------------------------------------------------------------- #
def _canon(key: str) -> str:
    k = str(key or "").strip().lower().replace("-", "_")
    k = ALIASES.get(k, k)
    return k


def _unquote(v: str) -> str:
    s = str(v or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    return s.replace('\\"', '"').replace("\\\\", "\\")


def parse_kv(text: str) -> dict:
    """FortiWeb syslog / CEF-ish ``key=value`` lines."""
    out: dict[str, str] = {}
    for m in _KV_RX.finditer(text or ""):
        out[m.group(1)] = _unquote(m.group(2))
    return out


def parse_json(text: str) -> dict:
    """A JSON object, or the first entry of the list/envelope SATOM's own attack
    log API returns. ``results``/``data`` envelopes are unwrapped because that is
    what an operator copies out of the API explorer."""
    try:
        doc = json.loads(text)
    except Exception:  # noqa: BLE001
        return {}
    for _ in range(3):
        if isinstance(doc, dict) and len(doc) and \
                any(k in doc for k in ("results", "data", "entries", "rows")):
            doc = doc.get("results") or doc.get("data") or \
                doc.get("entries") or doc.get("rows")
            continue
        break
    if isinstance(doc, list):
        doc = doc[0] if doc else {}
    if not isinstance(doc, dict):
        return {}
    return {str(k): ("" if v is None else v if isinstance(v, str) else json.dumps(v))
            for k, v in doc.items()}


def parse_http_request(text: str) -> dict:
    """A raw HTTP request — what a developer pastes from a curl reproduction.

    Deliberately produces NO ``main_type``/``signature_id``: a request carries
    what was sent, not what the appliance concluded about it. Inventing a module
    here would let the tool recommend a carve-out for a decision no device made.
    """
    lines = (text or "").replace("\r\n", "\n").split("\n")
    m = None
    start = 0
    for i, ln in enumerate(lines[:5]):
        m = _REQLINE_RX.match(ln)
        if m:
            start = i
            break
    if not m:
        return {}
    out = {"http_method": m.group("m"), "http_url": m.group("u")}
    for ln in lines[start + 1:]:
        if not ln.strip():
            break
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "host":
            out["http_host"] = v
        elif k == "user-agent":
            out["http_agent"] = v
        elif k == "referer":
            out["http_refer"] = v
        elif k == "x-forwarded-for":
            out["src"] = v.split(",")[0].strip()
    return out


def parse(text: str) -> dict:
    """Turn pasted text into ``{row, fmt, mapped, unmapped, missing}``.

    ``unmapped`` is not debris to hide: a key the appliance recorded and this
    parser could not place is a field the recommendation did not see, and an
    operator staring at a narrower carve-out than they expected needs to know
    which of their evidence was not used.
    """
    raw = (text or "")[:_MAX_INPUT]
    stripped = raw.strip()
    if not stripped:
        return {"row": {}, "fmt": "", "mapped": {}, "unmapped": {},
                "missing": [d for d in DECIDES], "error": "nothing to parse"}

    fmt = ""
    flat: dict = {}
    if stripped[0] in "{[":
        flat = parse_json(stripped)
        fmt = "json" if flat else ""
    if not flat:
        req = parse_http_request(stripped)
        if req:
            flat, fmt = req, "http-request"
    if not flat:
        flat = parse_kv(stripped)
        fmt = "key=value" if flat else ""

    row: dict[str, str] = {}
    mapped: dict[str, str] = {}
    unmapped: dict[str, str] = {}
    for k, v in flat.items():
        ck = _canon(k)
        if ck in ROW_KEYS:
            if str(v).strip():
                row[ck] = str(v).strip()
                if ck != str(k).strip().lower():
                    mapped[str(k)] = ck
        else:
            unmapped[str(k)] = str(v)[:200]

    # A logged URL is often absolute. The carve-out layer wants the path and
    # already derives it, but the HOST hides in that same string and is what
    # scopes the exception to one site — so it is recovered here rather than
    # lost because the operator's pipeline folded two fields into one.
    if row.get("http_url", "").startswith(("http://", "https://")):
        parts = urlsplit(row["http_url"])
        row.setdefault("http_host", parts.netloc)

    missing = [d for d in DECIDES if not str(row.get(d[0], "")).strip()]
    return {"row": row, "fmt": fmt, "mapped": mapped, "unmapped": unmapped,
            "missing": missing,
            "error": "" if row else "no recognisable attack-log fields found"}


# --------------------------------------------------------------------------- #
#  Payload decoding                                                            #
# --------------------------------------------------------------------------- #
def decode_layers(value: str) -> list[dict]:
    """Peel URL / HTML-entity / base64 / hex encodings off a payload, in order.

    Attack-log payloads arrive encoded — usually twice — and today they are
    decoded outside SATOM, in whatever tab the operator happens to have open.
    Each round is returned separately so the operator can see WHERE the readable
    string appeared; a single fully-decoded string hides whether the appliance
    was matching on the encoded or the decoded form.
    """
    out: list[dict] = []
    cur = str(value or "")[:_MAX_INPUT]
    seen = {cur}
    for _ in range(_MAX_DECODE_ROUNDS):
        nxt, how = _decode_once(cur)
        if not nxt or nxt == cur or nxt in seen:
            break
        out.append({"how": how, "value": nxt[:4000]})
        seen.add(nxt)
        cur = nxt
    return out


def _decode_once(s: str) -> tuple[str, str]:
    if "%" in s:
        try:
            d = unquote_plus(s)
            if d != s:
                return d, "percent-decode"
        except Exception:  # noqa: BLE001
            pass
    if "&#" in s or "&lt;" in s or "&amp;" in s:
        import html
        d = html.unescape(s)
        if d != s:
            return d, "HTML entity decode"
    body = s.strip()
    if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{8,}", body) and len(body) % 2 == 0:
        try:
            d = binascii.unhexlify(body[2:] if body.lower().startswith("0x") else body)
            txt = d.decode("utf-8")
            if txt.isprintable():
                return txt, "hex decode"
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    if re.fullmatch(r"[A-Za-z0-9+/=_\-]{12,}", body) and len(body) % 4 in (0, 2, 3):
        try:
            d = base64.b64decode(body + "=" * (-len(body) % 4), validate=False)
            txt = d.decode("utf-8")
            # Base64 will "decode" almost anything into mojibake. Only a result
            # that is readable text is a decode; anything else is a coincidence
            # dressed as evidence.
            if txt.isprintable() and sum(c.isalnum() or c in " /<>=\"'();:,.-_" for c in txt) >= len(txt) * 0.8:
                return txt, "base64 decode"
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    return "", ""


# --------------------------------------------------------------------------- #
#  Triage                                                                      #
# --------------------------------------------------------------------------- #
#: Why this tool cannot save, said once so the view and the panel cannot give
#: two different accounts of the same refusal.
SAVE_NOTE = (
    "This tool explains and drafts; it does not save. A carve-out is assembled "
    "from the entry AS THE DEVICE REPORTED IT — never from values a browser "
    "sent back — so an exception authored from pasted text would let whoever "
    "supplied the text author the exception. To save this, open the same entry "
    "in Attack Search on the appliance and use the carve-out panel there: the "
    "recommendation is identical, and the evidence is device-read.")


def triage(row: dict, *, wpp: str = "") -> dict:
    """Everything SATOM can say about this entry, best carve-out first.

    Every option is proved by RUNNING the real assembly, exactly as the
    device-backed panel does — a preview produced by a second, friendlier code
    path is a preview of something that will not be what gets saved.
    """
    from . import exception_explain

    row = dict(row or {})
    labels = dict(attack_log.PRIMARY_FIELDS)
    types = attack_carveout.suggest_types(row)
    for t in types:
        t["scopers"] = [dict(s, value=str(row.get(s["row_key"]) or ""))
                        for s in attack_carveout.scopers_for(t["exc_type"])]
        subject = attack_carveout.subject_for(t["exc_type"], row)
        if subject:
            subject["label"] = labels.get(subject["row_key"], subject["row_key"])
        t["subject"] = subject
        rec = attack_carveout.recommend(row, t["exc_type"])
        rec["preview"] = attack_carveout.build(row, t["exc_type"], rec["picked"])
        t["recommended"] = rec
        t["explain"] = exception_explain.explain(
            t["exc_type"], rec["preview"].get("payload") or {},
            wpp=wpp, policy=row.get("policy", ""))
    return {
        "types": types,
        "policy": row.get("policy", ""),
        "wpp": wpp,
        "save": {"can_save": False, "note": SAVE_NOTE,
                 "where": "Attack Search → the entry → Carve-out"},
    }


__all__ = ["ROW_KEYS", "ALIASES", "DECIDES", "SAVE_NOTE",
           "parse", "parse_kv", "parse_json", "parse_http_request",
           "decode_layers", "triage"]
