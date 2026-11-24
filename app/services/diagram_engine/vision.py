"""Optional refinement of a recognised diagram by a LOCAL vision LLM.

An Ollama-compatible ``POST /api/chat`` endpoint receives the page picture
and the list of recognised elements and answers, as JSON, a category and/or a
corrected text for the elements it can identify::

    {"elements": {"<element id>": {"category": "network.firewall", "text": "FW-01"}}}

The reply is validated strictly (size, keys, types, ids, category grammar,
text length and characters); ANY violation rejects the whole reply. A valid
reply only fills ``category`` / ``text`` of elements whose confidence is under
``model.LOW_CONFIDENCE`` and marks them ``metadata.refined_by``; geometry,
connectors and confident elements are never touched, and nothing is added.

Pure: no network at import, no global state. The HTTP call goes through an
injectable ``transport(url, body_bytes, timeout) -> reply_bytes`` so tests run
without a server; the runner calls :func:`refine` only when an operator has
configured an endpoint.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import urllib.parse

from . import model

MAX_REPLY_BYTES = 256 * 1024
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_ELEMENTS_SENT = 300
MAX_TEXT = 500
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/\-]{0,99}$")
_TEXT_BAD = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

SYSTEM_PROMPT = (
    "You review diagrams that were recognised from a picture. You receive the picture and "
    "a JSON list of detected elements (id, kind, shape, text, bbox x/y/w/h in pixels, "
    "confidence). For elements you can identify with certainty, give a category of the form "
    "family.class (lower case, e.g. network.firewall, network.switch, network.router, "
    "infra.server, infra.database, cloud.internet, flow.decision, flow.process) and/or the "
    "correct text as printed in the picture. Answer ONLY with JSON of the form "
    '{"elements": {"<id>": {"category": "...", "text": "..."}}}. Use only ids from the list, '
    "omit elements you are unsure about, never invent elements.")


class RefineRejected(ValueError):
    """The model's reply failed validation; nothing was applied."""


def endpoint_url(endpoint: str) -> str:
    """Normalise an operator-configured endpoint to its ``/api/chat`` URL."""
    u = urllib.parse.urlsplit(str(endpoint or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("the vision endpoint must be an http(s) URL")
    if u.username or u.password:
        raise ValueError("credentials in the vision endpoint URL are not accepted")
    path = u.path.rstrip("/")
    if not path.endswith("/api/chat"):
        path = path + "/api/chat"
    return urllib.parse.urlunsplit((u.scheme, u.netloc, path, "", ""))


def http_transport(url: str, body: bytes, timeout: float) -> bytes:
    """Default transport: one POST, no redirects, reply capped at MAX_REPLY_BYTES+1."""
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=timeout) as resp:
        return resp.read(MAX_REPLY_BYTES + 1)


def _candidates(page: dict) -> list:
    out = []
    for e in page.get("elements", [])[:MAX_ELEMENTS_SENT]:
        out.append({"id": e["id"], "kind": e.get("kind"), "shape": e.get("shape"),
                    "text": (e.get("text") or e.get("name") or "")[:200],
                    "bbox": [round(e.get("x", 0)), round(e.get("y", 0)),
                             round(e.get("w", 0)), round(e.get("h", 0))],
                    "confidence": round(float(e.get("confidence", 1.0)), 2)})
    return out


def build_request(page: dict, image_png: bytes, model_name: str) -> dict:
    return {
        "model": model_name, "stream": False, "format": "json",
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",
             "content": "Detected elements:\n" + json.dumps(_candidates(page), ensure_ascii=False),
             "images": [base64.b64encode(image_png).decode("ascii")]},
        ],
    }


def parse_reply(raw: bytes, known_ids: set, categories=None) -> dict:
    """Validate the HTTP reply -> ``{element id: {"category"?, "text"?}}``.
    Raises :class:`RefineRejected` on anything unexpected."""
    if not isinstance(raw, (bytes, bytearray)):
        raise RefineRejected("reply is not bytes")
    if len(raw) > MAX_REPLY_BYTES:
        raise RefineRejected("reply larger than %d bytes" % MAX_REPLY_BYTES)
    try:
        envelope = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise RefineRejected("reply is not JSON") from None
    if not isinstance(envelope, dict):
        raise RefineRejected("reply is not a JSON object")
    msg = envelope.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, str):
        raise RefineRejected("reply has no message.content")
    try:
        body = json.loads(content)
    except ValueError:
        raise RefineRejected("message content is not JSON") from None
    if not isinstance(body, dict) or set(body) != {"elements"}:
        raise RefineRejected("content must be an object with exactly the key 'elements'")
    elements = body["elements"]
    if not isinstance(elements, dict):
        raise RefineRejected("'elements' must be an object")
    if len(elements) > len(known_ids):
        raise RefineRejected("more corrections than elements")
    out = {}
    for eid, fix in elements.items():
        if eid not in known_ids:
            raise RefineRejected("unknown element id %r" % str(eid)[:40])
        if not isinstance(fix, dict) or not fix or not set(fix) <= {"category", "text"}:
            raise RefineRejected("element %s: only 'category' and 'text' are allowed" % eid)
        clean = {}
        if "category" in fix:
            cat = fix["category"]
            if not isinstance(cat, str) or not model.CATEGORY_RE.match(cat):
                raise RefineRejected("element %s: category %r is not family.class" % (eid, str(cat)[:40]))
            if categories is not None and cat not in categories:
                raise RefineRejected("element %s: category %r is not in the library" % (eid, cat[:40]))
            clean["category"] = cat
        if "text" in fix:
            txt = fix["text"]
            if not isinstance(txt, str) or len(txt) > MAX_TEXT or _TEXT_BAD.search(txt):
                raise RefineRejected("element %s: text must be a plain string of at most %d characters"
                                     % (eid, MAX_TEXT))
            clean["text"] = txt.strip()
        out[eid] = clean
    return out


def refine(doc: dict, image_png_bytes: bytes, endpoint: str, model_name: str, timeout: float = 60.0,
           *, page_index: int = 0, transport=None, categories=None) -> dict:
    """Return a refined COPY of *doc* (the input is never modified).

    ``recognition.stats`` gets ``vision_applied`` / ``vision_skipped``; a
    failed call or a rejected reply leaves the elements untouched and adds a
    warning. ``categories``: optional set of allowed categories (the loaded
    symbol libraries)."""
    out = copy.deepcopy(doc)
    rec = out.setdefault("recognition", {})
    warnings = rec.setdefault("warnings", [])
    stats = rec.setdefault("stats", {})
    if not isinstance(model_name, str) or not MODEL_RE.match(model_name):
        raise ValueError("invalid vision model name")
    if not isinstance(image_png_bytes, (bytes, bytearray)) or len(image_png_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("the page image must be bytes of at most %d MB" % (MAX_IMAGE_BYTES >> 20))
    url = endpoint_url(endpoint)
    pages = out.get("pages") or []
    if not 0 <= page_index < len(pages):
        raise ValueError("no page %d" % page_index)
    page = pages[page_index]
    by_id = {e["id"]: e for e in page.get("elements", [])}
    body = json.dumps(build_request(page, bytes(image_png_bytes), model_name)).encode("utf-8")
    send = transport or http_transport
    try:
        raw = send(url, body, float(timeout))
        fixes = parse_reply(raw, set(by_id), categories)
    except RefineRejected as exc:
        warnings.append("Vision refinement rejected the model's reply: %s" % exc)
        stats["vision_applied"] = 0
        return out
    except Exception as exc:  # noqa: BLE001 -- network/timeouts: refinement is optional
        warnings.append("Vision refinement unavailable (%s)." % type(exc).__name__)
        stats["vision_applied"] = 0
        return out
    applied = skipped = 0
    for eid, fix in fixes.items():
        e = by_id[eid]
        if float(e.get("confidence", 1.0)) >= model.LOW_CONFIDENCE:
            skipped += 1
            continue
        changed = False
        if "category" in fix and fix["category"] != e.get("category"):
            e["category"] = fix["category"]
            changed = True
        if fix.get("text") and fix["text"] != e.get("text"):
            e["text"] = fix["text"][:model.MAX_TEXT]
            changed = True
        if changed:
            meta = e.setdefault("metadata", {})
            meta["refined_by"] = model_name
            applied += 1
    stats["vision_applied"] = applied
    stats["vision_skipped"] = skipped
    return out
