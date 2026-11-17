"""Secrets in template pushes: never taken from the template, never written down.

A template body is desired state captured from one device or typed by hand. A
secret in it (an SMTP password, a JWT secret) is either empty, the device's own
``ENC …`` ciphertext — meaningless on any other box — or a plaintext value that
should not sit in the database. So a push NEVER sends the template's secret
values: each secret field is dropped from the payload (the device keeps what it
has) unless the operator types a value at apply time (Mass Deploy, 2026-10-24).

What the operator types lives only in the request and in the background job's
memory. Everything that is written down — the job state file, the change
history, the audit row, the preview sent back to the browser — goes through
:func:`mask` first.

The field test is narrower than the ADOM search's (``adom_search``) and than
``cli_writer.is_secret``: a template must still push ``token-header``,
``jwt-token-name`` and ``jwt-public-key`` (a header name, a token location, a
PUBLIC key), and ``cli_writer``'s ``key$`` also matches ``mkey``.
"""
from __future__ import annotations

import copy
import re
from typing import Any

MASK = "<secret>"

_SECRET = re.compile(r"(passw|passphrase|secret|psk|private[-_]?key|credential"
                     r"|^pwd$|[-_]pwd$)", re.I)


def is_secret_key(name) -> bool:
    return bool(_SECRET.search(str(name or "")))


def _is_enc(value: Any) -> bool:
    """A FortiOS-family ciphertext: ``"ENC …"`` (or ``["ENC", …]``)."""
    if isinstance(value, str):
        return value.startswith("ENC ")
    if isinstance(value, list):
        return bool(value) and value[0] == "ENC"
    return False


def mask(obj: Any) -> Any:
    """A copy of ``obj`` with every non-empty secret value replaced by ``MASK``."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if is_secret_key(k) and not isinstance(v, (dict, list)) and v not in (None, ""):
                out[k] = MASK
            elif _is_enc(v):
                out[k] = MASK
            else:
                out[k] = mask(v)
        return out
    if isinstance(obj, list):
        return [mask(v) for v in obj]
    return obj


def _payload(item: dict) -> dict | None:
    """The object fields of a push item: ``data`` or the ``data.data`` wrapper
    the FortiWeb REST body uses."""
    data = item.get("data")
    if not isinstance(data, dict):
        return None
    inner = data.get("data")
    return inner if isinstance(inner, dict) else data


def _short(endpoint: str) -> str:
    """``/api/v2.0/cmdb/log/email-policy`` -> ``log/email-policy``."""
    ep = (endpoint or "").split("/api/v2.0/")[-1]
    return ep[len("cmdb/"):] if ep.startswith("cmdb/") else ep


def field_key(index: int, field: str) -> str:
    return "%d:%s" % (index, field)


def secret_fields(items: list[dict]) -> list[dict]:
    """The secret fields of the push items an operator can type a value for:
    top-level fields of each object. ``[{key, item, endpoint, mkey, field, label}]``."""
    out = []
    for i, it in enumerate(items or []):
        data = _payload(it) or {}
        for f in sorted(data):
            if is_secret_key(f) and not isinstance(data[f], (dict, list)):
                where = _short(it.get("endpoint")) + (" %s" % it["mkey"] if it.get("mkey") else "")
                out.append({"key": field_key(i, f), "item": i,
                            "endpoint": it.get("endpoint") or "",
                            "mkey": it.get("mkey") or "", "field": f,
                            "label": "%s · %s" % (where.strip(), f)})
    return out


def _strip_nested(node: Any, path: str, dropped: list[str]) -> Any:
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            p = "%s.%s" % (path, k) if path else str(k)
            if is_secret_key(k) and not isinstance(v, (dict, list)):
                dropped.append(p)
                continue
            out[k] = _strip_nested(v, p, dropped)
        return out
    if isinstance(node, list):
        return [_strip_nested(v, path, dropped) for v in node]
    return node


def prepare(items: list[dict], supplied: dict | None = None) -> tuple[list[dict], dict]:
    """The push items to send, and what happened to each secret field.

    ``supplied`` = ``{field_key: value}`` typed at apply time; an empty value
    counts as not supplied. Returns ``(items, {"sent": [label], "kept": [label]})``
    — ``kept`` = dropped from the payload, so each device keeps its own value.
    Never mutates ``items``."""
    supplied = {k: v for k, v in (supplied or {}).items() if v not in (None, "")}
    fields = {f["key"]: f for f in secret_fields(items)}
    out = copy.deepcopy(items or [])
    sent, kept = [], []
    for i, it in enumerate(out):
        data = it.get("data")
        if not isinstance(data, dict):
            continue
        wrapped = isinstance(data.get("data"), dict)
        obj = data["data"] if wrapped else data
        dropped: list[str] = []
        clean = _strip_nested(obj, "", dropped)
        for p in dropped:
            key = field_key(i, p)
            if key in supplied and key in fields:
                clean[p] = supplied[key]
                sent.append(fields[key]["label"])
            else:
                f = fields.get(key)
                kept.append(f["label"] if f else "%s · %s" % (_short(it.get("endpoint")), p))
        if wrapped:
            data["data"] = clean
        else:
            it["data"] = clean
    return out, {"sent": sent, "kept": kept}
