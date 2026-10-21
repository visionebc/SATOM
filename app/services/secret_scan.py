"""Find credentials in text a person is about to publish outside SATOM.

Used before a Wiki article goes to Confluence (services/wiki_confluence.py):
a runbook that quotes a FortiOS ``set ... ENC ...`` line, a pasted
``Authorization: Bearer ...`` header or a PEM private key would otherwise
leave the management network with it. Findings name the KIND and the LINE,
never the value: the report is shown on screen and written to the audit log.

Deliberately strict where it costs nothing (a PEM block, a cloud key prefix)
and tolerant where it would cry wolf: an assignment counts only when its value
looks like a value, not a placeholder (``<password>``, ``****``, ``${VAR}``,
``{{ x }}``, ``changeme``, ``example``...).
"""
from __future__ import annotations

import re

#: (kind, pattern) -- text that is a credential by its shape alone.
SHAPES = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("PuTTY private key", re.compile(r"^PuTTY-User-Key-File-\d", re.M)),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Atlassian API token", re.compile(r"\bATATT3[A-Za-z0-9_=-]{30,}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Fernet token", re.compile(r"\bgAAAAA[A-Za-z0-9_-]{60,}={0,2}")),
    ("password in a URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s/]+", re.I)),
    ("FortiOS encrypted secret", re.compile(
        r"^\s*set\s+(?:password|passwd|psksecret|secret|key|passphrase|auth-pwd|"
        r"ppk-secret|sslvpn-password)\s+ENC\s+(?!<)\S{8,}", re.I | re.M)),
    ("authorization header", re.compile(
        r"\bAuthorization\s*:\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{12,}", re.I)),
)

#: ``name: value`` / ``name=value`` / FortiOS ``set name value``.
_ASSIGN = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<name>password|passwd|pwd|passphrase|secret|client[_-]?secret|"
    r"api[_-]?key|apikey|access[_-]?key|private[_-]?key|token|auth[_-]?token|psk|"
    r"psksecret|pre-shared-key|community)[\"']?(?:\s*[:=]\s*|\s+)"
    r"[\"']?(?P<value>[^\s\"'`,;)]{6,})", re.I)

_PLACEHOLDER = re.compile(
    r"^(?:<.*>|\[.*\]|\{.*\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_]+%|\*+|x+|\.+|-+|"
    r"(?:your|my|the|some|new|old|a|an)[-_]?(?:pass\w*|secret|token|key|api[-_]?key|"
    r"psk|value)s?|changeme|change[-_]?me|example\w*|"
    r"placeholder|redacted|hidden|secret|password|none|null|true|false|enable|disable|"
    r"required|optional|string|value|default|policy|generator|field|setting|rotation|"
    r"manager|expired?|length|reset|requires?|must|should|will|with|from|into|and|for)$",
    re.I)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _looks_like_value(value: str) -> bool:
    """A real secret mixes characters: at least four distinct ones and a
    digit, a symbol or mixed case. Plain lower-case words ("generator",
    "rotation") are prose."""
    if _PLACEHOLDER.match(value) or len(set(value)) < 4:
        return False
    return bool(re.search(r"[0-9]", value) or re.search(r"[^A-Za-z0-9]", value)
                or (re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)))


def scan(text: str | None) -> list[dict]:
    """``[{"kind", "line"}]``, one per finding, in line order. Empty = clean."""
    text = str(text or "")
    found: dict[tuple, dict] = {}
    for kind, rx in SHAPES:
        for m in rx.finditer(text):
            line = _line(text, m.start())
            found.setdefault((kind, line), {"kind": kind, "line": line})
    taken = {f["line"] for f in found.values()}
    for m in _ASSIGN.finditer(text):
        value = m.group("value").rstrip(".")
        line = _line(text, m.start())
        if line in taken or not _looks_like_value(value):
            continue
        kind = "%s value" % m.group("name").lower().replace("_", " ")
        found[(kind, line)] = {"kind": kind, "line": line}
        taken.add(line)
    return sorted(found.values(), key=lambda f: (f["line"], f["kind"]))


def summary(findings: list[dict]) -> str:
    return "; ".join("%s on line %d" % (f["kind"], f["line"]) for f in findings)


REDACTED = "***"


def redact(text: str | None) -> str:
    """``text`` with every credential-shaped value replaced by ``***``.

    The same shapes and assignments :func:`scan` reports, applied in place:
    a whole PEM block or token becomes ``***``; ``password=hunter2x!`` becomes
    ``password=***``. Used where text from a device is shown on a page (the
    syslog receiver's recent messages): a login line that quotes a secret must
    not reach a screen, and the message with the value blanked is still
    readable evidence.
    """
    text = str(text or "")
    if not text:
        return text
    for _kind, rx in SHAPES:
        text = rx.sub(REDACTED, text)

    def _blank(m):
        if not _looks_like_value(m.group("value").rstrip(".")):
            return m.group(0)
        start, end = m.start("value") - m.start(), m.end("value") - m.start()
        whole = m.group(0)
        return whole[:start] + REDACTED + whole[end:]

    return _ASSIGN.sub(_blank, text)
