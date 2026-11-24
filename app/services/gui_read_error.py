"""One sentence for "the device could not be read", for every product.

A page that cannot read its object says what actually happened, in one of
three ways (plus the two shapes that are not a failure of the device):

* ``unreachable``  -- nothing answered (timeout, TLS, connection refused);
* ``not_served``   -- the build does not serve this object over REST;
* ``device_error`` -- the device ANSWERED and said no: HTTP status, errcode and
  its own message ("HTTP 200, Invalid VM License");
* ``empty``        -- the device answered and returned no object.

FortiWeb builds the pieces itself (``workspace._read_form_object`` reads the
status and the errcode from the response). The other products' clients hand
the page one free-text ``error`` string (``HTTP 404``, ``401 unauthorized ...``,
``device refused: Invalid VM License``, ``ConnectTimeout: ...``,
``code -11: ...``): :func:`describe` reads that string back into the same
pieces, so FortiADC, FortiGate, FortiAnalyzer and FortiAuthenticator print the
same wording as FortiWeb and never "did not answer: device refused".
"""
from __future__ import annotations

import re

from flask_babel import gettext as _

KINDS = ("unreachable", "not_served", "device_error", "empty", "unknown")


def _code(status=None, errcode=None, message="") -> str:
    return ", ".join(x for x in (
        ("HTTP %s" % status) if status else "",
        ("errcode %s" % errcode) if errcode not in (None, "", 0, "0") else "",
        str(message or "").strip()[:200]) if x)


def sentence(kind: str, dev: str, status=None, errcode=None, message="", *, library=True) -> str:
    """The one wording per kind. ``dev`` is the appliance name; ``library`` says
    the API library (not only the device's answer) established that the build
    lacks the object -- FortiWeb's form read; the other products only have the
    device's answer."""
    code = _code(status, errcode, message)
    if kind == "unreachable":
        return _("%(dev)s is unreachable: %(why)s", dev=dev, why=code or _("no answer"))
    if kind == "not_served" and not library:
        return _("%(dev)s's build does not serve this object over REST; the device answered: %(code)s",
                 dev=dev, code=code or "-")
    if kind == "not_served":
        return _("The API library says %(dev)s's build does not serve this object over REST "
                 "(measured); the device answered: %(code)s", dev=dev, code=code or "-")
    if kind == "empty":
        return _("%(dev)s answered but returned no object (%(code)s).", dev=dev, code=code or "HTTP 200")
    if kind == "unknown":
        return _("%(dev)s could not be read: %(why)s", dev=dev, why=code or "-")
    return _("%(dev)s refused the read: %(code)s", dev=dev, code=code or "-")


def failure(kind: str, dev: str, status=None, errcode=None, message="", *, library=True) -> dict:
    """``{kind, status, errcode, message, text}``: the shape the form read prints."""
    return {"kind": kind, "status": status, "errcode": errcode,
            "message": str(message or "")[:200],
            "text": sentence(kind, dev, status, errcode, message, library=library)}


_HTTP = re.compile(r"^(?:HTTP\s+)?(\d{3})\b\s*(?:[-:—–]+\s*)?(.*)$", re.S)
_ERRCODE = re.compile(r"^device errcode\s+(-?\d+)\s*$", re.I)
_CODE_N = re.compile(r"^(?:device\s+)?code\s+(-?\d+)\s*:\s*(.*)$", re.S | re.I)
_REFUSED = re.compile(r"^device refused:\s*(.*)$", re.S | re.I)
_MESSAGE = re.compile(r"^device returned a message instead of data:\s*(.*)$", re.S | re.I)
_TRANSPORT = re.compile(r"^[A-Za-z_][\w.]*(?:Error|Exception|Timeout|Refused|Reset|Unreachable)\b"
                        r"|\bMax retries exceeded\b|\btimed out\b|\bName or service not known\b"
                        r"|\bNo route to host\b|\bConnection (?:refused|reset|aborted)\b", re.I)
#: an HTTP 404 that says the path does not exist (not "this object is not there")
_NO_RESOURCE = re.compile(r"no such resource|not found", re.I)


def classify(err) -> tuple:
    """``(kind, status, errcode, message)`` of a client's free-text ``error``.
    The status is filled only where the client's own code proves it (the ADC
    refusals are read from an HTTP 200 body)."""
    text = " ".join(str(err or "").split())
    if not text:
        return "unknown", None, None, ""
    m = _REFUSED.match(text) or _MESSAGE.match(text)
    if m:
        return "device_error", 200, None, m.group(1).strip()
    m = _ERRCODE.match(text)
    if m:
        return "device_error", 200, m.group(1), ""
    m = _CODE_N.match(text)
    if m:
        return "device_error", None, m.group(1), m.group(2).strip()
    m = _HTTP.match(text)
    if m:
        status, rest = int(m.group(1)), m.group(2).strip()
        if status == 404 and (not rest or _NO_RESOURCE.search(rest)) and "no such object" not in rest:
            return "not_served", status, None, rest
        return "device_error", status, None, rest
    if _TRANSPORT.search(text):
        return "unreachable", None, None, text
    if text.lower().startswith("unparseable response body") or text.lower() == "unexpected result shape":
        return "device_error", None, None, text
    return "unknown", None, None, text


def describe(dev: str, err) -> dict:
    """The failure of one read whose only record is the client's ``error`` text."""
    kind, status, errcode, message = classify(err)
    return failure(kind, dev, status, errcode, message, library=False)


__all__ = ["KINDS", "sentence", "failure", "classify", "describe"]
