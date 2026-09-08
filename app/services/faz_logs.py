"""FortiAnalyzer ``logview`` search — the ONE author of that JSON-RPC route.

Why this module exists as a separate thing
------------------------------------------
Two features need the collector's logs and they ask it opposite questions:

* :mod:`app.services.sentinel.edge` asks *"did the border ever see this source
  address?"* — corroboration of an attacker.
* :mod:`app.services.scout_ladder` asks *"what happened to the flow from this
  appliance to this backend?"* — the fault mode of a path.

The QUESTION differs; the transport does not. Letting each own its own copy of
``add /logview/.../logsearch -> tid`` then ``get .../<tid>`` would give this
product two authors of one wire protocol, and the second one would be the one
that never gets fixed when a firmware changes the shape. So the transport
lives here and both callers pass their own filter.

EVERY FAILURE IS AN ERROR, NEVER AN EMPTY LIST
    A device refusal rendered as zero rows is a refusal that gets read as
    evidence of absence. That is the FortiWeb license-lock lesson, and it is
    the reason :func:`search` returns ``(rows, error)`` and never raises.

UNVERIFIED AGAINST HARDWARE, AND IT SAYS SO
    The only FortiAnalyzer registered in this fleet (``faz01``) is retired and
    answers on a ``.invalid`` host, so this route has never been proved against
    a live collector. Callers must therefore degrade to "we could not look" —
    never to "nothing was there".
"""
from __future__ import annotations

from datetime import datetime

#: The two JSON-RPC routes. NOT registry-resolved: every FortiAnalyzer entry in
#: ``endpoints_fortianalyzer.yaml`` is pinned to ``adom/root``, and choosing the
#: ADOM is the whole point — resolving through the registry would silently query
#: the wrong ADOM, which returns zero rows, which reads exactly like "the
#: collector never saw this flow".
SEARCH_URL = "/logview/adom/{adom}/logsearch"
FETCH_URL = "/logview/adom/{adom}/logsearch/{tid}"

MECHANISM = (
    "add /logview/adom/<adom>/logsearch {device: [{devid, vdom}], filter, "
    "logtype, time-range: {start, end}} -> tid; then "
    "get /logview/adom/<adom>/logsearch/<tid> {offset, limit} -> rows. "
    "READ ONLY: no add/set/delete is ever issued against a FortiGate."
)

DEFAULT_TIMEOUT = 20.0
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000

#: A collector that is neutralised or parked is not a collector that is silent.
#: The eligibility rule lives HERE and not only in each caller, because that is
#: precisely how the deep monitors spent months probing recycled addresses: the
#: rule was in one entry point and a second entry point simply did not have it.
def reachable(analyzer) -> tuple[bool, str]:
    """``(may_probe, why_not)`` for a FortiAnalyzer row."""
    if analyzer is None:
        return False, "no FortiAnalyzer selected"
    if str(getattr(analyzer, "kind", "") or "") != "fortianalyzer":
        return False, "the selected appliance is not a FortiAnalyzer"
    if getattr(analyzer, "maintenance", False):
        return False, "analyzer is in maintenance"
    if str(getattr(analyzer, "host", "") or "").endswith(".invalid"):
        return False, "analyzer host is neutralised (.invalid)"
    return True, ""


def fmt_time(dt: datetime) -> str:
    """The collector's wall-clock format. One author, so both callers agree."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def device_selector(devid: str = "", vdom: str = "") -> list:
    """FortiAnalyzer's ``device`` parameter.

    An EMPTY list means "every device in the ADOM", which is the correct
    reading of an unset FortiGate name — not "no devices". Sending an entry
    with an empty ``devid`` instead asks the collector for a device called
    ``""`` and returns nothing, which is indistinguishable from a flow the
    collector genuinely never saw.
    """
    devid = str(devid or "").strip()
    if not devid:
        return []
    entry = {"devid": devid}
    vdom = str(vdom or "").strip()
    if vdom:
        entry["vdom"] = vdom
    return [entry]


def search(analyzer, *, adom: str = "root", devices=None, log_filter: str = "",
           logtype: str = "traffic", start: datetime, end: datetime,
           limit: int = DEFAULT_LIMIT, timeout: float = DEFAULT_TIMEOUT,
           client_factory=None):
    """``(rows, error)`` — never raises, and never reports failure as ``[]``.

    ``client_factory`` exists so a caller can be tested without a collector.
    It is NOT a place to put a second transport: it must return something with
    ``call(verb, url, **params) -> (data, error)`` and ``logout()``.
    """
    adom = (str(adom or "root").strip() or "root")
    try:
        limit = max(1, min(int(limit), MAX_LIMIT))
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT

    if client_factory is None:
        def client_factory(_a, _t):
            from ..clients.fortianalyzer import FortiAnalyzerClient
            return FortiAnalyzerClient(_a, timeout=_t)

    client = None
    try:
        client = client_factory(analyzer, float(timeout))
        data, err = client.call(
            "add", SEARCH_URL.format(adom=adom),
            device=list(devices or []),
            filter=str(log_filter or ""),
            logtype=str(logtype or "traffic"),
            **{"time-range": {"start": fmt_time(start), "end": fmt_time(end)}},
        )
        if err:
            return [], "logsearch refused: %s" % err
        tid = (data or {}).get("tid") if isinstance(data, dict) else None
        if not tid:
            return [], "logsearch returned no task id"
        out, err = client.call("get", FETCH_URL.format(adom=adom, tid=tid),
                               offset=0, limit=limit)
        if err:
            return [], "logsearch fetch refused: %s" % err
        if isinstance(out, dict):
            out = out.get("data") or []
        return (out if isinstance(out, list) else []), None
    except Exception as exc:                      # noqa: BLE001 — transport
        return [], "%s: %s" % (type(exc).__name__, exc)[:280]
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:                     # noqa: BLE001
                pass


__all__ = ["SEARCH_URL", "FETCH_URL", "MECHANISM", "DEFAULT_TIMEOUT",
           "DEFAULT_LIMIT", "MAX_LIMIT", "reachable", "fmt_time",
           "device_selector", "search"]
