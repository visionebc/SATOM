"""Border corroboration — does the FortiGate agree that this source exists?

Why this layer exists
---------------------
FortiWeb reports the source of an attack. WHICH source it reports depends on
whether the policy reads ``X-Forwarded-For``:

* XFF on  — the log carries the TRUE client, and the FortiGate in front never
  saw that address as a peer. It saw the CDN.
* XFF off — the log carries whatever opened the connection, which behind a CDN
  is the CDN itself.

Both cases produce a plausible IPv4 address in an attack log, and nothing in
the log distinguishes them. The border can, because a border only ever logs
addresses that actually opened a connection to it.

That is worth two different things, and they are NOT the same thing:

1. **Evidence.** A source the border independently logged in the same window
   is a source that exists. One the border saw reaching many distinct
   destinations is a source that is scanning. Neither fact is obtainable from
   the WAF alone, and both matter most on installations with no hypervisor
   access — where ``vm_anomaly`` and ``host_anomaly`` are structurally
   unavailable and up to 18 points are missing from every score.

2. **A veto.** An address the border never saw is an address a border
   blocklist cannot usefully act on: at best the entry is inert, at worst the
   address is a shared egress and blocking it removes every legitimate client
   behind it. So the answer here GATES the blocklist, and it gates it in the
   safe direction — no answer means no autonomous entry.

"Not corroborated" is never "not an attack"
-------------------------------------------
There is no negative weight in this module and there must not be one. An
attack behind a CDN is still an attack; the border's silence is a fact about
ADDRESSING, not about hostility. Turning it into subtracted points would
systematically under-score exactly the customers who put a CDN in front of
their applications — and it would do so invisibly, because the incident would
still look complete.

Reads only
----------
Nothing in this module issues ``add`` / ``set`` / ``delete`` against a
FortiAnalyzer or a FortiGate. The user's instruction was explicit — the border
receives a list, never a write from this engine — and a guard test asserts the
absence of write verbs here.

Unverified, and says so
-----------------------
:data:`MECHANISM` names the JSON-RPC route this module drives. As of
2026-08-23 it has NOT been proved against a live FortiAnalyzer: the only FAZ
registered in this fleet (``faz01``, appliance id 9) is retired and answers on
a ``.invalid`` host, so there was nothing to run it against. Consequences,
all deliberate:

* every failure degrades to ``corroborated=None`` — "we could not look" —
  never to ``False``;
* the score gains nothing from a call that did not return rows;
* the Context page carries a **Test lookup** button that surfaces the raw
  device refusal, so the first operator with a real FAZ sees the cause instead
  of a feature that is silently inert. That silence is exactly how
  ``metrics.vm_url`` stayed unconfigurable in this product for months.

This is the ``actions.CATALOG`` contract applied to a read: a mechanism
written from a reference manual and never run is a specification, and it is
displayed as one.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from ...models import Appliance
from ...models_sentinel import SentinelEdgeMap
from . import config

#: The JSON-RPC routes this module drives. NOT registry-resolved, and that is
#: on purpose: every FortiAnalyzer entry in ``endpoints_fortianalyzer.yaml``
#: is pinned to ``adom/root``, and letting the operator choose the ADOM is the
#: entire point of this feature. Resolving through the registry would silently
#: query the wrong ADOM on any multi-ADOM collector — which returns zero rows,
#: which reads exactly like "the border never saw this address".
SEARCH_URL = "/logview/adom/{adom}/logsearch"
FETCH_URL = "/logview/adom/{adom}/logsearch/{tid}"

MECHANISM = (
    "add /logview/adom/<adom>/logsearch {device: [{devid, vdom}], "
    "filter: 'srcip=<ip>', logtype, time-range: {start, end}, apiver: 3} "
    "-> tid; then get /logview/adom/<adom>/logsearch/<tid> {offset, limit} "
    "-> rows. READ ONLY: no add/set/delete is ever issued against a FortiGate."
)

#: Verdicts. ``UNKNOWN`` is a first-class answer and outranks a guess.
CORROBORATED = "corroborated"
ABSENT = "absent"
UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
#  Mapping                                                                      #
# --------------------------------------------------------------------------- #
def map_for(appliance_id: int):
    """The edge map row for one protected appliance, or ``None``."""
    if not appliance_id:
        return None
    return SentinelEdgeMap.query.filter_by(appliance_id=appliance_id).first()


def analyzer_of(row):
    """The FortiAnalyzer a map points at, or ``None``.

    The kind is re-checked here instead of trusted from the form: an appliance
    can be re-kinded after the map was saved, and a map that ends up pointing
    at a FortiWeb would drive the JSON-RPC client against a device that does
    not speak JSON-RPC — producing a transport error that reads like a dead
    collector rather than a misconfiguration.
    """
    if row is None or not row.analyzer_id:
        return None
    a = Appliance.query.get(row.analyzer_id)
    if a is None or a.kind != "fortianalyzer":
        return None
    return a


def _reachable(analyzer) -> tuple[bool, str]:
    """Whether this collector may be probed at all.

    The eligibility filter lives HERE, not only in the calling route. The deep
    monitors spent months probing recycled IP addresses every three minutes
    because that rule lived in a caller: a second entry point simply did not
    have it.
    """
    if getattr(analyzer, "maintenance", False):
        return False, "analyzer is in maintenance"
    if str(getattr(analyzer, "host", "") or "").endswith(".invalid"):
        return False, "analyzer host is neutralised (.invalid)"
    return True, ""


# --------------------------------------------------------------------------- #
#  Result shape                                                                 #
# --------------------------------------------------------------------------- #
def blank(reason: str = "", **extra) -> dict:
    """The shape every caller gets, including every failure path.

    One shape, always. A function that returns ``{}`` on failure and a full
    dict on success makes every consumer write ``.get(...)`` defensively, and
    the one that forgets reads a missing key as a falsy answer — which here
    means reading "we could not look" as "the border says no".
    """
    out = {
        "enabled": bool(config.get("edge_enabled")),
        "mapped": False,
        "checked": False,          # did a query actually reach the collector?
        "corroborated": None,      # True / False / None — None means unknown
        "verdict": UNKNOWN,
        "multi_target": False,
        "reason": reason,
        "error": "",
        "analyzer": "", "adom": "", "fortigate": "", "vdom": "",
        "scope": "",
        "hits": 0, "distinct_dst": 0, "distinct_dport": 0, "denied": 0,
        "rows": [],
        "mechanism": MECHANISM,
        "verified": False,
    }
    out.update(extra)
    return out


def _scope_text(row, analyzer) -> str:
    parts = [getattr(analyzer, "name", "") or "?", f"adom {row.adom or 'root'}"]
    parts.append(f"device {row.fortigate}" if row.fortigate else "all devices")
    parts.append(f"vdom {row.vdom}" if row.vdom else "all vdoms")
    return " · ".join(parts)


# --------------------------------------------------------------------------- #
#  The query                                                                    #
# --------------------------------------------------------------------------- #
def _valid_ip(value: str):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _device_selector(row) -> list:
    """FortiAnalyzer's ``device`` parameter.

    An EMPTY list means "every device in the ADOM", which is the correct
    reading of an unset FortiGate name — not "no devices". Sending an entry
    with an empty ``devid`` instead would ask the collector for a device
    called ``""`` and return nothing, which is indistinguishable from a source
    the border never saw.
    """
    if not (row.fortigate or "").strip():
        return []
    entry = {"devid": row.fortigate.strip()}
    if (row.vdom or "").strip():
        entry["vdom"] = row.vdom.strip()
    return [entry]


def _shift(dt: datetime) -> datetime:
    """UTC → the collector's wall clock.

    Sentinel stores event timestamps naive UTC; a FortiAnalyzer answers in its
    own configured timezone. A one-hour mismatch returns zero rows for every
    lookup, forever, and zero rows is the same output as a source the border
    genuinely never saw. That is why the offset is a setting and not an
    assumption.
    """
    return dt + timedelta(minutes=int(config.get("edge_tz_offset_min")))


def lookup(src_ip: str, *, appliance_id: int, t0: datetime,
           pre_s: int | None = None, post_s: int | None = None) -> dict:
    """Ask the border whether it saw ``src_ip`` around ``t0``.

    Never raises, and never reports ``corroborated=False`` for anything other
    than a query that completed and came back empty.
    """
    if not config.get("edge_enabled"):
        return blank("border corroboration is disabled")

    ip = _valid_ip(src_ip)
    if ip is None:
        return blank("source address does not parse")

    row = map_for(appliance_id)
    if row is None:
        return blank("no edge map for this appliance — the border layer is "
                     "not evaluated, which is not the same as clean")

    analyzer = analyzer_of(row)
    if analyzer is None:
        return blank("edge map points at no usable FortiAnalyzer",
                     mapped=True, adom=row.adom or "", vdom=row.vdom or "",
                     fortigate=row.fortigate or "")

    ok, why = _reachable(analyzer)
    scope = _scope_text(row, analyzer)
    common = dict(mapped=True, analyzer=analyzer.name, adom=row.adom or "root",
                  fortigate=row.fortigate or "", vdom=row.vdom or "",
                  scope=scope)
    if not ok:
        return blank(why, **common)

    pre = int(pre_s if pre_s is not None else config.get("window_pre_s"))
    post = int(post_s if post_s is not None else config.get("window_post_s"))
    slack = int(config.get("edge_slack_minutes"))
    start = _shift(t0 - timedelta(seconds=pre) - timedelta(minutes=slack))
    end = _shift(t0 + timedelta(seconds=post) + timedelta(minutes=slack))

    rows, err = _search(analyzer, row, str(ip), start, end)
    if err:
        return blank("", error=err, **common)

    return _summarise(rows, str(ip), **common)


def _search(analyzer, row, ip: str, start: datetime, end: datetime):
    """(rows, error). Every failure surfaces as ``error`` — never as ``[]``.

    The FortiWeb license-lock lesson, applied to a second product: a device
    refusal that masquerades as an empty result set is a refusal that gets
    scored as evidence of absence.
    """
    from ...clients.fortianalyzer import FortiAnalyzerClient

    adom = (row.adom or "root").strip()
    limit = int(config.get("edge_max_rows"))
    client = None
    try:
        client = FortiAnalyzerClient(analyzer, timeout=float(
            config.get("edge_timeout_s")))
        data, err = client.call(
            "add", SEARCH_URL.format(adom=adom),
            device=_device_selector(row),
            filter=f'srcip="{ip}"',
            logtype=(row.logtype or "traffic"),
            **{"time-range": {"start": _fmt(start), "end": _fmt(end)}},
        )
        if err:
            return [], f"logsearch refused: {err}"
        tid = (data or {}).get("tid") if isinstance(data, dict) else None
        if not tid:
            return [], "logsearch returned no task id"
        out, err = client.call("get", FETCH_URL.format(adom=adom, tid=tid),
                               offset=0, limit=limit)
        if err:
            return [], f"logsearch fetch refused: {err}"
        if isinstance(out, dict):
            out = out.get("data") or []
        return (out if isinstance(out, list) else []), None
    except Exception as exc:                      # noqa: BLE001 — transport
        return [], f"{type(exc).__name__}: {exc}"[:280]
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:                     # noqa: BLE001
                pass


def _summarise(rows: list, ip: str, **common) -> dict:
    """Turn raw border log rows into the verdict and its two factors."""
    dsts, dports, denied, hits = set(), set(), 0, 0
    sample = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        # Only rows where the address is the SOURCE corroborate it. A row
        # where it is the destination proves the opposite of what we are
        # asking: something reached out TO it.
        if str(r.get("srcip") or "").strip() != ip:
            continue
        hits += 1
        if r.get("dstip"):
            dsts.add(str(r["dstip"]))
        if r.get("dstport"):
            dports.add(str(r["dstport"]))
        if str(r.get("action") or "").lower() in ("deny", "blocked", "block"):
            denied += 1
        if len(sample) < 10:
            sample.append({k: r.get(k) for k in
                           ("date", "time", "devname", "vd", "srcip",
                            "dstip", "dstport", "service", "action")})

    scan_floor = int(config.get("edge_scan_dst"))
    out = blank("", checked=True, hits=hits, distinct_dst=len(dsts),
                distinct_dport=len(dports), denied=denied, rows=sample,
                **common)
    out["corroborated"] = hits > 0
    out["verdict"] = CORROBORATED if hits else ABSENT
    out["multi_target"] = len(dsts) >= scan_floor
    if not hits:
        out["reason"] = ("the border logged nothing from this address in the "
                         "window — most often it is a client behind a proxy "
                         "or CDN, not a quiet attacker")
    return out



# --------------------------------------------------------------------------- #
#  Operator probe                                                               #
# --------------------------------------------------------------------------- #
def probe(appliance_id: int, ip: str, hours: int = 24) -> dict:
    """Run one lookup NOW, over a wide window, and report what came back.

    This exists because the failure mode of this whole layer is silence. A
    wrong ADOM, a wrong device name, a collector on a different clock and a
    source the border genuinely never saw all produce the same thing — zero
    rows — and only one of those four is a real answer. Without a button that
    shows the raw device refusal, an operator's first evidence that the
    mapping is wrong would be a blocklist that never fills, months later.

    Deliberately NOT the same call path shortened: it reuses :func:`_search`
    so that a defect in the query cannot be present in production and absent
    from the test that is supposed to find it.
    """
    ip_obj = _valid_ip(ip)
    if ip_obj is None:
        return blank("address to test does not parse")
    row = map_for(appliance_id)
    if row is None:
        return blank("no edge map for this appliance")
    analyzer = analyzer_of(row)
    if analyzer is None:
        return blank("edge map points at no usable FortiAnalyzer", mapped=True)
    ok, why = _reachable(analyzer)
    common = dict(mapped=True, analyzer=analyzer.name, adom=row.adom or "root",
                  fortigate=row.fortigate or "", vdom=row.vdom or "",
                  scope=_scope_text(row, analyzer))
    if not ok:
        return blank(why, **common)
    now = datetime.utcnow()
    hours = max(1, min(int(hours or 24), 168))
    rows, err = _search(analyzer, row, str(ip_obj),
                        _shift(now - timedelta(hours=hours)), _shift(now))
    if err:
        return blank("", error=err, **common)
    return _summarise(rows, str(ip_obj), **common)


# --------------------------------------------------------------------------- #
#  The veto                                                                     #
# --------------------------------------------------------------------------- #
def blockable(edge: dict) -> tuple[bool, str]:
    """May a BORDER blocklist carry this address? And if not, why not.

    The default answer is no, and the setting that relaxes it is off-by-safe:
    ``edge_require`` on means an address the border never confirmed never
    reaches the feed. Turning it off is a deliberate decision to accept that
    an entry may be a shared egress — which is a decision an operator is
    entitled to make and this engine is not.
    """
    if not config.get("edge_require"):
        return True, "border corroboration not required by policy"
    e = edge or {}
    if not e.get("enabled"):
        return False, ("border corroboration is required but disabled — "
                       "nothing can be confirmed")
    if not e.get("mapped"):
        return False, ("no edge map for this appliance, so the address cannot "
                       "be confirmed as a real border peer")
    if e.get("error"):
        return False, f"border lookup failed: {e['error']}"
    if not e.get("checked"):
        return False, e.get("reason") or "border was not consulted"
    if not e.get("corroborated"):
        return False, ("the border never logged this address as a source — "
                       "blocking it there is inert at best, and removes every "
                       "client behind a shared egress at worst")
    return True, (f"the border logged {e.get('hits')} entry/entries from this "
                  f"address ({e.get('scope')})")
