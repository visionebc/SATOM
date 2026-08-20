"""Vulnerability intelligence — a LOCAL mirror, read-only in the incident path.

The rule this module exists to enforce
--------------------------------------
**No third party is contacted while handling an incident.** Ever. A live
lookup — "is CVE-2024-1234 exploited?" — asked of a vendor at the moment an
attack fires tells that vendor, in real time, which vulnerabilities this
fleet is being attacked with and which it cares about. That is a continuously
updated map of the customer's attack surface, exported as a side effect of
defending it. The latency argument (a network call inside a hot path) is real
but secondary; the disclosure argument is the one that decides.

So there are two components with a wall between them:

* :func:`lookup`, :func:`enrich_cves` — used by the pipeline, touch the
  ``sentinel_vuln`` table and nothing else. There is no HTTP client reachable
  from them, which is asserted by a test rather than promised by a comment.
* :func:`sync` — a scheduled batch, OFF by default, gated on its own separate
  setting, and the only code here that opens a socket.

Why EPSS and KEV outrank CVSS
-----------------------------
CVSS scores how bad a vulnerability would be if exploited. EPSS estimates
whether it actually will be, and CISA's KEV list records that it already has
been. A CVSS 9.8 nobody has ever exploited is a worse use of an operator's
night than a 7.5 on the KEV list with a Metasploit module. The scoring layer
weights them in that order, and this module surfaces all three so the choice
is visible rather than buried.

Staleness is reported, never hidden
-----------------------------------
A mirror older than the configured horizon still enriches — old intelligence
beats none — but every incident it touches says so. Silently presenting
month-old exploit data as current is the failure this product keeps meeting in
other guises (a probe that cannot answer looking healthy).
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from ...models import db
from ...models_sentinel import SentinelSignatureCve, SentinelVuln
from . import config

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

VULNERS_URL = "https://vulners.com/api/v3/search/id/"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


# --------------------------------------------------------------------------- #
#  Read path — the ONLY path the incident pipeline may use                      #
# --------------------------------------------------------------------------- #
def lookup(cve: str) -> "SentinelVuln | None":
    """One CVE from the local mirror. Never leaves this node."""
    if not cve:
        return None
    return SentinelVuln.query.filter_by(cve=cve.upper()).first()


def cves_for_signature(signature_id: str) -> list:
    """Fallback mapping for entries the device did not annotate itself.

    The primary source is ``signature_cve_id`` ON THE EVENT — the vendor's own
    statement about its own signature, which no local table can improve on.
    This table covers the rest, and is data (operator-editable) rather than
    code so a wrong mapping is fixable without a release.
    """
    if not signature_id:
        return []
    rows = SentinelSignatureCve.query.filter_by(signature_id=signature_id).all()
    return [r.cve for r in rows]


def is_stale(row: "SentinelVuln") -> bool:
    if row is None or row.fetched_at is None:
        return True
    days = int(config.get("vuln_stale_days"))
    return row.fetched_at < datetime.utcnow() - timedelta(days=days)


def enrich_cves(cve_ids: list, *, cpe_hints: list | None = None) -> dict:
    """Resolve a list of CVE ids into the incident's ``vuln`` evidence block.

    ``target_vulnerable`` is only ``True`` when a CVE's affected-CPE list
    actually intersects what we believe the target runs. That cross-check is
    the single largest false-positive reducer available here: an exploit aimed
    at a product the backend does not run is noise, however severe the CVE.
    Absent a CPE hint the answer is ``False`` with ``cpe_known=False`` beside
    it — "we could not check" is reported as itself, never as "not vulnerable".
    """
    if not config.get("vuln_enabled"):
        return {"enabled": False, "cves": [], "worst": None,
                "exploit_available": False, "target_vulnerable": False,
                "cpe_known": bool(cpe_hints), "stale": False, "missing": []}

    hints = [h.lower() for h in (cpe_hints or []) if h]
    out, missing, stale_any = [], [], False
    exploit = False
    vulnerable = False
    worst = None
    for cve in dict.fromkeys(c.upper() for c in cve_ids if c):
        row = lookup(cve)
        if row is None:
            missing.append(cve)
            continue
        stale = is_stale(row)
        stale_any = stale_any or stale
        matched = _cpe_match(row.affected_cpe, hints) if hints else False
        item = dict(row.to_dict(), stale=stale, cpe_matched=matched)
        out.append(item)
        exploit = exploit or row.exploit_available
        vulnerable = vulnerable or matched
        if worst is None or _rank(item) > _rank(worst):
            worst = item
    return {"enabled": True, "cves": out, "worst": worst,
            "exploit_available": exploit, "target_vulnerable": vulnerable,
            "cpe_known": bool(hints), "stale": stale_any, "missing": missing}


def _rank(item: dict) -> tuple:
    """Ordering for 'worst CVE': exploited-in-the-wild first, then likelihood,
    then severity. Deliberately NOT cvss-first — see the module docstring."""
    return (1 if item.get("in_kev") else 0,
            1 if item.get("exploit_available") else 0,
            float(item.get("epss") or 0.0),
            float(item.get("cvss") or 0.0))


def _cpe_match(affected: list, hints: list) -> bool:
    """Substring match both ways, on purpose.

    Real CPE strings are long and version-qualified
    (``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``) while an asset hint
    is usually short (``apache:http_server``). Requiring equality would make
    the check never fire, which reads as "nothing is vulnerable" — the most
    dangerous possible way for this function to be wrong.
    """
    for a in affected or []:
        al = str(a).lower()
        for h in hints:
            if h and (h in al or al in h):
                return True
    return False


def mirror_health() -> dict:
    """What the console shows about the mirror. ``count`` alone would let an
    empty-but-recently-synced mirror look identical to a full one."""
    total = SentinelVuln.query.count()
    kev = SentinelVuln.query.filter_by(in_kev=True).count()
    newest = db.session.query(db.func.max(SentinelVuln.fetched_at)).scalar()
    days = int(config.get("vuln_stale_days"))
    stale = bool(newest is None or
                 newest < datetime.utcnow() - timedelta(days=days))
    return {"total": total, "kev": kev,
            "mappings": SentinelSignatureCve.query.count(),
            "newest": newest.isoformat(timespec="seconds") if newest else "",
            "stale": stale, "stale_days": days,
            "sync_enabled": bool(config.get("vuln_sync_enabled")),
            "source": config.get("vuln_source")}


# --------------------------------------------------------------------------- #
#  Write path — manual entry and the scheduled sync                             #
# --------------------------------------------------------------------------- #
def upsert(cve: str, **fields) -> "SentinelVuln":
    """Insert or update one CVE. Used by the sync, by the importer, and by the
    operator's manual entry — one writer, so the three cannot drift."""
    cve = (cve or "").upper()
    if not CVE_RE.fullmatch(cve):
        raise ValueError(f"not a CVE id: {cve!r}")
    row = SentinelVuln.query.filter_by(cve=cve).first()
    if row is None:
        row = SentinelVuln(cve=cve)
        db.session.add(row)
    for key in ("cvss", "cvss_vector", "epss", "in_kev", "summary", "source"):
        if key in fields and fields[key] is not None:
            setattr(row, key, fields[key])
    if fields.get("exploit_refs") is not None:
        row.exploit_refs = list(fields["exploit_refs"])
    if fields.get("affected_cpe") is not None:
        row.affected_cpe = list(fields["affected_cpe"])
    row.fetched_at = datetime.utcnow()
    return row


def map_signature(signature_id: str, cve: str, *, product: str = "",
                  source: str = "manual") -> "SentinelSignatureCve":
    cve = (cve or "").upper()
    if not CVE_RE.fullmatch(cve):
        raise ValueError(f"not a CVE id: {cve!r}")
    row = SentinelSignatureCve.query.filter_by(signature_id=signature_id,
                                               cve=cve).first()
    if row is None:
        row = SentinelSignatureCve(signature_id=signature_id, cve=cve)
        db.session.add(row)
    row.product = product or row.product
    row.source = source
    return row


def _fetch_json(url: str, payload: dict | None = None, timeout: float = 30.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json",
                 "User-Agent": "SATOM-Sentinel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def sync(cve_ids: list | None = None, *, limit: int = 500) -> dict:
    """Refresh the mirror. THE ONLY function here that opens a socket.

    Refuses to run unless ``vuln_sync_enabled`` is on — a separate switch from
    ``vuln_enabled`` precisely so that "use vulnerability intelligence" and
    "talk to the internet" are two different decisions an operator makes
    separately.

    Default subject: the CVEs this installation has actually SEEN (referenced
    by an event or a mapping) and does not yet hold. Pulling a full vendor
    catalogue would be both enormous and a broader disclosure than necessary.
    """
    if not config.get("vuln_sync_enabled"):
        return {"ok": False, "reason": "sync disabled",
                "detail": "sentinel.vuln_sync_enabled is off — the mirror is "
                          "read-only on this node.", "updated": 0}

    wanted = [c.upper() for c in (cve_ids or _wanted_cves(limit)) if c]
    if not wanted:
        return {"ok": True, "updated": 0, "kev": 0,
                "detail": "nothing to fetch — every seen CVE is already mirrored"}

    updated = kev_n = 0
    errors = []

    # KEV first: it is a free, keyless, authoritative statement about
    # exploitation, and it is the field that most changes an operator's night.
    kev_set = set()
    try:
        feed = _fetch_json(KEV_URL, timeout=45.0)
        kev_set = {str(v.get("cveID", "")).upper()
                   for v in (feed.get("vulnerabilities") or [])}
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        errors.append(f"kev: {exc}")

    source = config.get("vuln_source")
    details = {}
    if source == "vulners":
        key = config.get("vuln_api_key")
        if not key:
            errors.append("vulners: no API key configured")
        else:
            try:
                res = _fetch_json(VULNERS_URL,
                                  {"id": wanted[:limit], "apiKey": key},
                                  timeout=60.0)
                details = ((res.get("data") or {}).get("documents") or {})
            except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
                errors.append(f"vulners: {exc}")

    for cve in wanted:
        doc = details.get(cve) or details.get(cve.lower()) or {}
        in_kev = cve in kev_set
        if not doc and not in_kev:
            continue
        upsert(cve,
               cvss=_cvss_of(doc), summary=(doc.get("description") or "")[:4000],
               exploit_refs=_exploit_refs(doc), affected_cpe=doc.get("cpe") or [],
               in_kev=in_kev, source=source)
        updated += 1
        kev_n += 1 if in_kev else 0
    db.session.commit()
    return {"ok": not errors, "updated": updated, "kev": kev_n,
            "requested": len(wanted), "errors": errors,
            "detail": f"{updated} CVE(s) refreshed, {kev_n} on the KEV list"}


def _cvss_of(doc: dict):
    cvss = doc.get("cvss") or {}
    if isinstance(cvss, dict) and cvss.get("score") is not None:
        try:
            return float(cvss["score"])
        except (TypeError, ValueError):
            return None
    return None


def _exploit_refs(doc: dict) -> list:
    refs = []
    for item in (doc.get("references") or []):
        s = str(item)
        if any(k in s.lower() for k in ("exploit", "metasploit", "poc",
                                        "github.com")):
            refs.append(s[:300])
    return refs[:20]


def _wanted_cves(limit: int) -> list:
    """CVEs referenced by this installation's own data but not yet mirrored."""
    from ...models_sentinel import SentinelEvent
    seen: set = set()
    for (raw,) in db.session.query(SentinelEvent.raw_json).limit(20000):
        for m in CVE_RE.findall(raw or ""):
            seen.add(m.upper())
    for (cve,) in db.session.query(SentinelSignatureCve.cve):
        seen.add((cve or "").upper())
    have = {c for (c,) in db.session.query(SentinelVuln.cve)}
    return sorted(seen - have)[:limit]
