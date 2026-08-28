"""Which backend answers this question — the ONLY author of that decision.

With one provider there was nothing to decide. With N there is, and the whole
value of this module is that the decision lives in exactly one place. Three
independent resolvers of a segment name disagreed on 2026-08-27 and built a
policy describing one row's network while allocating from another's; the same
shape here would publish a name in the wrong zone or take an address from a
pool that belongs to a different customer. Every consumer routes through
:func:`resolve_dns` / :func:`resolve_ipam`.

The rules, in order:

1. **Role first.** Only backends the operator marked for that role are
   candidates. A backend that could do the job but was not given the role is
   not a candidate — the role is the operator's declaration and it wins over
   what the software thinks the box is capable of.
2. **Specificity beats priority.** A backend declaring ``sub.example.com``
   answers ``www.sub.example.com``; one declaring ``example.com`` does not get
   a look in. Declaring nothing is CATCH-ALL and ranks below every explicit
   claim, so a single-backend install (which declares nothing) keeps working
   unchanged.
3. **Priority breaks ties between equals**, lowest number first. It is an
   explicit operator decision, so honouring it is not guessing.
4. **A tie on both is a REFUSAL, never a pick.** Two backends claiming the
   same zone at the same priority is a configuration the operator has to
   resolve. Choosing one of them silently is precisely the bug this module
   exists to prevent, and "the first row" is not an answer anybody declared.

Nothing here raises. A caller gets a :class:`Resolution` and decides whether
its problem is fatal — a provisioning run that never asked for a hostname does
not care that no backend claims the zone, and that judgement is not this
module's to make (the rule §130 was restored on).
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Refusal codes. Stable strings: blockers, run steps and tests name them.
NO_BACKEND = "no_backend"        # nothing enabled carries the role at all
NO_MATCH = "no_match"            # backends exist, none claims this zone/pool
AMBIGUOUS = "ambiguous"          # two equal claims — the operator must choose


@dataclass
class Resolution:
    """The chosen backend, or exactly why there is not one."""

    backend: object = None          # DnsBackend row, or None
    code: str = ""                  # "" when resolved
    detail: str = ""
    candidates: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.backend is not None

    def as_dict(self) -> dict:
        return {
            "backend_id": getattr(self.backend, "id", None),
            "backend": getattr(self.backend, "name", ""),
            "code": self.code, "detail": self.detail,
            "candidates": list(self.candidates),
        }


def _rows():
    from ...models_dnsbackend import DnsBackend
    try:
        return DnsBackend.query.order_by(DnsBackend.priority.asc(),
                                         DnsBackend.id.asc()).all()
    except Exception:  # noqa: BLE001 — table absent on a pre-migration boot
        return []


def enabled_backends(role: str = "") -> list:
    """Enabled rows, optionally filtered to a role. Ordered by priority, id."""
    out = []
    for row in _rows():
        if not row.enabled:
            continue
        if role == "dns" and not row.role_dns:
            continue
        if role == "ipam" and not row.role_ipam:
            continue
        out.append(row)
    return out


def zone_specificity(declared: str, query: str) -> int:
    """How well ``declared`` covers ``query``; -1 when it does not cover it.

    A zone covers a name when they are equal or the name is a subdomain of it.
    ``example.com`` must NOT cover ``notexample.com``, which is why the test is
    on ``"." + declared`` and not a bare ``endswith``.
    """
    d = (declared or "").strip().rstrip(".").lower()
    q = (query or "").strip().rstrip(".").lower()
    if not d or not q:
        return -1
    if q == d or q.endswith("." + d):
        return d.count(".") + 1
    return -1


def _pick(cands: list[tuple[int, object]], what: str, query: str) -> Resolution:
    """Best of ``(specificity, row)``; a tie on specificity AND priority refuses."""
    if not cands:
        return Resolution(code=NO_MATCH, detail=(
            f"no enabled {what} backend claims {query!r}, and none is "
            f"configured as a catch-all (a backend with no {what} scope "
            f"declared answers anything)"))
    best = max(spec for spec, _row in cands)
    top = [row for spec, row in cands if spec == best]
    if len(top) > 1:
        best_prio = min(r.priority for r in top)
        top = [r for r in top if r.priority == best_prio]
    if len(top) > 1:
        names = sorted(r.name for r in top)
        return Resolution(code=AMBIGUOUS, candidates=names, detail=(
            f"{len(top)} backends claim {query!r} with the same scope and the "
            f"same priority ({', '.join(names)}) — nothing in the "
            f"configuration says which one should answer. Give one of them a "
            f"lower priority number, or narrow its scope."))
    return Resolution(backend=top[0])


def resolve_dns(name_or_zone: str = "") -> Resolution:
    """Which backend publishes records for this FQDN (or zone)."""
    rows = enabled_backends("dns")
    if not rows:
        return Resolution(code=NO_BACKEND, detail=(
            "no enabled backend carries the DNS role (Settings -> DNS "
            "Records)"))
    query = (name_or_zone or "").strip().rstrip(".").lower()
    cands: list[tuple[int, object]] = []
    for row in rows:
        declared = row.zone_list()
        if not declared:
            cands.append((-1, row))       # catch-all, ranks below every claim
            continue
        # With no name to match, an explicit zone claim cannot be checked
        # and only a catch-all can honestly answer. That is not enforced here:
        # ``zone_specificity`` already returns -1 for an empty query, so the
        # test below is its ONLY author. An early ``continue`` saying the same
        # thing was dead code, and a second author of one rule is exactly what
        # this module exists to remove.
        spec = max(zone_specificity(d, query) for d in declared)
        if spec >= 0:
            cands.append((spec, row))
    return _pick(cands, "DNS", query or "(no zone given)")


def resolve_ipam(pool: str = "") -> Resolution:
    """Which backend hands out addresses from this pool.

    Pool identifiers are matched EXACTLY, never by network containment. A pool
    is provider-native and may be a subnet id (``42``) or a name, not only a
    CIDR, so treating ``10.30.0.0/16`` as covering ``10.30.20.0/22`` would be
    arithmetic applied to a string that may not be an address at all. A site
    that wants that grouping declares the specific pools; a site with one
    backend declares none and every pool resolves to it.
    """
    rows = enabled_backends("ipam")
    if not rows:
        return Resolution(code=NO_BACKEND, detail=(
            "no enabled backend carries the IPAM role (Settings -> DNS "
            "Records)"))
    query = (pool or "").strip().lower()
    cands: list[tuple[int, object]] = []
    for row in rows:
        declared = row.pool_list()
        if not declared:
            cands.append((-1, row))
            continue
        if query and query in declared:
            cands.append((1, row))
    return _pick(cands, "IPAM", pool or "(no pool given)")


def backend_by_id(backend_id: object):
    """The row with this id, or None. Used to honour a RECORDED choice."""
    from ...models_dnsbackend import DnsBackend
    try:
        bid = int(str(backend_id).strip())
    except (TypeError, ValueError):
        return None
    try:
        return DnsBackend.query.get(bid)
    except Exception:  # noqa: BLE001
        return None
