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

#: Refusals that only an EXPLICIT pick can produce. Kept apart from the three
#: above because they are answers to a different question — not "what does the
#: configuration imply" but "can the thing you named actually do this" — and
#: every one of them has its own fix.
UNKNOWN = "backend_unknown"            # the picked row is not in the registry
DISABLED = "backend_disabled"          # picked, but switched off
WRONG_ROLE = "backend_wrong_role"      # picked, but never given that role
OUT_OF_SCOPE = "backend_out_of_scope"  # picked, but its scope excludes this


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


def pool_matches(declared: list, query: str) -> bool:
    """Does a declared pool list claim ``query``? The ONE author of that test.

    Exact and CASE-PRESERVING on both sides. ``split_list`` deliberately
    refuses to fold pool identifiers, because a provider-native id may differ
    only in case; a matcher that lowered the query while the store preserved
    the declaration could never match a pool with a capital letter in it, and
    that is exactly what this function replaced (a backend scoped to
    ``Prod-DMZ`` resolved to NO_MATCH for the pool ``Prod-DMZ``).
    """
    q = (query or "").strip()
    if not q:
        return False
    return q in [str(d).strip() for d in (declared or [])]


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
    query = (pool or "").strip()
    cands: list[tuple[int, object]] = []
    for row in rows:
        declared = row.pool_list()
        if not declared:
            cands.append((-1, row))
            continue
        if pool_matches(declared, query):
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


def claims(row, role: str, query: str) -> bool:
    """Does this row's declared scope cover ``query`` for ``role``?

    Reads the scope the SAME way ``resolve_dns`` / ``resolve_ipam`` do —
    empty means catch-all, zones by specificity, pools exactly — instead of
    re-deriving it, so an explicit pick and an automatic resolution can never
    disagree about what one row claims.
    """
    if role == "ipam":
        declared = row.pool_list()
        return True if not declared else pool_matches(declared, query)
    declared = row.zone_list()
    if not declared:
        return True
    return max(zone_specificity(d, query) for d in declared) >= 0


def choose(role: str, query: str = "", backend_id: object = None) -> Resolution:
    """Resolve ``role`` for ``query``, honouring the operator's explicit pick.

    An empty ``backend_id`` means AUTO and is byte-for-byte ``resolve_*`` —
    the default behaviour of an install that never picks anything is
    unchanged, which is what lets the selector be additive.

    A pick is an operator declaration, and it is CHECKED against the same
    rules rather than trusted: the row must exist, be enabled, carry the role
    and claim the query.

    **An invalid pick is refused, never quietly downgraded to AUTO.** A
    fallback would hand the work to a backend nobody named while the page
    still showed the one that was chosen — silent substitution, which is the
    single failure this module exists to prevent. It is also why the pick
    cannot widen a scope: the scope is an earlier declaration by the same
    operator, and the wizard is not the place to overrule it by accident.
    """
    auto = resolve_ipam if role == "ipam" else resolve_dns
    if backend_id in (None, "", 0, "0"):
        return auto(query)
    row = backend_by_id(backend_id)
    if row is None:
        return Resolution(code=UNKNOWN, detail=(
            f"backend id {backend_id} is not in the registry — it was most "
            "likely deleted after this page was opened; reload and choose "
            "again"))
    if not row.enabled:
        return Resolution(code=DISABLED, detail=(
            f"{row.name} is disabled (Settings -> DNS Records)"))
    if (role == "ipam" and not row.role_ipam) or \
       (role == "dns" and not row.role_dns):
        return Resolution(code=WRONG_ROLE, detail=(
            f"{row.name} does not carry the {role.upper()} role — give it "
            f"that role in Settings -> DNS Records, or choose another "
            f"backend"))
    if not claims(row, role, query):
        declared = row.pool_list() if role == "ipam" else row.zone_list()
        return Resolution(code=OUT_OF_SCOPE, detail=(
            f"{row.name} was chosen for {query or '(nothing)'!r} but its "
            f"declared scope is {', '.join(declared)} — widen that scope in "
            f"Settings -> DNS Records, or choose a backend that claims it"))
    return Resolution(backend=row)
