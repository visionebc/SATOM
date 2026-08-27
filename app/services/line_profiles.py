"""``line_plan`` — the ONLY place "what does this line get?" is answered.

Everything that needs the answer (the new-policy wizard, the provisioning
form, a future report) calls this. That is not tidiness: three consumers each
string-matching ``segments[].line`` is precisely the shape that produced §127,
where three sites re-derived one verdict under a comment promising they were
identical, and drifted.

**Two sources, never confused.** A plan carries ``source``:

``declared``
    A :class:`~app.models_lineprofile.LineProfile` exists. Its segment names
    are resolved against the live segment list, and a name that resolves to
    nothing becomes a **problem**, not a shorter list. The whole point of
    declaring the relationship is that breaking it is visible.

``inferred``
    No profile exists, so the old string match is used — and SAID SO. Callers
    that are about to change the world (create a policy, reserve an address)
    must treat an inferred plan as a question, not an answer. It exists so the
    feature works on day one against catalogs nobody has declared yet; it is
    not a fallback that quietly does the same job.

There is no third state where a plan is partly declared. A profile that names
zero resolvable segments is a declared plan with zero segments and a problem
explaining why — never an inferred one. Falling back to the guess when the
declaration fails would hide the failure behind an answer that looks fine.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import settings_store as store

#: Problem codes a plan can carry. Codes rather than prose so a caller can
#: decide (block vs warn) without matching on a sentence that may be reworded.
P_MISSING_SEGMENT = "missing_segment"
P_NO_SEGMENTS = "no_segments"
P_NO_CERT_CLASS = "no_cert_class"
P_NO_WPP = "no_wpp"
P_WPP_GONE = "wpp_gone"
P_WPP_NOT_APPROVED = "wpp_not_approved"
P_WPP_WRONG_PRODUCT = "wpp_wrong_product"
P_SEGMENT_NO_CIDR = "segment_no_cidr"

#: Problems that must STOP an action that changes the world. The rest are
#: things the operator can be asked about. Membership is data so a caller
#: cannot invent its own idea of "serious".
BLOCKING = frozenset({P_MISSING_SEGMENT, P_NO_SEGMENTS, P_WPP_GONE,
                      P_WPP_NOT_APPROVED, P_WPP_WRONG_PRODUCT})


@dataclass
class Problem:
    code: str
    detail: str

    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail,
                "blocking": self.code in BLOCKING}


@dataclass
class LinePlan:
    line: str
    product: str
    source: str                                   # 'declared' | 'inferred'
    segments: list[dict] = field(default_factory=list)
    cert_class: str = ""
    wpp_template_id: int | None = None
    wpp_template_name: str = ""
    ipam_pool: str = ""
    problems: list[Problem] = field(default_factory=list)

    @property
    def declared(self) -> bool:
        return self.source == "declared"

    @property
    def blocked(self) -> bool:
        return any(p.code in BLOCKING for p in self.problems)

    def problem_codes(self) -> list[str]:
        return [p.code for p in self.problems]

    def as_dict(self) -> dict:
        return {
            "line": self.line, "product": self.product, "source": self.source,
            "declared": self.declared, "segments": self.segments,
            "cert_class": self.cert_class,
            "wpp_template_id": self.wpp_template_id,
            "wpp_template_name": self.wpp_template_name,
            "ipam_pool": self.ipam_pool, "blocked": self.blocked,
            "problems": [p.as_dict() for p in self.problems],
        }


def _segments_by_name() -> dict[str, dict]:
    """Live segments keyed by name.

    Exact strings, not case-folded: a profile naming ``DMZ`` does not resolve
    a segment called ``dmz``, and pretending otherwise reports a link the rest
    of the system will never make (the same reasoning as
    ``classification_ops.usage``).
    """
    out: dict[str, dict] = {}
    for seg in store.segments():
        name = (seg.get("name") or "").strip()
        if name:
            out.setdefault(name, seg)
    return out


def profile_for(line: str, product: str = "fortiweb"):
    """The stored profile for a line, or None. Never raises on a missing table."""
    from ..models_lineprofile import LineProfile
    line = (line or "").strip()
    if not line:
        return None
    return (LineProfile.query
            .filter(LineProfile.product == product, LineProfile.line == line)
            .first())


def _resolve_wpp(plan: LinePlan, template_id: int | None) -> None:
    """Attach the WPP template, and say exactly why it cannot be used.

    Checked HERE and not stored on the profile because approval moves after
    the profile is written: a template approved on Monday and rejected on
    Tuesday must stop being instantiable on Tuesday.
    """
    if not template_id:
        plan.problems.append(Problem(
            P_NO_WPP, "this line does not name a Web Protection Profile "
                      "template to start from"))
        return
    from ..models import Template
    tpl = db_get(Template, template_id)
    if tpl is None:
        plan.problems.append(Problem(
            P_WPP_GONE, f"the Web Protection Profile template #{template_id} "
                        "this line names no longer exists"))
        return
    plan.wpp_template_id = tpl.id
    plan.wpp_template_name = tpl.name
    if (tpl.product or "") != plan.product:
        plan.problems.append(Problem(
            P_WPP_WRONG_PRODUCT,
            f"template {tpl.name!r} belongs to {tpl.product!r}, not "
            f"{plan.product!r}"))
    if tpl.status != Template.STATUS_APPROVED:
        plan.problems.append(Problem(
            P_WPP_NOT_APPROVED,
            f"template {tpl.name!r} is {tpl.status!r}; only an approved "
            "template may be instantiated onto a device"))


def db_get(model, pk):
    """``Session.get`` without dragging SQLAlchemy version differences into
    every call site."""
    from ..extensions import db
    return db.session.get(model, pk)


def line_plan(line: str, product: str = "fortiweb") -> LinePlan:
    """What ``line`` receives — declared if anyone said so, inferred if not."""
    line = (line or "").strip()
    plan = LinePlan(line=line, product=product, source="inferred")
    if not line:
        plan.problems.append(Problem(P_NO_SEGMENTS, "no line was given"))
        return plan

    by_name = _segments_by_name()
    prof = profile_for(line, product)

    if prof is not None:
        plan.source = "declared"
        plan.cert_class = prof.cert_class or ""
        plan.ipam_pool = prof.ipam_pool or ""
        for name in prof.segments():
            seg = by_name.get(name)
            if seg is None:
                # NOT a shorter list. A declaration that stopped resolving is
                # the failure this table exists to make visible.
                plan.problems.append(Problem(
                    P_MISSING_SEGMENT,
                    f"segment {name!r} is named by this line but no longer "
                    "exists in Network segments"))
                continue
            plan.segments.append(dict(seg))
        _resolve_wpp(plan, prof.wpp_template_id)
    else:
        # The historical behaviour, kept ONLY as a labelled inference.
        plan.segments = [dict(seg) for seg in store.segments()
                         if (seg.get("line") or "").strip() == line]
        plan.problems.append(Problem(
            P_NO_CERT_CLASS,
            "no line profile exists, so the certificate class is undecided"))
        plan.problems.append(Problem(
            P_NO_WPP,
            "no line profile exists, so no Web Protection Profile template "
            "is named"))

    if not plan.segments and P_MISSING_SEGMENT not in plan.problem_codes():
        plan.problems.append(Problem(
            P_NO_SEGMENTS,
            f"no network segment is assigned to line {line!r}"))
    if plan.declared and not plan.cert_class:
        plan.problems.append(Problem(
            P_NO_CERT_CLASS,
            "this line does not declare a certificate class"))
    for seg in plan.segments:
        if not (seg.get("cidr") or "").strip():
            plan.problems.append(Problem(
                P_SEGMENT_NO_CIDR,
                f"segment {seg.get('name')!r} has no CIDR, so no address can "
                "be allocated from it"))
    return plan


def pool_for(plan: LinePlan, segment_name: str = "") -> str:
    """Which IPAM pool an address for this line comes from.

    The profile's explicit pool wins; otherwise the chosen segment's CIDR.
    Returns "" when neither is known — the caller must then ASK, because the
    provider's configured default is a fleet-wide pool and silently reaching
    for it puts a policy on a network this line was never given.
    """
    if plan.ipam_pool:
        return plan.ipam_pool
    for seg in plan.segments:
        if not segment_name or (seg.get("name") or "") == segment_name:
            return (seg.get("cidr") or "").strip()
    return ""


def lines_overview(product: str = "fortiweb") -> list[dict]:
    """Every catalog line with its plan — the admin page's whole payload."""
    out = []
    for line in store.classification("lines"):
        out.append(line_plan(line, product).as_dict())
    return out
