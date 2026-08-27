"""Editing a classification catalog is editing REFERENCES, not a word list.

Zone / line / department are stored as **free strings** on ``Appliance``, on
``Baseline`` and inside each network segment -- there is no foreign key
anywhere. The three textareas this page used to be could therefore not tell a
RENAME from a DELETE-plus-ADD, and to every consumer the two look identical:
the old string simply stops matching.

What that costs, measured against the live fleet rather than imagined:

* An appliance keeps ``zone="internal"`` after the catalog says ``Internal``.
  Architecture groups it under "(no zone)", the bookmarks lens buckets it as
  unclassified, and the appliance Edit page offers the value back as
  "(unregistered)".
* ``baselines.appliances_in_scope()`` filters on ``Appliance.zone ==
  baseline.zone``. A half-applied rename does not raise -- it returns an empty
  scope, which reads exactly like "no appliance matches this baseline yet".
* Worst of all, combos are auto-generated from the catalogs. Leave 24 baselines
  on the old triple and the next ``generate_missing_combos()`` builds a second
  full grid for the new one: 24 combos silently become 36.

Hence the rules this module exists to enforce:

1.  **A rename CASCADES.** The catalog entry and every reference to it move
    together, in ONE transaction, or neither moves.
2.  **A delete with references is REFUSED** until the caller says what happens
    to them -- clear them, or reassign them to another value. Deleting quietly
    is how a baseline's scope becomes empty without anyone touching the
    baseline.
3.  **Usage is counted from the LIVE rows, never from the catalog.** A value
    absent from the catalog can still be on ten appliances (that is precisely
    what the old textarea produced), and those references are the ones that
    matter.
4.  **Validation for every catalog finishes before the first write.**
    ``AppSetting.set()`` commits on its own, so validating and writing one
    catalog at a time would leave zones saved and lines refused -- a state no
    operator asked for and none can see.
"""
from __future__ import annotations

from dataclasses import dataclass, field as _dcfield

from ..models import Appliance, Baseline, db
from . import settings_store as store

#: catalog kind -> the column/key that holds a reference to one of its values.
FIELD_FOR_KIND = {"zones": "zone", "lines": "line", "departments": "department"}
#: Same three axes, as they are spelled ON A SEGMENT. Departments diverge:
#: the Appliance/Baseline column is a single string, the segment column is a
#: list, because a network can serve several departments while a device
#: belongs to one. Two maps rather than one lookup with a special case, so a
#: reader cannot use the wrong spelling without saying which map it meant.
SEGMENT_FIELD_FOR_KIND = {"zones": "zone", "lines": "line",
                          "departments": "departments"}

#: How a submitted row asks to be treated.
ACTIONS = ("keep", "delete")


class ClassificationError(ValueError):
    """A refused edit. The message is shown to the operator verbatim, so it
    always names the value and the reason -- "in use" without a count is not
    something anybody can act on."""


@dataclass
class Row:
    """One submitted catalog row.

    ``orig`` empty means "added in this form". ``value`` empty is only legal on
    a delete: renaming a value to nothing would be a delete wearing a costume,
    and it would skip the reference check that makes deletes safe.
    """
    orig: str = ""
    value: str = ""
    action: str = "keep"
    #: Where a deleted value's references go. Empty means "clear them", which
    #: is a real decision -- hence ``decided``, kept separate so an untouched
    #: dropdown can never read as "the operator chose to wipe them".
    reassign: str = ""
    decided: bool = False


@dataclass
class Usage:
    appliances: int = 0
    baselines: int = 0
    segments: int = 0
    #: Line profiles pointing at this value ('lines' catalog only). Counted
    #: like every other reference: a value with a profile is IN USE, so a
    #: delete has to say what happens to it instead of quietly orphaning it.
    line_profiles: int = 0

    @property
    def total(self) -> int:
        return (self.appliances + self.baselines + self.segments
                + self.line_profiles)

    def as_dict(self) -> dict[str, int]:
        return {"appliances": self.appliances, "baselines": self.baselines,
                "segments": self.segments, "line_profiles": self.line_profiles,
                "total": self.total}


@dataclass
class Report:
    added: list[str] = _dcfield(default_factory=list)
    renamed: list[tuple[str, str]] = _dcfield(default_factory=list)
    deleted: list[str] = _dcfield(default_factory=list)
    appliances: int = 0
    baselines: int = 0
    baselines_absorbed: int = 0
    baselines_renamed: int = 0
    segments: int = 0
    line_profiles: int = 0
    line_profiles_deleted: int = 0

    @property
    def touched(self) -> int:
        return (self.appliances + self.baselines + self.segments
                + self.line_profiles + self.line_profiles_deleted)


@dataclass
class _Plan:
    """A validated submission: what the catalog becomes, and the reference
    moves that have to happen for it to stay true."""
    kind: str
    final: list[str]
    moves: list[tuple[str, str]]          # (old, new); new "" means clear
    report: Report


# --------------------------------------------------------------------------- #
#  Usage — counted from the live rows                                          #
# --------------------------------------------------------------------------- #
def usage(kind: str) -> dict[str, Usage]:
    """Reference counts keyed by the EXACT stored string.

    Deliberately not folded case-insensitively: ``Appliance.zone == "dmz"``
    does not match a row holding ``"DMZ"``, so merging them here would report a
    reference the database will never resolve.
    """
    fld = FIELD_FOR_KIND.get(kind)
    out: dict[str, Usage] = {}
    if not fld:
        return out

    def bucket(val: str | None) -> Usage | None:
        val = (val or "").strip()
        if not val:
            return None
        return out.setdefault(val, Usage())

    for appl in Appliance.query.all():
        u = bucket(getattr(appl, fld, None))
        if u:
            u.appliances += 1
    for base in Baseline.query.all():
        u = bucket(getattr(base, fld, None))
        if u:
            u.baselines += 1
    for seg in store.segments():
        # A segment names ONE zone and ONE line but any number of departments
        # (two departments sharing a network share the row). Counting the list
        # as a single value would report every shared network as unused by
        # both -- and unregistered() would then hide a live reference.
        for val in (seg.get(SEGMENT_FIELD_FOR_KIND[kind]) if kind == "departments"
                    else [seg.get(fld)]):
            u = bucket(val)
            if u:
                u.segments += 1
    if kind == "lines":
        from ..models_lineprofile import LineProfile
        for prof in LineProfile.query.all():
            u = bucket(prof.line)
            if u:
                u.line_profiles += 1
    return out


def usage_for(kind: str, value: str) -> Usage:
    return usage(kind).get((value or "").strip(), Usage())


def unregistered(kind: str) -> dict[str, Usage]:
    """Values in USE that the catalog does not list. Shown, never hidden: they
    are live references, and an operator cannot fix what the page hides."""
    catalog = {v.strip() for v in store.classification(kind)}
    return {v: u for v, u in usage(kind).items() if v not in catalog}


# --------------------------------------------------------------------------- #
#  Validation                                                                  #
# --------------------------------------------------------------------------- #
def _plan_for(kind: str, rows: list[Row]) -> _Plan:
    if kind not in FIELD_FOR_KIND:
        raise ClassificationError(f"Unknown catalog '{kind}'.")

    current = store.classification(kind)
    rows = [r for r in rows if (r.orig.strip() or r.value.strip())]

    # -- rows that name an original which is not in the catalog --------------
    known = {v.strip() for v in current}
    for r in rows:
        if r.orig.strip() and r.orig.strip() not in known:
            raise ClassificationError(
                f"'{r.orig.strip()}' is no longer in the catalog — it changed "
                f"while this page was open. Reload and retry.")

    # -- an original the form did not send back is an UNINSTRUCTED delete ----
    # Dropping it outright is what the textarea did. Routing it through the
    # same delete path means it still has to survive the reference check.
    sent = {r.orig.strip() for r in rows if r.orig.strip()}
    for missing in [v for v in current if v.strip() not in sent]:
        rows.append(Row(orig=missing, value="", action="delete", reassign=""))

    # -- shape ---------------------------------------------------------------
    for r in rows:
        if r.action not in ACTIONS:
            raise ClassificationError(f"Unknown action '{r.action}'.")
        if r.action == "keep" and not r.value.strip():
            raise ClassificationError(
                f"'{r.orig.strip()}' cannot be renamed to an empty value. "
                f"Use Remove if you want it gone.")

    kept = [r for r in rows if r.action == "keep"]
    gone = [r for r in rows if r.action == "delete" and r.orig.strip()]

    # -- duplicates, case-insensitively --------------------------------------
    # save_classification() silently swallows the second one, so without this
    # the operator types two values, sees one, and is never told why.
    seen: dict[str, str] = {}
    for r in kept:
        key = r.value.strip().lower()
        if key in seen:
            raise ClassificationError(
                f"'{r.value.strip()}' is listed twice (also as '{seen[key]}'). "
                f"Values must be unique.")
        seen[key] = r.value.strip()

    final = [r.value.strip() for r in kept]

    # -- no rename may land on a name this same save is moving off ------------
    # A -> B together with B -> A passes every check above and then applies
    # sequentially: the first move puts A's references on B, the second puts
    # ALL of B on A. Both sets end up on one value, and nothing warned.
    originals = {r.orig.strip() for r in rows if r.orig.strip()}
    for r in kept:
        old, new = r.orig.strip(), r.value.strip()
        if old and old != new and new in originals:
            raise ClassificationError(
                f"Cannot rename '{old}' to '{new}' in the same save that also "
                f"changes '{new}'. Do it in two steps.")

    # -- deletes must say what happens to their references --------------------
    use = usage(kind)
    for r in gone:
        old = r.orig.strip()
        u = use.get(old, Usage())
        target = r.reassign.strip()
        if target and target not in final:
            raise ClassificationError(
                f"Cannot reassign '{old}' to '{target}': that value is not in "
                f"the catalog being saved.")
        if u.total and not r.decided:
            raise ClassificationError(
                f"'{old}' is still used by {u.appliances} appliance(s), "
                f"{u.baselines} baseline(s) and {u.segments} segment(s). "
                f"Choose what happens to them before removing it.")

    report = Report(
        added=[r.value.strip() for r in kept if not r.orig.strip()],
        renamed=[(r.orig.strip(), r.value.strip()) for r in kept
                 if r.orig.strip() and r.orig.strip() != r.value.strip()],
        deleted=[r.orig.strip() for r in gone],
    )
    moves = list(report.renamed) + [(r.orig.strip(), r.reassign.strip())
                                    for r in gone]
    return _Plan(kind=kind, final=final, moves=moves, report=report)


# --------------------------------------------------------------------------- #
#  Applying                                                                    #
# --------------------------------------------------------------------------- #
def apply_all(rows_by_kind: dict[str, list[Row]]) -> dict[str, Report]:
    """Validate EVERY catalog, then write. One commit for the whole thing.

    Raises ``ClassificationError`` with the catalog named. Nothing is committed
    on a refusal; the caller is expected to roll the session back.
    """
    plans: dict[str, _Plan] = {}
    for kind in store.CLASSIFICATION_KINDS:
        rows = rows_by_kind.get(kind)
        if rows is None:
            continue
        try:
            plans[kind] = _plan_for(kind, rows)
        except ClassificationError as exc:
            raise ClassificationError(f"{kind}: {exc}") from exc

    # Segments live in ONE JSON blob shared by all three axes, so they are
    # loaded once, edited by every plan, and written once. Saving per axis
    # would make the second write clobber the first.
    segs = store.segments()
    for kind, plan in plans.items():
        fld = FIELD_FOR_KIND[kind]
        for old, new in plan.moves:
            try:
                _retarget(fld, old, new, plan.report, segs)
            except ClassificationError as exc:
                raise ClassificationError(f"{kind}: {exc}") from exc

    # Only now does anything become durable. save_classification /
    # save_segments each commit, which also flushes the ORM work above.
    for kind, plan in plans.items():
        store.save_classification(kind, plan.final)
    if any(p.report.segments for p in plans.values()):
        store.save_segments(segs)
    db.session.commit()
    return {k: p.report for k, p in plans.items()}


def apply_rows(kind: str, rows: list[Row]) -> Report:
    """Single-catalog convenience wrapper over :func:`apply_all`."""
    return apply_all({kind: rows})[kind]


def _retarget(fld: str, old: str, new: str, report: Report,
              segs: list[dict[str, str]]) -> None:
    """Move every reference from *old* to *new* (empty *new* = clear it)."""
    if not old or old == new:
        return

    # -- appliances ----------------------------------------------------------
    n = (Appliance.query.filter(getattr(Appliance, fld) == old)
         .update({fld: (new or None)}, synchronize_session=False))
    report.appliances += int(n or 0)

    # -- baselines -----------------------------------------------------------
    # A combo's NAME is derived from its triple, so a scope change that leaves
    # the name alone produces a row labelled "internal / A / WAF-LB" scoped to
    # zone "Internal" -- readable, wrong, and invisible in a list of 24.
    from .baselines import combo_name  # local: avoids an import cycle
    for base in Baseline.query.filter(getattr(Baseline, fld) == old).all():
        triple = {"zone": base.zone or "", "line": base.line or "",
                  "department": base.department or ""}
        was_auto = base.name == combo_name(triple["zone"], triple["line"],
                                           triple["department"])
        triple[fld] = new or ""
        twin = _combo_at(triple, exclude_id=base.id)
        if twin is not None:
            # The destination triple already has a combo. Keeping both would
            # duplicate a scope, and missing_combos() would then treat the pair
            # as satisfied forever. Absorb -- but never at the cost of template
            # assignments nobody agreed to drop.
            mine = {link.template_id for link in base.items}
            theirs = {link.template_id for link in twin.items}
            if mine - theirs:
                raise ClassificationError(
                    f"combo '{base.name}' would merge into '{twin.name}', but it "
                    f"has {len(mine - theirs)} template(s) that combo does not. "
                    f"Reassign or delete that combo first.")
            db.session.delete(base)
            report.baselines_absorbed += 1
            continue
        setattr(base, fld, new or "")
        if was_auto:
            new_name = combo_name(triple["zone"], triple["line"],
                                  triple["department"])
            if Baseline.query.filter(Baseline.name == new_name,
                                     Baseline.id != base.id).first() is None:
                base.name = new_name
                report.baselines_renamed += 1
        report.baselines += 1

    # -- line profiles -------------------------------------------------------
    # A profile is what a line MEANS. Left behind on a renamed string it is an
    # orphan, and the line silently reverts to the inferred segment match —
    # which is the guess this whole feature replaced, restored without anyone
    # choosing it.
    if fld == "line":
        from ..models_lineprofile import LineProfile
        for prof in LineProfile.query.filter(LineProfile.line == old).all():
            if not new:
                # Clearing the line leaves a profile that answers for nothing.
                # Deleting it is the honest outcome and it is REPORTED, so the
                # operator who chose "clear the references" sees what that
                # cost. Keeping it with line="" would make it unreachable and
                # invisible at once.
                db.session.delete(prof)
                report.line_profiles_deleted += 1
                continue
            twin = (LineProfile.query
                    .filter(LineProfile.product == prof.product,
                            LineProfile.line == new,
                            LineProfile.id != prof.id).first())
            if twin is not None:
                # (product, line) is unique, so one of the two would have to
                # go. Picking silently means a line quietly starts handing out
                # a different set of networks — the exact class of error the
                # declaration exists to prevent.
                raise ClassificationError(
                    f"line {new!r} already has a profile in product "
                    f"{prof.product!r}, and {old!r} has one too. Merging them "
                    "would silently pick one line's networks for the other — "
                    "delete or edit one of the two profiles first.")
            prof.line = new
            report.line_profiles += 1

    # -- network segments (JSON blob in app_settings) ------------------------
    if fld == "department":
        # The list case. A rename must not create a duplicate entry (the row
        # may already carry the destination name), and clearing must REMOVE
        # the entry rather than leave an empty string, which would render as a
        # blank badge and count as a department in usage().
        for seg in segs:
            depts = list(seg.get("departments") or [])
            if old not in depts:
                continue
            # Rename in place and STOP. Dropping the empty string a clear
            # leaves, and collapsing a rename onto a name the row already
            # carries, both belong to settings_store.normalize_departments --
            # which save_segments runs on every row on the way in. Repeating
            # the rule here would make this the second author of it, and the
            # copy nobody reads is the copy that drifts (§132).
            seg["departments"] = [new if d == old else d for d in depts]
            report.segments += 1
        return
    for seg in segs:
        if (seg.get(fld) or "") == old:
            seg[fld] = new or ""
            report.segments += 1


def _combo_at(triple: dict[str, str], exclude_id: int) -> Baseline | None:
    return (Baseline.query
            .filter(Baseline.zone == triple["zone"],
                    Baseline.line == triple["line"],
                    Baseline.department == triple["department"],
                    Baseline.id != exclude_id)
            .first())
