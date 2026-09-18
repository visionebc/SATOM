"""Shared body of the API Versions page (firmware evidence, per BUILD).

Mounted twice — FortiWeb (``/web/registry/versions``) and FortiADC
(``/adc/api/versions``) — for the same reason ``_reconcile`` is: the catalog is
product-scoped and each product's API hub is its own ADOM page. One
implementation, two thin routes.

What changed on 2026-09-16: the page used to have one axis, the firmware
**line** (``8.0``). A line merges builds, and ``api_matrix``'s merge rule is
*"OK from any healthy witness wins"* — so an endpoint served only by one build
was attributed to the whole line, and ``preflight`` could answer *compatible*
about a box that does not serve it. The atomic axis is now the full version
(``8.0.5``); the line survives as a rollup that always DECLARES which builds it
merged and which endpoints only some of them attested.

Read-only except ``rebuild`` / ``declare`` / ``forget``. ``rebuild`` writes only
the DERIVED matrix file (``data/api_matrix/<product>.json``); the other two
write one row of operator-authored text. All three are gated on REGISTRY_EDIT:
the same audience as the reconcile page and strictly less dangerous than it.
"""
from __future__ import annotations

import csv
import io as _io

from flask import (Response, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user

from ..services import (absence_corroboration, absence_record, api_matrix,
                        cli_coverage, firmware_versions, pdf_kit)
from ..services.audit import log_action


def _scopes(matrix: dict) -> list:
    """Everything comparable on this page, builds first then rollups.

    Builds and rollups share one selector because the operator's question is
    the same shape ("what changes between these two?"), and they are LABELLED
    apart in the option text because the answers are not the same kind of
    claim.
    """
    versions = sorted((matrix.get("versions") or {}), key=firmware_versions.sort_key)
    lines = sorted(matrix.get("lines") or {})
    return [{"key": v, "kind": "version"} for v in versions] + \
           [{"key": ln, "kind": "line"} for ln in lines]


# --- the CLI field delta, per row -----------------------------------------
# Buckets whose rec came from a block the dump actually printed. The other
# three (no_block, monitor_only, unknown) have NO block, and an absent block is
# not an empty one: a config table with nothing in it prints no block at all,
# so counting it as zero would fabricate "the CLI lost every field here".
_CLI_HAS_BLOCK = (cli_coverage.BUCKET_BOTH, cli_coverage.BUCKET_NEAR,
                  cli_coverage.BUCKET_CLI_ONLY)


def _cli_pair_note(base, base_prov, target, target_prov):
    """The sentence every CLI number on the page has to carry.

    The two dumps were taken on TWO DIFFERENT APPLIANCES. Rendered bare, a
    ``+3`` under a build column reads as "this firmware gained three CLI
    fields" — it did not; three more fields were CONFIGURED on the other box.
    That is the single misreading this page exists to prevent (RULE 1 in
    api_matrix, and the 56 phantom removals behind it), so the note travels
    with the data instead of being retyped per surface.
    """
    bdev = (base_prov.device if base_prov and base_prov.measured else "")
    tdev = (target_prov.device if target_prov and target_prov.measured else "")
    return ("CLI field names come from two different appliances — %s on %s, "
            "%s on %s. They are what an operator CONFIGURED on each box, so "
            "this subtraction measures the two configurations, not the "
            "firmware." % (bdev or "?", base, tdev or "?", target))


def _cli_field_delta(base_rec, target_rec, note):
    """``set`` names each build's dump printed for this block, and the gap.

    ``None`` when neither side printed a block — the caller then falls back to
    the transport verdict. Only a side that printed one gets a count, and the
    subtraction is offered only when BOTH did: subtracting against a side that
    was never answered is the "gap worded as a change" this table already
    separates everywhere else.
    """
    def has(rec):
        return bool(rec) and rec.get("bucket") in _CLI_HAS_BLOCK

    hb, ht = has(base_rec), has(target_rec)
    if not hb and not ht:
        return None
    b = set((base_rec or {}).get("settings") or ())
    t = set((target_rec or {}).get("settings") or ())
    both = hb and ht
    return {
        "base_count": len(b) if hb else None,
        "target_count": len(t) if ht else None,
        "comparable": both,
        "removed": sorted(b - t) if both else [],
        "added": sorted(t - b) if both else [],
        "note": note,
    }


def _pick(matrix: dict) -> tuple:
    """Default (base, target): oldest → newest MEASURED build.

    Newest-as-target is the direction an operator actually asks about ("what
    does the upgrade add?"). Builds are preferred over lines for the default
    because a build-to-build answer is the stronger one; with fewer than two
    measured builds it falls back to lines, and with fewer than two of those
    both come back empty and the template renders the single-scope case.
    """
    measured = sorted([v for v, d in (matrix.get("versions") or {}).items()
                       if d.get("measured")], key=firmware_versions.sort_key)
    if len(measured) >= 2:
        return measured[0], measured[-1]
    lines = sorted(matrix.get("lines") or {})
    if len(lines) >= 2:
        return lines[0], lines[-1]
    return "", ""


def _empty(product: str) -> dict:
    return {"product": product, "lines": {}, "versions": {}, "fleet_lines": [],
            "fleet_versions": [], "witnesses": [], "notes": [], "built_at": "",
            "sweepable": product in api_matrix.SWEPT_PRODUCTS}


def _resolved(product: str) -> dict:
    """Everything the comparison rests on, resolved ONCE.

    The page and its CSV export read the SAME object. Recomputing the delta on
    the export side would give this table two authors, and of a drifting pair
    it is always the one nobody looks at that goes wrong first — here that is
    the download, which is also the copy that leaves the building.
    """
    # Read-time merge of the DERIVED matrix (a file on disk) with the AUTHORED
    # declarations (rows in Postgres). Two stores on purpose — one is rebuilt
    # from evidence, the other is typed by a person — and merged here so a
    # declaration is visible the moment it is made, without a rebuild that
    # would drop evidence from deleted witnesses.
    matrix = firmware_versions.overlay(product, api_matrix.load(product) or _empty(product))
    vdocs = matrix.get("versions") or {}
    versions = sorted(vdocs, key=firmware_versions.sort_key)
    lines = sorted(matrix.get("lines") or {})
    scopes = _scopes(matrix)
    scope_keys = {s["key"] for s in scopes}

    d_base, d_target = _pick(matrix)
    base = request.args.get("base") or d_base
    target = request.args.get("target") or d_target
    # A base/target that is not a known scope is silently dropped rather than
    # rendered as an empty diff: an empty diff and "you asked about a firmware
    # nobody has ever measured" look identical and mean opposite things.
    if base not in scope_keys:
        base = d_base
    if target not in scope_keys:
        target = d_target

    delta = None
    if base and target and base != target:
        delta = api_matrix.diff(product, base, target, matrix=matrix)

    # CLI provenance is per BUILD here, never per product and no longer merely
    # per line. A dump comes from one box running one build, so answering "does
    # 8.0.5 have this in its CLI?" with an 8.0.3 capture would be this page's
    # only way to lie, and it would look like a confident answer.
    # ``cli_coverage.report`` owns that selection; a build with no capture comes
    # back unmeasured and every badge for it is "—".
    ver_prov = {v: cli_coverage.provenance(product, version=v) for v in versions}
    line_prov = {ln: cli_coverage.provenance(product, line=ln) for ln in lines}
    prov = dict(line_prov)
    prov.update(ver_prov)
    base_prov = prov.get(base)
    target_prov = prov.get(target)

    # Until now the page printed only COUNTS of endpoints added/removed.
    # A provenance column needs the rows, so they are rendered — annotated
    # in the view rather than looked up in the template, so the lookup has
    # exactly one call site.
    #
    # EVERY bucket, not just the two endpoint ones: the comparison renders a
    # single table since 2026-09-16, and a row that reached it through the
    # field buckets carries the same two per-build transport lines as its
    # neighbours (they were two columns of their own until the operator asked
    # for them stacked inside Change, same day). Annotating only some buckets
    # would leave those verdicts empty — indistinguishable on screen from "the
    # CLI does not serve it", which is the one confusion they exist to prevent.
    # A key that names no catalog entry answers ``unknown`` (an em dash
    # carrying its reason), never a badge.
    if delta:
        _pair_note = _cli_pair_note(base, base_prov, target, target_prov)
        for bucket in ("endpoints_added", "endpoints_removed", "endpoints_unknown",
                       "fields_changed", "fields_unknown", "fields_incomparable"):
            for row in delta.get(bucket) or []:
                name = row.get("endpoint") or row.get("key") or ""
                row["cli_base"] = base_prov.for_name(name) if base_prov else None
                row["cli_target"] = target_prov.for_name(name) if target_prov else None
                # The field delta is computed HERE, never in the template: one
                # author for the subtraction, and the template cannot reach the
                # configured field names at all (guarded).
                row["cli_delta"] = _cli_field_delta(
                    row["cli_base"], row["cli_target"], _pair_note)

        # --- corroboration, on the ONE bucket that claims a disappearance --
        # ``endpoints_removed`` is the only bucket where the comparison says
        # "this used to be here and is not". Every other bucket is a gap or a
        # field delta, and stamping a corroboration verdict on those would
        # answer a question they never asked -- the same fabrication as
        # printing an evidence kind for a record that never carried one.
        #
        # Computed here and not in ``api_matrix.diff`` because it needs the CLI
        # provenance, which is resolved in this view (per BUILD, which is
        # strictly better evidence than the per-line pass the ledger runs). The
        # two therefore answer for different scope pairs and are keyed by those
        # scopes on both sides; they are not two answers to one question.
        for row in delta.get("endpoints_removed") or []:
            state = absence_corroboration.corroborate(
                second_now=absence_corroboration.source_of(row.get("cli_target")),
                second_before=absence_corroboration.source_of(row.get("cli_base")))
            row["corroboration"] = state
            row["corroboration_label"] = absence_corroboration.label(state)
            # The alternative CLI spelling travels only with the verdict that
            # makes it meaningful -- on a corroborated disappearance there is
            # no path to offer, and offering one would read as a fix for a
            # finding that needs none.
            #
            # That coupling is NOT re-checked here. A spelling exists only for
            # a ``near_match``, and ``near_match`` is a bucket that holds a
            # block, so it can only ever produce the contradicted verdict: an
            # ``if is_actionable(state)`` wrapper around this line was dead
            # code that no mutation could reach. A conditional that cannot be
            # false is an invitation to hang a second condition off it later.
            # The invariant is pinned where it is actually true, on the bucket
            # mapping, by
            # ``test_an_alternative_spelling_belongs_only_to_the_actionable_verdict``.
            row["proposed_path"] = absence_corroboration.proposed_path(
                row.get("cli_target"))
        tally = {}
        for row in delta.get("endpoints_removed") or []:
            k = row.get("corroboration") or ""
            tally[k] = tally.get(k, 0) + 1
        delta["corroboration_counts"] = tally
        delta["corroboration_actionable"] = sum(
            n for k, n in tally.items() if absence_corroboration.is_actionable(k))

        # --- the LEDGER, joined to the pair the page is actually looking at -
        # The comparison is derived and is rebuilt from evidence on every
        # sweep, so it cannot answer the two questions a finding needs to
        # outlive its page: since when has this been true, and has anybody
        # looked at it. Those live in ``object_absences`` and are joined here.
        #
        # NO SECOND VERDICT. The state printed on the row is still the one this
        # view computed live, per BUILD, from the evidence on disk. The ledger
        # contributes only what a live computation cannot know -- first proof,
        # repetition, and the review decision -- and its own scopes travel with
        # it so a line-scoped row can never be read as a claim about two
        # builds. That is the same boundary that keeps sweep and schema
        # evidence apart, applied to time instead of to source.
        ledger = absence_record.ledger_for_pair(product, base, target,
                                                matrix=matrix)
        for row in delta.get("endpoints_removed") or []:
            rec = ledger["rows"].get(row.get("endpoint") or "")
            row["ledger"] = rec
            # Computed here, never in the template, for the same reason the
            # field delta is: one call site for the lookup and one author for
            # the vocabulary.
            row["ledger_label"] = absence_record.review_label(rec) if rec else None
            row["ledger_open"] = bool(rec) and absence_record.is_open(rec)
        delta["ledger"] = ledger

    # Orphaned ledger pairs are resolved for the PRODUCT, not for the pair on
    # screen, and that is the whole reason they are here: a pair that stopped
    # being adjacent cannot be found by browsing, because no comparison offers
    # it any more. If it were only surfaced on its own comparison the operator
    # would have to already know which one to open.
    orphans = absence_record.orphans(product, matrix)

    return {"matrix": matrix, "vdocs": vdocs, "versions": versions,
            "lines": lines, "scopes": scopes, "base": base, "target": target,
            "delta": delta, "prov": prov, "ver_prov": ver_prov,
            "line_prov": line_prov, "base_prov": base_prov,
            "target_prov": target_prov, "ledger_orphans": orphans}


def render_page(product: str, hub_endpoint: str, rebuild_endpoint: str,
                page_endpoint: str, declare_endpoint: str = "",
                forget_endpoint: str = "", export_endpoint: str = "",
                export_pdf_endpoint: str = "", review_endpoint: str = ""):
    R = _resolved(product)
    matrix, vdocs = R["matrix"], R["vdocs"]
    versions, lines, scopes = R["versions"], R["lines"], R["scopes"]
    base, target, delta = R["base"], R["target"], R["delta"]
    prov, ver_prov, line_prov = R["prov"], R["ver_prov"], R["line_prov"]
    base_prov, target_prov = R["base_prov"], R["target_prov"]

    _hub_bp = (hub_endpoint or "").split(".")[0]
    from ..models import Appliance, visible_appliances
    probe_appliances = (visible_appliances().filter(Appliance.kind == product)
                        .order_by(Appliance.name).all()) if _hub_bp else []

    # --- the discovery run, scoped to the row the operator clicked ----------
    # ``?discover=8.0.5`` is the whole mechanism: no JavaScript, the scope is
    # in the URL so it is shareable and it reaches the audit log of whoever
    # follows the link. An UNKNOWN build scopes to nothing rather than to
    # "whatever dump sorted first" — silently widening it is the exact defect
    # this move exists to end.
    discover = firmware_versions.normalize(request.args.get("discover") or "")
    if discover and discover not in vdocs:
        discover = ""
    scope_boxes = [a for a in probe_appliances
                   if firmware_versions.normalize(
                       getattr(a, "fw_version", "") or a.firmware) == discover
                   ] if discover else []

    dr_ctx, cc_ctx = {}, {}
    if _hub_bp:
        from . import _clicoverage, _discovery
        cc_ctx = _clicoverage.context(
            product, page_endpoint=page_endpoint,
            block_endpoint="%s.cli_coverage_block" % _hub_bp,
            capture_endpoint="%s.cli_coverage_capture" % _hub_bp,
            live_endpoint="%s.cli_coverage_live" % _hub_bp,
            probe_endpoint="%s.cli_coverage_probe" % _hub_bp,
            registry_save_endpoint="registry.save")
        dr_ctx = _discovery.context(
            product,
            load_endpoint="%s.discovery_load" % _hub_bp,
            scope=discover, scope_appliances=scope_boxes)

    return render_template(
        # NOT ``product=``: the branding context processor already puts the
        # ADOM's branding DICT under that name in every template, and the
        # chrome prints ``product.title`` from it. Passing the product KEY
        # shadows the dict; ``.title`` on a str is the bound METHOD, which the
        # topbar rendered verbatim beside the logo until 2026-09-16.
        "registry/versions.html", product_key=product, matrix=matrix, lines=lines,
        versions=versions, vdocs=vdocs, scopes=scopes,
        discover=discover, **cc_ctx, **dr_ctx,
        stale_format=bool(matrix.get("stale_format")),
        probe_appliances=probe_appliances,
        exec_endpoint=("%s.execute" % _hub_bp) if _hub_bp else "",
        live_endpoint=("%s.cli_coverage_live" % _hub_bp) if _hub_bp else "",
        base=base, target=target, delta=delta, hub_endpoint=hub_endpoint,
        rebuild_endpoint=rebuild_endpoint, page_endpoint=page_endpoint,
        declare_endpoint=declare_endpoint, forget_endpoint=forget_endpoint,
        export_endpoint=export_endpoint,
        export_pdf_endpoint=export_pdf_endpoint,
        review_endpoint=review_endpoint,
        line_prov=line_prov, ver_prov=ver_prov, prov=prov,
        base_prov=base_prov, target_prov=target_prov,
        # Enumerated, like every other key: this function does not splat
        # ``**R``. Resolving a value and forgetting to hand it over renders as
        # a feature that simply is not there, with every unit test green --
        # which is what happened to this one on its first pass, and is why the
        # guard for it asks the SERVER for the page instead of the resolver.
        ledger_orphans=R["ledger_orphans"],
        source_label=firmware_versions.SOURCE_LABEL,
    )



# ---------------------------------------------------------------------------
#  CSV export of the comparison                                              #
# ---------------------------------------------------------------------------
# Three things the screen says with affordances a CSV does not have, and which
# therefore have to be said in COLUMNS or the file means something else than
# the page it came from:
#
# * **Which finding a row is.** On screen it is read off a badge and the two
#   build columns. A spreadsheet gets pivoted, so the bucket is a column.
# * **Whether it is a change at all.** ``known on one side only`` and
#   ``incomparable`` are gaps in the evidence. Summed into a change count they
#   become the phantom removals the sweep/schema split exists to prevent, so
#   the answer is its own column rather than something to infer from the
#   bucket name.
# * **Where a CLI number comes from.** The two CLI columns are two different
#   appliances' configuration, not one firmware measured twice. On screen that
#   caveat is a tooltip; here it is written into the column heading, where it
#   cannot be detached from the numbers it qualifies.
#
# The field NAMES are included in full. They live behind a [+] window on the
# page, and an export of "the whole table" that quietly dropped them would be
# the one thing a download is for.

#: Re-exported, not redefined. ``api_matrix`` fills the buckets, so it names
#: them; the export, the PDF and the row cross-reference all read that one
#: definition. A copy here would be the second author of a vocabulary — the
#: shape of drift this page has already been bitten by twice.
_BUCKET_LABEL = api_matrix.BUCKET_LABEL


def _cli_head(scope: str, prov, what: str) -> str:
    """A CLI column heading that carries its own capture.

    A bare ``7.6.8 CLI sets`` invites the reader to subtract it from the other
    column as if both were the same box at two firmwares. They are two boxes.
    """
    if prov is not None and getattr(prov, "measured", False):
        return "%s CLI %s (%s, captured %s — operator configuration, not firmware)" % (
            scope, what, prov.device, prov.captured_at)
    return "%s CLI %s (no dump captured on this build)" % (scope, what)


def _columns(base, target, bp, tp):
    """``(heading, explanation)`` for every column, in file order.

    ONE author for the pair. A legend written beside the header rather than
    WITH it is exactly how a column ends up documented as something it stopped
    being three releases ago.
    """
    def _side(scope, prov, other):
        return [
            ("%s API" % scope,
             "What %s's API catalogue says about the object: served, absent, or "
             "blank when this build was never asked." % scope),
            ("%s API fields" % scope,
             "How many fields %s's catalogue lists for it. Blank means there is "
             "no catalogue entry to count, which is not the same as zero." % scope),
            ("fields only on %s" % scope,
             "Field names %s has and %s does not. These are the names the page "
             "keeps behind its [+] window." % (scope, other)),
            (_cli_head(scope, prov, "verdict"),
             "Whether the CLI dump captured on %s contains a block for this "
             "object. That dump is ONE appliance's configuration: this column "
             "and the %s one are two different boxes, never one firmware "
             "measured twice." % (scope, other)),
            (_cli_head(scope, prov, "sets"),
             "How many set lines that block printed. Blank means no block was "
             "captured on %s — again, not a zero." % scope),
            ("CLI fields only on %s" % scope,
             "set names in the %s dump's block and not in the %s one's. "
             "Operator configuration, not firmware." % (scope, other)),
        ]

    return [
        ("finding",
         "Which bucket the comparison put the row in: "
         + ", ".join(lbl for lbl, _ in _BUCKET_LABEL.values()) + "."),
        ("is a change",
         "yes only when BOTH builds were measured and they differ. A no row is "
         "a gap in the evidence; summed into a change count it becomes a "
         "removal nobody ever measured."),
        ("endpoint / object", "The name the page prints in its first column."),
        ("evidence",
         "How the row was measured: sweep (a live walk of that build) or schema "
         "(the shipped schema). An incomparable row prints both sides, as "
         "base=... target=... ."),
        ("urn",
         "The REST path, when the row has one. An object that exists solely in "
         "the configuration language has none."),
    ] + _side(base, bp, target) + _side(target, tp, base) + [
        # Last column on purpose: appended rather than inserted beside
        # ``evidence``, so every existing column keeps its index and the PDF's
        # two tables keep addressing the cells they were built to address.
        ("why the evidence is missing",
         "For a row with no schema on one side, what the harvest recorded when "
         "it tried: an empty table on the reference appliance (a fact about that "
         "box, not the firmware), a rejected URN, or an unreachable device. "
         "Blank when the row is not a schema gap, or when no harvest has ever "
         "recorded that line — and those two blanks are not the same claim."),
        # Appended AFTER the gap column for the reason stated above it: an
        # inserted column renumbers every later one, and the PDF's two tables
        # address cells by INDEX. Index 17 stays the gap column.
        ("corroboration",
         "For a row reported GONE, what a SECOND source says. The API alone "
         "cannot tell a removed object from a path that is wrong for this "
         "firmware line, so the appliance's own configuration dump -- which is "
         "addressed in CLI syntax and cannot inherit our path's mistake -- is "
         "asked too. \"check the registry\" means the dump HOLDS a block the "
         "REST path is rejecting: the object is on the box and this catalogue "
         "is wrong. Blank on every row that is not a disappearance claim, "
         "which is not the same as an uncorroborated one."),
        # Appended, again, and for the third time for the same reason: an
        # inserted column renumbers every later one and the PDF addresses its
        # cells by INDEX. The gap column stays 17 and corroboration stays 18.
        ("ledger review",
         "Whether a person has accepted or refused this disappearance, and "
         "who. Blank means the finding is not in the lifecycle ledger for this "
         "pair at all -- which is not the same as unreviewed, and the scope "
         "column beside it says why."),
        ("ledger scope and age",
         "The line pair the ledger recorded this against, when it was first "
         "proved and how many times it has been re-proved since. The scopes "
         "are printed because they are the LEDGER's, not necessarily the two "
         "scopes compared above: a disappearance is recorded against the "
         "firmware LINE that removed it, so a build-to-build comparison shows "
         "its line-level record and says so rather than restating it as a "
         "claim about the builds."),
    ]


def _api_cell(row, side: str):
    """(verdict, field count) for one build's API half, mirroring the page."""
    b = row.get("_bucket")
    scope = row["_base"] if side == "base" else row["_target"]
    if b == "endpoints_added":
        return ("absent" if side == "base" else "served", "")
    if b == "endpoints_removed":
        return ("served" if side == "base" else "absent", "")
    if b == "endpoints_unknown":
        return ("served", "") if row.get("measured_on") == scope else ("", "")
    if b == "fields_unknown":
        if row.get("known_on") == scope:
            return ("served", row.get("count"))
        # The side with no schema is not necessarily a side nobody asked. Since
        # 2026-09-17 the page prints the sweep's own verdict for that build when
        # it recorded one, and a copy that leaves the building must not be the
        # quieter of the two: a blank here reads as "no finding", which is the
        # exact misreading the page was changed to stop. Still blank when the
        # sweep has no record for that key — that one really is unasked.
        return ((row.get("measured") or {}).get("verdict") or "", "")
    n = row.get("base_count") if side == "base" else row.get("target_count")
    return ("served", n)


def _rows(delta: dict):
    for bucket, rows in ((b, delta.get(b) or []) for b in _BUCKET_LABEL):
        for r in rows:
            r["_bucket"] = bucket
            r["_base"], r["_target"] = delta["base"], delta["target"]
            yield r


def export_page(product: str, page_endpoint: str):
    R = _resolved(product)
    delta, base, target = R["delta"], R["base"], R["target"]
    if not delta:
        # An empty CSV reads as "nothing differs". It is not the same claim as
        # "you have not picked two comparable builds", so it is not served.
        flash("Pick two different builds (or rollups) before exporting.", "warning")
        return redirect(url_for(page_endpoint))

    bp, tp = R["base_prov"], R["target_prov"]
    buf = _io.StringIO()
    w = csv.writer(buf)
    cols = _columns(base, target, bp, tp)
    w.writerow([h for h, _ in cols])
    n = 0
    for cells in _export_rows(delta, base, target):
        w.writerow(cells)
        n += 1

    # The column legend, BELOW the findings and below a blank row. A blank row
    # ends a spreadsheet's auto-detected range, so a pivot or a SUM over the
    # table above cannot reach these lines; the "#" in the first cell is there
    # for whoever reads the file with code instead. Putting the explanations in
    # a second header row, or above the header, would make them the one thing
    # they must never be: rows that count.
    w.writerow([])
    w.writerow(["#", "column", "what it means"])
    for _h, _note in cols:
        w.writerow(["#", _h, _note])

    log_action("api_versions.export", target="%s %s -> %s" % (product, base, target),
               extra={"rows": n})
    fn = "satom-api-delta-%s-%s-to-%s.csv" % (product, base, target)
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fn})

def _gap_text(row) -> str:
    """The recorded reason a side has no schema, flattened for one cell.

    The scope is named INSIDE the text. A spreadsheet column has no tooltip and
    gets sorted away from its neighbours, so a reason that said "the table is
    empty" without saying empty on WHICH build would be re-attachable to either
    column by whoever reads it next.
    """
    g = row.get("gap_reason") or {}
    if not g:
        return ""
    return "no schema on %s (%s): %s" % (g.get("scope") or g.get("line") or "?",
                                         g.get("status") or "", g.get("reason") or "")


def _ledger_review_text(row) -> str:
    """The review decision for one row, flattened for a spreadsheet cell.

    Names WHO decided, not just what was decided: a download that says
    "accepted" without an actor is an audit trail with the audit taken out.
    """
    rec = row.get("ledger")
    if rec is None:
        return ""
    text = absence_record.review_label(rec)[0]
    who = (rec.reviewed_by or "").strip()
    if who and not absence_record.is_open(rec):
        return "%s by %s%s" % (text, who,
                               (" on %s" % rec.reviewed_at.strftime("%Y-%m-%d"))
                               if rec.reviewed_at else "")
    return text


def _ledger_scope_text(row) -> str:
    """The ledger row's OWN scopes, its first proof and its repetition count.

    The scopes are in the cell rather than only in the header, for the reason
    every other scope on this page is: a spreadsheet column gets sorted away
    from its neighbours, and a date with no scope beside it is re-attachable to
    whichever comparison the reader happens to remember.
    """
    rec = row.get("ledger")
    if rec is None:
        return ""
    first = rec.first_seen_at.strftime("%Y-%m-%d") if rec.first_seen_at else "?"
    return "%s -> %s; first proved %s; re-proved %d time(s)" % (
        rec.base_scope, rec.target_scope, first, rec.seen_count or 0)


def _export_rows(delta: dict, base: str, target: str):
    """One cell list per finding, in ``_columns`` order. ONE author.

    The CSV and the PDF render the same 18 values. Building them twice is how
    two exports of "the same table" start disagreeing, and of a drifting pair
    it is always the copy nobody opens that goes wrong first.
    """
    for r in _rows(delta):
        label, is_change = _BUCKET_LABEL[r["_bucket"]]
        if r["_bucket"] == "fields_incomparable":
            evidence = "%s=%s; %s=%s" % (base, r.get("base_origin") or "",
                                         target, r.get("target_origin") or "")
        else:
            evidence = r.get("origin") or ""
        b_api, b_n = _api_cell(r, "base")
        t_api, t_n = _api_cell(r, "target")
        cd = r.get("cli_delta")
        # The CLI verdict is the raw BUCKET key, never the display vocabulary:
        # that vocabulary is spelled in ``_cli_provenance.html`` and nowhere
        # else, and a second author of it is how a label drifts out of sync
        # with the badge it is supposed to mirror.
        cb, ct = r.get("cli_base"), r.get("cli_target")
        yield [
            label, is_change, r.get("endpoint") or r.get("key") or "",
            evidence, r.get("urn") or "",
            b_api, b_n, " ".join(r.get("removed") or []),
            (cb or {}).get("bucket") or "", (cd or {}).get("base_count", ""),
            " ".join((cd or {}).get("removed") or []),
            t_api, t_n, " ".join(r.get("added") or []),
            (ct or {}).get("bucket") or "", (cd or {}).get("target_count", ""),
            " ".join((cd or {}).get("added") or []),
            _gap_text(r),
            absence_corroboration.label(r["corroboration"])[0]
            if r.get("corroboration") else "",
            _ledger_review_text(r),
            _ledger_scope_text(r),
        ]


#: How the 17 columns are split across the PDF's two tables, by INDEX into
#: ``_columns``. Two tables because the shared renderer drops everything past
#: the tenth column, and seventeen columns across a landscape page renders as
#: columns of single characters either way. Index 2 (the object name) is
#: repeated as the second table's join key — it is the only cell that may
#: appear twice, and the legend says so.
_PDF_TABLE_A = (0, 1, 2, 3, 18, 17, 4, 5, 11, 12)
_PDF_TABLE_B = (2, 6, 7, 8, 9, 10, 13, 14, 15, 16)
#: The lifecycle ledger, third table. Its own rather than squeezed into A: the
#: two ledger cells answer "who decided, and since when" and the tables above
#: answer "what the firmware does" -- and A is already at the ten columns the
#: renderer will draw. The name repeats here as the join key, same as in B.
_PDF_TABLE_C = (2, 19, 20)


def export_pdf_page(product: str, page_endpoint: str):
    """The rendered comparison as a PDF, columns documented in the document.

    Reads the SAME resolved comparison and the SAME ``_columns`` pairs as the
    CSV, so the two downloads cannot describe their columns differently.
    """
    R = _resolved(product)
    delta, base, target = R["delta"], R["base"], R["target"]
    if not delta:
        # An empty PDF reads as "nothing differs", which is not the same claim
        # as "you have not picked two comparable builds".
        flash("Pick two different builds (or rollups) before exporting.", "warning")
        return redirect(url_for(page_endpoint))

    bp, tp = R["base_prov"], R["target_prov"]
    cols = _columns(base, target, bp, tp)
    rows = list(_export_rows(delta, base, target))

    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                    Spacer)

    buf = _io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm,
                            title="SATOM API delta %s %s to %s" % (product, base, target))
    sty = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=sty["Title"], fontSize=17, spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=sty["Heading2"], fontSize=11, spaceBefore=8,
                        spaceAfter=3)
    body = ParagraphStyle("Body", parent=sty["Normal"], fontSize=8.4, leading=11)
    small = ParagraphStyle("Small", parent=sty["Normal"], fontSize=7, leading=9)
    cell = ParagraphStyle("Cell", parent=sty["Normal"], fontSize=6.4, leading=7.8)

    def _cap(prov, scope):
        if prov is not None and getattr(prov, "measured", False):
            return "%s: CLI dump from %s, captured %s" % (scope, prov.device,
                                                          prov.captured_at)
        return "%s: no CLI dump captured on this build" % scope

    story = [
        Paragraph("SATOM &mdash; API delta", h1),
        Paragraph("%s &nbsp;&middot;&nbsp; <b>%s</b> &rarr; <b>%s</b> &nbsp;&middot;&nbsp; "
                  "%d finding(s)" % (pdf_kit.esc(product), pdf_kit.esc(base),
                                     pdf_kit.esc(target), len(rows)), body),
        # The two captures are named on the cover, not only inside the CLI
        # column headings: a reader who skips the legend must still not be able
        # to read the two CLI columns as one box measured at two firmwares.
        Paragraph(pdf_kit.esc(_cap(bp, base)), small),
        Paragraph(pdf_kit.esc(_cap(tp, target)), small),
        Paragraph("The two CLI columns are two different appliances. Their "
                  "difference measures operator configuration, not firmware.", small),
        Spacer(1, 5 * mm),
    ]

    avail = doc.width
    for title, idx in (("Findings &mdash; identity and API evidence", _PDF_TABLE_A),
                       ("Field names and CLI evidence", _PDF_TABLE_B),
                       ("Lifecycle ledger &mdash; what was decided, and when",
                        _PDF_TABLE_C)):
        story.append(Paragraph(title, h2))
        story.append(pdf_kit.table_flowable(
            {"columns": [cols[i][0] for i in idx],
             "rows": [[r[i] for i in idx] for r in rows]},
            avail, cell,
            # Every finding, whole. The renderer's defaults (40 rows, 10
            # columns, 300 characters) exist to keep a dashboard widget
            # readable; here a dropped row or a clipped name list is the
            # evidence this download exists to carry.
            max_rows=len(rows) or 1, max_cols=len(idx), cell_cap=4000))
        story.append(Spacer(1, 4 * mm))

    # The legend, LAST and behind a rule. In a PDF there is no auto-detected
    # range to poison the way a spreadsheet has, but the ordering claim is the
    # same one: these lines describe the findings, they are not findings.
    story.append(HRFlowable(width="100%", thickness=0.6, color="#94a3b8",
                            spaceBefore=4, spaceAfter=4))
    story.append(Paragraph("What each column means", h2))
    for head, note in cols:
        story.append(Paragraph("<b>%s</b> &mdash; %s" % (pdf_kit.esc(head),
                                                         pdf_kit.esc(note)), small))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "&ldquo;endpoint / object&rdquo; appears in both tables; it is the key "
        "that joins a finding's two halves and is the only column printed twice.",
        small))

    doc.build(story)
    log_action("api_versions.export_pdf", target="%s %s -> %s" % (product, base, target),
               extra={"rows": len(rows)})
    fn = "satom-api-delta-%s-%s-to-%s.pdf" % (product, base, target)
    return Response(buf.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fn})


def rebuild_page(product: str, page_endpoint: str):
    try:
        matrix = api_matrix.rebuild(product)
    except Exception as exc:  # noqa: BLE001 — a rebuild failure must be visible
        flash("Rebuild failed: %s: %s" % (type(exc).__name__, exc), "danger")
        return redirect(url_for(page_endpoint))
    vers = matrix.get("versions") or {}
    measured = [v for v, d in vers.items() if d.get("measured")]
    flash("Matrix rebuilt from evidence on disk — %d firmware version(s), %d of "
          "them measured: %s."
          % (len(vers), len(measured),
             ", ".join(sorted(measured, key=firmware_versions.sort_key)) or "none"),
          "success")
    # A rollup made of more than one build is the thing an operator most needs
    # told, because every "the line serves it" on this page is then a claim
    # about a merge.
    for ln, doc in sorted((matrix.get("lines") or {}).items()):
        if doc.get("heterogeneous"):
            flash("Line %s merges %s — %d endpoint(s) are attested by only some "
                  "of them and are listed as partial, never as served."
                  % (ln, ", ".join(doc.get("measured_versions") or []),
                     (doc.get("counts") or {}).get("partial", 0)), "warning")
    # Every skipped witness is surfaced. A device dropped for being unhealthy
    # is the single most useful thing on this page and the easiest to lose in
    # a success banner.
    for note in matrix.get("notes") or []:
        flash("%s skipped — %s." % (note.get("device", "?"), note.get("skipped", "")),
              "warning")
    return redirect(url_for(page_endpoint))


def declare_page(product: str, page_endpoint: str):
    """Author a firmware version by hand.

    This is the half of "versions get registered when a firmware is uploaded or
    by hand" that has nowhere else to live. The upload half is DERIVED from the
    ``FirmwareImage`` table on every read — see
    ``firmware_versions._image_versions`` — because two separate code paths
    create those rows and hooking both would be one refactor away from a
    version that silently never appears here.
    """
    ok, msg, version = firmware_versions.declare(
        product, request.form.get("version") or "",
        note=request.form.get("note") or "",
        by=getattr(current_user, "username", "") or "")
    flash(msg, "success" if ok else "danger")
    if ok:
        log_action("api_versions.declare", target="%s %s" % (product, version),
                   extra={"note": (request.form.get("note") or "")[:200]})
    return redirect(url_for(page_endpoint))


def review_page(product: str, page_endpoint: str):
    """Accept or refuse ONE ledger finding, from the comparison that shows it.

    There is deliberately no ``apply`` verb here either: see
    ``absence_record.BLOCKED_REASON``. A control that always refuses teaches
    the operator that the page is broken, which is worse than its absence.

    The redirect preserves the pair. A review that drops the operator back on
    the default comparison makes the second decision harder than the first,
    which is how a queue stops being worked.
    """
    base = request.form.get("base") or ""
    target = request.form.get("target") or ""

    def _back():
        return redirect(url_for(page_endpoint, base=base, target=target))

    try:
        rid = int(request.form.get("row_id") or "")
    except (TypeError, ValueError):
        flash("No finding selected.", "warning")
        return _back()
    ok, msg, row = absence_record.review(
        rid, (request.form.get("decision") or "").strip(),
        actor=getattr(current_user, "username", "") or "unknown",
        note=(request.form.get("note") or "").strip())
    flash(msg, "success" if ok else "danger")
    if ok and row is not None:
        # The row's OWN scopes in the audit target, never the page's: the
        # decision was recorded against the line pair, and an audit line that
        # named the two builds on screen would be a record of something that
        # did not happen.
        log_action("api_versions.absence_review",
                   target="%s %s %s->%s" % (product, row.name, row.base_scope,
                                            row.target_scope),
                   extra={"decision": request.form.get("decision") or "",
                          "state": row.state,
                          "note": (request.form.get("note") or "")[:200]})
    return _back()


def forget_page(product: str, page_endpoint: str):
    """Drop a hand-authored declaration. Never unmakes a derived one."""
    version = request.form.get("version") or ""
    ok, msg = firmware_versions.forget(product, version)
    flash(msg, "success" if ok else "warning")
    if ok:
        log_action("api_versions.forget", target="%s %s" % (product, version))
    return redirect(url_for(page_endpoint))


__all__ = ["render_page", "rebuild_page", "declare_page", "forget_page"]
