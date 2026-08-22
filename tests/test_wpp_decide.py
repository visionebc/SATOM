"""New, compare and decide — the profile policy that edits a live object.

⚠ THE SLICE RUNS BACKWARDS, AND THAT IS THE WHOLE THING

The plan is POST-ORDER: a referenced object is emitted BEFORE the object that
names it, because a clone creates the dependency first. Measured on a real plan
(fortiweb12 -> fortiweb13, ``pol-root-shop``):

    Web Protection Profile   #125  depth 1
    root Server Policy       #126  depth 0
    walking BACK while depth > 1   -> 111 items
    scanning FORWARD from #125     ->   1 item

A forward scan does not fail — it SUB-REPORTS, and sub-reporting reads exactly
like agreement: the comparison would offer the profile's own fields and nothing
else, and declining everything would decline almost nothing. That is how the
standalone shipped it for four releases.

The tests below build a post-order fixture BY THE SAME RULE the planner uses,
and one of them asserts the fixture really is post-order — a pre-order fixture
is what let the bug survive.
"""
import pytest

from app.services import clone, wpp_decide
from app.services.clone import CloneItem

WPP = clone._WPP_INLINE
SIG = "cmdb/waf/signature"
SIGLIST = SIG + "/disable-signature-list"


def _it(label, urn, mkey, parent, kind, depth, payload, status):
    return CloneItem(label, urn, "logical", mkey, parent, kind, depth,
                     dict(payload), status)


def _plan(wpp_status="exists", rows=(("r1", "create"), ("r2", "exists")),
          wpp_payload=None):
    """A POST-ORDER plan: the profile's descendants, then the profile, then the
    policy. Deliberately with a SIBLING of the profile at the same depth before
    the block, because that is what bounds the slice."""
    items = [
        _it("Replacement Message Group", "cmdb/system/replacemsg", "rmg1", "",
            "object", 1, {"name": "rmg1"}, "exists"),
        _it("Signatures", SIG, "sig1", "", "object", 2, {"name": "sig1"},
            "create"),
    ]
    for mkey, status in rows:
        items.append(_it("Signatures · Disabled", SIGLIST, mkey, "sig1",
                         "subrow", 3, {"id": mkey}, status))
    items.append(_it("Web Protection Profile", WPP, "wpp1", "", "object", 1,
                     wpp_payload or {"name": "wpp1", "signature-rule": "sig1",
                                     "url-access-policy": ""},
                     wpp_status))
    items.append(_it("Server Policy", "cmdb/server-policy/policy", "pol1", "",
                     "object", 0, {"name": "pol1"}, "create"))
    return items


class FakeDst:
    def __init__(self, rows):
        self.rows = rows

    def get_raw(self, urn, mkey=""):
        return [dict(r) for r in self.rows.get((urn, mkey), [])]


# --------------------------------------------------------------------------- #
#  0. the fixture itself                                                        #
# --------------------------------------------------------------------------- #
def test_the_fixture_is_post_order_like_a_real_plan():
    """A PRE-ORDER fixture is what let the forward-scan bug survive."""
    items = _plan()
    wpp_i = next(i for i, it in enumerate(items) if it.urn == WPP)
    pol_i = next(i for i, it in enumerate(items)
                 if it.urn == "cmdb/server-policy/policy")
    sig_i = next(i for i, it in enumerate(items) if it.urn == SIG)
    assert sig_i < wpp_i < pol_i


# --------------------------------------------------------------------------- #
#  1. the slice                                                                 #
# --------------------------------------------------------------------------- #
def test_the_subtree_walks_BACKWARDS_and_ends_at_the_profile():
    items = _plan()
    block = wpp_decide.wpp_subtree(items)
    assert block[-1].urn == WPP
    assert [b.urn for b in block[:-1]] == [SIG, SIGLIST, SIGLIST]
    assert len(block) == 4


def test_a_forward_scan_would_find_almost_nothing():
    """Pinned so the direction can never be 'simplified' back."""
    items = _plan()
    wpp = next(it for it in items if it.urn == WPP)
    idx = items.index(wpp)
    forward = [it for it in items[idx + 1:] if it.depth > wpp.depth]
    assert forward == []
    assert len(wpp_decide.wpp_subtree(items)) == 4


def test_a_sibling_at_the_same_depth_is_not_swept_in():
    items = _plan()
    block = wpp_decide.wpp_subtree(items)
    assert all(b.urn != "cmdb/system/replacemsg" for b in block)


def test_a_plan_with_no_profile_slices_to_nothing():
    items = [it for it in _plan() if it.urn != WPP]
    assert wpp_decide.wpp_subtree(items) == []


# --------------------------------------------------------------------------- #
#  2. what gets offered                                                         #
# --------------------------------------------------------------------------- #
def test_nothing_is_offered_when_the_profile_is_not_already_there():
    """A routine copy must not look like a merge."""
    items = _plan(wpp_status="create")
    assert wpp_decide.offers(items, FakeDst({})) == []


def test_the_profiles_OWN_fields_are_compared_which_the_planner_never_did():
    """An existing profile is classified ``exists`` and asked nothing more, so
    one whose ~40 lists all match but whose own switches differ reads identical
    and is not."""
    items = _plan()
    dst = FakeDst({(WPP, "wpp1"): [{"name": "wpp1", "signature-rule": "",
                                    "url-access-policy": "uap-prod"}]})
    # by ACTION, not by kind: a created OBJECT under the profile (the
    # Signatures object here) is also kind="object", and filtering on that
    # would have this test pass for the wrong reason.
    got = wpp_decide.offers(items, dst)
    obj = [o for o in got if o["action"] == "retune"]
    assert len(obj) == 1
    fields = {f["field"]: (f["destination"], f["source"])
              for f in obj[0]["fields"]}
    assert fields["signature-rule"] == ("", "sig1")
    # a field the SOURCE leaves blank is still a difference, but the direction
    # is reported honestly
    assert fields["url-access-policy"] == ("uap-prod", "")


def test_an_identical_profile_offers_no_RETUNE():
    """Its rows may still differ — that is a separate question and it keeps its
    own offers. What must disappear is the profile's own field change."""
    items = _plan()
    dst = FakeDst({(WPP, "wpp1"): [{"name": "wpp1", "signature-rule": "sig1",
                                    "url-access-policy": ""}]})
    got = wpp_decide.offers(items, dst)
    assert [o["action"] for o in got if o["action"] == "retune"] == []
    assert [o["mkey"] for o in got if o["kind"] == "subrow"] == ["r1"]


def test_only_rows_that_would_be_WRITTEN_are_offered():
    items = _plan(rows=(("r1", "create"), ("r2", "exists"), ("r3", "update")))
    dst = FakeDst({(WPP, "wpp1"): [{"name": "wpp1", "signature-rule": "sig1"}]})
    rows = [o for o in wpp_decide.offers(items, dst) if o["kind"] == "subrow"]
    assert {o["mkey"] for o in rows} == {"r1", "r3"}
    assert {o["action"] for o in rows} == {"add", "change"}


def test_an_unreadable_destination_object_does_not_invent_differences():
    """``get_raw`` never raises; a failed read comes back empty, and empty
    compared field-by-field would report EVERY field as changed."""
    items = _plan()
    got = wpp_decide.offers(items, FakeDst({}))
    obj = [o for o in got if o["action"] == "retune"]
    # it still offers a retune, but only for the fields the SOURCE names
    assert obj and all(f["field"] in ("signature-rule", "url-access-policy")
                       for f in obj[0]["fields"])


# --------------------------------------------------------------------------- #
#  3. the key                                                                   #
# --------------------------------------------------------------------------- #
def test_the_key_is_built_from_identity_not_position():
    a = _it("x", SIGLIST, "r1", "sig1", "subrow", 3, {}, "create")
    b = _it("DIFFERENT LABEL", SIGLIST, "r1", "sig1", "subrow", 3, {"z": 1},
            "update")
    assert wpp_decide.item_key(a) == wpp_decide.item_key(b)
    c = _it("x", SIGLIST, "r2", "sig1", "subrow", 3, {}, "create")
    assert wpp_decide.item_key(a) != wpp_decide.item_key(c)
    # the same mkey under a DIFFERENT parent is a different row
    d = _it("x", SIGLIST, "r1", "sig2", "subrow", 3, {}, "create")
    assert wpp_decide.item_key(a) != wpp_decide.item_key(d)


# --------------------------------------------------------------------------- #
#  4. applying the answer                                                       #
# --------------------------------------------------------------------------- #
def _keys(items, urn=None):
    return [wpp_decide.item_key(it) for it in items
            if urn is None or it.urn == urn]


def test_an_unticked_offer_is_REMOVED_from_the_plan_not_skipped():
    """An item left in saying ``create`` describes a write that will not happen,
    and every counter, report and verification reads the plan."""
    # ⚠ CORRECTED IN 1.12.0. This test used to accept ``r1`` while DECLINING
    # its parent ``sig1``, and then assert that r1 survived. That is a write
    # addressed with ``?mkey=sig1`` against an object the same decision had
    # just removed from the plan — ``-651`` on the appliance. The old
    # expectation pinned the defect; the orphan case now has its own test.
    # Here the parent is ACCEPTED, so the only question left is the one this
    # test is actually about: an unticked row is removed, not skipped.
    items = _plan(rows=(("r1", "create"), ("r2", "create")))
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update") and it.urn != "cmdb/server-policy/policy"]
    keep = [k for k in shown if k.endswith("r1|sig1|subrow") or "|sig1||object" in k]
    res = wpp_decide.apply_decisions(items, keep, shown)
    assert res["kept"] == 2 and res["dropped"] == 1   # r2 only
    assert [it.mkey for it in items if it.urn == SIGLIST] == ["r1"]


def test_a_declined_profile_object_is_KEPT_as_exists():
    """The rows beneath it are addressed through it — removing it takes them."""
    items = _plan()
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update") or it.urn == WPP]
    wpp_decide.apply_decisions(items, [], shown)
    wpp = next(it for it in items if it.urn == WPP)
    assert wpp.status == "exists" and "declined" in wpp.note


def test_an_accepted_profile_object_becomes_obj_update_not_update():
    """``update`` addresses a ROW (``?mkey=`` plus ``?sub_mkey=``). Sent that
    way an object carries an empty sub-key and addresses nothing at all."""
    items = _plan()
    wpp = next(it for it in items if it.urn == WPP)
    key = wpp_decide.item_key(wpp)
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update")] + [key]
    res = wpp_decide.apply_decisions(items, shown, shown)
    assert res["retuned"] is True
    assert next(it for it in items if it.urn == WPP).status == "obj-update"
    assert "obj-update" in clone._STATUS_LABELS


def test_an_offer_that_was_never_shown_REFUSES_the_apply():
    """The source changed between analyse and apply. Skipping it writes nothing
    the operator saw and calls the run green; taking it writes something they
    never saw at all."""
    items = _plan(rows=(("r1", "create"), ("r9", "create")))
    shown = [wpp_decide.item_key(it) for it in items
             if it.urn == SIGLIST and it.mkey == "r1"]
    shown.append(wpp_decide.item_key(
        next(it for it in items if it.urn == SIG)))
    with pytest.raises(wpp_decide.StaleDecision) as exc:
        wpp_decide.apply_decisions(items, shown, shown)
    assert "re-run the comparison" in str(exc.value)


def test_items_outside_the_profile_are_never_touched():
    items = _plan()
    before = [it.mkey for it in items
              if it.urn in ("cmdb/system/replacemsg", "cmdb/server-policy/policy")]
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update")
             and it.urn not in ("cmdb/server-policy/policy",)]
    wpp_decide.apply_decisions(items, shown, shown)
    after = [it.mkey for it in items
             if it.urn in ("cmdb/system/replacemsg", "cmdb/server-policy/policy")]
    assert before == after


def test_nothing_happens_when_the_profile_is_being_created():
    items = _plan(wpp_status="create")
    n = len(items)
    res = wpp_decide.apply_decisions(items, [], [])
    assert (res["kept"], res["dropped"], res["retuned"]) == (0, 0, False)
    # Nothing was decided, so nothing may have been reverted or cascaded
    # either — an empty outcome has to be empty on every axis it reports.
    assert res["reverted"] == [] and res["cascaded"] == []
    assert len(items) == n


# --------------------------------------------------------------------------- #
#  5. the write body                                                            #
# --------------------------------------------------------------------------- #
def test_the_object_write_is_the_MINIMAL_EDIT():
    """A bare source payload blanks every destination field the source never
    named. And a blank in the SOURCE means "this box does not use this field",
    not "erase the other one's"."""
    body = wpp_decide.object_update_payload(
        {"name": "wpp1", "signature-rule": "sig1", "url-access-policy": ""},
        {"name": "wpp1", "signature-rule": "", "url-access-policy": "uap-prod",
         "amethod-policy": "am-prod"})
    assert body["signature-rule"] == "sig1"       # taken from the source
    assert body["url-access-policy"] == "uap-prod"  # source blank => left alone
    assert body["amethod-policy"] == "am-prod"   # never named => survives


def test_the_name_always_comes_from_the_destination():
    """It is what the URL addresses. A body renaming the object mid-PUT is a
    different operation wearing this one's name."""
    body = wpp_decide.object_update_payload({"name": "SOURCE", "a": "1"},
                                            {"name": "DEST", "a": "0"})
    assert body["name"] == "DEST" and body["a"] == "1"


# --------------------------------------------------------------------------- #
#  6. the asymmetry between a row and the object                                #
# --------------------------------------------------------------------------- #
def test_an_unshown_ROW_refuses_but_an_unshown_RETUNE_just_declines():
    """The two "never shown" cases are not symmetric, and the reason is which
    way the default writes.

    A row that was never shown would be CREATED without anyone seeing it, so the
    apply is refused. The profile object is never created here — it already
    exists — so a retune nobody saw simply does not happen, and the destination
    keeps exactly what it is serving. Refusing that would block a run over a
    change the operator never asked for.
    """
    items = _plan(rows=(("r1", "create"),))
    row_key = next(wpp_decide.item_key(it) for it in items if it.urn == SIGLIST)
    sig_key = next(wpp_decide.item_key(it) for it in items if it.urn == SIG)
    # the retune is NOT in `shown`, and that is fine
    res = wpp_decide.apply_decisions(items, [], [row_key, sig_key])
    wpp = next(it for it in items if it.urn == WPP)
    assert res["retuned"] is False and wpp.status == "exists"
    # but drop the ROW from `shown` and it refuses
    items2 = _plan(rows=(("r1", "create"),))
    with pytest.raises(wpp_decide.StaleDecision):
        wpp_decide.apply_decisions(items2, [], [sig_key])


def test_an_accepted_retune_is_visible_in_the_summary():
    """Measured on a real dry run before this was wired: the retune moved out of
    ``exists`` and into NO counter at all — a plan describing a write and a
    summary mentioning it nowhere."""
    from app.services import policy_ops
    items = _plan()
    wpp = next(it for it in items if it.urn == WPP)
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update")] + [wpp_decide.item_key(wpp)]
    wpp_decide.apply_decisions(items, shown, shown)
    summary = policy_ops.clone_summary(items)
    assert summary["to_update"] >= 1


# --------------------------------------------------------------------------- #
#  7. an accepted retune must actually be WRITTEN                               #
# --------------------------------------------------------------------------- #
def _retuned_plan():
    items = _plan()
    wpp = next(it for it in items if it.urn == WPP)
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update")] + [wpp_decide.item_key(wpp)]
    wpp_decide.apply_decisions(items, shown, shown)
    return items


def test_apply_clone_WRITES_an_obj_update_and_does_not_skip_it():
    """The gap this closes: every earlier test drove the PLANNER. A status the
    plan produces and the writer ignores is a run that reports a change it never
    made — and it looks identical to one that made it.
    """
    written = []
    items = _retuned_plan()
    clone.apply_clone(items, written.append, dry_run=False)
    wpp = next(it for it in items if it.urn == WPP)
    assert wpp.status == "obj-update"
    assert wpp in written, "an accepted retune was planned and never written"
    assert wpp.applied is True and wpp.result == "updated"


def test_a_DECLINED_retune_is_never_written():
    written = []
    items = _plan()
    shown = [wpp_decide.item_key(it) for it in items
             if it.status in ("create", "update")]
    shown.append(wpp_decide.item_key(next(it for it in items if it.urn == WPP)))
    wpp_decide.apply_decisions(items, [], shown)
    clone.apply_clone(items, written.append, dry_run=False)
    wpp = next(it for it in items if it.urn == WPP)
    assert wpp.status == "exists" and wpp not in written


def test_a_dry_run_writes_nothing_but_still_reports_the_retune():
    written = []
    items = _retuned_plan()
    clone.apply_clone(items, written.append, dry_run=True)
    wpp = next(it for it in items if it.urn == WPP)
    assert written == [] and wpp.result == "dry-run"
    assert "obj-update" in clone.summarize(items)


# --------------------------------------------------------------------------- #
#  6. honouring a decline in the fields that NAME it (1.12.0)                    #
# --------------------------------------------------------------------------- #
#
# ⚠ Dropping the declined item was only HALF of "decline", and the missing half
# was the half that writes. The profile that NAMED the declined section was
# still written with the SOURCE's value for that field, so the destination
# ended up naming a sub-policy it does not have — and this firmware answers
# that by seating a default of its own. The operator who asked to keep the
# destination's original got neither tree.


def _shown_keys(items):
    keys = [wpp_decide.item_key(it) for it in items
            if it.status in ("create", "update")]
    keys.append(wpp_decide.item_key(next(it for it in items if it.urn == WPP)))
    return keys


def _dst(signature_rule="dst-sig"):
    return FakeDst({(WPP, "wpp1"): [{"name": "wpp1",
                                     "signature-rule": signature_rule,
                                     "url-access-policy": "dst-uap"}]})


def test_names_one_of_matches_a_scalar_reference_by_value():
    assert wpp_decide._names_one_of({"signature-rule": "sig1"}, {"sig1"}) \
        == ["signature-rule"]


def test_names_one_of_ignores_the_row_id_a_blank_and_a_list():
    # ``id`` is auto-assigned per box: one that happens to equal a declined
    # object's name is not a reference to it. A blank names nothing, and a list
    # field is re-pointed name by name elsewhere.
    hit = wpp_decide._names_one_of(
        {"id": "sig1", "blank": "", "refs": ["sig1"], "real": "sig1"}, {"sig1"})
    assert hit == ["real"]


def test_names_one_of_with_nothing_declined_matches_nothing():
    assert wpp_decide._names_one_of({"signature-rule": "sig1"}, set()) == []


def test_declining_a_section_puts_the_naming_field_back_to_the_destination():
    items = _plan()
    shown = _shown_keys(items)
    wpp_key = wpp_decide.item_key(next(it for it in items if it.urn == WPP))
    # the retune is ACCEPTED; only the signature object is declined.
    accepted = [k for k in shown if k != wpp_decide.item_key(
        next(it for it in items if it.urn == SIG))]
    res = wpp_decide.apply_decisions(items, accepted, shown,
                                     dst_reader=_dst())
    assert wpp_key in accepted
    wpp = next(it for it in items if it.urn == WPP)
    assert wpp.status == "obj-update"
    assert wpp.payload["signature-rule"] == "dst-sig", \
        "the declined section is still named by the profile that will be written"
    assert any(r["field"] == "signature-rule" and r["destination"] == "dst-sig"
               for r in res["reverted"])


def test_the_reverted_field_is_not_in_the_write_body_either():
    items = _plan()
    shown = _shown_keys(items)
    accepted = [k for k in shown if k != wpp_decide.item_key(
        next(it for it in items if it.urn == SIG))]
    wpp_decide.apply_decisions(items, accepted, shown, dst_reader=_dst())
    wpp = next(it for it in items if it.urn == WPP)
    body = wpp_decide.object_update_payload(wpp.payload, wpp.dst_row)
    assert body["signature-rule"] == "dst-sig"


def test_a_revert_never_writes_the_source_value_when_the_destination_is_blank():
    # Restoring a blank is not a third outcome invented here: the destination
    # genuinely holds nothing, and ``object_update_payload`` drops empty source
    # fields, so the destination keeps what it has. What must NEVER survive is
    # the SOURCE's name for a section that is not being created.
    items = _plan()
    shown = _shown_keys(items)
    accepted = [k for k in shown if k != wpp_decide.item_key(
        next(it for it in items if it.urn == SIG))]
    wpp_decide.apply_decisions(items, accepted, shown,
                               dst_reader=_dst(signature_rule=""))
    wpp = next(it for it in items if it.urn == WPP)
    body = wpp_decide.object_update_payload(wpp.payload, wpp.dst_row)
    assert body.get("signature-rule", "") != "sig1"


def test_accepting_everything_reverts_nothing():
    items = _plan()
    shown = _shown_keys(items)
    res = wpp_decide.apply_decisions(items, shown, shown, dst_reader=_dst())
    assert res["reverted"] == [] and res["cascaded"] == []
    wpp = next(it for it in items if it.urn == WPP)
    assert wpp.payload["signature-rule"] == "sig1"


def test_a_declined_retune_is_not_reverted_because_it_is_never_written():
    # The profile itself was declined, so it drops to ``exists`` and no body is
    # sent. Reverting a field on an item nobody writes would report a repair
    # that did not happen.
    items = _plan()
    shown = _shown_keys(items)
    res = wpp_decide.apply_decisions(items, [], shown, dst_reader=_dst())
    wpp = next(it for it in items if it.urn == WPP)
    assert wpp.status == "exists" and res["reverted"] == []


# --------------------------------------------------------------------------- #
#  7. the cascade: a CREATE has no original to keep                             #
# --------------------------------------------------------------------------- #


def _plan_with_dependent_create():
    """``uap1`` is a CREATE that names the signature object. Declining ``sig1``
    leaves nothing for ``uap1`` to name."""
    items = _plan()
    uap = _it("URL Access Policy", "cmdb/waf/url-access.url-access-policy",
              "uap1", "", "object", 2, {"name": "uap1",
                                        "signature-rule": "sig1"}, "create")
    items.insert(2, uap)
    return items


def test_a_create_that_names_a_declined_section_is_dropped_not_blanked():
    items = _plan_with_dependent_create()
    shown = _shown_keys(items)
    accepted = [k for k in shown if k != wpp_decide.item_key(
        next(it for it in items if it.urn == SIG))]
    res = wpp_decide.apply_decisions(items, accepted, shown, dst_reader=_dst())
    assert not any(it.mkey == "uap1" for it in items), \
        "it would have been written naming an object that will not exist (-651)"
    assert any(c["mkey"] == "uap1" for c in res["cascaded"])


def test_a_cascaded_drop_is_counted_as_a_drop():
    items = _plan_with_dependent_create()
    shown = _shown_keys(items)
    accepted = [k for k in shown if k != wpp_decide.item_key(
        next(it for it in items if it.urn == SIG))]
    before = len([it for it in items if it.status == "create"])
    res = wpp_decide.apply_decisions(items, accepted, shown, dst_reader=_dst())
    after = len([it for it in items if it.status == "create"])
    assert res["dropped"] == before - after


def test_the_cascade_is_transitive():
    # uap1 names sig1; a third object names uap1. Declining sig1 must reach it.
    items = _plan_with_dependent_create()
    third = _it("Custom Response", "cmdb/waf/http-custom-response", "cr1", "",
                "object", 2, {"name": "cr1", "url-access-policy": "uap1"},
                "create")
    items.insert(3, third)
    shown = _shown_keys(items)
    accepted = [k for k in shown if k != wpp_decide.item_key(
        next(it for it in items if it.urn == SIG))]
    res = wpp_decide.apply_decisions(items, accepted, shown, dst_reader=_dst())
    assert not any(it.mkey == "cr1" for it in items)
    # ``r1`` is in there by the OTHER route: its parent ``sig1`` was declined,
    # so the row has no object left to be addressed through.
    assert {c["mkey"] for c in res["cascaded"]} == {"uap1", "cr1", "r1"}


def test_an_accepted_row_under_a_declined_parent_is_dropped_too():
    # ⚠ A row does not NAME its parent in a field — it is addressed by
    # ``parent_mkey``. Matching only payload values let an accepted row survive
    # a declined parent and be written with ``?mkey=`` pointing at an object
    # that will not exist.
    items = _plan()
    shown = _shown_keys(items)
    sig_key = wpp_decide.item_key(next(it for it in items if it.urn == SIG))
    accepted = [k for k in shown if k != sig_key]       # r1 IS accepted
    res = wpp_decide.apply_decisions(items, accepted, shown, dst_reader=_dst())
    assert not any(it.mkey == "r1" for it in items)
    assert any(c["mkey"] == "r1" and "parent" in c["why"]
               for c in res["cascaded"])


def test_a_row_of_a_DIFFERENT_collection_sharing_the_parent_name_survives():
    # Parenthood is the pair (collection, key). Two unrelated objects that
    # share a name must not drag each other's rows out of the plan.
    items = _plan()
    other = _it("Elsewhere · row", "cmdb/waf/url-access.url-access-policy/rule",
                "x1", "sig1", "subrow", 3, {"id": "x1"}, "create")
    items.insert(3, other)
    shown = _shown_keys(items)
    sig_key = wpp_decide.item_key(next(it for it in items if it.urn == SIG))
    accepted = [k for k in shown if k != sig_key]
    wpp_decide.apply_decisions(items, accepted, shown, dst_reader=_dst())
    assert any(it.mkey == "x1" for it in items)


def test_nothing_outside_the_profile_subtree_is_ever_touched():
    items = _plan_with_dependent_create()
    shown = _shown_keys(items)
    res = wpp_decide.apply_decisions(items, [], shown, dst_reader=_dst())
    assert any(it.mkey == "pol1" and it.status == "create" for it in items), \
        "the policy itself was never offered, so it may not change"
    assert any(it.mkey == "rmg1" for it in items)
    assert all(c["mkey"] != "pol1" for c in res["cascaded"])
