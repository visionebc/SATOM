"""Two things that are only true of a BULK run.

PROFILES ONCE PER RUN
    Several policies routinely share one Web Protection Profile, and walking its
    ~40 sub-tables again for the second policy is the slow half of a plan spent
    reaching the same verdict — 123 planned objects against 12, measured live.
    This is the ONLY part of the clone that is inherently cross-policy;
    everything else rides in ``opts``, which ``perform_one`` reads once, so a
    knob threaded there is true of the single-policy dialog and of the job at
    the same time.

READERS IN PARALLEL, WRITERS NEVER
    Measured on fortiweb12 (7.6.8), 40 identical GETs:

        workers   1      2      4      8     10     16
        seconds   3.85   1.90   1.61   1.61  1.56   1.54

    So the ceiling is real and it is near four. Applies stay sequential, and not
    out of caution: policies share objects, so two applies creating the same one
    at the same instant hand the loser a duplicate error that depends on the
    clock — a correct plan reporting a failure nobody can reproduce.
"""
import inspect
import threading

import pytest

from app.services import policy_ops


# --------------------------------------------------------------------------- #
#  1. the dedup key                                                             #
# --------------------------------------------------------------------------- #
class FakeSrc:
    def __init__(self, rows):
        self.rows = rows

    def get_raw(self, urn, mkey=""):
        return list(self.rows.get(mkey, []))


def _src(**policies):
    return FakeSrc({k: [dict(v, name=k)] for k, v in policies.items()})


def test_the_key_is_the_PAIR_not_the_landing_name():
    """Two policies landing on the same NAME from DIFFERENT source profiles are
    not a repeat: the second walk carries rows the first never had."""
    src = _src(p1={"web-protection-profile": "A"},
               p2={"web-protection-profile": "B"})
    k1 = policy_ops.wpp_dedup_key(src, "p1")
    k2 = policy_ops.wpp_dedup_key(src, "p2")
    assert k1 != k2
    assert k1[0] == "A" and k2[0] == "B"


def test_two_policies_on_the_same_profile_share_a_key():
    src = _src(p1={"web-protection-profile": "A"},
               p2={"web-protection-profile": "A"})
    assert policy_ops.wpp_dedup_key(src, "p1") == policy_ops.wpp_dedup_key(src, "p2")


def test_a_policy_with_no_profile_has_no_key():
    src = _src(p1={"web-protection-profile": ""})
    assert policy_ops.wpp_dedup_key(src, "p1") == ()
    assert policy_ops.wpp_dedup_key(src, "absent") == ()


def test_an_unreadable_source_means_cannot_dedup_not_a_crash():
    class Boom:
        def get_raw(self, *a, **k):
            raise RuntimeError("device down")

    assert policy_ops.wpp_dedup_key(Boom(), "p1") == ()


def test_a_rename_changes_the_landing_half_of_the_key():
    src = _src(p1={"web-protection-profile": "A"})
    plain = policy_ops.wpp_dedup_key(src, "p1")
    renamed = policy_ops.wpp_dedup_key(src, "p1", "A-copy")
    assert plain[0] == renamed[0] == "A"
    assert plain[1] != renamed[1]


# --------------------------------------------------------------------------- #
#  2. how many readers                                                          #
# --------------------------------------------------------------------------- #
def test_the_default_is_one_and_the_ceiling_is_ten():
    assert policy_ops.analyse_workers(None) == 1
    assert policy_ops.analyse_workers({}) == 1
    assert policy_ops.analyse_workers({"analyse_workers": 4}) == 4
    assert policy_ops.analyse_workers({"analyse_workers": 99}) == 10
    assert policy_ops.analyse_workers({"analyse_workers": 0}) == 1
    assert policy_ops.analyse_workers({"analyse_workers": -3}) == 1
    assert policy_ops.analyse_workers({"analyse_workers": "banana"}) == 1


def test_the_saturation_point_is_published_next_to_the_ceiling():
    """Offering 10 without saying where it saturates reads as "ten times
    faster", which is the one thing the measurement says it is not."""
    assert policy_ops.ANALYSE_SATURATION == 4
    assert policy_ops.ANALYSE_SATURATION < policy_ops.MAX_ANALYSE_WORKERS


# --------------------------------------------------------------------------- #
#  3. the apply path may never read it                                          #
# --------------------------------------------------------------------------- #
def test_the_bulk_APPLY_never_reads_the_worker_count():
    """Structural, because the failure mode is a race: policies share objects,
    so parallel applies hand the loser a clock-dependent duplicate error."""
    src = inspect.getsource(policy_ops.start_policy_job)
    assert "analyse_workers" not in src
    assert "ThreadPoolExecutor" not in src


def test_only_the_preview_builds_a_pool():
    pooled = [name for name, fn in vars(policy_ops).items()
              if inspect.isfunction(fn)
              and "ThreadPoolExecutor" in (inspect.getsource(fn) or "")]
    assert pooled == ["preview"]


# --------------------------------------------------------------------------- #
#  4. the preview itself                                                        #
# --------------------------------------------------------------------------- #
class _Appl:
    def __init__(self, ident):
        self.id = ident
        self.name = "appl%s" % ident


POLICIES = ["p-%02d" % i for i in range(8)]


def _patch_perform(monkeypatch, sink=None, delay=None):
    def fake(action, *, source_appl, dest_appl=None, policy, new_name,
             dry_run, opts=None):
        assert dry_run is True, "a preview must never write"
        if sink is not None:
            sink.append(policy)
        if delay:
            delay(policy)
        return {"policy": policy, "ok": True, "action": action}

    monkeypatch.setattr(policy_ops, "perform_one", fake)


def test_one_worker_does_not_build_a_pool_at_all(monkeypatch):
    """A pool of one is a different execution model with the old default's
    name. The sequential path must return before any thread exists."""
    seen = []
    _patch_perform(monkeypatch, sink=seen)
    started = []
    real = threading.Thread.start
    monkeypatch.setattr(threading.Thread, "start",
                        lambda self, *a, **k: started.append(1) or real(self, *a, **k))
    out = policy_ops.preview("clone_to", source_appl=_Appl(1), dest_appl=_Appl(2),
                             policies=POLICIES, opts={"analyse_workers": 1})
    assert [r["policy"] for r in out] == POLICIES
    assert started == []


def test_results_come_back_in_SELECTION_order_never_completion_order(app):
    """A list in completion order silently re-labels every row against the
    selection the operator is looking at."""
    import random
    from app.services import policy_ops as po

    def fake(action, *, source_appl, dest_appl=None, policy, new_name,
             dry_run, opts=None):
        # deliberately finish out of order
        threading.Event().wait(0.02 if policy.endswith("0") else 0.001)
        return {"policy": policy, "ok": True, "action": action}

    orig, po.perform_one = po.perform_one, fake
    try:
        with app.app_context():
            out = po.preview("clone_to", source_appl=_Appl(1),
                             dest_appl=_Appl(2), policies=POLICIES,
                             opts={"analyse_workers": 4})
    finally:
        po.perform_one = orig
    assert [r["policy"] for r in out] == POLICIES


def test_no_more_than_the_asked_for_workers_run_at_once(app):
    from app.services import policy_ops as po
    live, peak, lock = 0, [0], threading.Lock()

    def fake(action, *, source_appl, dest_appl=None, policy, new_name,
             dry_run, opts=None):
        nonlocal live
        with lock:
            live += 1
            peak[0] = max(peak[0], live)
        threading.Event().wait(0.03)
        with lock:
            live -= 1
        return {"policy": policy, "ok": True}

    orig, po.perform_one = po.perform_one, fake
    try:
        with app.app_context():
            po.preview("clone_to", source_appl=_Appl(1), dest_appl=_Appl(2),
                       policies=POLICIES, opts={"analyse_workers": 3})
    finally:
        po.perform_one = orig
    assert 1 < peak[0] <= 3


def test_one_policy_that_raises_does_not_sink_the_preview(app):
    from app.services import policy_ops as po

    def fake(action, *, source_appl, dest_appl=None, policy, new_name,
             dry_run, opts=None):
        if policy == "p-03":
            raise RuntimeError("device refused")
        return {"policy": policy, "ok": True}

    orig, po.perform_one = po.perform_one, fake
    try:
        with app.app_context():
            out = po.preview("clone_to", source_appl=_Appl(1),
                             dest_appl=_Appl(2), policies=POLICIES,
                             opts={"analyse_workers": 4})
    finally:
        po.perform_one = orig
    assert [r["policy"] for r in out] == POLICIES
    bad = next(r for r in out if r["policy"] == "p-03")
    assert bad["ok"] is False and "device refused" in bad["error"]


# --------------------------------------------------------------------------- #
#  5. the per-policy decision the bulk loop makes                               #
# --------------------------------------------------------------------------- #
def test_the_first_time_a_profile_is_seen_nothing_changes():
    base = {"copy_wpp": True, "vip_ip": "auto"}
    assert policy_ops.dedup_opts(base, ("A", "A"), set()) is base


def test_a_repeat_of_an_already_carried_profile_prunes_the_subtree():
    """It REUSES ``wpp_only_if_missing`` — one tested implementation of "leave
    an existing profile alone", not two that can disagree."""
    base = {"copy_wpp": True}
    got = policy_ops.dedup_opts(base, ("A", "A"), {("A", "A")})
    assert got["wpp_only_if_missing"] is True
    assert got["copy_wpp"] is True


def test_the_jobs_own_options_are_never_edited_in_place():
    """Editing them would make policy N's answer depend on policy N-1 for every
    knob, not just this one."""
    base = {"copy_wpp": True}
    policy_ops.dedup_opts(base, ("A", "A"), {("A", "A")})
    assert "wpp_only_if_missing" not in base


def test_a_policy_with_no_key_is_never_deduped():
    base = {"copy_wpp": True}
    assert policy_ops.dedup_opts(base, (), {("A", "A")}) is base
    assert policy_ops.dedup_opts(base, ("B", "B"), {("A", "A")}) is base
