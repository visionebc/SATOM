"""Guards for what the Scout page SHOWS — the two defects a passing suite kept.

Both classes here were reported by the operator, in one sentence, on
2026-09-10: *"quitaste los filtros y divisiones, y el reporte está como
cortado, los campos no están completos"*. Nothing had been removed and nothing
raised. Both halves of the sentence were nevertheless accurate descriptions of
what the page put on screen, which is the whole problem:

1.  **A cut that does not say it is a cut.** Six rungs listed their findings
    ``[:4]`` or ``[:6]`` with no marker. A pool of twelve rendered as six
    members and read as a pool of six. Nothing in the report — headline,
    detail, evidence — distinguished a short list from a trimmed one, so the
    operator diagnosed from a page that looked complete. The engine's own
    convention already says a bounded sweep must name what it dropped; these
    six sites predated it.

2.  **Chrome that names a rule nobody wrote.** ``fw-btn-primary`` matches no
    selector in ``fortiweb.css`` (the defined spelling is ``btn-fw-primary``),
    so the submit control of this page rendered as bare text with an icon from
    9b37a02 until 2026-09-10. A class name is a claim about a stylesheet, and
    an unbacked claim degrades to *invisible*, never to an error. The same is
    true of the eight controls that sat behind a collapsed ``<details>``:
    a criterion the operator cannot see is a criterion they cannot decline.

The product-wide count of the reversed button spelling is NOT re-asserted
here: tests/test_tool_modal_chrome.py already owns that rule and prints its
budget. A second author of one fact is how this repo ends up with two
spellings of the same guarantee — the mistake being guarded against.
"""
from __future__ import annotations

import os
import re

from app.services import scout_ladder as sl
from tests.test_scout_ladder import Appl, _ctx

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(REPO, "app", "templates", "scout", "index.html")
CSS = os.path.join(REPO, "app", "static", "css", "fortiweb.css")
TEMPLATES = os.path.join(REPO, "app", "templates")


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _template():
    """The template WITHOUT its Jinja comments.

    Its comments name ``<details>`` in order to record why it went away, and
    discuss the button spelling in order to forbid it. Asserting over the raw
    file is how a guard passes by matching its own documentation — this repo
    has shipped that mistake ten times, and the first draft of THIS file made
    it eleven.
    """
    return re.sub(r"\{#.*?#\}", "", _read(TPL), flags=re.S)


def _labels(out):
    return [str(a) for a, _ in out["evidence"]]


def _values(out):
    return [str(b) for _, b in out["evidence"]]


# --------------------------------------------------------------------------- #
#  1.  A cut that says it is a cut                                              #
# --------------------------------------------------------------------------- #
def test_a_list_that_fits_is_reported_with_no_marker():
    ev = sl._capped([], [("member", str(i)) for i in range(4)], 6, "member(s)")
    assert len(ev) == 4
    assert "not shown" not in [a for a, _ in ev], (
        "a note about rows that were not shown, on a report where every row "
        "IS shown, teaches the reader to ignore the note")


def test_a_list_of_exactly_the_cap_does_not_claim_a_cut():
    ev = sl._capped([], [("member", str(i)) for i in range(6)], 6, "member(s)")
    assert len(ev) == 6 and "not shown" not in [a for a, _ in ev]


def test_a_trimmed_list_names_both_how_many_were_dropped_and_the_total():
    ev = sl._capped([], [("member", str(i)) for i in range(12)], 6, "member(s)")
    assert len(ev) == 7, "six rows plus one marker"
    marker = ev[-1][1]
    assert "6 more" in marker, "the count of what is missing must be a number"
    assert "of 12" in marker, (
        "without the total, 'more' is unbounded: six of twelve and six of six "
        "hundred are different reports and this one must say which")


def test_the_marker_attributes_the_cut_to_this_page_and_not_to_the_device():
    ev = sl._capped([], [("m", str(i)) for i in range(9)], 6, "member(s)")
    marker = ev[-1][1].lower()
    assert "not by the device" in marker, (
        "'no more' would be a claim about the appliance that this page has no "
        "standing to make; the reader must be able to tell a device that "
        "listed six from a page that printed six")


def test_a_pool_of_twelve_members_does_not_report_as_a_pool_of_six():
    rows = [{"address": "10.0.0.%d" % i, "port": 443, "enabled": True,
             "pool": "p"} for i in range(1, 13)]
    out = sl.layer_pool(_ctx({"pool_targets": lambda a, p: rows}))
    assert out["verdict"] == sl.PASS
    assert _labels(out).count("member") == 6
    assert "not shown" in _labels(out), (
        "six of twelve members with nothing to mark the cut is the exact "
        "report an operator reads as 'this pool has six members'")
    assert "of 12" in _values(out)[-1]


def test_the_backend_rung_marks_the_backends_it_did_not_print():
    from app.services import backend_probe
    rows = [{"address": "10.0.0.%d" % i, "port": 443,
             "local": {"ok": True}} for i in range(1, 10)]
    out = sl.layer_backend(_ctx({"probe_backends": lambda t, **k: rows,
                                 "summarise_backends": backend_probe.summarise},
                                state={"pool_rows": rows}))
    assert "not shown" in _labels(out) and "of 9" in _values(out)[-1]


def test_the_name_rung_marks_the_answers_it_did_not_print():
    out = sl.layer_dns(_ctx({"resolve_name": lambda h: ["10.0.0.%d" % i
                                                        for i in range(1, 10)]},
                            state={"endpoint": {"host": "svc.example.test",
                                                "ip": "192.0.2.1", "port": 443,
                                                "scheme": "https",
                                                "derived": False}}))
    assert "not shown" in _labels(out) and "of 9" in _values(out)[-1]


def test_the_appliance_rung_marks_the_signals_it_did_not_print():
    health = {"status": "warn",
              "reasons": [{"label": "sig%d" % i, "text": "t%d" % i}
                          for i in range(7)]}
    out = sl.layer_device(_ctx({"device_health": lambda a: health}))
    assert "not shown" in _labels(out) and "of 7" in _values(out)[-1]


def test_the_waf_rung_marks_the_blocks_it_did_not_print():
    rows = [{"date": "d%d" % i, "src": "1.2.3.4", "msg": "m"}
            for i in range(9)]
    out = sl.layer_waf(_ctx({"recent_attacks": lambda a, p, w: rows}))
    assert "not shown" in _labels(out), (
        "nine blocks printed as four is how 'the WAF blocked a couple of "
        "requests' replaces 'the WAF is blocking this client'")
    assert "of 9" in _values(out)[-1]


# --- the border rung counts FLOWS, not the five rows it was handed ---------- #
def _path_ctx(rows):
    return _ctx({"border_logs": lambda **k: (rows, "")},
                state={"pool_rows": [{"address": "192.0.2.246", "port": 443}]})


def _many_flows(n):
    return [{"date": "2026-09-10 12:00:%02d" % (i % 60), "srcip": "192.0.2.251",
             "dstip": "192.0.2.246", "dstport": "443", "action": "accept",
             "policyid": "7"} for i in range(n)]


def test_the_border_rung_counts_the_flows_and_not_the_sample_it_kept():
    """The denominator here is the ONLY one the classifier does not hold.

    ``classify_path_rows`` keeps at most five rows for display, so a cut
    measured against its own list reports "3 of 5" for a window that held nine
    hundred flows — a denominator that is arithmetically fine and factually a
    fabrication. The honest total is the classifier's count of everything it
    read.
    """
    out = sl.layer_path(_path_ctx(_many_flows(900)))
    tail = _values(out)[-1]
    assert "900" in tail, (
        "a report that says 'of 5' about 900 flows has invented a smaller "
        "window than the operator asked for")
    assert " of 5" not in tail and "of 5 " not in tail
    assert "sample" in tail.lower(), (
        "these rows are a sample and the word promises exactly that much; "
        "'trimmed' would promise the rest are reachable somewhere")


def test_the_border_rung_is_silent_when_every_flow_it_read_is_on_screen():
    out = sl.layer_path(_path_ctx(_many_flows(2)))
    assert "not shown" not in _labels(out)


# --------------------------------------------------------------------------- #
#  2.  Chrome: a class name is a claim about the stylesheet                     #
# --------------------------------------------------------------------------- #
def _css_classes():
    return set(re.findall(r"\.([A-Za-z][\w-]*)", _read(CSS)))


def _template_classes(text):
    """Static class tokens only.

    A token holding ``{{ … }}`` is composed at render time; the colours those
    expressions can produce are pinned separately, from the map itself.
    """
    out = set()
    for blob in re.findall(r'class="([^"]*)"', text):
        if "{{" in blob or "{%" in blob:
            blob = re.sub(r"\{\{.*?\}\}|\{%.*?%\}", " ", blob)
        out.update(t for t in blob.split() if t)
    return out


def test_every_fw_class_this_template_names_is_defined_in_the_stylesheet():
    defined = _css_classes()
    used = {c for c in _template_classes(_template())
            if c.startswith("fw-") or c.startswith("btn-fw")}
    missing = sorted(c for c in used if c not in defined)
    assert not missing, (
        "%s matches no rule in fortiweb.css. An undefined class does not "
        "raise and does not warn — the element simply renders unstyled, which "
        "is how the button that runs this page shipped as plain text"
        % ", ".join(missing))


def test_the_submit_control_uses_the_spelling_the_stylesheet_defines():
    text = _template()
    assert "btn btn-fw-primary" in text
    assert "fw-btn-" not in text, (
        "fw-btn-* is the undefined spelling; it is one transposition away "
        "from the real one and produces a control that looks like a caption")
    assert ".btn-fw-primary" in _read(CSS)


def test_the_verdict_pill_is_held_to_one_line():
    assert "fw-badge-nowrap" in _template()
    assert ".fw-badge-nowrap" in _read(CSS), (
        "the class that keeps the pill on one line must exist, or the fix is "
        "a comment: 'could not look' wraps in the verdict column and the "
        "second word falls outside the tint, which reads as a cut graphic")


def test_every_colour_the_verdict_map_can_emit_exists_in_the_stylesheet():
    text = _read(TPL)
    block = re.search(r"V_BADGE\s*=\s*\{(.*?)\}", text, re.S).group(1)
    colours = re.findall(r":\s*'([a-z]+)'", block)
    assert len(colours) == 5, "five verdicts, five colours"
    defined = _css_classes()
    for colour in colours:
        assert "fw-badge-%s" % colour in defined, (
            "a verdict rendered with an undefined colour is an uncoloured "
            "pill: 'FAULT' and 'pass' would look identical")


# --------------------------------------------------------------------------- #
#  3.  Twelve controls, visible, and divided                                    #
# --------------------------------------------------------------------------- #
def _form(text):
    m = re.search(r"<form\b.*?</form>", text, re.S)
    assert m, "the walk form"
    return m.group(0)


def test_no_control_of_the_walk_form_is_hidden_behind_a_collapsed_section():
    form = _form(_template())
    assert "<details" not in form, (
        "eight of twelve controls sat inside a collapsed <details>. The page "
        "was then reported as having had its fields REMOVED, which is the "
        "correct reading of four visible inputs: an operator cannot decline "
        "a criterion they were never shown"
    )
    assert len(re.findall(r'name="(?!csrf_token)[a-z_]+"', form)) >= 12, (
        "twelve controls; a guard that only forbids <details> would pass "
        "against a form somebody emptied")


def test_the_form_is_divided_into_named_sections():
    form = _form(_template())
    titles = re.findall(r'class="fw-form-section-title">([^<]+)<', form)
    assert len(titles) >= 3, (
        "three groups of criteria — what to walk, the front door, the border "
        "— printed as one undivided run of twelve boxes is the layout that "
        "made the collapse look necessary in the first place")
    assert form.count("fw-section-separator") >= 2
    assert all(t.strip() for t in titles), "a divider with no name divides nothing"
