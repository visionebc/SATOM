"""The regex lab judges with Python ``re``; FortiWeb and FortiADC judge with
PCRE. Those are different languages, and until this guard existed the product
said the opposite: the modal footer read "Tested server-side against a
PCRE-compatible engine — matches FortiWeb & FortiADC", under a shield icon.

Nothing failed. The endpoint worked, the verdict was correct *for Python*, and
an operator who proved ``\\p{L}+`` here was told the pattern was INVALID for a
pattern the appliance accepts. That is the expensive direction of the error:
the tester's verdict sends someone to rewrite a working rule.

So this file pins two things:

1. **The divergence table is earned, not typed.** Every ``device_only`` entry is
   fed to ``re.compile`` and must actually fail; every construct deliberately
   left OUT must actually compile. Python 3.11 gained possessive quantifiers and
   atomic groups — the first draft of the table warned about both, and this
   guard is what caught it. When the interpreter changes, these fail rather than
   the product quietly warning about a construct that works (or staying silent
   about one that no longer does).
2. **Every verdict names its engine.** Including the invalid-pattern path, which
   is exactly where a PCRE-only construct is the explanation for the error.
"""
import re

import pytest

from app.services import regex_lab


# --------------------------------------------------------------------------
# 1. the table is derived from the interpreter, not from a typed list
# --------------------------------------------------------------------------

# One probe pattern per escape key, so the claim can be executed.
_ESC_PROBES = {
    "K": r"\K", "R": r"\R", "h": r"\h", "H": r"\H", "X": r"\X", "G": r"\G",
    "N": r"\N", "p": r"\p{L}", "P": r"\P{L}", "k": r"\k<n>", "z": r"\z",
    "Z": r"\Z", "d": r"\d", "w": r"\w", "s": r"\s", "b": r"\b",
}

_GROUP_PROBES = {
    "(?<name>...)": "(?<name>x)",
    "(?R)": "(?R)",
    "(?&name)": "(?&n)",
    "(*VERB)": "(*SKIP)x",
    "(?C...)": "(?C1)x",
    "(?i) mid-pattern": "foo(?i)bar",
}

# Constructs NOT in the table. If a future interpreter stops accepting one of
# these, the lab starts silently disagreeing with the appliance and this fails.
_MUST_COMPILE = [
    "a++", "a*+", "a?+", "a{2,3}+",   # possessive quantifiers - Python 3.11+
    "(?>abc)",                        # atomic group - Python 3.11+
    "(?P<n>x)(?P=n)",                 # named group + named backref
    "foo(?i:bar)",                    # scoped inline flag
    "(?i)foo",                        # leading global flag
    "(x)?(?(1)a|b)",                  # conditional
]


def test_every_escape_probe_is_covered():
    """The probe map and the shipped table describe the same set — a new rule
    added without a probe would otherwise be asserted by nothing."""
    assert set(_ESC_PROBES) == set(regex_lab._ESC_RULES)


@pytest.mark.parametrize("key", sorted(_ESC_PROBES))
def test_escape_rule_direction_matches_the_interpreter(key):
    construct, direction, severity, note = regex_lab._ESC_RULES[key]
    probe = _ESC_PROBES[key]
    try:
        re.compile(probe)
        compiles = True
    except re.error:
        compiles = False
    if direction == "device_only":
        assert not compiles, (
            "%s is listed device_only but Python compiles it — the lab would "
            "warn about a construct it handles fine" % probe)
    else:
        assert compiles, (
            "%s is listed semantic (both compile) but Python rejects it — it "
            "belongs in device_only" % probe)
    assert severity in ("warn", "info")
    assert note.strip(), "a divergence with no explanation is a scare, not a finding"


@pytest.mark.parametrize("construct,probe", sorted(_GROUP_PROBES.items()))
def test_group_constructs_really_fail_here(construct, probe):
    with pytest.raises(re.error):
        re.compile(probe)
    found = [d["construct"] for d in regex_lab.pcre_divergences(probe)]
    assert construct in found, "%r should report %s, got %s" % (probe, construct, found)


@pytest.mark.parametrize("pattern", _MUST_COMPILE)
def test_excluded_constructs_still_compile_and_are_not_flagged(pattern):
    re.compile(pattern)                      # would raise if support vanished
    warns = [d for d in regex_lab.pcre_divergences(pattern) if d["severity"] == "warn"]
    assert warns == [], (
        "%r behaves the same on both engines; warning about it sends the "
        "operator to rewrite a working pattern (got %s)" % (pattern, warns))


# --------------------------------------------------------------------------
# 2. the scanner reads regex, not text
# --------------------------------------------------------------------------

def test_construct_inside_character_class_is_not_a_group():
    # '(' and '?' inside a class are literals; only the \d escape is real.
    # The probe must use a construct the scanner STILL reports outside a class
    # (an earlier version used "(?>", which stopped being a finding when
    # Python 3.11 gained atomic groups — so the test passed without the
    # suppression it claimed to cover).
    assert any(x["construct"] == "(?R)"
               for x in regex_lab.pcre_divergences("(?R)")), "probe went stale"
    d = regex_lab.pcre_divergences(r"[(?R)a]\d")
    assert [x["construct"] for x in d] == [r"\d"]


def test_escaped_backslash_is_not_an_escape_sequence():
    # \\p is a literal backslash followed by a literal p.
    assert regex_lab.pcre_divergences(r"\\p{L}") == []


def test_brace_quantifier_after_property_is_not_mistaken_for_possessive():
    # \p{L}+ is a plus quantifier on a property, and the property is the only
    # finding. An earlier draft reported a second, invented one here.
    d = regex_lab.pcre_divergences(r"\p{L}+")
    assert [x["construct"] for x in d] == [r"\p{...}"]


def test_leading_inline_flag_is_allowed_but_mid_pattern_is_not():
    assert regex_lab.pcre_divergences("(?i)foo") == []
    assert [x["construct"] for x in regex_lab.pcre_divergences("foo(?i)bar")] \
        == ["(?i) mid-pattern"]


def test_lookbehind_is_not_reported_as_a_pcre_named_group():
    assert regex_lab.pcre_divergences("(?<=/api)/v1") == []
    assert regex_lab.pcre_divergences("(?<!/api)/v1") == []


def test_findings_are_deduplicated_per_construct():
    d = regex_lab.pcre_divergences(r"\d+-\d+-\d+")
    assert len(d) == 1 and d[0]["construct"] == r"\d"


def test_clean_operational_pattern_reports_nothing():
    assert regex_lab.pcre_divergences(r"^/shop/item/[0-9]+/?$") == []


# --------------------------------------------------------------------------
# 3. every verdict carries the engine that produced it
# --------------------------------------------------------------------------

@pytest.mark.parametrize("call", [
    lambda: regex_lab.test_pattern(r"\p{L}+", ["abc"]),      # invalid here
    lambda: regex_lab.test_pattern(r"^/a$", ["/a"]),          # ok
    lambda: regex_lab.test_pattern("", []),                   # empty
    lambda: regex_lab.render_rewrite(r"\p{L}+", "$1", ["a"]),
    lambda: regex_lab.render_rewrite(r"^/a/(.*)$", "/b/$1", ["/a/x"]),
    lambda: regex_lab.render_rewrite("", "", []),
])
def test_engine_block_on_every_return_path(call):
    res = call()
    assert res["engine"]["id"] == "python-re"
    assert res["engine"]["exact"] is False, \
        "claiming exactness is the defect this module exists to fix"
    assert "PCRE" in res["engine"]["target"]
    assert isinstance(res["divergences"], list)


def test_invalid_here_but_valid_on_device_is_flagged_as_blocking():
    res = regex_lab.test_pattern(r"\p{L}+", ["abc"])
    assert res["ok"] is False and res["error"].startswith("invalid regex")
    assert res["blocking"] is True, \
        "the pattern the appliance accepts must not be reported as merely invalid"


def test_info_only_divergence_does_not_block():
    res = regex_lab.test_pattern(r"\d{3}", ["123"])
    assert res["ok"] is True and res["blocking"] is False
    assert [d["severity"] for d in res["divergences"]] == ["info"]


def test_core_verdict_is_unchanged_by_the_wrapper():
    r = regex_lab.test_pattern(r"^/admin(/.*)?$", ["/admin/x", "/public/y"])
    assert r["matched"] == 1 and r["total"] == 2
    w = regex_lab.render_rewrite(r"^/old/(.*)$", r"/new/$1", ["/old/i/42"])
    assert w["results"][0]["output"] == "/new/i/42"


# --------------------------------------------------------------------------
# 4. the two surfaces that told the operator the wrong thing
# --------------------------------------------------------------------------

def _js():
    from pathlib import Path
    return Path(regex_lab.__file__).resolve().parents[1] \
        .joinpath("static/js/regex_lab.js").read_text(encoding="utf-8")


def test_modal_no_longer_claims_a_pcre_compatible_engine():
    js = _js()
    assert "PCRE-compatible engine" not in js, \
        "the lab is not a PCRE engine; saying so is the original defect"
    assert "matches FortiWeb & FortiADC" not in js


def test_modal_names_the_engine_that_judged_and_renders_divergences():
    js = _js()
    assert "fw-rxlab-engine" in js
    assert "Python re" in js
    assert "renderEngine" in js
    # both verdict paths must call it, or one of them shows a stale engine line
    assert js.count("renderEngine(j);") == 2


def test_flavor_notes_do_not_warn_about_constructs_that_work():
    for product in ("fortiweb", "fortiadc"):
        blob = " ".join(regex_lab.guide_notes(product))
        flat = " ".join(blob.split())
        assert "possessive quantifiers `a++` and recursion aren't supported" not in flat
        assert "PCRE-compatible engine" not in flat


@pytest.mark.parametrize("product", ["fortiweb", "fortiadc"])
def test_engine_note_is_first_and_survives_truncation(product):
    """``guide_notes`` returns ``(harvested + base)[:10]``. The engine caveat
    used to sit at the END of the shared note block, so on FortiWeb — where the
    harvested admin-guide notes are prepended — it was the line the cap dropped.
    The stale claim was visible and its correction would not have been."""
    notes = regex_lab.guide_notes(product)
    assert notes, "no notes at all"
    assert notes[0] == regex_lab.ENGINE_NOTE, \
        "the engine caveat must lead, not compete for a slot with harvested prose"
    assert len(notes) <= 10, "the side panel is capped; pinning must not grow it"
    flat = " ".join(" ".join(notes).split())
    assert "Python `re`" in flat and "PCRE" in flat


def test_engine_note_names_constructs_the_lab_actually_rejects():
    """A caveat that lists the wrong tokens teaches the wrong lesson. Every
    construct named in the note is compiled here and must really fail."""
    named = [r"\p{L}", r"\K", r"\z", "(?R)", "(?<name>x)"]
    for probe in named:
        with pytest.raises(re.error):
            re.compile(probe)
    flat = " ".join(regex_lab.ENGINE_NOTE.split())
    for token in (r"\p{L}", r"\K", r"\z", "(?R)", "(?<name>)"):
        assert token in flat


# --------------------------------------------------------------------------
# 5. the endpoint hands the browser what the panel needs
# --------------------------------------------------------------------------

def test_endpoint_returns_divergences(client, app):
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    r = client.post("/regex-lab/test", json={"pattern": r"\p{L}+", "samples": ["a"]})
    j = r.get_json()
    assert j["engine"]["id"] == "python-re"
    assert j["blocking"] is True
    assert any(d["construct"] == r"\p{...}" for d in j["divergences"])
