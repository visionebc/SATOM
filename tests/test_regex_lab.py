"""Regex Lab service tests — match tester, rewrite/backreference preview,
product-aware examples, and the cheat sheet. Pure, no Qt/DB/network."""
from app.services import regex_lab


def test_match_basic():
    r = regex_lab.test_pattern(r"^/admin(/.*)?$", ["/admin/x", "/public/y"])
    assert r["ok"] and r["matched"] == 1 and r["total"] == 2
    assert r["results"][0]["match"] and not r["results"][1]["match"]


def test_match_invalid_pattern():
    r = regex_lab.test_pattern("(", ["x"])
    assert not r["ok"] and r["error"].startswith("invalid regex")


def test_match_empty_pattern():
    r = regex_lab.test_pattern("", ["x"])
    assert not r["ok"] and r["error"] == "empty pattern"


def test_rewrite_dollar_captures():
    r = regex_lab.render_rewrite(r"^/old-shop/(.*)$", r"/new-shop/$0",
                                 ["/old-shop/item/42", "/other"])
    assert r["ok"] and r["matched"] == 1
    assert r["results"][0]["output"] == "/new-shop/item/42"
    assert r["results"][1]["match"] is False and r["results"][1]["output"] is None


def test_rewrite_brace_and_backslash_forms():
    assert regex_lab.render_rewrite(r"^/(.*)$", r"/x/${0}", ["/a"])["results"][0]["output"] == "/x/a"
    assert regex_lab.render_rewrite(r"^/(.*)$", r"/y/\1", ["/b"])["results"][0]["output"] == "/y/b"


def test_rewrite_dollar0_first_group():
    # FortiWeb/FortiADC $0 == first capture group.
    r = regex_lab.render_rewrite(r"(.*)", r"https://$0/", ["shop.example.com"])
    assert r["results"][0]["output"] == "https://shop.example.com/"


def test_rewrite_dollar0_is_the_first_group_not_the_whole_match():
    """Fortinet numbering is zero-based: on the device ``$0`` is the first
    ( … ) group. A preview that maps it to the whole match shows a URL the
    appliance would never build."""
    r = regex_lab.render_rewrite(r"^/a/(.*)$", r"/b/$0", ["/a/x"])
    assert r["results"][0]["output"] == "/b/x"
    r = regex_lab.render_rewrite(r"^/(\w+)/(\w+)$", r"/$1/$0", ["/one/two"])
    assert r["results"][0]["output"] == "/two/one"


def test_rewrite_naming_a_missing_group_says_so():
    r = regex_lab.render_rewrite(r"^/(.*)$", r"/$1", ["/a"])
    row = r["results"][0]
    assert row["output"] is None and "$0 is the first" in row["error"]


def test_every_library_rewrite_example_renders_on_its_own_sample():
    """The examples are the documentation of the numbering: each one must
    preview without an error against the sample it ships with."""
    seen = 0
    for kind, product in (("url_rewrite_rule", "fortiweb"),
                          ("content_rewriting", "fortiadc")):
        for e in regex_lab.examples_for(kind, product):
            if not e.get("replacement"):
                continue
            seen += 1
            res = regex_lab.render_rewrite(e["pattern"], e["replacement"],
                                           [e["sample"]])
            row = res["results"][0]
            assert row["match"] and not row.get("error"), e
    assert seen >= 3, "no rewrite example was checked -- did examples_for move?"


def test_rewrite_literal_dollar():
    r = regex_lab.render_rewrite(r"^(.*)$", r"$$1 = $0", ["hi"])
    assert r["results"][0]["output"] == "$1 = hi"


def test_examples_product_aware():
    fw = regex_lab.examples_for("url_rewrite_rule", "fortiweb")
    fadc = regex_lab.examples_for("content_rewriting", "fortiadc")
    assert fw and fadc
    # FortiADC highlight uses the Host→$0 pattern.
    assert any("$0" in (e.get("replacement") or "") for e in fadc)
    # No duplicate patterns.
    pats = [e["pattern"] for e in fw]
    assert len(pats) == len(set(pats))


def test_guide_notes_per_product():
    assert any("FortiADC" in n for n in regex_lab.guide_notes("fortiadc"))
    assert regex_lab.guide_notes("bogus")  # falls back to fortiweb


def test_cheatsheet_shape():
    cs = regex_lab.cheatsheet()
    assert cs and all("group" in g and "items" in g for g in cs)
    assert all("tok" in it and "desc" in it for g in cs for it in g["items"])


def test_sample_caps():
    big = ["x" * 10] * (regex_lab.MAX_SAMPLES + 20)
    r = regex_lab.test_pattern("x", big)
    assert r["total"] == regex_lab.MAX_SAMPLES
