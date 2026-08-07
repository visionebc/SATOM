"""A PEM private-key header in a source file aborts the release.

The publisher scans every blob of the sanitised mirror for high-confidence
secret patterns and refuses to push when it finds one.  It cannot tell a real
key from a test fixture that merely *looks* like one, and it must not learn to:
a scanner that skips headers followed by the word "fake" is a scanner a real
key walks past the day someone names a variable `fake_key`.

So the rule lives here instead, where it costs a failing test at commit time
rather than a failed publish.  A test that needs PEM-shaped bytes builds the
header at runtime from parts.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TREES = ("app", "deploy", "tests", "scripts", "installers")
SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".json", ".html", ".md", ".txt", ".conf"}

# Matches the literal header only.  Split across a concatenation so this file
# does not trip its own rule.
PEM = re.compile("-{5}BEGIN [A-Z0-9 ]*" + "PRIVATE KEY-{5}")


def _sources() -> list[pathlib.Path]:
    out = []
    for tree in TREES:
        base = ROOT / tree
        if not base.is_dir():
            continue
        for f in base.rglob("*"):
            if not f.is_file() or f.suffix not in SUFFIXES:
                continue
            if "__pycache__" in f.parts or ".git" in f.parts:
                continue
            out.append(f)
    return sorted(out)


def test_the_sweep_actually_looks_at_files():
    """Anti-vacuity: a narrowed collector would make every case below pass."""
    files = _sources()
    assert len(files) > 200, f"only {len(files)} files collected — collector is broken"


@pytest.mark.parametrize("path", _sources(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_source_file_carries_a_pem_private_key_header(path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pytest.skip("unreadable")
    hits = [m.group(0) for m in PEM.finditer(text)]
    assert not hits, (
        f"{path.relative_to(ROOT)} contains a literal PEM private-key header "
        f"{hits!r}. The publisher's secret scanner aborts the release on this, "
        "and it cannot distinguish a fixture from a real key. Build the header "
        'at runtime instead: "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5.'
    )


def test_the_pattern_would_catch_a_real_header():
    """Counterweight: proves the regex is not narrowed into uselessness."""
    sample = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
    assert PEM.search(sample), "pattern no longer matches a real PEM header"
    assert PEM.search("-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5)
    assert not PEM.search("BEGIN PRIVATE KEY"), "pattern must require the dashes"
