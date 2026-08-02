"""Loader for the adversarial corpus used by the leak-scanner tests.

The corpus itself is the only file in this repository that must contain real
internal identifiers -- a detector proved against sanitised input proves
nothing -- so the publication pipeline drops it by path and these tests skip
on a published mirror rather than failing over a leak that is correctly no
longer there.

This module carries no identifiers of its own and is safe to publish.
"""
from __future__ import annotations

import json
import pathlib

import pytest

_PATH = pathlib.Path(__file__).resolve().parent / "fixtures" / \
    "internal_identifier_samples.json"

SKIP_REASON = (
    "adversarial corpus (tests/fixtures/internal_identifier_samples.json) is "
    "absent: this is a published mirror, from which the publisher removes it "
    "by design -- see docs/safeguards.md 7e"
)


def load() -> dict | None:
    """The corpus, or None when it has been stripped by publication."""
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


SAMPLES = load()
requires_corpus = pytest.mark.skipif(SAMPLES is None, reason=SKIP_REASON)
