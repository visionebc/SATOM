"""The reconcile page and the firmware-line matrix must be findable by name.

Why this file exists
--------------------
Nothing fails when documentation goes stale.  The page renders, the CLI
answers, the suite is green — the sentence simply stops being true.  This
subsystem is the worst possible place for that, because its entire purpose is
to be consulted BEFORE a write to a production appliance: an operator who
cannot find "unmeasured" in the manual reads it as a synonym for "fine".

Both surfaces this repository has already lost prose to are covered here:

* the reference (``docs/device-api.md``) documented the registry for months
  while the sweep's verdicts had nowhere to be read back to;
* ``docs/user-guide.md`` section 30 described an explorer with three
  sub-sections on the day a fourth and a fifth page shipped.

So the guards below are *derived*.  The bucket names come from the report the
service actually returns, the verdicts and preflight statuses from the modules
that define them, the routes from the live URL map, and the "unmeasured" exit
code from running the real CLI entry point.  Adding a bucket, a status, a page
or a verdict without documenting it fails the suite in the same commit.

Deliberately NOT guarded: whether the prose is any good.  A guard that polices
explanation quality rejects correct writing.  What is checkable is presence —
that a reader can find, by name, every answer the product will actually give.
"""
from __future__ import annotations

import pathlib
import re
import sys
import types

import pytest

from app.models import Permission
from app.services import api_matrix as am
from app.services import doc_publication, registry_reconcile as rr

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy'))
GUIDE = ROOT / 'docs' / 'user-guide.md'
REFERENCE = ROOT / 'docs' / 'device-api.md'

REF_RECONCILE_HEAD = '## 6. Reconciling the catalog against the fleet'
REF_MATRIX_HEAD = '## 7. Firmware lines: which fields a line actually serves'
GUIDE_RECONCILE_HEAD = '### 30.4 Reconcile'
GUIDE_MATRIX_HEAD = '### 30.5 API versions'

# The two pages, by the endpoint names the blueprints register them under.
PAGE_ENDPOINTS = ('registry.reconcile', 'registry.api_versions',
                  'adc_api.reconcile', 'adc_api.api_versions')


def bounded(text: str, head: str, stop: str) -> str:
    """The named section and nothing after it.

    A whole-file assertion is the recurring false pass in this repository: a
    word used three sections away satisfies a guard about the section being
    edited, and the guard then survives deleting the very sentence it exists
    to hold.
    """
    start = text.index(head)
    nxt = text.find(stop, start + len(head))
    return text[start:] if nxt == -1 else text[start:nxt]


def squashed(text: str) -> str:
    """Lowercase, alphanumerics only.

    Prose legitimately spells an identifier that code writes solid
    (``FortiAnalyzer`` for ``fortianalyzer``, ``unknown fields`` for
    ``unknown_fields``).  Comparing raw would fail against correct writing,
    which is how a guard teaches people to delete it.
    """
    return ''.join(c for c in text.lower() if c.isalnum())


def reference() -> str:
    return REFERENCE.read_text(encoding='utf-8')


def guide() -> str:
    return GUIDE.read_text(encoding='utf-8')


def ref_reconcile() -> str:
    return bounded(reference(), REF_RECONCILE_HEAD, '\n## 7.')


def ref_matrix() -> str:
    return bounded(reference(), REF_MATRIX_HEAD, '\n## 8.')


def guide_reconcile() -> str:
    return bounded(guide(), GUIDE_RECONCILE_HEAD, '\n### 30.5')


def guide_matrix() -> str:
    return bounded(guide(), GUIDE_MATRIX_HEAD, '\n## 31.')


def ref_apply() -> str:
    """§6.4 only.

    ``rejected`` also appears in §6.3, in a sentence about *appliances*
    rejecting endpoints — the opposite direction.  A guard scoped to the whole
    of §6 was answered by that one and survived deleting the paragraph about
    the server re-deriving the proposal set.
    """
    return bounded(reference(), '### 6.4 Applying', '\n---')


def guide_reconcile_table() -> str:
    """The card-by-card table only.

    Scoped because several card names are ordinary words that appear
    elsewhere in the same section ("Evidence", "Preflight"): a guard answered
    by any occurrence survives renaming the row that walks the operator
    through the screen, which is the thing being guarded.
    """
    return bounded(guide_reconcile(), '| card | meaning |', '\n\n')


def guide_matrix_parts() -> str:
    """The numbered walkthrough of the API-versions page, same reason."""
    return bounded(guide_matrix(), 'The page has four parts:', '\n\n**')


def guide_exit_codes() -> str:
    """The one paragraph that states the CLI contract.

    Scoped because the section also contains a NUMBERED LIST, so a bare search
    for the digit ``4`` was answered by "4. **Preflight**" and survived
    documenting the wrong exit code.
    """
    return bounded(guide_matrix(), 'Exit codes:', '\n\n')


# ---------------------------------------------------------------------------
# The documents have to exist, be published, and contain the sections — or
# every guard below is checking a file nobody can reach.
# ---------------------------------------------------------------------------

def test_the_reference_is_published_and_reachable():
    """A doc absent from the registry is published nowhere, and the user
    guide's cross-link to it degrades to plain text."""
    assert 'device-api.md' in doc_publication.SLUG_BY_FILE
    slug = doc_publication.SLUG_BY_FILE['device-api.md']
    grouped = {s for _name, _lead, slugs in doc_publication.GROUPS for s in slugs}
    assert slug in grouped, (
        f'{slug!r} is published but appears in no hub group, so the only way '
        f'to reach it is to already know the URL'
    )


@pytest.mark.parametrize('head', [REF_RECONCILE_HEAD, REF_MATRIX_HEAD])
def test_the_reference_carries_the_section(head):
    assert head in reference()


@pytest.mark.parametrize('head', [GUIDE_RECONCILE_HEAD, GUIDE_MATRIX_HEAD])
def test_the_manual_carries_the_section(head):
    assert head in guide(), (
        'the reference is for integrators; an operator reads the manual, and '
        'a page absent from it is a page nobody knows to open'
    )


def test_the_sections_are_bounded_not_the_whole_file():
    """If the terminators ever stop matching, every derived guard below turns
    into a whole-file search and silently stops proving anything."""
    for part in (ref_reconcile(), ref_matrix(), guide_reconcile(), guide_matrix()):
        assert 0 < len(part) < 12000, len(part)
    assert REF_MATRIX_HEAD not in ref_reconcile()
    assert GUIDE_MATRIX_HEAD not in guide_reconcile()


# ---------------------------------------------------------------------------
# Reconcile — the buckets and the two signals.
# ---------------------------------------------------------------------------

@pytest.fixture()
def buckets(app, session):
    """The bucket names the service actually returns, not a list I typed."""
    return sorted(rr.reconcile('fortiweb')['counts'])


def test_every_reconcile_bucket_is_named_in_the_reference(buckets):
    body = squashed(ref_reconcile())
    missing = [b for b in buckets if squashed(b) not in body]
    assert not missing, (
        f'{missing} are buckets the reconcile report produces but the '
        f'reference never names — an operator meets them first on the page'
    )


TEMPLATES = ROOT / 'app' / 'templates' / 'registry'
_TITLE = re.compile(r'fw-card-title"[^>]*>\s*(?:<i[^>]*></i>)?\s*([^<{\n]+)')
_HEADER = re.compile(r'fw-card-header"><i[^>]*></i>\s*([^<{\n]+)')


def card_titles(template: str, pattern=_TITLE) -> list:
    html = (TEMPLATES / template).read_text(encoding='utf-8')
    return [m.strip() for m in pattern.findall(html) if m.strip()]


@pytest.mark.parametrize('title', card_titles('reconcile.html'))
def test_the_manual_names_every_card_the_reconcile_page_renders(title):
    """The operator navigates by what is on screen.  Deriving from the
    template rather than from the bucket keys is the difference between a
    guard that tracks the page and one that tracks my memory of it."""
    assert squashed(title) in squashed(guide_reconcile_table()), title


@pytest.mark.parametrize('title', card_titles('versions.html', _HEADER))
def test_the_manual_names_every_card_the_versions_page_renders(title):
    assert squashed(title) in squashed(guide_matrix_parts()), title


@pytest.mark.parametrize('verdict', [rr.VERDICT_OK, rr.VERDICT_ABSENT, rr.VERDICT_ERROR])
def test_every_sweep_verdict_is_named_in_the_reference(verdict):
    assert verdict in ref_reconcile(), (
        f'{verdict!r} is a verdict the sweep writes into the ledger; a reader '
        f'who cannot look it up cannot tell a catalog fact from a device fault'
    )


def test_absent_and_error_are_documented_as_evidence_about_different_things():
    """The single most expensive confusion in this subsystem.  Collapsing them
    is how one unlicensed appliance proposes deleting a whole catalog."""
    body = ref_reconcile()
    row = [ln for ln in body.splitlines() if ln.startswith(f'| `{rr.VERDICT_ABSENT}`')]
    err = [ln for ln in body.splitlines() if ln.startswith(f'| `{rr.VERDICT_ERROR}`')]
    assert row and err
    assert 'catalog' in row[0] and 'device' not in row[0]
    assert 'device' in err[0]


def test_the_error_ratio_threshold_is_stated_as_a_number():
    """'Unhealthy devices are ignored' is not actionable; the ratio is."""
    pct = str(int(rr.MAX_ERROR_RATIO * 100))
    assert pct in ref_reconcile()
    assert pct in guide_reconcile(), (
        'the operator reading the Evidence card needs to know the threshold '
        'that excluded their appliance'
    )


def test_the_firmware_caveat_survives_in_both_documents():
    """Absence is a claim about a RELEASE.  This is the sentence that stands
    between a tidy-looking Apply and a catalog stripped of the endpoints the
    next upgrade needs."""
    for part in (ref_reconcile(), guide_reconcile()):
        low = part.lower()
        assert 'firmware' in low and ('8.0' in part or 'release' in low)
    assert 'fleet_spans_one_firmware' not in guide_reconcile(), (
        'the manual is for operators; an internal flag name there means the '
        'sentence was copied from the code instead of written for a reader'
    )


def test_apply_is_documented_as_re_derived_server_side():
    """The POST is a filter over the evidence, never the authority for it."""
    body = ref_apply()
    assert 'rejected' in body and 'filter' in body


@pytest.mark.parametrize('product', sorted(set(am._KIND_FOR) - set(am.SWEPT_PRODUCTS)))
def test_products_without_a_sweep_are_named_as_such(product):
    """A page that simply does not exist for FAZ/FAC reads as a bug unless the
    reference says the evidence cannot exist."""
    assert squashed(product) in squashed(ref_reconcile())


# ---------------------------------------------------------------------------
# The firmware-line matrix.
# ---------------------------------------------------------------------------

PREFLIGHT_STATUSES = sorted({
    getattr(am, n) for n in dir(am) if n.startswith('STATUS_')
})


@pytest.mark.parametrize('status', PREFLIGHT_STATUSES)
def test_every_preflight_status_is_documented(status):
    """A status the caller can receive and cannot look up is a status they
    will guess at, and the guess that costs money is 'unmeasured means ok'."""
    body = squashed(ref_matrix() + guide_matrix())
    assert squashed(status) in body, status


def test_unmeasured_is_documented_as_not_a_yes():
    body = guide_matrix()
    assert am.STATUS_UNMEASURED in body
    assert 'never a yes' in body or 'never' in body.split(am.STATUS_UNMEASURED, 1)[1][:200]


def test_the_two_evidence_kinds_are_named_and_kept_apart():
    """Merging sweep and schema field sets produced 56 phantom removals.  The
    rule that fixed it is only useful if the reader knows it exists."""
    body = ref_matrix()
    assert 'sweep' in body and 'schema' in body
    assert 'incomparable' in body.lower()


def test_the_line_granularity_is_stated():
    assert 'major.minor' in ref_matrix()


def test_the_matrix_is_documented_as_derived_not_authored():
    """Someone will eventually look for this in a database backup."""
    low = ref_matrix().lower()
    assert 'derived' in low
    assert am.MATRIX_ROOT.split('data/')[-1] in ref_matrix()


# ---------------------------------------------------------------------------
# Routes — derived from the live URL map, so a moved page fails the docs.
# ---------------------------------------------------------------------------

@pytest.fixture()
def page_rules(app):
    out = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint in PAGE_ENDPOINTS:
            out[rule.endpoint] = str(rule)
    return out


def test_all_four_pages_exist(page_rules):
    assert sorted(page_rules) == sorted(PAGE_ENDPOINTS), page_rules


@pytest.mark.parametrize('doc', ['reference', 'guide'])
def test_every_page_url_appears_in_both_documents(page_rules, doc):
    """Both, not either.  The integrator needs the address to script against
    and the operator needs it to navigate to; a URL present in only one of the
    two is a page half the readership cannot find."""
    body = reference() if doc == 'reference' else guide()
    missing = {e: u for e, u in page_rules.items() if u not in body}
    assert not missing, (
        f'{missing} render but appear at no address in the {doc} — a page an '
        f'operator cannot navigate to might as well not ship'
    )


def test_the_manual_names_the_permission_that_gates_them():
    # ``Permission`` is a namespace of string constants, not an Enum.
    perm = Permission.REGISTRY_EDIT
    assert perm in guide_reconcile() and perm in guide_matrix(), (
        'the first question after "I cannot see the button" is which '
        'permission grants it'
    )


# ---------------------------------------------------------------------------
# The CLI contract — the exit code is RUN, not transcribed.
# ---------------------------------------------------------------------------

def test_the_documented_unmeasured_exit_code_is_the_one_the_cli_returns(tmp_path):
    from satom_cli import cmd_apiver

    ctx = types.SimpleNamespace(app_dir=str(tmp_path))
    res = cmd_apiver.api_preflight(ctx, ['9.9', 'admin', 'anything'])
    rc = res.exit_code
    assert rc == 4, rc
    assert am.STATUS_UNMEASURED in (res.title or '')
    assert f'`{rc}` {am.STATUS_UNMEASURED}' in guide_matrix(), (
        'the manual prints an exit code a script will branch on; if it is not '
        'the one the CLI returns, the script trusts the wrong one'
    )
    assert f'rc {rc}' in ref_matrix()


def test_a_usage_error_and_unmeasured_do_not_share_an_exit_code(tmp_path):
    from satom_cli import cmd_apiver

    ctx = types.SimpleNamespace(app_dir=str(tmp_path))
    usage = cmd_apiver.api_preflight(ctx, ['admin'])
    unmeasured = cmd_apiver.api_preflight(ctx, ['9.9', 'admin', 'x'])
    assert usage.exit_code != unmeasured.exit_code
    codes = guide_exit_codes()
    for code in (usage.exit_code, unmeasured.exit_code):
        assert f'`{code}`' in codes, (
            f'exit code {code} is missing from the manual paragraph that '
            f'claims to list them'
        )


@pytest.mark.parametrize('command', ['satom get api versions', 'satom get api preflight'])
def test_both_cli_commands_are_documented(command):
    assert command.replace('satom ', '') in reference()
    assert command.replace('satom ', '') in guide()
