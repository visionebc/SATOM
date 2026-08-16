"""The alerting documentation must name every surface alerting ships.

Why this file exists
--------------------
Nothing fails when documentation goes stale.  The engine runs, the page
renders, the suite is green — the sentence simply stops being true.  This
subsystem has already produced two instances of exactly that, both found by
reading rather than by anything failing:

* ``docs/user-guide.md`` section 26.6 described the delivery policy for a whole
  round after per-sink routing and the syslog feed had shipped;
* section 35.3 listed the hook catalog as six events on the day a seventh,
  ``alert.fired``, was the entire point of the release.

So the guards below are *derived*: the sink roster, the family map, the event
catalog, the starter registry, the retry statuses and the wire encodings all
come from the code that implements them.  Adding a sink, an event or a starter
without documenting it fails the suite in the same commit that adds it.

Deliberately NOT guarded: whether the prose is any good.  A guard that tries to
police explanation quality rejects correct writing.  What is checkable is
presence — that a reader can find, by name, every thing the product will
actually do.
"""
from __future__ import annotations

import pathlib

import pytest

from app.services import alert_routing as routing
from app.services import alert_syslog, alert_webhook, doc_publication
from app.services import hook_starters, integration_hooks

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'docs' / 'user-guide.md'
REFERENCE = ROOT / 'docs' / 'alerting.md'


def bounded(text: str, head: str, stop: str) -> str:
    """The named section and nothing after it.

    A whole-file assertion is the recurring false pass in this repo: a word
    used three sections away satisfies a guard about the section being edited,
    and the guard then survives deleting the very sentence it exists to hold.
    """
    start = text.index(head)
    nxt = text.find(stop, start + len(head))
    return text[start:] if nxt == -1 else text[start:nxt]


def guide() -> str:
    return GUIDE.read_text(encoding='utf-8')


def reference() -> str:
    return REFERENCE.read_text(encoding='utf-8')


def squashed(text: str) -> str:
    """Lowercase, alphanumerics only — so ``RFC 5424`` satisfies ``rfc5424``.

    Prose legitimately spaces an identifier that code writes solid.  Comparing
    raw would fail against correct writing, which is how a guard teaches people
    to delete it.
    """
    return ''.join(c for c in text.lower() if c.isalnum())


def delivery_section() -> str:
    return bounded(guide(), '### 26.6 Email & Alerts', '\n### ')


def hooks_section() -> str:
    return bounded(guide(), '### 35.3 Integration hooks', '\n### ')


# ---------------------------------------------------------------------------
# The reference document has to exist and be published, or every guard below
# is checking a file nobody can read.
# ---------------------------------------------------------------------------

def test_the_reference_document_exists():
    assert REFERENCE.is_file(), (
        'docs/alerting.md is the wire contract the user guide sends '
        'integrators to; a missing file makes that link plain text'
    )


def test_the_reference_document_is_published():
    """A doc absent from the registry is published nowhere, and a cross-link
    to it is unwrapped to plain text — the reference disappears silently."""
    assert 'alerting.md' in doc_publication.SLUG_BY_FILE, (
        'docs/alerting.md is not in PUBLIC_DOCS, so it is not published and '
        'the user guide link to it degrades to plain text'
    )
    slug = doc_publication.SLUG_BY_FILE['alerting.md']
    grouped = {s for _name, _lead, slugs in doc_publication.GROUPS for s in slugs}
    assert slug in grouped, (
        f'{slug!r} is published but appears in no hub group, so the only way '
        f'to reach it is to already know the URL'
    )


# ---------------------------------------------------------------------------
# User guide 26.6 — the delivery policy screen.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sink', routing.SINKS)
def test_every_sink_is_named_in_the_delivery_section(sink):
    # The label as the settings page prints it, minus its parenthetical: prose
    # writes "Webhook", the form writes "Webhook (HTTP POST)".
    name = routing.SINK_LABELS[sink].split(' (')[0]
    assert name in delivery_section(), (
        f'sink {sink!r} ships as {name!r} and section 26.6 never names it: an '
        f'operator reading the manual cannot know that switch exists'
    )


@pytest.mark.parametrize('family', routing.FAMILIES)
def test_every_maskable_family_is_named_in_the_delivery_section(family):
    assert f'`{family}`' in delivery_section(), (
        f'family {family!r} is a tickbox on the sink mask and section 26.6 '
        f'never names it, so an operator cannot tell which checks a mask they '
        f'are editing will silence'
    )


@pytest.mark.parametrize('family', routing.FAMILIES)
def test_the_guide_states_the_key_prefix_behind_each_family(family):
    """The mask says ``actions`` and the engine emits ``action.*``.  A reader
    matching a finding key against the mask by eye gets that one wrong, and it
    is the mask most likely to be narrowed."""
    prefix = next(p for p, f in routing._PREFIX_FAMILY.items() if f == family)
    assert f'`{prefix}.`' in delivery_section(), (
        f'family {family!r} is raised by keys beginning {prefix + "."!r} and '
        f'section 26.6 never says so'
    )


# ---------------------------------------------------------------------------
# User guide 35.3 — the hook catalog.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('event', sorted(integration_hooks.EVENT_NAMES))
def test_every_hook_event_is_in_the_enumerated_event_list(event):
    """Bound to the enumeration, not to the section.

    Dropping an event from the list is invisible to a section-wide guard as
    soon as any later paragraph happens to mention that event by name — which
    is exactly what the paragraphs below the list do.  The list is the thing a
    reader scans to find out what they can subscribe to.
    """
    listing = bounded(hooks_section(), 'Events: ', '\n\n')
    assert f'`{event}`' in listing, (
        f'event {event!r} can be bound in the hook editor and the event list '
        f'in section 35.3 does not enumerate it; an undocumented event is one '
        f'nobody subscribes to'
    )


@pytest.mark.parametrize('slug', sorted(hook_starters.STARTERS))
def test_every_starter_is_named_in_the_hooks_section(slug):
    label = hook_starters.STARTERS[slug]['label']
    assert label in hooks_section(), (
        f'starter {slug!r} is offered as {label!r} on the New hook screen and '
        f'section 35.3 never mentions it'
    )


def test_the_hooks_section_states_that_alert_fired_is_per_finding():
    """The other six events fire once per change.  A subscriber that assumes
    the same cadence writes a handler that floods."""
    body = hooks_section()
    assert 'once per finding' in body.lower()
    assert 'primary' in body, (
        'alert.fired never fires from the standby; a reader debugging "the '
        'hook did not run" needs to be told which node emits it'
    )


# ---------------------------------------------------------------------------
# docs/alerting.md — the wire contract.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sink', routing.SINKS)
def test_the_reference_names_every_sink_by_its_settings_key(sink):
    assert f'`{sink}`' in reference(), (
        f'sink key {sink!r} is what the settings form and the run result use; '
        f'the reference has to name it or a reader cannot map the two'
    )


@pytest.mark.parametrize('family', routing.FAMILIES + routing.UNFILTERABLE)
def test_the_reference_names_every_family_including_the_unfilterable_ones(family):
    assert f'`{family}`' in reference(), (
        f'family {family!r} appears in delivered payloads and the reference '
        f'never names it'
    )


def test_the_reference_states_that_two_families_bypass_the_filters():
    body = bounded(reference(), '## 1. What a finding is', '\n## ')
    for family in routing.UNFILTERABLE:
        assert f'`{family}`' in body, (
            f'{family!r} is delivered no matter how a sink is configured, and '
            f'that is the single most surprising rule in the router'
        )


@pytest.mark.parametrize('header', [alert_webhook.SIG_HEADER,
                                    alert_webhook.TS_HEADER,
                                    alert_webhook.ID_HEADER])
def test_the_reference_names_every_webhook_header(header):
    assert header in reference(), (
        f'{header} is sent on every webhook delivery; a receiver cannot be '
        f'written against headers the contract does not name'
    )


def test_the_reference_states_the_exact_signed_string():
    """The one detail a receiver cannot guess.  Signing the body alone is the
    common implementation and it is replayable forever."""
    assert f'{alert_webhook.SIG_SCHEME}:<epoch>:<body>' in reference(), (
        'the signed string is scheme:timestamp:body — a reference that omits '
        'the timestamp produces receivers that verify replayed requests'
    )


def test_the_reference_states_the_envelope_version():
    assert f'"version": {alert_webhook.ENVELOPE_VERSION}' in reference(), (
        'the envelope version is what a receiver branches on; a sample that '
        'shows the wrong one is worse than no sample'
    )


@pytest.mark.parametrize('fmt', alert_webhook.FORMATS)
def test_the_reference_names_both_webhook_encodings(fmt):
    label = alert_webhook.FORMAT_LABELS[fmt].split(' (')[0]
    body = bounded(reference(), '## 5. Webhook', '\n## ')
    assert label in body, (
        f'webhook encoding {fmt!r} ships as {label!r} and the webhook section '
        f'never names it, so half the receivers are written against the wrong '
        f'body'
    )


@pytest.mark.parametrize('status', sorted(alert_webhook.RETRY_STATUSES))
def test_the_reference_lists_every_retried_status(status):
    body = bounded(reference(), '### Retries', '\n## ')
    assert f'`{status}`' in body, (
        f'HTTP {status} is retried and every other 4xx is not; a receiver '
        f'author who does not know which is which cannot tell a bug from the '
        f'policy'
    )


@pytest.mark.parametrize('proto', alert_syslog.PROTOCOLS)
def test_the_reference_names_every_syslog_transport(proto):
    body = bounded(reference(), '## 6. Syslog and CEF feed', '\n## ')
    assert proto in squashed(body), (
        f'transport {proto!r} is offered in the form and the syslog section '
        f'never names it'
    )


@pytest.mark.parametrize('fmt', alert_syslog.FORMATS)
def test_the_reference_documents_every_syslog_encoding(fmt):
    body = bounded(reference(), '## 6. Syslog and CEF feed', '\n## ')
    assert fmt in squashed(body), (
        f'encoding {fmt!r} is selectable and the syslog section never shows '
        f'its line shape; a collector parser cannot be written from prose'
    )


@pytest.mark.parametrize('sev', routing.SEVERITIES)
def test_the_reference_maps_every_severity_to_both_wire_scales(sev):
    """Three scales are in play — SATOM's names, syslog numbers and CEF's
    0-10.  A collector filtering on the wrong one drops criticals."""
    row = '| `%s` | %d | %d |' % (sev, alert_syslog._SYSLOG_SEV[sev],
                                  alert_syslog._CEF_SEV[sev])
    assert row in reference(), (
        f'severity {sev!r} has no row mapping it to the syslog and CEF scales'
    )


def test_the_reference_states_the_real_private_enterprise_number():
    """The PEN is composed at format time, not written as a literal in the
    emitter — a document that guesses it sends collector authors to a
    structured-data id that never appears on the wire."""
    body = bounded(reference(), '## 6. Syslog and CEF feed', '\n## ')
    assert f'satom@{alert_syslog._PEN}' in body


def test_the_reference_records_the_missing_timezone_in_the_cef_header():
    """The defect that shipped: the RFC 3164 header carries no timezone, so a
    UTC stamp files every event at the wrong hour on any non-UTC install."""
    body = squashed(bounded(reference(), '## 6. Syslog and CEF feed', '\n## '))
    assert 'notimezone' in body or 'notimezonefield' in body
    assert 'rfc3164' in body


@pytest.mark.parametrize('field', sorted(
    integration_hooks.EVENTS['alert.fired']['payload']))
def test_the_reference_documents_every_alert_fired_payload_field(field):
    body = bounded(reference(), '## 7. Integration hooks', '\n## ')
    assert f'`{field}`' in body, (
        f'`alert.fired` delivers {field!r} and the reference never names it; '
        f'a hook author reads the payload from here'
    )


@pytest.mark.parametrize('slug', sorted(hook_starters.STARTERS))
def test_the_reference_names_every_starter_and_the_secret_it_needs(slug):
    spec = hook_starters.STARTERS[slug]
    body = bounded(reference(), '## 7. Integration hooks', '\n## ')
    assert spec['label'] in body, f'starter {slug!r} is not in the reference'
    assert f'`{spec["event"]}`' in body, (
        f'starter {slug!r} binds to {spec["event"]!r} and the reference does '
        f'not say which event it is for'
    )
    for name in spec['secrets']:
        assert f'`{name}`' in body, (
            f'starter {slug!r} calls ctx.secret({name!r}); a hook saved '
            f'without declaring it raises at the moment it fires, which is '
            f'during an incident'
        )


def not_implemented_rows() -> list[str]:
    body = bounded(reference(), '## 8. Not implemented', '\n## ')
    return [ln for ln in body.splitlines()
            if ln.startswith('|') and 'not implemented' in ln.lower()]


@pytest.mark.parametrize('absent,registry,needle', [
    ('tls', alert_syslog.PROTOCOLS, 'TLS'),
    ('leef', alert_syslog.FORMATS, 'LEEF'),
])
def test_a_capability_the_code_does_not_offer_has_its_own_row(absent, registry,
                                                              needle):
    """Derived from the absence, and it cuts both ways.

    The premise assert fails the day the capability ships, forcing the row to
    be deleted instead of leaving the manual telling an operator that a
    feature they are looking at does not exist.  Asserting on the ROW and not
    on the section is deliberate: the closing paragraph of that section
    mentions TLS in prose, so a section-wide check stays green with the table
    row deleted.
    """
    assert absent not in registry, (
        f'{needle} now ships — the "not implemented" row for it has to go'
    )
    rows = [r for r in not_implemented_rows() if needle in r]
    assert rows, (
        f'{needle} is not offered anywhere in the product and section 8 has '
        f'no row saying so; an operator plans a SIEM integration on this, '
        f'before the change window rather than during it'
    )


def test_the_not_implemented_table_is_not_empty():
    """Anti-vacuity for the two guards above."""
    assert len(not_implemented_rows()) >= 3


def test_the_reference_names_the_ha_unit_that_executes_queued_hooks():
    """A standby whose watcher is disabled accepts queued work forever.  It
    has happened on this product."""
    assert 'satom-integrations.path' in reference()


# ---------------------------------------------------------------------------
# Anti-vacuity: every parametrised guard above iterates a registry.  If one
# stopped resolving they would all pass over zero cases and prove nothing.
# ---------------------------------------------------------------------------

def test_the_registries_are_not_empty():
    assert len(routing.SINKS) == 5
    assert len(routing.FAMILIES) == 7
    assert len(routing.UNFILTERABLE) == 2
    assert len(routing.SEVERITIES) == 3
    assert len(integration_hooks.EVENT_NAMES) >= 7
    assert len(hook_starters.STARTERS) >= 4
    assert len(alert_webhook.FORMATS) == 2
    assert len(alert_webhook.RETRY_STATUSES) >= 7
    assert len(alert_syslog.FORMATS) == 2
    assert len(alert_syslog.PROTOCOLS) == 2


def test_the_two_documents_are_not_empty():
    assert len(guide()) > 50_000
    assert len(reference()) > 5_000


def test_the_bounded_sections_actually_bound_something():
    """If a heading were renamed, ``bounded`` would return the rest of the
    file and every section guard would silently become a whole-file one."""
    assert 0 < len(delivery_section()) < 12_000
    assert 0 < len(hooks_section()) < 12_000
    for head in ('## 5. Webhook', '## 6. Syslog and CEF feed',
                 '## 7. Integration hooks', '## 8. Not implemented'):
        assert 0 < len(bounded(reference(), head, '\n## ')) < 12_000
