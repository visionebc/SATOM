"""Guards for the pre-write reference check.

What went wrong (fortiweb08, audit entries 1128 and 1129, 2026-08-09). The
operator edited Web Protection Profile ``wpp-shop-strict`` and set three
reference fields. One of them, ``subresource-integrity-policy``, had NO entry in
``REF_ENDPOINTS``, so the editor fell through to ``widget = "text"`` and offered
a free text box for a field that only accepts the name of an existing object --
while its two neighbours, mapped, were dropdowns. The value went to the device,
FortiWeb refused the WHOLE PUT with ``HTTP 500 / errcode -651: Invalid input
value.`` and named neither the field nor the value. The two good values were
discarded with it. Seven seconds earlier the same refusal had come back for the
same reason, and the operator -- reasonably -- had changed a DIFFERENT field
between the two attempts, because nothing in the message pointed anywhere.

Two halves, and each is useless without the other:

* the map has to know the collection (18 more WPP fields and 2 Server Policy
  fields were in exactly the same state -- this was never one field);
* the write has to ASK the device before it writes, so the refusal names the
  field, the value and the collection instead of arriving as ``-651``.

The third state is the one that is easy to get wrong: "collection empty",
"collection absent on this firmware" and "could not ask" all answer with zero
names and they mean opposite things. Only the first two license a rejection.
"""
import io
import os
import re

import pytest

from app.services import ref_validate
from app.services.fortiweb_field_schema import REF_ENDPOINTS
from app.clients.fortiweb import FortiWebClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FakeClient:
    """Answers ``cmdb_names_checked`` from a scripted table and counts reads."""

    def __init__(self, table):
        self.table = table          # endpoint -> (names, status, error)
        self.reads = []

    def cmdb_names_checked(self, endpoint):
        self.reads.append(endpoint)
        return self.table.get(endpoint, ([], 'ok', ''))


# --------------------------------------------------------------------------- #
#  1. the map                                                                   #
# --------------------------------------------------------------------------- #
# Probed live on fortiweb08 (8.0.x) on 2026-08-09: HTTP 200 with no errcode.
# A path that does not exist answers HTTP 500 + errcode -20001, so "it returned
# nothing" was never proof either way.
VERIFIED_2026_08_09 = {
    'advanced-bot-protection': 'waf/advanced-bot-protection',
    'application-layer-dos-prevention': 'waf/application-layer-dos-prevention',
    'client-side-protection-policy': 'waf/client-side-protection-policy',
    'dlp-policy': 'waf/dlp.policy',
    'file-compress-rule': 'waf/file-compress-rule',
    'file-exception-policy': 'waf/file-exception-policy',
    'graphql-validation-policy': 'waf/graphql-validation.policy',
    'http-authen-policy': 'waf/http-authen.http-authen-policy',
    'link-cloaking-policy': 'waf/link-cloaking.link-cloaking-policy',
    'mobile-api-protection': 'waf/mobile-api-protection.mobile-api-protection-policy',
    'quarantined-ip-trigger': 'log/trigger-policy',
    'site-publish-helper': 'waf/site-publish-helper.policy',
    'subresource-integrity-policy': 'waf/subresource-integrity-policy',
    'syntax-based-attack-detection': 'waf/syntax-based-attack-detection',
    'url-encryption-policy': 'waf/url-encryption.url-encryption-policy',
    'waiting-room-policy': 'waf/waiting-room-policy',
    'webshell-detection-policy': 'waf/webshell-detection-policy',
    'websocket-security-policy': 'waf/websocket-security.policy',
    'acceleration-policy': 'server-policy/acceleration.policy',
    'trigger': 'log/trigger-policy',
}

# Device-declared selects on the same two objects that stay UNMAPPED on purpose:
# every candidate path answered errcode -20001 on this firmware, or the only
# plausible collection is a rename we could not prove. A wrong mapping is worse
# than none -- it would populate the dropdown from the wrong collection AND make
# the validator reject values FortiWeb accepts.
DELIBERATELY_UNMAPPED = {
    'custom-response', 'grpc-policy', 'mitb-protection', 'ftp-protection-profile',
    'adfs-certificate-service', 'certificate-group', 'urlcert-group',
    'traffic-mirror-type',
}


def test_the_field_that_caused_1129_is_mapped():
    assert REF_ENDPOINTS.get('subresource-integrity-policy') == \
        'waf/subresource-integrity-policy'


@pytest.mark.parametrize('key,endpoint', sorted(VERIFIED_2026_08_09.items()))
def test_each_verified_reference_field_keeps_its_collection(key, endpoint):
    assert REF_ENDPOINTS.get(key) == endpoint


def test_unproven_collections_are_not_guessed_into_the_map():
    """A mapping we could not verify must stay out.

    This is the half of the fix that is invisible: adding all 28 fields would
    have looked more complete and would have started refusing valid saves on
    the eight whose collection we never proved.
    """
    guessed = sorted(k for k in DELIBERATELY_UNMAPPED if k in REF_ENDPOINTS)
    assert not guessed, 'unverified mapping(s) added: %s' % guessed


def test_every_endpoint_is_a_section_slash_collection():
    bad = [f'{k}={v}' for k, v in REF_ENDPOINTS.items()
           for part in v.split('|') if not re.fullmatch(r'[a-z0-9.\-]+/[a-z0-9.\-]+', part)]
    assert not bad, bad


def test_new_mappings_reach_the_options_allow_list():
    """A mapped field whose collection is not in ALL_REF_ENDPOINTS renders a
    dropdown the options endpoint then refuses to populate — an empty select
    that reads as 'nothing configured'."""
    from app.services.fortiweb_field_schema import ALL_REF_ENDPOINTS
    missing = [v for v in VERIFIED_2026_08_09.values() if v not in ALL_REF_ENDPOINTS]
    assert not missing, missing


def test_a_mapped_field_renders_as_a_dropdown_not_a_text_box():
    from app.services.fortiweb_field_schema import descriptor
    d = descriptor('wpp', 'subresource-integrity-policy', '', {})
    assert d['widget'] == 'ref'
    assert d['ref'] == 'waf/subresource-integrity-policy'


# --------------------------------------------------------------------------- #
#  2. validate() — the three states                                             #
# --------------------------------------------------------------------------- #
def test_a_value_absent_from_a_readable_collection_is_a_problem():
    c = FakeClient({'waf/url-rewrite.url-rewrite-policy': (['urw-shop'], 'ok', '')})
    problems, unverified = ref_validate.validate(c, {'url-rewrite-policy': 'nope'})
    assert unverified == []
    assert len(problems) == 1
    p = problems[0]
    assert p['field'] == 'url-rewrite-policy'
    assert p['value'] == 'nope'
    assert p['endpoint'] == 'waf/url-rewrite.url-rewrite-policy'
    assert 'urw-shop' in p['options']


def test_an_empty_collection_says_there_is_nothing_to_name():
    """The exact 1129 case: the collection exists and holds nothing, so every
    non-empty value is wrong. 'no configured objects' is actionable; 'invalid
    input value' is not."""
    c = FakeClient({'waf/subresource-integrity-policy': ([], 'ok', '')})
    problems, _ = ref_validate.validate(c, {'subresource-integrity-policy': 'admin'})
    assert len(problems) == 1
    assert 'no configured objects' in problems[0]['reason']


def test_a_collection_absent_from_this_firmware_is_a_problem_naming_it():
    """"Absent" and "empty" must not share a sentence.

    Both refuse the value, so a test that only checks "there is a problem", or
    that the endpoint is quoted, passes for either -- and the operator is told
    to go create an object in a collection this firmware does not have.
    """
    c = FakeClient({'waf/dlp.policy': ([], 'absent', '')})
    problems, _ = ref_validate.validate(c, {'dlp-policy': 'dlp1'})
    assert len(problems) == 1
    reason = problems[0]['reason']
    assert 'this firmware has no "waf/dlp.policy" collection' in reason
    assert 'no configured objects' not in reason


def test_a_read_failure_never_blocks_the_write():
    """Refusing a legitimate change because a GET failed would make the editor
    unusable on a flaky or license-locked box, and the device is still the
    authority — it answers -651 if the value really is wrong."""
    c = FakeClient({'waf/dlp.policy': ([], 'error', 'HTTP 423')})
    problems, unverified = ref_validate.validate(c, {'dlp-policy': 'dlp1'})
    assert problems == []
    assert unverified == [{'field': 'dlp-policy', 'endpoint': 'waf/dlp.policy',
                           'error': 'HTTP 423'}]


def test_clearing_a_reference_is_never_validated():
    c = FakeClient({})
    problems, unverified = ref_validate.validate(c, {'dlp-policy': ''})
    assert (problems, unverified, c.reads) == ([], [], [])


def test_a_non_reference_field_costs_no_read():
    c = FakeClient({})
    problems, _ = ref_validate.validate(c, {'comment': 'anything at all'})
    assert problems == [] and c.reads == []


def test_a_value_that_is_present_passes():
    c = FakeClient({'waf/user-tracking.policy': (['trk-shop'], 'ok', '')})
    problems, _ = ref_validate.validate(c, {'user-tracking-policy': 'trk-shop'})
    assert problems == []


def test_a_list_valued_reference_names_only_the_missing_element():
    c = FakeClient({'waf/signature': (['sig-a', 'sig-b'], 'ok', '')})
    problems, _ = ref_validate.validate(c, {'signature-rule': 'sig-a, sig-zz'})
    assert len(problems) == 1
    # The elements must be split on the separator, not merely tokenised: a
    # whitespace-only split leaves "sig-a," -- trailing comma and all -- which
    # then reads as a SECOND missing object and blames a name that is present.
    assert problems[0]['reason'] == '"sig-zz" not configured on this device'


def test_one_read_per_collection_even_with_several_fields():
    """Two fields sharing a collection must not cost two round trips: the
    editor saves whole objects and a per-field read turns one save into dozens."""
    c = FakeClient({'system/interface': (['port1'], 'ok', '')})
    ref_validate.validate(c, {'interface': 'port1', 'block-port': 'port1'})
    assert c.reads == ['system/interface']


def test_the_1129_payload_names_the_one_bad_field_of_three():
    """The whole point: the operator changed user-tracking-policy between the
    two attempts because the device's message pointed nowhere."""
    c = FakeClient({
        'waf/url-rewrite.url-rewrite-policy': (['test', 'urw-shop'], 'ok', ''),
        'waf/user-tracking.policy': (['trk-shop', 'ut-full'], 'ok', ''),
        'waf/subresource-integrity-policy': ([], 'ok', ''),
    })
    problems, _ = ref_validate.validate(c, {
        'url-rewrite-policy': 'test',
        'user-tracking-policy': 'trk-shop',
        'subresource-integrity-policy': 'admin',
    })
    assert [p['field'] for p in problems] == ['subresource-integrity-policy']
    msg = ref_validate.message(problems)
    assert 'subresource-integrity-policy' in msg and '"admin"' in msg
    assert 'user-tracking-policy' not in msg


def test_message_is_the_only_author_of_a_refusal_sentence():
    """A second place formatting this sentence is how the editor and the
    workspace would start explaining the same refusal differently."""
    hits = 0
    for base, _dirs, files in os.walk(os.path.join(ROOT, 'app')):
        for f in files:
            if f.endswith('.py'):
                text = io.open(os.path.join(base, f), encoding='utf-8').read()
                hits += text.count('not configured on this device')
    assert hits == 1, 'refusal wording duplicated in %d places' % hits


def test_unambiguous_per_object_refs_are_covered_too():
    assert ref_validate.endpoint_for('ip-list') == 'server-policy/ip-group'


# --------------------------------------------------------------------------- #
#  3. the client's three-state read                                             #
# --------------------------------------------------------------------------- #
class Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError('not json')
        return self._payload


def _client(monkeypatch, answers):
    c = FortiWebClient.__new__(FortiWebClient)

    def fake_get(path):
        a = answers[path]
        if isinstance(a, Exception):
            raise a
        return a
    c.get = fake_get
    return c


def test_absent_collection_reads_as_absent_not_as_empty(monkeypatch):
    c = _client(monkeypatch, {'/api/v2.0/cmdb/waf/nope':
                              Resp(500, {'errcode': '-20001'})})
    names, status, _ = c.cmdb_names_checked('waf/nope')
    assert (names, status) == ([], 'absent')


def test_empty_collection_reads_as_ok(monkeypatch):
    c = _client(monkeypatch, {'/api/v2.0/cmdb/waf/sri': Resp(200, {'results': []})})
    assert c.cmdb_names_checked('waf/sri') == ([], 'ok', '')


def test_transport_failure_reads_as_error(monkeypatch):
    c = _client(monkeypatch, {'/api/v2.0/cmdb/waf/sri': OSError('unreachable')})
    names, status, err = c.cmdb_names_checked('waf/sri')
    assert (names, status) == ([], 'error')
    assert 'unreachable' in err


def test_a_merged_pair_is_ok_when_one_source_answers(monkeypatch):
    c = _client(monkeypatch, {
        '/api/v2.0/cmdb/a/one': Resp(500, {'errcode': '-20001'}),
        '/api/v2.0/cmdb/b/two': Resp(200, {'results': [{'name': 'x'}]}),
    })
    assert c.cmdb_names_checked('a/one|b/two') == (['x'], 'ok', '')


def test_cmdb_names_has_no_second_reader(monkeypatch):
    """cmdb_names must delegate: two readers of a reference collection is how
    the dropdown and the validator come to disagree about what exists."""
    c = FortiWebClient.__new__(FortiWebClient)
    c.cmdb_names_checked = lambda ep: (['only-from-checked'], 'ok', '')
    assert c.cmdb_names('anything') == ['only-from-checked']


# --------------------------------------------------------------------------- #
#  4. every operator-facing write is behind the guard                           #
# --------------------------------------------------------------------------- #
def _strip_prose(src):
    """Source with docstrings and comments blanked out, positions preserved.

    Without this the guard below matches the WORD "FortiWebOps" inside
    ``workspace.save``'s own docstring -- which sits ABOVE the check and made a
    correct function look like it validated after it wrote. Asserting against
    prose that describes the code is the failure mode this file exists to catch
    in the product; it applies to the tests too.
    """
    out = re.sub(r'(?s)("""|\'\'\')(?:(?!\1).)*\1',
                 lambda m: ' ' * (m.end() - m.start()), src)
    return re.sub(r'#[^\n]*', lambda m: ' ' * (m.end() - m.start()), out)


def _func_body(path, name):
    text = _strip_prose(io.open(path, encoding='utf-8').read())
    start = text.index('def %s(' % name)
    nxt = text.find('\ndef ', start + 1)
    return text[start:nxt if nxt > 0 else len(text)]


@pytest.mark.parametrize('module,func', [
    ('app/views/objedit.py', 'save_object'),
    ('app/views/objedit.py', 'create_object'),
    ('app/views/objedit.py', 'save_row'),
    ('app/views/workspace.py', 'save'),
])
def test_each_write_endpoint_checks_references_first(module, func):
    body = _func_body(os.path.join(ROOT, module), func)
    assert ('_ref_guard(' in body) or ('ref_validate.check(' in body), \
        '%s writes operator fields without the reference check' % func
    write = min([i for i in (body.find('FortiWebOps'), body.find('ops.create'),
                             body.find('ops.update')) if i > 0] or [len(body)])
    guard = min([i for i in (body.find('_ref_guard('), body.find('ref_validate.check(')) if i > 0])
    assert guard < write, '%s validates AFTER it writes' % func


def test_the_check_also_runs_on_the_dry_run_path():
    """A preview that hides a certain refusal is worse than no preview: the
    operator approves a plan the device will reject."""
    body = _func_body(os.path.join(ROOT, 'app/views/objedit.py'), 'save_object')
    guard = body.find('_ref_guard(')
    assert 'do_apply' not in body[guard:body.find('\n', guard) + 1]
