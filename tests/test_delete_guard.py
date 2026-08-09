# tests/test_delete_guard.py
"""Guards for the pre-delete reference check.

The defect these exist for is SILENT: FortiWeb does not reliably refuse the
deletion of an object other objects still name. When it does not, nothing
fails -- the holders simply point at a name that no longer resolves, and the
first symptom is broken traffic. Nothing in the app would notice, so every rule
below has to be asserted rather than observed.
"""
from __future__ import annotations

import io
import re
import types

import pytest

from app.services import delete_guard, policy_graph
from app.clients.fortiweb import FortiWebClient


# --------------------------------------------------------------------------- #
#  Fakes                                                                       #
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Client:
    """A FortiWebClient with only the read path wired, recording its calls."""

    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp

    # the methods under test are taken verbatim from the real client
    _errcode = staticmethod(FortiWebClient._errcode)
    _results_list = staticmethod(FortiWebClient._results_list)
    cmdb_refcount = FortiWebClient.cmdb_refcount


def _rows(**over):
    row = {'name': 'obj-a', 'q_ref': 0}
    row.update(over)
    return _Resp({'results': [row]})


class _CountClient:
    """Skips the HTTP layer: returns a canned cmdb_refcount answer."""

    def __init__(self, answer):
        self.answer = answer
        self.asked = 0

    def cmdb_refcount(self, endpoint, mkey):
        self.asked += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


# --------------------------------------------------------------------------- #
#  1. cmdb_refcount — reading the device's own bookkeeping                     #
# --------------------------------------------------------------------------- #
def test_refcount_reads_q_ref_as_the_count():
    c = _Client(_rows(q_ref=3))
    assert c.cmdb_refcount('waf/x', 'obj-a')[:3][0] == 3
    assert c.cmdb_refcount('waf/x', 'obj-a')[2] == 'ok'


def test_refcount_parses_q_ref_string_into_holder_lines():
    c = _Client(_rows(q_ref=2, q_ref_string='inline-protection(a)\n\ninline-protection(b)\n'))
    count, holders, status, _ = c.cmdb_refcount('waf/x', 'obj-a')
    assert (count, status) == (2, 'ok')
    # blank lines are dropped: an empty holder would print as a stray comma
    assert holders == ['inline-protection(a)', 'inline-protection(b)']


def test_refcount_without_q_ref_is_unsupported_not_zero():
    # The firmware not reporting a refcount must never read as "referenced by
    # nothing" -- that is the exact silent-pass this whole feature prevents.
    count, _, status, _ = _Client(_Resp({'results': [{'name': 'obj-a'}]})).cmdb_refcount('waf/x', 'a')
    assert status == 'unsupported'
    assert count == 0


def test_refcount_with_unparsable_q_ref_is_unsupported_not_zero():
    _, _, status, _ = _Client(_rows(q_ref='lots')).cmdb_refcount('waf/x', 'a')
    assert status == 'unsupported'


def test_refcount_reports_error_on_http_failure():
    _, _, status, err = _Client(_Resp({}, status=500)).cmdb_refcount('waf/x', 'a')
    assert status == 'error' and '500' in err


def test_refcount_reports_error_on_device_errcode():
    _, _, status, err = _Client(_Resp({'results': {'errcode': -3}})).cmdb_refcount('waf/x', 'a')
    assert status == 'error' and '-3' in err


def test_refcount_reports_error_when_the_transport_raises():
    _, _, status, err = _Client(RuntimeError('tls handshake')).cmdb_refcount('waf/x', 'a')
    assert status == 'error' and 'tls handshake' in err


def test_refcount_reports_error_on_empty_result_set():
    _, _, status, _ = _Client(_Resp({'results': []})).cmdb_refcount('waf/x', 'a')
    assert status == 'error'


def test_refcount_url_quotes_the_mkey():
    # Object names carry spaces ("Inline Standard Protection"); an unquoted
    # mkey silently reads the WRONG object or none at all.
    c = _Client(_rows())
    c.cmdb_refcount('waf/x', 'Inline Standard Protection')
    assert 'mkey=Inline%20Standard%20Protection' in c.calls[0]


def test_refcount_does_not_double_prefix_an_absolute_endpoint():
    c = _Client(_rows())
    c.cmdb_refcount('/api/v2.0/cmdb/waf/x', 'a')
    assert c.calls[0].count('/api/v2.0/cmdb/') == 1


def test_refcount_appends_mkey_with_ampersand_when_the_path_has_a_query():
    c = _Client(_rows())
    c.cmdb_refcount('waf/x?vdom=root', 'a')
    assert '?vdom=root&mkey=a' in c.calls[0]


# --------------------------------------------------------------------------- #
#  2. check() — the verdict                                                    #
# --------------------------------------------------------------------------- #
def test_unreferenced_object_may_be_deleted():
    reason, info = delete_guard.check(_CountClient((0, [], 'ok', '')), 'waf/x', 'a')
    assert reason == ''
    assert info['count'] == 0


def test_referenced_object_is_refused_and_the_holders_are_named():
    reason, info = delete_guard.check(
        _CountClient((2, ['inline-protection(wpp-full-lab)', 'inline-protection(wpp-b)'],
                      'ok', '')), 'waf/x', 'urw-full')
    assert reason
    assert 'urw-full' in reason
    assert 'inline-protection(wpp-full-lab)' in reason
    assert 'inline-protection(wpp-b)' in reason
    assert info['count'] == 2


def test_referenced_without_names_says_so_instead_of_printing_an_empty_list():
    # q_ref_string is absent on ~half the collections. "referenced by 3 —"
    # with nothing after the dash reads like a bug, or worse, like "by nothing".
    reason, _ = delete_guard.check(_CountClient((3, [], 'ok', '')), 'waf/x', 'a')
    assert reason
    assert 'does not name them' in reason
    assert not re.search(r'—\s*$', reason.strip())


def test_holder_list_is_truncated_and_says_how_many_were_hidden():
    holders = ['pol-%d' % i for i in range(20)]
    reason, _ = delete_guard.check(_CountClient((20, holders, 'ok', '')), 'waf/x', 'a')
    assert 'pol-0' in reason
    assert 'and %d more' % (20 - delete_guard.SAMPLE) in reason
    assert 'pol-19' not in reason


def test_unsupported_firmware_does_not_block_the_delete():
    # A firmware that never reports a refcount would otherwise make every
    # delete on that collection impossible, permanently.
    reason, info = delete_guard.check(_CountClient((0, [], 'unsupported', '')), 'waf/x', 'a')
    assert reason == ''
    assert info['status'] == 'unsupported'


def test_unreadable_object_is_refused():
    # The opposite call from ref_validate: there the device is a second
    # authority, here there is none.
    reason, _ = delete_guard.check(_CountClient((0, [], 'error', 'HTTP 500')), 'waf/x', 'a')
    assert reason
    assert 'HTTP 500' in reason


def test_unreadable_refusal_names_the_collection_it_could_not_read():
    reason, _ = delete_guard.check(_CountClient((0, [], 'error', 'boom')), 'waf/url-rewrite', 'a')
    assert 'waf/url-rewrite' in reason


def test_a_raising_client_is_a_refusal_not_a_crash():
    # A guard that raises into the write path turns a refusal into a 500 and
    # loses the reason entirely.
    reason, info = delete_guard.check(_CountClient(RuntimeError('nope')), 'waf/x', 'a')
    assert reason and 'nope' in reason
    assert info['status'] == 'error'


@pytest.mark.parametrize('client,endpoint,mkey', [
    (None, 'waf/x', 'a'),
    (_CountClient((9, [], 'ok', '')), '', 'a'),
    (_CountClient((9, [], 'ok', '')), 'waf/x', ''),
])
def test_nothing_to_look_up_is_skipped_not_refused(client, endpoint, mkey):
    reason, info = delete_guard.check(client, endpoint, mkey)
    assert reason == ''
    assert info['status'] == 'skipped'


def test_skipping_does_not_ask_the_device():
    c = _CountClient((9, [], 'ok', ''))
    delete_guard.check(c, 'waf/x', '')
    assert c.asked == 0


# --------------------------------------------------------------------------- #
#  3. The wording is load-bearing for the cascade                              #
# --------------------------------------------------------------------------- #
def test_referenced_refusal_reads_as_in_use_to_the_cascade():
    # policy_graph classifies a cascade child it could not delete by matching
    # phrases in the error text: "in use" -> kept_shared (benign), anything
    # else -> failed (an alarm). Reword the refusal without this and a shared
    # dependency starts reporting as a cascade failure.
    reason, _ = delete_guard.check(_CountClient((1, ['pol-a'], 'ok', '')), 'waf/x', 'a')
    assert policy_graph._is_in_use_error(reason) is True


def test_unverified_refusal_does_NOT_read_as_in_use_to_the_cascade():
    # The other half, and the dangerous one: a transport failure classified as
    # "another policy claims it; safe to leave" hides a real error behind a
    # benign label.
    reason, _ = delete_guard.check(_CountClient((0, [], 'error', 'timeout')), 'waf/x', 'a')
    assert policy_graph._is_in_use_error(reason) is False


# --------------------------------------------------------------------------- #
#  4. Wiring into FortiWebOps.delete                                           #
# --------------------------------------------------------------------------- #
def _ops(monkeypatch, answer, recorder=None):
    from app.services import fortiweb_ops

    client = _CountClient(answer)
    ops = fortiweb_ops.FortiWebOps(types.SimpleNamespace(id=None))
    ops._client = client
    if recorder is not None:
        monkeypatch.setattr(ops, '_record',
                            lambda *a, **k: recorder.append((a, k)), raising=False)
    return ops, client


def test_the_guard_runs_on_the_dry_run_too(monkeypatch):
    # Every delete surface previews first and applies only after the operator
    # confirms. Checking only the apply shows a clean "would delete" and then
    # fails the CONFIRMED action.
    ops, client = _ops(monkeypatch, (2, ['pol-a'], 'ok', ''))
    res = ops.delete('waf/x', 'a', dry_run=True)
    assert res.ok is False
    assert client.asked == 1
    assert 'pol-a' in res['error']


def test_a_blocked_delete_exposes_the_verdict_structurally(monkeypatch):
    ops, _ = _ops(monkeypatch, (2, ['pol-a'], 'ok', ''))
    res = ops.delete('waf/x', 'a', dry_run=True)
    assert res['blocked']['count'] == 2
    assert res['blocked']['holders'] == ['pol-a']


def test_an_unreferenced_object_still_previews_normally(monkeypatch):
    ops, _ = _ops(monkeypatch, (0, [], 'ok', ''))
    res = ops.delete('waf/x', 'a', dry_run=True)
    assert res.ok is True
    assert res['request']['method'] == 'DELETE'
    assert 'mkey=a' in res['request']['path']


def test_a_blocked_preview_is_not_written_to_the_audit_log(monkeypatch):
    # Nothing was asked of the device yet; auditing every click on a delete
    # button would bury the entries that mean something.
    rec = []
    ops, _ = _ops(monkeypatch, (2, ['pol-a'], 'ok', ''), rec)
    ops.delete('waf/x', 'a', dry_run=True)
    assert rec == []


def test_a_blocked_apply_IS_written_to_the_audit_log(monkeypatch):
    # A confirmed destructive action that was stopped is exactly what an audit
    # trail is for.
    rec = []
    ops, _ = _ops(monkeypatch, (2, ['pol-a'], 'ok', ''), rec)
    ops.delete('waf/x', 'a', dry_run=False)
    assert len(rec) == 1
    assert 'pol-a' in rec[0][0][-1]


def test_check_refs_false_does_not_even_ask_the_device(monkeypatch):
    ops, client = _ops(monkeypatch, (9, ['pol-a'], 'ok', ''))
    res = ops.delete('waf/x', 'a', dry_run=True, check_refs=False)
    assert res.ok is True
    assert client.asked == 0


def test_force_overrides_the_refusal(monkeypatch):
    ops, _ = _ops(monkeypatch, (9, ['pol-a'], 'ok', ''))
    assert ops.delete('waf/x', 'a', dry_run=True, force=True).ok is True


def _applying_ops(monkeypatch, answer, seen):
    """Ops whose real ``_apply`` runs against stubs — no device, no DB."""
    from app.services import fortiweb_ops

    monkeypatch.setattr(fortiweb_ops, 'log_action',
                        lambda *a, **k: seen.update(k), raising=True)
    monkeypatch.setattr(fortiweb_ops, 'db', types.SimpleNamespace(
        session=types.SimpleNamespace(add=lambda *a: None,
                                      commit=lambda: None,
                                      rollback=lambda: None)), raising=True)
    client = _CountClient(answer)
    client.api_call = lambda *a, **k: None
    ops = fortiweb_ops.FortiWebOps(types.SimpleNamespace(id=None))
    ops._client = client
    return ops


def test_a_forced_apply_is_stamped_in_the_audit_detail(monkeypatch):
    # An override that leaves no trace is indistinguishable from an object
    # that was genuinely unreferenced.
    seen = {}
    _applying_ops(monkeypatch, (9, ['pol-a'], 'ok', ''), seen).delete(
        'waf/x', 'a', dry_run=False, force=True)
    assert 'ref_check=forced' in seen.get('detail', '')


def test_an_unforced_apply_is_not_stamped_as_forced(monkeypatch):
    seen = {}
    _applying_ops(monkeypatch, (0, [], 'ok', ''), seen).delete(
        'waf/x', 'a', dry_run=False)
    assert 'ref_check=forced' not in seen.get('detail', '')


def test_an_opted_out_apply_is_not_stamped_as_forced(monkeypatch):
    # check_refs=False is a call-site decision, not an operator override; the
    # two must not be conflated in the trail.
    seen = {}
    _applying_ops(monkeypatch, (9, ['pol-a'], 'ok', ''), seen).delete(
        'waf/x', 'a', dry_run=False, check_refs=False, force=True)
    assert 'ref_check=forced' not in seen.get('detail', '')


def test_a_sub_row_delete_is_not_checked_against_its_parent(monkeypatch):
    # ?mkey=<parent>&sub_mkey=<row> deletes a ROW, not the parent, so the
    # parent's refcount says nothing about it.
    ops, client = _ops(monkeypatch, (9, ['pol-a'], 'ok', ''))
    assert ops.delete('waf/x', 'sni1', dry_run=True, sub_mkey='7').ok is True
    assert client.asked == 0


def test_a_delete_with_no_mkey_is_not_checked(monkeypatch):
    ops, client = _ops(monkeypatch, (9, ['pol-a'], 'ok', ''))
    assert ops.delete('waf/x/rows?parent=p', '', dry_run=True).ok is True
    assert client.asked == 0


def test_an_unbuildable_client_does_not_block_the_delete():
    # A stub appliance (offline preview, tests) yields no client. Refusing
    # there would break every headless preview, and a real delete without a
    # client fails at the device anyway.
    from app.services.fortiweb_ops import FortiWebOps

    class _NoClient(FortiWebOps):
        @property
        def client(self):
            raise RuntimeError('no credentials')

    assert _NoClient(types.SimpleNamespace(id=None)).delete('waf/x', 'a', dry_run=True).ok is True


# --------------------------------------------------------------------------- #
#  5. The opt-outs are exactly the reviewed ones                               #
# --------------------------------------------------------------------------- #
def _src(rel):
    return io.open('/opt/satom/' + rel, encoding='utf-8').read()


def _calls(body, needle):
    """Every ``needle(...)`` call in ``body``, balanced.

    A ``[^)]*`` regex stops at the first ``)``, so ``ops.delete(path,
    str(any_id), check_refs=False)`` truncates to ``ops.delete(path,
    str(any_id)`` and the guard asserts against half a call — it fails on
    CORRECT code and would pass on code missing the argument entirely.
    """
    out, i = [], body.find(needle)
    while i != -1:
        depth, j = 0, i + len(needle) - 1
        while j < len(body):
            if body[j] == '(':
                depth += 1
            elif body[j] == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append(body[i:j + 1])
        i = body.find(needle, j + 1)
    return out


def _no_comments_py(src):
    out = []
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        out.append(line)
    return '\n'.join(out)


OPTOUT_SITES = {
    # rebuilding a singleton sub-table: the rows are re-added immediately
    'app/views/objedit.py': 2,
    # a rollback deletes what the job just created, refs and all
    'app/services/jobs.py': 1,
}


def test_check_refs_is_disabled_only_at_the_reviewed_call_sites():
    # The guard is opt-OUT, so it can be turned off silently one call site at a
    # time. This fails the build for a new one until it is justified here.
    import subprocess

    out = subprocess.run(
        ['grep', '-rn', 'check_refs=False', '--include=*.py', '/opt/satom/app'],
        capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        rel = line.split(':', 1)[0].replace('/opt/satom/', '')
        if rel == 'app/services/fortiweb_ops.py':
            continue  # the parameter's own definition and docstring
        found[rel] = found.get(rel, 0) + 1
    assert found == OPTOUT_SITES, (
        'check_refs=False appears at unreviewed call sites: %r' % (found,))


def test_the_subtable_rebuild_wipe_opts_out():
    src = _no_comments_py(_src('app/views/objedit.py'))
    body = src[src.index('def _replace_set'):src.index('def _read_object')]
    calls = _calls(body, 'ops.delete(')
    assert calls, 'the sub-table rebuild no longer deletes — re-read this guard'
    for call in calls:
        assert 'check_refs=False' in call, call


def test_the_delete_object_view_passes_the_operator_override():
    src = _no_comments_py(_src('app/views/objedit.py'))
    body = src[src.index('def delete_object'):src.index('def clone_object')]
    assert "force=bool(body.get('force'))" in body


def test_the_rollback_example_teaches_the_opt_out():
    # jobs.Rollback's docstring is the pattern every worker copies; an example
    # that omits check_refs=False teaches a rollback that cannot roll back.
    src = _src('app/services/jobs.py')
    body = src[src.index('class Rollback'):]
    calls = _calls(body, 'ops.delete(')
    assert calls, 'the Rollback docstring no longer shows a delete compensation'
    for call in calls:
        assert 'check_refs=False' in call, call
